"""Pure, production-shaped capability evaluation for DirectPath.

The evaluator deliberately accepts already-pinned facts.  It performs no
inventory reads, clock reads, database access, owner transitions, resets, or
device I/O.  Callers must obtain and authenticate those facts before invoking
this module.

Two projections are produced:

* ``CapabilityDecision.to_wire()`` is the closed, fail-closed boolean hash
  subject defined by ``directpath-portable-hash-subjects.schema.json``.
* ``CapabilityEvaluation.to_operation_payload()`` preserves ``UNKNOWN`` for
  the tri-state ``OP-EVALUATE-CAPABILITY`` response.

``semantic_hash`` binds only owner-independent capability semantics.  In
particular, it excludes snapshot epoch, administrator enablement, owner
readback, health/free availability, and current-request runtime gates.  A
freshly published snapshot whose only change is availability therefore gets a
new decision hash but retains the same semantic hash.

This module is a portable component premise.  It is not evidence of Qman
product integration, E3 closure, E4 qualification, or release readiness.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Iterable

from .canonical import canonical_json_bytes, sha256_digest
from .errors import fail


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SCHEMA_REF_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    r"(?:#(?:/[A-Za-z0-9._~$-]+)+)?$"
)
_DETAIL_KEY_RE = re.compile(r"^[a-z][a-zA-Z0-9._-]{0,127}$")
_ARTIFACT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,127}$")
_SAFE_INTEGER = 9_007_199_254_740_991


class TriState(str, Enum):
    """Closed three-valued state used at the operation boundary."""

    YES = "YES"
    NO = "NO"
    UNKNOWN = "UNKNOWN"

    @property
    def fail_closed_bool(self) -> bool:
        return self is TriState.YES


class EvaluationContext(str, Enum):
    """Context used by the stable capability-decision hash subject."""

    HOST_ONLY = "HOST_ONLY"
    VM_REQUEST = "VM_REQUEST"


class PolicyMode(str, Enum):
    """Policy isolation mode used by the stable decision wire."""

    PRODUCTION = "PRODUCTION"
    ISOLATED_UNQUALIFIED_LAB = "ISOLATED_UNQUALIFIED_LAB"


class OperationContext(str, Enum):
    """Closed context enumeration used by OP-EVALUATE-CAPABILITY."""

    STATIC_ADMISSION = "STATIC_ADMISSION"
    DYNAMIC_CANDIDATE = "DYNAMIC_CANDIDATE"
    OWNER_ACTIVATION = "OWNER_ACTIVATION"
    RECONCILE = "RECONCILE"


class AdmissionRequirement(str, Enum):
    """Minimum support tier required by this evaluation."""

    TECHNICAL = "TECHNICAL"
    QUALIFIED = "QUALIFIED"
    SUPPORTED = "SUPPORTED"


class DetailValueType(str, Enum):
    TEXT = "TEXT"
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    DIGEST = "DIGEST"
    ID = "ID"


_REASON_CODES_BY_STAGE: dict[str, tuple[str, ...]] = {
    "inventory": (
        "DEVICE_NOT_IN_INVENTORY",
        "SNAPSHOT_INCOMPLETE",
    ),
    "concurrency": (
        "INVENTORY_EPOCH_CHANGED",
        "STALE_RESOURCE_VERSION",
        "STALE_CONTROLLER_GENERATION",
        "STALE_RUN_GENERATION",
        "STALE_HOST_EPOCH",
    ),
    "api": ("IDEMPOTENCY_KEY_REUSED",),
    "capability": (
        "HOST_IOMMU_MISSING",
        "DEVICE_NO_IOMMU_DMA_ISOLATION",
        "DEVICE_IOMMU_BACKING_UNKNOWN",
        "INTERRUPT_REMAP_MISSING",
        "PHYSICAL_ISOLATION_DOMAIN_UNKNOWN",
        "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN",
        "HARDWARE_ROLE_NOT_ASSIGNABLE",
        "PLATFORM_RESERVED",
        "DEPENDENCY_PROVENANCE_UNKNOWN",
        "DEPENDENCY_ACTION_UNKNOWN",
        "DEPENDENCY_ACTION_CONFLICT",
        "DEPENDENCY_CLOSURE_LIMIT",
        "RESET_NOT_SUPPORTED",
        "RESET_DOMAIN_UNVERIFIED",
    ),
    "qualification": (
        "DEVICE_ERRATA_DENY",
        "PROFILE_NO_MATCH",
        "QUALIFICATION_EVIDENCE_MISSING",
    ),
    "reservation": (
        "DEPENDENCY_BUSY",
        "EXCLUSIVE_ATTACH_GROUP_COLLISION",
    ),
    "prepare": (
        "RESET_DOMAIN_CHANGED",
        "RESET_FAILED",
    ),
    "release": (
        "RESET_STATE_VERIFY_FAILED",
        "BACKEND_RELEASE_UNVERIFIED",
        "BACKEND_RELEASE_CONTEXT_UNAVAILABLE",
        "RELEASE_GUARD_CONFLICT",
        "QEMU_EXIT_UNVERIFIED",
        "DMA_TEARDOWN_UNVERIFIED",
        "OWNER_RESTORE_UNVERIFIED",
        "RELEASE_CLEANUP_UNCERTAIN",
    ),
    "policy": (
        "ADMIN_DISABLED",
        "DEVICE_QUARANTINED",
    ),
    "owner": (
        "HOST_ACTIVATION_REQUIRED",
        "HOST_REBOOT_REQUIRED",
        "HOST_DRIVER_BUSY",
        "HOST_CRITICAL_DEPENDENCY",
        "HOST_DEVICE_RESERVED",
        "CURRENT_OWNER_UNKNOWN",
        "QUIESCE_STATE_UNKNOWN",
        "PERSISTENT_HOST_USE",
        "ACTIVATION_IDENTITY_MISMATCH",
        "ACTIVATION_OBSERVED_STATE_MISMATCH",
        "ACTIVATION_ROLLBACK_UNCERTAIN",
        "BOOT_CLAIM_UNSUPPORTED",
    ),
    "admission": (
        "PROFILE_ABI_MISMATCH",
        "PROFILE_DEVICE_LIMIT",
        "RMRR_PROFILE_CONFLICT",
        "MMIO_APERTURE_EXHAUSTED",
        "MMIO_PLANNER_TIMEOUT",
    ),
    "solver": (
        "PROFILE_NO_GLOBAL_SOLUTION",
        "NUMA_POLICY_UNSATISFIED",
    ),
    "runtime-verification": (
        "MANDATORY_BAR_UNASSIGNED",
        "OBSERVED_PLAN_DRIFT",
        "GUEST_PROBE_MISSING",
    ),
    "backend": (
        "BACKEND_TOPOLOGY_GAP",
        "BACKEND_APERTURE_ENCODING_GAP",
        "BACKEND_RESOURCE_PLACEMENT_GAP",
        "UNSUPPORTED_IOCTL_ABI",
    ),
    "placement": ("STATIC_DEVICE_HOST_AFFINITY",),
    "launch": ("QEMU_START_FAILED",),
    "runtime": ("QEMU_CRASH",),
    "reconcile": (
        "OWNERSHIP_UNCERTAIN",
        "HOST_RECONCILE_INCOMPLETE",
    ),
    "relocation": (
        "CLEAN_RELEASE_RECEIPT_MISSING",
        "CLEAN_RELEASE_RECEIPT_STALE",
        "HOST_UNREACHABLE",
        "RELOCATION_CANDIDATE_EXHAUSTED",
    ),
    "remediation": ("REMEDIATION_NOT_AUTHORIZED",),
    "lifecycle": (
        "LIVE_MIGRATION_UNSUPPORTED",
        "SNAPSHOT_UNSUPPORTED",
        "SUSPEND_RESUME_UNSUPPORTED",
        "FAULT_TOLERANCE_UNSUPPORTED",
        "HOTPLUG_UNSUPPORTED",
        "UNMANAGED_ATTACH_PATH",
    ),
    "audit": (
        "AUDIT_WRITE_FAILED",
        "EVIDENCE_INCOMPLETE",
    ),
}
_REASON_STAGE_BY_CODE = {
    code: stage for stage, codes in _REASON_CODES_BY_STAGE.items() for code in codes
}


def _invalid(path: str, message: str) -> None:
    fail("CAPABILITY_INPUT_INVALID", path, message)


def _as_enum(enum_type: type[Enum], value: Any, path: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        allowed = ", ".join(item.value for item in enum_type)
        _invalid(path, f"expected one of: {allowed}")


def _validate_digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _invalid(path, "expected sha256:<64 lowercase hexadecimal characters>")
    return value


def _validate_id(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _invalid(path, "value is not a closed portable identifier")
    return value


def _validate_schema_ref(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SCHEMA_REF_RE.fullmatch(value) is None:
        _invalid(path, "value is not a closed portable schema reference")
    return value


@dataclass(frozen=True, slots=True)
class ReasonDetail:
    """One typed, hash-stable reason detail (never a display message)."""

    key: str
    value_type: DetailValueType
    value: str | int | bool

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or _DETAIL_KEY_RE.fullmatch(self.key) is None:
            _invalid("reason.details.key", "invalid reason-detail key")
        value_type = _as_enum(
            DetailValueType, self.value_type, "reason.details.valueType"
        )
        object.__setattr__(self, "value_type", value_type)
        if value_type is DetailValueType.TEXT:
            if (
                not isinstance(self.value, str)
                or not self.value
                or len(self.value) > 4096
            ):
                _invalid(
                    "reason.details.value",
                    "TEXT must be a non-empty string of at most 4096 characters",
                )
        elif value_type is DetailValueType.INTEGER:
            if (
                isinstance(self.value, bool)
                or not isinstance(self.value, int)
                or abs(self.value) > _SAFE_INTEGER
            ):
                _invalid(
                    "reason.details.value",
                    "INTEGER must be an interoperable JSON integer",
                )
        elif value_type is DetailValueType.BOOLEAN:
            if not isinstance(self.value, bool):
                _invalid("reason.details.value", "BOOLEAN must be a boolean")
        elif value_type is DetailValueType.DIGEST:
            _validate_digest(self.value, "reason.details.value")
        elif value_type is DetailValueType.ID:
            _validate_id(self.value, "reason.details.value")

    def to_wire(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "valueType": self.value_type.value,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class ReasonProvenance:
    """Exact evidence pointer attached to a stable reason."""

    artifact_type: str
    artifact_id: str
    schema_ref: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.artifact_type, str)
            or _ARTIFACT_TYPE_RE.fullmatch(self.artifact_type) is None
        ):
            _invalid(
                "reason.provenance.artifactType",
                "invalid closed artifact type",
            )
        _validate_id(self.artifact_id, "reason.provenance.artifactId")
        _validate_schema_ref(self.schema_ref, "reason.provenance.schemaRef")
        _validate_digest(self.artifact_sha256, "reason.provenance.artifactSha256")

    def to_wire(self) -> dict[str, Any]:
        return {
            "artifactType": self.artifact_type,
            "artifactId": self.artifact_id,
            "schemaRef": self.schema_ref,
            "artifactSha256": self.artifact_sha256,
        }


def _canonical_unique(
    values: Iterable[Any],
    *,
    path: str,
    wire,
    duplicate_key=None,
) -> tuple[Any, ...]:
    normalized: dict[bytes, tuple[bytes, Any]] = {}
    duplicate_keys: dict[bytes, bytes] = {}
    for value in values:
        try:
            encoded = canonical_json_bytes(wire(value))
        except (AttributeError, TypeError, ValueError) as exc:
            _invalid(path, f"invalid immutable item: {exc}")
        key = duplicate_key(value) if duplicate_key is not None else encoded
        existing = duplicate_keys.get(key)
        if existing is not None and existing != encoded:
            _invalid(path, "two distinct items have the same canonical set key")
        duplicate_keys[key] = encoded
        normalized.setdefault(encoded, (key, value))
    return tuple(
        item[1]
        for item in sorted(normalized.values(), key=lambda entry: (entry[0], entry[1]))
    )


@dataclass(frozen=True, slots=True)
class Reason:
    """Closed operation reason with canonical-set members."""

    code: str
    stage: str
    devices: tuple[str, ...] = ()
    details: tuple[ReasonDetail, ...] = ()
    provenance: tuple[ReasonProvenance, ...] = ()

    def __post_init__(self) -> None:
        expected_stage = _REASON_STAGE_BY_CODE.get(self.code)
        if expected_stage is None:
            _invalid("reason.code", f"unknown closed reason code {self.code!r}")
        if self.stage != expected_stage:
            _invalid(
                "reason.stage",
                f"{self.code} requires stage {expected_stage!r}",
            )

        devices = tuple(self.devices)
        for index, device in enumerate(devices):
            _validate_id(device, f"reason.devices[{index}]")
        devices = tuple(
            sorted(
                set(devices),
                key=lambda item: canonical_json_bytes(item),
            )
        )
        if len(devices) != len(tuple(self.devices)):
            _invalid("reason.devices", "duplicate device identifier")
        object.__setattr__(self, "devices", devices)

        details = tuple(self.details)
        for index, detail in enumerate(details):
            if not isinstance(detail, ReasonDetail):
                _invalid(
                    f"reason.details[{index}]",
                    "expected immutable ReasonDetail",
                )
        detail_keys: set[str] = set()
        for detail in details:
            if detail.key in detail_keys:
                _invalid("reason.details", "duplicate detail key")
            detail_keys.add(detail.key)
        object.__setattr__(
            self,
            "details",
            _canonical_unique(
                details,
                path="reason.details",
                wire=lambda item: [
                    item.key,
                    item.value_type.value,
                    item.value,
                ],
            ),
        )

        provenance = tuple(self.provenance)
        for index, item in enumerate(provenance):
            if not isinstance(item, ReasonProvenance):
                _invalid(
                    f"reason.provenance[{index}]",
                    "expected immutable ReasonProvenance",
                )
        object.__setattr__(
            self,
            "provenance",
            _canonical_unique(
                provenance,
                path="reason.provenance",
                wire=lambda item: [
                    item.artifact_type,
                    item.artifact_id,
                    item.schema_ref,
                    item.artifact_sha256,
                ],
            ),
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "devices": list(self.devices),
            "details": [item.to_wire() for item in self.details],
            "provenance": [item.to_wire() for item in self.provenance],
        }


def _reason_set(values: Iterable[Reason], path: str) -> tuple[Reason, ...]:
    reasons = tuple(values)
    for index, reason in enumerate(reasons):
        if not isinstance(reason, Reason):
            _invalid(f"{path}[{index}]", "expected immutable Reason")
    return _canonical_unique(
        reasons,
        path=path,
        wire=lambda reason: reason.to_wire(),
        duplicate_key=lambda reason: canonical_json_bytes(
            [reason.stage, reason.code, list(reason.devices)]
        ),
    )


@dataclass(frozen=True, slots=True)
class GateAssessment:
    """One explicit immutable fact assessment and its stable explanation."""

    state: TriState
    reasons: tuple[Reason, ...] = ()

    def __post_init__(self) -> None:
        state = _as_enum(TriState, self.state, "gate.state")
        object.__setattr__(self, "state", state)
        reasons = _reason_set(self.reasons, "gate.reasons")
        object.__setattr__(self, "reasons", reasons)
        if state is TriState.YES and reasons:
            _invalid("gate.reasons", "a YES gate cannot have blocking reasons")
        if state is not TriState.YES and not reasons:
            _invalid(
                "gate.reasons",
                "a NO or UNKNOWN gate requires at least one stable reason",
            )

    @classmethod
    def yes(cls) -> "GateAssessment":
        return cls(TriState.YES)

    @classmethod
    def no(cls, *reasons: Reason) -> "GateAssessment":
        return cls(TriState.NO, tuple(reasons))

    @classmethod
    def unknown(cls, *reasons: Reason) -> "GateAssessment":
        return cls(TriState.UNKNOWN, tuple(reasons))


@dataclass(frozen=True, slots=True)
class DocumentReference:
    """Closed immutable document reference used by the OP payload."""

    document_kind: str
    document_id: str
    document_version: int
    schema_ref: str
    content_hash: str

    def __post_init__(self) -> None:
        if self.document_kind not in {"DEPENDENCY_BUNDLE", "RESET_CONTRACT"}:
            _invalid(
                "document.documentKind",
                "capability core accepts only dependency-bundle and reset-contract refs",
            )
        _validate_id(self.document_id, "document.documentId")
        if (
            isinstance(self.document_version, bool)
            or not isinstance(self.document_version, int)
            or not 1 <= self.document_version <= _SAFE_INTEGER
        ):
            _invalid("document.documentVersion", "expected a positive safe integer")
        _validate_schema_ref(self.schema_ref, "document.schemaRef")
        _validate_digest(self.content_hash, "document.contentHash")

    def to_wire(self) -> dict[str, Any]:
        return {
            "documentKind": self.document_kind,
            "documentId": self.document_id,
            "documentVersion": self.document_version,
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": self.schema_ref,
            "contentHash": self.content_hash,
        }


@dataclass(frozen=True, slots=True)
class CapabilityInput:
    """All pinned inputs needed for one side-effect-free evaluation."""

    evaluation_context: EvaluationContext
    operation_context: OperationContext
    policy_mode: PolicyMode
    admission_requirement: AdmissionRequirement
    request_hash: str
    closure_request_hash: str
    snapshot_epoch: int
    snapshot_semantic_hash: str
    policy_hash: str
    profile_hash: str
    profile_semantic_hash: str
    bundle: DocumentReference
    reset_contract: DocumentReference
    resource_plan_hash: str | None
    hardware: GateAssessment
    technical: GateAssessment | None
    qualification: GateAssessment
    catalog_support: GateAssessment
    policy_gate: GateAssessment
    lab_policy_gate: GateAssessment | None
    admin_gate: GateAssessment
    owner_active_gate: GateAssessment
    availability_gate: GateAssessment
    current_request_gate: GateAssessment | None
    warnings: tuple[Reason, ...] = ()

    def __post_init__(self) -> None:
        evaluation_context = _as_enum(
            EvaluationContext,
            self.evaluation_context,
            "input.evaluationContext",
        )
        operation_context = _as_enum(
            OperationContext,
            self.operation_context,
            "input.operationContext",
        )
        policy_mode = _as_enum(PolicyMode, self.policy_mode, "input.policyMode")
        admission_requirement = _as_enum(
            AdmissionRequirement,
            self.admission_requirement,
            "input.admissionRequirement",
        )
        object.__setattr__(self, "evaluation_context", evaluation_context)
        object.__setattr__(self, "operation_context", operation_context)
        object.__setattr__(self, "policy_mode", policy_mode)
        object.__setattr__(self, "admission_requirement", admission_requirement)

        _validate_digest(self.request_hash, "input.requestHash")
        _validate_digest(
            self.closure_request_hash,
            "input.closureRequestHash",
        )
        if (
            isinstance(self.snapshot_epoch, bool)
            or not isinstance(self.snapshot_epoch, int)
            or self.snapshot_epoch < 1
            or self.snapshot_epoch > _SAFE_INTEGER
        ):
            _invalid("input.snapshotEpoch", "expected a positive safe integer")
        _validate_digest(self.snapshot_semantic_hash, "input.snapshotSemanticHash")
        _validate_digest(self.policy_hash, "input.policyHash")
        _validate_digest(self.profile_hash, "input.profileHash")
        _validate_digest(self.profile_semantic_hash, "input.profileSemanticHash")
        if self.resource_plan_hash is not None:
            _validate_digest(self.resource_plan_hash, "input.resourcePlanHash")

        if not isinstance(self.bundle, DocumentReference):
            _invalid("input.bundle", "expected immutable DocumentReference")
        if self.bundle.document_kind != "DEPENDENCY_BUNDLE":
            _invalid("input.bundle", "expected DEPENDENCY_BUNDLE reference")
        if not isinstance(self.reset_contract, DocumentReference):
            _invalid(
                "input.resetContract",
                "expected immutable DocumentReference",
            )
        if self.reset_contract.document_kind != "RESET_CONTRACT":
            _invalid("input.resetContract", "expected RESET_CONTRACT reference")

        assessment_fields = (
            "hardware",
            "qualification",
            "catalog_support",
            "policy_gate",
            "admin_gate",
            "owner_active_gate",
            "availability_gate",
        )
        for field_name in assessment_fields:
            if not isinstance(getattr(self, field_name), GateAssessment):
                _invalid(
                    f"input.{field_name}",
                    "expected immutable GateAssessment",
                )

        if evaluation_context is EvaluationContext.HOST_ONLY:
            if self.technical is not None:
                _invalid(
                    "input.technical",
                    "HOST_ONLY requires technical=None",
                )
            if self.current_request_gate is not None:
                _invalid(
                    "input.currentRequestGate",
                    "HOST_ONLY has no current VM request gate",
                )
            if self.resource_plan_hash is not None:
                _invalid(
                    "input.resourcePlanHash",
                    "HOST_ONLY cannot bind a VM resource plan",
                )
        else:
            if not isinstance(self.technical, GateAssessment):
                _invalid(
                    "input.technical",
                    "VM_REQUEST requires an explicit technical assessment",
                )
            if not isinstance(self.current_request_gate, GateAssessment):
                _invalid(
                    "input.currentRequestGate",
                    "VM_REQUEST requires an explicit current-request assessment",
                )
            if self.technical.state is TriState.YES and self.resource_plan_hash is None:
                _invalid(
                    "input.resourcePlanHash",
                    "a technically attachable VM request must bind its resource plan",
                )

        if policy_mode is PolicyMode.PRODUCTION:
            if admission_requirement is not AdmissionRequirement.SUPPORTED:
                _invalid(
                    "input.admissionRequirement",
                    "PRODUCTION requires the SUPPORTED tier",
                )
            if self.lab_policy_gate is not None:
                _invalid(
                    "input.labPolicyGate",
                    "PRODUCTION cannot use a lab-policy override",
                )
        else:
            if not isinstance(self.lab_policy_gate, GateAssessment):
                _invalid(
                    "input.labPolicyGate",
                    "isolated unqualified lab mode requires an explicit lab gate",
                )

        object.__setattr__(
            self, "warnings", _reason_set(self.warnings, "input.warnings")
        )


@dataclass(frozen=True, slots=True)
class CapabilityStates:
    """Tri-state internal result retained for the operation projection."""

    hardware_capable: TriState
    technically_attachable: TriState
    qualified: TriState
    supported: TriState
    policy_eligible: TriState
    admin_enabled: TriState
    host_active: TriState
    available: TriState
    attachable: TriState
    eligible: TriState


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    """Closed immutable capability-decision hash subject."""

    evaluation_context: EvaluationContext
    policy_mode: PolicyMode
    request_hash: str
    snapshot_epoch: int
    policy_hash: str
    profile_hash: str
    bundle_hash: str | None
    resource_plan_hash: str | None
    hardware_capable: bool
    technically_attachable: bool | None
    qualified: bool
    supported: bool
    policy_eligible: bool
    admin_enabled: bool
    host_active: bool
    available: bool
    attachable: bool
    eligible: bool
    reasons: tuple[Reason, ...]
    warnings: tuple[Reason, ...]
    decision_hash: str

    def __post_init__(self) -> None:
        if self.eligible != self.attachable:
            _invalid("decision.eligible", "eligible must equal attachable")
        if self.evaluation_context is EvaluationContext.HOST_ONLY:
            if self.technically_attachable is not None:
                _invalid(
                    "decision.technicallyAttachable",
                    "HOST_ONLY requires null",
                )
            if self.attachable:
                _invalid("decision.attachable", "HOST_ONLY cannot attach")
        elif not isinstance(self.technically_attachable, bool):
            _invalid(
                "decision.technicallyAttachable",
                "VM_REQUEST requires a boolean",
            )
        implications = (
            (self.qualified, self.hardware_capable, "qualified"),
            (self.supported, self.qualified, "supported"),
            (self.policy_eligible, self.hardware_capable, "policyEligible"),
            (self.admin_enabled, self.policy_eligible, "adminEnabled"),
            (self.host_active, self.admin_enabled, "hostActive"),
            (self.available, self.host_active, "available"),
            (self.attachable, self.available, "attachable"),
        )
        for antecedent, consequent, field_name in implications:
            if antecedent and not consequent:
                _invalid(
                    f"decision.{field_name}",
                    "derived capability implication is violated",
                )
        if (
            self.policy_mode is PolicyMode.PRODUCTION
            and self.policy_eligible
            and not self.supported
        ):
            _invalid(
                "decision.policyEligible",
                "production policy eligibility requires support",
            )
        _validate_digest(self.decision_hash, "decision.decisionHash")
        expected = sha256_digest(canonical_json_bytes(self._wire(decision_hash=None)))
        if expected != self.decision_hash:
            _invalid(
                "decision.decisionHash",
                "digest does not match the null-hash canonical subject",
            )

    def _wire(self, *, decision_hash: str | None) -> dict[str, Any]:
        return {
            "subjectType": "CAPABILITY_DECISION",
            "schemaVersion": 1,
            "evaluationContext": self.evaluation_context.value,
            "admissionMode": self.policy_mode.value,
            "requestHash": self.request_hash,
            "snapshotEpoch": self.snapshot_epoch,
            "policyHash": self.policy_hash,
            "profileHash": self.profile_hash,
            "bundleHashOrNull": self.bundle_hash,
            "resourcePlanHashOrNull": self.resource_plan_hash,
            "hardwareCapable": self.hardware_capable,
            "technicallyAttachable": self.technically_attachable,
            "qualified": self.qualified,
            "supported": self.supported,
            "policyEligible": self.policy_eligible,
            "adminEnabled": self.admin_enabled,
            "hostActive": self.host_active,
            "available": self.available,
            "attachable": self.attachable,
            "eligible": self.eligible,
            "reasons": [reason.to_wire() for reason in self.reasons],
            "warnings": [warning.to_wire() for warning in self.warnings],
            "decisionHash": decision_hash,
        }

    def to_wire(self) -> dict[str, Any]:
        """Return a fresh closed JSON-compatible decision projection."""

        return self._wire(decision_hash=self.decision_hash)


@dataclass(frozen=True, slots=True)
class CapabilityEvaluation:
    """Both projections plus the owner-independent semantic cache key."""

    decision: CapabilityDecision
    states: CapabilityStates
    operation_context: OperationContext
    admission_requirement: AdmissionRequirement
    bundle: DocumentReference
    reset_contract: DocumentReference
    snapshot_semantic_hash: str
    profile_semantic_hash: str
    semantic_hash: str

    def to_wire(self) -> dict[str, Any]:
        return self.decision.to_wire()

    def to_operation_payload(self) -> dict[str, Any]:
        """Return the closed OP-EVALUATE-CAPABILITY output projection."""

        return {
            "evaluationContext": self.operation_context.value,
            "admissionMode": self.admission_requirement.value,
            "hardwareCapable": self.states.hardware_capable.value,
            "technicallyAttachable": self.states.technically_attachable.value,
            "policyEligible": self.states.policy_eligible.value,
            "adminEnabled": self.states.admin_enabled.value,
            "hostActive": self.states.host_active.value,
            "available": self.states.available.value,
            "attachable": self.states.attachable.value,
            "eligible": self.states.eligible.value,
            "qualified": self.states.qualified.value,
            "supported": self.states.supported.value,
            "completeBundle": self.bundle.to_wire(),
            "resetContract": self.reset_contract.to_wire(),
            "reasons": [reason.to_wire() for reason in self.decision.reasons],
        }


def _tri_and(*values: TriState) -> TriState:
    if any(value is TriState.NO for value in values):
        return TriState.NO
    if all(value is TriState.YES for value in values):
        return TriState.YES
    return TriState.UNKNOWN


def _all_reasons(source: CapabilityInput) -> tuple[Reason, ...]:
    assessments: list[GateAssessment] = [
        source.hardware,
        source.qualification,
        source.catalog_support,
        source.policy_gate,
        source.admin_gate,
        source.owner_active_gate,
        source.availability_gate,
    ]
    if source.technical is not None:
        assessments.append(source.technical)
    if source.lab_policy_gate is not None:
        assessments.append(source.lab_policy_gate)
    if source.current_request_gate is not None:
        assessments.append(source.current_request_gate)
    return _reason_set(
        (reason for assessment in assessments for reason in assessment.reasons),
        "evaluation.reasons",
    )


def _semantic_reasons(source: CapabilityInput) -> tuple[Reason, ...]:
    assessments: list[GateAssessment] = [
        source.hardware,
        source.qualification,
        source.catalog_support,
        source.policy_gate,
    ]
    if source.technical is not None:
        assessments.append(source.technical)
    if source.lab_policy_gate is not None:
        assessments.append(source.lab_policy_gate)
    return _reason_set(
        (reason for assessment in assessments for reason in assessment.reasons),
        "evaluation.semanticReasons",
    )


def evaluate_capability(source: CapabilityInput) -> CapabilityEvaluation:
    """Evaluate one immutable input without observable side effects."""

    hardware = source.hardware.state
    if source.evaluation_context is EvaluationContext.HOST_ONLY:
        technical = TriState.UNKNOWN
    else:
        assert source.technical is not None
        technical = _tri_and(hardware, source.technical.state)

    qualified = _tri_and(hardware, source.qualification.state)
    supported = _tri_and(qualified, source.catalog_support.state)

    if source.admission_requirement is AdmissionRequirement.TECHNICAL:
        required_tier = TriState.YES
    elif source.admission_requirement is AdmissionRequirement.QUALIFIED:
        required_tier = qualified
    else:
        required_tier = supported

    policy_terms = [hardware, source.policy_gate.state, required_tier]
    if source.policy_mode is PolicyMode.ISOLATED_UNQUALIFIED_LAB:
        assert source.lab_policy_gate is not None
        policy_terms.append(source.lab_policy_gate.state)
    policy_eligible = _tri_and(*policy_terms)

    admin_enabled = _tri_and(policy_eligible, source.admin_gate.state)
    host_active = _tri_and(admin_enabled, source.owner_active_gate.state)
    available = _tri_and(host_active, source.availability_gate.state)

    if source.evaluation_context is EvaluationContext.HOST_ONLY:
        attachable_state = TriState.UNKNOWN
    else:
        assert source.current_request_gate is not None
        attachable_state = _tri_and(
            technical,
            policy_eligible,
            admin_enabled,
            host_active,
            available,
            source.current_request_gate.state,
        )
    eligible_state = attachable_state

    states = CapabilityStates(
        hardware_capable=hardware,
        technically_attachable=technical,
        qualified=qualified,
        supported=supported,
        policy_eligible=policy_eligible,
        admin_enabled=admin_enabled,
        host_active=host_active,
        available=available,
        attachable=attachable_state,
        eligible=eligible_state,
    )

    reasons = _all_reasons(source)
    semantic_reasons = _semantic_reasons(source)
    semantic_subject = {
        "subjectType": "CAPABILITY_SEMANTICS_PREMISE",
        "schemaVersion": 1,
        "evaluationContext": source.evaluation_context.value,
        "operationContext": source.operation_context.value,
        "policyMode": source.policy_mode.value,
        "admissionRequirement": source.admission_requirement.value,
        "requestHash": source.request_hash,
        "closureRequestHash": source.closure_request_hash,
        "snapshotSemanticHash": source.snapshot_semantic_hash,
        "policyHash": source.policy_hash,
        "profileSemanticHash": source.profile_semantic_hash,
        "bundleHash": source.bundle.content_hash,
        "resetContractHash": source.reset_contract.content_hash,
        "resourcePlanHashOrNull": source.resource_plan_hash,
        "rawAssessments": {
            "hardware": source.hardware.state.value,
            "technical": (
                None if source.technical is None else source.technical.state.value
            ),
            "qualification": source.qualification.state.value,
            "catalogSupport": source.catalog_support.state.value,
            "policy": source.policy_gate.state.value,
            "labPolicy": (
                None
                if source.lab_policy_gate is None
                else source.lab_policy_gate.state.value
            ),
        },
        "derivedSemantics": {
            "hardwareCapable": hardware.value,
            "technicallyAttachable": technical.value,
            "qualified": qualified.value,
            "supported": supported.value,
            "policyEligible": policy_eligible.value,
        },
        "reasons": [reason.to_wire() for reason in semantic_reasons],
    }
    semantic_hash = sha256_digest(canonical_json_bytes(semantic_subject))

    wire_without_hash = {
        "subjectType": "CAPABILITY_DECISION",
        "schemaVersion": 1,
        "evaluationContext": source.evaluation_context.value,
        "admissionMode": source.policy_mode.value,
        "requestHash": source.request_hash,
        "snapshotEpoch": source.snapshot_epoch,
        "policyHash": source.policy_hash,
        "profileHash": source.profile_hash,
        "bundleHashOrNull": source.bundle.content_hash,
        "resourcePlanHashOrNull": source.resource_plan_hash,
        "hardwareCapable": hardware.fail_closed_bool,
        "technicallyAttachable": (
            None
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else technical.fail_closed_bool
        ),
        "qualified": qualified.fail_closed_bool,
        "supported": supported.fail_closed_bool,
        "policyEligible": policy_eligible.fail_closed_bool,
        "adminEnabled": admin_enabled.fail_closed_bool,
        "hostActive": host_active.fail_closed_bool,
        "available": available.fail_closed_bool,
        "attachable": (
            False
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else attachable_state.fail_closed_bool
        ),
        "eligible": (
            False
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else eligible_state.fail_closed_bool
        ),
        "reasons": [reason.to_wire() for reason in reasons],
        "warnings": [warning.to_wire() for warning in source.warnings],
        "decisionHash": None,
    }
    decision_hash = sha256_digest(canonical_json_bytes(wire_without_hash))

    decision = CapabilityDecision(
        evaluation_context=source.evaluation_context,
        policy_mode=source.policy_mode,
        request_hash=source.request_hash,
        snapshot_epoch=source.snapshot_epoch,
        policy_hash=source.policy_hash,
        profile_hash=source.profile_hash,
        bundle_hash=source.bundle.content_hash,
        resource_plan_hash=source.resource_plan_hash,
        hardware_capable=hardware.fail_closed_bool,
        technically_attachable=(
            None
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else technical.fail_closed_bool
        ),
        qualified=qualified.fail_closed_bool,
        supported=supported.fail_closed_bool,
        policy_eligible=policy_eligible.fail_closed_bool,
        admin_enabled=admin_enabled.fail_closed_bool,
        host_active=host_active.fail_closed_bool,
        available=available.fail_closed_bool,
        attachable=(
            False
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else attachable_state.fail_closed_bool
        ),
        eligible=(
            False
            if source.evaluation_context is EvaluationContext.HOST_ONLY
            else eligible_state.fail_closed_bool
        ),
        reasons=reasons,
        warnings=source.warnings,
        decision_hash=decision_hash,
    )
    return CapabilityEvaluation(
        decision=decision,
        states=states,
        operation_context=source.operation_context,
        admission_requirement=source.admission_requirement,
        bundle=source.bundle,
        reset_contract=source.reset_contract,
        snapshot_semantic_hash=source.snapshot_semantic_hash,
        profile_semantic_hash=source.profile_semantic_hash,
        semantic_hash=semantic_hash,
    )


__all__ = [
    "AdmissionRequirement",
    "CapabilityDecision",
    "CapabilityEvaluation",
    "CapabilityInput",
    "CapabilityStates",
    "DetailValueType",
    "DocumentReference",
    "EvaluationContext",
    "GateAssessment",
    "OperationContext",
    "PolicyMode",
    "Reason",
    "ReasonDetail",
    "ReasonProvenance",
    "TriState",
    "evaluate_capability",
]
