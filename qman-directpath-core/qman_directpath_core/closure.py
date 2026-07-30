"""Bounded, side-effect-free dependency and reset closure.

The public input type is :class:`VerifiedClosureFacts`, not a raw inventory
DTO.  A product adapter must construct it only after it has authenticated one
immutable HostSnapshot, every referenced DeviceRecord, and the retained fact
receipt.  Shape validation in this module is deliberately not an authenticity
claim: a fixture carrying plausible digests remains fixture evidence.

The resolver performs no I/O and accepts no provider callback.  It expands the
seven closed dependency-domain kinds to a deterministic fixed point, selects a
reset contract only for members whose resolved primary action is ``PAYLOAD``,
and adds reset-affected peers as ``LEASE_ONLY``.  A reset-only peer therefore
does not recursively select an unrelated reset contract unless an independent
verified dependency fact promotes that peer to ``PAYLOAD``.

Successful results contain the exact portable ``dependencyBundle`` hash
subject plus the selected source reset-contract digests and a canonical reset
contract-set digest.  This is a portable component premise; it is not evidence
that a production inventory provider, signer, external authority, Qman
repository, or physical device path exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable

from .canonical import SAFE_INTEGER, canonical_json_bytes, sha256_digest
from .capability import (
    DetailValueType,
    DocumentReference,
    Reason,
    ReasonDetail,
    ReasonProvenance,
)
from .errors import fail


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
MAX_CLOSURE_DEVICES = 4096
MAX_CLOSURE_EDGES = 65536
DEPENDENCY_BUNDLE_SCHEMA_REF = (
    "contracts/directpath-portable-hash-subjects.schema.json#/$defs/dependencyBundle"
)
RESET_CONTRACT_SET_SCHEMA_REF = "contracts/directpath-reset-contract-set.schema.json"
CLOSURE_REQUEST_SCHEMA_REF = (
    "contracts/directpath-dependency-closure-request.schema.json"
)


class DependencyKind(str, Enum):
    """Closed owner-independent dependency domains."""

    IOMMU = "IOMMU"
    PHYSICAL_ISOLATION = "PHYSICAL_ISOLATION"
    REQUESTER_ALIAS = "REQUESTER_ALIAS"
    MULTIFUNCTION = "MULTIFUNCTION"
    PF_VF = "PF_VF"
    FUNCTIONAL = "FUNCTIONAL"
    PLATFORM = "PLATFORM"


class FactState(str, Enum):
    """Completeness state of an authenticated retained fact."""

    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


class DependencyAction(str, Enum):
    """The exact dependencyBundle wire actions."""

    PAYLOAD = "PAYLOAD"
    LEASE_ONLY = "LEASE_ONLY"
    DETACH = "DETACH"
    RESET_WITH = "RESET_WITH"
    RESTORE_OWNER = "RESTORE_OWNER"
    DENY_IF_PRESENT = "DENY_IF_PRESENT"


class ResetMethod(str, Enum):
    """The exact DeviceRecord reset-method enumeration."""

    PCI_FLR = "PCI_FLR"
    VFIO_DEVICE_RESET = "VFIO_DEVICE_RESET"
    VFIO_HOT_RESET = "VFIO_HOT_RESET"
    SECONDARY_BUS_RESET = "SECONDARY_BUS_RESET"
    PM_RESET = "PM_RESET"
    VENDOR_QUALIFIED_RESET = "VENDOR_QUALIFIED_RESET"


_REQUIRED_DOMAIN_KINDS = tuple(DependencyKind)
_PRIMARY_ACTION_RANK = {
    DependencyAction.LEASE_ONLY: 0,
    DependencyAction.DETACH: 1,
    DependencyAction.PAYLOAD: 2,
}
_AUXILIARY_ACTIONS = {
    DependencyAction.RESET_WITH,
    DependencyAction.RESTORE_OWNER,
}


def _invalid(path: str, message: str) -> None:
    fail("CAPABILITY_INPUT_INVALID", path, message)


def _enum(enum_type: type[Enum], value: object, path: str):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        _invalid(path, f"expected a closed {enum_type.__name__} value")


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _invalid(path, "expected sha256:<64 lowercase hex>")
    return value


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _invalid(path, "expected a closed portable identifier")
    return value


def _positive(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= SAFE_INTEGER
    ):
        _invalid(path, "expected an interoperable-safe positive integer")
    return value


def _canonical_values(
    values: Iterable[object],
    *,
    path: str,
    wire,
) -> tuple[object, ...]:
    result = tuple(values)
    encoded = tuple(canonical_json_bytes(wire(value)) for value in result)
    if len(set(encoded)) != len(encoded):
        _invalid(path, "canonical set contains a duplicate")
    expected = tuple(
        value
        for _, value in sorted(
            zip(encoded, result, strict=True),
            key=lambda item: item[0],
        )
    )
    if result != expected:
        _invalid(path, "set is not in CANONICAL-JSON-V1 order")
    return result


def _canonical_id_set(
    values: Iterable[str],
    *,
    path: str,
) -> tuple[str, ...]:
    result = tuple(values)
    for index, value in enumerate(result):
        _identifier(value, f"{path}[{index}]")
    return tuple(
        _canonical_values(
            result,
            path=path,
            wire=lambda value: value,
        )
    )


def _sorted_ids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=lambda value: canonical_json_bytes(value)))


@dataclass(frozen=True, slots=True)
class VerifiedDependencyEdge:
    """One retained member-action fact inside a complete domain fact."""

    target_device_uid: str
    action_state: FactState
    required_action: DependencyAction | None
    provenance_digest: str

    def __post_init__(self) -> None:
        _identifier(self.target_device_uid, "edge.target_device_uid")
        state = _enum(FactState, self.action_state, "edge.action_state")
        object.__setattr__(self, "action_state", state)
        _digest(self.provenance_digest, "edge.provenance_digest")
        if state is FactState.KNOWN:
            if self.required_action is None:
                _invalid(
                    "edge.required_action",
                    "a KNOWN action fact requires a closed action",
                )
            action = _enum(
                DependencyAction,
                self.required_action,
                "edge.required_action",
            )
            object.__setattr__(self, "required_action", action)
        elif self.required_action is not None:
            _invalid(
                "edge.required_action",
                "UNKNOWN or CONFLICT action fact must not guess an action",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "targetDeviceUid": self.target_device_uid,
            "actionState": self.action_state.value,
            "requiredActionOrNull": (
                None if self.required_action is None else self.required_action.value
            ),
            "provenanceDigest": self.provenance_digest,
        }


@dataclass(frozen=True, slots=True)
class VerifiedDependencyDomain:
    """One explicit complete, unknown, or conflicting dependency domain."""

    kind: DependencyKind
    state: FactState
    provenance_digest: str
    edges: tuple[VerifiedDependencyEdge, ...] = ()

    def __post_init__(self) -> None:
        kind = _enum(DependencyKind, self.kind, "domain.kind")
        state = _enum(FactState, self.state, "domain.state")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "state", state)
        _digest(self.provenance_digest, "domain.provenance_digest")
        edges = tuple(self.edges)
        for index, edge in enumerate(edges):
            if not isinstance(edge, VerifiedDependencyEdge):
                _invalid(
                    f"domain.edges[{index}]",
                    "expected VerifiedDependencyEdge",
                )
        edges = tuple(
            _canonical_values(
                edges,
                path="domain.edges",
                wire=lambda edge: edge.to_subject(),
            )
        )
        object.__setattr__(self, "edges", edges)
        if state is not FactState.KNOWN and edges:
            _invalid(
                "domain.edges",
                "UNKNOWN or CONFLICT domain cannot publish guessed members",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "state": self.state.value,
            "provenanceDigest": self.provenance_digest,
            "edges": [edge.to_subject() for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class VerifiedResetContract:
    """One authenticated reset fact retained in the selected DeviceRecord."""

    state: FactState
    supported: bool
    selected_method: ResetMethod | None
    affected_device_uids: tuple[str, ...]
    contract_digest: str
    provenance_digest: str

    def __post_init__(self) -> None:
        state = _enum(FactState, self.state, "reset.state")
        object.__setattr__(self, "state", state)
        if not isinstance(self.supported, bool):
            _invalid("reset.supported", "expected a boolean")
        affected = _canonical_id_set(
            self.affected_device_uids,
            path="reset.affected_device_uids",
        )
        if state is FactState.KNOWN and not affected:
            _invalid(
                "reset.affected_device_uids",
                "a KNOWN reset affected set must be non-empty",
            )
        if state is not FactState.KNOWN and affected:
            _invalid(
                "reset.affected_device_uids",
                "UNKNOWN or CONFLICT reset cannot guess affected members",
            )
        object.__setattr__(self, "affected_device_uids", affected)
        _digest(self.contract_digest, "reset.contract_digest")
        _digest(self.provenance_digest, "reset.provenance_digest")
        if state is FactState.KNOWN and self.supported:
            if self.selected_method is None:
                _invalid(
                    "reset.selected_method",
                    "a supported known reset requires a method",
                )
            method = _enum(
                ResetMethod,
                self.selected_method,
                "reset.selected_method",
            )
            object.__setattr__(self, "selected_method", method)
        elif self.selected_method is not None:
            _invalid(
                "reset.selected_method",
                "unsupported or non-KNOWN reset must not select a method",
            )
        if state is not FactState.KNOWN and self.supported:
            _invalid(
                "reset.supported",
                "UNKNOWN or CONFLICT reset cannot be supported",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "supported": self.supported,
            "selectedMethodOrNull": (
                None if self.selected_method is None else self.selected_method.value
            ),
            "affectedDeviceUids": list(self.affected_device_uids),
            "contractDigest": self.contract_digest,
            "provenanceDigest": self.provenance_digest,
        }


@dataclass(frozen=True, slots=True)
class VerifiedDeviceFacts:
    """Closed dependency/reset projection from one authenticated DeviceRecord."""

    device_uid: str
    device_record_digest: str
    device_generation: int
    resource_version: int
    domains: tuple[VerifiedDependencyDomain, ...]
    reset_contract: VerifiedResetContract

    def __post_init__(self) -> None:
        _identifier(self.device_uid, "device.device_uid")
        _digest(self.device_record_digest, "device.device_record_digest")
        _positive(
            self.device_generation,
            "device.device_generation",
        )
        _positive(
            self.resource_version,
            "device.resource_version",
        )
        domains = tuple(self.domains)
        for index, domain in enumerate(domains):
            if not isinstance(domain, VerifiedDependencyDomain):
                _invalid(
                    f"device.domains[{index}]",
                    "expected VerifiedDependencyDomain",
                )
        domains = tuple(
            _canonical_values(
                domains,
                path="device.domains",
                wire=lambda domain: domain.kind.value,
            )
        )
        kinds = tuple(domain.kind for domain in domains)
        if kinds != tuple(
            sorted(
                _REQUIRED_DOMAIN_KINDS,
                key=lambda kind: canonical_json_bytes(kind.value),
            )
        ):
            _invalid(
                "device.domains",
                "every closed dependency kind must appear exactly once",
            )
        object.__setattr__(self, "domains", domains)
        if not isinstance(self.reset_contract, VerifiedResetContract):
            _invalid(
                "device.reset_contract",
                "expected VerifiedResetContract",
            )
        for domain in domains:
            if (
                domain.kind
                in {
                    DependencyKind.IOMMU,
                    DependencyKind.PHYSICAL_ISOLATION,
                }
                and domain.state is FactState.KNOWN
                and not any(
                    edge.target_device_uid == self.device_uid for edge in domain.edges
                )
            ):
                _invalid(
                    "device.domains",
                    (
                        f"KNOWN {domain.kind.value} domain must explicitly "
                        "contain its source member"
                    ),
                )

    def to_subject(self) -> dict[str, object]:
        return {
            "deviceUid": self.device_uid,
            "deviceRecordDigest": self.device_record_digest,
            "deviceGeneration": self.device_generation,
            "resourceVersion": self.resource_version,
            "domains": [domain.to_subject() for domain in self.domains],
            "resetContract": self.reset_contract.to_subject(),
        }

    def to_semantic_subject(self) -> dict[str, object]:
        """Return owner-independent facts without exact record identity."""

        return {
            "deviceUid": self.device_uid,
            "domains": [domain.to_subject() for domain in self.domains],
            "resetContract": self.reset_contract.to_subject(),
        }


@dataclass(frozen=True, slots=True)
class VerifiedClosureFacts:
    """Authenticated immutable input boundary for the pure resolver.

    The resolver validates this projection's shape and deterministic digest.
    It cannot prove that the receipt came from a real inventory verifier.  A
    product integration must create this value only from a verified current
    HostSnapshot and must bind ``snapshot_digest`` and
    ``inventory_verification_receipt_digest`` into its current-authority
    guard.
    """

    snapshot_epoch: int
    snapshot_digest: str
    inventory_verification_receipt_digest: str
    inventory_verifier_identity_digest: str
    request_provenance_digest: str
    policy_provenance_digest: str
    devices: tuple[VerifiedDeviceFacts, ...]

    def __post_init__(self) -> None:
        _positive(self.snapshot_epoch, "facts.snapshot_epoch")
        for field_name in (
            "snapshot_digest",
            "inventory_verification_receipt_digest",
            "inventory_verifier_identity_digest",
            "request_provenance_digest",
            "policy_provenance_digest",
        ):
            _digest(getattr(self, field_name), f"facts.{field_name}")
        devices = tuple(self.devices)
        for index, device in enumerate(devices):
            if not isinstance(device, VerifiedDeviceFacts):
                _invalid(
                    f"facts.devices[{index}]",
                    "expected VerifiedDeviceFacts",
                )
        devices = tuple(
            _canonical_values(
                devices,
                path="facts.devices",
                wire=lambda device: device.device_uid,
            )
        )
        object.__setattr__(self, "devices", devices)

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "VERIFIED_CLOSURE_FACTS",
            "schemaVersion": 1,
            "snapshotEpoch": self.snapshot_epoch,
            "snapshotDigest": self.snapshot_digest,
            "inventoryVerificationReceiptDigest": (
                self.inventory_verification_receipt_digest
            ),
            "inventoryVerifierIdentityDigest": (
                self.inventory_verifier_identity_digest
            ),
            "requestProvenanceDigest": self.request_provenance_digest,
            "policyProvenanceDigest": self.policy_provenance_digest,
            "devices": [device.to_subject() for device in self.devices],
        }

    @property
    def facts_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_subject()))

    @property
    def hardware_semantic_digest(self) -> str:
        subject = {
            "subjectType": "CLOSURE_HARDWARE_SEMANTICS",
            "schemaVersion": 1,
            "inventoryVerifierIdentityDigest": (
                self.inventory_verifier_identity_digest
            ),
            "devices": [device.to_semantic_subject() for device in self.devices],
        }
        return sha256_digest(canonical_json_bytes(subject))


@dataclass(frozen=True, slots=True)
class ClosureLimits:
    """Qualified deterministic safety limits."""

    max_devices: int = 256
    max_edges: int = 4096

    def __post_init__(self) -> None:
        _positive(self.max_devices, "limits.max_devices")
        _positive(self.max_edges, "limits.max_edges")
        if self.max_devices > MAX_CLOSURE_DEVICES:
            _invalid(
                "limits.max_devices",
                (
                    "configured limit exceeds portable hard ceiling "
                    f"{MAX_CLOSURE_DEVICES}"
                ),
            )
        if self.max_edges > MAX_CLOSURE_EDGES:
            _invalid(
                "limits.max_edges",
                (f"configured limit exceeds portable hard ceiling {MAX_CLOSURE_EDGES}"),
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "maxDevices": self.max_devices,
            "maxEdges": self.max_edges,
        }


@dataclass(frozen=True, slots=True)
class ClosureRequest:
    """Exact roots and approved bounds used for one closure replay.

    The provenance digests bind the roots to the selected request and the
    numeric limits to the selected policy.  A product adapter must derive this
    value from those verified documents; merely copying their digests is not a
    substitute for request/policy schema validation.
    """

    request_provenance_digest: str
    policy_provenance_digest: str
    payload_device_uids: tuple[str, ...]
    limits: ClosureLimits

    def __post_init__(self) -> None:
        _digest(
            self.request_provenance_digest,
            "closure_request.request_provenance_digest",
        )
        _digest(
            self.policy_provenance_digest,
            "closure_request.policy_provenance_digest",
        )
        payload = _canonical_id_set(
            self.payload_device_uids,
            path="closure_request.payload_device_uids",
        )
        if not payload:
            _invalid(
                "closure_request.payload_device_uids",
                "at least one payload is required",
            )
        object.__setattr__(self, "payload_device_uids", payload)
        if not isinstance(self.limits, ClosureLimits):
            _invalid(
                "closure_request.limits",
                "expected ClosureLimits",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "DEPENDENCY_CLOSURE_REQUEST",
            "schemaVersion": 1,
            "requestProvenanceDigest": self.request_provenance_digest,
            "policyProvenanceDigest": self.policy_provenance_digest,
            "payloadDeviceUids": list(self.payload_device_uids),
            "limits": self.limits.to_subject(),
        }

    @property
    def request_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_subject()))


@dataclass(frozen=True, slots=True)
class ResolvedDependencyEdge:
    """One retained edge used by the fixed point and evidence explanation."""

    kind: str
    source_device_uid: str
    target_device_uid: str
    domain_provenance_digest: str
    action_provenance_digest: str
    action_state: FactState
    required_action: DependencyAction | None

    def __post_init__(self) -> None:
        allowed = {kind.value for kind in DependencyKind} | {"RESET"}
        if self.kind not in allowed:
            _invalid("resolved_edge.kind", "unknown resolved dependency kind")
        _identifier(
            self.source_device_uid,
            "resolved_edge.source_device_uid",
        )
        _identifier(
            self.target_device_uid,
            "resolved_edge.target_device_uid",
        )
        _digest(
            self.domain_provenance_digest,
            "resolved_edge.domain_provenance_digest",
        )
        _digest(
            self.action_provenance_digest,
            "resolved_edge.action_provenance_digest",
        )
        state = _enum(
            FactState,
            self.action_state,
            "resolved_edge.action_state",
        )
        object.__setattr__(self, "action_state", state)
        if state is FactState.KNOWN:
            if self.required_action is None:
                _invalid(
                    "resolved_edge.required_action",
                    "KNOWN edge requires an action",
                )
            action = _enum(
                DependencyAction,
                self.required_action,
                "resolved_edge.required_action",
            )
            object.__setattr__(self, "required_action", action)
        elif self.required_action is not None:
            _invalid(
                "resolved_edge.required_action",
                "UNKNOWN or CONFLICT edge must not guess an action",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "sourceDeviceUid": self.source_device_uid,
            "targetDeviceUid": self.target_device_uid,
            "domainProvenanceDigest": self.domain_provenance_digest,
            "actionProvenanceDigest": self.action_provenance_digest,
            "actionState": self.action_state.value,
            "requiredActionOrNull": (
                None if self.required_action is None else self.required_action.value
            ),
        }


@dataclass(frozen=True, slots=True)
class ActionProvenanceSet:
    """Canonical provenance aggregation for one output member/action."""

    device_uid: str
    action: DependencyAction
    source_digests: tuple[str, ...]
    provenance_digest: str

    def __post_init__(self) -> None:
        _identifier(self.device_uid, "action_provenance.device_uid")
        action = _enum(
            DependencyAction,
            self.action,
            "action_provenance.action",
        )
        object.__setattr__(self, "action", action)
        sources = tuple(self.source_digests)
        for index, digest in enumerate(sources):
            _digest(digest, f"action_provenance.source_digests[{index}]")
        sources = tuple(
            _canonical_values(
                sources,
                path="action_provenance.source_digests",
                wire=lambda digest: digest,
            )
        )
        if not sources:
            _invalid(
                "action_provenance.source_digests",
                "at least one retained provenance digest is required",
            )
        object.__setattr__(self, "source_digests", sources)
        _digest(
            self.provenance_digest,
            "action_provenance.provenance_digest",
        )
        expected = sha256_digest(canonical_json_bytes(self.to_subject()))
        if self.provenance_digest != expected:
            _invalid(
                "action_provenance.provenance_digest",
                "digest does not match canonical provenance-set subject",
            )

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "DEPENDENCY_ACTION_PROVENANCE_SET",
            "schemaVersion": 1,
            "deviceUid": self.device_uid,
            "action": self.action.value,
            "sourceDigests": list(self.source_digests),
        }

    @classmethod
    def create(
        cls,
        *,
        device_uid: str,
        action: DependencyAction,
        source_digests: Iterable[str],
    ) -> "ActionProvenanceSet":
        sources = tuple(
            sorted(
                set(source_digests),
                key=lambda digest: canonical_json_bytes(digest),
            )
        )
        subject = {
            "subjectType": "DEPENDENCY_ACTION_PROVENANCE_SET",
            "schemaVersion": 1,
            "deviceUid": device_uid,
            "action": action.value,
            "sourceDigests": list(sources),
        }
        return cls(
            device_uid=device_uid,
            action=action,
            source_digests=sources,
            provenance_digest=sha256_digest(canonical_json_bytes(subject)),
        )


@dataclass(frozen=True, slots=True)
class ResolvedDependencyAction:
    """One exact dependencyBundle action entry."""

    device_uid: str
    action: DependencyAction
    provenance_digest: str

    def __post_init__(self) -> None:
        _identifier(self.device_uid, "resolved_action.device_uid")
        action = _enum(
            DependencyAction,
            self.action,
            "resolved_action.action",
        )
        object.__setattr__(self, "action", action)
        _digest(
            self.provenance_digest,
            "resolved_action.provenance_digest",
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "deviceUid": self.device_uid,
            "action": self.action.value,
            "provenanceDigest": self.provenance_digest,
        }


@dataclass(frozen=True, slots=True)
class ResolvedResetContract:
    """Selected source reset contract bound to its target."""

    target_device_uid: str
    selected_method: ResetMethod
    affected_device_uids: tuple[str, ...]
    contract_digest: str
    provenance_digest: str

    def __post_init__(self) -> None:
        _identifier(
            self.target_device_uid,
            "resolved_reset.target_device_uid",
        )
        method = _enum(
            ResetMethod,
            self.selected_method,
            "resolved_reset.selected_method",
        )
        object.__setattr__(self, "selected_method", method)
        affected = _canonical_id_set(
            self.affected_device_uids,
            path="resolved_reset.affected_device_uids",
        )
        if self.target_device_uid not in affected:
            _invalid(
                "resolved_reset.affected_device_uids",
                "selected reset must include its target",
            )
        object.__setattr__(self, "affected_device_uids", affected)
        _digest(
            self.contract_digest,
            "resolved_reset.contract_digest",
        )
        _digest(
            self.provenance_digest,
            "resolved_reset.provenance_digest",
        )

    def to_subject(self) -> dict[str, object]:
        return {
            "targetDeviceUid": self.target_device_uid,
            "selectedMethod": self.selected_method.value,
            "affectedDeviceUids": list(self.affected_device_uids),
            "contractDigest": self.contract_digest,
            "provenanceDigest": self.provenance_digest,
        }


@dataclass(frozen=True, slots=True)
class ResolvedDependencyBundle:
    """Exact portable dependencyBundle hash subject."""

    snapshot_epoch: int
    member_device_uids: tuple[str, ...]
    physical_isolation_domain: tuple[str, ...]
    owner_activation_group: tuple[str, ...]
    exclusive_attach_group: str
    reset_affected_set: tuple[str, ...]
    dependency_actions: tuple[ResolvedDependencyAction, ...]
    bundle_hash: str

    def __post_init__(self) -> None:
        _positive(self.snapshot_epoch, "bundle.snapshot_epoch")
        for field_name in (
            "member_device_uids",
            "physical_isolation_domain",
            "owner_activation_group",
            "reset_affected_set",
        ):
            values = _canonical_id_set(
                getattr(self, field_name),
                path=f"bundle.{field_name}",
            )
            if not values:
                _invalid(
                    f"bundle.{field_name}",
                    "portable bundle sets must be non-empty",
                )
            object.__setattr__(self, field_name, values)
        _identifier(
            self.exclusive_attach_group,
            "bundle.exclusive_attach_group",
        )
        actions = tuple(self.dependency_actions)
        for index, action in enumerate(actions):
            if not isinstance(action, ResolvedDependencyAction):
                _invalid(
                    f"bundle.dependency_actions[{index}]",
                    "expected ResolvedDependencyAction",
                )
        actions = tuple(
            _canonical_values(
                actions,
                path="bundle.dependency_actions",
                wire=lambda action: [
                    action.device_uid,
                    action.action.value,
                ],
            )
        )
        action_keys = tuple((action.device_uid, action.action) for action in actions)
        if len(set(action_keys)) != len(action_keys):
            _invalid(
                "bundle.dependency_actions",
                "duplicate [deviceUid,action] entry",
            )
        object.__setattr__(self, "dependency_actions", actions)
        _digest(self.bundle_hash, "bundle.bundle_hash")
        expected = sha256_digest(canonical_json_bytes(self._wire(bundle_hash=None)))
        if self.bundle_hash != expected:
            _invalid(
                "bundle.bundle_hash",
                "digest does not match null-hash canonical bundle subject",
            )

    def _wire(self, *, bundle_hash: str | None) -> dict[str, object]:
        return {
            "subjectType": "DEPENDENCY_BUNDLE",
            "schemaVersion": 1,
            "snapshotEpoch": self.snapshot_epoch,
            "memberDeviceUids": list(self.member_device_uids),
            "physicalIsolationDomain": list(self.physical_isolation_domain),
            "ownerActivationGroup": list(self.owner_activation_group),
            "exclusiveAttachGroup": self.exclusive_attach_group,
            "resetAffectedSet": list(self.reset_affected_set),
            "dependencyActions": [
                action.to_wire() for action in self.dependency_actions
            ],
            "bundleHash": bundle_hash,
        }

    def to_wire(self) -> dict[str, object]:
        return self._wire(bundle_hash=self.bundle_hash)

    def to_semantic_subject(self) -> dict[str, object]:
        """Return closure semantics without exact publication epoch/hash."""

        return {
            "subjectType": "DEPENDENCY_BUNDLE_SEMANTICS",
            "schemaVersion": 1,
            "memberDeviceUids": list(self.member_device_uids),
            "physicalIsolationDomain": list(self.physical_isolation_domain),
            "ownerActivationGroup": list(self.owner_activation_group),
            "exclusiveAttachGroup": self.exclusive_attach_group,
            "resetAffectedSet": list(self.reset_affected_set),
            "dependencyActions": [
                action.to_wire() for action in self.dependency_actions
            ],
        }

    @property
    def semantic_digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_semantic_subject()))

    @property
    def document_id(self) -> str:
        return f"bundle:{self.bundle_hash.removeprefix('sha256:')}"


@dataclass(frozen=True, slots=True)
class DependencyClosureResult:
    """Complete successful closure or fail-closed reasons with no bundle."""

    success: bool
    facts_digest: str
    closure_request: ClosureRequest
    bundle: ResolvedDependencyBundle | None
    reset_contracts: tuple[ResolvedResetContract, ...]
    reset_contract_set_digest: str | None
    edges: tuple[ResolvedDependencyEdge, ...]
    action_provenance_sets: tuple[ActionProvenanceSet, ...]
    reasons: tuple[Reason, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            _invalid("result.success", "expected a boolean")
        _digest(self.facts_digest, "result.facts_digest")
        if not isinstance(self.closure_request, ClosureRequest):
            _invalid(
                "result.closure_request",
                "expected ClosureRequest",
            )
        reset_contracts = tuple(self.reset_contracts)
        for index, contract in enumerate(reset_contracts):
            if not isinstance(contract, ResolvedResetContract):
                _invalid(
                    f"result.reset_contracts[{index}]",
                    "expected ResolvedResetContract",
                )
        reset_contracts = tuple(
            _canonical_values(
                reset_contracts,
                path="result.reset_contracts",
                wire=lambda contract: contract.to_subject(),
            )
        )
        object.__setattr__(self, "reset_contracts", reset_contracts)
        if self.success:
            if self.bundle is None or self.reset_contract_set_digest is None:
                _invalid(
                    "result",
                    "successful closure requires bundle and reset-set digest",
                )
            if self.reasons:
                _invalid(
                    "result.reasons",
                    "successful closure cannot have blocking reasons",
                )
            if not reset_contracts:
                _invalid(
                    "result.reset_contracts",
                    "successful payload closure requires a reset contract",
                )
            _digest(
                self.reset_contract_set_digest,
                "result.reset_contract_set_digest",
            )
            expected_reset_digest = sha256_digest(
                canonical_json_bytes(self.reset_contract_set_wire())
            )
            if self.reset_contract_set_digest != expected_reset_digest:
                _invalid(
                    "result.reset_contract_set_digest",
                    "digest does not match complete reset-contract-set bytes",
                )
            assert self.bundle is not None
            affected = _sorted_ids(
                member
                for contract in reset_contracts
                for member in contract.affected_device_uids
            )
            if affected != self.bundle.reset_affected_set:
                _invalid(
                    "result.reset_contracts",
                    "reset-contract union does not match bundle reset set",
                )
        else:
            if (
                self.bundle is not None
                or self.reset_contract_set_digest is not None
                or reset_contracts
                or self.action_provenance_sets
            ):
                _invalid(
                    "result",
                    (
                        "failed closure cannot expose an authorizable partial "
                        "bundle, reset set, or action provenance"
                    ),
                )
            if not self.reasons:
                _invalid(
                    "result.reasons",
                    "failed closure requires at least one closed reason",
                )

    def reset_contract_set_wire(self) -> dict[str, object]:
        """Return the complete immutable RESET_CONTRACT_SET artifact."""

        return {
            "subjectType": "RESET_CONTRACT_SET",
            "schemaVersion": 1,
            "contracts": [contract.to_subject() for contract in self.reset_contracts],
        }

    def dependency_bundle_reference(self) -> DocumentReference:
        if not self.success or self.bundle is None:
            _invalid("result", "failed closure has no dependency bundle")
        return DocumentReference(
            document_kind="DEPENDENCY_BUNDLE",
            document_id=self.bundle.document_id,
            document_version=1,
            schema_ref=DEPENDENCY_BUNDLE_SCHEMA_REF,
            content_hash=self.bundle.bundle_hash,
        )

    def reset_contract_reference(self) -> DocumentReference:
        if not self.success or self.reset_contract_set_digest is None:
            _invalid("result", "failed closure has no reset-contract set")
        return DocumentReference(
            document_kind="RESET_CONTRACT",
            document_id=(
                "reset-set:" + self.reset_contract_set_digest.removeprefix("sha256:")
            ),
            document_version=1,
            schema_ref=RESET_CONTRACT_SET_SCHEMA_REF,
            content_hash=self.reset_contract_set_digest,
        )


@dataclass(frozen=True, slots=True)
class _Failure:
    code: str
    devices: tuple[str, ...]
    fact_kinds: tuple[str, ...]
    provenance: tuple[ReasonProvenance, ...]


class _Failures:
    def __init__(self) -> None:
        self._values: dict[
            tuple[str, tuple[str, ...]],
            dict[str, set[object]],
        ] = {}

    def add(
        self,
        code: str,
        *,
        devices: Iterable[str],
        fact_kind: str,
        provenance: ReasonProvenance,
    ) -> None:
        device_set = _sorted_ids(devices)
        key = (code, device_set)
        value = self._values.setdefault(
            key,
            {"fact_kinds": set(), "provenance": set()},
        )
        value["fact_kinds"].add(fact_kind)
        value["provenance"].add(provenance)

    def to_reasons(self) -> tuple[Reason, ...]:
        stage = {
            "DEVICE_NOT_IN_INVENTORY": "inventory",
            "DEPENDENCY_PROVENANCE_UNKNOWN": "capability",
            "DEPENDENCY_ACTION_UNKNOWN": "capability",
            "DEPENDENCY_ACTION_CONFLICT": "capability",
            "DEPENDENCY_CLOSURE_LIMIT": "capability",
            "RESET_NOT_SUPPORTED": "capability",
            "RESET_DOMAIN_UNVERIFIED": "capability",
        }
        reasons: list[Reason] = []
        for (code, devices), value in self._values.items():
            kinds = tuple(
                sorted(
                    (str(item) for item in value["fact_kinds"]),
                    key=lambda item: canonical_json_bytes(item),
                )
            )
            details = (
                ReasonDetail(
                    key="factKinds",
                    value_type=DetailValueType.TEXT,
                    value=",".join(kinds),
                ),
            )
            provenance = tuple(
                sorted(
                    (
                        item
                        for item in value["provenance"]
                        if isinstance(item, ReasonProvenance)
                    ),
                    key=lambda item: canonical_json_bytes(item.to_wire()),
                )
            )
            reasons.append(
                Reason(
                    code=code,
                    stage=stage[code],
                    devices=devices,
                    details=details,
                    provenance=provenance,
                )
            )
        return tuple(
            sorted(
                reasons,
                key=lambda reason: canonical_json_bytes(reason.to_wire()),
            )
        )

    @property
    def present(self) -> bool:
        return bool(self._values)

    def has(self, code: str, *, devices: Iterable[str]) -> bool:
        return (code, _sorted_ids(devices)) in self._values


def _snapshot_provenance(facts: VerifiedClosureFacts) -> ReasonProvenance:
    return ReasonProvenance(
        artifact_type="HOST_SNAPSHOT",
        artifact_id=f"snapshot-{facts.snapshot_epoch}",
        schema_ref=(
            "directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot"
        ),
        artifact_sha256=facts.snapshot_digest,
    )


def _device_provenance(device: VerifiedDeviceFacts) -> ReasonProvenance:
    return ReasonProvenance(
        artifact_type="DEVICE_RECORD",
        artifact_id=device.device_uid,
        schema_ref=(
            "directpath-portable-entities.schema.json#/$defs/ENTITY-DEVICE-RECORD"
        ),
        artifact_sha256=device.device_record_digest,
    )


def _dependency_provenance(
    *,
    source: str,
    digest: str,
) -> ReasonProvenance:
    return ReasonProvenance(
        artifact_type="DEPENDENCY_FACT",
        artifact_id=source,
        schema_ref=("directpath-portable-entities.schema.json#/$defs/dependencyAction"),
        artifact_sha256=digest,
    )


def _reset_provenance(
    device: VerifiedDeviceFacts,
) -> ReasonProvenance:
    return ReasonProvenance(
        artifact_type="RESET_CONTRACT",
        artifact_id=device.device_uid,
        schema_ref=("directpath-portable-entities.schema.json#/$defs/resetContract"),
        artifact_sha256=device.reset_contract.contract_digest,
    )


def _state_key(
    *,
    members: set[str],
    requirements: dict[str, dict[DependencyAction, set[str]]],
    edges: set[ResolvedDependencyEdge],
    resets: dict[str, ResolvedResetContract],
) -> bytes:
    subject = {
        "members": list(_sorted_ids(members)),
        "requirements": [
            {
                "deviceUid": device_uid,
                "actions": [
                    {
                        "action": action.value,
                        "provenance": list(
                            sorted(
                                digests,
                                key=lambda value: canonical_json_bytes(value),
                            )
                        ),
                    }
                    for action, digests in sorted(
                        action_map.items(),
                        key=lambda item: canonical_json_bytes(item[0].value),
                    )
                ],
            }
            for device_uid, action_map in sorted(
                requirements.items(),
                key=lambda item: canonical_json_bytes(item[0]),
            )
        ],
        "edges": [
            edge.to_subject()
            for edge in sorted(
                edges,
                key=lambda edge: canonical_json_bytes(edge.to_subject()),
            )
        ],
        "resets": [
            reset.to_subject()
            for _, reset in sorted(
                resets.items(),
                key=lambda item: canonical_json_bytes(item[0]),
            )
        ],
    }
    return canonical_json_bytes(subject)


def _resolved_primary(
    requirements: dict[DependencyAction, set[str]],
) -> DependencyAction | None:
    primary = [action for action in requirements if action in _PRIMARY_ACTION_RANK]
    if not primary:
        return None
    return max(primary, key=lambda action: _PRIMARY_ACTION_RANK[action])


def _add_requirement(
    requirements: dict[str, dict[DependencyAction, set[str]]],
    *,
    device_uid: str,
    action: DependencyAction,
    provenance_digest: str,
) -> None:
    action_map = requirements.setdefault(device_uid, {})
    action_map.setdefault(action, set()).add(provenance_digest)
    if action in _AUXILIARY_ACTIONS:
        action_map.setdefault(DependencyAction.LEASE_ONLY, set()).add(provenance_digest)


def _resolved_actions(
    requirements: dict[str, dict[DependencyAction, set[str]]],
) -> tuple[
    tuple[ResolvedDependencyAction, ...],
    tuple[ActionProvenanceSet, ...],
]:
    actions: list[ResolvedDependencyAction] = []
    provenance_sets: list[ActionProvenanceSet] = []
    for device_uid in _sorted_ids(requirements):
        action_map = requirements[device_uid]
        primary = _resolved_primary(action_map)
        selected = set(_AUXILIARY_ACTIONS & set(action_map))
        if primary is not None:
            selected.add(primary)
        for action in sorted(
            selected,
            key=lambda item: canonical_json_bytes(item.value),
        ):
            sources = set(action_map[action])
            if (
                action is primary
                and primary is not None
                and action in _PRIMARY_ACTION_RANK
            ):
                for candidate, digests in action_map.items():
                    if candidate in _PRIMARY_ACTION_RANK:
                        sources.update(digests)
            provenance_set = ActionProvenanceSet.create(
                device_uid=device_uid,
                action=action,
                source_digests=sources,
            )
            provenance_sets.append(provenance_set)
            actions.append(
                ResolvedDependencyAction(
                    device_uid=device_uid,
                    action=action,
                    provenance_digest=provenance_set.provenance_digest,
                )
            )
    actions.sort(
        key=lambda action: canonical_json_bytes(
            [action.device_uid, action.action.value]
        )
    )
    provenance_sets.sort(
        key=lambda item: canonical_json_bytes([item.device_uid, item.action.value])
    )
    return tuple(actions), tuple(provenance_sets)


def _reset_set_digest(
    reset_contracts: tuple[ResolvedResetContract, ...],
) -> str:
    subject = {
        "subjectType": "RESET_CONTRACT_SET",
        "schemaVersion": 1,
        "contracts": [contract.to_subject() for contract in reset_contracts],
    }
    return sha256_digest(canonical_json_bytes(subject))


def _failed_result(
    *,
    facts: VerifiedClosureFacts,
    closure_request: ClosureRequest,
    failures: _Failures,
    edges: Iterable[ResolvedDependencyEdge] = (),
) -> DependencyClosureResult:
    resolved_edges = tuple(
        sorted(
            set(edges),
            key=lambda edge: canonical_json_bytes(edge.to_subject()),
        )
    )
    return DependencyClosureResult(
        success=False,
        facts_digest=facts.facts_digest,
        closure_request=closure_request,
        bundle=None,
        reset_contracts=(),
        reset_contract_set_digest=None,
        edges=resolved_edges,
        action_provenance_sets=(),
        reasons=failures.to_reasons(),
    )


def resolve_dependency_closure(
    *,
    facts: VerifiedClosureFacts,
    payload_device_uids: Iterable[str],
    limits: ClosureLimits | None = None,
) -> DependencyClosureResult:
    """Resolve one complete owner-independent closure to a bounded fixed point."""

    if not isinstance(facts, VerifiedClosureFacts):
        _invalid("facts", "expected VerifiedClosureFacts")
    resolved_limits = limits or ClosureLimits()
    if not isinstance(resolved_limits, ClosureLimits):
        _invalid("limits", "expected ClosureLimits")
    payload = tuple(payload_device_uids)
    for index, device_uid in enumerate(payload):
        _identifier(device_uid, f"payload_device_uids[{index}]")
    if len(set(payload)) != len(payload):
        _invalid("payload_device_uids", "duplicate payload device")
    payload = _sorted_ids(payload)
    if not payload:
        _invalid("payload_device_uids", "at least one payload is required")
    closure_request = ClosureRequest(
        request_provenance_digest=facts.request_provenance_digest,
        policy_provenance_digest=facts.policy_provenance_digest,
        payload_device_uids=payload,
        limits=resolved_limits,
    )

    devices = {device.device_uid: device for device in facts.devices}
    failures = _Failures()
    snapshot_provenance = _snapshot_provenance(facts)
    if len(payload) > resolved_limits.max_devices:
        failures.add(
            "DEPENDENCY_CLOSURE_LIMIT",
            devices=(payload[resolved_limits.max_devices],),
            fact_kind="PAYLOAD_DEVICE_LIMIT",
            provenance=snapshot_provenance,
        )
        return _failed_result(
            facts=facts,
            closure_request=closure_request,
            failures=failures,
        )

    members = set(payload)
    requirements: dict[str, dict[DependencyAction, set[str]]] = {}
    for device_uid in payload:
        _add_requirement(
            requirements,
            device_uid=device_uid,
            action=DependencyAction.PAYLOAD,
            provenance_digest=facts.request_provenance_digest,
        )
    edges: set[ResolvedDependencyEdge] = set()
    selected_resets: dict[str, ResolvedResetContract] = {}
    limit_exceeded = False

    def add_edge(edge: ResolvedDependencyEdge) -> bool:
        nonlocal limit_exceeded
        attempted_edges = len(edges) + (edge not in edges)
        attempted_devices = len(members) + (edge.target_device_uid not in members)
        if (
            attempted_edges > resolved_limits.max_edges
            or attempted_devices > resolved_limits.max_devices
        ):
            failures.add(
                "DEPENDENCY_CLOSURE_LIMIT",
                devices=(edge.target_device_uid,),
                fact_kind=(
                    "EDGE_LIMIT"
                    if attempted_edges > resolved_limits.max_edges
                    else "DEVICE_LIMIT"
                ),
                provenance=snapshot_provenance,
            )
            limit_exceeded = True
            return False
        edges.add(edge)
        members.add(edge.target_device_uid)
        return True

    max_iterations = resolved_limits.max_edges + 8 * resolved_limits.max_devices + 1
    converged = False
    for _ in range(max_iterations):
        before = _state_key(
            members=members,
            requirements=requirements,
            edges=edges,
            resets=selected_resets,
        )

        for source_uid in _sorted_ids(members):
            source = devices.get(source_uid)
            if source is None:
                failures.add(
                    "DEVICE_NOT_IN_INVENTORY",
                    devices=(source_uid,),
                    fact_kind="DEPENDENCY_MEMBER",
                    provenance=snapshot_provenance,
                )
                continue
            for domain in source.domains:
                if domain.state is not FactState.KNOWN:
                    failures.add(
                        "DEPENDENCY_PROVENANCE_UNKNOWN",
                        devices=(source_uid,),
                        fact_kind=domain.kind.value,
                        provenance=_dependency_provenance(
                            source=source_uid,
                            digest=domain.provenance_digest,
                        ),
                    )
                    continue
                for raw_edge in domain.edges:
                    action = raw_edge.required_action
                    edge = ResolvedDependencyEdge(
                        kind=domain.kind.value,
                        source_device_uid=source_uid,
                        target_device_uid=raw_edge.target_device_uid,
                        domain_provenance_digest=(domain.provenance_digest),
                        action_provenance_digest=(raw_edge.provenance_digest),
                        action_state=raw_edge.action_state,
                        required_action=action,
                    )
                    if not add_edge(edge):
                        break
                    if raw_edge.action_state is FactState.UNKNOWN:
                        failures.add(
                            "DEPENDENCY_ACTION_UNKNOWN",
                            devices=(raw_edge.target_device_uid,),
                            fact_kind=domain.kind.value,
                            provenance=_dependency_provenance(
                                source=source_uid,
                                digest=raw_edge.provenance_digest,
                            ),
                        )
                        continue
                    if raw_edge.action_state is FactState.CONFLICT:
                        failures.add(
                            "DEPENDENCY_ACTION_CONFLICT",
                            devices=(raw_edge.target_device_uid,),
                            fact_kind=domain.kind.value,
                            provenance=_dependency_provenance(
                                source=source_uid,
                                digest=raw_edge.provenance_digest,
                            ),
                        )
                        continue
                    assert action is not None
                    _add_requirement(
                        requirements,
                        device_uid=raw_edge.target_device_uid,
                        action=action,
                        provenance_digest=raw_edge.provenance_digest,
                    )
                    _add_requirement(
                        requirements,
                        device_uid=raw_edge.target_device_uid,
                        action=action,
                        provenance_digest=domain.provenance_digest,
                    )
                    if action is DependencyAction.DENY_IF_PRESENT:
                        failures.add(
                            "DEPENDENCY_ACTION_CONFLICT",
                            devices=(raw_edge.target_device_uid,),
                            fact_kind="DENY_IF_PRESENT",
                            provenance=_dependency_provenance(
                                source=source_uid,
                                digest=raw_edge.provenance_digest,
                            ),
                        )
                if limit_exceeded:
                    break
            if limit_exceeded:
                break
        if limit_exceeded:
            break

        reset_targets = tuple(
            device_uid
            for device_uid in _sorted_ids(members)
            if _resolved_primary(requirements.get(device_uid, {}))
            is DependencyAction.PAYLOAD
        )
        for target_uid in reset_targets:
            device = devices.get(target_uid)
            if device is None:
                continue
            reset = device.reset_contract
            if reset.state is not FactState.KNOWN:
                failures.add(
                    "RESET_DOMAIN_UNVERIFIED",
                    devices=(target_uid,),
                    fact_kind="RESET_FACT_STATE",
                    provenance=_reset_provenance(device),
                )
                continue
            if not reset.supported:
                failures.add(
                    "RESET_NOT_SUPPORTED",
                    devices=(target_uid,),
                    fact_kind="RESET_UNSUPPORTED",
                    provenance=_reset_provenance(device),
                )
                continue
            if target_uid not in reset.affected_device_uids:
                failures.add(
                    "RESET_DOMAIN_UNVERIFIED",
                    devices=(target_uid,),
                    fact_kind="RESET_TARGET_NOT_IN_AFFECTED_SET",
                    provenance=_reset_provenance(device),
                )
                continue
            assert reset.selected_method is not None
            selected_resets[target_uid] = ResolvedResetContract(
                target_device_uid=target_uid,
                selected_method=reset.selected_method,
                affected_device_uids=reset.affected_device_uids,
                contract_digest=reset.contract_digest,
                provenance_digest=reset.provenance_digest,
            )
            for peer_uid in reset.affected_device_uids:
                edge = ResolvedDependencyEdge(
                    kind="RESET",
                    source_device_uid=target_uid,
                    target_device_uid=peer_uid,
                    domain_provenance_digest=reset.provenance_digest,
                    action_provenance_digest=reset.provenance_digest,
                    action_state=FactState.KNOWN,
                    required_action=DependencyAction.LEASE_ONLY,
                )
                if not add_edge(edge):
                    break
                _add_requirement(
                    requirements,
                    device_uid=peer_uid,
                    action=DependencyAction.LEASE_ONLY,
                    provenance_digest=reset.provenance_digest,
                )
            if limit_exceeded:
                break
        if limit_exceeded:
            break

        after = _state_key(
            members=members,
            requirements=requirements,
            edges=edges,
            resets=selected_resets,
        )
        if after == before:
            converged = True
            break

    if not converged and not limit_exceeded:
        failures.add(
            "DEPENDENCY_CLOSURE_LIMIT",
            devices=members,
            fact_kind="FIXED_POINT_ITERATION_LIMIT",
            provenance=snapshot_provenance,
        )

    for device_uid in _sorted_ids(members):
        if device_uid not in devices:
            failures.add(
                "DEVICE_NOT_IN_INVENTORY",
                devices=(device_uid,),
                fact_kind="DEPENDENCY_MEMBER",
                provenance=snapshot_provenance,
            )
        action_map = requirements.get(device_uid, {})
        if (
            _resolved_primary(action_map) is None
            and DependencyAction.DENY_IF_PRESENT not in action_map
            and not failures.has(
                "DEPENDENCY_ACTION_CONFLICT",
                devices=(device_uid,),
            )
        ):
            provenance = (
                _device_provenance(devices[device_uid])
                if device_uid in devices
                else snapshot_provenance
            )
            failures.add(
                "DEPENDENCY_ACTION_UNKNOWN",
                devices=(device_uid,),
                fact_kind="MEMBER_PRIMARY_ACTION",
                provenance=provenance,
            )
        if DependencyAction.DENY_IF_PRESENT in action_map:
            provenance = (
                _device_provenance(devices[device_uid])
                if device_uid in devices
                else snapshot_provenance
            )
            failures.add(
                "DEPENDENCY_ACTION_CONFLICT",
                devices=(device_uid,),
                fact_kind="DENY_IF_PRESENT",
                provenance=provenance,
            )

    if failures.present:
        return _failed_result(
            facts=facts,
            closure_request=closure_request,
            failures=failures,
            edges=edges,
        )

    actions, provenance_sets = _resolved_actions(requirements)
    reset_contracts = tuple(
        reset
        for _, reset in sorted(
            selected_resets.items(),
            key=lambda item: canonical_json_bytes(item[0]),
        )
    )
    reset_affected = _sorted_ids(
        peer for reset in reset_contracts for peer in reset.affected_device_uids
    )
    physical_domain = set(payload)
    for edge in edges:
        if edge.kind == DependencyKind.PHYSICAL_ISOLATION.value:
            physical_domain.add(edge.source_device_uid)
            physical_domain.add(edge.target_device_uid)
    member_values = _sorted_ids(members)
    group_subject = {
        "subjectType": "EXCLUSIVE_ATTACH_GROUP_KEY",
        "schemaVersion": 1,
        "memberDeviceUids": list(member_values),
    }
    group_digest = sha256_digest(canonical_json_bytes(group_subject))
    exclusive_group = "exclusive:" + group_digest.removeprefix("sha256:")
    bundle_without_hash = {
        "subjectType": "DEPENDENCY_BUNDLE",
        "schemaVersion": 1,
        "snapshotEpoch": facts.snapshot_epoch,
        "memberDeviceUids": list(member_values),
        "physicalIsolationDomain": list(_sorted_ids(physical_domain)),
        "ownerActivationGroup": list(member_values),
        "exclusiveAttachGroup": exclusive_group,
        "resetAffectedSet": list(reset_affected),
        "dependencyActions": [action.to_wire() for action in actions],
        "bundleHash": None,
    }
    bundle = ResolvedDependencyBundle(
        snapshot_epoch=facts.snapshot_epoch,
        member_device_uids=member_values,
        physical_isolation_domain=_sorted_ids(physical_domain),
        owner_activation_group=member_values,
        exclusive_attach_group=exclusive_group,
        reset_affected_set=reset_affected,
        dependency_actions=actions,
        bundle_hash=sha256_digest(canonical_json_bytes(bundle_without_hash)),
    )
    resolved_edges = tuple(
        sorted(
            edges,
            key=lambda edge: canonical_json_bytes(edge.to_subject()),
        )
    )
    return DependencyClosureResult(
        success=True,
        facts_digest=facts.facts_digest,
        closure_request=closure_request,
        bundle=bundle,
        reset_contracts=reset_contracts,
        reset_contract_set_digest=_reset_set_digest(reset_contracts),
        edges=resolved_edges,
        action_provenance_sets=provenance_sets,
        reasons=(),
    )


__all__ = [
    "ActionProvenanceSet",
    "ClosureLimits",
    "ClosureRequest",
    "CLOSURE_REQUEST_SCHEMA_REF",
    "DEPENDENCY_BUNDLE_SCHEMA_REF",
    "DependencyAction",
    "DependencyClosureResult",
    "DependencyKind",
    "FactState",
    "MAX_CLOSURE_DEVICES",
    "MAX_CLOSURE_EDGES",
    "ResetMethod",
    "RESET_CONTRACT_SET_SCHEMA_REF",
    "ResolvedDependencyAction",
    "ResolvedDependencyBundle",
    "ResolvedDependencyEdge",
    "ResolvedResetContract",
    "VerifiedClosureFacts",
    "VerifiedDependencyDomain",
    "VerifiedDependencyEdge",
    "VerifiedDeviceFacts",
    "VerifiedResetContract",
    "resolve_dependency_closure",
]
