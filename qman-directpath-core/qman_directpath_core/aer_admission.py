"""Fail-closed component admission assessment for Correctable AER.

This module intentionally does not return a product authorization.  The
current product QualificationRecord/exact key does not yet normatively bind
``aerPolicyDigest`` or the M24-M29 matrix, and this package has no physical E4
resolver or current repository.  A successful result is therefore only a
``COMPONENT_PREMISE`` eligible assessment; ``product_authorized`` is always
false.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Protocol

from ._verified import FactoryVerified, require_factory_verified
from .aer_evidence import (
    AER_AUTHORITY_BOUNDARY,
    AER_E4_CASE_RESULTS_DOMAIN,
    AER_MAX_E4_EVIDENCE_HASHES,
    AER_MAX_SOURCE_HASHES,
    AER_REQUIRED_CASE_IDS,
    AerDimension,
    AerDimensionResult,
    AerEnvironmentKind,
    AerObservationBinding,
    VerifiedAerEvidence,
    VerifiedAerQualification,
    _enforce_json_resource_budget,
)
from .aer_policy import VerifiedAerPolicy
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .errors import fail


AER_ADMISSION_EXPECTATION_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-ADMISSION-EXPECTATION/V1\x00"
)
AER_RUNTIME_GATE_DOMAIN = b"QMAN-DIRECTPATH/AER-RUNTIME-GATE/V1\x00"
AER_ADMISSION_ASSESSMENT_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-ADMISSION-ASSESSMENT/V2\x00"
)
AER_ADMISSION_CURRENT_REQUEST_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-ADMISSION-CURRENT-REQUEST/V1\x00"
)
AER_ADMISSION_CURRENT_RECEIPT_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-ADMISSION-CURRENT-RECEIPT/V1\x00"
)
AER_ADMISSION_MAX_RECEIPT_BYTES = 262_144
AER_ADMISSION_MAX_RUNTIME_GATE_TTL = timedelta(seconds=60)
AER_ADMISSION_MAX_OBSERVATION_HORIZON = timedelta(seconds=5)
AER_ADMISSION_MAX_RESOLUTION_HORIZON = timedelta(seconds=5)
AER_ADMISSION_MAX_CHECK_HORIZON = timedelta(seconds=60)
_AER_CURRENT_REQUEST_FACTORY_TOKEN = object()
_AER_CURRENT_RECEIPT_FACTORY_TOKEN = object()
_PORTABLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{15,127}$")


class AerAdmissionDenyReason(str, Enum):
    MISSING_INPUT = "MISSING_INPUT"
    POLICY_DIGEST_MISMATCH = "POLICY_DIGEST_MISMATCH"
    EVIDENCE_DIGEST_MISMATCH = "EVIDENCE_DIGEST_MISMATCH"
    QUALIFICATION_DIGEST_MISMATCH = "QUALIFICATION_DIGEST_MISMATCH"
    OBSERVATION_BINDING_MISMATCH = "OBSERVATION_BINDING_MISMATCH"
    EVIDENCE_NOT_AUTHORITATIVE = "EVIDENCE_NOT_AUTHORITATIVE"
    QUALIFICATION_NOT_AUTHORITATIVE = "QUALIFICATION_NOT_AUTHORITATIVE"
    TRUSTED_E4_ADAPTER_REQUIRED = "TRUSTED_E4_ADAPTER_REQUIRED"
    PHYSICAL_E4_REQUIRED = "PHYSICAL_E4_REQUIRED"
    REQUIRED_CASES_INCOMPLETE = "REQUIRED_CASES_INCOMPLETE"
    DIMENSION_UNVERIFIED = "DIMENSION_UNVERIFIED"
    ASSIGNMENT_MISMATCH = "ASSIGNMENT_MISMATCH"
    STALE_LEASE_GENERATION_REJECTED = "STALE_LEASE_GENERATION_REJECTED"
    STALE_OWNER_EPOCH_REJECTED = "STALE_OWNER_EPOCH_REJECTED"
    STALE_HOST_BOOT_REJECTED = "STALE_HOST_BOOT_REJECTED"
    STALE_AUTHORITY_REJECTED = "STALE_AUTHORITY_REJECTED"
    CURRENT_AUTHORITY_RECEIPT_REQUIRED = (
        "CURRENT_AUTHORITY_RECEIPT_REQUIRED"
    )
    CURRENT_AUTHORITY_RECEIPT_MISMATCH = (
        "CURRENT_AUTHORITY_RECEIPT_MISMATCH"
    )
    CONFIG_LAYOUT_MISMATCH = "CONFIG_LAYOUT_MISMATCH"
    LIFECYCLE_CLEANUP_UNVERIFIED = "LIFECYCLE_CLEANUP_UNVERIFIED"
    REUSE_GATE_NOT_PASSED = "REUSE_GATE_NOT_PASSED"
    RESET_SCOPE_UNCLEAN = "RESET_SCOPE_UNCLEAN"
    DEVICE_QUARANTINED = "DEVICE_QUARANTINED"


def _digest(value: object, path: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        fail("INVALID_DIGEST", path, "expected sha256:<64 lowercase hex>")
    return value


def _positive(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 9_007_199_254_740_991
    ):
        fail("INVALID_SEQUENCE", path, "expected a positive safe integer")
    return value


def _authority_revision(value: object, path: str) -> int:
    revision = _positive(value, path)
    if revision >= 9_007_199_254_740_991:
        fail(
            "INVALID_SEQUENCE",
            path,
            "authority revision must leave room for one monotonic CAS commit",
        )
    return revision


def _portable_id(value: object, path: str) -> str:
    if not isinstance(value, str) or _PORTABLE_ID_RE.fullmatch(value) is None:
        fail(
            "INVALID_ID",
            path,
            "expected a closed portable identifier of at most 256 characters",
        )
    return value


def _nonce(value: object, path: str) -> str:
    if not isinstance(value, str) or _NONCE_RE.fullmatch(value) is None:
        fail(
            "INVALID_NONCE",
            path,
            "expected a 16..128 character independently generated nonce",
        )
    return value


def _utc(value: object, path: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        fail("TIME_INVALID", path, "expected a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: object, path: str) -> datetime:
    if not isinstance(value, str):
        fail("TIME_INVALID", path, "expected a contract timestamp string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _closed_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    path: str,
) -> None:
    actual = set(value)
    if actual != expected:
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_SHAPE_INVALID",
            path,
            (
                "object members are not the closed shape: "
                f"missing={sorted(expected - actual)!r}, "
                f"extra={sorted(actual - expected)!r}"
            ),
        )


def _receipt_document(
    value: Mapping[str, Any] | bytes | bytearray | memoryview,
) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) > AER_ADMISSION_MAX_RECEIPT_BYTES:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                "currentAuthorityReceipt",
                (
                    "receipt exceeds "
                    f"{AER_ADMISSION_MAX_RECEIPT_BYTES} bytes"
                ),
            )
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail(
                "CANONICAL_JSON_INVALID",
                "currentAuthorityReceipt",
                str(exc),
            )
    elif isinstance(value, Mapping):
        _enforce_json_resource_budget(
            value,
            max_bytes=AER_ADMISSION_MAX_RECEIPT_BYTES,
            path="currentAuthorityReceipt",
        )
        try:
            raw = canonical_json_bytes(value)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            fail(
                "CANONICAL_JSON_INVALID",
                "currentAuthorityReceipt",
                str(exc),
            )
        if len(raw) > AER_ADMISSION_MAX_RECEIPT_BYTES:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                "currentAuthorityReceipt",
                (
                    "receipt exceeds "
                    f"{AER_ADMISSION_MAX_RECEIPT_BYTES} bytes"
                ),
            )
        loaded = load_canonical_json(raw)
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            "currentAuthorityReceipt",
            "expected canonical JSON bytes or a JSON object",
        )
    if not isinstance(loaded, dict):
        fail(
            "DOCUMENT_TYPE_INVALID",
            "currentAuthorityReceipt",
            "expected a JSON object",
        )
    return loaded, raw


@dataclass(frozen=True, slots=True)
class AerAdmissionExpectation:
    """Current independently read coordinates required for exact admission."""

    aer_policy_digest: str
    evidence_digest: str
    qualification_digest: str
    observation_binding_digest: str
    esxi_build: str
    environment_kind: AerEnvironmentKind
    pci_id: str
    requester_id: int
    device_identity_digest: str
    owner_phase: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    host_boot_id: str
    gate: str
    profile_digest: str
    backend_digest: str
    qman_build_digest: str
    implementation_digest: str
    parity_oracle_digest: str
    layout_digest: str
    current_authority_vector_digest: str
    source_hashes: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        for name in (
            "aer_policy_digest",
            "evidence_digest",
            "qualification_digest",
            "observation_binding_digest",
            "device_identity_digest",
            "profile_digest",
            "backend_digest",
            "qman_build_digest",
            "implementation_digest",
            "parity_oracle_digest",
            "layout_digest",
            "current_authority_vector_digest",
        ):
            _digest(getattr(self, name), f"expectation.{name}")
        for name in (
            "esxi_build",
            "pci_id",
            "owner_phase",
            "assignment_id",
            "host_boot_id",
            "gate",
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 256
            ):
                fail(
                    "AER_ADMISSION_EXPECTATION_INVALID",
                    f"expectation.{name}",
                    "expected a non-empty UTF-8 string of at most 256 bytes",
                )
        if not isinstance(self.environment_kind, AerEnvironmentKind):
            fail(
                "AER_ADMISSION_EXPECTATION_INVALID",
                "expectation.environment_kind",
                "expected AerEnvironmentKind",
            )
        if (
            not isinstance(self.requester_id, int)
            or isinstance(self.requester_id, bool)
            or not 0 <= self.requester_id <= 0xFFFF
        ):
            fail(
                "AER_ADMISSION_EXPECTATION_INVALID",
                "expectation.requester_id",
                "expected a 16-bit Requester ID",
            )
        _positive(self.lease_generation, "expectation.lease_generation")
        _positive(self.owner_epoch, "expectation.owner_epoch")
        if (
            not isinstance(self.source_hashes, tuple)
            or not 1 <= len(self.source_hashes) <= AER_MAX_SOURCE_HASHES
        ):
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                "expectation.source_hashes",
                (
                    "expected a tuple containing 1.."
                    f"{AER_MAX_SOURCE_HASHES} source hashes"
                ),
            )
        sources = self.source_hashes
        for index, source in enumerate(sources):
            if (
                not isinstance(source, tuple)
                or len(source) != 2
            ):
                fail(
                    "AER_ADMISSION_EXPECTATION_INVALID",
                    f"expectation.source_hashes[{index}]",
                    "expected (sourceId, sha256) tuple",
                )
            _portable_id(
                source[0],
                f"expectation.source_hashes[{index}].source_id",
            )
            _digest(source[1], f"expectation.source_hashes[{index}].sha256")
        if (
            not sources
            or sources
            != tuple(sorted(set(sources), key=lambda item: item[0]))
            or len({item[0] for item in sources}) != len(sources)
        ):
            fail(
                "AER_ADMISSION_EXPECTATION_INVALID",
                "expectation.source_hashes",
                "source hashes must be non-empty, unique, and sorted",
            )
        object.__setattr__(self, "source_hashes", sources)

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "QMAN_AER_ADMISSION_EXPECTATION",
            "schemaVersion": 1,
            "aerPolicyDigest": self.aer_policy_digest,
            "evidenceDigest": self.evidence_digest,
            "qualificationDigest": self.qualification_digest,
            "observationBindingDigest": self.observation_binding_digest,
            "esxiBuild": self.esxi_build,
            "environmentKind": self.environment_kind.value,
            "pciId": self.pci_id,
            "requesterId": self.requester_id,
            "deviceIdentityDigest": self.device_identity_digest,
            "ownerPhase": self.owner_phase,
            "assignmentId": self.assignment_id,
            "leaseGeneration": self.lease_generation,
            "ownerEpoch": self.owner_epoch,
            "hostBootId": self.host_boot_id,
            "gate": self.gate,
            "profileDigest": self.profile_digest,
            "backendDigest": self.backend_digest,
            "qmanBuildDigest": self.qman_build_digest,
            "implementationDigest": self.implementation_digest,
            "parityOracleDigest": self.parity_oracle_digest,
            "layoutDigest": self.layout_digest,
            "currentAuthorityVectorDigest": (
                self.current_authority_vector_digest
            ),
            "sourceHashes": [
                {"sourceId": source_id, "sha256": digest}
                for source_id, digest in self.source_hashes
            ],
        }

    @property
    def expectation_digest(self) -> str:
        return sha256_digest(
            AER_ADMISSION_EXPECTATION_DOMAIN
            + canonical_json_bytes(self.to_subject())
        )


@dataclass(frozen=True, slots=True)
class AerRuntimeGate:
    """Current cleanup/reuse/reset/quarantine observations from product ports."""

    cleanup_verified: bool
    reuse_gate_passed: bool
    reset_scope_clean: bool
    quarantined: bool
    layout_digest: str
    current_authority_vector_digest: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        for name in (
            "cleanup_verified",
            "reuse_gate_passed",
            "reset_scope_clean",
            "quarantined",
        ):
            if not isinstance(getattr(self, name), bool):
                fail(
                    "AER_RUNTIME_GATE_INVALID",
                    f"runtime_gate.{name}",
                    "expected bool",
                )
        _digest(self.layout_digest, "runtime_gate.layout_digest")
        _digest(
            self.current_authority_vector_digest,
            "runtime_gate.current_authority_vector_digest",
        )
        observed = _utc(self.observed_at, "runtime_gate.observed_at")
        valid_until = _utc(self.valid_until, "runtime_gate.valid_until")
        if not observed < valid_until:
            fail(
                "AER_RUNTIME_GATE_INVALID",
                "runtime_gate.valid_until",
                "observed_at must be strictly before valid_until",
            )
        if valid_until - observed > AER_ADMISSION_MAX_RUNTIME_GATE_TTL:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                "runtime_gate.valid_until",
                (
                    "runtime gate validity exceeds the portable "
                    f"{AER_ADMISSION_MAX_RUNTIME_GATE_TTL.total_seconds():.0f}s "
                    "TTL"
                ),
            )
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "valid_until", valid_until)

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "QMAN_AER_RUNTIME_GATE",
            "schemaVersion": 1,
            "cleanupVerified": self.cleanup_verified,
            "reuseGatePassed": self.reuse_gate_passed,
            "resetScopeClean": self.reset_scope_clean,
            "quarantined": self.quarantined,
            "layoutDigest": self.layout_digest,
            "currentAuthorityVectorDigest": (
                self.current_authority_vector_digest
            ),
            "observedAt": _timestamp(self.observed_at),
            "validUntil": _timestamp(self.valid_until),
        }

    @property
    def runtime_gate_digest(self) -> str:
        return sha256_digest(
            AER_RUNTIME_GATE_DOMAIN + canonical_json_bytes(self.to_subject())
        )


@dataclass(frozen=True, slots=True, init=False)
class AerAdmissionCurrentRequest(FactoryVerified):
    """Frozen candidate sent to a product-owned current-authority adapter.

    The request binds the complete portable subject but carries no proof that
    its time, revision, vector, or nonce is current.  A product adapter must
    read those coordinates from a trusted repository/clock and perform a
    durable CAS; callers cannot promote this request inside the portable core.
    """

    document: Mapping[str, Any]
    canonical_bytes: bytes
    verification_nonce: str
    authority_revision: int
    requested_at: datetime
    aer_policy_digest: str
    evidence_digest: str
    qualification_digest: str
    observation_binding_digest: str
    layout_digest: str
    device_identity_digest: str
    owner_phase: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    host_boot_id: str
    current_authority_vector_digest: str
    source_hashes: tuple[tuple[str, str], ...]
    case_results_digest: str
    e4_evidence_hashes: tuple[str, ...]
    request_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    @classmethod
    def _construct(cls, **_values: Any) -> "AerAdmissionCurrentRequest":
        raise TypeError(
            "AerAdmissionCurrentRequest is constructed only by "
            "prepare_aer_admission_current_request"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "AerAdmissionCurrentRequest":
        if factory_token is not _AER_CURRENT_REQUEST_FACTORY_TOKEN:
            raise TypeError("invalid AER current-request factory token")
        return FactoryVerified._construct.__func__(cls, **values)


def prepare_aer_admission_current_request(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    qualification: VerifiedAerQualification,
    expectation: AerAdmissionExpectation,
    *,
    verification_nonce: str,
    authority_revision: int,
    requested_at: datetime,
) -> AerAdmissionCurrentRequest:
    """Freeze one exact request without claiming current product authority."""

    require_factory_verified(
        policy,
        VerifiedAerPolicy,
        code="AER_ADMISSION_INPUT_INVALID",
        path="policy",
        message="policy must come from verify_aer_policy",
    )
    require_factory_verified(
        evidence,
        VerifiedAerEvidence,
        code="AER_ADMISSION_INPUT_INVALID",
        path="evidence",
        message="evidence must come from verify_aer_evidence",
    )
    require_factory_verified(
        qualification,
        VerifiedAerQualification,
        code="AER_ADMISSION_INPUT_INVALID",
        path="qualification",
        message="qualification must come from verify_aer_qualification",
    )
    if not isinstance(expectation, AerAdmissionExpectation):
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "expectation",
            "expected AerAdmissionExpectation",
        )
    binding = evidence.binding
    if (
        expectation.aer_policy_digest != policy.aer_policy_digest
        or evidence.aer_policy_digest != policy.aer_policy_digest
        or qualification.aer_policy_digest != policy.aer_policy_digest
        or expectation.evidence_digest != evidence.evidence_digest
        or qualification.evidence_digest != evidence.evidence_digest
        or expectation.qualification_digest
        != qualification.qualification_digest
        or qualification.observation_binding_digest
        != binding.binding_digest
        or _binding_mismatch(expectation, binding)
        or expectation.assignment_id != binding.assignment_id
        or expectation.lease_generation != binding.lease_generation
        or expectation.owner_epoch != binding.owner_epoch
        or expectation.host_boot_id != binding.host_boot_id
    ):
        fail(
            "AER_ADMISSION_CURRENT_REQUEST_BINDING_MISMATCH",
            "currentAuthorityRequest",
            (
                "policy/evidence/qualification/layout/device/owner/source "
                "coordinates are not one exact subject"
            ),
        )
    nonce = _nonce(verification_nonce, "verification_nonce")
    revision = _authority_revision(
        authority_revision,
        "authority_revision",
    )
    request_time = _utc(requested_at, "requested_at")
    case_subjects = [item.to_subject() for item in evidence.case_results]
    if len(case_subjects) != len(AER_REQUIRED_CASE_IDS):
        fail(
            "AER_RESOURCE_BUDGET_EXCEEDED",
            "evidence.case_results",
            "expected the exact six M24-M29 case results",
        )
    case_results_digest = sha256_digest(
        AER_E4_CASE_RESULTS_DOMAIN + canonical_json_bytes(case_subjects)
    )
    if (
        not 1
        <= len(qualification.e4_evidence_hashes)
        <= AER_MAX_E4_EVIDENCE_HASHES
    ):
        fail(
            "AER_RESOURCE_BUDGET_EXCEEDED",
            "qualification.e4_evidence_hashes",
            (
                "expected 1.."
                f"{AER_MAX_E4_EVIDENCE_HASHES} E4 evidence hashes"
            ),
        )
    projection: dict[str, Any] = {
        "subjectType": "QMAN_AER_ADMISSION_CURRENT_REQUEST",
        "schemaVersion": 1,
        "verificationNonce": nonce,
        "authorityRevision": revision,
        "requestedAt": _timestamp(request_time),
        "aerPolicyDigest": policy.aer_policy_digest,
        "policyBytesDigest": sha256_digest(policy.canonical_bytes),
        "evidenceDigest": evidence.evidence_digest,
        "evidenceBytesDigest": sha256_digest(evidence.canonical_bytes),
        "qualificationDigest": qualification.qualification_digest,
        "qualificationBytesDigest": sha256_digest(
            qualification.canonical_bytes
        ),
        "observationBindingDigest": binding.binding_digest,
        "layoutDigest": binding.layout_digest,
        "device": {
            "pciId": binding.pci_id,
            "requesterId": binding.requester_id,
            "identityDigest": binding.device_identity_digest,
        },
        "owner": {
            "ownerPhase": binding.owner_phase,
            "assignmentId": binding.assignment_id,
            "leaseGeneration": binding.lease_generation,
            "ownerEpoch": binding.owner_epoch,
            "hostBootId": binding.host_boot_id,
        },
        "currentAuthorityVectorDigest": (
            expectation.current_authority_vector_digest
        ),
        "sourceHashes": [
            {"sourceId": source_id, "sha256": digest}
            for source_id, digest in expectation.source_hashes
        ],
        "caseResultsDigest": case_results_digest,
        "caseResults": case_subjects,
        "e4EvidenceHashes": list(qualification.e4_evidence_hashes),
        "requestDigest": None,
    }
    request_digest = sha256_digest(
        AER_ADMISSION_CURRENT_REQUEST_DOMAIN
        + canonical_json_bytes(projection)
    )
    projection["requestDigest"] = request_digest
    canonical_bytes = canonical_json_bytes(projection)
    if len(canonical_bytes) > AER_ADMISSION_MAX_RECEIPT_BYTES:
        fail(
            "AER_RESOURCE_BUDGET_EXCEEDED",
            "currentAuthorityRequest",
            (
                "request exceeds "
                f"{AER_ADMISSION_MAX_RECEIPT_BYTES} bytes"
            ),
        )
    return AerAdmissionCurrentRequest._construct_verified(
        _AER_CURRENT_REQUEST_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(projection)),
        canonical_bytes=canonical_bytes,
        verification_nonce=nonce,
        authority_revision=revision,
        requested_at=request_time,
        aer_policy_digest=policy.aer_policy_digest,
        evidence_digest=evidence.evidence_digest,
        qualification_digest=qualification.qualification_digest,
        observation_binding_digest=binding.binding_digest,
        layout_digest=binding.layout_digest,
        device_identity_digest=binding.device_identity_digest,
        owner_phase=binding.owner_phase,
        assignment_id=binding.assignment_id,
        lease_generation=binding.lease_generation,
        owner_epoch=binding.owner_epoch,
        host_boot_id=binding.host_boot_id,
        current_authority_vector_digest=(
            expectation.current_authority_vector_digest
        ),
        source_hashes=expectation.source_hashes,
        case_results_digest=case_results_digest,
        e4_evidence_hashes=qualification.e4_evidence_hashes,
        request_digest=request_digest,
    )


class AerAdmissionCurrentReceiptResolver(Protocol):
    """Product transport only; authenticity, clock and CAS remain external."""

    def resolve_aer_admission_current_receipt(
        self,
        *,
        request: AerAdmissionCurrentRequest,
        expected_receipt_digest: str,
    ) -> Mapping[str, Any] | bytes | bytearray | memoryview:
        """Return canonical receipt bytes; never return an authorization bool."""


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStructuralAerAdmissionCurrentReceipt(FactoryVerified):
    """Closed current/CAS receipt bytes with no portable trust promotion."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    receipt_id: str
    verification_nonce: str
    request_digest: str
    authority_revision: int
    committed_authority_revision: int
    requested_at: datetime
    resolved_at: datetime
    runtime_gate: AerRuntimeGate
    receipt_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    @property
    def component_authority(self) -> bool:
        """Structural bytes cannot authenticate a product adapter or CAS."""

        return False

    @classmethod
    def _construct(
        cls,
        **_values: Any,
    ) -> "VerifiedStructuralAerAdmissionCurrentReceipt":
        raise TypeError(
            "VerifiedStructuralAerAdmissionCurrentReceipt is constructed "
            "only by verify_structural_aer_admission_current_receipt"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedStructuralAerAdmissionCurrentReceipt":
        if factory_token is not _AER_CURRENT_RECEIPT_FACTORY_TOKEN:
            raise TypeError("invalid AER current-receipt factory token")
        return FactoryVerified._construct.__func__(cls, **values)


_CURRENT_RECEIPT_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "receiptId",
        "verificationNonce",
        "requestDigest",
        "authorityRevision",
        "requestedAt",
        "resolvedAt",
        "aerPolicyDigest",
        "policyBytesDigest",
        "evidenceDigest",
        "evidenceBytesDigest",
        "qualificationDigest",
        "qualificationBytesDigest",
        "observationBindingDigest",
        "layoutDigest",
        "device",
        "owner",
        "currentAuthorityVectorDigest",
        "runtimeGate",
        "sourceHashes",
        "caseResultsDigest",
        "caseResults",
        "e4EvidenceHashes",
        "cas",
        "receiptDigest",
    }
)
_CURRENT_GATE_KEYS = frozenset(
    {
        "cleanupVerified",
        "reuseGatePassed",
        "resetScopeClean",
        "quarantined",
        "layoutDigest",
        "currentAuthorityVectorDigest",
        "observedAt",
        "validUntil",
    }
)
_CURRENT_CAS_KEYS = frozenset(
    {
        "nonce",
        "expectedAuthorityRevision",
        "committedAuthorityRevision",
        "consumedAt",
    }
)
_REQUEST_RECEIPT_EXACT_KEYS = frozenset(
    {
        "aerPolicyDigest",
        "policyBytesDigest",
        "evidenceDigest",
        "evidenceBytesDigest",
        "qualificationDigest",
        "qualificationBytesDigest",
        "observationBindingDigest",
        "layoutDigest",
        "device",
        "owner",
        "currentAuthorityVectorDigest",
        "sourceHashes",
        "caseResultsDigest",
        "caseResults",
        "e4EvidenceHashes",
    }
)


def verify_structural_aer_admission_current_receipt(
    request: AerAdmissionCurrentRequest,
    value: Mapping[str, Any] | bytes | bytearray | memoryview,
    *,
    expected_receipt_digest: str,
) -> VerifiedStructuralAerAdmissionCurrentReceipt:
    """Verify shape/exact binding only; never authenticate product authority."""

    require_factory_verified(
        request,
        AerAdmissionCurrentRequest,
        code="AER_ADMISSION_CURRENT_REQUEST_INVALID",
        path="currentAuthorityRequest",
        message=(
            "request must come from "
            "prepare_aer_admission_current_request"
        ),
    )
    expected_digest = _digest(
        expected_receipt_digest,
        "expected_receipt_digest",
    )
    document, raw = _receipt_document(value)
    _closed_keys(document, _CURRENT_RECEIPT_KEYS, "currentAuthorityReceipt")
    if (
        document["subjectType"]
        != "QMAN_AER_ADMISSION_CURRENT_RECEIPT"
        or not isinstance(document["schemaVersion"], int)
        or isinstance(document["schemaVersion"], bool)
        or document["schemaVersion"] != 1
    ):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_VERSION_UNSUPPORTED",
            "currentAuthorityReceipt",
            "expected QMAN_AER_ADMISSION_CURRENT_RECEIPT schemaVersion 1",
        )
    receipt_id = _portable_id(
        document["receiptId"],
        "currentAuthorityReceipt.receiptId",
    )
    nonce = _nonce(
        document["verificationNonce"],
        "currentAuthorityReceipt.verificationNonce",
    )
    request_digest = _digest(
        document["requestDigest"],
        "currentAuthorityReceipt.requestDigest",
    )
    revision = _authority_revision(
        document["authorityRevision"],
        "currentAuthorityReceipt.authorityRevision",
    )
    requested_at = _parse_timestamp(
        document["requestedAt"],
        "currentAuthorityReceipt.requestedAt",
    )
    resolved_at = _parse_timestamp(
        document["resolvedAt"],
        "currentAuthorityReceipt.resolvedAt",
    )
    gate_document = document["runtimeGate"]
    if not isinstance(gate_document, dict):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_SHAPE_INVALID",
            "currentAuthorityReceipt.runtimeGate",
            "expected an object",
        )
    _closed_keys(
        gate_document,
        _CURRENT_GATE_KEYS,
        "currentAuthorityReceipt.runtimeGate",
    )
    runtime_gate = AerRuntimeGate(
        cleanup_verified=gate_document["cleanupVerified"],
        reuse_gate_passed=gate_document["reuseGatePassed"],
        reset_scope_clean=gate_document["resetScopeClean"],
        quarantined=gate_document["quarantined"],
        layout_digest=gate_document["layoutDigest"],
        current_authority_vector_digest=gate_document[
            "currentAuthorityVectorDigest"
        ],
        observed_at=_parse_timestamp(
            gate_document["observedAt"],
            "currentAuthorityReceipt.runtimeGate.observedAt",
        ),
        valid_until=_parse_timestamp(
            gate_document["validUntil"],
            "currentAuthorityReceipt.runtimeGate.validUntil",
        ),
    )
    if not (
        requested_at == request.requested_at
        and request.requested_at
        <= runtime_gate.observed_at
        <= resolved_at
        < runtime_gate.valid_until
        and runtime_gate.observed_at - request.requested_at
        <= AER_ADMISSION_MAX_OBSERVATION_HORIZON
        and resolved_at - runtime_gate.observed_at
        <= AER_ADMISSION_MAX_RESOLUTION_HORIZON
    ):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_STALE",
            "currentAuthorityReceipt",
            (
                "receipt timestamps exceed the request/observation/"
                "resolution horizon"
            ),
        )
    cas = document["cas"]
    if not isinstance(cas, dict):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_SHAPE_INVALID",
            "currentAuthorityReceipt.cas",
            "expected an object",
        )
    _closed_keys(cas, _CURRENT_CAS_KEYS, "currentAuthorityReceipt.cas")
    cas_nonce = _nonce(cas["nonce"], "currentAuthorityReceipt.cas.nonce")
    expected_revision = _authority_revision(
        cas["expectedAuthorityRevision"],
        "currentAuthorityReceipt.cas.expectedAuthorityRevision",
    )
    committed_revision = _positive(
        cas["committedAuthorityRevision"],
        "currentAuthorityReceipt.cas.committedAuthorityRevision",
    )
    consumed_at = _parse_timestamp(
        cas["consumedAt"],
        "currentAuthorityReceipt.cas.consumedAt",
    )
    if not (
        nonce == request.verification_nonce == cas_nonce
        and request_digest == request.request_digest
        and revision == request.authority_revision == expected_revision
        and committed_revision == expected_revision + 1
        and consumed_at == resolved_at
    ):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_CAS_INVALID",
            "currentAuthorityReceipt.cas",
            (
                "nonce/revision CAS must exactly consume this request and "
                "advance by one"
            ),
        )
    source_hashes = document["sourceHashes"]
    case_results = document["caseResults"]
    e4_hashes = document["e4EvidenceHashes"]
    if (
        not isinstance(source_hashes, list)
        or not 1 <= len(source_hashes) <= AER_MAX_SOURCE_HASHES
        or not isinstance(case_results, list)
        or len(case_results) != len(AER_REQUIRED_CASE_IDS)
        or not isinstance(e4_hashes, list)
        or not 1 <= len(e4_hashes) <= AER_MAX_E4_EVIDENCE_HASHES
    ):
        fail(
            "AER_RESOURCE_BUDGET_EXCEEDED",
            "currentAuthorityReceipt",
            (
                "source/case/E4 hash containers exceed their closed "
                f"{AER_MAX_SOURCE_HASHES}/"
                f"{len(AER_REQUIRED_CASE_IDS)}/"
                f"{AER_MAX_E4_EVIDENCE_HASHES} budgets"
            ),
        )
    request_document = load_canonical_json(request.canonical_bytes)
    if (
        any(
            document[key] != request_document[key]
            for key in _REQUEST_RECEIPT_EXACT_KEYS
        )
        or runtime_gate.layout_digest != request.layout_digest
        or runtime_gate.current_authority_vector_digest
        != request.current_authority_vector_digest
    ):
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_BINDING_MISMATCH",
            "currentAuthorityReceipt",
            (
                "receipt is not exact for policy/evidence/qualification/"
                "layout/device/owner/source/case/hash/vector coordinates"
            ),
        )
    projection = copy.deepcopy(document)
    projection["receiptDigest"] = None
    computed_digest = sha256_digest(
        AER_ADMISSION_CURRENT_RECEIPT_DOMAIN
        + canonical_json_bytes(projection)
    )
    declared_digest = _digest(
        document["receiptDigest"],
        "currentAuthorityReceipt.receiptDigest",
    )
    if declared_digest != computed_digest or declared_digest != expected_digest:
        fail(
            "AER_ADMISSION_CURRENT_RECEIPT_DIGEST_INVALID",
            "currentAuthorityReceipt.receiptDigest",
            "receipt digest does not equal its bytes and expected binding",
        )
    return VerifiedStructuralAerAdmissionCurrentReceipt._construct_verified(
        _AER_CURRENT_RECEIPT_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        receipt_id=receipt_id,
        verification_nonce=nonce,
        request_digest=request_digest,
        authority_revision=revision,
        committed_authority_revision=committed_revision,
        requested_at=requested_at,
        resolved_at=resolved_at,
        runtime_gate=runtime_gate,
        receipt_digest=declared_digest,
    )


@dataclass(frozen=True, slots=True, init=False)
class AerAdmissionAssessment(FactoryVerified):
    """Deterministic assessment with an explicit non-product boundary."""

    component_eligible: bool
    deny_reasons: tuple[AerAdmissionDenyReason, ...]
    unverified_dimensions: tuple[AerDimension, ...]
    aer_policy_digest: str | None
    evidence_digest: str | None
    qualification_digest: str | None
    observation_binding_digest: str | None
    expectation_digest: str | None
    runtime_gate_digest: str | None
    current_request_digest: str | None
    current_receipt_digest: str | None
    current_authority_vector_digest: str | None
    checked_at: datetime | None
    assessment_digest: str

    def __post_init__(self) -> None:
        if self.component_eligible:
            fail(
                "AER_TRUSTED_E4_ADAPTER_REQUIRED",
                "assessment.component_eligible",
                (
                    "portable AER core cannot mint component eligibility "
                    "without a trusted product resolver/repository adapter"
                ),
            )
        if self.component_eligible != (not self.deny_reasons):
            fail(
                "AER_ADMISSION_ASSESSMENT_INVALID",
                "assessment.component_eligible",
                "eligibility must equal absence of deny reasons",
            )
        if self.deny_reasons != tuple(
            sorted(set(self.deny_reasons), key=lambda item: item.value)
        ):
            fail(
                "AER_ADMISSION_ASSESSMENT_INVALID",
                "assessment.deny_reasons",
                "deny reasons must be unique and canonically ordered",
            )
        projection = self.to_subject()
        projection["assessmentDigest"] = None
        expected = sha256_digest(
            AER_ADMISSION_ASSESSMENT_DOMAIN
            + canonical_json_bytes(projection)
        )
        if self.assessment_digest != expected:
            fail(
                "AER_ADMISSION_ASSESSMENT_INVALID",
                "assessment.assessment_digest",
                "digest does not match the canonical null-hash assessment",
            )

    @property
    def product_authorized(self) -> bool:
        """This component can never mint a product authorization."""

        return False

    @property
    def authority_boundary(self) -> str:
        return AER_AUTHORITY_BOUNDARY

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "QMAN_AER_ADMISSION_ASSESSMENT",
            "schemaVersion": 2,
            "componentEligible": self.component_eligible,
            "productAuthorized": self.product_authorized,
            "authorityBoundary": self.authority_boundary,
            "denyReasons": [reason.value for reason in self.deny_reasons],
            "unverifiedDimensions": [
                dimension.value for dimension in self.unverified_dimensions
            ],
            "aerPolicyDigest": self.aer_policy_digest,
            "evidenceDigest": self.evidence_digest,
            "qualificationDigest": self.qualification_digest,
            "observationBindingDigest": self.observation_binding_digest,
            "expectationDigest": self.expectation_digest,
            "runtimeGateDigest": self.runtime_gate_digest,
            "currentRequestDigest": self.current_request_digest,
            "currentReceiptDigest": self.current_receipt_digest,
            "currentAuthorityVectorDigest": (
                self.current_authority_vector_digest
            ),
            "checkedAt": (
                _timestamp(self.checked_at)
                if self.checked_at is not None
                else None
            ),
            "assessmentDigest": self.assessment_digest,
        }


def _assessment(
    *,
    reasons: set[AerAdmissionDenyReason],
    unverified_dimensions: tuple[AerDimension, ...],
    policy_digest: str | None,
    evidence_digest: str | None,
    qualification_digest: str | None,
    binding_digest: str | None,
    expectation: AerAdmissionExpectation | None,
    runtime_gate: AerRuntimeGate | None,
    current_request: AerAdmissionCurrentRequest | None,
    current_receipt: VerifiedStructuralAerAdmissionCurrentReceipt | None,
    checked_at: datetime | None,
) -> AerAdmissionAssessment:
    ordered_reasons = tuple(sorted(reasons, key=lambda item: item.value))
    eligible = not ordered_reasons
    projection = {
        "subjectType": "QMAN_AER_ADMISSION_ASSESSMENT",
        "schemaVersion": 2,
        "componentEligible": eligible,
        "productAuthorized": False,
        "authorityBoundary": AER_AUTHORITY_BOUNDARY,
        "denyReasons": [reason.value for reason in ordered_reasons],
        "unverifiedDimensions": [
            dimension.value for dimension in unverified_dimensions
        ],
        "aerPolicyDigest": policy_digest,
        "evidenceDigest": evidence_digest,
        "qualificationDigest": qualification_digest,
        "observationBindingDigest": binding_digest,
        "expectationDigest": (
            expectation.expectation_digest
            if expectation is not None
            else None
        ),
        "runtimeGateDigest": (
            runtime_gate.runtime_gate_digest
            if runtime_gate is not None
            else None
        ),
        "currentRequestDigest": (
            current_request.request_digest
            if current_request is not None
            else None
        ),
        "currentReceiptDigest": (
            current_receipt.receipt_digest
            if current_receipt is not None
            else None
        ),
        "currentAuthorityVectorDigest": (
            runtime_gate.current_authority_vector_digest
            if runtime_gate is not None
            else None
        ),
        "checkedAt": _timestamp(checked_at) if checked_at is not None else None,
        "assessmentDigest": None,
    }
    digest = sha256_digest(
        AER_ADMISSION_ASSESSMENT_DOMAIN + canonical_json_bytes(projection)
    )
    return AerAdmissionAssessment._construct(
        component_eligible=eligible,
        deny_reasons=ordered_reasons,
        unverified_dimensions=unverified_dimensions,
        aer_policy_digest=policy_digest,
        evidence_digest=evidence_digest,
        qualification_digest=qualification_digest,
        observation_binding_digest=binding_digest,
        expectation_digest=projection["expectationDigest"],
        runtime_gate_digest=projection["runtimeGateDigest"],
        current_request_digest=projection["currentRequestDigest"],
        current_receipt_digest=projection["currentReceiptDigest"],
        current_authority_vector_digest=projection[
            "currentAuthorityVectorDigest"
        ],
        checked_at=checked_at,
        assessment_digest=digest,
    )


def _binding_mismatch(
    expected: AerAdmissionExpectation,
    binding: AerObservationBinding,
) -> bool:
    return (
        expected.observation_binding_digest != binding.binding_digest
        or expected.esxi_build != binding.esxi_build
        or expected.environment_kind is not binding.environment_kind
        or expected.pci_id != binding.pci_id
        or expected.requester_id != binding.requester_id
        or expected.device_identity_digest != binding.device_identity_digest
        or expected.owner_phase != binding.owner_phase
        or expected.gate != binding.gate
        or expected.profile_digest != binding.profile_digest
        or expected.backend_digest != binding.backend_digest
        or expected.qman_build_digest != binding.qman_build_digest
        or expected.implementation_digest != binding.implementation_digest
        or expected.parity_oracle_digest != binding.parity_oracle_digest
        or expected.layout_digest != binding.layout_digest
        or expected.source_hashes != binding.source_hashes
    )


def evaluate_aer_admission(
    *,
    policy: VerifiedAerPolicy | None = None,
    evidence: VerifiedAerEvidence | None = None,
    qualification: VerifiedAerQualification | None = None,
    expectation: AerAdmissionExpectation | None = None,
    runtime_gate: AerRuntimeGate | None = None,
    checked_at: datetime | None = None,
    current_request: AerAdmissionCurrentRequest | None = None,
    current_receipt: VerifiedStructuralAerAdmissionCurrentReceipt
    | None = None,
) -> AerAdmissionAssessment:
    """Default deny; caller coordinates are never current-authority proof.

    ``expectation``, ``runtime_gate`` and ``checked_at`` are untrusted
    candidates used for mismatch diagnostics.  Even an exact structural
    request/receipt pair cannot remove ``TRUSTED_E4_ADAPTER_REQUIRED`` because
    this package has no trusted clock, repository identity, signature verifier,
    nonce ledger, or linearizable CAS port.
    """

    if any(
        item is None
        for item in (
            policy,
            evidence,
            qualification,
            expectation,
            runtime_gate,
            checked_at,
        )
    ):
        return _assessment(
            reasons={AerAdmissionDenyReason.MISSING_INPUT},
            unverified_dimensions=tuple(AerDimension),
            policy_digest=None,
            evidence_digest=None,
            qualification_digest=None,
            binding_digest=None,
            expectation=None,
            runtime_gate=None,
            current_request=None,
            current_receipt=None,
            checked_at=None,
        )
    assert policy is not None
    assert evidence is not None
    assert qualification is not None
    assert expectation is not None
    assert runtime_gate is not None
    assert checked_at is not None
    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    if (
        not isinstance(evidence, VerifiedAerEvidence)
        or not evidence._factory_verified()
    ):
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "evidence",
            "evidence must come from verify_aer_evidence",
        )
    if (
        not isinstance(qualification, VerifiedAerQualification)
        or not qualification._factory_verified()
    ):
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "qualification",
            "qualification must come from verify_aer_qualification",
        )
    if not isinstance(expectation, AerAdmissionExpectation):
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "expectation",
            "expected AerAdmissionExpectation",
        )
    if not isinstance(runtime_gate, AerRuntimeGate):
        fail(
            "AER_ADMISSION_INPUT_INVALID",
            "runtime_gate",
            "expected AerRuntimeGate",
        )
    if current_request is not None:
        require_factory_verified(
            current_request,
            AerAdmissionCurrentRequest,
            code="AER_ADMISSION_CURRENT_REQUEST_INVALID",
            path="current_request",
            message=(
                "current request must come from "
                "prepare_aer_admission_current_request"
            ),
        )
    if current_receipt is not None:
        require_factory_verified(
            current_receipt,
            VerifiedStructuralAerAdmissionCurrentReceipt,
            code="AER_ADMISSION_CURRENT_RECEIPT_INVALID",
            path="current_receipt",
            message=(
                "current receipt must come from "
                "verify_structural_aer_admission_current_receipt"
            ),
        )
    normalized_checked_at = _utc(checked_at, "checked_at")

    reasons: set[AerAdmissionDenyReason] = set()
    binding = evidence.binding
    if (
        expectation.aer_policy_digest != policy.aer_policy_digest
        or evidence.aer_policy_digest != policy.aer_policy_digest
        or qualification.aer_policy_digest != policy.aer_policy_digest
    ):
        reasons.add(AerAdmissionDenyReason.POLICY_DIGEST_MISMATCH)
    if (
        expectation.evidence_digest != evidence.evidence_digest
        or qualification.evidence_digest != evidence.evidence_digest
    ):
        reasons.add(AerAdmissionDenyReason.EVIDENCE_DIGEST_MISMATCH)
    if (
        expectation.qualification_digest
        != qualification.qualification_digest
    ):
        reasons.add(AerAdmissionDenyReason.QUALIFICATION_DIGEST_MISMATCH)
    if (
        _binding_mismatch(expectation, binding)
        or qualification.observation_binding_digest != binding.binding_digest
    ):
        reasons.add(AerAdmissionDenyReason.OBSERVATION_BINDING_MISMATCH)
    if expectation.assignment_id != binding.assignment_id:
        reasons.add(AerAdmissionDenyReason.ASSIGNMENT_MISMATCH)
    if expectation.lease_generation != binding.lease_generation:
        reasons.add(AerAdmissionDenyReason.STALE_LEASE_GENERATION_REJECTED)
    if expectation.owner_epoch != binding.owner_epoch:
        reasons.add(AerAdmissionDenyReason.STALE_OWNER_EPOCH_REJECTED)
    if expectation.host_boot_id != binding.host_boot_id:
        reasons.add(AerAdmissionDenyReason.STALE_HOST_BOOT_REJECTED)
    if (
        expectation.layout_digest != runtime_gate.layout_digest
    ):
        reasons.add(AerAdmissionDenyReason.CONFIG_LAYOUT_MISMATCH)
    if (
        expectation.current_authority_vector_digest
        != runtime_gate.current_authority_vector_digest
        or not (
            runtime_gate.observed_at
            <= normalized_checked_at
            < runtime_gate.valid_until
        )
        or normalized_checked_at - runtime_gate.observed_at
        > AER_ADMISSION_MAX_CHECK_HORIZON
    ):
        reasons.add(AerAdmissionDenyReason.STALE_AUTHORITY_REJECTED)
    if not evidence.behavior_authority:
        reasons.add(AerAdmissionDenyReason.EVIDENCE_NOT_AUTHORITATIVE)
    if not qualification.component_authority:
        reasons.add(AerAdmissionDenyReason.QUALIFICATION_NOT_AUTHORITATIVE)
    # This portable package deliberately has no product resolver trust anchor
    # or durable receipt-CAS port.  No caller-created object can remove this
    # reason; a product adapter must perform the separate promotion step.
    reasons.add(AerAdmissionDenyReason.TRUSTED_E4_ADAPTER_REQUIRED)
    if current_request is None or current_receipt is None:
        reasons.add(
            AerAdmissionDenyReason.CURRENT_AUTHORITY_RECEIPT_REQUIRED
        )
    elif (
        current_receipt.request_digest != current_request.request_digest
        or current_receipt.verification_nonce
        != current_request.verification_nonce
        or current_receipt.authority_revision
        != current_request.authority_revision
        or current_request.aer_policy_digest != policy.aer_policy_digest
        or current_request.evidence_digest != evidence.evidence_digest
        or current_request.qualification_digest
        != qualification.qualification_digest
        or current_request.observation_binding_digest
        != binding.binding_digest
        or current_request.layout_digest != expectation.layout_digest
        or current_request.device_identity_digest
        != expectation.device_identity_digest
        or current_request.owner_phase != expectation.owner_phase
        or current_request.assignment_id != expectation.assignment_id
        or current_request.lease_generation
        != expectation.lease_generation
        or current_request.owner_epoch != expectation.owner_epoch
        or current_request.host_boot_id != expectation.host_boot_id
        or current_request.current_authority_vector_digest
        != expectation.current_authority_vector_digest
        or current_request.source_hashes != expectation.source_hashes
        or current_request.e4_evidence_hashes
        != qualification.e4_evidence_hashes
        or current_receipt.runtime_gate.runtime_gate_digest
        != runtime_gate.runtime_gate_digest
    ):
        reasons.add(
            AerAdmissionDenyReason.CURRENT_AUTHORITY_RECEIPT_MISMATCH
        )
    elif (
        current_receipt.resolved_at > normalized_checked_at
        or normalized_checked_at
        >= current_receipt.runtime_gate.valid_until
        or normalized_checked_at - current_receipt.resolved_at
        > AER_ADMISSION_MAX_CHECK_HORIZON
    ):
        reasons.add(AerAdmissionDenyReason.STALE_AUTHORITY_REJECTED)
    receipt = qualification.e4_replay_receipt
    if receipt is not None and not (
        receipt.resolved_at <= normalized_checked_at < receipt.valid_until
    ):
        reasons.add(AerAdmissionDenyReason.STALE_AUTHORITY_REJECTED)
    if binding.environment_kind is not AerEnvironmentKind.PHYSICAL:
        reasons.add(AerAdmissionDenyReason.PHYSICAL_E4_REQUIRED)
    if qualification.case_ids != AER_REQUIRED_CASE_IDS:
        reasons.add(AerAdmissionDenyReason.REQUIRED_CASES_INCOMPLETE)

    unverified_dimensions = tuple(
        dimension
        for dimension in AerDimension
        if evidence.dimensions[dimension] is not AerDimensionResult.VERIFIED
        or qualification.dimension_results[dimension]
        is not AerDimensionResult.VERIFIED
    )
    if unverified_dimensions:
        reasons.add(AerAdmissionDenyReason.DIMENSION_UNVERIFIED)
    if not evidence.cleanup_verified or not runtime_gate.cleanup_verified:
        reasons.add(AerAdmissionDenyReason.LIFECYCLE_CLEANUP_UNVERIFIED)
    if not evidence.reuse_gate_passed or not runtime_gate.reuse_gate_passed:
        reasons.add(AerAdmissionDenyReason.REUSE_GATE_NOT_PASSED)
    if not runtime_gate.reset_scope_clean:
        reasons.add(AerAdmissionDenyReason.RESET_SCOPE_UNCLEAN)
    if runtime_gate.quarantined:
        reasons.add(AerAdmissionDenyReason.DEVICE_QUARANTINED)

    return _assessment(
        reasons=reasons,
        unverified_dimensions=unverified_dimensions,
        policy_digest=policy.aer_policy_digest,
        evidence_digest=evidence.evidence_digest,
        qualification_digest=qualification.qualification_digest,
        binding_digest=binding.binding_digest,
        expectation=expectation,
        runtime_gate=runtime_gate,
        current_request=current_request,
        current_receipt=current_receipt,
        checked_at=normalized_checked_at,
    )


__all__ = [
    "AER_ADMISSION_ASSESSMENT_DOMAIN",
    "AER_ADMISSION_CURRENT_RECEIPT_DOMAIN",
    "AER_ADMISSION_CURRENT_REQUEST_DOMAIN",
    "AER_ADMISSION_EXPECTATION_DOMAIN",
    "AER_ADMISSION_MAX_CHECK_HORIZON",
    "AER_ADMISSION_MAX_OBSERVATION_HORIZON",
    "AER_ADMISSION_MAX_RECEIPT_BYTES",
    "AER_ADMISSION_MAX_RESOLUTION_HORIZON",
    "AER_ADMISSION_MAX_RUNTIME_GATE_TTL",
    "AER_RUNTIME_GATE_DOMAIN",
    "AerAdmissionAssessment",
    "AerAdmissionCurrentReceiptResolver",
    "AerAdmissionCurrentRequest",
    "AerAdmissionDenyReason",
    "AerAdmissionExpectation",
    "AerRuntimeGate",
    "VerifiedStructuralAerAdmissionCurrentReceipt",
    "evaluate_aer_admission",
    "prepare_aer_admission_current_request",
    "verify_structural_aer_admission_current_receipt",
]
