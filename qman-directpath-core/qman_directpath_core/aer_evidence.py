"""Canonical Correctable AER observation and qualification bindings.

The objects in this module verify closed bytes and exact relationships.  They
do not prove where bytes came from, that an ESXi run was real, that an E4
resolver replayed physical artifacts, or that the product QualificationRecord
schema currently binds ``aerPolicyDigest``.  Consequently the only authority
boundary emitted here is ``COMPONENT_PREMISE``.
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
from .aer_policy import VerifiedAerPolicy
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .errors import DirectPathVerificationError, fail, require


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview

AER_EVIDENCE_DIGEST_DOMAIN = b"QMAN-DIRECTPATH/AER-EVIDENCE/V1\x00"
AER_OBSERVATION_BINDING_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-OBSERVATION-BINDING/V1\x00"
)
AER_QUALIFICATION_DIGEST_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-QUALIFICATION/V1\x00"
)
AER_E4_REPLAY_REQUEST_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-E4-REPLAY-REQUEST/V1\x00"
)
AER_E4_CASE_RESULTS_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-E4-CASE-RESULTS/V1\x00"
)
AER_E4_REPLAY_RECEIPT_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-E4-REPLAY-RECEIPT/V1\x00"
)
AER_AUTHORITY_BOUNDARY = "COMPONENT_PREMISE"
AER_REQUIRED_CASE_IDS = ("M24", "M25", "M26", "M27", "M28", "M29")
AER_MAX_DOCUMENT_BYTES = 1_048_576
AER_MAX_SOURCE_HASHES = 64
AER_MAX_E4_EVIDENCE_HASHES = 1 + (3 * len(AER_REQUIRED_CASE_IDS))
AER_MAX_REPLAY_RECEIPT_TTL = timedelta(seconds=60)
AER_MAX_JSON_DEPTH = 32
AER_MAX_JSON_NODES = 8_192
_AER_QUALIFICATION_FACTORY_TOKEN = object()
_AER_EVIDENCE_FACTORY_TOKEN = object()
_AER_E4_REQUEST_FACTORY_TOKEN = object()
_AER_E4_RECEIPT_FACTORY_TOKEN = object()

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_PCI_ID_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{4}$")

_EVIDENCE_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "evidenceId",
        "aerPolicyDigest",
        "binding",
        "classification",
        "complete",
        "integrityExact",
        "oracleExact",
        "identityExact",
        "sourceExact",
        "runtimeContainmentVerified",
        "oracleContainmentVerified",
        "containmentExact",
        "cleanupVerified",
        "reuseGatePassed",
        "dimensions",
        "caseResults",
        "evidenceDigest",
    }
)
_BINDING_KEYS = frozenset(
    {
        "esxiBuild",
        "environmentKind",
        "device",
        "owner",
        "gate",
        "profileDigest",
        "backendDigest",
        "qmanBuildDigest",
        "implementationDigest",
        "parityOracleDigest",
        "layoutDigest",
        "sourceHashes",
    }
)
_DEVICE_KEYS = frozenset({"pciId", "requesterId", "identityDigest"})
_OWNER_KEYS = frozenset(
    {
        "ownerPhase",
        "assignmentId",
        "leaseGeneration",
        "ownerEpoch",
        "hostBootId",
    }
)
_SOURCE_HASH_KEYS = frozenset({"sourceId", "sha256"})
_CASE_RESULT_KEYS = frozenset(
    {
        "caseId",
        "result",
        "runResultDigest",
        "artifactManifestDigest",
        "oracleDigest",
    }
)
_QUALIFICATION_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "qualificationId",
        "authorityBoundary",
        "aerPolicyDigest",
        "evidenceDigest",
        "observationBindingDigest",
        "caseIds",
        "e4EvidenceHashes",
        "e4VerifierIdentityDigest",
        "e4ReplayReceiptDigest",
        "dimensionResults",
        "qualificationResult",
        "qualificationDigest",
    }
)
_E4_REPLAY_RECEIPT_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "replayId",
        "verificationNonce",
        "requestDigest",
        "e4VerifierIdentityDigest",
        "authorityRevision",
        "resolvedAt",
        "validUntil",
        "aerPolicyDigest",
        "policyBytesDigest",
        "evidenceDigest",
        "evidenceBytesDigest",
        "observationBindingDigest",
        "layoutDigest",
        "device",
        "owner",
        "caseResultsDigest",
        "caseResults",
        "e4EvidenceHashes",
        "dimensionResults",
        "replayResult",
        "receiptDigest",
    }
)


class AerEvidenceClassification(str, Enum):
    MATCH = "MATCH"
    CANDIDATE = "CANDIDATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    MISMATCH = "MISMATCH"


class AerDimension(str, Enum):
    GUEST_WRITES = "GUEST_WRITES"
    IRQ_DELIVERY = "IRQ_DELIVERY"
    SERVICE_ATTRIBUTION = "SERVICE_ATTRIBUTION"
    DEVICE_HEALTH = "DEVICE_HEALTH"
    PHYSICAL_RECOVERY = "PHYSICAL_RECOVERY"


class AerDimensionResult(str, Enum):
    VERIFIED = "VERIFIED"
    UNKNOWN = "UNKNOWN"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


class AerEnvironmentKind(str, Enum):
    PHYSICAL = "PHYSICAL"
    NESTED = "NESTED"
    SYNTHETIC = "SYNTHETIC"


class AerQualificationResult(str, Enum):
    QUALIFIED = "QUALIFIED"
    CANDIDATE = "CANDIDATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


class AerE4ReplayResult(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


class AerEvidenceReplayVerifier(Protocol):
    """Untrusted transport port for one pre-existing E4 replay receipt.

    Returning bytes from this port never grants component or product authority.
    A product adapter must authenticate the receipt against a separately trusted
    resolver/repository authority and atomically consume its nonce/revision.
    """

    def resolve_aer_e4_replay_receipt(
        self,
        *,
        request: AerE4ReplayRequest,
        expected_receipt_digest: str,
    ) -> JsonDocument:
        """Resolve canonical receipt bytes or raise; never return an auth bool."""


@dataclass(frozen=True, slots=True)
class AerCaseResult:
    case_id: str
    result: AerEvidenceClassification
    run_result_digest: str
    artifact_manifest_digest: str
    oracle_digest: str

    def to_subject(self) -> dict[str, str]:
        return {
            "caseId": self.case_id,
            "result": self.result.value,
            "runResultDigest": self.run_result_digest,
            "artifactManifestDigest": self.artifact_manifest_digest,
            "oracleDigest": self.oracle_digest,
        }


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
    require(
        actual == expected,
        "AER_EVIDENCE_SHAPE_INVALID",
        path,
        (
            "object members are not the closed shape: "
            f"missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}"
        ),
    )


def _enforce_json_resource_budget(
    value: Any,
    *,
    max_bytes: int,
    path: str,
) -> None:
    """Bound a Mapping input before canonicalization allocates output bytes."""

    estimated_bytes = 0
    nodes = 0
    active_containers: set[int] = set()

    def add_bytes(amount: int) -> None:
        nonlocal estimated_bytes
        estimated_bytes += amount
        if estimated_bytes > max_bytes:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                path,
                f"document exceeds the {max_bytes} byte budget",
            )

    def add_string(text: str) -> None:
        add_bytes(2)
        for character in text:
            codepoint = ord(character)
            if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
                add_bytes(2)
            elif codepoint < 0x20:
                add_bytes(6)
            else:
                try:
                    add_bytes(len(character.encode("utf-8", errors="strict")))
                except UnicodeEncodeError as exc:
                    fail("CANONICAL_JSON_INVALID", path, str(exc))

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > AER_MAX_JSON_NODES:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                path,
                f"document exceeds the {AER_MAX_JSON_NODES} node budget",
            )
        if depth > AER_MAX_JSON_DEPTH:
            fail(
                "AER_RESOURCE_BUDGET_EXCEEDED",
                path,
                f"document exceeds the {AER_MAX_JSON_DEPTH} level budget",
            )
        if item is None:
            add_bytes(4)
        elif item is True:
            add_bytes(4)
        elif item is False:
            add_bytes(5)
        elif isinstance(item, int):
            add_bytes(len(str(item)))
        elif isinstance(item, str):
            add_string(item)
        elif isinstance(item, list):
            identity = id(item)
            if identity in active_containers:
                fail("CANONICAL_JSON_INVALID", path, "cyclic list is forbidden")
            active_containers.add(identity)
            add_bytes(2)
            try:
                for index, child in enumerate(item):
                    if index:
                        add_bytes(1)
                    visit(child, depth + 1)
            finally:
                active_containers.remove(identity)
        elif isinstance(item, Mapping):
            identity = id(item)
            if identity in active_containers:
                fail(
                    "CANONICAL_JSON_INVALID",
                    path,
                    "cyclic object is forbidden",
                )
            active_containers.add(identity)
            add_bytes(2)
            try:
                for index, (key, child) in enumerate(item.items()):
                    if not isinstance(key, str):
                        fail(
                            "CANONICAL_JSON_INVALID",
                            path,
                            "JSON object key is not a string",
                        )
                    if index:
                        add_bytes(1)
                    add_string(key)
                    add_bytes(1)
                    visit(child, depth + 1)
            finally:
                active_containers.remove(identity)
        else:
            # Unsupported scalars are cheap; the canonicalizer reports the
            # precise type error after the resource preflight.
            add_bytes(1)

    visit(value, 0)


def _document(value: JsonDocument, path: str) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        require(
            len(raw) <= AER_MAX_DOCUMENT_BYTES,
            "AER_RESOURCE_BUDGET_EXCEEDED",
            path,
            f"document exceeds {AER_MAX_DOCUMENT_BYTES} bytes",
        )
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    elif isinstance(value, Mapping):
        _enforce_json_resource_budget(
            value,
            max_bytes=AER_MAX_DOCUMENT_BYTES,
            path=path,
        )
        try:
            raw = canonical_json_bytes(value)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
        require(
            len(raw) <= AER_MAX_DOCUMENT_BYTES,
            "AER_RESOURCE_BUDGET_EXCEEDED",
            path,
            f"document exceeds {AER_MAX_DOCUMENT_BYTES} bytes",
        )
        loaded = load_canonical_json(raw)
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            path,
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "DOCUMENT_TYPE_INVALID",
        path,
        "expected a JSON object",
    )
    return loaded, raw


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        fail("INVALID_DIGEST", path, "expected sha256:<64 lowercase hex>")
    return value


def _id(value: object, path: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        fail("INVALID_ID", path, "expected a closed portable identifier")
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


def _utc(value: object, path: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        fail("TIME_INVALID", path, "expected a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _timestamp(value: object, path: str) -> datetime:
    if not isinstance(value, str):
        fail("TIME_INVALID", path, "expected a contract timestamp string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _bool(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        fail("AER_EVIDENCE_SHAPE_INVALID", path, "expected bool")
    return value


def _enum(enum_type: type[Enum], value: object, path: str) -> Enum:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        fail(
            "AER_EVIDENCE_ENUM_INVALID",
            path,
            f"expected one of {[item.value for item in enum_type]!r}",
        )


@dataclass(frozen=True, slots=True)
class AerObservationBinding:
    """Exact build/device/owner/gate/profile/backend/source coordinate."""

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
    source_hashes: tuple[tuple[str, str], ...]
    binding_digest: str

    def to_subject(self) -> dict[str, Any]:
        return {
            "esxiBuild": self.esxi_build,
            "environmentKind": self.environment_kind.value,
            "device": {
                "pciId": self.pci_id,
                "requesterId": self.requester_id,
                "identityDigest": self.device_identity_digest,
            },
            "owner": {
                "ownerPhase": self.owner_phase,
                "assignmentId": self.assignment_id,
                "leaseGeneration": self.lease_generation,
                "ownerEpoch": self.owner_epoch,
                "hostBootId": self.host_boot_id,
            },
            "gate": self.gate,
            "profileDigest": self.profile_digest,
            "backendDigest": self.backend_digest,
            "qmanBuildDigest": self.qman_build_digest,
            "implementationDigest": self.implementation_digest,
            "parityOracleDigest": self.parity_oracle_digest,
            "layoutDigest": self.layout_digest,
            "sourceHashes": [
                {"sourceId": source_id, "sha256": digest}
                for source_id, digest in self.source_hashes
            ],
        }


def _binding(value: object, path: str) -> AerObservationBinding:
    require(
        isinstance(value, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        path,
        "expected an object",
    )
    _closed_keys(value, _BINDING_KEYS, path)
    esxi_build = value["esxiBuild"]
    require(
        isinstance(esxi_build, str) and esxi_build.isdigit(),
        "AER_BINDING_INVALID",
        f"{path}.esxiBuild",
        "expected a decimal ESXi build identifier",
    )
    environment_kind = _enum(
        AerEnvironmentKind,
        value["environmentKind"],
        f"{path}.environmentKind",
    )
    device = value["device"]
    require(
        isinstance(device, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        f"{path}.device",
        "expected an object",
    )
    _closed_keys(device, _DEVICE_KEYS, f"{path}.device")
    require(
        isinstance(device["pciId"], str)
        and _PCI_ID_RE.fullmatch(device["pciId"]) is not None,
        "AER_BINDING_INVALID",
        f"{path}.device.pciId",
        "expected lowercase vendor:device PCI ID",
    )
    requester_id = device["requesterId"]
    require(
        isinstance(requester_id, int)
        and not isinstance(requester_id, bool)
        and 0 <= requester_id <= 0xFFFF,
        "AER_BINDING_INVALID",
        f"{path}.device.requesterId",
        "expected a 16-bit Requester ID",
    )
    device_digest = _digest(
        device["identityDigest"],
        f"{path}.device.identityDigest",
    )

    owner = value["owner"]
    require(
        isinstance(owner, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        f"{path}.owner",
        "expected an object",
    )
    _closed_keys(owner, _OWNER_KEYS, f"{path}.owner")
    owner_phase = _id(owner["ownerPhase"], f"{path}.owner.ownerPhase")
    assignment_id = _id(owner["assignmentId"], f"{path}.owner.assignmentId")
    lease_generation = _positive(
        owner["leaseGeneration"],
        f"{path}.owner.leaseGeneration",
    )
    owner_epoch = _positive(owner["ownerEpoch"], f"{path}.owner.ownerEpoch")
    host_boot_id = _id(owner["hostBootId"], f"{path}.owner.hostBootId")
    gate = _id(value["gate"], f"{path}.gate")
    profile_digest = _digest(value["profileDigest"], f"{path}.profileDigest")
    backend_digest = _digest(value["backendDigest"], f"{path}.backendDigest")
    qman_build_digest = _digest(
        value["qmanBuildDigest"],
        f"{path}.qmanBuildDigest",
    )
    implementation_digest = _digest(
        value["implementationDigest"],
        f"{path}.implementationDigest",
    )
    parity_oracle_digest = _digest(
        value["parityOracleDigest"],
        f"{path}.parityOracleDigest",
    )
    layout_digest = _digest(
        value["layoutDigest"],
        f"{path}.layoutDigest",
    )

    source_hashes = value["sourceHashes"]
    require(
        isinstance(source_hashes, list) and bool(source_hashes),
        "AER_BINDING_INVALID",
        f"{path}.sourceHashes",
        "expected a non-empty source hash array",
    )
    require(
        len(source_hashes) <= AER_MAX_SOURCE_HASHES,
        "AER_RESOURCE_BUDGET_EXCEEDED",
        f"{path}.sourceHashes",
        f"source hashes exceed the {AER_MAX_SOURCE_HASHES} entry budget",
    )
    checked_sources: list[tuple[str, str]] = []
    for index, source in enumerate(source_hashes):
        source_path = f"{path}.sourceHashes[{index}]"
        require(
            isinstance(source, dict),
            "AER_EVIDENCE_SHAPE_INVALID",
            source_path,
            "expected an object",
        )
        _closed_keys(source, _SOURCE_HASH_KEYS, source_path)
        checked_sources.append(
            (
                _id(source["sourceId"], f"{source_path}.sourceId"),
                _digest(source["sha256"], f"{source_path}.sha256"),
            )
        )
    require(
        checked_sources
        == sorted(set(checked_sources), key=lambda item: item[0])
        and len({item[0] for item in checked_sources}) == len(checked_sources),
        "AER_BINDING_INVALID",
        f"{path}.sourceHashes",
        "source hashes must be unique and sorted by sourceId",
    )

    projection = copy.deepcopy(value)
    binding_digest = sha256_digest(
        AER_OBSERVATION_BINDING_DOMAIN + canonical_json_bytes(projection)
    )
    return AerObservationBinding(
        esxi_build=esxi_build,
        environment_kind=environment_kind,
        pci_id=device["pciId"],
        requester_id=requester_id,
        device_identity_digest=device_digest,
        owner_phase=owner_phase,
        assignment_id=assignment_id,
        lease_generation=lease_generation,
        owner_epoch=owner_epoch,
        host_boot_id=host_boot_id,
        gate=gate,
        profile_digest=profile_digest,
        backend_digest=backend_digest,
        qman_build_digest=qman_build_digest,
        implementation_digest=implementation_digest,
        parity_oracle_digest=parity_oracle_digest,
        layout_digest=layout_digest,
        source_hashes=tuple(checked_sources),
        binding_digest=binding_digest,
    )


def _dimensions(
    value: object,
    path: str,
) -> Mapping[AerDimension, AerDimensionResult]:
    require(
        isinstance(value, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        path,
        "expected an object",
    )
    expected = {dimension.value for dimension in AerDimension}
    require(
        set(value) == expected,
        "AER_EVIDENCE_SHAPE_INVALID",
        path,
        (
            "dimension results must cover the exact closed set: "
            f"missing={sorted(expected - set(value))!r}, "
            f"extra={sorted(set(value) - expected)!r}"
        ),
    )
    return MappingProxyType(
        {
            dimension: _enum(
                AerDimensionResult,
                value[dimension.value],
                f"{path}.{dimension.value}",
            )
            for dimension in AerDimension
        }
    )


def _case_results(value: object, path: str) -> tuple[AerCaseResult, ...]:
    require(
        isinstance(value, list),
        "AER_EVIDENCE_SHAPE_INVALID",
        path,
        "expected an ordered case-result array",
    )
    require(
        len(value) == len(AER_REQUIRED_CASE_IDS),
        "AER_EVIDENCE_CASES_INCOMPLETE",
        path,
        "expected one result for every M24-M29 case",
    )
    results: list[AerCaseResult] = []
    for index, expected_case_id in enumerate(AER_REQUIRED_CASE_IDS):
        item = value[index]
        item_path = f"{path}[{index}]"
        require(
            isinstance(item, dict),
            "AER_EVIDENCE_SHAPE_INVALID",
            item_path,
            "expected an object",
        )
        _closed_keys(item, _CASE_RESULT_KEYS, item_path)
        require(
            item["caseId"] == expected_case_id,
            "AER_EVIDENCE_CASES_INCOMPLETE",
            f"{item_path}.caseId",
            "case results must be the exact ordered M24-M29 set",
        )
        results.append(
            AerCaseResult(
                case_id=expected_case_id,
                result=_enum(
                    AerEvidenceClassification,
                    item["result"],
                    f"{item_path}.result",
                ),
                run_result_digest=_digest(
                    item["runResultDigest"],
                    f"{item_path}.runResultDigest",
                ),
                artifact_manifest_digest=_digest(
                    item["artifactManifestDigest"],
                    f"{item_path}.artifactManifestDigest",
                ),
                oracle_digest=_digest(
                    item["oracleDigest"],
                    f"{item_path}.oracleDigest",
                ),
            )
        )
    return tuple(results)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAerEvidence(FactoryVerified):
    """Canonical evidence envelope; origin and E4 replay remain external."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    evidence_id: str
    aer_policy_digest: str
    binding: AerObservationBinding
    classification: AerEvidenceClassification
    complete: bool
    integrity_exact: bool
    oracle_exact: bool
    identity_exact: bool
    source_exact: bool
    runtime_containment_verified: bool
    oracle_containment_verified: bool
    containment_exact: bool
    cleanup_verified: bool
    reuse_gate_passed: bool
    dimensions: Mapping[AerDimension, AerDimensionResult]
    case_results: tuple[AerCaseResult, ...]
    behavior_authority: bool
    evidence_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    @classmethod
    def _construct(cls, **_values: Any) -> "VerifiedAerEvidence":
        raise TypeError(
            "VerifiedAerEvidence is constructed only by verify_aer_evidence"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedAerEvidence":
        if factory_token is not _AER_EVIDENCE_FACTORY_TOKEN:
            raise TypeError("invalid AER evidence factory token")
        return FactoryVerified._construct.__func__(cls, **values)


def verify_aer_evidence(
    policy: VerifiedAerPolicy,
    value: JsonDocument,
) -> VerifiedAerEvidence:
    """Verify exact evidence bytes against one current AER policy digest."""

    require_factory_verified(
        policy,
        VerifiedAerPolicy,
        code="AER_POLICY_INPUT_INVALID",
        path="policy",
        message="policy must come from verify_aer_policy",
    )
    document, raw = _document(value, "aerEvidence")
    _closed_keys(document, _EVIDENCE_KEYS, "aerEvidence")
    require(
        document["subjectType"] == "QMAN_AER_CORRECTABLE_EVIDENCE"
        and isinstance(document["schemaVersion"], int)
        and not isinstance(document["schemaVersion"], bool)
        and document["schemaVersion"] == 1,
        "AER_EVIDENCE_VERSION_UNSUPPORTED",
        "aerEvidence",
        "expected QMAN_AER_CORRECTABLE_EVIDENCE schemaVersion 1",
    )
    evidence_id = _id(document["evidenceId"], "aerEvidence.evidenceId")
    policy_digest = _digest(
        document["aerPolicyDigest"],
        "aerEvidence.aerPolicyDigest",
    )
    require(
        policy_digest == policy.aer_policy_digest,
        "AER_BINDING_MISMATCH",
        "aerEvidence.aerPolicyDigest",
        "evidence is not bound to the current AER policy",
    )
    binding = _binding(document["binding"], "aerEvidence.binding")
    classification = _enum(
        AerEvidenceClassification,
        document["classification"],
        "aerEvidence.classification",
    )
    booleans = {
        name: _bool(document[field], f"aerEvidence.{field}")
        for name, field in (
            ("complete", "complete"),
            ("integrity_exact", "integrityExact"),
            ("oracle_exact", "oracleExact"),
            ("identity_exact", "identityExact"),
            ("source_exact", "sourceExact"),
            (
                "runtime_containment_verified",
                "runtimeContainmentVerified",
            ),
            (
                "oracle_containment_verified",
                "oracleContainmentVerified",
            ),
            ("containment_exact", "containmentExact"),
            ("cleanup_verified", "cleanupVerified"),
            ("reuse_gate_passed", "reuseGatePassed"),
        )
    }
    dimensions = _dimensions(document["dimensions"], "aerEvidence.dimensions")
    case_results = _case_results(
        document["caseResults"],
        "aerEvidence.caseResults",
    )

    projection = copy.deepcopy(document)
    projection["evidenceDigest"] = None
    expected_digest = sha256_digest(
        AER_EVIDENCE_DIGEST_DOMAIN + canonical_json_bytes(projection)
    )
    require(
        document["evidenceDigest"] == expected_digest,
        "AER_EVIDENCE_DIGEST_INVALID",
        "aerEvidence.evidenceDigest",
        "digest does not match the canonical null-hash evidence projection",
    )
    behavior_authority = (
        classification is AerEvidenceClassification.MATCH
        and booleans["complete"]
        and booleans["integrity_exact"]
        and booleans["oracle_exact"]
        and booleans["identity_exact"]
        and booleans["source_exact"]
        and booleans["runtime_containment_verified"]
        and booleans["oracle_containment_verified"]
        and booleans["containment_exact"]
        and all(
            item.result is AerEvidenceClassification.MATCH
            for item in case_results
        )
    )
    return VerifiedAerEvidence._construct_verified(
        _AER_EVIDENCE_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        evidence_id=evidence_id,
        aer_policy_digest=policy_digest,
        binding=binding,
        classification=classification,
        complete=booleans["complete"],
        integrity_exact=booleans["integrity_exact"],
        oracle_exact=booleans["oracle_exact"],
        identity_exact=booleans["identity_exact"],
        source_exact=booleans["source_exact"],
        runtime_containment_verified=booleans[
            "runtime_containment_verified"
        ],
        oracle_containment_verified=booleans[
            "oracle_containment_verified"
        ],
        containment_exact=booleans["containment_exact"],
        cleanup_verified=booleans["cleanup_verified"],
        reuse_gate_passed=booleans["reuse_gate_passed"],
        dimensions=dimensions,
        case_results=case_results,
        behavior_authority=behavior_authority,
        evidence_digest=expected_digest,
    )


@dataclass(frozen=True, slots=True, init=False)
class AerE4ReplayRequest(FactoryVerified):
    """Frozen exact replay subject sent to an untrusted resolver transport."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    policy_bytes: bytes
    evidence_bytes: bytes
    verification_nonce: str
    authority_revision: int
    evaluated_at: datetime
    aer_policy_digest: str
    policy_bytes_digest: str
    evidence_digest: str
    evidence_bytes_digest: str
    observation_binding_digest: str
    layout_digest: str
    device_identity_digest: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    host_boot_id: str
    case_results: tuple[AerCaseResult, ...]
    case_results_digest: str
    e4_evidence_hashes: tuple[str, ...]
    e4_verifier_identity_digest: str
    request_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    @classmethod
    def _construct(cls, **_values: Any) -> "AerE4ReplayRequest":
        raise TypeError(
            "AerE4ReplayRequest is constructed only by "
            "prepare_aer_e4_replay_request"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "AerE4ReplayRequest":
        if factory_token is not _AER_E4_REQUEST_FACTORY_TOKEN:
            raise TypeError("invalid AER E4 request factory token")
        return FactoryVerified._construct.__func__(cls, **values)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAerE4ReplayReceipt(FactoryVerified):
    """Frozen exact receipt bytes, without portable trust promotion.

    This type proves only closed shape, digest equality and current request
    binding.  It deliberately carries no ``component_authority`` bit.
    """

    document: Mapping[str, Any]
    canonical_bytes: bytes
    replay_id: str
    verification_nonce: str
    request_digest: str
    e4_verifier_identity_digest: str
    authority_revision: int
    resolved_at: datetime
    valid_until: datetime
    aer_policy_digest: str
    policy_bytes_digest: str
    evidence_digest: str
    evidence_bytes_digest: str
    observation_binding_digest: str
    layout_digest: str
    device_identity_digest: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    host_boot_id: str
    case_results: tuple[AerCaseResult, ...]
    case_results_digest: str
    e4_evidence_hashes: tuple[str, ...]
    dimension_results: Mapping[AerDimension, AerDimensionResult]
    result: AerE4ReplayResult
    receipt_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    @classmethod
    def _construct(
        cls,
        **_values: Any,
    ) -> "VerifiedAerE4ReplayReceipt":
        raise TypeError(
            "VerifiedAerE4ReplayReceipt is constructed only by its verifier"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedAerE4ReplayReceipt":
        if factory_token is not _AER_E4_RECEIPT_FACTORY_TOKEN:
            raise TypeError("invalid AER E4 receipt factory token")
        return FactoryVerified._construct.__func__(cls, **values)


def _required_e4_hashes(
    evidence: VerifiedAerEvidence,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                evidence.evidence_digest,
                *(
                    digest
                    for item in evidence.case_results
                    for digest in (
                        item.run_result_digest,
                        item.artifact_manifest_digest,
                        item.oracle_digest,
                    )
                ),
            }
        )
    )


def prepare_aer_e4_replay_request(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    *,
    e4_evidence_hashes: tuple[str, ...] | list[str],
    e4_verifier_identity_digest: str,
    verification_nonce: str,
    authority_revision: int,
    evaluated_at: datetime,
) -> AerE4ReplayRequest:
    """Freeze one exact M24-M29 replay request at a current authority revision.

    Preparation is not verification and grants no authority.  It exists so a
    product resolver can create a pre-existing signed/CAS receipt whose digest
    is then bound by the qualification document.
    """

    require_factory_verified(
        policy,
        VerifiedAerPolicy,
        code="AER_POLICY_INPUT_INVALID",
        path="policy",
        message="policy must come from verify_aer_policy",
    )
    require_factory_verified(
        evidence,
        VerifiedAerEvidence,
        code="AER_EVIDENCE_INPUT_INVALID",
        path="evidence",
        message="evidence must come from verify_aer_evidence",
    )
    require(
        policy.aer_policy_digest == evidence.aer_policy_digest,
        "AER_BINDING_MISMATCH",
        "aerE4ReplayRequest",
        "policy and evidence do not share one exact policy digest",
    )
    require(
        isinstance(e4_evidence_hashes, (tuple, list))
        and len(e4_evidence_hashes) <= AER_MAX_E4_EVIDENCE_HASHES,
        "AER_RESOURCE_BUDGET_EXCEEDED",
        "e4_evidence_hashes",
        (
            "expected a bounded tuple/list with at most "
            f"{AER_MAX_E4_EVIDENCE_HASHES} hashes"
        ),
    )
    checked_hashes = tuple(
        _digest(item, f"e4_evidence_hashes[{index}]")
        for index, item in enumerate(e4_evidence_hashes)
    )
    required_hashes = _required_e4_hashes(evidence)
    require(
        checked_hashes == required_hashes,
        "AER_QUALIFICATION_E4_INVALID",
        "e4_evidence_hashes",
        (
            "E4 hashes must exactly equal the sorted evidence plus every "
            "M24-M29 run/manifest/oracle digest; extras are forbidden"
        ),
    )
    verifier_identity_digest = _digest(
        e4_verifier_identity_digest,
        "e4_verifier_identity_digest",
    )
    nonce = _id(verification_nonce, "verification_nonce")
    revision = _positive(authority_revision, "authority_revision")
    evaluation_time = _utc(evaluated_at, "evaluated_at")
    case_subjects = [item.to_subject() for item in evidence.case_results]
    case_results_digest = sha256_digest(
        AER_E4_CASE_RESULTS_DOMAIN + canonical_json_bytes(case_subjects)
    )
    binding = evidence.binding
    policy_bytes_digest = sha256_digest(policy.canonical_bytes)
    evidence_bytes_digest = sha256_digest(evidence.canonical_bytes)
    projection: dict[str, Any] = {
        "subjectType": "QMAN_AER_E4_REPLAY_REQUEST",
        "schemaVersion": 1,
        "verificationNonce": nonce,
        "authorityRevision": revision,
        "evaluatedAt": _timestamp_text(evaluation_time),
        "aerPolicyDigest": policy.aer_policy_digest,
        "policyBytesDigest": policy_bytes_digest,
        "evidenceDigest": evidence.evidence_digest,
        "evidenceBytesDigest": evidence_bytes_digest,
        "observationBinding": binding.to_subject(),
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
        "caseResultsDigest": case_results_digest,
        "caseResults": case_subjects,
        "e4EvidenceHashes": list(checked_hashes),
        "dimensionResults": {
            dimension.value: evidence.dimensions[dimension].value
            for dimension in AerDimension
        },
        "e4VerifierIdentityDigest": verifier_identity_digest,
        "requestDigest": None,
    }
    request_digest = sha256_digest(
        AER_E4_REPLAY_REQUEST_DOMAIN + canonical_json_bytes(projection)
    )
    projection["requestDigest"] = request_digest
    canonical_bytes = canonical_json_bytes(projection)
    return AerE4ReplayRequest._construct_verified(
        _AER_E4_REQUEST_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(projection)),
        canonical_bytes=canonical_bytes,
        policy_bytes=bytes(policy.canonical_bytes),
        evidence_bytes=bytes(evidence.canonical_bytes),
        verification_nonce=nonce,
        authority_revision=revision,
        evaluated_at=evaluation_time,
        aer_policy_digest=policy.aer_policy_digest,
        policy_bytes_digest=policy_bytes_digest,
        evidence_digest=evidence.evidence_digest,
        evidence_bytes_digest=evidence_bytes_digest,
        observation_binding_digest=binding.binding_digest,
        layout_digest=binding.layout_digest,
        device_identity_digest=binding.device_identity_digest,
        assignment_id=binding.assignment_id,
        lease_generation=binding.lease_generation,
        owner_epoch=binding.owner_epoch,
        host_boot_id=binding.host_boot_id,
        case_results=evidence.case_results,
        case_results_digest=case_results_digest,
        e4_evidence_hashes=checked_hashes,
        e4_verifier_identity_digest=verifier_identity_digest,
        request_digest=request_digest,
    )


def _verify_aer_e4_replay_receipt(
    request: AerE4ReplayRequest,
    value: JsonDocument,
    *,
    expected_receipt_digest: str,
) -> VerifiedAerE4ReplayReceipt:
    document, raw = _document(value, "aerE4ReplayReceipt")
    _closed_keys(
        document,
        _E4_REPLAY_RECEIPT_KEYS,
        "aerE4ReplayReceipt",
    )
    require(
        document["subjectType"] == "QMAN_AER_E4_REPLAY_RECEIPT"
        and isinstance(document["schemaVersion"], int)
        and not isinstance(document["schemaVersion"], bool)
        and document["schemaVersion"] == 1,
        "AER_E4_REPLAY_RECEIPT_VERSION_UNSUPPORTED",
        "aerE4ReplayReceipt",
        "expected QMAN_AER_E4_REPLAY_RECEIPT schemaVersion 1",
    )
    replay_id = _id(document["replayId"], "aerE4ReplayReceipt.replayId")
    nonce = _id(
        document["verificationNonce"],
        "aerE4ReplayReceipt.verificationNonce",
    )
    request_digest = _digest(
        document["requestDigest"],
        "aerE4ReplayReceipt.requestDigest",
    )
    verifier_identity_digest = _digest(
        document["e4VerifierIdentityDigest"],
        "aerE4ReplayReceipt.e4VerifierIdentityDigest",
    )
    revision = _positive(
        document["authorityRevision"],
        "aerE4ReplayReceipt.authorityRevision",
    )
    resolved_at = _timestamp(
        document["resolvedAt"],
        "aerE4ReplayReceipt.resolvedAt",
    )
    valid_until = _timestamp(
        document["validUntil"],
        "aerE4ReplayReceipt.validUntil",
    )
    require(
        resolved_at <= request.evaluated_at < valid_until,
        "AER_E4_REPLAY_RECEIPT_STALE",
        "aerE4ReplayReceipt.validUntil",
        "receipt does not cover the frozen replay evaluation time",
    )
    require(
        valid_until - resolved_at <= AER_MAX_REPLAY_RECEIPT_TTL,
        "AER_RESOURCE_BUDGET_EXCEEDED",
        "aerE4ReplayReceipt.validUntil",
        (
            "receipt validity exceeds the portable "
            f"{AER_MAX_REPLAY_RECEIPT_TTL.total_seconds():.0f}s TTL"
        ),
    )

    policy_digest = _digest(
        document["aerPolicyDigest"],
        "aerE4ReplayReceipt.aerPolicyDigest",
    )
    policy_bytes_digest = _digest(
        document["policyBytesDigest"],
        "aerE4ReplayReceipt.policyBytesDigest",
    )
    evidence_digest = _digest(
        document["evidenceDigest"],
        "aerE4ReplayReceipt.evidenceDigest",
    )
    evidence_bytes_digest = _digest(
        document["evidenceBytesDigest"],
        "aerE4ReplayReceipt.evidenceBytesDigest",
    )
    binding_digest = _digest(
        document["observationBindingDigest"],
        "aerE4ReplayReceipt.observationBindingDigest",
    )
    layout_digest = _digest(
        document["layoutDigest"],
        "aerE4ReplayReceipt.layoutDigest",
    )

    device = document["device"]
    require(
        isinstance(device, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        "aerE4ReplayReceipt.device",
        "expected an object",
    )
    _closed_keys(device, _DEVICE_KEYS, "aerE4ReplayReceipt.device")
    device_identity_digest = _digest(
        device["identityDigest"],
        "aerE4ReplayReceipt.device.identityDigest",
    )
    owner = document["owner"]
    require(
        isinstance(owner, dict),
        "AER_EVIDENCE_SHAPE_INVALID",
        "aerE4ReplayReceipt.owner",
        "expected an object",
    )
    _closed_keys(owner, _OWNER_KEYS, "aerE4ReplayReceipt.owner")
    assignment_id = _id(
        owner["assignmentId"],
        "aerE4ReplayReceipt.owner.assignmentId",
    )
    lease_generation = _positive(
        owner["leaseGeneration"],
        "aerE4ReplayReceipt.owner.leaseGeneration",
    )
    owner_epoch = _positive(
        owner["ownerEpoch"],
        "aerE4ReplayReceipt.owner.ownerEpoch",
    )
    host_boot_id = _id(
        owner["hostBootId"],
        "aerE4ReplayReceipt.owner.hostBootId",
    )
    _id(owner["ownerPhase"], "aerE4ReplayReceipt.owner.ownerPhase")

    case_results = _case_results(
        document["caseResults"],
        "aerE4ReplayReceipt.caseResults",
    )
    case_results_digest = _digest(
        document["caseResultsDigest"],
        "aerE4ReplayReceipt.caseResultsDigest",
    )
    computed_case_digest = sha256_digest(
        AER_E4_CASE_RESULTS_DOMAIN
        + canonical_json_bytes([item.to_subject() for item in case_results])
    )
    hashes = document["e4EvidenceHashes"]
    require(
        isinstance(hashes, list),
        "AER_EVIDENCE_SHAPE_INVALID",
        "aerE4ReplayReceipt.e4EvidenceHashes",
        "expected an ordered hash array",
    )
    require(
        len(hashes) <= AER_MAX_E4_EVIDENCE_HASHES,
        "AER_RESOURCE_BUDGET_EXCEEDED",
        "aerE4ReplayReceipt.e4EvidenceHashes",
        (
            "E4 hashes exceed the "
            f"{AER_MAX_E4_EVIDENCE_HASHES} entry budget"
        ),
    )
    checked_hashes = tuple(
        _digest(item, f"aerE4ReplayReceipt.e4EvidenceHashes[{index}]")
        for index, item in enumerate(hashes)
    )
    dimensions = _dimensions(
        document["dimensionResults"],
        "aerE4ReplayReceipt.dimensionResults",
    )
    result = _enum(
        AerE4ReplayResult,
        document["replayResult"],
        "aerE4ReplayReceipt.replayResult",
    )
    require(
        result is AerE4ReplayResult.VERIFIED,
        "AER_E4_REPLAY_RESULT_MISMATCH",
        "aerE4ReplayReceipt.replayResult",
        "only a VERIFIED replay result is structurally complete",
    )

    request_subject = request.document
    require(
        nonce == request.verification_nonce
        and request_digest == request.request_digest
        and verifier_identity_digest
        == request.e4_verifier_identity_digest
        and revision == request.authority_revision
        and policy_digest == request.aer_policy_digest
        and policy_bytes_digest == request.policy_bytes_digest
        and evidence_digest == request.evidence_digest
        and evidence_bytes_digest == request.evidence_bytes_digest
        and binding_digest == request.observation_binding_digest
        and layout_digest == request.layout_digest
        and device == request_subject["device"]
        and owner == request_subject["owner"]
        and case_results == request.case_results
        and case_results_digest == request.case_results_digest
        == computed_case_digest
        and checked_hashes == request.e4_evidence_hashes
        and all(
            dimensions[dimension].value
            == request_subject["dimensionResults"][dimension.value]
            for dimension in AerDimension
        ),
        "AER_E4_REPLAY_BINDING_MISMATCH",
        "aerE4ReplayReceipt",
        (
            "receipt is not exact for policy/layout/device/owner/lease/"
            "generation/case artifacts/authority revision"
        ),
    )

    projection = copy.deepcopy(document)
    projection["receiptDigest"] = None
    computed_receipt_digest = sha256_digest(
        AER_E4_REPLAY_RECEIPT_DOMAIN + canonical_json_bytes(projection)
    )
    declared_receipt_digest = _digest(
        document["receiptDigest"],
        "aerE4ReplayReceipt.receiptDigest",
    )
    require(
        declared_receipt_digest == computed_receipt_digest
        == expected_receipt_digest,
        "AER_E4_REPLAY_RECEIPT_DIGEST_INVALID",
        "aerE4ReplayReceipt.receiptDigest",
        "resolved receipt does not equal its bytes or qualification binding",
    )
    return VerifiedAerE4ReplayReceipt._construct_verified(
        _AER_E4_RECEIPT_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        replay_id=replay_id,
        verification_nonce=nonce,
        request_digest=request_digest,
        e4_verifier_identity_digest=verifier_identity_digest,
        authority_revision=revision,
        resolved_at=resolved_at,
        valid_until=valid_until,
        aer_policy_digest=policy_digest,
        policy_bytes_digest=policy_bytes_digest,
        evidence_digest=evidence_digest,
        evidence_bytes_digest=evidence_bytes_digest,
        observation_binding_digest=binding_digest,
        layout_digest=layout_digest,
        device_identity_digest=device_identity_digest,
        assignment_id=assignment_id,
        lease_generation=lease_generation,
        owner_epoch=owner_epoch,
        host_boot_id=host_boot_id,
        case_results=case_results,
        case_results_digest=case_results_digest,
        e4_evidence_hashes=checked_hashes,
        dimension_results=dimensions,
        result=result,
        receipt_digest=declared_receipt_digest,
    )


def _resolve_aer_e4_replay_receipt(
    resolver: AerEvidenceReplayVerifier,
    request: AerE4ReplayRequest,
    *,
    expected_receipt_digest: str,
) -> VerifiedAerE4ReplayReceipt:
    method = getattr(
        resolver,
        "resolve_aer_e4_replay_receipt",
        None,
    )
    require(
        callable(method),
        "AER_QUALIFICATION_E4_RESOLVER_INVALID",
        "aerQualification.evidenceVerifier",
        (
            "expected a resolver returning canonical receipt bytes; a "
            "verify-and-return-None port is never authorization"
        ),
    )
    try:
        resolved = method(
            request=request,
            expected_receipt_digest=expected_receipt_digest,
        )
    except DirectPathVerificationError:
        raise
    except Exception as exc:
        fail(
            "AER_QUALIFICATION_E4_VERIFICATION_FAILED",
            "aerQualification.e4ReplayReceiptDigest",
            f"E4 resolver failed: {exc}",
        )
    require(
        resolved is not None and not isinstance(resolved, bool),
        "AER_QUALIFICATION_E4_RESOLVER_INVALID",
        "aerQualification.e4ReplayReceiptDigest",
        "resolver must return canonical receipt bytes, not None or a bool",
    )
    return _verify_aer_e4_replay_receipt(
        request,
        resolved,
        expected_receipt_digest=expected_receipt_digest,
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAerQualification(FactoryVerified):
    """Exact COMPONENT_PREMISE binding, never portable E4 authority."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    qualification_id: str
    aer_policy_digest: str
    evidence_digest: str
    observation_binding_digest: str
    case_ids: tuple[str, ...]
    e4_evidence_hashes: tuple[str, ...]
    e4_verifier_identity_digest: str
    e4_replay_receipt_digest: str
    dimension_results: Mapping[AerDimension, AerDimensionResult]
    result: AerQualificationResult
    e4_replay_request: AerE4ReplayRequest | None
    e4_replay_receipt: VerifiedAerE4ReplayReceipt | None
    closure_structurally_valid: bool
    component_authority: bool
    qualification_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document

    def __post_init__(self) -> None:
        require(
            not self.component_authority,
            "AER_QUALIFICATION_TRUST_ADAPTER_REQUIRED",
            "qualification.componentAuthority",
            (
                "portable qualification cannot mint component authority; "
                "a trusted product resolver/repository adapter is required"
            ),
        )
        require(
            self.closure_structurally_valid
            is (self.e4_replay_receipt is not None)
            and (
                self.e4_replay_receipt is None
                or self.e4_replay_request is not None
            ),
            "AER_QUALIFICATION_RECEIPT_STATE_INVALID",
            "qualification.e4ReplayReceipt",
            "receipt/request structural state is inconsistent",
        )

    @classmethod
    def _construct(cls, **_values: Any) -> "VerifiedAerQualification":
        raise TypeError(
            "VerifiedAerQualification is constructed only by "
            "verify_aer_qualification"
        )

    @classmethod
    def _construct_verified(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedAerQualification":
        if factory_token is not _AER_QUALIFICATION_FACTORY_TOKEN:
            raise TypeError("invalid AER qualification factory token")
        return FactoryVerified._construct.__func__(cls, **values)


def verify_aer_qualification(
    policy: VerifiedAerPolicy,
    evidence: VerifiedAerEvidence,
    value: JsonDocument,
    *,
    evidence_verifier: AerEvidenceReplayVerifier | None = None,
    verification_nonce: str | None = None,
    authority_revision: int | None = None,
    evaluated_at: datetime | None = None,
) -> VerifiedAerQualification:
    """Bind M24-M29 and exact evidence coordinates as a component premise."""

    require_factory_verified(
        policy,
        VerifiedAerPolicy,
        code="AER_POLICY_INPUT_INVALID",
        path="policy",
        message="policy must come from verify_aer_policy",
    )
    require_factory_verified(
        evidence,
        VerifiedAerEvidence,
        code="AER_EVIDENCE_INPUT_INVALID",
        path="evidence",
        message="evidence must come from verify_aer_evidence",
    )
    document, raw = _document(value, "aerQualification")
    _closed_keys(document, _QUALIFICATION_KEYS, "aerQualification")
    require(
        document["subjectType"] == "QMAN_AER_QUALIFICATION_BINDING"
        and isinstance(document["schemaVersion"], int)
        and not isinstance(document["schemaVersion"], bool)
        and document["schemaVersion"] == 1,
        "AER_QUALIFICATION_VERSION_UNSUPPORTED",
        "aerQualification",
        "expected QMAN_AER_QUALIFICATION_BINDING schemaVersion 1",
    )
    qualification_id = _id(
        document["qualificationId"],
        "aerQualification.qualificationId",
    )
    require(
        document["authorityBoundary"] == AER_AUTHORITY_BOUNDARY,
        "AER_QUALIFICATION_AUTHORITY_INVALID",
        "aerQualification.authorityBoundary",
        "portable AER qualification is COMPONENT_PREMISE only",
    )
    policy_digest = _digest(
        document["aerPolicyDigest"],
        "aerQualification.aerPolicyDigest",
    )
    evidence_digest = _digest(
        document["evidenceDigest"],
        "aerQualification.evidenceDigest",
    )
    binding_digest = _digest(
        document["observationBindingDigest"],
        "aerQualification.observationBindingDigest",
    )
    require(
        policy_digest == policy.aer_policy_digest
        == evidence.aer_policy_digest
        and evidence_digest == evidence.evidence_digest
        and binding_digest == evidence.binding.binding_digest,
        "AER_BINDING_MISMATCH",
        "aerQualification",
        "policy, evidence, or observation binding is not exact",
    )
    case_ids = document["caseIds"]
    require(
        isinstance(case_ids, list) and tuple(case_ids) == AER_REQUIRED_CASE_IDS,
        "AER_QUALIFICATION_CASES_INCOMPLETE",
        "aerQualification.caseIds",
        "qualification must bind the exact ordered M24-M29 case set",
    )
    hashes = document["e4EvidenceHashes"]
    require(
        isinstance(hashes, list) and bool(hashes),
        "AER_QUALIFICATION_E4_INVALID",
        "aerQualification.e4EvidenceHashes",
        "expected a non-empty E4 evidence hash array",
    )
    require(
        len(hashes) <= AER_MAX_E4_EVIDENCE_HASHES,
        "AER_RESOURCE_BUDGET_EXCEEDED",
        "aerQualification.e4EvidenceHashes",
        (
            "E4 hashes exceed the "
            f"{AER_MAX_E4_EVIDENCE_HASHES} entry budget"
        ),
    )
    checked_hashes = tuple(
        _digest(item, f"aerQualification.e4EvidenceHashes[{index}]")
        for index, item in enumerate(hashes)
    )
    required_e4_hashes = _required_e4_hashes(evidence)
    require(
        checked_hashes == required_e4_hashes,
        "AER_QUALIFICATION_E4_INVALID",
        "aerQualification.e4EvidenceHashes",
        (
            "hashes must exactly equal the unique sorted evidence plus every "
            "M24-M29 run/manifest/oracle digest; extras are forbidden"
        ),
    )
    verifier_identity_digest = _digest(
        document["e4VerifierIdentityDigest"],
        "aerQualification.e4VerifierIdentityDigest",
    )
    replay_receipt_digest = _digest(
        document["e4ReplayReceiptDigest"],
        "aerQualification.e4ReplayReceiptDigest",
    )
    dimensions = _dimensions(
        document["dimensionResults"],
        "aerQualification.dimensionResults",
    )
    require(
        all(
            dimensions[dimension] is evidence.dimensions[dimension]
            for dimension in AerDimension
        ),
        "AER_BINDING_MISMATCH",
        "aerQualification.dimensionResults",
        "qualification dimension results do not equal bound evidence",
    )
    result = _enum(
        AerQualificationResult,
        document["qualificationResult"],
        "aerQualification.qualificationResult",
    )
    all_dimensions_verified = all(
        outcome is AerDimensionResult.VERIFIED
        for outcome in dimensions.values()
    )
    qualified_prerequisites = (
        evidence.behavior_authority
        and evidence.binding.environment_kind is AerEnvironmentKind.PHYSICAL
        and evidence.cleanup_verified
        and evidence.reuse_gate_passed
        and all_dimensions_verified
    )
    if result is AerQualificationResult.QUALIFIED:
        require(
            qualified_prerequisites,
            "AER_QUALIFICATION_AUTHORITY_INVALID",
            "aerQualification.qualificationResult",
            (
                "QUALIFIED requires authoritative MATCH, PHYSICAL evidence, "
                "all dimensions, cleanup and reuse"
            ),
        )

    projection = copy.deepcopy(document)
    projection["qualificationDigest"] = None
    expected_digest = sha256_digest(
        AER_QUALIFICATION_DIGEST_DOMAIN + canonical_json_bytes(projection)
    )
    require(
        document["qualificationDigest"] == expected_digest,
        "AER_QUALIFICATION_DIGEST_INVALID",
        "aerQualification.qualificationDigest",
        "digest does not match the canonical null-hash projection",
    )
    replay_request: AerE4ReplayRequest | None = None
    replay_receipt: VerifiedAerE4ReplayReceipt | None = None
    replay_coordinates = (
        verification_nonce,
        authority_revision,
        evaluated_at,
    )
    if any(item is not None for item in replay_coordinates):
        require(
            all(item is not None for item in replay_coordinates),
            "AER_QUALIFICATION_E4_COORDINATES_INVALID",
            "aerQualification.e4ReplayReceiptDigest",
            (
                "verification nonce, authority revision and evaluation time "
                "must be supplied as one current coordinate"
            ),
        )
        assert verification_nonce is not None
        assert authority_revision is not None
        assert evaluated_at is not None
        replay_request = prepare_aer_e4_replay_request(
            policy,
            evidence,
            e4_evidence_hashes=checked_hashes,
            e4_verifier_identity_digest=verifier_identity_digest,
            verification_nonce=verification_nonce,
            authority_revision=authority_revision,
            evaluated_at=evaluated_at,
        )
    if evidence_verifier is not None:
        require(
            result is AerQualificationResult.QUALIFIED,
            "AER_QUALIFICATION_E4_RESOLVER_INVALID",
            "aerQualification.qualificationResult",
            "an E4 resolver is accepted only for a QUALIFIED structural claim",
        )
        require(
            replay_request is not None,
            "AER_QUALIFICATION_E4_COORDINATES_INVALID",
            "aerQualification.e4ReplayReceiptDigest",
            (
                "receipt resolution requires a current nonce, authority "
                "revision and evaluation time"
            ),
        )
        replay_receipt = _resolve_aer_e4_replay_receipt(
            evidence_verifier,
            replay_request,
            expected_receipt_digest=replay_receipt_digest,
        )
    return VerifiedAerQualification._construct_verified(
        _AER_QUALIFICATION_FACTORY_TOKEN,
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        qualification_id=qualification_id,
        aer_policy_digest=policy_digest,
        evidence_digest=evidence_digest,
        observation_binding_digest=binding_digest,
        case_ids=AER_REQUIRED_CASE_IDS,
        e4_evidence_hashes=checked_hashes,
        e4_verifier_identity_digest=verifier_identity_digest,
        e4_replay_receipt_digest=replay_receipt_digest,
        dimension_results=dimensions,
        result=result,
        e4_replay_request=replay_request,
        e4_replay_receipt=replay_receipt,
        closure_structurally_valid=replay_receipt is not None,
        # A caller-injected Python object, a hash match, or an unsigned receipt
        # cannot prove a real resolver/repository.  Product integration must
        # authenticate and atomically consume this frozen receipt against a
        # current trust anchor and authority revision outside this package.
        component_authority=False,
        qualification_digest=expected_digest,
    )


__all__ = [
    "AER_AUTHORITY_BOUNDARY",
    "AER_E4_CASE_RESULTS_DOMAIN",
    "AER_E4_REPLAY_RECEIPT_DOMAIN",
    "AER_E4_REPLAY_REQUEST_DOMAIN",
    "AER_EVIDENCE_DIGEST_DOMAIN",
    "AER_MAX_DOCUMENT_BYTES",
    "AER_MAX_E4_EVIDENCE_HASHES",
    "AER_MAX_REPLAY_RECEIPT_TTL",
    "AER_MAX_SOURCE_HASHES",
    "AER_OBSERVATION_BINDING_DOMAIN",
    "AER_QUALIFICATION_DIGEST_DOMAIN",
    "AER_REQUIRED_CASE_IDS",
    "AerE4ReplayRequest",
    "AerE4ReplayResult",
    "AerCaseResult",
    "AerDimension",
    "AerDimensionResult",
    "AerEnvironmentKind",
    "AerEvidenceClassification",
    "AerEvidenceReplayVerifier",
    "AerObservationBinding",
    "AerQualificationResult",
    "VerifiedAerEvidence",
    "VerifiedAerE4ReplayReceipt",
    "VerifiedAerQualification",
    "prepare_aer_e4_replay_request",
    "verify_aer_evidence",
    "verify_aer_qualification",
]
