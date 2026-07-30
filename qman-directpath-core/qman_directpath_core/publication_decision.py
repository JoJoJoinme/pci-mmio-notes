"""Component-only HostSnapshot publication decision verification.

The factories in this module replay exact retained artifacts and derive one of
the five publication decisions.  They do not open a repository transaction,
read a trusted clock, verify an external rollback-authority root quorum, run a
four-authority compare-and-swap, or prove atomic visibility.  Consequently
every returned value is permanently non-authorizing product evidence.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
import re
from types import MappingProxyType
from typing import Any, Final

from ._verified import FactoryVerified, require_factory_verified
from .canonical import (
    CanonicalizationError,
    CanonicalJsonLimitError,
    canonical_json_bytes,
    load_canonical_json,
    measure_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import DirectPathVerificationError, fail, require
from .inventory import (
    VerifiedDeviceRecord,
    VerifiedInventoryContext,
    verify_inventory_context,
)
from .policy import VerifiedCapabilityPolicy, verify_capability_policy
from .publication_capture import (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF,
    VerifiedHostSnapshotCaptureClosureContext,
    replay_host_snapshot_capture_closure,
)
from .snapshot_semantics import derive_no_change_projection


HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_CALLER_SUPPLIED_PUBLICATION_READ_SET_BYTES_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_STRUCTURAL_DECISION_PREMISE_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    "TARGET_PRODUCT_SERIALIZABLE_TRANSACTION_PORT_REQUIRED",
    "TRUSTED_PUBLICATION_LINEARIZATION_CLOCK_REQUIRED",
    "ROLLBACK_AUTHORITY_ROOT_SIGNATURE_QUORUM_VERIFICATION_REQUIRED",
    "ROLLBACK_AUTHORITY_FRESH_NONCE_TRANSPORT_REQUIRED",
    "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "TARGET_ATOMIC_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED",
    "TARGET_QMAN_COLLECTOR_PUBLISHER_EXECUTION_REQUIRED",
    "TARGET_QMAN_MAPPING_BUILD_RUNNER_EVIDENCE_REQUIRED",
)

MAX_FULL_PUBLICATION_DEVICE_RECORDS: Final = 4096

HOST_AUTHORITY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/hostAuthorityArtifact"
)
AVAILABILITY_AUTHORITY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/availabilityAuthorityArtifact"
)
CAPABILITY_POLICY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/capabilityPolicyArtifact"
)
CAPABILITY_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/capabilityPolicyAuthorityArtifact"
)
FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessPolicyArtifact"
)
FRESHNESS_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/freshnessPolicyAuthorityArtifact"
)
ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/rollbackAnchorArtifact"
)
ROLLBACK_FRESHNESS_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessArtifact"
)
ROLLBACK_PREFLIGHT_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/rollbackAuthorityPreflightArtifact"
)
NO_CHANGE_PROJECTION_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/noChangeProjection"
)
FRESHNESS_DECISION_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessDecision"
)
CAS_EXPECTATION_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/snapshotPublicationCasExpectation"
)

_HOST_AUTHORITY_STATE_SCHEMA_REF = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-HOST-AUTHORITY"
)
_AVAILABILITY_AUTHORITY_STATE_SCHEMA_REF = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
)
_CAPABILITY_POLICY_STATE_SCHEMA_REF = (
    "contracts/directpath-capability-policy.schema.json"
)
_CAPABILITY_POLICY_AUTHORITY_STATE_SCHEMA_REF = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-CAPABILITY-POLICY-AUTHORITY"
)
_FRESHNESS_POLICY_STATE_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessPolicy"
)
_FRESHNESS_POLICY_AUTHORITY_STATE_SCHEMA_REF = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
)
_ROLLBACK_ANCHOR_STATE_SCHEMA_REF = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
)
_ROLLBACK_FRESHNESS_STATE_SCHEMA_REF = (
    "contracts/directpath-anchor-freshness-envelope.schema.json"
)
_ROLLBACK_PREFLIGHT_STATE_SCHEMA_REF = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
    "#/$defs/rollbackAuthorityPreflightReceipt"
)

_CAS_EXPECTATION_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-CAS-EXPECTATION/V1\x00"
)
_FRESHNESS_POLICY_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-FRESHNESS-POLICY/V1\x00"
)
_FRESHNESS_DECISION_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-FRESHNESS-DECISION/V1\x00"
)
_STRUCTURAL_READ_RECEIPT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-STRUCTURAL-READ-SET/V1\x00"
)
_DECISION_CONTEXT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-DECISION-CONTEXT/V1\x00"
)
_ROLLBACK_PREFLIGHT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ROLLBACK-AUTHORITY-PREFLIGHT/V1\x00"
)
_ANCHOR_CANDIDATE_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ANCHOR-CANDIDATE/V1\x00"
)

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]*$")
_STRUCTURAL_RECEIPT_FIELDS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "repositoryId",
        "transactionId",
        "isolation",
        "beganAt",
        "hostAuthorityArtifactCanonicalSha256",
        "availabilityAuthorityArtifactCanonicalSha256",
        "capabilityPolicyArtifactCanonicalSha256",
        "capabilityPolicyAuthorityArtifactCanonicalSha256",
        "freshnessPolicyArtifactCanonicalSha256",
        "freshnessPolicyAuthorityArtifactCanonicalSha256",
        "currentInventoryVerificationReceiptDigestOrNull",
        "predecessorRollbackAnchorArtifactCanonicalSha256OrNull",
        "predecessorRollbackFreshnessArtifactCanonicalSha256OrNull",
        "rollbackAuthorityPreflightArtifactCanonicalSha256",
        "expectationHash",
        "receiptDigest",
    }
)

JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview


@dataclass(frozen=True, slots=True)
class PublicationDecisionVerifierLimits:
    """Caller-tightenable ceilings for the full publication composition."""

    max_full_device_records: int = MAX_FULL_PUBLICATION_DEVICE_RECORDS
    max_artifact_bytes: int = 32 * 1024 * 1024
    max_receipt_bytes: int = 2 * 1024 * 1024
    max_json_nodes: int = 2_000_000
    max_json_depth: int = 64


DEFAULT_PUBLICATION_DECISION_LIMITS = PublicationDecisionVerifierLimits()


@dataclass(frozen=True, slots=True)
class _VerifiedArtifact:
    wrapper: Mapping[str, Any]
    wrapper_canonical_bytes: bytes
    wrapper_canonical_sha256: str
    state: Mapping[str, Any]
    state_canonical_bytes: bytes
    state_canonical_sha256: str


@dataclass(frozen=True, slots=True, init=False)
class StructuralPublicationReadSet(FactoryVerified):
    """Exact caller-supplied structural read bytes, without product authority."""

    limits: PublicationDecisionVerifierLimits
    repository_id: str
    transaction_id: str
    isolation: str
    began_at: datetime
    began_at_text: str
    host_authority_before_artifact: Mapping[str, Any]
    host_authority_before_artifact_canonical_bytes: bytes
    host_authority_before: Mapping[str, Any]
    host_authority_before_canonical_bytes: bytes
    availability_authority_before_artifact: Mapping[str, Any]
    availability_authority_before_artifact_canonical_bytes: bytes
    availability_authority_before: Mapping[str, Any]
    availability_authority_before_canonical_bytes: bytes
    capability_policy_artifact: Mapping[str, Any]
    capability_policy_artifact_canonical_bytes: bytes
    capability_policy: VerifiedCapabilityPolicy
    capability_policy_authority_artifact: Mapping[str, Any]
    capability_policy_authority_artifact_canonical_bytes: bytes
    capability_policy_authority: Mapping[str, Any]
    capability_policy_authority_canonical_bytes: bytes
    freshness_policy_artifact: Mapping[str, Any]
    freshness_policy_artifact_canonical_bytes: bytes
    freshness_policy: Mapping[str, Any]
    freshness_policy_canonical_bytes: bytes
    freshness_policy_hash: str
    freshness_policy_authority_artifact: Mapping[str, Any]
    freshness_policy_authority_artifact_canonical_bytes: bytes
    freshness_policy_authority: Mapping[str, Any]
    freshness_policy_authority_canonical_bytes: bytes
    current_inventory_or_null: VerifiedInventoryContext | None
    predecessor_rollback_anchor_artifact_or_null: Mapping[str, Any] | None
    predecessor_rollback_anchor_artifact_canonical_bytes_or_null: bytes | None
    predecessor_rollback_anchor_or_null: Mapping[str, Any] | None
    predecessor_rollback_anchor_canonical_bytes_or_null: bytes | None
    predecessor_rollback_freshness_artifact_or_null: Mapping[str, Any] | None
    predecessor_rollback_freshness_artifact_canonical_bytes_or_null: bytes | None
    predecessor_rollback_freshness_or_null: Mapping[str, Any] | None
    predecessor_rollback_freshness_canonical_bytes_or_null: bytes | None
    rollback_authority_preflight_artifact: Mapping[str, Any]
    rollback_authority_preflight_artifact_canonical_bytes: bytes
    rollback_authority_preflight: Mapping[str, Any]
    rollback_authority_preflight_canonical_bytes: bytes
    cas_expectation: Mapping[str, Any]
    expectation_hash: str
    structural_transaction_read_receipt: Mapping[str, Any]
    structural_transaction_read_receipt_canonical_bytes: bytes
    context_digest: str
    authority_boundary: str
    authority_disposition: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]
    _schemas: ContractSchemas = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationDecisionContext(FactoryVerified):
    """Replayable deterministic decision over two verified factory contexts."""

    limits: PublicationDecisionVerifierLimits
    capture: VerifiedHostSnapshotCaptureClosureContext
    read_set: StructuralPublicationReadSet
    decision_kind: str
    publication_decision: str
    write_required: bool
    persisted_device_record_source: str
    persisted_device_records: tuple[VerifiedDeviceRecord, ...]
    current_no_change_projection_or_null: Mapping[str, Any] | None
    candidate_no_change_projection: Mapping[str, Any]
    proposed_snapshot_epoch: int
    proposed_host_authority_resource_version: int
    cas_operands: Mapping[str, Any]
    expectation_hash: str
    freshness_decision: Mapping[str, Any]
    freshness_decision_digest: str
    context_receipt: Mapping[str, Any]
    context_receipt_canonical_bytes: bytes
    context_digest: str
    authority_boundary: str
    authority_disposition: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _checked_limits(
    value: PublicationDecisionVerifierLimits | None,
) -> PublicationDecisionVerifierLimits:
    limits = value or DEFAULT_PUBLICATION_DECISION_LIMITS
    require(
        isinstance(limits, PublicationDecisionVerifierLimits),
        "PUBLICATION_DECISION_INPUT_INVALID",
        "limits",
        "expected PublicationDecisionVerifierLimits",
    )
    hard = DEFAULT_PUBLICATION_DECISION_LIMITS
    for descriptor in fields(PublicationDecisionVerifierLimits):
        actual = getattr(limits, descriptor.name)
        ceiling = getattr(hard, descriptor.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "PUBLICATION_DECISION_LIMIT_INVALID",
            f"limits.{descriptor.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {ceiling}"
            ),
        )
    return limits


def _load_document(
    value: JsonDocument,
    *,
    path: str,
    max_bytes: int,
    limits: PublicationDecisionVerifierLimits,
) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, Mapping):
            measured_bytes, _ = measure_canonical_json(
                value,
                max_bytes=max_bytes,
                max_nodes=limits.max_json_nodes,
                max_depth=limits.max_json_depth,
            )
            raw = canonical_json_bytes(value)
            require(
                len(raw) == measured_bytes,
                "PUBLICATION_DECISION_CANONICAL_BYTES_INVALID",
                path,
                "bounded canonical measurement differs from encoded bytes",
            )
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            require(
                0 < len(raw) <= max_bytes,
                "PUBLICATION_DECISION_TOO_LARGE",
                path,
                f"canonical object exceeds the closed {max_bytes}-byte limit",
            )
        else:
            raise TypeError("expected canonical JSON bytes or a JSON mapping")
        loaded = load_canonical_json(raw)
        if not isinstance(value, Mapping):
            measured_bytes, _ = measure_canonical_json(
                loaded,
                max_bytes=max_bytes,
                max_nodes=limits.max_json_nodes,
                max_depth=limits.max_json_depth,
            )
            require(
                measured_bytes == len(raw),
                "PUBLICATION_DECISION_CANONICAL_BYTES_INVALID",
                path,
                "bounded decoded measurement differs from retained bytes",
            )
    except DirectPathVerificationError:
        raise
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_DECISION_TOO_LARGE", path, str(exc))
    except (
        CanonicalizationError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        fail(
            "PUBLICATION_DECISION_CANONICAL_BYTES_INVALID",
            path,
            f"cannot load exact CANONICAL-JSON-V1 object: {exc}",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_DECISION_ARTIFACT_INVALID",
        path,
        "expected one canonical JSON object",
    )
    return loaded, raw


def _decode_canonical_state(
    encoded: Any,
    *,
    path: str,
    max_bytes: int,
    limits: PublicationDecisionVerifierLimits,
) -> tuple[dict[str, Any], bytes]:
    require(
        isinstance(encoded, str) and len(encoded) % 4 == 0,
        "PUBLICATION_DECISION_BASE64_INVALID",
        path,
        "expected exact padded RFC 4648 base64",
    )
    maximum_encoded = ((max_bytes + 2) // 3) * 4
    require(
        0 < len(encoded) <= maximum_encoded,
        "PUBLICATION_DECISION_TOO_LARGE",
        path,
        f"encoded state exceeds the closed {max_bytes}-byte decoded limit",
    )
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        fail(
            "PUBLICATION_DECISION_BASE64_INVALID",
            path,
            f"invalid strict base64: {exc}",
        )
    require(
        0 < len(raw) <= max_bytes
        and base64.b64encode(raw).decode("ascii") == encoded,
        "PUBLICATION_DECISION_BASE64_INVALID",
        path,
        "base64 is not the exact non-empty padded representation",
    )
    try:
        loaded = load_canonical_json(raw)
        measured_bytes, _ = measure_canonical_json(
            loaded,
            max_bytes=max_bytes,
            max_nodes=limits.max_json_nodes,
            max_depth=limits.max_json_depth,
        )
        require(
            measured_bytes == len(raw),
            "PUBLICATION_DECISION_CANONICAL_BYTES_INVALID",
            path,
            "bounded decoded-state measurement differs from retained bytes",
        )
    except DirectPathVerificationError:
        raise
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_DECISION_TOO_LARGE", path, str(exc))
    except (CanonicalizationError, RecursionError) as exc:
        fail(
            "PUBLICATION_DECISION_CANONICAL_BYTES_INVALID",
            path,
            f"decoded state is not exact CANONICAL-JSON-V1: {exc}",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_DECISION_ARTIFACT_INVALID",
        path,
        "decoded state must be one object",
    )
    return loaded, raw


def _verify_artifact(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    wrapper_schema_ref: str,
    state_schema_ref: str,
    path: str,
    limits: PublicationDecisionVerifierLimits,
) -> _VerifiedArtifact:
    wrapper, wrapper_raw = _load_document(
        value,
        path=path,
        max_bytes=limits.max_artifact_bytes,
        limits=limits,
    )
    schemas.validate_ref(wrapper_schema_ref, wrapper, path)
    state, state_raw = _decode_canonical_state(
        wrapper["canonicalInstanceBase64"],
        path=f"{path}.canonicalInstanceBase64",
        max_bytes=limits.max_artifact_bytes,
        limits=limits,
    )
    schemas.validate_ref(state_schema_ref, state, f"{path}.stateBytes")
    require(
        state == wrapper["state"],
        "PUBLICATION_DECISION_ARTIFACT_BINDING_MISMATCH",
        f"{path}.state",
        "wrapper state is not byte-equivalent to the decoded canonical state",
    )
    state_sha = sha256_digest(state_raw)
    require(
        wrapper["instanceBytesSha256"] == state_sha,
        "PUBLICATION_DECISION_ARTIFACT_HASH_MISMATCH",
        f"{path}.instanceBytesSha256",
        "instance hash does not bind the decoded canonical state bytes",
    )
    return _VerifiedArtifact(
        wrapper=_freeze_json(wrapper),
        wrapper_canonical_bytes=wrapper_raw,
        wrapper_canonical_sha256=sha256_digest(wrapper_raw),
        state=_freeze_json(state),
        state_canonical_bytes=state_raw,
        state_canonical_sha256=state_sha,
    )


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "PUBLICATION_DECISION_TIME_INVALID",
        path,
        "expected TIMESTAMP-UTC-US-V1 text",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail(
            "PUBLICATION_DECISION_TIME_INVALID",
            path,
            f"invalid TIMESTAMP-UTC-US-V1 value: {exc}",
        )
    return parsed.replace(tzinfo=timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _digest_projection(
    domain: bytes,
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str] = (),
    empty_array_fields: Sequence[str] = (),
) -> str:
    projection = _thaw_json(document)
    for name in null_fields:
        projection[name] = None
    for name in empty_array_fields:
        projection[name] = []
    return sha256_digest(domain + canonical_json_bytes(projection))


def _plain_digest_projection(
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str] = (),
    empty_array_fields: Sequence[str] = (),
) -> str:
    projection = _thaw_json(document)
    for name in null_fields:
        projection[name] = None
    for name in empty_array_fields:
        projection[name] = []
    return sha256_digest(canonical_json_bytes(projection))


def _require_digest(value: Any, path: str) -> str:
    require(
        isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None,
        "PUBLICATION_DECISION_RECEIPT_INVALID",
        path,
        "expected sha256:<64 lowercase hex> digest",
    )
    return value


def _require_id(value: Any, path: str) -> str:
    require(
        isinstance(value, str)
        and 1 <= len(value) <= 512
        and _ID_PATTERN.fullmatch(value) is not None,
        "PUBLICATION_DECISION_RECEIPT_INVALID",
        path,
        "expected a closed portable identifier",
    )
    return value


def _verify_structural_receipt_shape(
    value: JsonDocument,
    *,
    limits: PublicationDecisionVerifierLimits,
) -> tuple[dict[str, Any], bytes, datetime]:
    path = "publicationDecision.structuralTransactionReadReceipt"
    receipt, raw = _load_document(
        value,
        path=path,
        max_bytes=limits.max_receipt_bytes,
        limits=limits,
    )
    require(
        set(receipt) == _STRUCTURAL_RECEIPT_FIELDS,
        "PUBLICATION_DECISION_RECEIPT_INVALID",
        path,
        "receipt fields do not equal the closed V1 structural read-set fields",
    )
    require(
        receipt["subjectType"]
        == "HOST_SNAPSHOT_PUBLICATION_STRUCTURAL_READ_RECEIPT"
        and receipt["schemaVersion"] == 1
        and receipt["isolation"] == "SERIALIZABLE",
        "PUBLICATION_DECISION_RECEIPT_INVALID",
        path,
        "receipt type/version/isolation is not the closed SERIALIZABLE profile",
    )
    _require_id(receipt["repositoryId"], f"{path}.repositoryId")
    _require_id(receipt["transactionId"], f"{path}.transactionId")
    began_at = _timestamp(receipt["beganAt"], f"{path}.beganAt")
    digest_fields = (
        "hostAuthorityArtifactCanonicalSha256",
        "availabilityAuthorityArtifactCanonicalSha256",
        "capabilityPolicyArtifactCanonicalSha256",
        "capabilityPolicyAuthorityArtifactCanonicalSha256",
        "freshnessPolicyArtifactCanonicalSha256",
        "freshnessPolicyAuthorityArtifactCanonicalSha256",
        "rollbackAuthorityPreflightArtifactCanonicalSha256",
        "expectationHash",
        "receiptDigest",
    )
    for name in digest_fields:
        _require_digest(receipt[name], f"{path}.{name}")
    nullable_digest_fields = (
        "currentInventoryVerificationReceiptDigestOrNull",
        "predecessorRollbackAnchorArtifactCanonicalSha256OrNull",
        "predecessorRollbackFreshnessArtifactCanonicalSha256OrNull",
    )
    for name in nullable_digest_fields:
        if receipt[name] is not None:
            _require_digest(receipt[name], f"{path}.{name}")
    expected_digest = _digest_projection(
        _STRUCTURAL_READ_RECEIPT_DOMAIN,
        receipt,
        null_fields=("receiptDigest",),
    )
    require(
        receipt["receiptDigest"] == expected_digest,
        "PUBLICATION_DECISION_RECEIPT_HASH_MISMATCH",
        f"{path}.receiptDigest",
        "receiptDigest does not bind the closed structural read receipt",
    )
    return receipt, raw, began_at


def _verify_freshness_policy_hash(policy: Mapping[str, Any]) -> str:
    expected = _digest_projection(
        _FRESHNESS_POLICY_DOMAIN,
        policy,
        null_fields=("policyHash",),
    )
    require(
        policy["policyHash"] == expected,
        "PUBLICATION_DECISION_FRESHNESS_POLICY_INVALID",
        "publicationDecision.freshnessPolicy.state.policyHash",
        "freshness policy hash does not bind its complete null-hash projection",
    )
    ordering = [
        canonical_json_bytes([item["providerId"], item["factId"]])
        for item in policy["mandatoryProviderFacts"]
    ]
    require(
        ordering == sorted(ordering) and len(ordering) == len(set(ordering)),
        "PUBLICATION_DECISION_FRESHNESS_POLICY_INVALID",
        "publicationDecision.freshnessPolicy.state.mandatoryProviderFacts",
        "mandatory provider selectors are not a canonical unique set",
    )
    return expected


def _verify_root_signature_structure(
    signatures: Sequence[Mapping[str, Any]],
    *,
    path: str,
    not_before: datetime,
    not_after: datetime | None,
) -> tuple[datetime, ...]:
    root_ids = [item["rootKeyId"] for item in signatures]
    order = [canonical_json_bytes(item) for item in root_ids]
    require(
        order == sorted(order) and len(order) == len(set(order)),
        "PUBLICATION_DECISION_ROLLBACK_STRUCTURE_INVALID",
        path,
        "root signature IDs are not a canonical unique set",
    )
    signed_times: list[datetime] = []
    for index, signature in enumerate(signatures):
        signed_at = _timestamp(
            signature["signedAt"],
            f"{path}[{index}].signedAt",
        )
        require(
            signed_at >= not_before
            and (not_after is None or signed_at <= not_after),
            "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
            f"{path}[{index}].signedAt",
            "root signature time is outside the retained receipt interval",
        )
        signed_times.append(signed_at)
    return tuple(signed_times)


def _verify_predecessor_anchor_structure(
    anchor: Mapping[str, Any],
) -> tuple[datetime, ...]:
    path = "publicationDecision.predecessorRollbackAnchor.state"
    candidate_fields = (
        "hostId",
        "kernelBootId",
        "hostEpoch",
        "agentIdentity",
        "agentGeneration",
        "acceptedSnapshotEpoch",
        "acceptedSnapshotContentHash",
        "acceptedHostAuthorityResourceVersion",
        "anchorVersion",
        "resourceVersion",
        "previousAnchorDigestOrNull",
        "authorityId",
        "casPrecondition",
    )
    candidate = {name: _thaw_json(anchor[name]) for name in candidate_fields}
    expected_candidate_digest = sha256_digest(
        _ANCHOR_CANDIDATE_DOMAIN + canonical_json_bytes(candidate)
    )
    require(
        anchor["candidateProjectionDigest"] == expected_candidate_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.candidateProjectionDigest",
        "predecessor candidate projection digest mismatch",
    )
    prepare = anchor["prepareReceipt"]
    prepare_digest = _plain_digest_projection(
        prepare,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
    )
    require(
        prepare["receiptDigest"] == prepare_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.prepareReceipt.receiptDigest",
        "predecessor prepare receipt digest mismatch",
    )
    require(
        prepare["hostId"] == anchor["hostId"]
        and prepare["candidateProjectionDigest"]
        == anchor["candidateProjectionDigest"]
        and prepare["predecessorAnchorDigestOrNull"]
        == anchor["previousAnchorDigestOrNull"]
        and prepare["authorityId"] == anchor["authorityId"],
        "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
        f"{path}.prepareReceipt",
        "predecessor prepare receipt does not bind its anchor",
    )
    prepared_at = _timestamp(
        prepare["preparedAt"],
        f"{path}.prepareReceipt.preparedAt",
    )
    prepare_expires = _timestamp(
        prepare["expiresAt"],
        f"{path}.prepareReceipt.expiresAt",
    )
    require(
        prepared_at < prepare_expires,
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        f"{path}.prepareReceipt",
        "preparedAt must precede expiresAt",
    )
    updated_at = _timestamp(anchor["updatedAt"], f"{path}.updatedAt")
    require(
        prepared_at <= updated_at,
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        f"{path}.updatedAt",
        "committed anchor update predates preparation",
    )
    _verify_root_signature_structure(
        prepare["rootSignatures"],
        path=f"{path}.prepareReceipt.rootSignatures",
        not_before=prepared_at,
        not_after=min(prepare_expires, updated_at),
    )

    anchor_digest = _plain_digest_projection(
        anchor,
        null_fields=("anchorDigest", "receipt"),
    )
    require(
        anchor["anchorDigest"] == anchor_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.anchorDigest",
        "predecessor anchor digest mismatch",
    )
    receipt = anchor["receipt"]
    binding_names = (
        ("subjectAnchorDigest", "anchorDigest"),
        ("hostId", "hostId"),
        ("kernelBootId", "kernelBootId"),
        ("hostEpoch", "hostEpoch"),
        ("agentIdentity", "agentIdentity"),
        ("agentGeneration", "agentGeneration"),
        ("acceptedSnapshotEpoch", "acceptedSnapshotEpoch"),
        ("acceptedSnapshotContentHash", "acceptedSnapshotContentHash"),
        (
            "acceptedHostAuthorityResourceVersion",
            "acceptedHostAuthorityResourceVersion",
        ),
        ("anchorVersion", "anchorVersion"),
        ("resourceVersion", "resourceVersion"),
        ("authorityId", "authorityId"),
    )
    require(
        all(receipt[left] == anchor[right] for left, right in binding_names),
        "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
        f"{path}.receipt",
        "predecessor final receipt does not bind its anchor",
    )
    receipt_digest = _plain_digest_projection(
        receipt,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
    )
    require(
        receipt["receiptDigest"] == receipt_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.receipt.receiptDigest",
        "predecessor final receipt digest mismatch",
    )
    issued_at = _timestamp(receipt["issuedAt"], f"{path}.receipt.issuedAt")
    require(
        issued_at >= updated_at,
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        f"{path}.receipt.issuedAt",
        "final receipt predates the committed anchor update",
    )
    return _verify_root_signature_structure(
        receipt["rootSignatures"],
        path=f"{path}.receipt.rootSignatures",
        not_before=issued_at,
        not_after=None,
    )


def _verify_predecessor_freshness_structure(
    freshness: Mapping[str, Any],
    freshness_raw: bytes,
    *,
    anchor: Mapping[str, Any],
    anchor_raw: bytes,
    anchor_schema_sha256: str,
    began_at: datetime,
    final_receipt_signature_times: Sequence[datetime],
) -> None:
    del freshness_raw
    path = "publicationDecision.predecessorRollbackFreshness.state"
    bindings = {
        "anchorKind": "HOST_SNAPSHOT",
        "authorityId": anchor["authorityId"],
        "subjectId": anchor["hostId"],
        "anchorBlobSha256": sha256_digest(anchor_raw),
        "anchorSchemaRef": _ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
        "anchorSchemaSha256": anchor_schema_sha256,
        "anchorDigest": anchor["anchorDigest"],
        "anchorVersion": anchor["anchorVersion"],
        "resourceVersion": anchor["resourceVersion"],
    }
    require(
        all(freshness[name] == expected for name, expected in bindings.items()),
        "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
        path,
        "predecessor freshness does not bind exact predecessor anchor bytes",
    )
    expected_digest = _plain_digest_projection(
        freshness,
        null_fields=("freshnessReceiptDigest",),
        empty_array_fields=("rootSignatures",),
    )
    require(
        freshness["freshnessReceiptDigest"] == expected_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.freshnessReceiptDigest",
        "predecessor freshness receipt digest mismatch",
    )
    observed_at = _timestamp(freshness["observedAt"], f"{path}.observedAt")
    expires_at = _timestamp(freshness["expiresAt"], f"{path}.expiresAt")
    require(
        observed_at <= began_at <= expires_at
        and observed_at < expires_at
        and expires_at - observed_at <= timedelta(seconds=300),
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        path,
        (
            "predecessor freshness is not structurally live at caller-supplied "
            "read-set beganAt"
        ),
    )
    require(
        all(signed_at <= observed_at for signed_at in final_receipt_signature_times),
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        f"{path}.observedAt",
        "freshness observation predates a final-receipt quorum signature",
    )
    _verify_root_signature_structure(
        freshness["rootSignatures"],
        path=f"{path}.rootSignatures",
        not_before=observed_at,
        not_after=min(expires_at, began_at + timedelta(seconds=30)),
    )


def _verify_preflight_structure(
    preflight: Mapping[str, Any],
    *,
    host_id: str,
    predecessor_anchor_digest_or_null: str | None,
    predecessor_authority_id_or_null: str | None,
    began_at: datetime,
) -> None:
    path = "publicationDecision.rollbackAuthorityPreflight.state"
    expected_digest = _digest_projection(
        _ROLLBACK_PREFLIGHT_DOMAIN,
        preflight,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
    )
    require(
        preflight["receiptDigest"] == expected_digest,
        "PUBLICATION_DECISION_ROLLBACK_DIGEST_INVALID",
        f"{path}.receiptDigest",
        "rollback preflight receipt digest mismatch",
    )
    require(
        preflight["hostId"] == host_id
        and preflight["predecessorAnchorDigestOrNull"]
        == predecessor_anchor_digest_or_null,
        "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
        path,
        "rollback preflight does not bind the exact host/predecessor",
    )
    if predecessor_authority_id_or_null is not None:
        require(
            preflight["authorityId"] == predecessor_authority_id_or_null,
            "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
            f"{path}.authorityId",
            "rollback preflight authority differs from the predecessor authority",
        )
    require(
        preflight["unresolvedReservationCount"] == 0,
        "PUBLICATION_DECISION_ROLLBACK_UNRESOLVED",
        f"{path}.unresolvedReservationCount",
        "rollback authority reported an unresolved reservation",
    )
    checked_at = _timestamp(preflight["checkedAt"], f"{path}.checkedAt")
    expires_at = _timestamp(preflight["expiresAt"], f"{path}.expiresAt")
    require(
        checked_at <= began_at <= expires_at
        and checked_at < expires_at
        and expires_at - checked_at <= timedelta(seconds=300),
        "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID",
        path,
        (
            "preflight is not structurally live at caller-supplied read-set "
            "beganAt"
        ),
    )
    _verify_root_signature_structure(
        preflight["rootSignatures"],
        path=f"{path}.rootSignatures",
        not_before=checked_at,
        not_after=min(expires_at, began_at),
    )


def _replay_inventory(
    schemas: ContractSchemas,
    inventory: VerifiedInventoryContext,
    *,
    max_records: int,
) -> VerifiedInventoryContext:
    require_factory_verified(
        inventory,
        VerifiedInventoryContext,
        code="PUBLICATION_DECISION_CURRENT_INVENTORY_INVALID",
        path="publicationDecision.currentInventory",
        message="current inventory must come from verify_inventory_context",
    )
    require(
        len(inventory.device_records) <= max_records,
        "PUBLICATION_DECISION_TOO_LARGE",
        "publicationDecision.currentInventory.deviceRecords",
        f"full publication is bounded to {max_records} current records",
    )
    replayed = verify_inventory_context(
        schemas,
        inventory.trust,
        host_authority_before=inventory.host_authority_canonical_bytes,
        host_snapshot=inventory.host_snapshot_canonical_bytes,
        device_records=tuple(
            record.canonical_bytes for record in inventory.device_records
        ),
        host_authority_after=inventory.host_authority_canonical_bytes,
        now=inventory.verified_at,
    )
    require(
        replayed.inventory_verification_receipt_canonical_bytes
        == inventory.inventory_verification_receipt_canonical_bytes,
        "PUBLICATION_DECISION_CURRENT_INVENTORY_REPLAY_MISMATCH",
        "publicationDecision.currentInventory",
        "current inventory differs when replayed from retained canonical bytes",
    )
    return replayed


def _cas_expectation(
    *,
    repository_id: str,
    host: _VerifiedArtifact,
    availability: _VerifiedArtifact,
    capability_policy_authority: _VerifiedArtifact,
    capability_policy_hash: str,
    freshness_policy_authority: _VerifiedArtifact,
    freshness_policy_hash: str,
) -> dict[str, Any]:
    host_state = host.state
    availability_state = availability.state
    capability_state = capability_policy_authority.state
    freshness_state = freshness_policy_authority.state
    expectation = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_CAS_EXPECTATION",
        "schemaVersion": 1,
        "repositoryId": repository_id,
        "hostAuthority": {
            "authorityId": host_state["hostId"],
            "resourceVersion": host_state["resourceVersion"],
            "instanceBytesSha256": host.state_canonical_sha256,
        },
        "availabilityAuthority": {
            "authorityId": availability_state["availabilityAuthorityId"],
            "resourceVersion": availability_state["resourceVersion"],
            "instanceBytesSha256": availability.state_canonical_sha256,
        },
        "capabilityPolicyAuthority": {
            "authorityId": capability_state["policyAuthorityId"],
            "resourceVersion": capability_state["resourceVersion"],
            "policyHash": capability_policy_hash,
            "instanceBytesSha256": (
                capability_policy_authority.state_canonical_sha256
            ),
        },
        "freshnessPolicyAuthority": {
            "authorityId": freshness_state["freshnessPolicyAuthorityId"],
            "resourceVersion": freshness_state["resourceVersion"],
            "policyHash": freshness_policy_hash,
            "instanceBytesSha256": (
                freshness_policy_authority.state_canonical_sha256
            ),
        },
        "expectationHash": None,
    }
    expectation["expectationHash"] = _digest_projection(
        _CAS_EXPECTATION_DOMAIN,
        expectation,
        null_fields=("expectationHash",),
    )
    return expectation


def _receipt_binding_values(
    *,
    host: _VerifiedArtifact,
    availability: _VerifiedArtifact,
    capability_policy: _VerifiedArtifact,
    capability_policy_authority: _VerifiedArtifact,
    freshness_policy: _VerifiedArtifact,
    freshness_policy_authority: _VerifiedArtifact,
    current_inventory: VerifiedInventoryContext | None,
    predecessor_anchor: _VerifiedArtifact | None,
    predecessor_freshness: _VerifiedArtifact | None,
    preflight: _VerifiedArtifact,
) -> dict[str, Any]:
    return {
        "hostAuthorityArtifactCanonicalSha256": (
            host.wrapper_canonical_sha256
        ),
        "availabilityAuthorityArtifactCanonicalSha256": (
            availability.wrapper_canonical_sha256
        ),
        "capabilityPolicyArtifactCanonicalSha256": (
            capability_policy.wrapper_canonical_sha256
        ),
        "capabilityPolicyAuthorityArtifactCanonicalSha256": (
            capability_policy_authority.wrapper_canonical_sha256
        ),
        "freshnessPolicyArtifactCanonicalSha256": (
            freshness_policy.wrapper_canonical_sha256
        ),
        "freshnessPolicyAuthorityArtifactCanonicalSha256": (
            freshness_policy_authority.wrapper_canonical_sha256
        ),
        "currentInventoryVerificationReceiptDigestOrNull": (
            None
            if current_inventory is None
            else current_inventory.inventory_verification_receipt_digest
        ),
        "predecessorRollbackAnchorArtifactCanonicalSha256OrNull": (
            None
            if predecessor_anchor is None
            else predecessor_anchor.wrapper_canonical_sha256
        ),
        "predecessorRollbackFreshnessArtifactCanonicalSha256OrNull": (
            None
            if predecessor_freshness is None
            else predecessor_freshness.wrapper_canonical_sha256
        ),
        "rollbackAuthorityPreflightArtifactCanonicalSha256": (
            preflight.wrapper_canonical_sha256
        ),
    }


def verify_structural_publication_read_set(
    schemas: ContractSchemas,
    *,
    host_authority_before: JsonDocument,
    availability_authority_before: JsonDocument,
    capability_policy: JsonDocument,
    capability_policy_authority: JsonDocument,
    freshness_policy: JsonDocument,
    freshness_policy_authority: JsonDocument,
    current_inventory: VerifiedInventoryContext | None,
    predecessor_rollback_anchor: JsonDocument | None,
    predecessor_rollback_freshness: JsonDocument | None,
    rollback_authority_preflight: JsonDocument,
    structural_transaction_read_receipt: JsonDocument,
    limits: PublicationDecisionVerifierLimits | None = None,
) -> StructuralPublicationReadSet:
    """Verify exact structural read bytes without claiming a product read."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_DECISION_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    checked_limits = _checked_limits(limits)
    receipt, receipt_raw, began_at = _verify_structural_receipt_shape(
        structural_transaction_read_receipt,
        limits=checked_limits,
    )

    host = _verify_artifact(
        schemas,
        host_authority_before,
        wrapper_schema_ref=HOST_AUTHORITY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_HOST_AUTHORITY_STATE_SCHEMA_REF,
        path="publicationDecision.hostAuthorityBefore",
        limits=checked_limits,
    )
    availability = _verify_artifact(
        schemas,
        availability_authority_before,
        wrapper_schema_ref=AVAILABILITY_AUTHORITY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_AVAILABILITY_AUTHORITY_STATE_SCHEMA_REF,
        path="publicationDecision.availabilityAuthorityBefore",
        limits=checked_limits,
    )
    capability = _verify_artifact(
        schemas,
        capability_policy,
        wrapper_schema_ref=CAPABILITY_POLICY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_CAPABILITY_POLICY_STATE_SCHEMA_REF,
        path="publicationDecision.capabilityPolicy",
        limits=checked_limits,
    )
    capability_authority = _verify_artifact(
        schemas,
        capability_policy_authority,
        wrapper_schema_ref=CAPABILITY_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_CAPABILITY_POLICY_AUTHORITY_STATE_SCHEMA_REF,
        path="publicationDecision.capabilityPolicyAuthority",
        limits=checked_limits,
    )
    freshness = _verify_artifact(
        schemas,
        freshness_policy,
        wrapper_schema_ref=FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_FRESHNESS_POLICY_STATE_SCHEMA_REF,
        path="publicationDecision.freshnessPolicy",
        limits=checked_limits,
    )
    freshness_authority = _verify_artifact(
        schemas,
        freshness_policy_authority,
        wrapper_schema_ref=FRESHNESS_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_FRESHNESS_POLICY_AUTHORITY_STATE_SCHEMA_REF,
        path="publicationDecision.freshnessPolicyAuthority",
        limits=checked_limits,
    )
    preflight = _verify_artifact(
        schemas,
        rollback_authority_preflight,
        wrapper_schema_ref=ROLLBACK_PREFLIGHT_ARTIFACT_SCHEMA_REF,
        state_schema_ref=_ROLLBACK_PREFLIGHT_STATE_SCHEMA_REF,
        path="publicationDecision.rollbackAuthorityPreflight",
        limits=checked_limits,
    )

    require(
        (predecessor_rollback_anchor is None)
        == (predecessor_rollback_freshness is None),
        "PUBLICATION_DECISION_ROLLBACK_PAIR_INVALID",
        "publicationDecision.predecessorRollback",
        "predecessor anchor and freshness must both be null or both be present",
    )
    predecessor_anchor = (
        None
        if predecessor_rollback_anchor is None
        else _verify_artifact(
            schemas,
            predecessor_rollback_anchor,
            wrapper_schema_ref=ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF,
            state_schema_ref=_ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
            path="publicationDecision.predecessorRollbackAnchor",
            limits=checked_limits,
        )
    )
    predecessor_freshness = (
        None
        if predecessor_rollback_freshness is None
        else _verify_artifact(
            schemas,
            predecessor_rollback_freshness,
            wrapper_schema_ref=ROLLBACK_FRESHNESS_ARTIFACT_SCHEMA_REF,
            state_schema_ref=_ROLLBACK_FRESHNESS_STATE_SCHEMA_REF,
            path="publicationDecision.predecessorRollbackFreshness",
            limits=checked_limits,
        )
    )

    verified_policy = verify_capability_policy(
        schemas,
        capability.state_canonical_bytes,
        verified_at=began_at,
    )
    capability_authority_state = capability_authority.state
    require(
        capability_authority_state["policyId"] == verified_policy.policy_id
        and capability_authority_state["policyVersion"]
        == verified_policy.policy_version
        and capability_authority_state["policyDigest"]
        == verified_policy.policy_hash,
        "PUBLICATION_DECISION_POLICY_AUTHORITY_MISMATCH",
        "publicationDecision.capabilityPolicyAuthority.state",
        "capability policy authority does not bind exact active policy bytes",
    )
    freshness_hash = _verify_freshness_policy_hash(freshness.state)
    freshness_authority_state = freshness_authority.state
    require(
        freshness_authority_state["policyId"] == freshness.state["policyId"]
        and freshness_authority_state["policyVersion"]
        == freshness.state["policyVersion"]
        and freshness_authority_state["policyDigest"] == freshness_hash,
        "PUBLICATION_DECISION_POLICY_AUTHORITY_MISMATCH",
        "publicationDecision.freshnessPolicyAuthority.state",
        "freshness policy authority does not bind exact active policy bytes",
    )

    verified_inventory = (
        None
        if current_inventory is None
        else _replay_inventory(
            schemas,
            current_inventory,
            max_records=checked_limits.max_full_device_records,
        )
    )
    if verified_inventory is not None:
        require(
            verified_inventory.trust.verified_at
            <= verified_inventory.verified_at
            <= verified_inventory.trust.freshness_expires_at,
            "PUBLICATION_DECISION_CURRENT_INVENTORY_TIME_INVALID",
            "publicationDecision.currentInventory.verifiedAt",
            (
                "current inventory verification is outside its retained trust "
                "freshness interval"
            ),
        )
        require(
            verified_inventory.verified_at
            <= began_at
            <= verified_inventory.trust.freshness_expires_at,
            "PUBLICATION_DECISION_CURRENT_INVENTORY_TIME_INVALID",
            "publicationDecision.currentInventory",
            (
                "caller-supplied read-set beganAt is outside the current "
                "inventory verification/trust freshness interval"
            ),
        )
    host_state = host.state
    if verified_inventory is None:
        require(
            host_state["lastSnapshotEpoch"] == 0
            and host_state["currentSnapshotContentHash"] is None
            and host_state["cooperationState"] == "RECONCILING",
            "PUBLICATION_DECISION_CURRENT_STATE_MISMATCH",
            "publicationDecision.hostAuthorityBefore.state",
            "an unpublished incarnation requires the closed RECONCILING zero form",
        )
    else:
        require(
            host.state_canonical_bytes
            == verified_inventory.host_authority_canonical_bytes,
            "PUBLICATION_DECISION_CURRENT_STATE_MISMATCH",
            "publicationDecision.currentInventory.hostAuthority",
            "current inventory HostAuthority bytes differ from read-set bytes",
        )
        require(
            host_state["lastSnapshotEpoch"] == verified_inventory.snapshot_epoch
            and host_state["currentSnapshotContentHash"]
            == verified_inventory.snapshot_content_hash,
            "PUBLICATION_DECISION_CURRENT_STATE_MISMATCH",
            "publicationDecision.currentInventory.hostSnapshot",
            "current inventory snapshot is not the retained HostAuthority pointer",
        )
        require(
            predecessor_anchor is not None,
            "PUBLICATION_DECISION_ROLLBACK_PAIR_INVALID",
            "publicationDecision.predecessorRollbackAnchor",
            "a current snapshot requires its retained predecessor anchor",
    )

    if predecessor_anchor is not None:
        final_receipt_signature_times = (
            _verify_predecessor_anchor_structure(predecessor_anchor.state)
        )
        assert predecessor_freshness is not None
        _verify_predecessor_freshness_structure(
            predecessor_freshness.state,
            predecessor_freshness.state_canonical_bytes,
            anchor=predecessor_anchor.state,
            anchor_raw=predecessor_anchor.state_canonical_bytes,
            anchor_schema_sha256=schemas.digest_for_ref(
                _ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
                path=(
                    "publicationDecision.predecessorRollbackFreshness."
                    "anchorSchemaSha256"
                ),
            ),
            began_at=began_at,
            final_receipt_signature_times=final_receipt_signature_times,
        )
        if verified_inventory is not None:
            anchor_state = predecessor_anchor.state
            require(
                anchor_state["hostId"] == verified_inventory.host_id
                and anchor_state["kernelBootId"]
                == verified_inventory.kernel_boot_id
                and anchor_state["hostEpoch"] == verified_inventory.host_epoch
                and anchor_state["agentIdentity"]
                == verified_inventory.agent_identity
                and anchor_state["agentGeneration"]
                == verified_inventory.agent_generation
                and anchor_state["acceptedSnapshotEpoch"]
                == verified_inventory.snapshot_epoch
                and anchor_state["acceptedSnapshotContentHash"]
                == verified_inventory.snapshot_content_hash
                and anchor_state["acceptedHostAuthorityResourceVersion"]
                == verified_inventory.snapshot_authority_resource_version,
                "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
                "publicationDecision.predecessorRollbackAnchor.state",
                "predecessor anchor does not bind the exact current inventory",
            )

    predecessor_digest = (
        None
        if predecessor_anchor is None
        else predecessor_anchor.state["anchorDigest"]
    )
    predecessor_authority_id = (
        None
        if predecessor_anchor is None
        else predecessor_anchor.state["authorityId"]
    )
    _verify_preflight_structure(
        preflight.state,
        host_id=host_state["hostId"],
        predecessor_anchor_digest_or_null=predecessor_digest,
        predecessor_authority_id_or_null=predecessor_authority_id,
        began_at=began_at,
    )
    if predecessor_freshness is not None:
        require(
            predecessor_freshness.state["verifierNonce"]
            != preflight.state["verifierNonce"],
            "PUBLICATION_DECISION_ROLLBACK_NONCE_REUSE",
            "publicationDecision.rollbackAuthorityPreflight.verifierNonce",
            (
                "predecessor freshness and rollback preflight must use "
                "distinct verifier nonces"
            ),
        )

    for state, name in (
        (host_state, "hostAuthorityBefore.state.lastObservedAt"),
        (availability.state, "availabilityAuthorityBefore.state.lastMutatedAt"),
    ):
        timestamp_name = (
            "lastObservedAt"
            if "lastObservedAt" in state
            else "lastMutatedAt"
        )
        require(
            _timestamp(
                state[timestamp_name],
                f"publicationDecision.{name}",
            )
            <= began_at,
            "PUBLICATION_DECISION_FUTURE_BASIS",
            f"publicationDecision.{name}",
            "authority time basis is later than caller-supplied beganAt",
        )

    expectation = _cas_expectation(
        repository_id=receipt["repositoryId"],
        host=host,
        availability=availability,
        capability_policy_authority=capability_authority,
        capability_policy_hash=verified_policy.policy_hash,
        freshness_policy_authority=freshness_authority,
        freshness_policy_hash=freshness_hash,
    )
    schemas.validate_ref(
        CAS_EXPECTATION_SCHEMA_REF,
        expectation,
        "publicationDecision.casExpectation",
    )
    require(
        receipt["expectationHash"] == expectation["expectationHash"],
        "PUBLICATION_DECISION_EXPECTATION_MISMATCH",
        "publicationDecision.structuralTransactionReadReceipt.expectationHash",
        "receipt does not bind the exact four-authority expectation",
    )
    receipt_bindings = _receipt_binding_values(
        host=host,
        availability=availability,
        capability_policy=capability,
        capability_policy_authority=capability_authority,
        freshness_policy=freshness,
        freshness_policy_authority=freshness_authority,
        current_inventory=verified_inventory,
        predecessor_anchor=predecessor_anchor,
        predecessor_freshness=predecessor_freshness,
        preflight=preflight,
    )
    require(
        all(receipt[name] == expected for name, expected in receipt_bindings.items()),
        "PUBLICATION_DECISION_RECEIPT_BINDING_MISMATCH",
        "publicationDecision.structuralTransactionReadReceipt",
        "receipt artifact hashes do not bind the exact supplied read set",
    )

    return StructuralPublicationReadSet._construct(
        limits=checked_limits,
        repository_id=receipt["repositoryId"],
        transaction_id=receipt["transactionId"],
        isolation="SERIALIZABLE",
        began_at=began_at,
        began_at_text=receipt["beganAt"],
        host_authority_before_artifact=host.wrapper,
        host_authority_before_artifact_canonical_bytes=(
            host.wrapper_canonical_bytes
        ),
        host_authority_before=host.state,
        host_authority_before_canonical_bytes=host.state_canonical_bytes,
        availability_authority_before_artifact=availability.wrapper,
        availability_authority_before_artifact_canonical_bytes=(
            availability.wrapper_canonical_bytes
        ),
        availability_authority_before=availability.state,
        availability_authority_before_canonical_bytes=(
            availability.state_canonical_bytes
        ),
        capability_policy_artifact=capability.wrapper,
        capability_policy_artifact_canonical_bytes=(
            capability.wrapper_canonical_bytes
        ),
        capability_policy=verified_policy,
        capability_policy_authority_artifact=capability_authority.wrapper,
        capability_policy_authority_artifact_canonical_bytes=(
            capability_authority.wrapper_canonical_bytes
        ),
        capability_policy_authority=capability_authority.state,
        capability_policy_authority_canonical_bytes=(
            capability_authority.state_canonical_bytes
        ),
        freshness_policy_artifact=freshness.wrapper,
        freshness_policy_artifact_canonical_bytes=(
            freshness.wrapper_canonical_bytes
        ),
        freshness_policy=freshness.state,
        freshness_policy_canonical_bytes=freshness.state_canonical_bytes,
        freshness_policy_hash=freshness_hash,
        freshness_policy_authority_artifact=freshness_authority.wrapper,
        freshness_policy_authority_artifact_canonical_bytes=(
            freshness_authority.wrapper_canonical_bytes
        ),
        freshness_policy_authority=freshness_authority.state,
        freshness_policy_authority_canonical_bytes=(
            freshness_authority.state_canonical_bytes
        ),
        current_inventory_or_null=verified_inventory,
        predecessor_rollback_anchor_artifact_or_null=(
            None if predecessor_anchor is None else predecessor_anchor.wrapper
        ),
        predecessor_rollback_anchor_artifact_canonical_bytes_or_null=(
            None
            if predecessor_anchor is None
            else predecessor_anchor.wrapper_canonical_bytes
        ),
        predecessor_rollback_anchor_or_null=(
            None if predecessor_anchor is None else predecessor_anchor.state
        ),
        predecessor_rollback_anchor_canonical_bytes_or_null=(
            None
            if predecessor_anchor is None
            else predecessor_anchor.state_canonical_bytes
        ),
        predecessor_rollback_freshness_artifact_or_null=(
            None
            if predecessor_freshness is None
            else predecessor_freshness.wrapper
        ),
        predecessor_rollback_freshness_artifact_canonical_bytes_or_null=(
            None
            if predecessor_freshness is None
            else predecessor_freshness.wrapper_canonical_bytes
        ),
        predecessor_rollback_freshness_or_null=(
            None
            if predecessor_freshness is None
            else predecessor_freshness.state
        ),
        predecessor_rollback_freshness_canonical_bytes_or_null=(
            None
            if predecessor_freshness is None
            else predecessor_freshness.state_canonical_bytes
        ),
        rollback_authority_preflight_artifact=preflight.wrapper,
        rollback_authority_preflight_artifact_canonical_bytes=(
            preflight.wrapper_canonical_bytes
        ),
        rollback_authority_preflight=preflight.state,
        rollback_authority_preflight_canonical_bytes=(
            preflight.state_canonical_bytes
        ),
        cas_expectation=_freeze_json(expectation),
        expectation_hash=expectation["expectationHash"],
        structural_transaction_read_receipt=_freeze_json(receipt),
        structural_transaction_read_receipt_canonical_bytes=receipt_raw,
        context_digest=receipt["receiptDigest"],
        authority_boundary=HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY,
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_structural_publication_read_set(
    read_set: StructuralPublicationReadSet,
) -> StructuralPublicationReadSet:
    """Replay a structural read set from only its retained canonical bytes."""

    require_factory_verified(
        read_set,
        StructuralPublicationReadSet,
        code="PUBLICATION_DECISION_READ_SET_INVALID",
        path="publicationDecision.readSet",
        message=(
            "read set must come from verify_structural_publication_read_set"
        ),
    )
    replayed = verify_structural_publication_read_set(
        read_set._schemas,
        host_authority_before=(
            read_set.host_authority_before_artifact_canonical_bytes
        ),
        availability_authority_before=(
            read_set.availability_authority_before_artifact_canonical_bytes
        ),
        capability_policy=(
            read_set.capability_policy_artifact_canonical_bytes
        ),
        capability_policy_authority=(
            read_set.capability_policy_authority_artifact_canonical_bytes
        ),
        freshness_policy=read_set.freshness_policy_artifact_canonical_bytes,
        freshness_policy_authority=(
            read_set.freshness_policy_authority_artifact_canonical_bytes
        ),
        current_inventory=read_set.current_inventory_or_null,
        predecessor_rollback_anchor=(
            read_set.predecessor_rollback_anchor_artifact_canonical_bytes_or_null
        ),
        predecessor_rollback_freshness=(
            read_set
            .predecessor_rollback_freshness_artifact_canonical_bytes_or_null
        ),
        rollback_authority_preflight=(
            read_set.rollback_authority_preflight_artifact_canonical_bytes
        ),
        structural_transaction_read_receipt=(
            read_set.structural_transaction_read_receipt_canonical_bytes
        ),
        limits=read_set.limits,
    )
    require(
        replayed.context_digest == read_set.context_digest,
        "PUBLICATION_DECISION_READ_SET_REPLAY_MISMATCH",
        "publicationDecision.readSet.contextDigest",
        "structural read set digest changed during replay",
    )
    return replayed


def _age_micros(later: datetime, earlier: datetime, path: str) -> int:
    require(
        earlier <= later,
        "PUBLICATION_DECISION_FUTURE_BASIS",
        path,
        "time basis is later than caller-supplied beganAt",
    )
    delta = later - earlier
    return (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def _current_projection(
    schemas: ContractSchemas,
    inventory: VerifiedInventoryContext,
) -> dict[str, Any]:
    projection = derive_no_change_projection(
        snapshot=inventory.host_snapshot,
        agent_identity=inventory.agent_identity,
        topology_digest=inventory.snapshot_semantics.topology_digest,
        provider_facts_digest=inventory.snapshot_semantics.provider_facts_digest,
    )
    schemas.validate_ref(
        NO_CHANGE_PROJECTION_SCHEMA_REF,
        projection,
        "publicationDecision.currentNoChangeProjection",
    )
    return projection


def _current_oldest_mandatory_observation(
    inventory: VerifiedInventoryContext,
    selectors: Sequence[Mapping[str, Any]],
    *,
    began_at: datetime,
) -> datetime:
    oldest_by_selector: dict[tuple[str, str], datetime] = {}
    requested = {
        (selector["providerId"], selector["factId"]) for selector in selectors
    }
    for record in inventory.device_records:
        for fact in record.document["provenance"]["providerFacts"]:
            key = (fact["providerId"], fact["factId"])
            if key not in requested:
                continue
            observed_at = _timestamp(
                fact["observedAt"],
                (
                    "publicationDecision.currentInventory.providerFacts"
                    f"[{key[0]},{key[1]}].observedAt"
                ),
            )
            require(
                observed_at <= began_at,
                "PUBLICATION_DECISION_FUTURE_BASIS",
                "publicationDecision.currentInventory.providerFacts",
                "mandatory evidence observation is later than beganAt",
            )
            previous = oldest_by_selector.get(key)
            if previous is None or observed_at < previous:
                oldest_by_selector[key] = observed_at
    missing = requested - set(oldest_by_selector)
    require(
        not missing,
        "PUBLICATION_DECISION_MANDATORY_FACT_MISSING",
        "publicationDecision.currentInventory.providerFacts",
        f"current snapshot lacks mandatory selector(s): {sorted(missing)!r}",
    )
    return min(oldest_by_selector.values())


def _freshness_decision(
    *,
    read_set: StructuralPublicationReadSet,
    current: VerifiedInventoryContext | None,
    policy_changed: bool,
) -> dict[str, Any]:
    policy = read_set.freshness_policy
    evaluated_at = read_set.began_at
    if current is None:
        disposition = "GENESIS_NO_CURRENT"
        current_captured_text = None
        oldest_text = None
        refresh_required = False
    elif policy_changed:
        disposition = "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR"
        _age_micros(
            evaluated_at,
            current.captured_at,
            "publicationDecision.currentSnapshot.capturedAt",
        )
        current_captured_text = _format_timestamp(current.captured_at)
        oldest_text = None
        refresh_required = False
    else:
        disposition = "CURRENT_POLICY_MATCHED"
        snapshot_age = _age_micros(
            evaluated_at,
            current.captured_at,
            "publicationDecision.currentSnapshot.capturedAt",
        )
        oldest = _current_oldest_mandatory_observation(
            current,
            policy["mandatoryProviderFacts"],
            began_at=evaluated_at,
        )
        evidence_age = _age_micros(
            evaluated_at,
            oldest,
            "publicationDecision.currentMandatoryEvidence.observedAt",
        )
        current_captured_text = _format_timestamp(current.captured_at)
        oldest_text = _format_timestamp(oldest)
        refresh_required = (
            snapshot_age >= policy["maximumSnapshotAgeMicros"]
            or evidence_age >= policy["maximumMandatoryEvidenceAgeMicros"]
        )
    decision = {
        "policyId": policy["policyId"],
        "policyVersion": policy["policyVersion"],
        "policyDigest": policy["policyHash"],
        "policyAuthorityResourceVersion": (
            read_set.freshness_policy_authority["resourceVersion"]
        ),
        "evaluatedAt": read_set.began_at_text,
        "evaluationDisposition": disposition,
        "maximumSnapshotAgeMicros": policy["maximumSnapshotAgeMicros"],
        "maximumMandatoryEvidenceAgeMicros": (
            policy["maximumMandatoryEvidenceAgeMicros"]
        ),
        "currentSnapshotCapturedAtOrNull": current_captured_text,
        "oldestMandatoryEvidenceObservedAtOrNull": oldest_text,
        "refreshRequired": refresh_required,
        "decisionDigest": None,
    }
    decision["decisionDigest"] = _digest_projection(
        _FRESHNESS_DECISION_DOMAIN,
        decision,
        null_fields=("decisionDigest",),
    )
    read_set._schemas.validate_ref(
        FRESHNESS_DECISION_SCHEMA_REF,
        decision,
        "publicationDecision.freshnessDecision",
    )
    return decision


def _require_candidate_binding(
    capture: VerifiedHostSnapshotCaptureClosureContext,
    read_set: StructuralPublicationReadSet,
) -> None:
    batch = capture.capture_batch
    host = read_set.host_authority_before
    require(
        batch["hostId"] == host["hostId"]
        and batch["kernelBootId"] == host["kernelBootId"]
        and batch["hostEpoch"] == host["hostEpoch"]
        and batch["agentIdentity"] == host["agentIdentity"]
        and batch["agentGeneration"] == host["agentGeneration"],
        "PUBLICATION_DECISION_CAPTURE_BINDING_MISMATCH",
        "publicationDecision.captureBatch",
        "candidate capture does not bind the exact HostAuthority incarnation",
    )
    require(
        capture.capability_policy.canonical_bytes
        == read_set.capability_policy.canonical_bytes,
        "PUBLICATION_DECISION_POLICY_MISMATCH",
        "publicationDecision.capture.capabilityPolicy",
        "capture capability policy bytes differ from the read-set policy",
    )
    require(
        capture.freshness_policy_canonical_bytes
        == read_set.freshness_policy_canonical_bytes,
        "PUBLICATION_DECISION_POLICY_MISMATCH",
        "publicationDecision.capture.freshnessPolicy",
        "capture freshness policy bytes differ from the read-set policy",
    )
    completed_at = _timestamp(
        batch["captureCompletedAt"],
        "publicationDecision.captureBatch.captureCompletedAt",
    )
    require(
        completed_at <= read_set.began_at,
        "PUBLICATION_DECISION_FUTURE_BASIS",
        "publicationDecision.captureBatch.captureCompletedAt",
        "candidate capture completion is later than caller-supplied beganAt",
    )
    require(
        read_set.capability_policy.effective_at
        <= read_set.began_at
        < read_set.capability_policy.expires_at,
        "PUBLICATION_DECISION_CAPABILITY_POLICY_TIME_INVALID",
        "publicationDecision.capabilityPolicy",
        "capability policy is not active at caller-supplied beganAt",
    )
    expected_snapshot_epoch = host["lastSnapshotEpoch"] + 1
    expected_resource_version = host["resourceVersion"] + 1
    require(
        capture.candidate_snapshot_epoch == expected_snapshot_epoch,
        "PUBLICATION_DECISION_COORDINATE_MISMATCH",
        "publicationDecision.capture.candidateSnapshotEpoch",
        "candidate snapshot epoch is not HostAuthority-before plus one",
    )
    require(
        capture.candidate_resource_version == expected_resource_version,
        "PUBLICATION_DECISION_COORDINATE_MISMATCH",
        "publicationDecision.capture.candidateResourceVersion",
        "candidate resource version is not HostAuthority-before plus one",
    )


def _decision_names(
    *,
    current: VerifiedInventoryContext | None,
    predecessor_anchor: Mapping[str, Any] | None,
    projections_equal: bool,
    freshness: Mapping[str, Any],
) -> tuple[str, str]:
    if current is None:
        if predecessor_anchor is None:
            return "GENESIS", "GENESIS_COMMITTED"
        return "INCARNATION_GENESIS", "INCARNATION_GENESIS_COMMITTED"
    if freshness["evaluationDisposition"] == (
        "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR"
    ):
        return "SUCCESSOR", "SUCCESSOR_COMMITTED"
    if not projections_equal:
        return "SUCCESSOR", "SUCCESSOR_COMMITTED"
    if freshness["refreshRequired"]:
        return "REFRESH", "REFRESH_COMMITTED"
    return "NO_CHANGE", "NO_CHANGE"


def verify_host_snapshot_publication_decision(
    capture: VerifiedHostSnapshotCaptureClosureContext,
    read_set: StructuralPublicationReadSet,
) -> VerifiedHostSnapshotPublicationDecisionContext:
    """Derive the five-way publication decision without caller labels or time."""

    require_factory_verified(
        capture,
        VerifiedHostSnapshotCaptureClosureContext,
        code="PUBLICATION_DECISION_CAPTURE_INVALID",
        path="publicationDecision.capture",
        message="capture must come from verify_host_snapshot_capture_closure",
    )
    require_factory_verified(
        read_set,
        StructuralPublicationReadSet,
        code="PUBLICATION_DECISION_READ_SET_INVALID",
        path="publicationDecision.readSet",
        message=(
            "read set must come from verify_structural_publication_read_set"
        ),
    )

    # Count gates intentionally precede capture/read-set replay and every record
    # traversal in this full-publication layer.
    candidate_count = len(capture.candidate_device_records.device_records)
    current_count = (
        0
        if read_set.current_inventory_or_null is None
        else len(read_set.current_inventory_or_null.device_records)
    )
    maximum = read_set.limits.max_full_device_records
    require(
        candidate_count <= maximum,
        "PUBLICATION_DECISION_TOO_LARGE",
        "publicationDecision.capture.candidateDeviceRecords",
        f"full publication is bounded to {maximum} candidate records",
    )
    require(
        current_count <= maximum,
        "PUBLICATION_DECISION_TOO_LARGE",
        "publicationDecision.currentInventory.deviceRecords",
        f"full publication is bounded to {maximum} current records",
    )

    verified_read_set = replay_structural_publication_read_set(read_set)
    verified_capture = replay_host_snapshot_capture_closure(
        verified_read_set._schemas,
        capture,
    )
    _require_candidate_binding(verified_capture, verified_read_set)

    current = verified_read_set.current_inventory_or_null
    predecessor_anchor = (
        verified_read_set.predecessor_rollback_anchor_or_null
    )
    if current is None and predecessor_anchor is not None:
        host = verified_read_set.host_authority_before
        require(
            predecessor_anchor["hostId"] == host["hostId"],
            "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH",
            "publicationDecision.predecessorRollbackAnchor.state.hostId",
            "incarnation predecessor must belong to the same stable host",
        )
        predecessor_incarnation = (
            predecessor_anchor["kernelBootId"],
            predecessor_anchor["hostEpoch"],
            predecessor_anchor["agentIdentity"],
            predecessor_anchor["agentGeneration"],
        )
        candidate_incarnation = (
            host["kernelBootId"],
            host["hostEpoch"],
            host["agentIdentity"],
            host["agentGeneration"],
        )
        require(
            predecessor_incarnation != candidate_incarnation,
            "PUBLICATION_DECISION_INCARNATION_INVALID",
            "publicationDecision.predecessorRollbackAnchor.state",
            "incarnation genesis must differ from the retained predecessor",
        )
        require(
            host["hostEpoch"] >= predecessor_anchor["hostEpoch"]
            and host["agentGeneration"]
            >= predecessor_anchor["agentGeneration"]
            and (
                host["hostEpoch"] > predecessor_anchor["hostEpoch"]
                or host["agentGeneration"]
                > predecessor_anchor["agentGeneration"]
            ),
            "PUBLICATION_DECISION_INCARNATION_INVALID",
            "publicationDecision.hostAuthorityBefore",
            (
                "incarnation genesis cannot regress either hostEpoch or "
                "agentGeneration and must strictly advance at least one"
            ),
        )

    current_projection = (
        None
        if current is None
        else _current_projection(verified_read_set._schemas, current)
    )
    candidate_projection = _thaw_json(verified_capture.no_change_projection)
    verified_read_set._schemas.validate_ref(
        NO_CHANGE_PROJECTION_SCHEMA_REF,
        candidate_projection,
        "publicationDecision.candidateNoChangeProjection",
    )
    projections_equal = (
        current_projection is not None
        and canonical_json_bytes(current_projection)
        == canonical_json_bytes(candidate_projection)
    )
    policy_changed = (
        current is not None
        and current.host_snapshot["snapshotFreshnessPolicyHash"]
        != verified_read_set.freshness_policy_hash
    )
    freshness = _freshness_decision(
        read_set=verified_read_set,
        current=current,
        policy_changed=policy_changed,
    )
    decision_kind, publication_decision = _decision_names(
        current=current,
        predecessor_anchor=predecessor_anchor,
        projections_equal=projections_equal,
        freshness=freshness,
    )
    write_required = decision_kind != "NO_CHANGE"
    if write_required:
        capture_completed_at = _timestamp(
            verified_capture.capture_batch["captureCompletedAt"],
            "publicationDecision.captureBatch.captureCompletedAt",
        )
        preflight_checked_at = _timestamp(
            verified_read_set.rollback_authority_preflight["checkedAt"],
            "publicationDecision.rollbackAuthorityPreflight.checkedAt",
        )
        require(
            capture_completed_at <= preflight_checked_at,
            "PUBLICATION_DECISION_CAPTURE_PREFLIGHT_ORDER_INVALID",
            "publicationDecision.rollbackAuthorityPreflight.checkedAt",
            (
                "a write-required decision requires captureCompletedAt no "
                "later than rollback preflight checkedAt"
            ),
        )
    if write_required:
        persisted_source = "candidateDeviceRecords"
        persisted_records = (
            verified_capture.candidate_device_records.device_records
        )
    else:
        require(
            current is not None,
            "PUBLICATION_DECISION_INTERNAL_INVALID",
            "publicationDecision.persistedDeviceRecordSource",
            "NO_CHANGE requires a current inventory",
        )
        persisted_source = "currentDeviceRecordsOrNull"
        persisted_records = current.device_records

    cas_operands = _thaw_json(verified_read_set.cas_expectation)
    blockers = tuple(
        dict.fromkeys(
            (
                *verified_capture.product_evidence_blockers,
                *verified_read_set.product_evidence_blockers,
            )
        )
    )
    receipt = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_DECISION_CONTEXT",
        "schemaVersion": 1,
        "captureContextDigest": verified_capture.context_digest,
        "structuralReadSetDigest": verified_read_set.context_digest,
        "repositoryId": verified_read_set.repository_id,
        "transactionId": verified_read_set.transaction_id,
        "callerSuppliedBeganAt": verified_read_set.began_at_text,
        "decisionKind": decision_kind,
        "publicationDecision": publication_decision,
        "writeRequired": write_required,
        "persistedDeviceRecordSource": persisted_source,
        "persistedDeviceRecordCount": len(persisted_records),
        "currentNoChangeProjectionHashOrNull": (
            None
            if current_projection is None
            else current_projection["noChangeProjectionHash"]
        ),
        "candidateNoChangeProjectionHash": candidate_projection[
            "noChangeProjectionHash"
        ],
        "proposedSnapshotEpoch": verified_capture.candidate_snapshot_epoch,
        "proposedHostAuthorityResourceVersion": (
            verified_capture.candidate_resource_version
        ),
        "expectationHash": verified_read_set.expectation_hash,
        "freshnessDecision": freshness,
        "authorityBoundary": (
            HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY
        ),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(blockers),
        "contextDigest": None,
    }
    context_digest = _digest_projection(
        _DECISION_CONTEXT_DOMAIN,
        receipt,
        null_fields=("contextDigest",),
    )
    receipt["contextDigest"] = context_digest
    receipt_raw = canonical_json_bytes(receipt)
    return VerifiedHostSnapshotPublicationDecisionContext._construct(
        limits=verified_read_set.limits,
        capture=verified_capture,
        read_set=verified_read_set,
        decision_kind=decision_kind,
        publication_decision=publication_decision,
        write_required=write_required,
        persisted_device_record_source=persisted_source,
        persisted_device_records=persisted_records,
        current_no_change_projection_or_null=(
            None
            if current_projection is None
            else _freeze_json(current_projection)
        ),
        candidate_no_change_projection=_freeze_json(candidate_projection),
        proposed_snapshot_epoch=verified_capture.candidate_snapshot_epoch,
        proposed_host_authority_resource_version=(
            verified_capture.candidate_resource_version
        ),
        cas_operands=_freeze_json(cas_operands),
        expectation_hash=verified_read_set.expectation_hash,
        freshness_decision=_freeze_json(freshness),
        freshness_decision_digest=freshness["decisionDigest"],
        context_receipt=_freeze_json(receipt),
        context_receipt_canonical_bytes=receipt_raw,
        context_digest=context_digest,
        authority_boundary=(
            HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY
        ),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=blockers,
    )


def replay_host_snapshot_publication_decision(
    context: VerifiedHostSnapshotPublicationDecisionContext,
) -> VerifiedHostSnapshotPublicationDecisionContext:
    """Replay one decision from its retained factory-produced contexts."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationDecisionContext,
        code="PUBLICATION_DECISION_CONTEXT_INVALID",
        path="publicationDecision.context",
        message=(
            "context must come from verify_host_snapshot_publication_decision"
        ),
    )
    replayed = verify_host_snapshot_publication_decision(
        context.capture,
        context.read_set,
    )
    require(
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes,
        "PUBLICATION_DECISION_CONTEXT_REPLAY_MISMATCH",
        "publicationDecision.context",
        "decision context differs when replayed from retained contexts",
    )
    return replayed


__all__ = [
    "AVAILABILITY_AUTHORITY_ARTIFACT_SCHEMA_REF",
    "CAPABILITY_POLICY_ARTIFACT_SCHEMA_REF",
    "CAPABILITY_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF",
    "DEFAULT_PUBLICATION_DECISION_LIMITS",
    "FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF",
    "FRESHNESS_POLICY_AUTHORITY_ARTIFACT_SCHEMA_REF",
    "HOST_AUTHORITY_ARTIFACT_SCHEMA_REF",
    "HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_EVIDENCE_BLOCKERS",
    "MAX_FULL_PUBLICATION_DEVICE_RECORDS",
    "PublicationDecisionVerifierLimits",
    "ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF",
    "ROLLBACK_FRESHNESS_ARTIFACT_SCHEMA_REF",
    "ROLLBACK_PREFLIGHT_ARTIFACT_SCHEMA_REF",
    "StructuralPublicationReadSet",
    "VerifiedHostSnapshotPublicationDecisionContext",
    "replay_host_snapshot_publication_decision",
    "replay_structural_publication_read_set",
    "verify_host_snapshot_publication_decision",
    "verify_structural_publication_read_set",
]
