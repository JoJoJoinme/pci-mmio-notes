"""Component-only verification of HostSnapshot rollback-authority closure.

This module consumes a factory-produced publication decision and verifies the
cryptographic rollback-authority artifacts surrounding it.  It never contacts
the authority, generates a nonce, opens a repository transaction, or accepts a
caller-declared repository commit time.  The returned context therefore proves
only deterministic replay of retained component bytes and is permanently
non-authorizing product evidence.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
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
from .errors import fail, require
from .host_snapshot_anchor import (
    HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN,
    HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
    HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
    _validate_anchor,
    _validate_final_receipt,
    _validate_prepare_receipt,
    verify_host_snapshot_anchor_binding,
)
from .inventory import (
    VerifiedInventoryContext,
    verify_inventory_context,
)
from .publication_capture import HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
from .publication_decision import (
    HOST_AUTHORITY_ARTIFACT_SCHEMA_REF,
    ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF,
    ROLLBACK_FRESHNESS_ARTIFACT_SCHEMA_REF,
    StructuralPublicationReadSet,
    VerifiedHostSnapshotPublicationDecisionContext,
    replay_host_snapshot_publication_decision,
)
from .trust import (
    JsonDocument,
    VerifiedTrustContext,
    _projection_digest,
    _require_digest,
    _timestamp,
    _utc_now,
    _validate_freshness,
    _validate_nonce,
    _verify_root_quorum,
)


HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_CALLER_SUPPLIED_ROLLBACK_AUTHORITY_BYTES_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_CRYPTOGRAPHIC_ROLLBACK_CLOSURE_REPOSITORY_ORDER_NOT_PROVEN"
)
HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    "INDEPENDENT_ROLLBACK_AUTHORITY_NONCE_TRANSPORT_REQUIRED",
    "INDEPENDENT_TRUST_AUTHORITY_PATH_AND_NONCE_TRANSPORT_REQUIRED",
    "TARGET_PRODUCT_SERIALIZABLE_TRANSACTION_PORT_REQUIRED",
    "TARGET_REPOSITORY_COMMIT_RECORD_TIME_BINDING_REQUIRED",
    "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "TARGET_ATOMIC_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED",
    "TARGET_OPERATION_ENVELOPE_TIME_BINDING_REQUIRED",
    "TARGET_QMAN_COLLECTOR_PUBLISHER_EXECUTION_REQUIRED",
    "TARGET_QMAN_MAPPING_BUILD_RUNNER_EVIDENCE_REQUIRED",
)

HOST_SNAPSHOT_AFTER_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/hostSnapshotArtifact"
)
PREPARED_ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/preparedRollbackAnchorArtifact"
)
ROLLBACK_PREFLIGHT_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
    "#/$defs/rollbackAuthorityPreflightReceipt"
)
HOST_SNAPSHOT_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-portable-hash-subjects.schema.json"
    "#/$defs/hostSnapshot"
)
HOST_AUTHORITY_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-HOST-AUTHORITY"
)
ROLLBACK_ANCHOR_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
)
ROLLBACK_FRESHNESS_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-anchor-freshness-envelope.schema.json"
)

ROLLBACK_PREFLIGHT_RECEIPT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ROLLBACK-AUTHORITY-PREFLIGHT/V1\x00"
)
ROLLBACK_PREFLIGHT_SIGNATURE_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/"
    b"HOST-SNAPSHOT-ROLLBACK-AUTHORITY-PREFLIGHT-SIGNATURE/V1\x00"
)
ROLLBACK_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-ROLLBACK-CONTEXT/V1\x00"
)

_CANDIDATE_FIELDS: Final = (
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
_PUBLISHER_HOST_AUTHORITY_FIELDS: Final = frozenset(
    {
        "lastSnapshotEpoch",
        "currentSnapshotContentHash",
        "lastObservedAt",
        "resourceVersion",
    }
)
_SCHEMA_IDENTITY_REFS: Final = (
    "contracts/directpath-host-snapshot-publication-trace.schema.json",
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
    "contracts/directpath-anchor-freshness-envelope.schema.json",
    "contracts/directpath-portable-hash-subjects.schema.json",
    "contracts/directpath-authority-entities.schema.json",
    "contracts/directpath-portable-entities.schema.json",
    "contracts/directpath-identity-v1.schema.json",
)


@dataclass(frozen=True, slots=True)
class PublicationRollbackVerifierLimits:
    """Caller-tightenable ceilings for the fixed rollback artifact set."""

    max_artifact_bytes: int = 4 * 1024 * 1024
    max_decoded_state_bytes: int = 2 * 1024 * 1024
    max_total_input_bytes: int = 16 * 1024 * 1024
    max_json_nodes: int = 250_000
    max_json_depth: int = 64
    max_root_signatures: int = 256


DEFAULT_PUBLICATION_ROLLBACK_LIMITS = PublicationRollbackVerifierLimits()


@dataclass(slots=True)
class _Budget:
    limits: PublicationRollbackVerifierLimits
    input_bytes: int = 0
    json_nodes: int = 0

    def add(self, amount: int, nodes: int, path: str) -> None:
        self.input_bytes += amount
        self.json_nodes += nodes
        require(
            self.input_bytes <= self.limits.max_total_input_bytes,
            "PUBLICATION_ROLLBACK_TOO_LARGE",
            path,
            "aggregate rollback artifact bytes exceed the closed limit",
        )
        require(
            self.json_nodes <= self.limits.max_json_nodes,
            "PUBLICATION_ROLLBACK_TOO_LARGE",
            path,
            "aggregate rollback JSON nodes exceed the closed limit",
        )


@dataclass(frozen=True, slots=True)
class _VerifiedArtifact:
    wrapper: Mapping[str, Any]
    wrapper_canonical_bytes: bytes
    state: Mapping[str, Any]
    state_canonical_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationRollbackContext(FactoryVerified):
    """Replayable component verification of one rollback artifact chain."""

    limits: PublicationRollbackVerifierLimits
    trust: VerifiedTrustContext
    recovery_trust: VerifiedTrustContext
    decision: VerifiedHostSnapshotPublicationDecisionContext
    after_inventory: VerifiedInventoryContext
    host_snapshot_after_artifact: Mapping[str, Any]
    host_snapshot_after_artifact_canonical_bytes: bytes
    host_authority_after_artifact: Mapping[str, Any]
    host_authority_after_artifact_canonical_bytes: bytes
    prepared_anchor_artifact_or_null: Mapping[str, Any] | None
    prepared_anchor_artifact_canonical_bytes_or_null: bytes | None
    after_anchor_artifact: Mapping[str, Any]
    after_anchor_artifact_canonical_bytes: bytes
    after_freshness_artifact: Mapping[str, Any]
    after_freshness_artifact_canonical_bytes: bytes
    predecessor_freshness_nonce_or_null: str | None
    rollback_preflight_nonce: str
    after_freshness_nonce: str
    expected_authority_id: str
    expected_anchor_path: str
    expected_trust_anchor_path: str
    verified_at: datetime
    repository_id: str
    transaction_id: str
    expectation_hash: str
    publication_decision: str
    write_required: bool
    predecessor_anchor_digest_or_null: str | None
    reservation_id_or_null: str | None
    prepare_receipt_digest_or_null: str | None
    candidate_projection_digest: str
    required_anchor_version: int
    commit_not_before_or_null: datetime | None
    commit_not_after_or_null: datetime | None
    finalized_at: datetime
    after_anchor_digest: str
    after_anchor_version: int
    after_anchor_resource_version: int
    after_freshness_receipt_digest: str
    after_freshness_expires_at: datetime
    context_receipt: Mapping[str, Any]
    context_receipt_canonical_bytes: bytes
    publication_trust_context_digest: str
    publication_trust_freshness_receipt_digest: str
    publication_trust_verified_at: datetime
    publication_trust_freshness_expires_at: datetime
    publication_trust_anchor_path: str
    recovery_trust_context_digest: str
    recovery_trust_freshness_receipt_digest: str
    recovery_trust_verified_at: datetime
    recovery_trust_freshness_expires_at: datetime
    recovery_trust_anchor_path: str
    context_digest: str
    authority_boundary: str
    authority_disposition: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]
    _schemas: ContractSchemas = field(repr=False, compare=False)


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


def _format_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _checked_limits(
    value: PublicationRollbackVerifierLimits | None,
) -> PublicationRollbackVerifierLimits:
    limits = value or DEFAULT_PUBLICATION_ROLLBACK_LIMITS
    require(
        isinstance(limits, PublicationRollbackVerifierLimits),
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        "publicationRollback.limits",
        "expected PublicationRollbackVerifierLimits",
    )
    hard = DEFAULT_PUBLICATION_ROLLBACK_LIMITS
    for descriptor in fields(PublicationRollbackVerifierLimits):
        actual = getattr(limits, descriptor.name)
        ceiling = getattr(hard, descriptor.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "PUBLICATION_ROLLBACK_LIMIT_INVALID",
            f"publicationRollback.limits.{descriptor.name}",
            f"limit must be a positive integer no greater than {ceiling}",
        )
    return limits


def _measure(
    value: Any,
    *,
    limits: PublicationRollbackVerifierLimits,
    max_bytes: int,
    path: str,
) -> tuple[int, int]:
    try:
        byte_count, node_count = measure_canonical_json(
            value,
            max_bytes=max_bytes,
            max_nodes=limits.max_json_nodes,
            max_depth=limits.max_json_depth,
        )
    except (CanonicalizationError, CanonicalJsonLimitError, ValueError) as exc:
        fail("PUBLICATION_ROLLBACK_TOO_LARGE", path, str(exc))
    return byte_count, node_count


def _canonical_document(
    value: JsonDocument,
    *,
    limits: PublicationRollbackVerifierLimits,
    budget: _Budget,
    path: str,
) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        require(
            1 <= len(raw) <= limits.max_artifact_bytes,
            "PUBLICATION_ROLLBACK_TOO_LARGE",
            path,
            "artifact bytes exceed the closed per-artifact limit",
        )
        try:
            loaded = load_canonical_json(raw)
        except (CanonicalizationError, RecursionError, ValueError) as exc:
            fail("PUBLICATION_ROLLBACK_CANONICAL_INVALID", path, str(exc))
        _, node_count = _measure(
            loaded,
            limits=limits,
            max_bytes=limits.max_artifact_bytes,
            path=path,
        )
    elif isinstance(value, Mapping):
        _, node_count = _measure(
            value,
            limits=limits,
            max_bytes=limits.max_artifact_bytes,
            path=path,
        )
        try:
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        except (CanonicalizationError, RecursionError, ValueError) as exc:
            fail("PUBLICATION_ROLLBACK_CANONICAL_INVALID", path, str(exc))
    else:
        fail(
            "PUBLICATION_ROLLBACK_INPUT_INVALID",
            path,
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        path,
        "expected a JSON object",
    )
    budget.add(len(raw), node_count, path)
    return loaded, raw


def _decode_state(
    value: Any,
    *,
    limits: PublicationRollbackVerifierLimits,
    budget: _Budget,
    path: str,
) -> tuple[dict[str, Any], bytes]:
    require(
        isinstance(value, str) and value,
        "PUBLICATION_ROLLBACK_ARTIFACT_INVALID",
        path,
        "canonicalInstanceBase64 must be non-empty text",
    )
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        fail("PUBLICATION_ROLLBACK_ARTIFACT_INVALID", path, str(exc))
    require(
        1 <= len(raw) <= limits.max_decoded_state_bytes,
        "PUBLICATION_ROLLBACK_TOO_LARGE",
        path,
        "decoded artifact state exceeds the closed limit",
    )
    try:
        loaded = load_canonical_json(raw)
    except (CanonicalizationError, RecursionError, ValueError) as exc:
        fail("PUBLICATION_ROLLBACK_CANONICAL_INVALID", path, str(exc))
    require(
        isinstance(loaded, dict),
        "PUBLICATION_ROLLBACK_ARTIFACT_INVALID",
        path,
        "decoded artifact state must be a JSON object",
    )
    _, node_count = _measure(
        loaded,
        limits=limits,
        max_bytes=limits.max_decoded_state_bytes,
        path=path,
    )
    budget.add(len(raw), node_count, path)
    return loaded, raw


def _verify_artifact(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    wrapper_schema_ref: str,
    state_schema_ref: str,
    limits: PublicationRollbackVerifierLimits,
    budget: _Budget,
    path: str,
) -> _VerifiedArtifact:
    wrapper, wrapper_raw = _canonical_document(
        value,
        limits=limits,
        budget=budget,
        path=path,
    )
    require(
        {
            "schemaRef",
            "state",
            "canonicalInstanceBase64",
            "instanceBytesSha256",
        }
        <= set(wrapper),
        "PUBLICATION_ROLLBACK_ARTIFACT_INVALID",
        path,
        "artifact wrapper is missing a retained state field",
    )
    state, state_raw = _decode_state(
        wrapper["canonicalInstanceBase64"],
        limits=limits,
        budget=budget,
        path=f"{path}.canonicalInstanceBase64",
    )
    require(
        canonical_json_bytes(wrapper["state"]) == state_raw,
        "PUBLICATION_ROLLBACK_ARTIFACT_INVALID",
        f"{path}.state",
        "wrapper state is not the exact decoded canonical bytes",
    )
    require(
        wrapper["instanceBytesSha256"] == sha256_digest(state_raw),
        "PUBLICATION_ROLLBACK_ARTIFACT_INVALID",
        f"{path}.instanceBytesSha256",
        "artifact state hash mismatch",
    )
    schemas.validate_ref(wrapper_schema_ref, wrapper, path)
    schemas.validate_ref(state_schema_ref, state, f"{path}.state")
    return _VerifiedArtifact(
        wrapper=_freeze_json(wrapper),
        wrapper_canonical_bytes=wrapper_raw,
        state=_freeze_json(state),
        state_canonical_bytes=state_raw,
    )


def _require_schema_identity(
    schemas: ContractSchemas,
    read_set: StructuralPublicationReadSet,
) -> None:
    for schema_ref in _SCHEMA_IDENTITY_REFS:
        actual = schemas.digest_for_ref(
            schema_ref,
            path="publicationRollback.schemas",
        )
        expected = read_set._schemas.digest_for_ref(
            schema_ref,
            path="publicationRollback.decision.schemas",
        )
        require(
            actual == expected,
            "PUBLICATION_ROLLBACK_SCHEMA_MISMATCH",
            "publicationRollback.schemas",
            f"schema identity differs for {schema_ref}",
        )


def _require_trust_lineage(
    earlier: VerifiedTrustContext,
    later: VerifiedTrustContext,
    *,
    path: str,
) -> None:
    require(
        earlier.root_set_digest == later.root_set_digest,
        "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
        f"{path}.rootSetDigest",
        "trust transition changed the independently pinned root set",
    )
    require(
        earlier.key_ring_id == later.key_ring_id,
        "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
        f"{path}.keyRingId",
        "trust transition changed the key-ring namespace",
    )
    require(
        earlier.trust_anchor_authority_id
        == later.trust_anchor_authority_id,
        "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
        f"{path}.trustAnchorAuthorityId",
        "trust transition changed the rollback-authority namespace",
    )
    earlier_history = tuple(
        (ring.sequence, ring.digest, ring.previous_digest)
        for ring in earlier._rings
    )
    later_history = tuple(
        (ring.sequence, ring.digest, ring.previous_digest)
        for ring in later._rings
    )
    require(
        later.key_ring_sequence >= earlier.key_ring_sequence
        and len(later_history) >= len(earlier_history)
        and later_history[: len(earlier_history)] == earlier_history,
        "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
        f"{path}.keyRingHistory",
        "later trust does not retain the earlier history as an exact prefix",
    )
    require(
        later.trust_anchor_version >= earlier.trust_anchor_version
        and later.trust_anchor_resource_version
        >= earlier.trust_anchor_resource_version,
        "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
        f"{path}.trustAnchorVersion",
        "later trust rolls back the accepted trust anchor",
    )
    if later.trust_anchor_version == earlier.trust_anchor_version:
        require(
            later.trust_anchor_digest == earlier.trust_anchor_digest,
            "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID",
            f"{path}.trustAnchorDigest",
            "the same trust-anchor version has a different digest",
        )


def _require_signature_count(
    signatures: Any,
    *,
    limits: PublicationRollbackVerifierLimits,
    root_set: Mapping[str, Any],
    path: str,
) -> None:
    require(
        isinstance(signatures, (list, tuple)),
        "PUBLICATION_ROLLBACK_SIGNATURE_SET_INVALID",
        path,
        "rootSignatures must be an array",
    )
    allowed_count = len(root_set["verificationPolicy"]["allowedKeyIds"])
    require(
        1
        <= len(signatures)
        <= min(limits.max_root_signatures, allowed_count),
        "PUBLICATION_ROLLBACK_SIGNATURE_SET_INVALID",
        path,
        "root signature count exceeds the closed verifier/root-set bound",
    )


def _candidate_projection(anchor: Mapping[str, Any]) -> dict[str, Any]:
    return {name: _thaw_json(anchor[name]) for name in _CANDIDATE_FIELDS}


def _verify_candidate_digest(
    anchor: Mapping[str, Any],
    *,
    path: str,
) -> None:
    actual = sha256_digest(
        HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN
        + canonical_json_bytes(_candidate_projection(anchor))
    )
    _require_digest(
        anchor["candidateProjectionDigest"],
        actual,
        f"{path}.candidateProjectionDigest",
        "PUBLICATION_ROLLBACK_CANDIDATE_DIGEST_INVALID",
    )


def _verify_generic_anchor_cas(
    anchor: Mapping[str, Any],
    *,
    path: str,
) -> None:
    require(
        anchor["anchorVersion"] == anchor["resourceVersion"],
        "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
        path,
        "anchorVersion and resourceVersion must advance in lockstep",
    )
    cas = anchor["casPrecondition"]
    if anchor["anchorVersion"] == 1:
        require(
            anchor["previousAnchorDigestOrNull"] is None
            and all(value is None for value in cas.values())
            and anchor["acceptedSnapshotEpoch"] == 1,
            "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
            path,
            "genesis requires version one, epoch one, and an all-null CAS",
        )
        return
    require(
        anchor["anchorVersion"] == cas["expectedAnchorVersionOrNull"] + 1
        and anchor["resourceVersion"]
        == cas["expectedResourceVersionOrNull"] + 1
        and anchor["previousAnchorDigestOrNull"]
        == cas["expectedAnchorDigestOrNull"],
        "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
        path,
        "successor does not increment and bind the exact predecessor",
    )
    require(
        anchor["acceptedSnapshotContentHash"]
        != cas["expectedSnapshotContentHashOrNull"]
        and anchor["acceptedHostAuthorityResourceVersion"]
        > cas["expectedHostAuthorityResourceVersionOrNull"],
        "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
        path,
        "successor snapshot/HostAuthority coordinates did not advance",
    )
    same_incarnation = (
        anchor["kernelBootId"] == cas["expectedKernelBootIdOrNull"]
        and anchor["hostEpoch"] == cas["expectedHostEpochOrNull"]
        and anchor["agentIdentity"] == cas["expectedAgentIdentityOrNull"]
        and anchor["agentGeneration"]
        == cas["expectedAgentGenerationOrNull"]
    )
    if same_incarnation:
        require(
            anchor["acceptedSnapshotEpoch"]
            == cas["expectedSnapshotEpochOrNull"] + 1,
            "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
            f"{path}.acceptedSnapshotEpoch",
            "same-incarnation snapshot epoch must increment by one",
        )
    else:
        require(
            (
                anchor["hostEpoch"] >= cas["expectedHostEpochOrNull"]
                and anchor["agentGeneration"]
                >= cas["expectedAgentGenerationOrNull"]
                and (
                    anchor["hostEpoch"] > cas["expectedHostEpochOrNull"]
                    or anchor["agentGeneration"]
                    > cas["expectedAgentGenerationOrNull"]
                )
                and anchor["acceptedSnapshotEpoch"] == 1
            ),
            "PUBLICATION_ROLLBACK_ANCHOR_CAS_INVALID",
            path,
            "new incarnation must advance generation and restart at epoch one",
        )


def _verify_predecessor(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    *,
    predecessor_nonce: str | None,
    expected_authority_id: str,
    expected_anchor_path: str,
    limits: PublicationRollbackVerifierLimits,
) -> tuple[Mapping[str, Any] | None, bytes | None]:
    read_set = decision.read_set
    anchor = read_set.predecessor_rollback_anchor_or_null
    anchor_raw = read_set.predecessor_rollback_anchor_canonical_bytes_or_null
    freshness = read_set.predecessor_rollback_freshness_or_null
    freshness_raw = (
        read_set.predecessor_rollback_freshness_canonical_bytes_or_null
    )
    if anchor is None:
        require(
            anchor_raw is None
            and freshness is None
            and freshness_raw is None
            and predecessor_nonce is None,
            "PUBLICATION_ROLLBACK_PREDECESSOR_INVALID",
            "publicationRollback.predecessor",
            "genesis must not carry predecessor anchor/freshness/nonce",
        )
        return None, None
    require(
        anchor_raw is not None
        and freshness is not None
        and freshness_raw is not None
        and predecessor_nonce is not None,
        "PUBLICATION_ROLLBACK_PREDECESSOR_INVALID",
        "publicationRollback.predecessor",
        "non-genesis requires exact predecessor anchor/freshness/nonce",
    )
    require(
        anchor["authorityId"] == expected_authority_id,
        "PUBLICATION_ROLLBACK_AUTHORITY_MISMATCH",
        "publicationRollback.predecessor.authorityId",
        "predecessor anchor uses a different configured authority",
    )
    current = read_set.current_inventory_or_null
    historical_trust = trust if current is None else current.trust
    _require_signature_count(
        anchor["prepareReceipt"]["rootSignatures"],
        limits=limits,
        root_set=historical_trust._root_set,
        path="publicationRollback.predecessor.prepareReceipt.rootSignatures",
    )
    _require_signature_count(
        anchor["receipt"]["rootSignatures"],
        limits=limits,
        root_set=historical_trust._root_set,
        path="publicationRollback.predecessor.receipt.rootSignatures",
    )
    _require_signature_count(
        freshness["rootSignatures"],
        limits=limits,
        root_set=historical_trust._root_set,
        path="publicationRollback.predecessorFreshness.rootSignatures",
    )
    if current is not None:
        verify_host_snapshot_anchor_binding(
            schemas,
            historical_trust,
            current,
            external_host_snapshot_anchor=anchor_raw,
            host_snapshot_anchor_freshness=freshness_raw,
            verifier_nonce=predecessor_nonce,
            expected_anchor_path=expected_anchor_path,
            now=read_set.began_at,
        )
    else:
        path = "publicationRollback.predecessor"
        _verify_candidate_digest(anchor, path=path)
        mutable_anchor = _thaw_json(anchor)
        anchor_digest, _ = _projection_digest(
            mutable_anchor,
            null_fields=("anchorDigest", "receipt"),
            path=f"{path}.digestProjection",
        )
        _require_digest(
            anchor["anchorDigest"],
            anchor_digest,
            f"{path}.anchorDigest",
            "PUBLICATION_ROLLBACK_ANCHOR_DIGEST_INVALID",
        )
        _verify_generic_anchor_cas(anchor, path=path)
        _validate_prepare_receipt(
            mutable_anchor,
            historical_trust._root_set,
            path=path,
        )
        _validate_final_receipt(
            mutable_anchor,
            historical_trust._root_set,
            path=path,
        )
        checked_freshness, _, _ = _validate_freshness(
            schemas,
            freshness_raw,
            verifier_nonce=predecessor_nonce,
            now=read_set.began_at,
            anchor_kind="HOST_SNAPSHOT",
            anchor=anchor,
            anchor_raw=anchor_raw,
            anchor_schema_ref=HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
            subject_field="hostId",
            root_set=historical_trust._root_set,
            path="publicationRollback.predecessorFreshness",
        )
        require(
            checked_freshness["anchorPath"] == expected_anchor_path,
            "PUBLICATION_ROLLBACK_PATH_MISMATCH",
            "publicationRollback.predecessorFreshness.anchorPath",
            "predecessor freshness uses a different configured path",
        )
    return anchor, anchor_raw


def _verify_preflight(
    trust: VerifiedTrustContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    *,
    predecessor_anchor: Mapping[str, Any] | None,
    nonce: str,
    expected_authority_id: str,
    limits: PublicationRollbackVerifierLimits,
) -> tuple[datetime, datetime, tuple[datetime, ...]]:
    path = "publicationRollback.rollbackAuthorityPreflight"
    preflight = decision.read_set.rollback_authority_preflight
    _validate_nonce(nonce, f"{path}.verifierNonce")
    require(
        preflight["verifierNonce"] == nonce,
        "PUBLICATION_ROLLBACK_NONCE_MISMATCH",
        f"{path}.verifierNonce",
        "preflight does not bind the independently supplied nonce",
    )
    predecessor_digest = (
        None if predecessor_anchor is None else predecessor_anchor["anchorDigest"]
    )
    require(
        preflight["hostId"] == decision.read_set.host_authority_before["hostId"]
        and preflight["authorityId"] == expected_authority_id
        and preflight["predecessorAnchorDigestOrNull"] == predecessor_digest
        and preflight["unresolvedReservationCount"] == 0
        and preflight["trustRootDigest"] == trust.root_set_digest,
        "PUBLICATION_ROLLBACK_PREFLIGHT_BINDING_MISMATCH",
        path,
        "preflight does not bind the exact host/authority/predecessor/root",
    )
    digest = sha256_digest(
        ROLLBACK_PREFLIGHT_RECEIPT_DOMAIN
        + canonical_json_bytes(
            {
                **_thaw_json(preflight),
                "receiptDigest": None,
                "rootSignatures": [],
            }
        )
    )
    _require_digest(
        preflight["receiptDigest"],
        digest,
        f"{path}.receiptDigest",
        "PUBLICATION_ROLLBACK_PREFLIGHT_DIGEST_INVALID",
    )
    checked_at = _timestamp(preflight["checkedAt"], f"{path}.checkedAt")
    expires_at = _timestamp(preflight["expiresAt"], f"{path}.expiresAt")
    began_at = decision.read_set.began_at
    capture_completed_at = _timestamp(
        decision.capture.capture_batch["captureCompletedAt"],
        "publicationRollback.capture.captureCompletedAt",
    )
    require(
        capture_completed_at <= checked_at <= began_at <= expires_at
        and checked_at < expires_at
        and expires_at - checked_at <= timedelta(seconds=300),
        "PUBLICATION_ROLLBACK_TIME_INVALID",
        path,
        "preflight/capture/read-set timing is invalid",
    )
    _require_signature_count(
        preflight["rootSignatures"],
        limits=limits,
        root_set=trust._root_set,
        path=f"{path}.rootSignatures",
    )
    _verify_root_quorum(
        trust._root_set,
        preflight["rootSignatures"],
        digest_field="receiptDigest",
        digest=digest,
        domain=ROLLBACK_PREFLIGHT_SIGNATURE_DOMAIN,
        path=f"{path}.rootSignatures",
        require_algorithm=True,
        not_before=checked_at,
        not_after=min(expires_at, began_at),
    )
    signature_times = tuple(
        _timestamp(
            signature["signedAt"],
            f"{path}.rootSignatures[{index}].signedAt",
        )
        for index, signature in enumerate(preflight["rootSignatures"])
    )
    return checked_at, expires_at, signature_times


def _verify_host_snapshot_after(
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    inventory: VerifiedInventoryContext,
) -> None:
    snapshot = inventory.host_snapshot
    batch = decision.capture.capture_batch
    current = decision.read_set.current_inventory_or_null
    if not decision.write_required:
        require(
            current is not None
            and inventory.host_snapshot_canonical_bytes
            == current.host_snapshot_canonical_bytes
            and inventory.host_authority_canonical_bytes
            == current.host_authority_canonical_bytes,
            "PUBLICATION_ROLLBACK_NO_CHANGE_MUTATION",
            "publicationRollback.afterInventory",
            "NO_CHANGE must retain exact current snapshot and HostAuthority bytes",
        )
        return
    expected_previous = (
        None if current is None else current.snapshot_content_hash
    )
    expected = {
        "hostId": batch["hostId"],
        "kernelBootId": batch["kernelBootId"],
        "hostEpoch": batch["hostEpoch"],
        "agentGeneration": batch["agentGeneration"],
        "snapshotEpoch": decision.proposed_snapshot_epoch,
        "hostAuthorityResourceVersion": (
            decision.proposed_host_authority_resource_version
        ),
        "previousSnapshotContentHashOrNull": expected_previous,
        "capturedAt": batch["captureCompletedAt"],
        "policyHash": decision.read_set.capability_policy.policy_hash,
        "snapshotFreshnessPolicyHash": decision.read_set.freshness_policy_hash,
    }
    for name, value in expected.items():
        require(
            snapshot[name] == value,
            "PUBLICATION_ROLLBACK_AFTER_SNAPSHOT_MISMATCH",
            f"publicationRollback.hostSnapshotAfter.{name}",
            f"after snapshot does not bind decision value {value!r}",
        )


def _verify_host_authority_transition(
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    inventory: VerifiedInventoryContext,
) -> None:
    before = decision.read_set.host_authority_before
    after = inventory.host_authority
    if not decision.write_required:
        require(
            inventory.host_authority_canonical_bytes
            == decision.read_set.host_authority_before_canonical_bytes,
            "PUBLICATION_ROLLBACK_NO_CHANGE_MUTATION",
            "publicationRollback.hostAuthorityAfter",
            "NO_CHANGE cannot mutate HostAuthority",
        )
        return
    for name, before_value in before.items():
        if name in _PUBLISHER_HOST_AUTHORITY_FIELDS:
            continue
        require(
            after[name] == before_value,
            "PUBLICATION_ROLLBACK_HOST_AUTHORITY_SCOPE_INVALID",
            f"publicationRollback.hostAuthorityAfter.{name}",
            "capture publisher changed a field outside its authority",
        )
    expected = {
        "lastSnapshotEpoch": decision.proposed_snapshot_epoch,
        "currentSnapshotContentHash": inventory.snapshot_content_hash,
        "lastObservedAt": decision.capture.capture_batch["captureCompletedAt"],
        "resourceVersion": decision.proposed_host_authority_resource_version,
    }
    for name, value in expected.items():
        require(
            after[name] == value,
            "PUBLICATION_ROLLBACK_HOST_AUTHORITY_SCOPE_INVALID",
            f"publicationRollback.hostAuthorityAfter.{name}",
            f"after HostAuthority does not bind {value!r}",
        )


def _expected_cas(
    predecessor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if predecessor is None:
        return {
            "expectedAnchorVersionOrNull": None,
            "expectedResourceVersionOrNull": None,
            "expectedKernelBootIdOrNull": None,
            "expectedHostEpochOrNull": None,
            "expectedAgentIdentityOrNull": None,
            "expectedAgentGenerationOrNull": None,
            "expectedSnapshotEpochOrNull": None,
            "expectedSnapshotContentHashOrNull": None,
            "expectedHostAuthorityResourceVersionOrNull": None,
            "expectedAnchorDigestOrNull": None,
        }
    return {
        "expectedAnchorVersionOrNull": predecessor["anchorVersion"],
        "expectedResourceVersionOrNull": predecessor["resourceVersion"],
        "expectedKernelBootIdOrNull": predecessor["kernelBootId"],
        "expectedHostEpochOrNull": predecessor["hostEpoch"],
        "expectedAgentIdentityOrNull": predecessor["agentIdentity"],
        "expectedAgentGenerationOrNull": predecessor["agentGeneration"],
        "expectedSnapshotEpochOrNull": predecessor["acceptedSnapshotEpoch"],
        "expectedSnapshotContentHashOrNull": predecessor[
            "acceptedSnapshotContentHash"
        ],
        "expectedHostAuthorityResourceVersionOrNull": predecessor[
            "acceptedHostAuthorityResourceVersion"
        ],
        "expectedAnchorDigestOrNull": predecessor["anchorDigest"],
    }


def _expected_candidate(
    inventory: VerifiedInventoryContext,
    predecessor: Mapping[str, Any] | None,
    *,
    authority_id: str,
) -> dict[str, Any]:
    anchor_version = (
        1 if predecessor is None else predecessor["anchorVersion"] + 1
    )
    resource_version = (
        1 if predecessor is None else predecessor["resourceVersion"] + 1
    )
    return {
        "hostId": inventory.host_id,
        "kernelBootId": inventory.kernel_boot_id,
        "hostEpoch": inventory.host_epoch,
        "agentIdentity": inventory.agent_identity,
        "agentGeneration": inventory.agent_generation,
        "acceptedSnapshotEpoch": inventory.snapshot_epoch,
        "acceptedSnapshotContentHash": inventory.snapshot_content_hash,
        "acceptedHostAuthorityResourceVersion": (
            inventory.snapshot_authority_resource_version
        ),
        "anchorVersion": anchor_version,
        "resourceVersion": resource_version,
        "previousAnchorDigestOrNull": (
            None if predecessor is None else predecessor["anchorDigest"]
        ),
        "authorityId": authority_id,
        "casPrecondition": _expected_cas(predecessor),
    }


def _verify_prepared(
    prepared: Mapping[str, Any],
    expected_candidate: Mapping[str, Any],
    *,
    trust: VerifiedTrustContext,
    preflight_digest: str,
    preflight_checked_at: datetime,
    preflight_expires_at: datetime,
    preflight_signature_times: tuple[datetime, ...],
    began_at: datetime,
    limits: PublicationRollbackVerifierLimits,
) -> tuple[datetime, datetime]:
    path = "publicationRollback.preparedAnchor"
    require(
        _candidate_projection(prepared) == expected_candidate,
        "PUBLICATION_ROLLBACK_PREPARED_BINDING_MISMATCH",
        path,
        "prepared candidate/CAS fields differ from the expected after inventory",
    )
    _verify_candidate_digest(prepared, path=path)
    receipt = prepared["prepareReceipt"]
    require(
        receipt["hostId"] == prepared["hostId"]
        and receipt["candidateProjectionDigest"]
        == prepared["candidateProjectionDigest"]
        and receipt["predecessorAnchorDigestOrNull"]
        == prepared["previousAnchorDigestOrNull"]
        and receipt["authorityId"] == prepared["authorityId"]
        and receipt["rollbackAuthorityPreflightReceiptDigest"]
        == preflight_digest
        and receipt["trustRootDigest"] == trust.root_set_digest,
        "PUBLICATION_ROLLBACK_PREPARE_RECEIPT_BINDING_MISMATCH",
        f"{path}.prepareReceipt",
        "prepare receipt does not bind candidate/preflight/root",
    )
    prepared_at = _timestamp(
        receipt["preparedAt"],
        f"{path}.prepareReceipt.preparedAt",
    )
    expires_at = _timestamp(
        receipt["expiresAt"],
        f"{path}.prepareReceipt.expiresAt",
    )
    updated_at = _timestamp(prepared["updatedAt"], f"{path}.updatedAt")
    require(
        preflight_checked_at
        <= prepared_at
        <= preflight_expires_at
        and prepared_at <= updated_at <= began_at <= expires_at
        and prepared_at < expires_at,
        "PUBLICATION_ROLLBACK_TIME_INVALID",
        path,
        "prepared/preflight/read-set timing is invalid",
    )
    require(
        all(signed_at <= prepared_at for signed_at in preflight_signature_times),
        "PUBLICATION_ROLLBACK_TIME_INVALID",
        f"{path}.prepareReceipt.preparedAt",
        "preparedAt predates a preflight root signature",
    )
    digest, _ = _projection_digest(
        _thaw_json(receipt),
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.prepareReceipt.digestProjection",
    )
    _require_digest(
        receipt["receiptDigest"],
        digest,
        f"{path}.prepareReceipt.receiptDigest",
        "PUBLICATION_ROLLBACK_PREPARE_DIGEST_INVALID",
    )
    _require_signature_count(
        receipt["rootSignatures"],
        limits=limits,
        root_set=trust._root_set,
        path=f"{path}.prepareReceipt.rootSignatures",
    )
    _verify_root_quorum(
        trust._root_set,
        receipt["rootSignatures"],
        digest_field="receiptDigest",
        digest=digest,
        domain=HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
        path=f"{path}.prepareReceipt.rootSignatures",
        require_algorithm=True,
        not_before=prepared_at,
        not_after=min(expires_at, began_at),
    )
    return prepared_at, expires_at


def _context_digest(receipt: Mapping[str, Any]) -> str:
    projection = _thaw_json(receipt)
    projection["contextDigest"] = None
    return sha256_digest(
        ROLLBACK_CONTEXT_DOMAIN + canonical_json_bytes(projection)
    )


def verify_host_snapshot_publication_rollback_closure(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    *,
    host_snapshot_after_artifact: JsonDocument,
    host_authority_after_artifact: JsonDocument,
    prepared_anchor_artifact_or_none: JsonDocument | None,
    after_anchor_artifact: JsonDocument,
    after_freshness_artifact: JsonDocument,
    predecessor_freshness_nonce_or_none: str | None,
    rollback_preflight_nonce: str,
    after_freshness_nonce: str,
    expected_authority_id: str,
    expected_anchor_path: str,
    expected_trust_anchor_path: str,
    verified_at: datetime,
    recovery_trust: VerifiedTrustContext | None = None,
    limits: PublicationRollbackVerifierLimits | None = None,
) -> VerifiedHostSnapshotPublicationRollbackContext:
    """Verify exact rollback artifacts without claiming repository ordering."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        "publicationRollback.schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="PUBLICATION_ROLLBACK_TRUST_INVALID",
        path="publicationRollback.trust",
        message="trust must come from verify_trust_context",
    )
    checked_recovery_trust = trust if recovery_trust is None else recovery_trust
    require_factory_verified(
        checked_recovery_trust,
        VerifiedTrustContext,
        code="PUBLICATION_ROLLBACK_RECOVERY_TRUST_INVALID",
        path="publicationRollback.recoveryTrust",
        message="recovery_trust must come from verify_trust_context",
    )
    require_factory_verified(
        decision,
        VerifiedHostSnapshotPublicationDecisionContext,
        code="PUBLICATION_ROLLBACK_DECISION_INVALID",
        path="publicationRollback.decision",
        message=(
            "decision must come from verify_host_snapshot_publication_decision"
        ),
    )
    checked_limits = _checked_limits(limits)
    decision = replay_host_snapshot_publication_decision(decision)
    _require_schema_identity(schemas, decision.read_set)
    require(
        isinstance(expected_authority_id, str) and expected_authority_id,
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        "publicationRollback.expectedAuthorityId",
        "independently configured authority ID is required",
    )
    require(
        isinstance(expected_anchor_path, str) and expected_anchor_path,
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        "publicationRollback.expectedAnchorPath",
        "independently configured anchor path is required",
    )
    require(
        isinstance(expected_trust_anchor_path, str)
        and expected_trust_anchor_path,
        "PUBLICATION_ROLLBACK_INPUT_INVALID",
        "publicationRollback.expectedTrustAnchorPath",
        "independently configured trust-anchor path is required",
    )
    for name, checked_trust in (
        ("publicationTrust", trust),
        ("recoveryTrust", checked_recovery_trust),
    ):
        require(
            checked_trust.freshness_anchor_path
            == expected_trust_anchor_path,
            "PUBLICATION_ROLLBACK_TRUST_PATH_MISMATCH",
            f"publicationRollback.{name}.freshnessAnchorPath",
            "trust freshness uses a different independently configured path",
        )
    checked_at = _utc_now(verified_at, "publicationRollback.verifiedAt")
    require(
        decision.read_set.began_at <= checked_at,
        "PUBLICATION_ROLLBACK_TIME_INVALID",
        "publicationRollback.verifiedAt",
        "rollback verification predates the retained publication decision",
    )
    require(
        trust.verified_at
        <= decision.read_set.began_at
        <= trust.freshness_expires_at,
        "PUBLICATION_ROLLBACK_TRUST_STALE",
        "publicationRollback.trust",
        "publication trust is not live at the retained decision beganAt",
    )
    require(
        checked_recovery_trust.verified_at
        <= checked_at
        <= checked_recovery_trust.freshness_expires_at,
        "PUBLICATION_ROLLBACK_TRUST_STALE",
        "publicationRollback.recoveryTrust",
        "recovery trust is not live at rollback verifiedAt",
    )
    current = decision.read_set.current_inventory_or_null
    if current is not None:
        _require_trust_lineage(
            current.trust,
            trust,
            path="publicationRollback.currentToPublicationTrust",
        )
    _require_trust_lineage(
        trust,
        checked_recovery_trust,
        path="publicationRollback.publicationToRecoveryTrust",
    )

    predecessor, _ = _verify_predecessor(
        schemas,
        trust,
        decision,
        predecessor_nonce=predecessor_freshness_nonce_or_none,
        expected_authority_id=expected_authority_id,
        expected_anchor_path=expected_anchor_path,
        limits=checked_limits,
    )
    (
        preflight_checked_at,
        preflight_expires_at,
        preflight_signature_times,
    ) = _verify_preflight(
        trust,
        decision,
        predecessor_anchor=predecessor,
        nonce=rollback_preflight_nonce,
        expected_authority_id=expected_authority_id,
        limits=checked_limits,
    )
    _validate_nonce(
        after_freshness_nonce,
        "publicationRollback.afterFreshness.verifierNonce",
    )
    used_nonces = [
        rollback_preflight_nonce,
        after_freshness_nonce,
    ]
    if predecessor_freshness_nonce_or_none is not None:
        used_nonces.append(predecessor_freshness_nonce_or_none)
    require(
        len(used_nonces) == len(set(used_nonces)),
        "PUBLICATION_ROLLBACK_NONCE_REUSE",
        "publicationRollback.nonces",
        "before, preflight, and after reads require distinct nonces",
    )

    budget = _Budget(checked_limits)
    snapshot_after = _verify_artifact(
        schemas,
        host_snapshot_after_artifact,
        wrapper_schema_ref=HOST_SNAPSHOT_AFTER_ARTIFACT_SCHEMA_REF,
        state_schema_ref=HOST_SNAPSHOT_STATE_SCHEMA_REF,
        limits=checked_limits,
        budget=budget,
        path="publicationRollback.hostSnapshotAfter",
    )
    authority_after = _verify_artifact(
        schemas,
        host_authority_after_artifact,
        wrapper_schema_ref=HOST_AUTHORITY_ARTIFACT_SCHEMA_REF,
        state_schema_ref=HOST_AUTHORITY_STATE_SCHEMA_REF,
        limits=checked_limits,
        budget=budget,
        path="publicationRollback.hostAuthorityAfter",
    )
    after_anchor = _verify_artifact(
        schemas,
        after_anchor_artifact,
        wrapper_schema_ref=ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF,
        state_schema_ref=ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
        limits=checked_limits,
        budget=budget,
        path="publicationRollback.afterAnchor",
    )
    after_freshness = _verify_artifact(
        schemas,
        after_freshness_artifact,
        wrapper_schema_ref=ROLLBACK_FRESHNESS_ARTIFACT_SCHEMA_REF,
        state_schema_ref=ROLLBACK_FRESHNESS_STATE_SCHEMA_REF,
        limits=checked_limits,
        budget=budget,
        path="publicationRollback.afterFreshness",
    )
    prepared = (
        None
        if prepared_anchor_artifact_or_none is None
        else _verify_artifact(
            schemas,
            prepared_anchor_artifact_or_none,
            wrapper_schema_ref=PREPARED_ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF,
            state_schema_ref=ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
            limits=checked_limits,
            budget=budget,
            path="publicationRollback.preparedAnchor",
        )
    )

    persisted_records = tuple(
        record.canonical_bytes for record in decision.persisted_device_records
    )
    if decision.write_required:
        after_inventory = verify_inventory_context(
            schemas,
            trust,
            host_authority_before=authority_after.state_canonical_bytes,
            host_snapshot=snapshot_after.state_canonical_bytes,
            device_records=persisted_records,
            host_authority_after=authority_after.state_canonical_bytes,
            now=decision.read_set.began_at,
        )
    else:
        require(
            current is not None
            and snapshot_after.state_canonical_bytes
            == current.host_snapshot_canonical_bytes
            and authority_after.state_canonical_bytes
            == current.host_authority_canonical_bytes,
            "PUBLICATION_ROLLBACK_NO_CHANGE_MUTATION",
            "publicationRollback.afterInventory",
            "NO_CHANGE must reuse the exact retained current inventory bytes",
        )
        assert current is not None
        after_inventory = current
    _verify_host_snapshot_after(decision, after_inventory)
    _verify_host_authority_transition(decision, after_inventory)

    expected_candidate = _expected_candidate(
        after_inventory,
        predecessor,
        authority_id=expected_authority_id,
    )
    preflight_digest = decision.read_set.rollback_authority_preflight[
        "receiptDigest"
    ]
    prepare_receipt_digest: str | None
    reservation_id: str | None
    commit_not_before: datetime | None
    commit_not_after: datetime | None
    if decision.write_required:
        require(
            prepared is not None,
            "PUBLICATION_ROLLBACK_PREPARED_REQUIRED",
            "publicationRollback.preparedAnchor",
            "a committed publication requires a PREPARED reservation",
        )
        assert prepared is not None
        _, prepare_expires = _verify_prepared(
            prepared.state,
            expected_candidate,
            trust=trust,
            preflight_digest=preflight_digest,
            preflight_checked_at=preflight_checked_at,
            preflight_expires_at=preflight_expires_at,
            preflight_signature_times=preflight_signature_times,
            began_at=decision.read_set.began_at,
            limits=checked_limits,
        )
        require(
            _candidate_projection(after_anchor.state) == expected_candidate
            and after_anchor.state["candidateProjectionDigest"]
            == prepared.state["candidateProjectionDigest"]
            and after_anchor.state["prepareReceipt"]
            == prepared.state["prepareReceipt"],
            "PUBLICATION_ROLLBACK_FINALIZATION_BINDING_MISMATCH",
            "publicationRollback.afterAnchor",
            "COMMITTED anchor does not finalize the exact reservation",
        )
        after_updated_at = _timestamp(
            after_anchor.state["updatedAt"],
            "publicationRollback.afterAnchor.updatedAt",
        )
        require(
            after_updated_at >= decision.read_set.began_at,
            "PUBLICATION_ROLLBACK_TIME_INVALID",
            "publicationRollback.afterAnchor.updatedAt",
            "external finalization predates the publication read-set",
        )
        if predecessor is not None:
            predecessor_updated_at = _timestamp(
                predecessor["updatedAt"],
                "publicationRollback.predecessor.updatedAt",
            )
            require(
                after_updated_at > predecessor_updated_at,
                "PUBLICATION_ROLLBACK_TIME_INVALID",
                "publicationRollback.afterAnchor.updatedAt",
                "successor/incarnation finalization must advance updatedAt",
            )
        prepare_receipt_digest = prepared.state["prepareReceipt"][
            "receiptDigest"
        ]
        reservation_id = prepared.state["prepareReceipt"]["reservationId"]
        commit_not_before = decision.read_set.began_at
        commit_not_after = prepare_expires
    else:
        require(
            prepared is None
            and predecessor is not None
            and decision.read_set.predecessor_rollback_anchor_canonical_bytes_or_null
            == after_anchor.state_canonical_bytes
            and decision.read_set.predecessor_rollback_anchor_artifact_canonical_bytes_or_null
            == after_anchor.wrapper_canonical_bytes,
            "PUBLICATION_ROLLBACK_NO_CHANGE_MUTATION",
            "publicationRollback.afterAnchor",
            "NO_CHANGE cannot prepare or advance the rollback anchor",
        )
        prepare_receipt_digest = None
        reservation_id = None
        commit_not_before = None
        commit_not_after = None

    require(
        after_anchor.state["authorityId"] == expected_authority_id,
        "PUBLICATION_ROLLBACK_AUTHORITY_MISMATCH",
        "publicationRollback.afterAnchor.authorityId",
        "after anchor uses a different configured authority",
    )
    _require_signature_count(
        after_anchor.state["prepareReceipt"]["rootSignatures"],
        limits=checked_limits,
        root_set=checked_recovery_trust._root_set,
        path="publicationRollback.afterAnchor.prepareReceipt.rootSignatures",
    )
    _require_signature_count(
        after_anchor.state["receipt"]["rootSignatures"],
        limits=checked_limits,
        root_set=checked_recovery_trust._root_set,
        path="publicationRollback.afterAnchor.receipt.rootSignatures",
    )
    _require_signature_count(
        after_freshness.state["rootSignatures"],
        limits=checked_limits,
        root_set=checked_recovery_trust._root_set,
        path="publicationRollback.afterFreshness.rootSignatures",
    )
    checked_after_anchor, checked_after_anchor_raw = _validate_anchor(
        schemas,
        after_anchor.state_canonical_bytes,
        trust=checked_recovery_trust,
        inventory=after_inventory,
    )
    (
        checked_after_freshness,
        _,
        after_freshness_expires,
    ) = _validate_freshness(
        schemas,
        after_freshness.state_canonical_bytes,
        verifier_nonce=after_freshness_nonce,
        now=checked_at,
        anchor_kind="HOST_SNAPSHOT",
        anchor=checked_after_anchor,
        anchor_raw=checked_after_anchor_raw,
        anchor_schema_ref=HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
        subject_field="hostId",
        root_set=checked_recovery_trust._root_set,
        path="publicationRollback.afterFreshness",
    )
    require(
        checked_after_anchor["authorityId"] == expected_authority_id,
        "PUBLICATION_ROLLBACK_AUTHORITY_MISMATCH",
        "publicationRollback.afterAnchor.authorityId",
        "verified after binding uses a different configured authority",
    )
    require(
        checked_after_freshness["anchorPath"] == expected_anchor_path,
        "PUBLICATION_ROLLBACK_PATH_MISMATCH",
        "publicationRollback.afterFreshness.anchorPath",
        "after freshness uses a different configured path",
    )
    after_freshness_observed = _timestamp(
        checked_after_freshness["observedAt"],
        "publicationRollback.afterFreshness.observedAt",
    )
    after_anchor_updated_at = _timestamp(
        checked_after_anchor["updatedAt"],
        "publicationRollback.afterAnchor.updatedAt",
    )
    require(
        (
            after_freshness_observed >= decision.read_set.began_at
            if not decision.write_required
            else after_freshness_observed >= after_anchor_updated_at
        ),
        "PUBLICATION_ROLLBACK_TIME_INVALID",
        "publicationRollback.afterFreshness.observedAt",
        "after freshness predates the decision/finalized anchor",
    )

    predecessor_digest = (
        None if predecessor is None else predecessor["anchorDigest"]
    )
    receipt = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_ROLLBACK_CONTEXT",
        "schemaVersion": 1,
        "decisionContextDigest": decision.context_digest,
        "publicationTrustContextDigest": trust.context_digest,
        "publicationTrustFreshnessReceiptDigest": (
            trust.freshness_receipt_digest
        ),
        "publicationTrustVerifiedAt": _format_timestamp(trust.verified_at),
        "publicationTrustFreshnessExpiresAt": _format_timestamp(
            trust.freshness_expires_at
        ),
        "publicationTrustAnchorPath": trust.freshness_anchor_path,
        "recoveryTrustContextDigest": checked_recovery_trust.context_digest,
        "recoveryTrustFreshnessReceiptDigest": (
            checked_recovery_trust.freshness_receipt_digest
        ),
        "recoveryTrustVerifiedAt": _format_timestamp(
            checked_recovery_trust.verified_at
        ),
        "recoveryTrustFreshnessExpiresAt": _format_timestamp(
            checked_recovery_trust.freshness_expires_at
        ),
        "recoveryTrustAnchorPath": (
            checked_recovery_trust.freshness_anchor_path
        ),
        "repositoryId": decision.read_set.repository_id,
        "transactionId": decision.read_set.transaction_id,
        "expectationHash": decision.expectation_hash,
        "publicationDecision": decision.publication_decision,
        "writeRequired": decision.write_required,
        "hostSnapshotAfterArtifactCanonicalSha256": sha256_digest(
            snapshot_after.wrapper_canonical_bytes
        ),
        "hostAuthorityAfterArtifactCanonicalSha256": sha256_digest(
            authority_after.wrapper_canonical_bytes
        ),
        "predecessorAnchorDigestOrNull": predecessor_digest,
        "rollbackPreflightReceiptDigest": preflight_digest,
        "preparedAnchorArtifactCanonicalSha256OrNull": (
            None
            if prepared is None
            else sha256_digest(prepared.wrapper_canonical_bytes)
        ),
        "reservationIdOrNull": reservation_id,
        "prepareReceiptDigestOrNull": prepare_receipt_digest,
        "candidateProjectionDigest": after_anchor.state[
            "candidateProjectionDigest"
        ],
        "requiredAnchorVersion": after_anchor.state["anchorVersion"],
        "commitNotBeforeOrNull": (
            None
            if commit_not_before is None
            else _format_timestamp(commit_not_before)
        ),
        "commitNotAfterOrNull": (
            None
            if commit_not_after is None
            else _format_timestamp(commit_not_after)
        ),
        "repositoryCommitTimeDisposition": (
            "NOT_ACCEPTED_REQUIRES_VERIFIED_COMMIT_RECORD"
        ),
        "afterAnchorArtifactCanonicalSha256": sha256_digest(
            after_anchor.wrapper_canonical_bytes
        ),
        "afterAnchorDigest": after_anchor.state["anchorDigest"],
        "afterAnchorVersion": after_anchor.state["anchorVersion"],
        "afterAnchorResourceVersion": after_anchor.state["resourceVersion"],
        "afterFreshnessArtifactCanonicalSha256": sha256_digest(
            after_freshness.wrapper_canonical_bytes
        ),
        "afterFreshnessReceiptDigest": after_freshness.state[
            "freshnessReceiptDigest"
        ],
        "predecessorFreshnessNonceOrNull": (
            predecessor_freshness_nonce_or_none
        ),
        "rollbackPreflightNonce": rollback_preflight_nonce,
        "afterFreshnessNonce": after_freshness_nonce,
        "expectedAuthorityId": expected_authority_id,
        "expectedAnchorPath": expected_anchor_path,
        "expectedTrustAnchorPath": expected_trust_anchor_path,
        "verifiedAt": _format_timestamp(checked_at),
        "authorityBoundary": (
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY
        ),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = _context_digest(receipt)
    receipt["contextDigest"] = context_digest
    receipt_raw = canonical_json_bytes(receipt)
    finalized_at = _timestamp(
        after_anchor.state["updatedAt"],
        "publicationRollback.afterAnchor.updatedAt",
    )
    return VerifiedHostSnapshotPublicationRollbackContext._construct(
        limits=checked_limits,
        trust=trust,
        recovery_trust=checked_recovery_trust,
        decision=decision,
        after_inventory=after_inventory,
        host_snapshot_after_artifact=snapshot_after.wrapper,
        host_snapshot_after_artifact_canonical_bytes=(
            snapshot_after.wrapper_canonical_bytes
        ),
        host_authority_after_artifact=authority_after.wrapper,
        host_authority_after_artifact_canonical_bytes=(
            authority_after.wrapper_canonical_bytes
        ),
        prepared_anchor_artifact_or_null=(
            None if prepared is None else prepared.wrapper
        ),
        prepared_anchor_artifact_canonical_bytes_or_null=(
            None if prepared is None else prepared.wrapper_canonical_bytes
        ),
        after_anchor_artifact=after_anchor.wrapper,
        after_anchor_artifact_canonical_bytes=(
            after_anchor.wrapper_canonical_bytes
        ),
        after_freshness_artifact=after_freshness.wrapper,
        after_freshness_artifact_canonical_bytes=(
            after_freshness.wrapper_canonical_bytes
        ),
        predecessor_freshness_nonce_or_null=(
            predecessor_freshness_nonce_or_none
        ),
        rollback_preflight_nonce=rollback_preflight_nonce,
        after_freshness_nonce=after_freshness_nonce,
        expected_authority_id=expected_authority_id,
        expected_anchor_path=expected_anchor_path,
        expected_trust_anchor_path=expected_trust_anchor_path,
        verified_at=checked_at,
        repository_id=decision.read_set.repository_id,
        transaction_id=decision.read_set.transaction_id,
        expectation_hash=decision.expectation_hash,
        publication_decision=decision.publication_decision,
        write_required=decision.write_required,
        predecessor_anchor_digest_or_null=predecessor_digest,
        reservation_id_or_null=reservation_id,
        prepare_receipt_digest_or_null=prepare_receipt_digest,
        candidate_projection_digest=after_anchor.state[
            "candidateProjectionDigest"
        ],
        required_anchor_version=after_anchor.state["anchorVersion"],
        commit_not_before_or_null=commit_not_before,
        commit_not_after_or_null=commit_not_after,
        finalized_at=finalized_at,
        after_anchor_digest=after_anchor.state["anchorDigest"],
        after_anchor_version=after_anchor.state["anchorVersion"],
        after_anchor_resource_version=after_anchor.state["resourceVersion"],
        after_freshness_receipt_digest=after_freshness.state[
            "freshnessReceiptDigest"
        ],
        after_freshness_expires_at=after_freshness_expires,
        context_receipt=_freeze_json(receipt),
        context_receipt_canonical_bytes=receipt_raw,
        publication_trust_context_digest=trust.context_digest,
        publication_trust_freshness_receipt_digest=(
            trust.freshness_receipt_digest
        ),
        publication_trust_verified_at=trust.verified_at,
        publication_trust_freshness_expires_at=(
            trust.freshness_expires_at
        ),
        publication_trust_anchor_path=trust.freshness_anchor_path,
        recovery_trust_context_digest=(
            checked_recovery_trust.context_digest
        ),
        recovery_trust_freshness_receipt_digest=(
            checked_recovery_trust.freshness_receipt_digest
        ),
        recovery_trust_verified_at=checked_recovery_trust.verified_at,
        recovery_trust_freshness_expires_at=(
            checked_recovery_trust.freshness_expires_at
        ),
        recovery_trust_anchor_path=(
            checked_recovery_trust.freshness_anchor_path
        ),
        context_digest=context_digest,
        authority_boundary=(
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY
        ),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_host_snapshot_publication_rollback_closure(
    context: VerifiedHostSnapshotPublicationRollbackContext,
) -> VerifiedHostSnapshotPublicationRollbackContext:
    """Replay a rollback context from only its retained exact artifacts."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationRollbackContext,
        code="PUBLICATION_ROLLBACK_CONTEXT_INVALID",
        path="publicationRollback.context",
        message=(
            "context must come from "
            "verify_host_snapshot_publication_rollback_closure"
        ),
    )
    require(
        context.publication_trust_context_digest
        == context.trust.context_digest
        and context.publication_trust_freshness_receipt_digest
        == context.trust.freshness_receipt_digest
        and context.publication_trust_verified_at
        == context.trust.verified_at
        and context.publication_trust_freshness_expires_at
        == context.trust.freshness_expires_at
        and context.publication_trust_anchor_path
        == context.trust.freshness_anchor_path
        and context.recovery_trust_context_digest
        == context.recovery_trust.context_digest
        and context.recovery_trust_freshness_receipt_digest
        == context.recovery_trust.freshness_receipt_digest
        and context.recovery_trust_verified_at
        == context.recovery_trust.verified_at
        and context.recovery_trust_freshness_expires_at
        == context.recovery_trust.freshness_expires_at
        and context.recovery_trust_anchor_path
        == context.recovery_trust.freshness_anchor_path
        and context.publication_trust_anchor_path
        == context.expected_trust_anchor_path
        and context.recovery_trust_anchor_path
        == context.expected_trust_anchor_path,
        "PUBLICATION_ROLLBACK_CONTEXT_REPLAY_MISMATCH",
        "publicationRollback.context.trust",
        "retained publication/recovery trust digests do not match",
    )
    replayed = verify_host_snapshot_publication_rollback_closure(
        context._schemas,
        context.trust,
        context.decision,
        host_snapshot_after_artifact=(
            context.host_snapshot_after_artifact_canonical_bytes
        ),
        host_authority_after_artifact=(
            context.host_authority_after_artifact_canonical_bytes
        ),
        prepared_anchor_artifact_or_none=(
            context.prepared_anchor_artifact_canonical_bytes_or_null
        ),
        after_anchor_artifact=context.after_anchor_artifact_canonical_bytes,
        after_freshness_artifact=(
            context.after_freshness_artifact_canonical_bytes
        ),
        predecessor_freshness_nonce_or_none=(
            context.predecessor_freshness_nonce_or_null
        ),
        rollback_preflight_nonce=context.rollback_preflight_nonce,
        after_freshness_nonce=context.after_freshness_nonce,
        expected_authority_id=context.expected_authority_id,
        expected_anchor_path=context.expected_anchor_path,
        expected_trust_anchor_path=context.expected_trust_anchor_path,
        verified_at=context.verified_at,
        recovery_trust=context.recovery_trust,
        limits=context.limits,
    )
    require(
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes,
        "PUBLICATION_ROLLBACK_CONTEXT_REPLAY_MISMATCH",
        "publicationRollback.context",
        "rollback context differs when replayed from retained bytes",
    )
    return replayed


__all__ = [
    "DEFAULT_PUBLICATION_ROLLBACK_LIMITS",
    "HOST_SNAPSHOT_AFTER_ARTIFACT_SCHEMA_REF",
    "HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS",
    "PREPARED_ROLLBACK_ANCHOR_ARTIFACT_SCHEMA_REF",
    "PublicationRollbackVerifierLimits",
    "VerifiedHostSnapshotPublicationRollbackContext",
    "replay_host_snapshot_publication_rollback_closure",
    "verify_host_snapshot_publication_rollback_closure",
]
