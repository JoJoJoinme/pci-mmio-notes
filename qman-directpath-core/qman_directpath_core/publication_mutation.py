"""Component-only HostSnapshot publication mutation closure verification.

This module consumes factory-produced publication decision and rollback
contexts, then replays the deterministic mutation/hash closure over retained
rows.  It consumes and exact-binds a verified operation request but does not
authenticate target transport/acceptance, open a repository transaction,
execute compare-and-swap, observe atomic visibility, or deliver the pending
outbox event.  Every returned context is therefore permanently non-authorizing
product evidence.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
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
from .publication_capture import HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
from .publication_decision import (
    AVAILABILITY_AUTHORITY_ARTIFACT_SCHEMA_REF,
    VerifiedHostSnapshotPublicationDecisionContext,
    replay_host_snapshot_publication_decision,
)
from .publication_operation import (
    VerifiedHostSnapshotPublicationOperationRequestContext,
    replay_host_snapshot_publication_operation_request,
)
from .publication_rollback import (
    VerifiedHostSnapshotPublicationRollbackContext,
    replay_host_snapshot_publication_rollback_closure,
)
from .trust import JsonDocument


MAX_PUBLICATION_MUTATION_DEVICE_RECORDS: Final = 4096
MAX_PUBLICATION_MUTATIONS: Final = 4102

HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_CALLER_SUPPLIED_REPOSITORY_ROWS_AND_TRANSACTION_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_MUTATION_HASH_CLOSURE_PRODUCT_TRANSACTION_NOT_PROVEN"
)
HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    "TARGET_ACCEPTED_OPERATION_REQUEST_IDEMPOTENCY_AND_DEADLINE_RECEIPT_REQUIRED",
    "TARGET_CONTROLLER_GENERATION_AUTHORITY_RECEIPT_REQUIRED",
    "TARGET_PRODUCT_REPOSITORY_TRANSACTION_PORT_REQUIRED",
    "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "TARGET_ATOMIC_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED",
    "TARGET_OUTBOX_POST_ANCHOR_DELIVERY_RECEIPT_REQUIRED",
    "TARGET_OPERATION_RESULT_SCHEMA_AND_ENVELOPE_BINDING_REQUIRED",
    "TARGET_DURABLE_COMMIT_CONTEXT_AND_COMMIT_CLOCK_RECEIPT_REQUIRED",
)

REPOSITORY_TRANSACTION_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/repositoryTransaction"
)
AUDIT_RECORD_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/actualAuditRecordArtifact"
)
OUTBOX_RECORD_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/actualOutboxRecordArtifact"
)
COMMIT_RECORD_ARTIFACT_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/actualCommitRecordArtifact"
)
MUTATION_ARRAY_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/commitWitnessBase/properties/mutations"
)
RESOLVED_AUTHORITY_VECTOR_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/snapshotPublicationResolvedAuthorityVector"
)

AVAILABILITY_AUTHORITY_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-authority-entities.schema.json"
    "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
)
AUDIT_RECORD_STATE_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/publicationAuditRecord"
)
OUTBOX_RECORD_STATE_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/publicationOutboxRecord"
)
COMMIT_RECORD_STATE_SCHEMA_REF: Final = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/repositoryCommitRecord"
)

MUTATION_SET_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-MUTATION-SET/V1\x00"
)
OUTBOX_PAYLOAD_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLISHED-PAYLOAD/V1\x00"
)
AUDIT_RECORD_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUDIT/V1\x00"
)
OUTBOX_RECORD_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OUTBOX/V1\x00"
)
COMMIT_RECORD_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-REPOSITORY-COMMIT/V1\x00"
)
DEVICE_RECORD_SET_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-DEVICE-RECORD-SET/V1\x00"
)
RESOLVED_AUTHORITY_VECTOR_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUTHORITY-STATE/V1\x00"
)
MUTATION_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-MUTATION-CONTEXT/V1\x00"
)
AUDIT_EVENT_ID_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUDIT-EVENT-ID/V1\x00"
)
OUTBOX_EVENT_ID_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OUTBOX-EVENT-ID/V1\x00"
)

_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMITTED_DECISIONS: Final = frozenset(
    {
        "GENESIS_COMMITTED",
        "INCARNATION_GENESIS_COMMITTED",
        "SUCCESSOR_COMMITTED",
        "REFRESH_COMMITTED",
    }
)
_AVAILABILITY_MUTABLE_FIELDS: Final = frozenset(
    {"lastMutationDigest", "lastMutatedAt", "resourceVersion"}
)
_COMMIT_PROJECTION_NULL_FIELDS: Final = (
    "mutationSetHash",
    "availabilityAuthorityAfterInstanceSha256",
    "auditRecordInstanceSha256",
    "outboxRecordInstanceSha256",
    "commitRecordDigest",
)
_CAS_RESULT_FIELDS: Final = frozenset(
    {
        "decision",
        "expectationHashOrNull",
        "committedAuthorityHashOrNull",
        "expectedHostAuthorityResourceVersionOrNull",
        "expectedAvailabilityAuthorityResourceVersionOrNull",
        "expectedCapabilityPolicyAuthorityResourceVersionOrNull",
        "expectedCapabilityPolicyHashOrNull",
        "expectedFreshnessPolicyAuthorityResourceVersionOrNull",
        "expectedFreshnessPolicyHashOrNull",
        "committedHostAuthorityResourceVersionOrNull",
        "committedAvailabilityAuthorityResourceVersionOrNull",
        "mutationSetHashOrNull",
        "commitRecordDigestOrNull",
        "publicationMutationCount",
        "conflicts",
    }
)


@dataclass(frozen=True, slots=True)
class PublicationMutationVerifierLimits:
    """Caller-tightenable ceilings for the full-publication mutation slice."""

    max_device_records: int = MAX_PUBLICATION_MUTATION_DEVICE_RECORDS
    max_mutations: int = MAX_PUBLICATION_MUTATIONS
    max_artifact_bytes: int = 4 * 1024 * 1024
    max_transaction_bytes: int = 512 * 1024
    max_total_input_bytes: int = 20 * 1024 * 1024
    max_json_nodes: int = 500_000
    max_json_depth: int = 64


DEFAULT_PUBLICATION_MUTATION_LIMITS = PublicationMutationVerifierLimits()


@dataclass(slots=True)
class _Budget:
    limits: PublicationMutationVerifierLimits
    input_bytes: int = 0
    json_nodes: int = 0

    def add(self, byte_count: int, node_count: int, path: str) -> None:
        self.input_bytes += byte_count
        self.json_nodes += node_count
        require(
            self.input_bytes <= self.limits.max_total_input_bytes,
            "PUBLICATION_MUTATION_TOO_LARGE",
            path,
            "aggregate mutation input bytes exceed the closed limit",
        )
        require(
            self.json_nodes <= self.limits.max_json_nodes,
            "PUBLICATION_MUTATION_TOO_LARGE",
            path,
            "aggregate mutation JSON nodes exceed the closed limit",
        )


@dataclass(frozen=True, slots=True)
class _VerifiedArtifact:
    wrapper: Mapping[str, Any]
    wrapper_canonical_bytes: bytes
    state: Mapping[str, Any]
    state_canonical_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationMutationContext(FactoryVerified):
    """Replayable structural mutation/hash closure for one publication."""

    limits: PublicationMutationVerifierLimits
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext
    decision: VerifiedHostSnapshotPublicationDecisionContext
    rollback: VerifiedHostSnapshotPublicationRollbackContext
    repository_transaction: Mapping[str, Any]
    repository_transaction_canonical_bytes: bytes
    availability_authority_after_artifact_or_null: Mapping[str, Any] | None
    availability_authority_after_artifact_canonical_bytes_or_null: bytes | None
    audit_record_artifact_or_null: Mapping[str, Any] | None
    audit_record_artifact_canonical_bytes_or_null: bytes | None
    outbox_record_artifact_or_null: Mapping[str, Any] | None
    outbox_record_artifact_canonical_bytes_or_null: bytes | None
    commit_record_artifact_or_null: Mapping[str, Any] | None
    commit_record_artifact_canonical_bytes_or_null: bytes | None
    mutations: tuple[Mapping[str, Any], ...]
    mutations_canonical_bytes: bytes
    mutation_set_hash_or_null: str | None
    device_record_set_digest: str
    resolved_authority_vector: Mapping[str, Any]
    resolved_authority_vector_hash: str
    commit_record_digest_or_null: str | None
    publication_mutation_count: int
    snapshot_publication_cas_result: Mapping[str, Any]
    context_receipt: Mapping[str, Any]
    context_receipt_canonical_bytes: bytes
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


def _checked_limits(
    value: PublicationMutationVerifierLimits | None,
) -> PublicationMutationVerifierLimits:
    limits = value or DEFAULT_PUBLICATION_MUTATION_LIMITS
    require(
        isinstance(limits, PublicationMutationVerifierLimits),
        "PUBLICATION_MUTATION_INPUT_INVALID",
        "publicationMutation.limits",
        "expected PublicationMutationVerifierLimits",
    )
    hard = DEFAULT_PUBLICATION_MUTATION_LIMITS
    for descriptor in fields(PublicationMutationVerifierLimits):
        actual = getattr(limits, descriptor.name)
        ceiling = getattr(hard, descriptor.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "PUBLICATION_MUTATION_LIMIT_INVALID",
            f"publicationMutation.limits.{descriptor.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {ceiling}"
            ),
        )
    return limits


def _measure(
    value: Any,
    *,
    path: str,
    max_bytes: int,
    limits: PublicationMutationVerifierLimits,
) -> tuple[int, int]:
    try:
        return measure_canonical_json(
            value,
            max_bytes=max_bytes,
            max_nodes=limits.max_json_nodes,
            max_depth=limits.max_json_depth,
        )
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_MUTATION_TOO_LARGE", path, str(exc))
    except (CanonicalizationError, RecursionError, TypeError, ValueError) as exc:
        fail(
            "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
            path,
            f"cannot measure CANONICAL-JSON-V1 input: {exc}",
        )


def _load_document(
    value: JsonDocument,
    *,
    path: str,
    max_bytes: int,
    limits: PublicationMutationVerifierLimits,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, Mapping):
            measured_bytes, measured_nodes = _measure(
                value,
                path=path,
                max_bytes=max_bytes,
                limits=limits,
            )
            raw = canonical_json_bytes(value)
            require(
                len(raw) == measured_bytes,
                "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
                path,
                "bounded measurement differs from encoded bytes",
            )
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            require(
                0 < len(raw) <= max_bytes,
                "PUBLICATION_MUTATION_TOO_LARGE",
                path,
                f"canonical object exceeds the closed {max_bytes}-byte limit",
            )
            loaded_for_measure = load_canonical_json(raw)
            measured_bytes, measured_nodes = _measure(
                loaded_for_measure,
                path=path,
                max_bytes=max_bytes,
                limits=limits,
            )
            require(
                measured_bytes == len(raw),
                "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
                path,
                "bounded decoded measurement differs from retained bytes",
            )
        else:
            raise TypeError("expected canonical JSON bytes or a JSON mapping")
        loaded = load_canonical_json(raw)
    except DirectPathVerificationError:
        raise
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_MUTATION_TOO_LARGE", path, str(exc))
    except (
        CanonicalizationError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        fail(
            "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
            path,
            f"cannot load exact CANONICAL-JSON-V1 object: {exc}",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_MUTATION_ARTIFACT_INVALID",
        path,
        "expected one canonical JSON object",
    )
    budget.add(len(raw), measured_nodes, path)
    return loaded, raw


def _decode_canonical_state(
    encoded: Any,
    *,
    path: str,
    limits: PublicationMutationVerifierLimits,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes]:
    require(
        isinstance(encoded, str) and len(encoded) % 4 == 0,
        "PUBLICATION_MUTATION_BASE64_INVALID",
        path,
        "expected exact padded RFC 4648 base64",
    )
    maximum_encoded = ((limits.max_artifact_bytes + 2) // 3) * 4
    require(
        0 < len(encoded) <= maximum_encoded,
        "PUBLICATION_MUTATION_TOO_LARGE",
        path,
        "encoded state exceeds the closed decoded-state limit",
    )
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        fail(
            "PUBLICATION_MUTATION_BASE64_INVALID",
            path,
            f"invalid strict base64: {exc}",
        )
    require(
        0 < len(raw) <= limits.max_artifact_bytes
        and base64.b64encode(raw).decode("ascii") == encoded,
        "PUBLICATION_MUTATION_BASE64_INVALID",
        path,
        "base64 is not the exact non-empty padded representation",
    )
    try:
        loaded = load_canonical_json(raw)
        measured_bytes, measured_nodes = _measure(
            loaded,
            path=path,
            max_bytes=limits.max_artifact_bytes,
            limits=limits,
        )
    except DirectPathVerificationError:
        raise
    except (CanonicalizationError, RecursionError) as exc:
        fail(
            "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
            path,
            f"decoded state is not exact CANONICAL-JSON-V1: {exc}",
        )
    require(
        measured_bytes == len(raw),
        "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
        path,
        "bounded state measurement differs from retained bytes",
    )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_MUTATION_ARTIFACT_INVALID",
        path,
        "decoded state must be one object",
    )
    budget.add(len(raw), measured_nodes, path)
    return loaded, raw


def _verify_artifact(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    wrapper_schema_ref: str,
    state_schema_ref: str,
    path: str,
    limits: PublicationMutationVerifierLimits,
    budget: _Budget,
) -> _VerifiedArtifact:
    wrapper, wrapper_raw = _load_document(
        value,
        path=path,
        max_bytes=limits.max_artifact_bytes,
        limits=limits,
        budget=budget,
    )
    schemas.validate_ref(wrapper_schema_ref, wrapper, path)
    state, state_raw = _decode_canonical_state(
        wrapper["canonicalInstanceBase64"],
        path=f"{path}.canonicalInstanceBase64",
        limits=limits,
        budget=budget,
    )
    schemas.validate_ref(state_schema_ref, state, f"{path}.stateBytes")
    require(
        state == wrapper["state"],
        "PUBLICATION_MUTATION_ARTIFACT_BINDING_MISMATCH",
        f"{path}.state",
        "wrapper state differs from decoded canonical state bytes",
    )
    require(
        wrapper["instanceBytesSha256"] == sha256_digest(state_raw),
        "PUBLICATION_MUTATION_ARTIFACT_HASH_MISMATCH",
        f"{path}.instanceBytesSha256",
        "instance hash does not bind decoded canonical state bytes",
    )
    return _VerifiedArtifact(
        wrapper=_freeze_json(wrapper),
        wrapper_canonical_bytes=wrapper_raw,
        state=_freeze_json(state),
        state_canonical_bytes=state_raw,
    )


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "PUBLICATION_MUTATION_TIME_INVALID",
        path,
        "expected TIMESTAMP-UTC-US-V1 text",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail(
            "PUBLICATION_MUTATION_TIME_INVALID",
            path,
            f"invalid TIMESTAMP-UTC-US-V1 value: {exc}",
        )
    return parsed.replace(tzinfo=timezone.utc)


def _projection(
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str],
) -> dict[str, Any]:
    value = _thaw_json(document)
    for name in null_fields:
        require(
            name in value,
            "PUBLICATION_MUTATION_PROJECTION_INVALID",
            f"publicationMutation.projection.{name}",
            "declared digest projection field is absent",
        )
        value[name] = None
    return value


def _domain_digest(
    domain: bytes,
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str],
) -> str:
    return sha256_digest(
        domain
        + canonical_json_bytes(
            _projection(document, null_fields=null_fields)
        )
    )


def _plain_projection_digest(
    document: Mapping[str, Any],
    *,
    null_fields: Sequence[str] = (),
) -> str:
    projection = (
        _thaw_json(document)
        if not null_fields
        else _projection(document, null_fields=null_fields)
    )
    return sha256_digest(canonical_json_bytes(projection))


def _require_equal(
    actual: Any,
    expected: Any,
    *,
    path: str,
    message: str,
) -> None:
    require(
        actual == expected,
        "PUBLICATION_MUTATION_BINDING_MISMATCH",
        path,
        message,
    )


def _require_json_equal(
    actual: Any,
    expected: Any,
    *,
    path: str,
    message: str,
) -> None:
    require(
        canonical_json_bytes(_thaw_json(actual))
        == canonical_json_bytes(_thaw_json(expected)),
        "PUBLICATION_MUTATION_BINDING_MISMATCH",
        path,
        message,
    )


def _entity_ref(
    artifact: Mapping[str, Any],
    *,
    entity_type: str,
    entity_id: str,
    resource_version: int,
    generation_or_null: int | None,
) -> dict[str, Any]:
    return {
        "entityType": entity_type,
        "entityId": entity_id,
        "resourceVersion": resource_version,
        "generationOrNull": generation_or_null,
        "contentHash": artifact["instanceBytesSha256"],
    }


def _document_ref(
    artifact: Mapping[str, Any],
    *,
    document_kind: str,
    document_id: str,
    document_version: int,
    schema_ref: str,
) -> dict[str, Any]:
    return {
        "documentKind": document_kind,
        "documentId": document_id,
        "documentVersion": document_version,
        "canonicalProfile": "CANONICAL-JSON-V1",
        "schemaRef": schema_ref,
        "contentHash": artifact["instanceBytesSha256"],
    }


def _trust_document_ref(
    *,
    document_kind: str,
    document_id: str,
    document_version: int,
    schema_ref: str,
    canonical_sha256: str,
) -> dict[str, Any]:
    return {
        "documentKind": document_kind,
        "documentId": document_id,
        "documentVersion": document_version,
        "canonicalProfile": "CANONICAL-JSON-V1",
        "schemaRef": schema_ref,
        "contentHash": canonical_sha256,
    }


def _verify_operation_request_read_set(
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
) -> None:
    """Bind the accepted-shaped request to every retained publication input."""

    require(
        operation_request.issued_at
        <= decision.read_set.began_at
        <= operation_request.deadline_at,
        "PUBLICATION_MUTATION_OPERATION_TIME_INVALID",
        "publicationMutation.operationRequest",
        "publication read linearization time is outside the request window",
    )
    trust = rollback.trust
    require(
        trust.verified_at
        <= operation_request.issued_at
        <= trust.freshness_expires_at,
        "PUBLICATION_MUTATION_OPERATION_TRUST_STALE",
        "publicationMutation.operationRequest.issuedAt",
        "publication trust context was not live when the request was issued",
    )

    body = operation_request.request_payload["body"]
    batch = decision.capture.capture_batch
    host_before_artifact = decision.read_set.host_authority_before_artifact
    host_before = decision.read_set.host_authority_before
    availability_artifact = (
        decision.read_set.availability_authority_before_artifact
    )
    availability = decision.read_set.availability_authority_before
    capability_artifact = decision.read_set.capability_policy_artifact
    capability = capability_artifact["state"]
    capability_authority_artifact = (
        decision.read_set.capability_policy_authority_artifact
    )
    capability_authority = (
        decision.read_set.capability_policy_authority
    )
    freshness_artifact = decision.read_set.freshness_policy_artifact
    freshness = freshness_artifact["state"]
    freshness_authority_artifact = (
        decision.read_set.freshness_policy_authority_artifact
    )
    freshness_authority = decision.read_set.freshness_policy_authority

    expected_body = {
        "hostId": batch["hostId"],
        "hostBootIdentity": {
            "hostId": batch["hostId"],
            "kernelBootId": batch["kernelBootId"],
            "hostEpoch": batch["hostEpoch"],
        },
        "currentHostAuthority": _entity_ref(
            host_before_artifact,
            entity_type="ENTITY-HOST-AUTHORITY",
            entity_id=host_before["hostId"],
            resource_version=host_before["resourceVersion"],
            generation_or_null=host_before["agentGeneration"],
        ),
        "currentAvailabilityAuthority": _entity_ref(
            availability_artifact,
            entity_type="ENTITY-AVAILABILITY-AUTHORITY",
            entity_id=availability["availabilityAuthorityId"],
            resource_version=availability["resourceVersion"],
            generation_or_null=None,
        ),
        "capabilityPolicy": _document_ref(
            capability_artifact,
            document_kind="CAPABILITY_POLICY",
            document_id=capability["policyId"],
            document_version=capability["policyVersion"],
            schema_ref="contracts/directpath-capability-policy.schema.json",
        ),
        "capabilityPolicyAuthority": _entity_ref(
            capability_authority_artifact,
            entity_type="ENTITY-CAPABILITY-POLICY-AUTHORITY",
            entity_id=capability_authority["policyAuthorityId"],
            resource_version=capability_authority["resourceVersion"],
            generation_or_null=None,
        ),
        "trustedKeyRing": _trust_document_ref(
            document_kind="TRUST_KEY_RING",
            document_id=trust.key_ring_id,
            document_version=trust.key_ring_sequence,
            schema_ref="contracts/directpath-trust-key-ring.schema.json",
            canonical_sha256=trust.current_key_ring_canonical_sha256,
        ),
        "trustRootSet": _trust_document_ref(
            document_kind="TRUST_ROOT_SET",
            document_id=trust.root_set_id,
            document_version=1,
            schema_ref="contracts/directpath-trust-root-set.schema.json",
            canonical_sha256=trust.root_set_canonical_sha256,
        ),
        "rollbackAnchor": _trust_document_ref(
            document_kind="TRUST_ROLLBACK_ANCHOR",
            document_id=trust.trust_anchor_digest,
            document_version=trust.trust_anchor_version,
            schema_ref=(
                "contracts/directpath-trust-rollback-anchor.schema.json"
            ),
            canonical_sha256=trust.trust_anchor_canonical_sha256,
        ),
        "hostSnapshotRollbackAnchorOrNull": None,
        "hostSnapshotAnchorFreshnessOrNull": None,
        "snapshotFreshnessPolicy": _document_ref(
            freshness_artifact,
            document_kind="HOST_SNAPSHOT_FRESHNESS_POLICY",
            document_id=freshness["policyId"],
            document_version=freshness["policyVersion"],
            schema_ref=(
                "contracts/"
                "directpath-host-snapshot-publication-trace.schema.json"
                "#/$defs/freshnessPolicy"
            ),
        ),
        "snapshotFreshnessPolicyAuthority": _entity_ref(
            freshness_authority_artifact,
            entity_type=(
                "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
            ),
            entity_id=freshness_authority[
                "freshnessPolicyAuthorityId"
            ],
            resource_version=freshness_authority["resourceVersion"],
            generation_or_null=None,
        ),
    }
    predecessor_anchor_artifact = (
        decision.read_set.predecessor_rollback_anchor_artifact_or_null
    )
    predecessor_anchor = (
        decision.read_set.predecessor_rollback_anchor_or_null
    )
    predecessor_freshness_artifact = (
        decision.read_set.predecessor_rollback_freshness_artifact_or_null
    )
    predecessor_freshness = (
        decision.read_set.predecessor_rollback_freshness_or_null
    )
    if predecessor_anchor_artifact is not None:
        require(
            predecessor_anchor is not None
            and predecessor_freshness_artifact is not None
            and predecessor_freshness is not None,
            "PUBLICATION_MUTATION_OPERATION_READ_SET_INVALID",
            "publicationMutation.operationRequest.predecessor",
            "predecessor anchor and freshness must be retained together",
        )
        expected_body["hostSnapshotRollbackAnchorOrNull"] = _document_ref(
            predecessor_anchor_artifact,
            document_kind="HOST_SNAPSHOT_ROLLBACK_ANCHOR",
            document_id=predecessor_anchor["anchorDigest"],
            document_version=predecessor_anchor["anchorVersion"],
            schema_ref=(
                "contracts/"
                "directpath-host-snapshot-rollback-anchor.schema.json"
            ),
        )
        expected_body["hostSnapshotAnchorFreshnessOrNull"] = _document_ref(
            predecessor_freshness_artifact,
            document_kind="ANCHOR_FRESHNESS_ENVELOPE",
            document_id=predecessor_freshness["envelopeId"],
            document_version=predecessor_freshness["resourceVersion"],
            schema_ref=(
                "contracts/directpath-anchor-freshness-envelope.schema.json"
            ),
        )
        observed_at = _timestamp(
            predecessor_freshness["observedAt"],
            (
                "publicationMutation.operationRequest."
                "hostSnapshotAnchorFreshnessOrNull.observedAt"
            ),
        )
        expires_at = _timestamp(
            predecessor_freshness["expiresAt"],
            (
                "publicationMutation.operationRequest."
                "hostSnapshotAnchorFreshnessOrNull.expiresAt"
            ),
        )
        require(
            observed_at <= operation_request.issued_at <= expires_at,
            "PUBLICATION_MUTATION_OPERATION_PREDECESSOR_STALE",
            "publicationMutation.operationRequest.issuedAt",
            "predecessor rollback freshness was not live at request issuance",
        )
    else:
        require(
            predecessor_anchor is None
            and predecessor_freshness_artifact is None
            and predecessor_freshness is None,
            "PUBLICATION_MUTATION_OPERATION_READ_SET_INVALID",
            "publicationMutation.operationRequest.predecessor",
            "genesis must not retain a partial predecessor authority",
        )
    _require_json_equal(
        body,
        expected_body,
        path="publicationMutation.operationRequest.requestPayload.body",
        message="request body does not exactly project the publication read set",
    )

    current_inventory = decision.read_set.current_inventory_or_null
    expected_snapshot_epoch = (
        None if current_inventory is None else current_inventory.snapshot_epoch
    )
    expected_resource_versions = [
        {
            "entityType": expected_body[name]["entityType"],
            "resourceId": expected_body[name]["entityId"],
            "expectedResourceVersion": expected_body[name][
                "resourceVersion"
            ],
        }
        for name in (
            "currentHostAuthority",
            "currentAvailabilityAuthority",
            "capabilityPolicyAuthority",
            "snapshotFreshnessPolicyAuthority",
        )
    ]
    expected_resource_versions.sort(key=canonical_json_bytes)
    expected_authority = {
        "controllerGeneration": operation_request.controller_generation,
        "snapshotEpoch": expected_snapshot_epoch,
        "hostEpochs": [
            {
                "id": batch["hostId"],
                "generation": batch["hostEpoch"],
            }
        ],
        "runGenerations": [],
        "memberGenerations": [],
        "resourceVersions": expected_resource_versions,
    }
    _require_json_equal(
        operation_request.authority,
        expected_authority,
        path="publicationMutation.operationRequest.requestEnvelope.authority",
        message="request authority is not the exact four-authority read vector",
    )


def _verify_transaction_expectation(
    transaction: Mapping[str, Any],
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
) -> None:
    cas = decision.cas_operands
    expected = {
        "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
        "commandId": operation_request.command_id,
        "requestHash": operation_request.request_hash,
        "operationRequestContextDigest": operation_request.context_digest,
        "decisionContextDigest": decision.context_digest,
        "repositoryId": decision.read_set.repository_id,
        "transactionId": decision.read_set.transaction_id,
        "isolation": "SERIALIZABLE",
        "expectedHostAuthorityResourceVersion": (
            cas["hostAuthority"]["resourceVersion"]
        ),
        "expectedAvailabilityAuthorityResourceVersion": (
            cas["availabilityAuthority"]["resourceVersion"]
        ),
        "expectedCapabilityPolicyAuthorityResourceVersion": (
            cas["capabilityPolicyAuthority"]["resourceVersion"]
        ),
        "expectedCapabilityPolicyHash": (
            cas["capabilityPolicyAuthority"]["policyHash"]
        ),
        "expectedFreshnessPolicyAuthorityResourceVersion": (
            cas["freshnessPolicyAuthority"]["resourceVersion"]
        ),
        "expectedFreshnessPolicyHash": (
            cas["freshnessPolicyAuthority"]["policyHash"]
        ),
        "expectationHash": decision.expectation_hash,
        "beganAt": decision.read_set.began_at_text,
    }
    for name, value in expected.items():
        _require_equal(
            transaction[name],
            value,
            path=f"publicationMutation.repositoryTransaction.{name}",
            message="repository transaction does not bind the decision read-set",
        )


def _verify_transaction_outcome(
    transaction: Mapping[str, Any],
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
) -> datetime | None:
    clock_before = transaction["commitClockBefore"]
    clock_after = transaction["commitClockAfter"]
    if decision.write_required:
        require(
            decision.publication_decision in _COMMITTED_DECISIONS,
            "PUBLICATION_MUTATION_DECISION_INVALID",
            "publicationMutation.decision.publicationDecision",
            "write-required decision is not one committed publication branch",
        )
        _require_equal(
            transaction["outcome"],
            "COMMITTED",
            path="publicationMutation.repositoryTransaction.outcome",
            message="committed decision requires COMMITTED transaction outcome",
        )
        require(
            isinstance(transaction["commitIdOrNull"], str),
            "PUBLICATION_MUTATION_TRANSACTION_INVALID",
            "publicationMutation.repositoryTransaction.commitIdOrNull",
            "committed transaction requires commitId",
        )
        committed_at = _timestamp(
            transaction["committedAtOrNull"],
            "publicationMutation.repositoryTransaction.committedAtOrNull",
        )
        not_before = rollback.commit_not_before_or_null
        not_after = rollback.commit_not_after_or_null
        require(
            not_before is not None
            and not_after is not None
            and not_before <= committed_at <= not_after,
            "PUBLICATION_MUTATION_COMMIT_WINDOW_INVALID",
            "publicationMutation.repositoryTransaction.committedAtOrNull",
            "repository commit is outside the prepared reservation window",
        )
        require(
            committed_at <= rollback.finalized_at,
            "PUBLICATION_MUTATION_COMMIT_WINDOW_INVALID",
            "publicationMutation.repositoryTransaction.committedAtOrNull",
            "repository commit is later than rollback-anchor finalization",
        )
        require(
            committed_at <= operation_request.deadline_at,
            "PUBLICATION_MUTATION_OPERATION_TIME_INVALID",
            "publicationMutation.repositoryTransaction.committedAtOrNull",
            "repository commit is later than the accepted request deadline",
        )
        require(
            clock_after == clock_before + 1,
            "PUBLICATION_MUTATION_COMMIT_CLOCK_INVALID",
            "publicationMutation.repositoryTransaction.commitClockAfter",
            "committed publication must advance the repository clock exactly once",
        )
        return committed_at

    _require_equal(
        decision.publication_decision,
        "NO_CHANGE",
        path="publicationMutation.decision.publicationDecision",
        message="read-only mutation branch must be NO_CHANGE",
    )
    _require_equal(
        transaction["outcome"],
        "NO_CHANGE",
        path="publicationMutation.repositoryTransaction.outcome",
        message="NO_CHANGE decision requires NO_CHANGE transaction outcome",
    )
    require(
        transaction["commitIdOrNull"] is None
        and transaction["committedAtOrNull"] is None,
        "PUBLICATION_MUTATION_NO_CHANGE_WRITE",
        "publicationMutation.repositoryTransaction",
        "NO_CHANGE cannot retain a repository commit ID or time",
    )
    require(
        clock_after == clock_before,
        "PUBLICATION_MUTATION_COMMIT_CLOCK_INVALID",
        "publicationMutation.repositoryTransaction.commitClockAfter",
        "NO_CHANGE must preserve the repository commit clock exactly",
    )
    return None


def _resolved_authority_vector(
    schemas: ContractSchemas,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
    transaction: Mapping[str, Any],
    availability_after_or_none: _VerifiedArtifact | None,
) -> tuple[dict[str, Any], str]:
    if decision.write_required:
        require(
            availability_after_or_none is not None,
            "PUBLICATION_MUTATION_ARTIFACT_REQUIRED",
            "publicationMutation.availabilityAuthorityAfter",
            "committed publication requires AvailabilityAuthority after bytes",
        )
        host_sha = rollback.host_authority_after_artifact[
            "instanceBytesSha256"
        ]
        availability_sha = availability_after_or_none.wrapper[
            "instanceBytesSha256"
        ]
        outcome = "COMMITTED"
        commit_id = transaction["commitIdOrNull"]
    else:
        host_sha = decision.read_set.host_authority_before_artifact[
            "instanceBytesSha256"
        ]
        availability_sha = (
            decision.read_set.availability_authority_before_artifact[
                "instanceBytesSha256"
            ]
        )
        outcome = "NO_CHANGE"
        commit_id = None
    subject = {
        "subjectType": (
            "HOST_SNAPSHOT_PUBLICATION_RESOLVED_AUTHORITY_VECTOR"
        ),
        "schemaVersion": 1,
        "repositoryId": decision.read_set.repository_id,
        "transactionId": decision.read_set.transaction_id,
        "outcome": outcome,
        "commitIdOrNull": commit_id,
        "hostAuthorityInstanceSha256": host_sha,
        "availabilityAuthorityInstanceSha256": availability_sha,
        "capabilityPolicyAuthorityInstanceSha256": (
            decision.read_set.capability_policy_authority_artifact[
                "instanceBytesSha256"
            ]
        ),
        "freshnessPolicyAuthorityInstanceSha256": (
            decision.read_set.freshness_policy_authority_artifact[
                "instanceBytesSha256"
            ]
        ),
        "resolvedAuthorityVectorHash": None,
    }
    digest = sha256_digest(
        RESOLVED_AUTHORITY_VECTOR_DOMAIN + canonical_json_bytes(subject)
    )
    subject["resolvedAuthorityVectorHash"] = digest
    schemas.validate_ref(
        RESOLVED_AUTHORITY_VECTOR_SCHEMA_REF,
        subject,
        "publicationMutation.resolvedAuthorityVector",
    )
    _require_equal(
        transaction["resolvedAuthorityVectorHash"],
        digest,
        path=(
            "publicationMutation.repositoryTransaction."
            "resolvedAuthorityVectorHash"
        ),
        message="transaction does not bind the resolved four-authority vector",
    )
    return subject, digest


def _device_record_set_digest(
    host_snapshot: Mapping[str, Any],
) -> str:
    subject = {
        "hostSnapshotContentHashOrNull": host_snapshot["contentHash"],
        "deviceRecordDigests": _thaw_json(
            host_snapshot["deviceRecordDigests"]
        ),
    }
    return sha256_digest(
        DEVICE_RECORD_SET_DOMAIN + canonical_json_bytes(subject)
    )


def _verify_availability_scope(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    transaction: Mapping[str, Any],
) -> None:
    for name, value in before.items():
        if name in _AVAILABILITY_MUTABLE_FIELDS:
            continue
        _require_equal(
            after[name],
            value,
            path=f"publicationMutation.availabilityAuthorityAfter.{name}",
            message="publication changed AvailabilityAuthority identity/scope",
        )
    _require_equal(
        after["resourceVersion"],
        before["resourceVersion"] + 1,
        path="publicationMutation.availabilityAuthorityAfter.resourceVersion",
        message="committed publication must advance availability version once",
    )
    _require_equal(
        after["lastMutatedAt"],
        transaction["committedAtOrNull"],
        path="publicationMutation.availabilityAuthorityAfter.lastMutatedAt",
        message="availability fence time differs from repository commit time",
    )


def _event_id(domain: bytes, subject: Mapping[str, Any], prefix: str) -> str:
    digest = sha256_digest(domain + canonical_json_bytes(subject))
    return prefix + ":" + digest.removeprefix("sha256:")


def _verify_committed_row_bindings(
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
    transaction: Mapping[str, Any],
    *,
    availability: _VerifiedArtifact,
    audit: _VerifiedArtifact,
    outbox: _VerifiedArtifact,
    commit: _VerifiedArtifact,
) -> str:
    before_availability = decision.read_set.availability_authority_before
    _verify_availability_scope(
        before_availability,
        availability.state,
        transaction,
    )

    snapshot = rollback.host_snapshot_after_artifact["state"]
    host_authority = rollback.host_authority_after_artifact["state"]
    reservation_id = rollback.reservation_id_or_null
    prepare_digest = rollback.prepare_receipt_digest_or_null
    require(
        reservation_id is not None and prepare_digest is not None,
        "PUBLICATION_MUTATION_RECOVERY_BINDING_MISMATCH",
        "publicationMutation.rollback",
        "committed mutation requires retained rollback reservation keys",
    )

    event_subject = {
        "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
        "commandId": operation_request.command_id,
        "requestHash": operation_request.request_hash,
        "operationRequestContextDigest": operation_request.context_digest,
        "decisionContextDigest": decision.context_digest,
        "expectationHash": decision.expectation_hash,
        "repositoryId": transaction["repositoryId"],
        "transactionId": transaction["transactionId"],
        "commitId": transaction["commitIdOrNull"],
        "aggregateId": snapshot["hostId"],
        "createdAt": transaction["committedAtOrNull"],
        "commitClockBefore": transaction["commitClockBefore"],
        "commitClockAfter": transaction["commitClockAfter"],
        "anchorReservationId": reservation_id,
        "anchorPrepareReceiptDigest": prepare_digest,
        "anchorCandidateProjectionDigest": (
            rollback.candidate_projection_digest
        ),
    }
    expected_audit_event_id = _event_id(
        AUDIT_EVENT_ID_DOMAIN,
        event_subject,
        "audit",
    )
    expected_outbox_event_id = _event_id(
        OUTBOX_EVENT_ID_DOMAIN,
        event_subject,
        "outbox",
    )
    expected_audit = {
        "auditEventId": expected_audit_event_id,
        "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
        "commandId": operation_request.command_id,
        "transactionId": transaction["transactionId"],
        "commitId": transaction["commitIdOrNull"],
        "targetRepositoryObjectFormat": (
            operation_request.target_repository_object_format
        ),
        "targetRepositoryCommit": (
            operation_request.target_repository_commit
        ),
        "hostId": snapshot["hostId"],
        "anchorReservationId": reservation_id,
        "anchorPrepareReceiptDigest": prepare_digest,
        "anchorCandidateProjectionDigest": (
            rollback.candidate_projection_digest
        ),
        "requiredAnchorVersion": rollback.required_anchor_version,
        "snapshotContentHash": snapshot["contentHash"],
        "hostAuthorityResourceVersion": host_authority["resourceVersion"],
        "availabilityAuthorityResourceVersion": (
            availability.state["resourceVersion"]
        ),
        "priorAuditDigestOrNull": None,
        "createdAt": transaction["committedAtOrNull"],
    }
    for name, value in expected_audit.items():
        _require_equal(
            audit.state[name],
            value,
            path=f"publicationMutation.auditRecord.{name}",
            message="publication audit does not bind committed publication",
        )

    expected_outbox = {
        "outboxEventId": expected_outbox_event_id,
        "aggregateId": snapshot["hostId"],
        "transactionId": transaction["transactionId"],
        "commitId": transaction["commitIdOrNull"],
        "anchorReservationId": reservation_id,
        "anchorPrepareReceiptDigest": prepare_digest,
        "anchorCandidateProjectionDigest": (
            rollback.candidate_projection_digest
        ),
        "requiredAnchorVersion": rollback.required_anchor_version,
        "snapshotContentHash": snapshot["contentHash"],
        "hostAuthorityResourceVersion": host_authority["resourceVersion"],
        "availabilityAuthorityResourceVersion": (
            availability.state["resourceVersion"]
        ),
        "createdAt": transaction["committedAtOrNull"],
    }
    for name, value in expected_outbox.items():
        _require_equal(
            outbox.state[name],
            value,
            path=f"publicationMutation.outboxRecord.{name}",
            message="pending outbox row does not bind committed publication",
        )

    payload_subject = {
        "eventType": outbox.state["eventType"],
        "aggregateId": outbox.state["aggregateId"],
        "anchorReservationId": outbox.state["anchorReservationId"],
        "anchorPrepareReceiptDigest": outbox.state[
            "anchorPrepareReceiptDigest"
        ],
        "anchorCandidateProjectionDigest": outbox.state[
            "anchorCandidateProjectionDigest"
        ],
        "requiredAnchorVersion": outbox.state["requiredAnchorVersion"],
        "deliveryGate": outbox.state["deliveryGate"],
        "snapshotContentHash": outbox.state["snapshotContentHash"],
        "hostAuthorityResourceVersion": outbox.state[
            "hostAuthorityResourceVersion"
        ],
        "availabilityAuthorityResourceVersion": outbox.state[
            "availabilityAuthorityResourceVersion"
        ],
    }
    payload_hash = sha256_digest(
        OUTBOX_PAYLOAD_DOMAIN + canonical_json_bytes(payload_subject)
    )
    _require_equal(
        outbox.state["payloadHash"],
        payload_hash,
        path="publicationMutation.outboxRecord.payloadHash",
        message="pending outbox payload hash uses a different projection",
    )

    expected_commit = {
        "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
        "commandId": operation_request.command_id,
        "requestHash": operation_request.request_hash,
        "operationRequestContextDigest": operation_request.context_digest,
        "decisionContextDigest": decision.context_digest,
        "expectationHash": decision.expectation_hash,
        "commitId": transaction["commitIdOrNull"],
        "transactionId": transaction["transactionId"],
        "repositoryId": transaction["repositoryId"],
        "commitClockBefore": transaction["commitClockBefore"],
        "commitClockAfter": transaction["commitClockAfter"],
        "committedAt": transaction["committedAtOrNull"],
        "anchorReservationId": reservation_id,
        "anchorPrepareReceiptDigest": prepare_digest,
        "anchorCandidateProjectionDigest": (
            rollback.candidate_projection_digest
        ),
        "hostSnapshotInstanceSha256": (
            rollback.host_snapshot_after_artifact["instanceBytesSha256"]
        ),
        "hostAuthorityAfterInstanceSha256": (
            rollback.host_authority_after_artifact["instanceBytesSha256"]
        ),
    }
    for name, value in expected_commit.items():
        _require_equal(
            commit.state[name],
            value,
            path=f"publicationMutation.commitRecord.{name}",
            message="durable commit row does not bind transaction/rollback rows",
        )
    return payload_hash


def _mutation(
    *,
    mutation_kind: str,
    entity_type: str,
    record_id: str,
    digest_projection: str,
    before_digest_or_null: str | None,
    after_digest_or_null: str,
) -> dict[str, Any]:
    return {
        "mutationKind": mutation_kind,
        "entityType": entity_type,
        "recordId": record_id,
        "digestProjection": digest_projection,
        "beforeDigestOrNull": before_digest_or_null,
        "afterDigestOrNull": after_digest_or_null,
    }


def _derive_committed_mutations(
    schemas: ContractSchemas,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
    availability: _VerifiedArtifact,
    audit: _VerifiedArtifact,
    outbox: _VerifiedArtifact,
    commit: _VerifiedArtifact,
    *,
    limits: PublicationMutationVerifierLimits,
) -> tuple[list[dict[str, Any]], bytes, str]:
    mutations: list[dict[str, Any]] = []
    artifact_bytes = (
        decision.capture.device_record_artifact_canonical_bytes
    )
    require(
        len(artifact_bytes) == len(decision.persisted_device_records),
        "PUBLICATION_MUTATION_RECORD_SET_MISMATCH",
        "publicationMutation.persistedDeviceRecords",
        "candidate artifact count differs from committed DeviceRecord count",
    )
    for index, (retained_artifact_bytes, record) in enumerate(
        zip(
            artifact_bytes,
            decision.persisted_device_records,
            strict=True,
        )
    ):
        try:
            retained_artifact = load_canonical_json(
                retained_artifact_bytes
            )
        except (CanonicalizationError, RecursionError) as exc:
            fail(
                "PUBLICATION_MUTATION_CANONICAL_BYTES_INVALID",
                (
                    "publicationMutation.persistedDeviceRecords"
                    f"[{index}].artifact"
                ),
                f"retained candidate artifact is not canonical: {exc}",
            )
        require(
            isinstance(retained_artifact, dict)
            and retained_artifact["recordBinding"][
                "deviceRecordHash"
            ]
            == record.device_record_hash,
            "PUBLICATION_MUTATION_RECORD_ID_INVALID",
            (
                "publicationMutation.persistedDeviceRecords"
                f"[{index}].recordBinding.deviceRecordHash"
            ),
            "DeviceRecord mutation ID is not the exact retained binding",
        )
        mutations.append(
            _mutation(
                mutation_kind="INSERT",
                entity_type="ENTITY-DEVICE-RECORD",
                record_id=retained_artifact["recordBinding"][
                    "deviceRecordHash"
                ],
                digest_projection="FULL_CANONICAL_INSTANCE",
                before_digest_or_null=None,
                after_digest_or_null=sha256_digest(record.canonical_bytes),
            )
        )

    snapshot_after = rollback.host_snapshot_after_artifact["state"]
    host_authority_before = decision.read_set.host_authority_before
    host_authority_after = rollback.host_authority_after_artifact["state"]
    mutations.extend(
        (
            _mutation(
                mutation_kind="INSERT",
                entity_type="ENTITY-HOST-SNAPSHOT",
                record_id=snapshot_after["contentHash"],
                digest_projection="FULL_CANONICAL_INSTANCE",
                before_digest_or_null=None,
                after_digest_or_null=_plain_projection_digest(
                    snapshot_after
                ),
            ),
            _mutation(
                mutation_kind="UPDATE",
                entity_type="ENTITY-HOST-AUTHORITY",
                record_id=host_authority_after["hostId"],
                digest_projection="FULL_CANONICAL_INSTANCE",
                before_digest_or_null=_plain_projection_digest(
                    host_authority_before
                ),
                after_digest_or_null=_plain_projection_digest(
                    host_authority_after
                ),
            ),
            _mutation(
                mutation_kind="UPDATE",
                entity_type="ENTITY-AVAILABILITY-AUTHORITY",
                record_id=availability.state["availabilityAuthorityId"],
                digest_projection=(
                    "AVAILABILITY_AUTHORITY_LAST_MUTATION_DIGEST_NULL"
                ),
                before_digest_or_null=_plain_projection_digest(
                    decision.read_set.availability_authority_before,
                    null_fields=("lastMutationDigest",),
                ),
                after_digest_or_null=_plain_projection_digest(
                    availability.state,
                    null_fields=("lastMutationDigest",),
                ),
            ),
            _mutation(
                mutation_kind="INSERT",
                entity_type=(
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT"
                ),
                record_id=audit.state["auditEventId"],
                digest_projection=(
                    "PUBLICATION_AUDIT_MUTATION_SET_AND_AUDIT_DIGEST_NULL"
                ),
                before_digest_or_null=None,
                after_digest_or_null=_plain_projection_digest(
                    audit.state,
                    null_fields=("mutationSetHash", "auditDigest"),
                ),
            ),
            _mutation(
                mutation_kind="INSERT",
                entity_type=(
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX"
                ),
                record_id=outbox.state["outboxEventId"],
                digest_projection=(
                    "PUBLICATION_OUTBOX_MUTATION_SET_AND_OUTBOX_DIGEST_NULL"
                ),
                before_digest_or_null=None,
                after_digest_or_null=_plain_projection_digest(
                    outbox.state,
                    null_fields=("mutationSetHash", "outboxDigest"),
                ),
            ),
            _mutation(
                mutation_kind="INSERT",
                entity_type=(
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT"
                ),
                record_id=commit.state["commitId"],
                digest_projection=(
                    "PUBLICATION_COMMIT_DERIVED_FIELDS_NULL"
                ),
                before_digest_or_null=None,
                after_digest_or_null=_plain_projection_digest(
                    commit.state,
                    null_fields=_COMMIT_PROJECTION_NULL_FIELDS,
                ),
            ),
        )
    )
    mutations.sort(
        key=lambda item: canonical_json_bytes(
            [item["entityType"], item["recordId"], item["mutationKind"]]
        )
    )
    expected_count = len(decision.persisted_device_records) + 6
    require(
        len(mutations) == expected_count
        and len(mutations) <= limits.max_mutations,
        "PUBLICATION_MUTATION_COUNT_INVALID",
        "publicationMutation.mutations",
        "committed mutation set is not exactly N DeviceRecords plus six rows",
    )
    schemas.validate_ref(
        MUTATION_ARRAY_SCHEMA_REF,
        mutations,
        "publicationMutation.mutations",
    )
    identities = {
        (item["entityType"], item["recordId"], item["mutationKind"])
        for item in mutations
    }
    require(
        len(identities) == len(mutations),
        "PUBLICATION_MUTATION_RECORD_ID_INVALID",
        "publicationMutation.mutations",
        "derived mutation identities are not unique",
    )
    mutation_bytes = canonical_json_bytes(mutations)
    mutation_hash = sha256_digest(MUTATION_SET_DOMAIN + mutation_bytes)
    return mutations, mutation_bytes, mutation_hash


def _verify_fixed_point_and_self_digests(
    mutation_set_hash: str,
    *,
    availability: _VerifiedArtifact,
    audit: _VerifiedArtifact,
    outbox: _VerifiedArtifact,
    commit: _VerifiedArtifact,
) -> None:
    for path, value in (
        (
            "availabilityAuthorityAfter.lastMutationDigest",
            availability.state["lastMutationDigest"],
        ),
        ("auditRecord.mutationSetHash", audit.state["mutationSetHash"]),
        ("outboxRecord.mutationSetHash", outbox.state["mutationSetHash"]),
        ("commitRecord.mutationSetHash", commit.state["mutationSetHash"]),
    ):
        require(
            value == mutation_set_hash,
            "PUBLICATION_MUTATION_FIXED_POINT_MISMATCH",
            f"publicationMutation.{path}",
            "stored row does not retain the acyclic derived mutation-set hash",
        )

    expected_audit_digest = _domain_digest(
        AUDIT_RECORD_DOMAIN,
        audit.state,
        null_fields=("auditDigest",),
    )
    _require_equal(
        audit.state["auditDigest"],
        expected_audit_digest,
        path="publicationMutation.auditRecord.auditDigest",
        message="audit self-digest does not retain final mutationSetHash",
    )
    expected_outbox_digest = _domain_digest(
        OUTBOX_RECORD_DOMAIN,
        outbox.state,
        null_fields=("outboxDigest",),
    )
    _require_equal(
        outbox.state["outboxDigest"],
        expected_outbox_digest,
        path="publicationMutation.outboxRecord.outboxDigest",
        message="outbox self-digest does not retain final mutationSetHash",
    )


def _verify_commit_digests(
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
    device_record_set_digest: str,
    *,
    availability: _VerifiedArtifact,
    audit: _VerifiedArtifact,
    outbox: _VerifiedArtifact,
    commit: _VerifiedArtifact,
) -> str:
    expected = {
        "deviceRecordSetDigest": device_record_set_digest,
        "availabilityAuthorityAfterInstanceSha256": (
            availability.wrapper["instanceBytesSha256"]
        ),
        "auditRecordInstanceSha256": audit.wrapper["instanceBytesSha256"],
        "outboxRecordInstanceSha256": outbox.wrapper[
            "instanceBytesSha256"
        ],
    }
    for name, value in expected.items():
        _require_equal(
            commit.state[name],
            value,
            path=f"publicationMutation.commitRecord.{name}",
            message="durable commit row does not bind an exact retained row",
        )
    digest = _domain_digest(
        COMMIT_RECORD_DOMAIN,
        commit.state,
        null_fields=("commitRecordDigest",),
    )
    _require_equal(
        commit.state["commitRecordDigest"],
        digest,
        path="publicationMutation.commitRecord.commitRecordDigest",
        message="durable commit-row self-digest mismatch",
    )
    _require_equal(
        commit.state["hostSnapshotInstanceSha256"],
        rollback.host_snapshot_after_artifact["instanceBytesSha256"],
        path=(
            "publicationMutation.commitRecord."
            "hostSnapshotInstanceSha256"
        ),
        message="durable commit row does not bind HostSnapshot after bytes",
    )
    _require_equal(
        commit.state["hostAuthorityAfterInstanceSha256"],
        rollback.host_authority_after_artifact["instanceBytesSha256"],
        path=(
            "publicationMutation.commitRecord."
            "hostAuthorityAfterInstanceSha256"
        ),
        message="durable commit row does not bind HostAuthority after bytes",
    )
    return digest


def _cas_result(
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    transaction: Mapping[str, Any],
    *,
    committed_host_version: int,
    committed_availability_version: int,
    mutation_set_hash_or_null: str | None,
    commit_record_digest_or_null: str | None,
    publication_mutation_count: int,
) -> dict[str, Any]:
    return {
        "decision": transaction["outcome"],
        "expectationHashOrNull": decision.expectation_hash,
        "committedAuthorityHashOrNull": transaction[
            "resolvedAuthorityVectorHash"
        ],
        "expectedHostAuthorityResourceVersionOrNull": transaction[
            "expectedHostAuthorityResourceVersion"
        ],
        "expectedAvailabilityAuthorityResourceVersionOrNull": transaction[
            "expectedAvailabilityAuthorityResourceVersion"
        ],
        "expectedCapabilityPolicyAuthorityResourceVersionOrNull": transaction[
            "expectedCapabilityPolicyAuthorityResourceVersion"
        ],
        "expectedCapabilityPolicyHashOrNull": transaction[
            "expectedCapabilityPolicyHash"
        ],
        "expectedFreshnessPolicyAuthorityResourceVersionOrNull": transaction[
            "expectedFreshnessPolicyAuthorityResourceVersion"
        ],
        "expectedFreshnessPolicyHashOrNull": transaction[
            "expectedFreshnessPolicyHash"
        ],
        "committedHostAuthorityResourceVersionOrNull": (
            committed_host_version
        ),
        "committedAvailabilityAuthorityResourceVersionOrNull": (
            committed_availability_version
        ),
        "mutationSetHashOrNull": mutation_set_hash_or_null,
        "commitRecordDigestOrNull": commit_record_digest_or_null,
        "publicationMutationCount": publication_mutation_count,
        "conflicts": [],
    }


def _verify_local_cas_result_shape(
    result: Mapping[str, Any],
    *,
    write_required: bool,
) -> None:
    """Check the locally derived closed branch without claiming schema identity."""

    require(
        set(result) == _CAS_RESULT_FIELDS,
        "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
        "publicationMutation.snapshotPublicationCasResult",
        "derived CAS result does not have the exact closed local field set",
    )
    expected_decision = "COMMITTED" if write_required else "NO_CHANGE"
    require(
        result["decision"] == expected_decision,
        "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
        "publicationMutation.snapshotPublicationCasResult.decision",
        "derived CAS result branch differs from publication write disposition",
    )
    for name in (
        "expectationHashOrNull",
        "committedAuthorityHashOrNull",
        "expectedCapabilityPolicyHashOrNull",
        "expectedFreshnessPolicyHashOrNull",
    ):
        require(
            isinstance(result[name], str)
            and _DIGEST_PATTERN.fullmatch(result[name]) is not None,
            "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
            f"publicationMutation.snapshotPublicationCasResult.{name}",
            "successful CAS result requires one lowercase SHA-256 digest",
        )
    for name in (
        "expectedHostAuthorityResourceVersionOrNull",
        "expectedAvailabilityAuthorityResourceVersionOrNull",
        "expectedCapabilityPolicyAuthorityResourceVersionOrNull",
        "expectedFreshnessPolicyAuthorityResourceVersionOrNull",
        "committedHostAuthorityResourceVersionOrNull",
        "committedAvailabilityAuthorityResourceVersionOrNull",
    ):
        require(
            isinstance(result[name], int)
            and not isinstance(result[name], bool)
            and result[name] >= 1,
            "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
            f"publicationMutation.snapshotPublicationCasResult.{name}",
            "successful CAS result requires one positive authority version",
        )
    require(
        isinstance(result["publicationMutationCount"], int)
        and not isinstance(result["publicationMutationCount"], bool)
        and 0
        <= result["publicationMutationCount"]
        <= MAX_PUBLICATION_MUTATIONS,
        "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
        (
            "publicationMutation.snapshotPublicationCasResult."
            "publicationMutationCount"
        ),
        "publication mutation count is outside the closed local range",
    )
    conflicts = result["conflicts"]
    require(
        isinstance(conflicts, Sequence)
        and not isinstance(
            conflicts,
            (str, bytes, bytearray, memoryview),
        )
        and len(conflicts) == 0,
        "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
        "publicationMutation.snapshotPublicationCasResult.conflicts",
        "successful publication CAS result cannot contain conflicts",
    )
    if write_required:
        require(
            result["publicationMutationCount"] >= 7,
            "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
            (
                "publicationMutation.snapshotPublicationCasResult."
                "publicationMutationCount"
            ),
            "committed publication requires at least seven mutations",
        )
        for name in ("mutationSetHashOrNull", "commitRecordDigestOrNull"):
            require(
                isinstance(result[name], str)
                and _DIGEST_PATTERN.fullmatch(result[name]) is not None,
                "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
                f"publicationMutation.snapshotPublicationCasResult.{name}",
                "committed CAS result requires a lowercase SHA-256 digest",
            )
    else:
        require(
            result["publicationMutationCount"] == 0
            and result["mutationSetHashOrNull"] is None
            and result["commitRecordDigestOrNull"] is None,
            "PUBLICATION_MUTATION_CAS_RESULT_INVALID",
            "publicationMutation.snapshotPublicationCasResult",
            "NO_CHANGE CAS result must be an exact zero-write projection",
        )


def _context_digest(receipt: Mapping[str, Any]) -> str:
    return sha256_digest(
        MUTATION_CONTEXT_DOMAIN
        + canonical_json_bytes(
            _projection(receipt, null_fields=("contextDigest",))
        )
    )


def verify_host_snapshot_publication_mutation_closure(
    schemas: ContractSchemas,
    operation_request: VerifiedHostSnapshotPublicationOperationRequestContext,
    decision: VerifiedHostSnapshotPublicationDecisionContext,
    rollback: VerifiedHostSnapshotPublicationRollbackContext,
    *,
    repository_transaction: JsonDocument,
    availability_authority_after_artifact_or_none: JsonDocument | None,
    audit_record_artifact_or_none: JsonDocument | None,
    outbox_record_artifact_or_none: JsonDocument | None,
    commit_record_artifact_or_none: JsonDocument | None,
    limits: PublicationMutationVerifierLimits | None = None,
) -> VerifiedHostSnapshotPublicationMutationContext:
    """Verify an acyclic mutation/hash closure without claiming product I/O."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_MUTATION_INPUT_INVALID",
        "publicationMutation.schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        operation_request,
        VerifiedHostSnapshotPublicationOperationRequestContext,
        code="PUBLICATION_MUTATION_OPERATION_REQUEST_INVALID",
        path="publicationMutation.operationRequest",
        message=(
            "operation request must come from "
            "verify_host_snapshot_publication_operation_request"
        ),
    )
    require_factory_verified(
        decision,
        VerifiedHostSnapshotPublicationDecisionContext,
        code="PUBLICATION_MUTATION_DECISION_INVALID",
        path="publicationMutation.decision",
        message=(
            "decision must come from "
            "verify_host_snapshot_publication_decision"
        ),
    )
    require_factory_verified(
        rollback,
        VerifiedHostSnapshotPublicationRollbackContext,
        code="PUBLICATION_MUTATION_ROLLBACK_INVALID",
        path="publicationMutation.rollback",
        message=(
            "rollback must come from "
            "verify_host_snapshot_publication_rollback_closure"
        ),
    )
    checked_limits = _checked_limits(limits)

    # Count gates deliberately precede replay and every retained-record walk.
    device_count = len(decision.persisted_device_records)
    expected_mutation_count = device_count + 6 if decision.write_required else 0
    require(
        1 <= device_count <= checked_limits.max_device_records,
        "PUBLICATION_MUTATION_TOO_LARGE",
        "publicationMutation.persistedDeviceRecords",
        (
            "full publication DeviceRecord count is outside the closed "
            f"1..{checked_limits.max_device_records} limit"
        ),
    )
    require(
        expected_mutation_count <= checked_limits.max_mutations,
        "PUBLICATION_MUTATION_TOO_LARGE",
        "publicationMutation.mutations",
        (
            "derived mutation count exceeds the closed "
            f"{checked_limits.max_mutations} limit"
        ),
    )

    operation_request = replay_host_snapshot_publication_operation_request(
        operation_request
    )
    decision = replay_host_snapshot_publication_decision(decision)
    rollback = replay_host_snapshot_publication_rollback_closure(rollback)
    require(
        rollback.decision.context_digest == decision.context_digest
        and rollback.repository_id == decision.read_set.repository_id
        and rollback.transaction_id == decision.read_set.transaction_id
        and rollback.expectation_hash == decision.expectation_hash,
        "PUBLICATION_MUTATION_CONTEXT_MISMATCH",
        "publicationMutation.rollback",
        "rollback context does not consume this exact decision/read-set",
    )
    require(
        rollback._schemas is schemas
        and decision.read_set._schemas is schemas
        and operation_request._schemas is schemas,
        "PUBLICATION_MUTATION_SCHEMA_IDENTITY_MISMATCH",
        "publicationMutation.schemas",
        (
            "operation/decision/rollback contexts use a different "
            "ContractSchemas instance"
        ),
    )
    _verify_operation_request_read_set(
        operation_request,
        decision,
        rollback,
    )
    budget = _Budget(checked_limits)
    transaction, transaction_raw = _load_document(
        repository_transaction,
        path="publicationMutation.repositoryTransaction",
        max_bytes=checked_limits.max_transaction_bytes,
        limits=checked_limits,
        budget=budget,
    )
    schemas.validate_ref(
        REPOSITORY_TRANSACTION_SCHEMA_REF,
        transaction,
        "publicationMutation.repositoryTransaction",
    )
    _verify_transaction_expectation(
        transaction,
        operation_request,
        decision,
    )
    committed_at = _verify_transaction_outcome(
        transaction,
        operation_request,
        decision,
        rollback,
    )

    availability: _VerifiedArtifact | None = None
    audit: _VerifiedArtifact | None = None
    outbox: _VerifiedArtifact | None = None
    commit: _VerifiedArtifact | None = None
    supplied_artifacts = (
        availability_authority_after_artifact_or_none,
        audit_record_artifact_or_none,
        outbox_record_artifact_or_none,
        commit_record_artifact_or_none,
    )
    if decision.write_required:
        require(
            all(item is not None for item in supplied_artifacts),
            "PUBLICATION_MUTATION_ARTIFACT_REQUIRED",
            "publicationMutation.committedArtifacts",
            "committed publication requires all four final row artifacts",
        )
        assert availability_authority_after_artifact_or_none is not None
        assert audit_record_artifact_or_none is not None
        assert outbox_record_artifact_or_none is not None
        assert commit_record_artifact_or_none is not None
        availability = _verify_artifact(
            schemas,
            availability_authority_after_artifact_or_none,
            wrapper_schema_ref=AVAILABILITY_AUTHORITY_ARTIFACT_SCHEMA_REF,
            state_schema_ref=AVAILABILITY_AUTHORITY_STATE_SCHEMA_REF,
            path="publicationMutation.availabilityAuthorityAfter",
            limits=checked_limits,
            budget=budget,
        )
        audit = _verify_artifact(
            schemas,
            audit_record_artifact_or_none,
            wrapper_schema_ref=AUDIT_RECORD_ARTIFACT_SCHEMA_REF,
            state_schema_ref=AUDIT_RECORD_STATE_SCHEMA_REF,
            path="publicationMutation.auditRecord",
            limits=checked_limits,
            budget=budget,
        )
        outbox = _verify_artifact(
            schemas,
            outbox_record_artifact_or_none,
            wrapper_schema_ref=OUTBOX_RECORD_ARTIFACT_SCHEMA_REF,
            state_schema_ref=OUTBOX_RECORD_STATE_SCHEMA_REF,
            path="publicationMutation.outboxRecord",
            limits=checked_limits,
            budget=budget,
        )
        commit = _verify_artifact(
            schemas,
            commit_record_artifact_or_none,
            wrapper_schema_ref=COMMIT_RECORD_ARTIFACT_SCHEMA_REF,
            state_schema_ref=COMMIT_RECORD_STATE_SCHEMA_REF,
            path="publicationMutation.commitRecord",
            limits=checked_limits,
            budget=budget,
        )
    else:
        require(
            all(item is None for item in supplied_artifacts),
            "PUBLICATION_MUTATION_NO_CHANGE_WRITE",
            "publicationMutation.noChangeArtifacts",
            "NO_CHANGE forbids Availability/audit/outbox/commit row artifacts",
        )

    resolved_vector, resolved_hash = _resolved_authority_vector(
        schemas,
        decision,
        rollback,
        transaction,
        availability,
    )
    host_snapshot_after = rollback.host_snapshot_after_artifact["state"]
    device_set_digest = _device_record_set_digest(host_snapshot_after)

    if decision.write_required:
        assert committed_at is not None
        assert availability is not None
        assert audit is not None
        assert outbox is not None
        assert commit is not None
        _verify_committed_row_bindings(
            operation_request,
            decision,
            rollback,
            transaction,
            availability=availability,
            audit=audit,
            outbox=outbox,
            commit=commit,
        )
        mutations, mutation_raw, mutation_set_hash = (
            _derive_committed_mutations(
                schemas,
                decision,
                rollback,
                availability,
                audit,
                outbox,
                commit,
                limits=checked_limits,
            )
        )
        _verify_fixed_point_and_self_digests(
            mutation_set_hash,
            availability=availability,
            audit=audit,
            outbox=outbox,
            commit=commit,
        )
        commit_digest = _verify_commit_digests(
            rollback,
            device_set_digest,
            availability=availability,
            audit=audit,
            outbox=outbox,
            commit=commit,
        )
        publication_mutation_count = len(mutations)
        committed_host_version = rollback.host_authority_after_artifact[
            "state"
        ]["resourceVersion"]
        committed_availability_version = availability.state[
            "resourceVersion"
        ]
    else:
        schemas.validate_ref(
            MUTATION_ARRAY_SCHEMA_REF,
            [],
            "publicationMutation.mutations",
        )
        mutations = []
        mutation_raw = b"[]"
        mutation_set_hash = None
        commit_digest = None
        publication_mutation_count = 0
        committed_host_version = decision.read_set.host_authority_before[
            "resourceVersion"
        ]
        committed_availability_version = (
            decision.read_set.availability_authority_before[
                "resourceVersion"
            ]
        )

    cas_result = _cas_result(
        decision,
        transaction,
        committed_host_version=committed_host_version,
        committed_availability_version=committed_availability_version,
        mutation_set_hash_or_null=mutation_set_hash,
        commit_record_digest_or_null=commit_digest,
        publication_mutation_count=publication_mutation_count,
    )
    _verify_local_cas_result_shape(
        cas_result,
        write_required=decision.write_required,
    )
    receipt = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_MUTATION_CONTEXT",
        "schemaVersion": 1,
        "operationRequestContextDigest": operation_request.context_digest,
        "requestHash": operation_request.request_hash,
        "idempotencyKey": operation_request.idempotency_key,
        "idempotencyScopeHash": operation_request.idempotency_scope_hash,
        "decisionContextDigest": decision.context_digest,
        "rollbackContextDigest": rollback.context_digest,
        "repositoryTransactionCanonicalSha256": sha256_digest(
            transaction_raw
        ),
        "commandId": operation_request.command_id,
        "targetRepositoryObjectFormat": (
            operation_request.target_repository_object_format
        ),
        "targetRepositoryCommit": (
            operation_request.target_repository_commit
        ),
        "expectationHash": decision.expectation_hash,
        "commitClockBefore": transaction["commitClockBefore"],
        "commitClockAfter": transaction["commitClockAfter"],
        "availabilityAuthorityAfterArtifactCanonicalSha256OrNull": (
            None
            if availability is None
            else sha256_digest(availability.wrapper_canonical_bytes)
        ),
        "auditRecordArtifactCanonicalSha256OrNull": (
            None
            if audit is None
            else sha256_digest(audit.wrapper_canonical_bytes)
        ),
        "outboxRecordArtifactCanonicalSha256OrNull": (
            None
            if outbox is None
            else sha256_digest(outbox.wrapper_canonical_bytes)
        ),
        "commitRecordArtifactCanonicalSha256OrNull": (
            None
            if commit is None
            else sha256_digest(commit.wrapper_canonical_bytes)
        ),
        "publicationDecision": decision.publication_decision,
        "transactionOutcome": transaction["outcome"],
        "publicationMutationCount": publication_mutation_count,
        "mutationSetHashOrNull": mutation_set_hash,
        "deviceRecordSetDigest": device_set_digest,
        "resolvedAuthorityVectorHash": resolved_hash,
        "commitRecordDigestOrNull": commit_digest,
        "snapshotPublicationCasResult": cas_result,
        "authorityBoundary": (
            HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY
        ),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = _context_digest(receipt)
    receipt["contextDigest"] = context_digest
    receipt_raw = canonical_json_bytes(receipt)
    return VerifiedHostSnapshotPublicationMutationContext._construct(
        limits=checked_limits,
        operation_request=operation_request,
        decision=decision,
        rollback=rollback,
        repository_transaction=_freeze_json(transaction),
        repository_transaction_canonical_bytes=transaction_raw,
        availability_authority_after_artifact_or_null=(
            None if availability is None else availability.wrapper
        ),
        availability_authority_after_artifact_canonical_bytes_or_null=(
            None
            if availability is None
            else availability.wrapper_canonical_bytes
        ),
        audit_record_artifact_or_null=(
            None if audit is None else audit.wrapper
        ),
        audit_record_artifact_canonical_bytes_or_null=(
            None if audit is None else audit.wrapper_canonical_bytes
        ),
        outbox_record_artifact_or_null=(
            None if outbox is None else outbox.wrapper
        ),
        outbox_record_artifact_canonical_bytes_or_null=(
            None if outbox is None else outbox.wrapper_canonical_bytes
        ),
        commit_record_artifact_or_null=(
            None if commit is None else commit.wrapper
        ),
        commit_record_artifact_canonical_bytes_or_null=(
            None if commit is None else commit.wrapper_canonical_bytes
        ),
        mutations=tuple(_freeze_json(item) for item in mutations),
        mutations_canonical_bytes=mutation_raw,
        mutation_set_hash_or_null=mutation_set_hash,
        device_record_set_digest=device_set_digest,
        resolved_authority_vector=_freeze_json(resolved_vector),
        resolved_authority_vector_hash=resolved_hash,
        commit_record_digest_or_null=commit_digest,
        publication_mutation_count=publication_mutation_count,
        snapshot_publication_cas_result=_freeze_json(cas_result),
        context_receipt=_freeze_json(receipt),
        context_receipt_canonical_bytes=receipt_raw,
        context_digest=context_digest,
        authority_boundary=(
            HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY
        ),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_host_snapshot_publication_mutation_closure(
    context: VerifiedHostSnapshotPublicationMutationContext,
) -> VerifiedHostSnapshotPublicationMutationContext:
    """Replay one mutation context from only its retained exact inputs."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationMutationContext,
        code="PUBLICATION_MUTATION_CONTEXT_INVALID",
        path="publicationMutation.context",
        message=(
            "context must come from "
            "verify_host_snapshot_publication_mutation_closure"
        ),
    )
    replayed = verify_host_snapshot_publication_mutation_closure(
        context._schemas,
        context.operation_request,
        context.decision,
        context.rollback,
        repository_transaction=(
            context.repository_transaction_canonical_bytes
        ),
        availability_authority_after_artifact_or_none=(
            context.availability_authority_after_artifact_canonical_bytes_or_null
        ),
        audit_record_artifact_or_none=(
            context.audit_record_artifact_canonical_bytes_or_null
        ),
        outbox_record_artifact_or_none=(
            context.outbox_record_artifact_canonical_bytes_or_null
        ),
        commit_record_artifact_or_none=(
            context.commit_record_artifact_canonical_bytes_or_null
        ),
        limits=context.limits,
    )
    require(
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes
        and replayed.mutations_canonical_bytes
        == context.mutations_canonical_bytes
        and replayed == context
        and replayed._schemas is context._schemas,
        "PUBLICATION_MUTATION_CONTEXT_REPLAY_MISMATCH",
        "publicationMutation.context",
        (
            "mutation context claims differ when replayed from retained "
            "exact inputs"
        ),
    )
    require(
        canonical_json_bytes(
            _thaw_json(replayed.snapshot_publication_cas_result)
        )
        == canonical_json_bytes(
            _thaw_json(context.snapshot_publication_cas_result)
        ),
        "PUBLICATION_MUTATION_CONTEXT_REPLAY_MISMATCH",
        "publicationMutation.context.snapshotPublicationCasResult",
        "derived CAS result differs when replayed from retained bytes",
    )
    return replayed


__all__ = [
    "DEFAULT_PUBLICATION_MUTATION_LIMITS",
    "HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS",
    "MAX_PUBLICATION_MUTATION_DEVICE_RECORDS",
    "MAX_PUBLICATION_MUTATIONS",
    "PublicationMutationVerifierLimits",
    "VerifiedHostSnapshotPublicationMutationContext",
    "replay_host_snapshot_publication_mutation_closure",
    "verify_host_snapshot_publication_mutation_closure",
]
