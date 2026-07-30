"""Component-only repository receipt boundary for HostSnapshot publication.

The verifier in this module consumes an already verified publication mutation
closure and one independently queried, role-signed repository receipt.  It
checks exact canonical bytes, the complete transaction/mutation projection,
the operation-request trust references, a fresh verifier nonce, and a current
``CONTROL_REPOSITORY_EVIDENCE`` Ed25519 signer.

This remains a portable component boundary.  A conforming Python port or a
valid receipt does not map the port to Qman product code, prove that a product
database used SERIALIZABLE isolation, demonstrate crash durability, or supply
independent product-runner evidence.  Consequently every returned context is
permanently non-authorizing and receipt digests point only forward from the
mutation closure; they never enter the mutation or operation-result DAG.
"""

from __future__ import annotations

import base64
import binascii
import copy
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
import re
from types import MappingProxyType
from typing import Any, Final, Protocol

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
from .publication_mutation import (
    HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS,
    VerifiedHostSnapshotPublicationMutationContext,
    replay_host_snapshot_publication_mutation_closure,
)
from .trust import VerifiedTrustContext, _verify_ed25519


HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-publication-repository-receipt.schema.json"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_KIND: Final = (
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_TRANSACTION"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_QUERY_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-REPOSITORY-QUERY/V1\x00"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-REPOSITORY-RECEIPT/V1\x00"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-REPOSITORY-CONTEXT/V1\x00"
)

HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_ROLE_SIGNED_REPOSITORY_RECEIPT_VERIFICATION_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_REPOSITORY_RECEIPT_VALID_TARGET_PRODUCT_PORT_NOT_PROVEN"
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_STRUCTURALLY_COVERED_MUTATION_BLOCKERS: Final = (
    "TARGET_PRODUCT_REPOSITORY_TRANSACTION_PORT_REQUIRED",
    "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "TARGET_DURABLE_COMMIT_CONTEXT_AND_COMMIT_CLOCK_RECEIPT_REQUIRED",
)
_RETAINED_MUTATION_BLOCKERS: Final = tuple(
    blocker
    for blocker in (HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS)
    if blocker
    not in (HOST_SNAPSHOT_PUBLICATION_REPOSITORY_STRUCTURALLY_COVERED_MUTATION_BLOCKERS)
)
HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    *_RETAINED_MUTATION_BLOCKERS,
    "TARGET_PORT_GLOBAL_REPOSITORY_CODE_MAPPING_REQUIRED",
    "TARGET_SERIALIZABLE_FOUR_AUTHORITY_CAS_IMPLEMENTATION_REQUIRED",
    "TARGET_DURABLE_COMMIT_CLOCK_AND_CRASH_RECOVERY_EVIDENCE_REQUIRED",
    "TARGET_REPOSITORY_RECEIPT_NONCE_OWNERSHIP_AND_REPLAY_STORE_REQUIRED",
    "TARGET_REPOSITORY_RECEIPT_ENDPOINT_SESSION_BINDING_REQUIRED",
    "TARGET_QMAN_PRODUCT_BUILD_IDENTITY_EVIDENCE_REQUIRED",
    "TARGET_QMAN_PRODUCT_RUNNER_EXECUTION_EVIDENCE_REQUIRED",
)

_QUERY_SUBJECT_FIELDS: Final = frozenset(
    {
        "repositoryId",
        "transactionId",
        "operationId",
        "commandId",
        "requestHash",
        "operationRequestContextDigest",
        "decisionContextDigest",
        "mutationContextDigest",
        "verificationNonce",
        "targetRepositoryObjectFormat",
        "targetRepositoryCommit",
        "outcome",
        "commitIdOrNull",
        "repositoryTransactionCanonicalSha256",
        "requestedAt",
        "queryDigest",
    }
)
_RECEIPT_FIELDS: Final = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "receiptKind",
        "receiptId",
        "canonicalProfileId",
        "schemaRef",
        "schemaSha256",
        "queryDigest",
        "repositoryId",
        "transactionId",
        "operationId",
        "commandId",
        "requestHash",
        "operationRequestContextDigest",
        "decisionContextDigest",
        "mutationContextDigest",
        "verificationNonce",
        "targetRepositoryObjectFormat",
        "targetRepositoryCommit",
        "trustContextDigest",
        "trustBinding",
        "repositoryTransactionCanonicalSha256",
        "repositoryTransaction",
        "outcome",
        "commitIdOrNull",
        "committedAtOrNull",
        "commitClockBefore",
        "commitClockAfter",
        "mutationSetHashOrNull",
        "mutationsCanonicalSha256",
        "publicationMutationCount",
        "deviceRecordSetDigest",
        "resolvedAuthorityVectorHash",
        "commitRecordDigestOrNull",
        "snapshotPublicationCasResult",
        "artifactCanonicalSha256",
        "writeCounts",
        "requestedAt",
        "observedAt",
        "signedAt",
        "signerKeyId",
        "keyRingSequence",
        "algorithm",
        "receiptDigest",
        "signature",
    }
)
_TRUST_BINDING_FIELDS: Final = frozenset(
    {
        "rootSetId",
        "rootSetDigest",
        "rootSetCanonicalSha256",
        "keyRingId",
        "keyRingSequence",
        "keyRingDigest",
        "currentKeyRingCanonicalSha256",
        "trustAnchorAuthorityId",
        "trustAnchorVersion",
        "trustAnchorResourceVersion",
        "trustAnchorDigest",
        "trustAnchorCanonicalSha256",
        "trustFreshnessReceiptDigest",
        "trustFreshnessExpiresAt",
    }
)
_ARTIFACT_HASH_FIELDS: Final = frozenset(
    {
        "hostSnapshotAfter",
        "hostAuthorityAfter",
        "availabilityAuthorityAfterOrNull",
        "auditRecordOrNull",
        "outboxRecordOrNull",
        "commitRecordOrNull",
    }
)
_WRITE_COUNT_FIELDS: Final = frozenset(
    {
        "hostSnapshot",
        "deviceRecord",
        "hostAuthority",
        "availabilityAuthority",
        "publicationAuditRecord",
        "publicationOutboxRecord",
        "repositoryCommitRecord",
    }
)
_NONCE_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN: Final = re.compile(r"^\S(?:.*\S)?$")
_QUERY_MAX_BYTES: Final = 32 * 1024
_QUERY_MAX_NODES: Final = 256
_QUERY_MAX_DEPTH: Final = 8


@dataclass(frozen=True, slots=True)
class HostSnapshotPublicationRepositoryReceiptLimits:
    """Caller-tightenable resource and freshness ceilings."""

    max_receipt_bytes: int = 4 * 1024 * 1024
    max_repository_transaction_bytes: int = 512 * 1024
    max_json_nodes: int = 500_000
    max_json_depth: int = 64
    max_verification_horizon_seconds: int = 300


DEFAULT_HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_LIMITS = (
    HostSnapshotPublicationRepositoryReceiptLimits()
)


@dataclass(frozen=True, slots=True, init=False)
class HostSnapshotPublicationRepositoryReceiptQuery(FactoryVerified):
    """Factory-only nonce query exact-bound to one mutation transaction."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    repository_id: str
    transaction_id: str
    operation_id: str
    command_id: str
    request_hash: str
    operation_request_context_digest: str
    decision_context_digest: str
    mutation_context_digest: str
    verification_nonce: str
    target_repository_object_format: str
    target_repository_commit: str
    outcome: str
    commit_id_or_null: str | None
    repository_transaction_canonical_sha256: str
    requested_at: datetime
    query_digest: str


class HostSnapshotPublicationRepositoryReceiptPort(Protocol):
    """Product adapter boundary; a port implementation is not product proof."""

    def read_host_snapshot_publication_repository_receipt(
        self,
        *,
        query: HostSnapshotPublicationRepositoryReceiptQuery,
    ) -> bytes:
        """Return exact canonical receipt bytes, never an authorization bool."""


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationRepositoryContext(FactoryVerified):
    """Replayable component verification of one signed repository receipt."""

    limits: HostSnapshotPublicationRepositoryReceiptLimits
    trust: VerifiedTrustContext
    mutation: VerifiedHostSnapshotPublicationMutationContext
    query: HostSnapshotPublicationRepositoryReceiptQuery
    receipt: Mapping[str, Any]
    receipt_canonical_bytes: bytes
    receipt_id: str
    receipt_digest: str
    signer_key_id: str
    signer_principal_id: str
    requested_at: datetime
    observed_at: datetime
    signed_at: datetime
    verified_at: datetime
    repository_transaction_canonical_sha256: str
    outcome: str
    commit_id_or_null: str | None
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


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utc(value: datetime, path: str) -> datetime:
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None,
        "PUBLICATION_REPOSITORY_TIME_INVALID",
        path,
        "expected a timezone-aware datetime",
    )
    return value.astimezone(timezone.utc)


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "PUBLICATION_REPOSITORY_TIME_INVALID",
        path,
        "expected a TIMESTAMP-UTC-US-V1 string",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail(
            "PUBLICATION_REPOSITORY_TIME_INVALID",
            path,
            f"invalid TIMESTAMP-UTC-US-V1 value: {exc}",
        )
    return parsed.replace(tzinfo=timezone.utc)


def _canonical_nonce(value: Any, path: str) -> str:
    require(
        isinstance(value, str) and _NONCE_PATTERN.fullmatch(value) is not None,
        "PUBLICATION_REPOSITORY_QUERY_NONCE_INVALID",
        path,
        "expected a 16..64-byte canonical unpadded base64url nonce",
    )
    encoded = value.encode("ascii")
    padding = b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        fail(
            "PUBLICATION_REPOSITORY_QUERY_NONCE_INVALID",
            path,
            f"nonce is not valid unpadded base64url: {exc}",
        )
    require(
        16 <= len(decoded) <= 64
        and base64.urlsafe_b64encode(decoded).rstrip(b"=") == encoded,
        "PUBLICATION_REPOSITORY_QUERY_NONCE_INVALID",
        path,
        ("nonce must be the unique unpadded base64url encoding of 16..64 bytes"),
    )
    return value


def _closed_fields(
    value: Any,
    expected: frozenset[str],
    *,
    path: str,
    code: str = "PUBLICATION_REPOSITORY_RECEIPT_SHAPE_INVALID",
) -> Mapping[str, Any]:
    require(
        isinstance(value, Mapping),
        code,
        path,
        "expected a JSON object",
    )
    require(
        set(value) == expected,
        code,
        path,
        (
            "object does not have the exact closed field set; "
            f"missing={sorted(expected - set(value))!r}, "
            f"extra={sorted(set(value) - expected)!r}"
        ),
    )
    return value


def _checked_limits(
    value: HostSnapshotPublicationRepositoryReceiptLimits | None,
) -> HostSnapshotPublicationRepositoryReceiptLimits:
    limits = value or DEFAULT_HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_LIMITS
    require(
        isinstance(
            limits,
            HostSnapshotPublicationRepositoryReceiptLimits,
        ),
        "PUBLICATION_REPOSITORY_LIMIT_INVALID",
        "publicationRepository.limits",
        "expected HostSnapshotPublicationRepositoryReceiptLimits",
    )
    hard = DEFAULT_HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_LIMITS
    for descriptor in fields(HostSnapshotPublicationRepositoryReceiptLimits):
        actual = getattr(limits, descriptor.name)
        maximum = getattr(hard, descriptor.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= maximum,
            "PUBLICATION_REPOSITORY_LIMIT_INVALID",
            f"publicationRepository.limits.{descriptor.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {maximum}"
            ),
        )
    return limits


def _measure_json(
    value: Any,
    *,
    path: str,
    max_bytes: int,
    max_nodes: int,
    max_depth: int,
) -> tuple[int, int]:
    try:
        return measure_canonical_json(
            value,
            max_bytes=max_bytes,
            max_nodes=max_nodes,
            max_depth=max_depth,
        )
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_REPOSITORY_TOO_LARGE", path, str(exc))
    except (
        CanonicalizationError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        fail(
            "PUBLICATION_REPOSITORY_CANONICAL_BYTES_INVALID",
            path,
            f"cannot measure CANONICAL-JSON-V1 input: {exc}",
        )


def _reject_excessive_raw_depth(
    raw: bytes,
    *,
    maximum: int,
    path: str,
) -> None:
    """Reject parser-host-dependent nesting before constructing a JSON tree."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(
            "PUBLICATION_REPOSITORY_CANONICAL_BYTES_INVALID",
            path,
            f"input is not valid UTF-8: {exc}",
        )
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            require(
                depth <= maximum,
                "PUBLICATION_REPOSITORY_TOO_LARGE",
                path,
                "canonical JSON exceeds the configured depth limit",
            )
        elif character in "]}":
            depth = max(depth - 1, 0)


def _load_receipt(
    value: bytes,
    limits: HostSnapshotPublicationRepositoryReceiptLimits,
) -> tuple[dict[str, Any], bytes]:
    path = "publicationRepository.receipt"
    require(
        type(value) is bytes,
        "PUBLICATION_REPOSITORY_DOCUMENT_TYPE_INVALID",
        path,
        "expected exact canonical JSON bytes returned by the repository port",
    )
    raw = value
    require(
        0 < len(raw) <= limits.max_receipt_bytes,
        "PUBLICATION_REPOSITORY_TOO_LARGE",
        path,
        "receipt bytes exceed the closed limit",
    )
    _reject_excessive_raw_depth(
        raw,
        maximum=limits.max_json_depth,
        path=path,
    )
    try:
        loaded = load_canonical_json(raw)
    except (CanonicalizationError, RecursionError, ValueError) as exc:
        fail(
            "PUBLICATION_REPOSITORY_CANONICAL_BYTES_INVALID",
            path,
            str(exc),
        )
    _measure_json(
        loaded,
        path=path,
        max_bytes=limits.max_receipt_bytes,
        max_nodes=limits.max_json_nodes,
        max_depth=limits.max_json_depth,
    )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_REPOSITORY_DOCUMENT_TYPE_INVALID",
        path,
        "receipt must be a JSON object",
    )
    return loaded, raw


def _load_query_document(value: bytes) -> dict[str, Any]:
    require(
        isinstance(value, bytes) and len(value) <= _QUERY_MAX_BYTES,
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query.canonicalBytes",
        "query must retain bounded exact canonical bytes",
    )
    _reject_excessive_raw_depth(
        value,
        maximum=_QUERY_MAX_DEPTH,
        path="publicationRepository.query.canonicalBytes",
    )
    try:
        loaded = load_canonical_json(value)
    except (CanonicalizationError, RecursionError, ValueError) as exc:
        fail(
            "PUBLICATION_REPOSITORY_QUERY_INVALID",
            "publicationRepository.query.canonicalBytes",
            str(exc),
        )
    _measure_json(
        loaded,
        path="publicationRepository.query",
        max_bytes=_QUERY_MAX_BYTES,
        max_nodes=_QUERY_MAX_NODES,
        max_depth=_QUERY_MAX_DEPTH,
    )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query",
        "query subject must be a JSON object",
    )
    return loaded


def _query_digest(document: Mapping[str, Any]) -> str:
    projection = copy.deepcopy(dict(document))
    projection["queryDigest"] = None
    return sha256_digest(
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_QUERY_DOMAIN
        + canonical_json_bytes(projection)
    )


def _construct_query(
    document: Mapping[str, Any],
    canonical_bytes: bytes,
) -> HostSnapshotPublicationRepositoryReceiptQuery:
    _closed_fields(
        document,
        _QUERY_SUBJECT_FIELDS,
        path="publicationRepository.query",
        code="PUBLICATION_REPOSITORY_QUERY_INVALID",
    )
    nonce = _canonical_nonce(
        document["verificationNonce"],
        "publicationRepository.query.verificationNonce",
    )
    for name in (
        "requestHash",
        "operationRequestContextDigest",
        "decisionContextDigest",
        "mutationContextDigest",
        "repositoryTransactionCanonicalSha256",
        "queryDigest",
    ):
        require(
            isinstance(document[name], str)
            and _DIGEST_PATTERN.fullmatch(document[name]) is not None,
            "PUBLICATION_REPOSITORY_QUERY_INVALID",
            f"publicationRepository.query.{name}",
            "expected a lowercase SHA-256 digest",
        )
    require(
        document["queryDigest"] == _query_digest(document),
        "PUBLICATION_REPOSITORY_QUERY_DIGEST_INVALID",
        "publicationRepository.query.queryDigest",
        "query digest does not match the closed null projection",
    )
    for name in (
        "repositoryId",
        "transactionId",
        "operationId",
        "commandId",
    ):
        require(
            isinstance(document[name], str)
            and 1 <= len(document[name]) <= 512
            and _ID_PATTERN.fullmatch(document[name]) is not None,
            "PUBLICATION_REPOSITORY_QUERY_INVALID",
            f"publicationRepository.query.{name}",
            "expected a closed non-whitespace identifier",
        )
    require(
        document["operationId"] == "OP-CAPTURE-HOST-SNAPSHOT",
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query.operationId",
        "only OP-CAPTURE-HOST-SNAPSHOT is supported",
    )
    target_format = document["targetRepositoryObjectFormat"]
    target_commit = document["targetRepositoryCommit"]
    expected_commit_length = (
        40 if target_format == "SHA1" else 64 if target_format == "SHA256" else 0
    )
    require(
        isinstance(target_format, str)
        and target_format in {"SHA1", "SHA256"}
        and isinstance(target_commit, str)
        and len(target_commit) == expected_commit_length
        and all(character in "0123456789abcdef" for character in target_commit),
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query.targetRepositoryCommit",
        "target commit does not match its lowercase SHA1/SHA256 object format",
    )
    outcome = document["outcome"]
    require(
        isinstance(outcome, str)
        and outcome in {"COMMITTED", "NO_CHANGE"}
        and (
            (
                outcome == "COMMITTED"
                and isinstance(document["commitIdOrNull"], str)
                and bool(document["commitIdOrNull"])
            )
            or (outcome == "NO_CHANGE" and document["commitIdOrNull"] is None)
        ),
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query.outcome",
        "outcome and commitIdOrNull branch are inconsistent",
    )
    requested_at = _timestamp(
        document["requestedAt"],
        "publicationRepository.query.requestedAt",
    )
    return HostSnapshotPublicationRepositoryReceiptQuery._construct(
        document=_freeze_json(copy.deepcopy(dict(document))),
        canonical_bytes=canonical_bytes,
        repository_id=document["repositoryId"],
        transaction_id=document["transactionId"],
        operation_id=document["operationId"],
        command_id=document["commandId"],
        request_hash=document["requestHash"],
        operation_request_context_digest=document["operationRequestContextDigest"],
        decision_context_digest=document["decisionContextDigest"],
        mutation_context_digest=document["mutationContextDigest"],
        verification_nonce=nonce,
        target_repository_object_format=document["targetRepositoryObjectFormat"],
        target_repository_commit=document["targetRepositoryCommit"],
        outcome=document["outcome"],
        commit_id_or_null=document["commitIdOrNull"],
        repository_transaction_canonical_sha256=document[
            "repositoryTransactionCanonicalSha256"
        ],
        requested_at=requested_at,
        query_digest=document["queryDigest"],
    )


def prepare_host_snapshot_publication_repository_receipt_query(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    *,
    verification_nonce: str,
    requested_at: datetime,
) -> HostSnapshotPublicationRepositoryReceiptQuery:
    """Prepare a fresh query from one replayed mutation closure.

    The caller must generate and durably own ``verification_nonce`` before
    sending the query to an independently configured product endpoint.
    """

    require_factory_verified(
        mutation,
        VerifiedHostSnapshotPublicationMutationContext,
        code="PUBLICATION_REPOSITORY_MUTATION_INVALID",
        path="publicationRepository.mutation",
        message=(
            "mutation must come from verify_host_snapshot_publication_mutation_closure"
        ),
    )
    mutation = replay_host_snapshot_publication_mutation_closure(mutation)
    nonce = _canonical_nonce(
        verification_nonce,
        "publicationRepository.query.verificationNonce",
    )
    request_time = _utc(
        requested_at,
        "publicationRepository.query.requestedAt",
    )
    transaction = mutation.repository_transaction
    linearization_text = (
        transaction["committedAtOrNull"]
        if transaction["outcome"] == "COMMITTED"
        else transaction["beganAt"]
    )
    assert isinstance(linearization_text, str)
    linearization_time = _timestamp(
        linearization_text,
        "publicationRepository.mutation.repositoryTransaction",
    )
    require(
        linearization_time <= request_time,
        "PUBLICATION_REPOSITORY_QUERY_TIME_INVALID",
        "publicationRepository.query.requestedAt",
        "repository receipt query predates its transaction outcome",
    )
    operation_request = mutation.operation_request
    document = {
        "repositoryId": transaction["repositoryId"],
        "transactionId": transaction["transactionId"],
        "operationId": transaction["operationId"],
        "commandId": transaction["commandId"],
        "requestHash": transaction["requestHash"],
        "operationRequestContextDigest": transaction["operationRequestContextDigest"],
        "decisionContextDigest": transaction["decisionContextDigest"],
        "mutationContextDigest": mutation.context_digest,
        "verificationNonce": nonce,
        "targetRepositoryObjectFormat": (
            operation_request.target_repository_object_format
        ),
        "targetRepositoryCommit": (operation_request.target_repository_commit),
        "outcome": transaction["outcome"],
        "commitIdOrNull": transaction["commitIdOrNull"],
        "repositoryTransactionCanonicalSha256": sha256_digest(
            mutation.repository_transaction_canonical_bytes
        ),
        "requestedAt": _format_timestamp(request_time),
        "queryDigest": None,
    }
    document["queryDigest"] = _query_digest(document)
    raw = canonical_json_bytes(document)
    require(
        len(raw) <= _QUERY_MAX_BYTES,
        "PUBLICATION_REPOSITORY_QUERY_INVALID",
        "publicationRepository.query",
        "prepared query exceeds the closed byte limit",
    )
    return _construct_query(document, raw)


def replay_host_snapshot_publication_repository_receipt_query(
    query: HostSnapshotPublicationRepositoryReceiptQuery,
) -> HostSnapshotPublicationRepositoryReceiptQuery:
    """Replay a factory query from its retained exact canonical bytes."""

    require_factory_verified(
        query,
        HostSnapshotPublicationRepositoryReceiptQuery,
        code="PUBLICATION_REPOSITORY_QUERY_INVALID",
        path="publicationRepository.query",
        message=(
            "query must come from "
            "prepare_host_snapshot_publication_repository_receipt_query"
        ),
    )
    document = _load_query_document(query.canonical_bytes)
    replayed = _construct_query(document, query.canonical_bytes)
    require(
        replayed == query,
        "PUBLICATION_REPOSITORY_QUERY_REPLAY_MISMATCH",
        "publicationRepository.query",
        "query claims differ when replayed from retained exact bytes",
    )
    return replayed


def _trust_binding(trust: VerifiedTrustContext) -> dict[str, Any]:
    return {
        "rootSetId": trust.root_set_id,
        "rootSetDigest": trust.root_set_digest,
        "rootSetCanonicalSha256": trust.root_set_canonical_sha256,
        "keyRingId": trust.key_ring_id,
        "keyRingSequence": trust.key_ring_sequence,
        "keyRingDigest": trust.key_ring_digest,
        "currentKeyRingCanonicalSha256": (trust.current_key_ring_canonical_sha256),
        "trustAnchorAuthorityId": trust.trust_anchor_authority_id,
        "trustAnchorVersion": trust.trust_anchor_version,
        "trustAnchorResourceVersion": (trust.trust_anchor_resource_version),
        "trustAnchorDigest": trust.trust_anchor_digest,
        "trustAnchorCanonicalSha256": (trust.trust_anchor_canonical_sha256),
        "trustFreshnessReceiptDigest": trust.freshness_receipt_digest,
        "trustFreshnessExpiresAt": _format_timestamp(trust.freshness_expires_at),
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


def _verify_trust_binding(
    trust: VerifiedTrustContext,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    receipt: Mapping[str, Any],
) -> None:
    source_trust = mutation.rollback.trust
    require(
        source_trust.context_digest == trust.context_digest
        and _trust_binding(source_trust) == _trust_binding(trust),
        "PUBLICATION_REPOSITORY_TRUST_CONTEXT_MISMATCH",
        "publicationRepository.trust",
        (
            "receipt trust must exact-match the trust context consumed by "
            "the mutation rollback closure"
        ),
    )
    expected_binding = _trust_binding(trust)
    actual_binding = _closed_fields(
        receipt["trustBinding"],
        _TRUST_BINDING_FIELDS,
        path="publicationRepository.receipt.trustBinding",
    )
    require(
        dict(actual_binding) == expected_binding
        and receipt["trustContextDigest"] == trust.context_digest
        and receipt["keyRingSequence"] == trust.key_ring_sequence,
        "PUBLICATION_REPOSITORY_TRUST_BINDING_MISMATCH",
        "publicationRepository.receipt.trustBinding",
        "receipt does not exact-project the verified trust context",
    )

    body = mutation.operation_request.request_payload["body"]
    expected_refs = {
        "trustRootSet": _trust_document_ref(
            document_kind="TRUST_ROOT_SET",
            document_id=trust.root_set_id,
            document_version=1,
            schema_ref="contracts/directpath-trust-root-set.schema.json",
            canonical_sha256=trust.root_set_canonical_sha256,
        ),
        "trustedKeyRing": _trust_document_ref(
            document_kind="TRUST_KEY_RING",
            document_id=trust.key_ring_id,
            document_version=trust.key_ring_sequence,
            schema_ref="contracts/directpath-trust-key-ring.schema.json",
            canonical_sha256=trust.current_key_ring_canonical_sha256,
        ),
        "rollbackAnchor": _trust_document_ref(
            document_kind="TRUST_ROLLBACK_ANCHOR",
            document_id=trust.trust_anchor_digest,
            document_version=trust.trust_anchor_version,
            schema_ref=("contracts/directpath-trust-rollback-anchor.schema.json"),
            canonical_sha256=trust.trust_anchor_canonical_sha256,
        ),
    }
    for name, expected in expected_refs.items():
        require(
            body.get(name) == expected,
            "PUBLICATION_REPOSITORY_OPERATION_TRUST_MISMATCH",
            f"publicationRepository.mutation.operationRequest.body.{name}",
            (
                "operation request trust reference does not exact-match "
                "the receipt verifier trust context"
            ),
        )


def _expected_artifact_hashes(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> dict[str, Any]:
    return {
        "hostSnapshotAfter": sha256_digest(
            mutation.rollback.host_snapshot_after_artifact_canonical_bytes
        ),
        "hostAuthorityAfter": sha256_digest(
            mutation.rollback.host_authority_after_artifact_canonical_bytes
        ),
        "availabilityAuthorityAfterOrNull": (
            None
            if (
                mutation.availability_authority_after_artifact_canonical_bytes_or_null
                is None
            )
            else sha256_digest(
                mutation.availability_authority_after_artifact_canonical_bytes_or_null
            )
        ),
        "auditRecordOrNull": (
            None
            if mutation.audit_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.audit_record_artifact_canonical_bytes_or_null)
        ),
        "outboxRecordOrNull": (
            None
            if mutation.outbox_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.outbox_record_artifact_canonical_bytes_or_null)
        ),
        "commitRecordOrNull": (
            None
            if mutation.commit_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.commit_record_artifact_canonical_bytes_or_null)
        ),
    }


def _expected_write_counts(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> dict[str, int]:
    if mutation.repository_transaction["outcome"] == "NO_CHANGE":
        return {name: 0 for name in _WRITE_COUNT_FIELDS}
    return {
        "hostSnapshot": 1,
        "deviceRecord": len(mutation.decision.persisted_device_records),
        "hostAuthority": 1,
        "availabilityAuthority": 1,
        "publicationAuditRecord": 1,
        "publicationOutboxRecord": 1,
        "repositoryCommitRecord": 1,
    }


def _verify_query_mutation_binding(
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> None:
    transaction = mutation.repository_transaction
    request = mutation.operation_request
    expected = {
        "repository_id": transaction["repositoryId"],
        "transaction_id": transaction["transactionId"],
        "operation_id": transaction["operationId"],
        "command_id": transaction["commandId"],
        "request_hash": transaction["requestHash"],
        "operation_request_context_digest": transaction[
            "operationRequestContextDigest"
        ],
        "decision_context_digest": transaction["decisionContextDigest"],
        "mutation_context_digest": mutation.context_digest,
        "verification_nonce": query.verification_nonce,
        "target_repository_object_format": (request.target_repository_object_format),
        "target_repository_commit": request.target_repository_commit,
        "outcome": transaction["outcome"],
        "commit_id_or_null": transaction["commitIdOrNull"],
        "repository_transaction_canonical_sha256": sha256_digest(
            mutation.repository_transaction_canonical_bytes
        ),
    }
    for name, expected_value in expected.items():
        require(
            getattr(query, name) == expected_value,
            "PUBLICATION_REPOSITORY_QUERY_BINDING_MISMATCH",
            f"publicationRepository.query.{name}",
            "query does not exact-bind the replayed mutation transaction",
        )
    linearization_text = (
        transaction["committedAtOrNull"]
        if transaction["outcome"] == "COMMITTED"
        else transaction["beganAt"]
    )
    assert isinstance(linearization_text, str)
    require(
        _timestamp(
            linearization_text,
            "publicationRepository.mutation.repositoryTransaction",
        )
        <= query.requested_at,
        "PUBLICATION_REPOSITORY_QUERY_TIME_INVALID",
        "publicationRepository.query.requestedAt",
        "query predates the transaction outcome it asks to observe",
    )


def _verify_product_blocker_transition(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> None:
    """Retain upstream blockers and replace only this structural slice."""

    source = tuple(mutation.product_evidence_blockers)
    baseline = tuple(HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS)
    covered = (
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_STRUCTURALLY_COVERED_MUTATION_BLOCKERS
    )
    require(
        mutation.product_authorized is False
        and source == baseline
        and len(covered) == len(set(covered))
        and set(covered).issubset(baseline),
        "PUBLICATION_REPOSITORY_BLOCKER_TRANSITION_INVALID",
        "publicationRepository.mutation.productEvidenceBlockers",
        (
            "mutation blockers are not the exact replayed baseline for "
            "repository-receipt transition"
        ),
    )
    retained = tuple(item for item in baseline if item not in covered)
    require(
        retained == _RETAINED_MUTATION_BLOCKERS
        and (
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS[
                : len(retained)
            ]
            == retained
        ),
        "PUBLICATION_REPOSITORY_BLOCKER_TRANSITION_INVALID",
        "publicationRepository.productEvidenceBlockers",
        (
            "repository context did not retain every auth/result/"
            "visibility/outbox blocker in baseline order"
        ),
    )


def _verify_receipt_projection(
    schemas: ContractSchemas,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    receipt: Mapping[str, Any],
    receipt_schema_sha256: str,
    limits: HostSnapshotPublicationRepositoryReceiptLimits,
) -> None:
    transaction = mutation.repository_transaction
    transaction_raw = canonical_json_bytes(receipt["repositoryTransaction"])
    require(
        len(transaction_raw) <= limits.max_repository_transaction_bytes,
        "PUBLICATION_REPOSITORY_TOO_LARGE",
        "publicationRepository.receipt.repositoryTransaction",
        "embedded repository transaction exceeds the closed byte limit",
    )
    expected_transaction_sha = sha256_digest(
        mutation.repository_transaction_canonical_bytes
    )
    require(
        transaction_raw == mutation.repository_transaction_canonical_bytes
        and receipt["repositoryTransactionCanonicalSha256"] == expected_transaction_sha,
        "PUBLICATION_REPOSITORY_TRANSACTION_BYTES_MISMATCH",
        "publicationRepository.receipt.repositoryTransaction",
        (
            "embedded transaction bytes/hash do not exact-match the "
            "verified mutation transaction"
        ),
    )
    expected_top_level = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT",
        "schemaVersion": 1,
        "receiptKind": (HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_KIND),
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "schemaRef": (HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF),
        "schemaSha256": receipt_schema_sha256,
        "queryDigest": query.query_digest,
        "repositoryId": transaction["repositoryId"],
        "transactionId": transaction["transactionId"],
        "operationId": transaction["operationId"],
        "commandId": transaction["commandId"],
        "requestHash": transaction["requestHash"],
        "operationRequestContextDigest": transaction["operationRequestContextDigest"],
        "decisionContextDigest": transaction["decisionContextDigest"],
        "mutationContextDigest": mutation.context_digest,
        "verificationNonce": query.verification_nonce,
        "targetRepositoryObjectFormat": (query.target_repository_object_format),
        "targetRepositoryCommit": query.target_repository_commit,
        "repositoryTransactionCanonicalSha256": expected_transaction_sha,
        "outcome": transaction["outcome"],
        "commitIdOrNull": transaction["commitIdOrNull"],
        "committedAtOrNull": transaction["committedAtOrNull"],
        "commitClockBefore": transaction["commitClockBefore"],
        "commitClockAfter": transaction["commitClockAfter"],
        "mutationSetHashOrNull": mutation.mutation_set_hash_or_null,
        "mutationsCanonicalSha256": sha256_digest(mutation.mutations_canonical_bytes),
        "publicationMutationCount": mutation.publication_mutation_count,
        "deviceRecordSetDigest": mutation.device_record_set_digest,
        "resolvedAuthorityVectorHash": (mutation.resolved_authority_vector_hash),
        "commitRecordDigestOrNull": (mutation.commit_record_digest_or_null),
        "snapshotPublicationCasResult": _thaw_json(
            mutation.snapshot_publication_cas_result
        ),
        "requestedAt": _format_timestamp(query.requested_at),
    }
    for name, expected in expected_top_level.items():
        require(
            receipt[name] == expected,
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
            f"publicationRepository.receipt.{name}",
            "receipt field does not exact-project the verified mutation/query",
        )

    artifact_hashes = _closed_fields(
        receipt["artifactCanonicalSha256"],
        _ARTIFACT_HASH_FIELDS,
        path="publicationRepository.receipt.artifactCanonicalSha256",
    )
    require(
        dict(artifact_hashes) == _expected_artifact_hashes(mutation),
        "PUBLICATION_REPOSITORY_ARTIFACT_HASH_MISMATCH",
        "publicationRepository.receipt.artifactCanonicalSha256",
        "receipt artifact hashes do not exact-bind retained canonical wrappers",
    )
    write_counts = _closed_fields(
        receipt["writeCounts"],
        _WRITE_COUNT_FIELDS,
        path="publicationRepository.receipt.writeCounts",
    )
    expected_counts = _expected_write_counts(mutation)
    require(
        dict(write_counts) == expected_counts
        and sum(expected_counts.values()) == mutation.publication_mutation_count,
        "PUBLICATION_REPOSITORY_WRITE_COUNT_MISMATCH",
        "publicationRepository.receipt.writeCounts",
        "receipt does not retain the exact seven-category mutation counts",
    )


def _verify_receipt_times(
    trust: VerifiedTrustContext,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    receipt: Mapping[str, Any],
    verified_at: datetime,
    limits: HostSnapshotPublicationRepositoryReceiptLimits,
) -> tuple[datetime, datetime]:
    requested_at = _timestamp(
        receipt["requestedAt"],
        "publicationRepository.receipt.requestedAt",
    )
    observed_at = _timestamp(
        receipt["observedAt"],
        "publicationRepository.receipt.observedAt",
    )
    signed_at = _timestamp(
        receipt["signedAt"],
        "publicationRepository.receipt.signedAt",
    )
    transaction = mutation.repository_transaction
    lower_text = (
        transaction["committedAtOrNull"]
        if transaction["outcome"] == "COMMITTED"
        else transaction["beganAt"]
    )
    assert isinstance(lower_text, str)
    lower_bound = _timestamp(
        lower_text,
        "publicationRepository.mutation.repositoryTransaction",
    )
    horizon = timedelta(seconds=limits.max_verification_horizon_seconds)
    require(
        requested_at == query.requested_at
        and lower_bound <= requested_at
        and requested_at <= observed_at <= signed_at <= verified_at
        and verified_at - requested_at <= horizon,
        "PUBLICATION_REPOSITORY_RECEIPT_TIME_INVALID",
        "publicationRepository.receipt",
        (
            "expected transaction <= requestedAt <= observedAt <= "
            "signedAt <= verifier time within the closed horizon"
        ),
    )
    require(
        trust.verified_at <= requested_at and signed_at <= trust.freshness_expires_at,
        "PUBLICATION_REPOSITORY_TRUST_STALE",
        "publicationRepository.receipt.signedAt",
        "query/signature are outside the verified trust freshness window",
    )
    return observed_at, signed_at


def _verify_receipt_signature(
    trust: VerifiedTrustContext,
    receipt: Mapping[str, Any],
    *,
    signed_at: datetime,
    verified_at: datetime,
) -> tuple[str, str]:
    signer_key_id = receipt["signerKeyId"]
    require(
        receipt["algorithm"] == "Ed25519"
        and receipt["keyRingSequence"] == trust.key_ring_sequence,
        "PUBLICATION_REPOSITORY_SIGNER_INVALID",
        "publicationRepository.receipt",
        "receipt must use current-ring Ed25519",
    )
    signer_at_signed = trust.authorized_key(
        signer_key_id,
        required_role="CONTROL_REPOSITORY_EVIDENCE",
        at=signed_at,
    )
    signer_at_verified = trust.authorized_key(
        signer_key_id,
        required_role="CONTROL_REPOSITORY_EVIDENCE",
        at=verified_at,
    )
    require(
        signer_at_signed.key_id == signer_at_verified.key_id
        and signer_at_signed.principal_id == signer_at_verified.principal_id
        and signer_at_signed.public_key_base64url
        == signer_at_verified.public_key_base64url,
        "PUBLICATION_REPOSITORY_SIGNER_INVALID",
        "publicationRepository.receipt.signerKeyId",
        "receipt signer identity changed across the verification interval",
    )

    projection = copy.deepcopy(dict(receipt))
    projection["receiptDigest"] = None
    projection["signature"] = None
    projection_raw = canonical_json_bytes(projection)
    expected_digest = sha256_digest(projection_raw)
    require(
        receipt["receiptDigest"] == expected_digest,
        "PUBLICATION_REPOSITORY_RECEIPT_DIGEST_INVALID",
        "publicationRepository.receipt.receiptDigest",
        ("receiptDigest does not equal the SIGNED-ENVELOPE-V1 null/null projection"),
    )
    _verify_ed25519(
        signer_at_verified.public_key_base64url,
        receipt["signature"],
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_DOMAIN + projection_raw,
        "publicationRepository.receipt",
    )
    return signer_key_id, signer_at_verified.principal_id


def _verify_no_repository_receipt_back_references(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    receipt: Mapping[str, Any],
) -> None:
    """Reject post-mutation receipt material in every retained final row.

    The query and receipt are necessarily constructed after the repository
    mutation.  Searching the exact retained bytes makes that direction
    executable rather than relying only on a prose DAG rule or on the
    practical difficulty of solving a digest fixed point.
    """

    forbidden = (
        query.query_digest.encode("ascii"),
        receipt["receiptDigest"].encode("ascii"),
        receipt["signature"].encode("ascii"),
    )
    retained_bytes: list[tuple[str, bytes]] = [
        (
            "repositoryTransaction",
            mutation.repository_transaction_canonical_bytes,
        ),
        ("mutations", mutation.mutations_canonical_bytes),
        (
            "hostSnapshotAfter",
            mutation.rollback.host_snapshot_after_artifact_canonical_bytes,
        ),
        (
            "hostAuthorityAfter",
            mutation.rollback.host_authority_after_artifact_canonical_bytes,
        ),
    ]
    optional_artifacts = (
        (
            "availabilityAuthorityAfter",
            (mutation.availability_authority_after_artifact_canonical_bytes_or_null),
        ),
        (
            "auditRecord",
            mutation.audit_record_artifact_canonical_bytes_or_null,
        ),
        (
            "outboxRecord",
            mutation.outbox_record_artifact_canonical_bytes_or_null,
        ),
        (
            "commitRecord",
            mutation.commit_record_artifact_canonical_bytes_or_null,
        ),
    )
    retained_bytes.extend(
        (name, value) for name, value in optional_artifacts if value is not None
    )
    retained_bytes.extend(
        (
            f"deviceRecords[{index}]",
            record.canonical_bytes,
        )
        for index, record in enumerate(mutation.decision.persisted_device_records)
    )
    for name, raw in retained_bytes:
        require(
            not any(value in raw for value in forbidden),
            "PUBLICATION_REPOSITORY_DIGEST_BACK_REFERENCE",
            f"publicationRepository.mutation.{name}",
            (
                "a preexisting transaction/mutation/final-row byte string "
                "contains the later query digest, receipt digest, or "
                "receipt signature"
            ),
        )


def _context_receipt(
    trust: VerifiedTrustContext,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    receipt: Mapping[str, Any],
    *,
    signer_principal_id: str,
    verified_at: datetime,
) -> tuple[dict[str, Any], bytes, str]:
    context = {
        "subjectType": ("VERIFIED_HOST_SNAPSHOT_PUBLICATION_REPOSITORY_CONTEXT"),
        "schemaVersion": 1,
        "queryDigest": query.query_digest,
        "repositoryReceiptDigest": receipt["receiptDigest"],
        "repositoryReceiptCanonicalSha256": sha256_digest(
            canonical_json_bytes(receipt)
        ),
        "trustContextDigest": trust.context_digest,
        "mutationContextDigest": mutation.context_digest,
        "repositoryId": query.repository_id,
        "transactionId": query.transaction_id,
        "outcome": query.outcome,
        "commitIdOrNull": query.commit_id_or_null,
        "targetRepositoryObjectFormat": (query.target_repository_object_format),
        "targetRepositoryCommit": query.target_repository_commit,
        "signerKeyId": receipt["signerKeyId"],
        "signerPrincipalId": signer_principal_id,
        "verifiedAt": _format_timestamp(verified_at),
        "authorityBoundary": (HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    digest = sha256_digest(
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_CONTEXT_DOMAIN
        + canonical_json_bytes(context)
    )
    context["contextDigest"] = digest
    raw = canonical_json_bytes(context)
    return context, raw, digest


def verify_host_snapshot_publication_repository_receipt(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    *,
    query: HostSnapshotPublicationRepositoryReceiptQuery,
    receipt: bytes,
    verified_at: datetime,
    limits: (HostSnapshotPublicationRepositoryReceiptLimits | None) = None,
) -> VerifiedHostSnapshotPublicationRepositoryContext:
    """Verify a fresh role-signed repository receipt without product promotion."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_REPOSITORY_INPUT_INVALID",
        "publicationRepository.schemas",
        "expected ContractSchemas",
    )
    checked_limits = _checked_limits(limits)

    # The complete untrusted receipt receives byte/node/depth/canonical gates
    # before any expensive upstream context replay.
    document, receipt_raw = _load_receipt(receipt, checked_limits)
    _closed_fields(
        document,
        _RECEIPT_FIELDS,
        path="publicationRepository.receipt",
    )
    schemas.validate_ref(
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF,
        document,
        "publicationRepository.receipt",
    )
    receipt_schema_sha256 = schemas.digest_for_ref(
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF,
        path="publicationRepository.receipt.schemaSha256",
    )

    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="PUBLICATION_REPOSITORY_TRUST_INVALID",
        path="publicationRepository.trust",
        message="trust must come from verify_trust_context",
    )
    require_factory_verified(
        mutation,
        VerifiedHostSnapshotPublicationMutationContext,
        code="PUBLICATION_REPOSITORY_MUTATION_INVALID",
        path="publicationRepository.mutation",
        message=(
            "mutation must come from verify_host_snapshot_publication_mutation_closure"
        ),
    )
    require_factory_verified(
        query,
        HostSnapshotPublicationRepositoryReceiptQuery,
        code="PUBLICATION_REPOSITORY_QUERY_INVALID",
        path="publicationRepository.query",
        message=(
            "query must come from "
            "prepare_host_snapshot_publication_repository_receipt_query"
        ),
    )
    verifier_time = _utc(
        verified_at,
        "publicationRepository.verifiedAt",
    )
    mutation = replay_host_snapshot_publication_mutation_closure(mutation)
    query = replay_host_snapshot_publication_repository_receipt_query(query)
    require(
        mutation._schemas is schemas,
        "PUBLICATION_REPOSITORY_SCHEMA_IDENTITY_MISMATCH",
        "publicationRepository.schemas",
        "mutation closure uses a different ContractSchemas instance",
    )
    _verify_product_blocker_transition(mutation)
    _verify_query_mutation_binding(query, mutation)
    _verify_trust_binding(trust, mutation, document)
    _verify_receipt_projection(
        schemas,
        mutation,
        query,
        document,
        receipt_schema_sha256,
        checked_limits,
    )
    observed_at, signed_at = _verify_receipt_times(
        trust,
        mutation,
        query,
        document,
        verifier_time,
        checked_limits,
    )
    signer_key_id, signer_principal_id = _verify_receipt_signature(
        trust,
        document,
        signed_at=signed_at,
        verified_at=verifier_time,
    )
    _verify_no_repository_receipt_back_references(
        mutation,
        query,
        document,
    )
    context_receipt, context_raw, context_digest = _context_receipt(
        trust,
        mutation,
        query,
        document,
        signer_principal_id=signer_principal_id,
        verified_at=verifier_time,
    )
    return VerifiedHostSnapshotPublicationRepositoryContext._construct(
        limits=checked_limits,
        trust=trust,
        mutation=mutation,
        query=query,
        receipt=_freeze_json(copy.deepcopy(document)),
        receipt_canonical_bytes=receipt_raw,
        receipt_id=document["receiptId"],
        receipt_digest=document["receiptDigest"],
        signer_key_id=signer_key_id,
        signer_principal_id=signer_principal_id,
        requested_at=query.requested_at,
        observed_at=observed_at,
        signed_at=signed_at,
        verified_at=verifier_time,
        repository_transaction_canonical_sha256=document[
            "repositoryTransactionCanonicalSha256"
        ],
        outcome=document["outcome"],
        commit_id_or_null=document["commitIdOrNull"],
        context_receipt=_freeze_json(context_receipt),
        context_receipt_canonical_bytes=context_raw,
        context_digest=context_digest,
        authority_boundary=(HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_verified_host_snapshot_publication_repository_context(
    context: VerifiedHostSnapshotPublicationRepositoryContext,
) -> VerifiedHostSnapshotPublicationRepositoryContext:
    """Replay one context from only its retained exact verifier inputs."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationRepositoryContext,
        code="PUBLICATION_REPOSITORY_CONTEXT_INVALID",
        path="publicationRepository.context",
        message=(
            "context must come from verify_host_snapshot_publication_repository_receipt"
        ),
    )
    replayed = verify_host_snapshot_publication_repository_receipt(
        context._schemas,
        context.trust,
        context.mutation,
        query=context.query,
        receipt=context.receipt_canonical_bytes,
        verified_at=context.verified_at,
        limits=context.limits,
    )
    require(
        replayed == context
        and replayed._schemas is context._schemas
        and replayed.receipt_canonical_bytes == context.receipt_canonical_bytes
        and replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes,
        "PUBLICATION_REPOSITORY_CONTEXT_REPLAY_MISMATCH",
        "publicationRepository.context",
        ("repository context claims differ when replayed from retained exact inputs"),
    )
    return replayed


__all__ = [
    "DEFAULT_HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_LIMITS",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_CONTEXT_DOMAIN",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_QUERY_DOMAIN",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_DOMAIN",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_KIND",
    "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF",
    ("HOST_SNAPSHOT_PUBLICATION_REPOSITORY_STRUCTURALLY_COVERED_MUTATION_BLOCKERS"),
    "HostSnapshotPublicationRepositoryReceiptLimits",
    "HostSnapshotPublicationRepositoryReceiptPort",
    "HostSnapshotPublicationRepositoryReceiptQuery",
    "VerifiedHostSnapshotPublicationRepositoryContext",
    "prepare_host_snapshot_publication_repository_receipt_query",
    "replay_host_snapshot_publication_repository_receipt_query",
    "replay_verified_host_snapshot_publication_repository_context",
    "verify_host_snapshot_publication_repository_receipt",
]
