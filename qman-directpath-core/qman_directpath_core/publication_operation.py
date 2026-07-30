"""Portable HostSnapshot publication operation-envelope verification.

The request verifier in this module closes the detached payload, schema,
canonical-byte, request-hash, deployment-build, correlation, and deadline
bindings for ``OP-CAPTURE-HOST-SNAPSHOT``.  It deliberately performs no
transport authentication, idempotency claim, repository read, or mutation.
The publication mutation verifier consumes this factory-only context and owns
the exact projection from the request body/authority vector to its retained
publication read set.  The result verifier then closes the successful detached
result envelope/payload over that replayed mutation without feeding result
bytes or result hashes back into the repository commit DAG.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

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
from .trust import JsonDocument

if TYPE_CHECKING:
    from .publication_mutation import (
        VerifiedHostSnapshotPublicationMutationContext,
    )


CAPTURE_HOST_SNAPSHOT_REQUEST_ENVELOPE_SCHEMA_REF: Final = (
    "contracts/directpath-operation-envelope.schema.json#/$defs/requestEnvelope"
)
CAPTURE_HOST_SNAPSHOT_REQUEST_PAYLOAD_SCHEMA_REF: Final = (
    "contracts/directpath-operation-payload.schema.json"
    "#/$defs/profile_OP_CAPTURE_HOST_SNAPSHOT_REQUEST"
)
CAPTURE_HOST_SNAPSHOT_RESULT_ENVELOPE_SCHEMA_REF: Final = (
    "contracts/directpath-operation-envelope.schema.json#/$defs/resultEnvelope"
)
CAPTURE_HOST_SNAPSHOT_RESULT_PAYLOAD_SCHEMA_REF: Final = (
    "contracts/directpath-operation-payload.schema.json"
    "#/$defs/profile_OP_CAPTURE_HOST_SNAPSHOT_RESULT"
)
OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF: Final = (
    "contracts/directpath-operation-payload.schema.json"
)
HOST_SNAPSHOT_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-portable-hash-subjects.schema.json"
    "#/$defs/hostSnapshot"
)
ROLLBACK_ANCHOR_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
)
ROLLBACK_PREFLIGHT_RECEIPT_SCHEMA_REF: Final = (
    ROLLBACK_ANCHOR_STATE_SCHEMA_REF
    + "#/$defs/rollbackAuthorityPreflightReceipt"
)
ROLLBACK_PREPARE_RECEIPT_SCHEMA_REF: Final = (
    ROLLBACK_ANCHOR_STATE_SCHEMA_REF + "#/$defs/prepareReceipt"
)
ROLLBACK_COMMIT_RECEIPT_SCHEMA_REF: Final = (
    ROLLBACK_ANCHOR_STATE_SCHEMA_REF + "#/$defs/receipt"
)
ROLLBACK_FRESHNESS_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-anchor-freshness-envelope.schema.json"
)
PUBLICATION_COMMIT_STATE_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-publication-trace.schema.json"
    "#/$defs/repositoryCommitRecord"
)

HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_CALLER_SUPPLIED_OPERATION_EXCHANGE_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_REQUEST_BYTES_AND_BINDINGS_VERIFIED_PRODUCT_ACCEPTANCE_NOT_PROVEN"
)
HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    "TARGET_AUTHENTIC_OPERATION_REQUEST_ACCEPTANCE_RECEIPT_REQUIRED",
    "TARGET_IDEMPOTENCY_KEY_AND_SCOPE_OWNERSHIP_RECEIPT_REQUIRED",
    "TARGET_CONTROLLER_GENERATION_AUTHORITY_RECEIPT_REQUIRED",
    "TARGET_PUBLICATION_REQUEST_READ_SET_BINDING_REQUIRED",
)

PUBLICATION_OPERATION_REQUEST_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OPERATION-REQUEST/V1\x00"
)

HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_CALLER_SUPPLIED_OPERATION_RESULT_AND_MUTATION_ONLY"
)
HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_DISPOSITION: Final = (
    "COMPONENT_RESULT_BYTES_AND_TRACE_PROJECTION_VERIFIED_PRODUCT_EXCHANGE_NOT_PROVEN"
)
HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    "TARGET_ACCEPTED_OPERATION_REQUEST_IDEMPOTENCY_AND_DEADLINE_RECEIPT_REQUIRED",
    "TARGET_CONTROLLER_GENERATION_AUTHORITY_RECEIPT_REQUIRED",
    "TARGET_PRODUCT_REPOSITORY_TRANSACTION_PORT_REQUIRED",
    "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "TARGET_ATOMIC_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED",
    "TARGET_OUTBOX_POST_ANCHOR_DELIVERY_RECEIPT_REQUIRED",
    "TARGET_DURABLE_COMMIT_CONTEXT_AND_COMMIT_CLOCK_RECEIPT_REQUIRED",
    "TARGET_AUTHENTIC_OPERATION_RESULT_EXCHANGE_RECEIPT_REQUIRED",
    "TARGET_IDEMPOTENT_RESULT_STORE_AND_REPLAY_RECEIPT_REQUIRED",
)
PUBLICATION_OPERATION_RESULT_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OPERATION-RESULT/V1\x00"
)

_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION_PATTERN: Final = re.compile(r"^\d{4}-\d{2}-\d{2}\.[1-9][0-9]*$")
_COMMIT_PATTERNS: Final = {
    "SHA1": re.compile(r"^[0-9a-f]{40}$"),
    "SHA256": re.compile(r"^[0-9a-f]{64}$"),
}


@dataclass(frozen=True, slots=True)
class PublicationOperationVerifierLimits:
    """Caller-tightenable ceilings for the detached operation exchange."""

    max_envelope_bytes: int = 256 * 1024
    max_payload_bytes: int = 4 * 1024 * 1024
    max_total_input_bytes: int = 5 * 1024 * 1024
    max_json_nodes: int = 250_000
    max_json_depth: int = 64


DEFAULT_PUBLICATION_OPERATION_LIMITS = PublicationOperationVerifierLimits()


@dataclass(slots=True)
class _Budget:
    limits: PublicationOperationVerifierLimits
    input_bytes: int = 0
    json_nodes: int = 0

    def add(self, byte_count: int, node_count: int, path: str) -> None:
        self.input_bytes += byte_count
        self.json_nodes += node_count
        require(
            self.input_bytes <= self.limits.max_total_input_bytes,
            "PUBLICATION_OPERATION_TOO_LARGE",
            path,
            "aggregate operation input bytes exceed the closed limit",
        )
        require(
            self.json_nodes <= self.limits.max_json_nodes,
            "PUBLICATION_OPERATION_TOO_LARGE",
            path,
            "aggregate operation JSON nodes exceed the closed limit",
        )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationOperationRequestContext(FactoryVerified):
    """Replayable exact request envelope and detached payload binding."""

    limits: PublicationOperationVerifierLimits
    request_envelope: Mapping[str, Any]
    request_envelope_canonical_bytes: bytes
    request_payload: Mapping[str, Any]
    request_payload_canonical_bytes: bytes
    command_id: str
    idempotency_key: str
    idempotency_scope_hash: str
    issued_at: datetime
    deadline_at: datetime
    portable_contract_revision: str
    portable_contract_sha256: str
    target_repository_object_format: str
    target_repository_commit: str
    controller_generation: int
    authority: Mapping[str, Any]
    correlation: Mapping[str, Any]
    payload_hash: str
    request_hash: str
    context_receipt: Mapping[str, Any]
    context_receipt_canonical_bytes: bytes
    context_digest: str
    authority_boundary: str
    authority_disposition: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]
    _schemas: ContractSchemas = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotPublicationOperationResultContext(FactoryVerified):
    """Replayable successful result bound to one verified mutation closure."""

    limits: PublicationOperationVerifierLimits
    request: VerifiedHostSnapshotPublicationOperationRequestContext
    mutation: VerifiedHostSnapshotPublicationMutationContext
    result_envelope: Mapping[str, Any]
    result_envelope_canonical_bytes: bytes
    result_payload: Mapping[str, Any]
    result_payload_canonical_bytes: bytes
    completed_at: datetime
    payload_hash: str
    result_hash: str
    committed_resource_versions: tuple[Mapping[str, Any], ...]
    receipt_hashes: tuple[Mapping[str, Any], ...]
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
    value: PublicationOperationVerifierLimits | None,
) -> PublicationOperationVerifierLimits:
    limits = value or DEFAULT_PUBLICATION_OPERATION_LIMITS
    require(
        isinstance(limits, PublicationOperationVerifierLimits),
        "PUBLICATION_OPERATION_INPUT_INVALID",
        "publicationOperation.limits",
        "expected PublicationOperationVerifierLimits",
    )
    hard = DEFAULT_PUBLICATION_OPERATION_LIMITS
    for descriptor in fields(PublicationOperationVerifierLimits):
        actual = getattr(limits, descriptor.name)
        ceiling = getattr(hard, descriptor.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "PUBLICATION_OPERATION_LIMIT_INVALID",
            f"publicationOperation.limits.{descriptor.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {ceiling}"
            ),
        )
    return limits


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
            "PUBLICATION_OPERATION_CANONICAL_BYTES_INVALID",
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
                "PUBLICATION_OPERATION_TOO_LARGE",
                path,
                "canonical JSON exceeds the configured depth limit",
            )
        elif character in "]}":
            depth = max(depth - 1, 0)


def _load_document(
    value: JsonDocument,
    *,
    path: str,
    max_bytes: int,
    limits: PublicationOperationVerifierLimits,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, Mapping):
            measured_bytes, nodes = measure_canonical_json(
                value,
                max_bytes=max_bytes,
                max_nodes=limits.max_json_nodes,
                max_depth=limits.max_json_depth,
            )
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            require(
                0 < len(raw) <= max_bytes,
                "PUBLICATION_OPERATION_TOO_LARGE",
                path,
                f"canonical input exceeds the closed {max_bytes} byte limit",
            )
            _reject_excessive_raw_depth(
                raw,
                maximum=limits.max_json_depth,
                path=path,
            )
            loaded = load_canonical_json(raw)
            measured_bytes, nodes = measure_canonical_json(
                loaded,
                max_bytes=max_bytes,
                max_nodes=limits.max_json_nodes,
                max_depth=limits.max_json_depth,
            )
        else:
            fail(
                "PUBLICATION_OPERATION_INPUT_INVALID",
                path,
                "expected canonical JSON bytes or a JSON object",
            )
    except DirectPathVerificationError:
        raise
    except CanonicalJsonLimitError as exc:
        fail("PUBLICATION_OPERATION_TOO_LARGE", path, str(exc))
    except (CanonicalizationError, RecursionError, TypeError, ValueError) as exc:
        fail(
            "PUBLICATION_OPERATION_CANONICAL_BYTES_INVALID",
            path,
            f"input is not exact CANONICAL-JSON-V1: {exc}",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_OPERATION_INPUT_INVALID",
        path,
        "expected one canonical JSON object",
    )
    require(
        len(raw) == measured_bytes,
        "PUBLICATION_OPERATION_CANONICAL_BYTES_INVALID",
        path,
        "measured canonical size differs from retained bytes",
    )
    budget.add(len(raw), nodes, path)
    return loaded, raw


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "PUBLICATION_OPERATION_TIME_INVALID",
        path,
        "expected TIMESTAMP-UTC-US-V1 text",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail(
            "PUBLICATION_OPERATION_TIME_INVALID",
            path,
            f"invalid TIMESTAMP-UTC-US-V1 value: {exc}",
        )
    return parsed.replace(tzinfo=timezone.utc)


def _require_equal(
    actual: Any,
    expected: Any,
    *,
    path: str,
    message: str,
) -> None:
    require(
        canonical_json_bytes(actual) == canonical_json_bytes(expected),
        "PUBLICATION_OPERATION_BINDING_MISMATCH",
        path,
        message,
    )


def _validate_expected_deployment_binding(
    *,
    portable_revision: Any,
    portable_sha256: Any,
    target_format: Any,
    target_commit: Any,
    controller_generation: Any,
) -> tuple[str, str, str, str, int]:
    require(
        isinstance(portable_revision, str)
        and _REVISION_PATTERN.fullmatch(portable_revision) is not None,
        "PUBLICATION_OPERATION_EXPECTATION_INVALID",
        "publicationOperation.expectedPortableContractRevision",
        "expected portable revision is not a frozen revision identifier",
    )
    require(
        isinstance(portable_sha256, str)
        and _DIGEST_PATTERN.fullmatch(portable_sha256) is not None,
        "PUBLICATION_OPERATION_EXPECTATION_INVALID",
        "publicationOperation.expectedPortableContractSha256",
        "expected portable contract hash is not lowercase SHA-256",
    )
    require(
        isinstance(target_format, str)
        and target_format in _COMMIT_PATTERNS,
        "PUBLICATION_OPERATION_EXPECTATION_INVALID",
        "publicationOperation.expectedTargetRepositoryObjectFormat",
        "expected target object format must be SHA1 or SHA256",
    )
    require(
        isinstance(target_commit, str)
        and _COMMIT_PATTERNS[target_format].fullmatch(target_commit) is not None,
        "PUBLICATION_OPERATION_EXPECTATION_INVALID",
        "publicationOperation.expectedTargetRepositoryCommit",
        "expected target commit does not match its object format",
    )
    require(
        isinstance(controller_generation, int)
        and not isinstance(controller_generation, bool)
        and controller_generation >= 1,
        "PUBLICATION_OPERATION_EXPECTATION_INVALID",
        "publicationOperation.expectedControllerGeneration",
        "expected controller generation must be a positive integer",
    )
    return (
        portable_revision,
        portable_sha256,
        target_format,
        target_commit,
        controller_generation,
    )


def _context_digest(receipt: Mapping[str, Any]) -> str:
    projected = _thaw_json(receipt)
    projected["contextDigest"] = None
    return sha256_digest(
        PUBLICATION_OPERATION_REQUEST_CONTEXT_DOMAIN
        + canonical_json_bytes(projected)
    )


def verify_host_snapshot_publication_operation_request(
    schemas: ContractSchemas,
    *,
    request_envelope: JsonDocument,
    request_payload: JsonDocument,
    expected_portable_contract_revision: str,
    expected_portable_contract_sha256: str,
    expected_target_repository_object_format: str,
    expected_target_repository_commit: str,
    expected_controller_generation: int,
    limits: PublicationOperationVerifierLimits | None = None,
) -> VerifiedHostSnapshotPublicationOperationRequestContext:
    """Verify one exact detached OP-CAPTURE request without claiming acceptance."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_OPERATION_INPUT_INVALID",
        "publicationOperation.schemas",
        "expected ContractSchemas",
    )
    checked_limits = _checked_limits(limits)
    (
        portable_revision,
        portable_sha256,
        target_format,
        target_commit,
        controller_generation,
    ) = _validate_expected_deployment_binding(
        portable_revision=expected_portable_contract_revision,
        portable_sha256=expected_portable_contract_sha256,
        target_format=expected_target_repository_object_format,
        target_commit=expected_target_repository_commit,
        controller_generation=expected_controller_generation,
    )
    budget = _Budget(checked_limits)
    envelope, envelope_raw = _load_document(
        request_envelope,
        path="publicationOperation.requestEnvelope",
        max_bytes=checked_limits.max_envelope_bytes,
        limits=checked_limits,
        budget=budget,
    )
    payload, payload_raw = _load_document(
        request_payload,
        path="publicationOperation.requestPayload",
        max_bytes=checked_limits.max_payload_bytes,
        limits=checked_limits,
        budget=budget,
    )
    schemas.validate_ref(
        CAPTURE_HOST_SNAPSHOT_REQUEST_ENVELOPE_SCHEMA_REF,
        envelope,
        "publicationOperation.requestEnvelope",
    )
    schemas.validate_ref(
        CAPTURE_HOST_SNAPSHOT_REQUEST_PAYLOAD_SCHEMA_REF,
        payload,
        "publicationOperation.requestPayload",
    )

    _require_equal(
        envelope["portableContractRevision"],
        portable_revision,
        path="publicationOperation.requestEnvelope.portableContractRevision",
        message="request does not bind the independently selected portable revision",
    )
    _require_equal(
        envelope["portableContractSha256"],
        portable_sha256,
        path="publicationOperation.requestEnvelope.portableContractSha256",
        message="request does not bind the independently selected portable bytes",
    )
    _require_equal(
        envelope["targetRepositoryObjectFormat"],
        target_format,
        path="publicationOperation.requestEnvelope.targetRepositoryObjectFormat",
        message="request does not bind the independently selected target object format",
    )
    _require_equal(
        envelope["targetRepositoryCommit"],
        target_commit,
        path="publicationOperation.requestEnvelope.targetRepositoryCommit",
        message="request does not bind the independently selected target commit",
    )
    _require_equal(
        envelope["authority"]["controllerGeneration"],
        controller_generation,
        path="publicationOperation.requestEnvelope.authority.controllerGeneration",
        message="request uses a different controller generation",
    )

    expected_payload_schema_sha256 = schemas.digest_for_ref(
        OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
        path="publicationOperation.requestEnvelope.payloadSchemaSha256",
    )
    _require_equal(
        envelope["payloadSchemaSha256"],
        expected_payload_schema_sha256,
        path="publicationOperation.requestEnvelope.payloadSchemaSha256",
        message="request does not bind the exact loaded operation-payload schema bytes",
    )
    payload_hash = sha256_digest(payload_raw)
    _require_equal(
        envelope["payloadHash"],
        payload_hash,
        path="publicationOperation.requestEnvelope.payloadHash",
        message="request payload hash differs from the detached canonical payload bytes",
    )
    request_projection = dict(envelope)
    request_projection["requestHash"] = None
    request_hash = sha256_digest(canonical_json_bytes(request_projection))
    _require_equal(
        envelope["requestHash"],
        request_hash,
        path="publicationOperation.requestEnvelope.requestHash",
        message="request hash differs from the null-hash envelope projection",
    )

    require(
        envelope["operationLeaseCapabilityOrNull"] is None
        and envelope["releaseOwnershipGuardCapabilityOrNull"] is None,
        "PUBLICATION_OPERATION_CAPABILITY_INVALID",
        "publicationOperation.requestEnvelope",
        "OP-CAPTURE-HOST-SNAPSHOT carries no operation lease or release guard",
    )
    issued_at = _timestamp(
        envelope["issuedAt"],
        "publicationOperation.requestEnvelope.issuedAt",
    )
    deadline_at = _timestamp(
        envelope["deadlineAt"],
        "publicationOperation.requestEnvelope.deadlineAt",
    )
    require(
        issued_at < deadline_at,
        "PUBLICATION_OPERATION_TIME_INVALID",
        "publicationOperation.requestEnvelope.deadlineAt",
        "deadlineAt must be strictly later than issuedAt",
    )

    body = payload["body"]
    correlation = envelope["correlation"]
    require(
        correlation["hostIds"] == [body["hostId"]]
        and correlation["deviceUids"] == []
        and correlation["assignmentIdOrNull"] is None
        and correlation["runIdOrNull"] is None
        and correlation["relocationIdOrNull"] is None,
        "PUBLICATION_OPERATION_CORRELATION_INVALID",
        "publicationOperation.requestEnvelope.correlation",
        (
            "capture correlation must name exactly the host, no pre-capture "
            "devices, and no assignment/run/relocation scope"
        ),
    )
    require(
        body["hostBootIdentity"]["hostId"] == body["hostId"],
        "PUBLICATION_OPERATION_PAYLOAD_INVALID",
        "publicationOperation.requestPayload.body.hostBootIdentity.hostId",
        "host boot identity must name the request host",
    )
    require(
        envelope["authority"]["hostEpochs"]
        == [
            {
                "id": body["hostId"],
                "generation": body["hostBootIdentity"]["hostEpoch"],
            }
        ]
        and envelope["authority"]["runGenerations"] == []
        and envelope["authority"]["memberGenerations"] == [],
        "PUBLICATION_OPERATION_AUTHORITY_INVALID",
        "publicationOperation.requestEnvelope.authority",
        (
            "capture authority must carry exactly one host epoch and no "
            "run/member generations"
        ),
    )

    receipt = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_CONTEXT",
        "schemaVersion": 1,
        "requestEnvelopeCanonicalSha256": sha256_digest(envelope_raw),
        "requestPayloadCanonicalSha256": sha256_digest(payload_raw),
        "operationId": envelope["operationId"],
        "commandId": envelope["commandId"],
        "idempotencyKey": envelope["idempotencyKey"],
        "idempotencyScopeHash": envelope["idempotencyScopeHash"],
        "issuedAt": envelope["issuedAt"],
        "deadlineAt": envelope["deadlineAt"],
        "portableContractRevision": portable_revision,
        "portableContractSha256": portable_sha256,
        "targetRepositoryObjectFormat": target_format,
        "targetRepositoryCommit": target_commit,
        "controllerGeneration": controller_generation,
        "payloadSchemaSha256": expected_payload_schema_sha256,
        "payloadHash": payload_hash,
        "requestHash": request_hash,
        "authorityBoundary": (
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY
        ),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = _context_digest(receipt)
    receipt["contextDigest"] = context_digest
    receipt_raw = canonical_json_bytes(receipt)
    frozen_envelope = _freeze_json(envelope)
    return VerifiedHostSnapshotPublicationOperationRequestContext._construct(
        limits=checked_limits,
        request_envelope=frozen_envelope,
        request_envelope_canonical_bytes=envelope_raw,
        request_payload=_freeze_json(payload),
        request_payload_canonical_bytes=payload_raw,
        command_id=envelope["commandId"],
        idempotency_key=envelope["idempotencyKey"],
        idempotency_scope_hash=envelope["idempotencyScopeHash"],
        issued_at=issued_at,
        deadline_at=deadline_at,
        portable_contract_revision=portable_revision,
        portable_contract_sha256=portable_sha256,
        target_repository_object_format=target_format,
        target_repository_commit=target_commit,
        controller_generation=controller_generation,
        authority=frozen_envelope["authority"],
        correlation=frozen_envelope["correlation"],
        payload_hash=payload_hash,
        request_hash=request_hash,
        context_receipt=_freeze_json(receipt),
        context_receipt_canonical_bytes=receipt_raw,
        context_digest=context_digest,
        authority_boundary=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY
        ),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_host_snapshot_publication_operation_request(
    context: VerifiedHostSnapshotPublicationOperationRequestContext,
) -> VerifiedHostSnapshotPublicationOperationRequestContext:
    """Replay one request context from only its retained exact bytes."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationOperationRequestContext,
        code="PUBLICATION_OPERATION_CONTEXT_INVALID",
        path="publicationOperation.requestContext",
        message=(
            "context must come from "
            "verify_host_snapshot_publication_operation_request"
        ),
    )
    replayed = verify_host_snapshot_publication_operation_request(
        context._schemas,
        request_envelope=context.request_envelope_canonical_bytes,
        request_payload=context.request_payload_canonical_bytes,
        expected_portable_contract_revision=(
            context.portable_contract_revision
        ),
        expected_portable_contract_sha256=context.portable_contract_sha256,
        expected_target_repository_object_format=(
            context.target_repository_object_format
        ),
        expected_target_repository_commit=context.target_repository_commit,
        expected_controller_generation=context.controller_generation,
        limits=context.limits,
    )
    require(
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes
        and replayed == context
        and replayed._schemas is context._schemas,
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        "publicationOperation.requestContext",
        (
            "request context claims differ when replayed from retained "
            "exact bytes"
        ),
    )
    return replayed


def _result_context_digest(receipt: Mapping[str, Any]) -> str:
    projected = _thaw_json(receipt)
    projected["contextDigest"] = None
    return sha256_digest(
        PUBLICATION_OPERATION_RESULT_CONTEXT_DOMAIN
        + canonical_json_bytes(projected)
    )


def _schema_bytes_digest(
    schemas: ContractSchemas,
    schema_ref: str,
    *,
    path: str,
) -> str:
    document_ref, _, _ = schema_ref.partition("#")
    return schemas.digest_for_ref(document_ref, path=path)


def _sorted_closed_set(
    rows: list[dict[str, Any]],
    *,
    key_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: canonical_json_bytes(
            [row[field_name] for field_name in key_fields]
        ),
    )


def _receipt_hash(
    schemas: ContractSchemas,
    *,
    receipt_type: str,
    receipt_id: str,
    schema_ref: str,
    canonical_bytes: bytes,
) -> dict[str, Any]:
    return {
        "receiptType": receipt_type,
        "receiptId": receipt_id,
        "schemaRef": schema_ref,
        "schemaSha256": _schema_bytes_digest(
            schemas,
            schema_ref,
            path=(
                "publicationOperation.resultEnvelope.receiptHashes."
                f"{receipt_type}.schemaSha256"
            ),
        ),
        "receiptSha256": sha256_digest(canonical_bytes),
    }


def _expected_result_output(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> dict[str, Any]:
    rollback = mutation.rollback
    snapshot_artifact = rollback.host_snapshot_after_artifact
    snapshot = snapshot_artifact["state"]
    host_artifact = rollback.host_authority_after_artifact
    host_authority = host_artifact["state"]
    anchor_artifact = rollback.after_anchor_artifact
    anchor = anchor_artifact["state"]
    freshness_artifact = rollback.after_freshness_artifact
    freshness = freshness_artifact["state"]
    return {
        "hostSnapshot": {
            "documentKind": "HOST_SNAPSHOT",
            "documentId": snapshot["contentHash"],
            "documentVersion": snapshot["snapshotEpoch"],
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": HOST_SNAPSHOT_STATE_SCHEMA_REF,
            "contentHash": snapshot_artifact["instanceBytesSha256"],
        },
        "snapshotContentHash": snapshot["contentHash"],
        "inventorySignature": {
            "documentKind": "HOST_INVENTORY_SIGNATURE",
            "documentId": snapshot["contentHash"],
            "documentVersion": snapshot["keyRingVersion"],
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": HOST_SNAPSHOT_STATE_SCHEMA_REF,
            "contentHash": snapshot_artifact["instanceBytesSha256"],
        },
        "advancedHostAuthority": {
            "entityType": "ENTITY-HOST-AUTHORITY",
            "entityId": host_authority["hostId"],
            "resourceVersion": host_authority["resourceVersion"],
            "generationOrNull": host_authority["agentGeneration"],
            "contentHash": host_artifact["instanceBytesSha256"],
        },
        "factProvenanceSetHash": (
            mutation.decision.capture.snapshot_semantics.provider_facts_digest
        ),
        "freshnessDecision": _thaw_json(
            mutation.decision.freshness_decision
        ),
        "snapshotRollbackAnchor": {
            "documentKind": "HOST_SNAPSHOT_ROLLBACK_ANCHOR",
            "documentId": anchor["anchorDigest"],
            "documentVersion": anchor["anchorVersion"],
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": ROLLBACK_ANCHOR_STATE_SCHEMA_REF,
            "contentHash": anchor_artifact["instanceBytesSha256"],
        },
        "snapshotAnchorFreshness": {
            "documentKind": "ANCHOR_FRESHNESS_ENVELOPE",
            "documentId": freshness["envelopeId"],
            "documentVersion": freshness["resourceVersion"],
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": ROLLBACK_FRESHNESS_STATE_SCHEMA_REF,
            "contentHash": freshness_artifact["instanceBytesSha256"],
        },
    }


def _expected_committed_resource_versions(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> list[dict[str, Any]]:
    if not mutation.decision.write_required:
        return []
    availability_artifact = (
        mutation.availability_authority_after_artifact_or_null
    )
    require(
        availability_artifact is not None,
        "PUBLICATION_OPERATION_UPSTREAM_CONTEXT_INVALID",
        "publicationOperation.mutation.availabilityAuthorityAfter",
        "committed mutation is missing AvailabilityAuthority after bytes",
    )
    before = mutation.decision.read_set
    host_after = mutation.rollback.host_authority_after_artifact["state"]
    availability_after = availability_artifact["state"]
    return _sorted_closed_set(
        [
            {
                "entityType": "ENTITY-HOST-AUTHORITY",
                "resourceId": host_after["hostId"],
                "previousResourceVersionOrNull": (
                    before.host_authority_before["resourceVersion"]
                ),
                "committedResourceVersion": host_after["resourceVersion"],
            },
            {
                "entityType": "ENTITY-AVAILABILITY-AUTHORITY",
                "resourceId": availability_after["availabilityAuthorityId"],
                "previousResourceVersionOrNull": (
                    before.availability_authority_before["resourceVersion"]
                ),
                "committedResourceVersion": availability_after[
                    "resourceVersion"
                ],
            },
        ],
        key_fields=(
            "entityType",
            "resourceId",
            "committedResourceVersion",
        ),
    )


def _expected_receipt_hashes(
    schemas: ContractSchemas,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> list[dict[str, Any]]:
    rollback = mutation.rollback
    read_set = mutation.decision.read_set
    preflight = read_set.rollback_authority_preflight
    anchor = rollback.after_anchor_artifact["state"]
    anchor_receipt = _thaw_json(anchor["receipt"])
    freshness = _thaw_json(rollback.after_freshness_artifact["state"])
    rows = [
        _receipt_hash(
            schemas,
            receipt_type="RECEIPT-HOST-SNAPSHOT-ROLLBACK-PREFLIGHT",
            receipt_id=preflight["receiptId"],
            schema_ref=ROLLBACK_PREFLIGHT_RECEIPT_SCHEMA_REF,
            canonical_bytes=(
                read_set.rollback_authority_preflight_canonical_bytes
            ),
        ),
        _receipt_hash(
            schemas,
            receipt_type="RECEIPT-HOST-SNAPSHOT-ANCHOR-COMMIT",
            receipt_id=anchor_receipt["receiptId"],
            schema_ref=ROLLBACK_COMMIT_RECEIPT_SCHEMA_REF,
            canonical_bytes=canonical_json_bytes(anchor_receipt),
        ),
        _receipt_hash(
            schemas,
            receipt_type="RECEIPT-HOST-SNAPSHOT-ANCHOR-FRESHNESS",
            receipt_id=freshness["envelopeId"],
            schema_ref=ROLLBACK_FRESHNESS_STATE_SCHEMA_REF,
            canonical_bytes=canonical_json_bytes(freshness),
        ),
    ]
    if mutation.decision.write_required:
        prepared_artifact = rollback.prepared_anchor_artifact_or_null
        commit_artifact = mutation.commit_record_artifact_or_null
        require(
            prepared_artifact is not None and commit_artifact is not None,
            "PUBLICATION_OPERATION_UPSTREAM_CONTEXT_INVALID",
            "publicationOperation.mutation.receipts",
            "committed mutation is missing prepare or commit receipt bytes",
        )
        prepare_receipt = _thaw_json(
            prepared_artifact["state"]["prepareReceipt"]
        )
        rows.append(
            _receipt_hash(
                schemas,
                receipt_type="RECEIPT-HOST-SNAPSHOT-ANCHOR-PREPARE",
                receipt_id=prepare_receipt["reservationId"],
                schema_ref=ROLLBACK_PREPARE_RECEIPT_SCHEMA_REF,
                canonical_bytes=canonical_json_bytes(prepare_receipt),
            )
        )
        rows.append(
            _receipt_hash(
                schemas,
                receipt_type="RECEIPT-HOST-SNAPSHOT-REPOSITORY-COMMIT",
                receipt_id=commit_artifact["state"]["commitId"],
                schema_ref=PUBLICATION_COMMIT_STATE_SCHEMA_REF,
                canonical_bytes=canonical_json_bytes(
                    _thaw_json(commit_artifact["state"])
                ),
            )
        )
    return _sorted_closed_set(
        rows,
        key_fields=(
            "receiptType",
            "receiptId",
            "schemaRef",
            "receiptSha256",
        ),
    )


def _verify_result_request_echo(
    result: Mapping[str, Any],
    request: Mapping[str, Any],
) -> None:
    for field_name in (
        "operationId",
        "commandId",
        "idempotencyMode",
        "idempotencyKey",
        "idempotencyScopeHash",
        "actorPortId",
        "portableContractId",
        "portableContractRevision",
        "portableContractSha256",
        "targetRepositoryObjectFormat",
        "targetRepositoryCommit",
        "correlation",
    ):
        _require_equal(
            result[field_name],
            _thaw_json(request[field_name]),
            path=f"publicationOperation.resultEnvelope.{field_name}",
            message=(
                "result does not exact-echo the accepted request "
                f"{field_name}"
            ),
        )


def _expected_result_authority(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> dict[str, Any]:
    request_authority = mutation.operation_request.request_envelope[
        "authority"
    ]
    read_set = mutation.decision.read_set
    snapshot_after = mutation.rollback.host_snapshot_after_artifact["state"]
    host_after = mutation.rollback.host_authority_after_artifact["state"]
    if mutation.decision.write_required:
        availability_artifact = (
            mutation.availability_authority_after_artifact_or_null
        )
        require(
            availability_artifact is not None,
            "PUBLICATION_OPERATION_UPSTREAM_CONTEXT_INVALID",
            "publicationOperation.mutation.availabilityAuthorityAfter",
            "committed mutation is missing AvailabilityAuthority after bytes",
        )
        availability = availability_artifact["state"]
    else:
        availability = read_set.availability_authority_before
    resource_versions = _sorted_closed_set(
        [
            {
                "entityType": "ENTITY-HOST-AUTHORITY",
                "resourceId": host_after["hostId"],
                "expectedResourceVersion": host_after["resourceVersion"],
            },
            {
                "entityType": "ENTITY-AVAILABILITY-AUTHORITY",
                "resourceId": availability["availabilityAuthorityId"],
                "expectedResourceVersion": availability["resourceVersion"],
            },
            {
                "entityType": "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                "resourceId": read_set.capability_policy_authority[
                    "policyAuthorityId"
                ],
                "expectedResourceVersion": read_set.capability_policy_authority[
                    "resourceVersion"
                ],
            },
            {
                "entityType": (
                    "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
                ),
                "resourceId": read_set.freshness_policy_authority[
                    "freshnessPolicyAuthorityId"
                ],
                "expectedResourceVersion": read_set.freshness_policy_authority[
                    "resourceVersion"
                ],
            },
        ],
        key_fields=(
            "entityType",
            "resourceId",
            "expectedResourceVersion",
        ),
    )
    return {
        "controllerGeneration": request_authority["controllerGeneration"],
        "snapshotEpoch": snapshot_after["snapshotEpoch"],
        "hostEpochs": _thaw_json(request_authority["hostEpochs"]),
        "runGenerations": [],
        "memberGenerations": [],
        "resourceVersions": resource_versions,
    }


def verify_host_snapshot_publication_operation_result(
    schemas: ContractSchemas,
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    *,
    result_envelope: JsonDocument,
    result_payload: JsonDocument,
    limits: PublicationOperationVerifierLimits | None = None,
) -> VerifiedHostSnapshotPublicationOperationResultContext:
    """Verify one successful detached OP-CAPTURE result over one mutation."""

    from .publication_mutation import (
        VerifiedHostSnapshotPublicationMutationContext,
        replay_host_snapshot_publication_mutation_closure,
    )

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_OPERATION_INPUT_INVALID",
        "publicationOperation.schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        mutation,
        VerifiedHostSnapshotPublicationMutationContext,
        code="PUBLICATION_OPERATION_CONTEXT_INVALID",
        path="publicationOperation.mutationContext",
        message="result verification requires a factory-produced mutation",
    )
    request = mutation.operation_request
    require_factory_verified(
        request,
        VerifiedHostSnapshotPublicationOperationRequestContext,
        code="PUBLICATION_OPERATION_CONTEXT_INVALID",
        path="publicationOperation.mutationContext.operationRequest",
        message="mutation did not retain a factory-produced operation request",
    )
    require(
        mutation._schemas is schemas and request._schemas is schemas,
        "PUBLICATION_OPERATION_SCHEMA_CONTEXT_MISMATCH",
        "publicationOperation.schemas",
        "mutation, retained request, and result use different schema contexts",
    )

    checked_limits = _checked_limits(limits)
    budget = _Budget(checked_limits)
    envelope, envelope_raw = _load_document(
        result_envelope,
        path="publicationOperation.resultEnvelope",
        max_bytes=checked_limits.max_envelope_bytes,
        limits=checked_limits,
        budget=budget,
    )
    payload, payload_raw = _load_document(
        result_payload,
        path="publicationOperation.resultPayload",
        max_bytes=checked_limits.max_payload_bytes,
        limits=checked_limits,
        budget=budget,
    )
    schemas.validate_ref(
        CAPTURE_HOST_SNAPSHOT_RESULT_ENVELOPE_SCHEMA_REF,
        envelope,
        "publicationOperation.resultEnvelope",
    )
    schemas.validate_ref(
        CAPTURE_HOST_SNAPSHOT_RESULT_PAYLOAD_SCHEMA_REF,
        payload,
        "publicationOperation.resultPayload",
    )

    expected_schema_sha256 = schemas.digest_for_ref(
        OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
        path="publicationOperation.resultEnvelope.payloadSchemaSha256",
    )
    _require_equal(
        envelope["payloadSchemaSha256"],
        expected_schema_sha256,
        path="publicationOperation.resultEnvelope.payloadSchemaSha256",
        message="result does not bind the loaded operation-payload schema bytes",
    )
    payload_hash = sha256_digest(payload_raw)
    _require_equal(
        envelope["payloadHash"],
        payload_hash,
        path="publicationOperation.resultEnvelope.payloadHash",
        message="result payload hash differs from the detached payload bytes",
    )
    result_projection = dict(envelope)
    result_projection["resultHash"] = None
    result_hash = sha256_digest(canonical_json_bytes(result_projection))
    _require_equal(
        envelope["resultHash"],
        result_hash,
        path="publicationOperation.resultEnvelope.resultHash",
        message="result hash differs from the null-hash envelope projection",
    )
    # Parse, size-gate, schema-check, and hash-check detached result bytes
    # before replaying the much larger upstream closure.  No request claim is
    # consumed until replay has normalized and compared every retained claim.
    replayed_mutation = replay_host_snapshot_publication_mutation_closure(
        mutation
    )
    replayed_request = replay_host_snapshot_publication_operation_request(
        replayed_mutation.operation_request
    )
    request = replayed_request
    _verify_result_request_echo(
        envelope,
        request.request_envelope,
    )
    require(
        envelope["status"] == "SUCCEEDED"
        and envelope["retryable"] is False
        and envelope["reason"] is None
        and payload["body"]["outcome"] == "SUCCEEDED"
        and payload["body"]["outputOrNull"] is not None
        and payload["body"]["errorOrNull"] is None
        and payload["body"]["progressOrNull"] is None,
        "PUBLICATION_OPERATION_RESULT_OUTCOME_INVALID",
        "publicationOperation.result",
        "this verifier accepts only the closed successful result profile",
    )
    require(
        envelope["profileHash"] is None,
        "PUBLICATION_OPERATION_RESULT_BINDING_MISMATCH",
        "publicationOperation.resultEnvelope.profileHash",
        "OP-CAPTURE-HOST-SNAPSHOT has no qualification profile hash",
    )
    require(
        envelope["authoritativeStates"] == [],
        "PUBLICATION_OPERATION_RESULT_BINDING_MISMATCH",
        "publicationOperation.resultEnvelope.authoritativeStates",
        "snapshot capture does not advance an assignment or owner FSM",
    )

    upstream_blockers = tuple(
        blocker
        for blocker in replayed_mutation.product_evidence_blockers
        if blocker
        != "TARGET_OPERATION_RESULT_SCHEMA_AND_ENVELOPE_BINDING_REQUIRED"
    ) + (
        "TARGET_AUTHENTIC_OPERATION_RESULT_EXCHANGE_RECEIPT_REQUIRED",
        "TARGET_IDEMPOTENT_RESULT_STORE_AND_REPLAY_RECEIPT_REQUIRED",
    )
    require(
        upstream_blockers
        == HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS,
        "PUBLICATION_OPERATION_UPSTREAM_CONTEXT_INVALID",
        "publicationOperation.mutation.productEvidenceBlockers",
        "result blocker closure drifted from the verified mutation boundary",
    )

    expected_output = _expected_result_output(replayed_mutation)
    expected_cas = _thaw_json(
        replayed_mutation.snapshot_publication_cas_result
    )
    _require_equal(
        payload["body"]["outputOrNull"],
        expected_output,
        path="publicationOperation.resultPayload.body.outputOrNull",
        message="result output is not the exact retained publication projection",
    )
    _require_equal(
        payload["body"]["casResult"],
        expected_cas,
        path="publicationOperation.resultPayload.body.casResult",
        message="result CAS receipt differs from the verified mutation closure",
    )
    _require_equal(
        envelope["policyHash"],
        replayed_mutation.decision.read_set.capability_policy.policy_hash,
        path="publicationOperation.resultEnvelope.policyHash",
        message="result policy hash differs from the deciding capability policy",
    )
    _require_equal(
        envelope["authority"],
        _expected_result_authority(replayed_mutation),
        path="publicationOperation.resultEnvelope.authority",
        message="result authority is not the exact resolved post-state vector",
    )
    expected_versions = _expected_committed_resource_versions(
        replayed_mutation
    )
    expected_receipts = _expected_receipt_hashes(
        schemas,
        replayed_mutation,
    )
    _require_equal(
        envelope["committedResourceVersions"],
        expected_versions,
        path="publicationOperation.resultEnvelope.committedResourceVersions",
        message="result committed version set is not the closed operation set",
    )
    _require_equal(
        envelope["receiptHashes"],
        expected_receipts,
        path="publicationOperation.resultEnvelope.receiptHashes",
        message="result receipt set is not the closed retained-artifact set",
    )

    completed_at = _timestamp(
        envelope["completedAt"],
        "publicationOperation.resultEnvelope.completedAt",
    )
    after_observed_at = _timestamp(
        replayed_mutation.rollback.after_freshness_artifact["state"][
            "observedAt"
        ],
        (
            "publicationOperation.mutation.rollback.afterFreshness."
            "state.observedAt"
        ),
    )
    require(
        max(
            replayed_request.issued_at,
            replayed_mutation.rollback.verified_at,
            after_observed_at,
        )
        <= completed_at
        <= replayed_request.deadline_at,
        "PUBLICATION_OPERATION_TIME_INVALID",
        "publicationOperation.resultEnvelope.completedAt",
        (
            "completedAt must follow verified rollback/freshness observation "
            "and be no later than the accepted request deadline"
        ),
    )

    receipt = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_CONTEXT",
        "schemaVersion": 1,
        "requestContextDigest": replayed_request.context_digest,
        "mutationContextDigest": replayed_mutation.context_digest,
        "requestHash": replayed_request.request_hash,
        "resultEnvelopeCanonicalSha256": sha256_digest(envelope_raw),
        "resultPayloadCanonicalSha256": sha256_digest(payload_raw),
        "payloadSchemaSha256": expected_schema_sha256,
        "payloadHash": payload_hash,
        "resultHash": result_hash,
        "completedAt": envelope["completedAt"],
        "publicationDecision": (
            replayed_mutation.decision.publication_decision
        ),
        "committedResourceVersionsCanonicalSha256": sha256_digest(
            canonical_json_bytes(expected_versions)
        ),
        "receiptHashesCanonicalSha256": sha256_digest(
            canonical_json_bytes(expected_receipts)
        ),
        "outputCanonicalSha256": sha256_digest(
            canonical_json_bytes(expected_output)
        ),
        "casResultCanonicalSha256": sha256_digest(
            canonical_json_bytes(expected_cas)
        ),
        "authorityBoundary": (
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY
        ),
        "authorityDisposition": (
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_DISPOSITION
        ),
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = _result_context_digest(receipt)
    receipt["contextDigest"] = context_digest
    receipt_raw = canonical_json_bytes(receipt)
    frozen_envelope = _freeze_json(envelope)
    return VerifiedHostSnapshotPublicationOperationResultContext._construct(
        limits=checked_limits,
        request=replayed_request,
        mutation=replayed_mutation,
        result_envelope=frozen_envelope,
        result_envelope_canonical_bytes=envelope_raw,
        result_payload=_freeze_json(payload),
        result_payload_canonical_bytes=payload_raw,
        completed_at=completed_at,
        payload_hash=payload_hash,
        result_hash=result_hash,
        committed_resource_versions=tuple(
            _freeze_json(row) for row in expected_versions
        ),
        receipt_hashes=tuple(_freeze_json(row) for row in expected_receipts),
        context_receipt=_freeze_json(receipt),
        context_receipt_canonical_bytes=receipt_raw,
        context_digest=context_digest,
        authority_boundary=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY
        ),
        authority_disposition=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_DISPOSITION
        ),
        product_authorized=False,
        product_evidence_blockers=(
            HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS
        ),
        _schemas=schemas,
    )


def replay_host_snapshot_publication_operation_result(
    context: VerifiedHostSnapshotPublicationOperationResultContext,
) -> VerifiedHostSnapshotPublicationOperationResultContext:
    """Replay one successful result from its retained exact inputs."""

    from .publication_mutation import (
        VerifiedHostSnapshotPublicationMutationContext,
    )

    require_factory_verified(
        context,
        VerifiedHostSnapshotPublicationOperationResultContext,
        code="PUBLICATION_OPERATION_CONTEXT_INVALID",
        path="publicationOperation.resultContext",
        message=(
            "context must come from "
            "verify_host_snapshot_publication_operation_result"
        ),
    )
    require_factory_verified(
        context.request,
        VerifiedHostSnapshotPublicationOperationRequestContext,
        code="PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        path="publicationOperation.resultContext.request",
        message="retained result request is not a factory-produced context",
    )
    require_factory_verified(
        context.mutation,
        VerifiedHostSnapshotPublicationMutationContext,
        code="PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        path="publicationOperation.resultContext.mutation",
        message="retained result mutation is not a factory-produced context",
    )
    require_factory_verified(
        context.mutation.operation_request,
        VerifiedHostSnapshotPublicationOperationRequestContext,
        code="PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        path="publicationOperation.resultContext.mutation.operationRequest",
        message="retained mutation request is not a factory-produced context",
    )
    require(
        (
            context.request.context_digest
            == context.mutation.operation_request.context_digest
        )
        and (
            context.request.request_envelope_canonical_bytes
            == context.mutation.operation_request.request_envelope_canonical_bytes
        )
        and (
            context.request.request_payload_canonical_bytes
            == context.mutation.operation_request.request_payload_canonical_bytes
        ),
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        "publicationOperation.resultContext.request",
        "retained result request differs from the mutation operation request",
    )
    replayed = verify_host_snapshot_publication_operation_result(
        context._schemas,
        context.mutation,
        result_envelope=context.result_envelope_canonical_bytes,
        result_payload=context.result_payload_canonical_bytes,
        limits=context.limits,
    )
    require(
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes
        and replayed.limits == context.limits
        and replayed.request.context_digest == context.request.context_digest
        and (
            replayed.mutation.context_digest
            == context.mutation.context_digest
        )
        and (
            replayed.result_envelope_canonical_bytes
            == context.result_envelope_canonical_bytes
        )
        and (
            canonical_json_bytes(_thaw_json(replayed.result_envelope))
            == canonical_json_bytes(_thaw_json(context.result_envelope))
        )
        and (
            replayed.result_payload_canonical_bytes
            == context.result_payload_canonical_bytes
        )
        and (
            canonical_json_bytes(_thaw_json(replayed.result_payload))
            == canonical_json_bytes(_thaw_json(context.result_payload))
        )
        and replayed.completed_at == context.completed_at
        and replayed.payload_hash == context.payload_hash
        and replayed.result_hash == context.result_hash
        and (
            canonical_json_bytes(
                _thaw_json(replayed.committed_resource_versions)
            )
            == canonical_json_bytes(
                _thaw_json(context.committed_resource_versions)
            )
        )
        and (
            canonical_json_bytes(_thaw_json(replayed.receipt_hashes))
            == canonical_json_bytes(_thaw_json(context.receipt_hashes))
        )
        and (
            canonical_json_bytes(_thaw_json(replayed.context_receipt))
            == canonical_json_bytes(_thaw_json(context.context_receipt))
        )
        and replayed.context_digest == context.context_digest
        and replayed.authority_boundary == context.authority_boundary
        and replayed.authority_disposition == context.authority_disposition
        and replayed.product_authorized is context.product_authorized
        and (
            replayed.product_evidence_blockers
            == context.product_evidence_blockers
        ),
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH",
        "publicationOperation.resultContext",
        "result context claims differ when replayed from retained exact inputs",
    )
    return replayed


__all__ = [
    "CAPTURE_HOST_SNAPSHOT_REQUEST_ENVELOPE_SCHEMA_REF",
    "CAPTURE_HOST_SNAPSHOT_REQUEST_PAYLOAD_SCHEMA_REF",
    "CAPTURE_HOST_SNAPSHOT_RESULT_ENVELOPE_SCHEMA_REF",
    "CAPTURE_HOST_SNAPSHOT_RESULT_PAYLOAD_SCHEMA_REF",
    "DEFAULT_PUBLICATION_OPERATION_LIMITS",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS",
    "OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF",
    "PUBLICATION_OPERATION_REQUEST_CONTEXT_DOMAIN",
    "PUBLICATION_OPERATION_RESULT_CONTEXT_DOMAIN",
    "PublicationOperationVerifierLimits",
    "VerifiedHostSnapshotPublicationOperationRequestContext",
    "VerifiedHostSnapshotPublicationOperationResultContext",
    "replay_host_snapshot_publication_operation_request",
    "replay_host_snapshot_publication_operation_result",
    "verify_host_snapshot_publication_operation_request",
    "verify_host_snapshot_publication_operation_result",
]
