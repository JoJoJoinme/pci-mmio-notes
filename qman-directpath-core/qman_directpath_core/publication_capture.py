"""Executable component verifier for HostSnapshot capture closure.

This module closes the publication *capture* rules over retained canonical
bytes.  It verifies provider coverage, raw PCI configuration replay, normalized
semantic facts, the complete candidate DeviceRecord set, topology/provider
projections, the no-change projection, and candidate evidence freshness.

It deliberately does not prove that a target Qman collector or decoder binary
produced the bytes, that a SERIALIZABLE repository transaction occurred, that
an external rollback authority advanced, or that publication became visible.
The returned context is therefore fixed to component-premise authority and can
never authorize a product side effect.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

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
    InventoryVerifierLimits,
    MAX_HOST_SNAPSHOT_DEVICE_RECORDS,
    JsonDocument,
    VerifiedCandidateDeviceRecordSet,
    verify_candidate_device_record_set,
)
from .pci_config import normalize_pci_config_capture
from .policy import (
    CAPABILITY_POLICY_SCHEMA_REF,
    VerifiedCapabilityPolicy,
    verify_capability_policy,
)
from .snapshot_semantics import (
    VerifiedHostSnapshotSemantics,
    derive_host_snapshot_semantics,
    derive_no_change_projection,
)


HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF = (
    "contracts/directpath-host-snapshot-publication-trace.schema.json"
)
HOST_SNAPSHOT_CAPTURE_BATCH_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/captureBatch"
)
HOST_SNAPSHOT_CAPTURE_BATCH_ARTIFACT_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/captureBatchArtifact"
)
HOST_SNAPSHOT_FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessPolicyArtifact"
)
HOST_SNAPSHOT_DEVICE_RECORD_ARTIFACT_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/deviceRecordArtifact"
)
HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/providerCaptureOutputEnvelope"
)
HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/providerCaptureSemanticFactsEnvelope"
)
HOST_SNAPSHOT_TOPOLOGY_PROJECTION_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/topologyProjection"
)
HOST_SNAPSHOT_PROVIDER_PROJECTION_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/providerSemanticProjection"
)
HOST_SNAPSHOT_NO_CHANGE_PROJECTION_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/noChangeProjection"
)
HOST_SNAPSHOT_CAPTURE_CLOSURE_RECEIPT_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/captureClosureVerificationReceipt"
)
HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_SCHEMA_REF = (
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF
    + "#/$defs/captureClosureVerifierAlgorithmIdentity"
)

HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_ID = (
    "HOST_SNAPSHOT_CAPTURE_CLOSURE_VERIFIER_V2"
)
HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY = (
    "COMPONENT_CALLER_SUPPLIED_CAPTURE_BYTES_ONLY"
)
HOST_SNAPSHOT_CAPTURE_AUTHORITY_DISPOSITION = "COMPONENT_PREMISE_ONLY"
HOST_SNAPSHOT_CAPTURE_PRODUCT_AUTHORIZED = False
HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS = (
    "TARGET_COMMIT_PROVIDER_DECODER_BUILD_ATTESTATION_REQUIRED",
    "TARGET_QMAN_COLLECTOR_PUBLISHER_EXECUTION_REQUIRED",
    "TRUSTED_PUBLICATION_EVALUATION_TIME_REQUIRED",
    "LINEARIZABLE_SERIALIZABLE_REPOSITORY_RECEIPT_REQUIRED",
    "CAPABILITY_POLICY_AUTHORITY_CAS_RECEIPT_REQUIRED",
    "EXTERNAL_ROLLBACK_AUTHORITY_RECEIPT_REQUIRED",
    "INDEPENDENT_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED",
    "TARGET_QMAN_MAPPING_BUILD_RUNNER_EVIDENCE_REQUIRED",
)

_CAPTURE_BATCH_DOMAIN = b"QMAN-DIRECTPATH/HOST-CAPTURE-BATCH/V1\x00"
_FRESHNESS_POLICY_DOMAIN = b"QMAN-DIRECTPATH/HOST-SNAPSHOT-FRESHNESS-POLICY/V1\x00"
_PROVIDER_SEMANTIC_FACTS_DOMAIN = b"QMAN-DIRECTPATH/PROVIDER-SEMANTIC-FACTS/V1\x00"
_CAPTURE_CONTEXT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-CAPTURE-CLOSURE-CONTEXT/V2\x00"
)
_CAPTURE_ALGORITHM_IDENTITY_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-CAPTURE-CLOSURE-VERIFIER-ALGORITHM/V2\x00"
)
_CAPTURE_VERIFIER_SCHEMA_REFS = (
    CAPABILITY_POLICY_SCHEMA_REF,
    HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF,
    "contracts/directpath-identity-v1.schema.json",
    "contracts/directpath-portable-entities.schema.json",
    "contracts/directpath-portable-hash-subjects.schema.json",
)
_CAPTURE_VERIFIER_VALIDATION_STAGES = (
    "BOUNDED_CANONICAL_INPUT_V2",
    "CAPABILITY_POLICY_CURRENT_SCHEMA_REPLAY_V1",
    "CAPTURE_BATCH_ARTIFACT_REPLAY_V1",
    "DEVICE_RECORD_V3_SET_REPLAY_V1",
    "COMMITTED_ROW_COORDINATE_COMPOSABILITY_V1",
    "PROVIDER_COVERAGE_PCI_BIJECTION_V1",
    "PROVIDER_RAW_SEMANTIC_REPLAY_V1",
    "SNAPSHOT_SEMANTIC_PROJECTION_REPLAY_V1",
    "MANDATORY_FACT_FRESHNESS_INDEXED_V2",
    "CAPTURE_CLOSURE_RECEIPT_V2",
)


@dataclass(frozen=True, slots=True)
class PublicationCaptureVerifierLimits:
    """Closed resource ceilings; callers may tighten but never relax them."""

    max_capture_artifact_bytes: int = 128 * 1024 * 1024
    max_decoded_capture_batch_bytes: int = 16 * 1024 * 1024
    max_device_record_artifact_bytes: int = 2 * 1024 * 1024
    max_decoded_provider_artifact_bytes: int = 16 * 1024 * 1024
    max_total_input_bytes: int = 256 * 1024 * 1024
    max_total_decoded_bytes: int = 128 * 1024 * 1024
    max_json_nodes: int = 20_000_000
    max_json_depth: int = 64
    max_device_records: int = MAX_HOST_SNAPSHOT_DEVICE_RECORDS
    max_provider_captures: int = 1024
    max_pci_bindings: int = MAX_HOST_SNAPSHOT_DEVICE_RECORDS
    max_mandatory_provider_facts: int = MAX_HOST_SNAPSHOT_DEVICE_RECORDS
    max_provider_facts_per_device: int = 4096
    max_total_retained_provider_fact_rows: int = 2_097_152
    max_total_dependency_edges: int = 4_194_304


DEFAULT_PUBLICATION_CAPTURE_LIMITS = PublicationCaptureVerifierLimits()


@dataclass(slots=True)
class _Budget:
    limits: PublicationCaptureVerifierLimits
    input_bytes: int = 0
    decoded_bytes: int = 0
    json_nodes: int = 0
    retained_provider_fact_rows: int = 0
    dependency_edges: int = 0

    def add_input(self, amount: int, path: str) -> None:
        self.input_bytes += amount
        require(
            self.input_bytes <= self.limits.max_total_input_bytes,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate canonical input bytes exceed the closed verifier budget",
        )

    def add_decoded(self, amount: int, path: str) -> None:
        self.decoded_bytes += amount
        require(
            self.decoded_bytes <= self.limits.max_total_decoded_bytes,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate decoded artifact bytes exceed the closed verifier budget",
        )

    def add_json_nodes(self, amount: int, path: str) -> None:
        self.json_nodes += amount
        require(
            self.json_nodes <= self.limits.max_json_nodes,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate JSON nodes exceed the closed verifier budget",
        )

    def add_provider_fact_rows(self, amount: int, path: str) -> None:
        self.retained_provider_fact_rows += amount
        require(
            self.retained_provider_fact_rows
            <= self.limits.max_total_retained_provider_fact_rows,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate retained provider fact rows exceed the closed verifier budget",
        )

    def add_dependency_edges(self, amount: int, path: str) -> None:
        self.dependency_edges += amount
        require(
            self.dependency_edges <= self.limits.max_total_dependency_edges,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate dependency edges exceed the closed verifier budget",
        )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedProviderCaptureClosure(FactoryVerified):
    """One provider capture replayed from both retained representations."""

    provider_id: str
    provider_version: int
    provider_definition_digest: str
    covered_device_uids: tuple[str, ...]
    output_document: Mapping[str, Any]
    output_canonical_bytes: bytes
    output_bytes_sha256: str
    semantic_facts_document: Mapping[str, Any]
    semantic_facts_canonical_bytes: bytes
    semantic_facts_digest: str
    pci_binding_device_uids: tuple[str, ...]


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotCaptureClosureContext(FactoryVerified):
    """Immutable, replayable component result for one candidate capture."""

    limits: PublicationCaptureVerifierLimits
    algorithm_identity: Mapping[str, Any]
    algorithm_identity_canonical_bytes: bytes
    algorithm_identity_digest: str
    capability_policy: VerifiedCapabilityPolicy
    capture_batch_artifact: Mapping[str, Any]
    capture_batch_artifact_canonical_bytes: bytes
    capture_batch: Mapping[str, Any]
    capture_batch_canonical_bytes: bytes
    capture_batch_digest: str
    candidate_snapshot_epoch: int
    candidate_resource_version: int
    coordinate_authority_disposition: str
    freshness_policy_artifact: Mapping[str, Any]
    freshness_policy_artifact_canonical_bytes: bytes
    freshness_policy: Mapping[str, Any]
    freshness_policy_canonical_bytes: bytes
    freshness_policy_hash: str
    device_record_artifact_canonical_bytes: tuple[bytes, ...]
    candidate_device_records: VerifiedCandidateDeviceRecordSet
    snapshot_semantics: VerifiedHostSnapshotSemantics
    provider_captures: tuple[VerifiedProviderCaptureClosure, ...]
    no_change_projection: Mapping[str, Any]
    oldest_mandatory_evidence_observed_at: datetime
    freshness_time_basis: str
    verification_receipt: Mapping[str, Any]
    verification_receipt_canonical_bytes: bytes
    context_digest: str
    authority_boundary: str
    authority_disposition: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]


def _clone_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _clone_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clone_json(item) for item in value]
    return value


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
    value: PublicationCaptureVerifierLimits | None,
) -> PublicationCaptureVerifierLimits:
    limits = value or DEFAULT_PUBLICATION_CAPTURE_LIMITS
    require(
        isinstance(limits, PublicationCaptureVerifierLimits),
        "PUBLICATION_CAPTURE_INPUT_INVALID",
        "limits",
        "expected PublicationCaptureVerifierLimits",
    )
    hard = DEFAULT_PUBLICATION_CAPTURE_LIMITS
    for field in fields(PublicationCaptureVerifierLimits):
        actual = getattr(limits, field.name)
        ceiling = getattr(hard, field.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "PUBLICATION_CAPTURE_LIMIT_INVALID",
            f"limits.{field.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {ceiling}"
            ),
        )
    return limits


def _preflight_json(
    value: Any,
    *,
    budget: _Budget,
    path: str,
) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        budget.json_nodes += 1
        require(
            budget.json_nodes <= budget.limits.max_json_nodes,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate JSON nodes exceed the closed verifier budget",
        )
        require(
            depth <= budget.limits.max_json_depth,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "JSON nesting depth exceeds the closed verifier budget",
        )
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)


def _document(
    value: JsonDocument,
    *,
    path: str,
    max_bytes: int,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, Mapping):
            remaining_bytes = min(
                max_bytes,
                budget.limits.max_total_input_bytes - budget.input_bytes,
            )
            remaining_nodes = budget.limits.max_json_nodes - budget.json_nodes
            require(
                remaining_bytes >= 1 and remaining_nodes >= 1,
                "PUBLICATION_CAPTURE_TOO_LARGE",
                path,
                "aggregate canonical input budget is exhausted",
            )
            measured_bytes, measured_nodes = measure_canonical_json(
                value,
                max_bytes=remaining_bytes,
                max_nodes=remaining_nodes,
                max_depth=budget.limits.max_json_depth,
            )
            budget.add_input(measured_bytes, path)
            budget.add_json_nodes(measured_nodes, path)
            raw = canonical_json_bytes(value)
            require(
                len(raw) == measured_bytes,
                "PUBLICATION_CAPTURE_CANONICAL_BYTES_INVALID",
                path,
                "bounded canonical measurement differs from encoded bytes",
            )
            loaded = load_canonical_json(raw)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw_size = memoryview(value).nbytes
            require(
                raw_size <= max_bytes,
                "PUBLICATION_CAPTURE_TOO_LARGE",
                path,
                f"canonical artifact exceeds the {max_bytes}-byte limit",
            )
            budget.add_input(raw_size, path)
            raw = bytes(value)
            loaded = load_canonical_json(raw)
            _preflight_json(loaded, budget=budget, path=path)
        else:
            raise TypeError("expected canonical JSON bytes or a JSON mapping")
    except DirectPathVerificationError:
        raise
    except CanonicalJsonLimitError as exc:
        fail(
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            str(exc),
        )
    except (
        CanonicalizationError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        fail(
            "PUBLICATION_CAPTURE_CANONICAL_BYTES_INVALID",
            path,
            f"cannot load exact CANONICAL-JSON-V1 artifact: {exc}",
        )
    require(
        isinstance(loaded, dict),
        "PUBLICATION_CAPTURE_ARTIFACT_INVALID",
        path,
        "artifact must encode one JSON object",
    )
    return loaded, raw


def _decode_canonical_object(
    encoded: Any,
    *,
    path: str,
    max_bytes: int,
    budget: _Budget,
) -> tuple[bytes, dict[str, Any]]:
    require(
        isinstance(encoded, str),
        "PUBLICATION_CAPTURE_BASE64_INVALID",
        path,
        "expected padded RFC 4648 base64 text",
    )
    maximum_encoded = ((max_bytes + 2) // 3) * 4
    require(
        0 < len(encoded) <= maximum_encoded,
        "PUBLICATION_CAPTURE_TOO_LARGE",
        path,
        f"encoded artifact exceeds the {max_bytes}-decoded-byte limit",
    )
    require(
        len(encoded) % 4 == 0,
        "PUBLICATION_CAPTURE_BASE64_INVALID",
        path,
        "base64 length must be a multiple of four",
    )
    padding = 2 if encoded.endswith("==") else 1 if encoded.endswith("=") else 0
    expected_decoded_size = (len(encoded) // 4) * 3 - padding
    require(
        0 < expected_decoded_size <= max_bytes,
        "PUBLICATION_CAPTURE_TOO_LARGE",
        path,
        f"decoded artifact exceeds the {max_bytes}-byte limit",
    )
    budget.add_decoded(expected_decoded_size, path)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        fail(
            "PUBLICATION_CAPTURE_BASE64_INVALID",
            path,
            f"invalid strict base64: {exc}",
        )
    require(
        raw
        and len(raw) == expected_decoded_size
        and base64.b64encode(raw).decode("ascii") == encoded,
        "PUBLICATION_CAPTURE_BASE64_INVALID",
        path,
        "base64 must be the exact non-empty padded RFC 4648 representation",
    )
    try:
        loaded = load_canonical_json(raw)
    except (CanonicalizationError, RecursionError) as exc:
        fail(
            "PUBLICATION_CAPTURE_CANONICAL_BYTES_INVALID",
            path,
            f"decoded bytes are not exact CANONICAL-JSON-V1: {exc}",
        )
    _preflight_json(loaded, budget=budget, path=path)
    require(
        isinstance(loaded, dict),
        "PUBLICATION_CAPTURE_ARTIFACT_INVALID",
        path,
        "decoded artifact must be one JSON object",
    )
    return raw, loaded


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "PUBLICATION_CAPTURE_TIME_INVALID",
        path,
        "expected the contract timestamp string",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail(
            "PUBLICATION_CAPTURE_TIME_INVALID",
            path,
            f"invalid contract timestamp: {exc}",
        )
    return parsed.replace(tzinfo=timezone.utc)


def _digest_subject(
    domain: bytes,
    document: Mapping[str, Any],
    digest_field: str,
) -> str:
    projection = copy.deepcopy(dict(document))
    projection[digest_field] = None
    return sha256_digest(domain + canonical_json_bytes(projection))


def _require_equal(
    actual: Any,
    expected: Any,
    *,
    code: str,
    path: str,
    description: str,
) -> None:
    require(
        actual == expected,
        code,
        path,
        f"{description}; expected {expected!r}, got {actual!r}",
    )


def _require_canonical_set(
    values: Sequence[Any],
    *,
    path: str,
    order_key: Any,
    unique_key: Any | None = None,
) -> None:
    order_bytes = [canonical_json_bytes(order_key(item)) for item in values]
    require(
        order_bytes == sorted(order_bytes),
        "PUBLICATION_CAPTURE_NONCANONICAL_SET",
        path,
        "members are not in ascending CANONICAL-JSON-V1 key order",
    )
    selector = unique_key or order_key
    unique_bytes = [canonical_json_bytes(selector(item)) for item in values]
    require(
        len(unique_bytes) == len(set(unique_bytes)),
        "PUBLICATION_CAPTURE_DUPLICATE_SET_MEMBER",
        path,
        "members contain a duplicate semantic set key",
    )


def _provider_key(value: Mapping[str, Any]) -> tuple[str, int, str]:
    return (
        value["providerId"],
        value["providerVersion"],
        value["providerDefinitionDigest"],
    )


def _provider_key_json(value: Mapping[str, Any]) -> list[Any]:
    return list(_provider_key(value))


def _provider_fact_order_key(value: Mapping[str, Any]) -> list[Any]:
    return [
        value["factId"],
        value["providerId"],
        value["providerVersion"],
        value["evidenceHash"],
    ]


def _bounded_array_length(
    value: Any,
    *,
    path: str,
    maximum: int,
    minimum: int = 0,
) -> int | None:
    if not isinstance(value, list):
        return None
    require(
        minimum <= len(value) <= maximum,
        "PUBLICATION_CAPTURE_TOO_LARGE",
        path,
        f"array length is outside the closed {minimum}..{maximum} budget",
    )
    return len(value)


def _preflight_capture_batch_collections(
    batch: Mapping[str, Any],
    *,
    limits: PublicationCaptureVerifierLimits,
) -> None:
    providers = batch.get("providerCaptures")
    if isinstance(providers, list):
        _bounded_array_length(
            providers,
            path="publicationCapture.captureBatch.providerCaptures",
            minimum=1,
            maximum=limits.max_provider_captures,
        )
        aggregate_bindings = 0
        for index, provider in enumerate(providers):
            if not isinstance(provider, Mapping):
                continue
            _bounded_array_length(
                provider.get("coveredDeviceUids"),
                path=(
                    "publicationCapture.captureBatch."
                    f"providerCaptures[{index}].coveredDeviceUids"
                ),
                minimum=1,
                maximum=limits.max_device_records,
            )
            binding_count = _bounded_array_length(
                provider.get("deviceFactBindings"),
                path=(
                    "publicationCapture.captureBatch."
                    f"providerCaptures[{index}].deviceFactBindings"
                ),
                maximum=limits.max_pci_bindings,
            )
            if binding_count is not None:
                aggregate_bindings += binding_count
                require(
                    aggregate_bindings <= limits.max_pci_bindings,
                    "PUBLICATION_CAPTURE_TOO_LARGE",
                    "publicationCapture.captureBatch.providerCaptures",
                    "aggregate PCI bindings exceed the closed verifier budget",
                )

    topology = batch.get("topologyProjection")
    if isinstance(topology, Mapping):
        _bounded_array_length(
            topology.get("members"),
            path="publicationCapture.captureBatch.topologyProjection.members",
            minimum=1,
            maximum=limits.max_device_records,
        )
    provider_projection = batch.get("providerSemanticProjection")
    if isinstance(provider_projection, Mapping):
        projected = provider_projection.get("providers")
        if isinstance(projected, list):
            _bounded_array_length(
                projected,
                path=(
                    "publicationCapture.captureBatch."
                    "providerSemanticProjection.providers"
                ),
                minimum=1,
                maximum=limits.max_provider_captures,
            )
            for index, provider in enumerate(projected):
                if isinstance(provider, Mapping):
                    _bounded_array_length(
                        provider.get("coveredDeviceUids"),
                        path=(
                            "publicationCapture.captureBatch."
                            "providerSemanticProjection."
                            f"providers[{index}].coveredDeviceUids"
                        ),
                        minimum=1,
                        maximum=limits.max_device_records,
                    )


def _preflight_freshness_policy_collections(
    policy: Mapping[str, Any],
    *,
    limits: PublicationCaptureVerifierLimits,
) -> None:
    _bounded_array_length(
        policy.get("mandatoryProviderFacts"),
        path="publicationCapture.freshnessPolicy.mandatoryProviderFacts",
        minimum=1,
        maximum=limits.max_mandatory_provider_facts,
    )


def _preflight_provider_envelope_collections(
    envelope: Mapping[str, Any],
    *,
    path: str,
    limits: PublicationCaptureVerifierLimits,
    budget: _Budget,
) -> None:
    rows = envelope.get("deviceRows")
    if not isinstance(rows, list):
        return
    _bounded_array_length(
        rows,
        path=f"{path}.deviceRows",
        minimum=1,
        maximum=limits.max_device_records,
    )
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        fact_count = _bounded_array_length(
            row.get("providerFacts"),
            path=f"{path}.deviceRows[{index}].providerFacts",
            minimum=1,
            maximum=limits.max_provider_facts_per_device,
        )
        if fact_count is not None:
            budget.add_provider_fact_rows(
                fact_count,
                f"{path}.deviceRows[{index}].providerFacts",
            )


def _preflight_device_record_dependencies(
    record: Mapping[str, Any],
    *,
    path: str,
    budget: _Budget,
) -> None:
    domains = record.get("dependencyDomains")
    if not isinstance(domains, list):
        return
    for index, domain in enumerate(domains):
        if not isinstance(domain, Mapping):
            continue
        edges = domain.get("edges")
        if isinstance(edges, list):
            budget.add_dependency_edges(
                len(edges),
                f"{path}.dependencyDomains[{index}].edges",
            )


def _verify_capture_batch_artifact(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    limits: PublicationCaptureVerifierLimits,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    path = "publicationCapture.captureBatchArtifact"
    artifact, artifact_raw = _document(
        value,
        path=path,
        max_bytes=limits.max_capture_artifact_bytes,
        budget=budget,
    )
    artifact_instance = artifact.get("instance")
    if isinstance(artifact_instance, Mapping):
        _preflight_capture_batch_collections(
            artifact_instance,
            limits=limits,
        )
    schemas.validate_ref(
        HOST_SNAPSHOT_CAPTURE_BATCH_ARTIFACT_SCHEMA_REF,
        artifact,
        path,
    )
    batch_raw, batch = _decode_canonical_object(
        artifact["canonicalCaptureBatchBase64"],
        path=f"{path}.canonicalCaptureBatchBase64",
        max_bytes=limits.max_decoded_capture_batch_bytes,
        budget=budget,
    )
    _preflight_capture_batch_collections(batch, limits=limits)
    schemas.validate_ref(
        HOST_SNAPSHOT_CAPTURE_BATCH_SCHEMA_REF,
        batch,
        "publicationCapture.captureBatch",
    )
    _require_equal(
        batch,
        artifact["instance"],
        code="PUBLICATION_CAPTURE_ARTIFACT_BINDING_MISMATCH",
        path=f"{path}.instance",
        description="captureBatch instance is not the decoded retained bytes",
    )
    _require_equal(
        artifact["canonicalBytesSha256"],
        sha256_digest(batch_raw),
        code="PUBLICATION_CAPTURE_HASH_MISMATCH",
        path=f"{path}.canonicalBytesSha256",
        description="captureBatch canonical byte hash mismatch",
    )
    _require_equal(
        batch["captureBatchDigest"],
        _digest_subject(
            _CAPTURE_BATCH_DOMAIN,
            batch,
            "captureBatchDigest",
        ),
        code="PUBLICATION_CAPTURE_BATCH_DIGEST_INVALID",
        path="publicationCapture.captureBatch.captureBatchDigest",
        description="capture batch digest does not bind the complete batch",
    )
    return artifact, artifact_raw, batch, batch_raw


def _verify_freshness_policy_artifact(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    limits: PublicationCaptureVerifierLimits,
    budget: _Budget,
) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    path = "publicationCapture.freshnessPolicyArtifact"
    artifact, artifact_raw = _document(
        value,
        path=path,
        max_bytes=limits.max_device_record_artifact_bytes,
        budget=budget,
    )
    artifact_state = artifact.get("state")
    if isinstance(artifact_state, Mapping):
        _preflight_freshness_policy_collections(
            artifact_state,
            limits=limits,
        )
    schemas.validate_ref(
        HOST_SNAPSHOT_FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF,
        artifact,
        path,
    )
    policy_raw, policy = _decode_canonical_object(
        artifact["canonicalInstanceBase64"],
        path=f"{path}.canonicalInstanceBase64",
        max_bytes=limits.max_device_record_artifact_bytes,
        budget=budget,
    )
    _preflight_freshness_policy_collections(policy, limits=limits)
    schemas.validate_ref(
        HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF + "#/$defs/freshnessPolicy",
        policy,
        "publicationCapture.freshnessPolicy",
    )
    _require_equal(
        policy,
        artifact["state"],
        code="PUBLICATION_CAPTURE_ARTIFACT_BINDING_MISMATCH",
        path=f"{path}.state",
        description="freshness policy state is not the decoded retained bytes",
    )
    _require_equal(
        artifact["instanceBytesSha256"],
        sha256_digest(policy_raw),
        code="PUBLICATION_CAPTURE_HASH_MISMATCH",
        path=f"{path}.instanceBytesSha256",
        description="freshness policy canonical byte hash mismatch",
    )
    _require_equal(
        policy["policyHash"],
        _digest_subject(_FRESHNESS_POLICY_DOMAIN, policy, "policyHash"),
        code="PUBLICATION_CAPTURE_FRESHNESS_POLICY_INVALID",
        path="publicationCapture.freshnessPolicy.policyHash",
        description="freshness policy hash mismatch",
    )
    _require_canonical_set(
        policy["mandatoryProviderFacts"],
        path="publicationCapture.freshnessPolicy.mandatoryProviderFacts",
        order_key=lambda item: [item["providerId"], item["factId"]],
    )
    return artifact, artifact_raw, policy, policy_raw


def _verify_device_record_artifacts(
    schemas: ContractSchemas,
    values: Sequence[JsonDocument],
    *,
    batch: Mapping[str, Any],
    limits: PublicationCaptureVerifierLimits,
    budget: _Budget,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[bytes, ...],
    tuple[dict[str, Any], ...],
]:
    path = "publicationCapture.deviceRecordArtifacts"
    require(
        isinstance(values, Sequence)
        and not isinstance(values, (str, bytes, bytearray, memoryview)),
        "PUBLICATION_CAPTURE_INPUT_INVALID",
        path,
        "expected the complete sequence of DeviceRecord artifacts",
    )
    require(
        1 <= len(values) <= limits.max_device_records,
        "PUBLICATION_CAPTURE_TOO_LARGE",
        path,
        (
            "DeviceRecord artifact count is outside the closed "
            f"1..{limits.max_device_records} budget"
        ),
    )
    artifacts: list[dict[str, Any]] = []
    artifact_raws: list[bytes] = []
    records: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        artifact_path = f"{path}[{index}]"
        artifact, artifact_raw = _document(
            value,
            path=artifact_path,
            max_bytes=limits.max_device_record_artifact_bytes,
            budget=budget,
        )
        schemas.validate_ref(
            HOST_SNAPSHOT_DEVICE_RECORD_ARTIFACT_SCHEMA_REF,
            artifact,
            artifact_path,
        )
        record_raw, record = _decode_canonical_object(
            artifact["canonicalInstanceBase64"],
            path=f"{artifact_path}.canonicalInstanceBase64",
            max_bytes=limits.max_device_record_artifact_bytes,
            budget=budget,
        )
        _preflight_device_record_dependencies(
            record,
            path=f"{artifact_path}.record",
            budget=budget,
        )
        schemas.validate_ref(
            (
                "contracts/directpath-portable-entities.schema.json"
                "#/$defs/ENTITY-DEVICE-RECORD"
            ),
            record,
            f"{artifact_path}.record",
        )
        _require_equal(
            artifact["instanceBytesSha256"],
            sha256_digest(record_raw),
            code="PUBLICATION_CAPTURE_HASH_MISMATCH",
            path=f"{artifact_path}.instanceBytesSha256",
            description="DeviceRecord canonical byte hash mismatch",
        )
        generations = record["generations"]
        expected_binding = {
            "hostId": record["hostId"],
            "deviceUid": record["deviceUid"],
            "hostEpoch": generations["hostEpoch"],
            "agentGeneration": generations["agentGeneration"],
            "snapshotEpoch": generations["snapshotEpoch"],
            "deviceGeneration": generations["deviceGeneration"],
            "resourceVersion": generations["resourceVersion"],
            "deviceRecordHash": record["deviceRecordHash"],
        }
        _require_equal(
            artifact["recordBinding"],
            expected_binding,
            code="PUBLICATION_CAPTURE_ARTIFACT_BINDING_MISMATCH",
            path=f"{artifact_path}.recordBinding",
            description="recordBinding is not the exact DeviceRecord projection",
        )
        _require_equal(
            generations["deviceGeneration"],
            generations["snapshotEpoch"],
            code="PUBLICATION_CAPTURE_COORDINATE_MISMATCH",
            path=f"{artifact_path}.record.generations.deviceGeneration",
            description=(
                "a committed-row candidate must stamp deviceGeneration "
                "equal to snapshotEpoch"
            ),
        )
        _require_equal(
            record["provenance"]["captureStartedAt"],
            batch["captureStartedAt"],
            code="PUBLICATION_CAPTURE_INTERVAL_INVALID",
            path=f"{artifact_path}.record.provenance.captureStartedAt",
            description="DeviceRecord capture start differs from the batch",
        )
        _require_equal(
            record["provenance"]["capturedAt"],
            batch["captureCompletedAt"],
            code="PUBLICATION_CAPTURE_INTERVAL_INVALID",
            path=f"{artifact_path}.record.provenance.capturedAt",
            description="DeviceRecord capture completion differs from the batch",
        )
        artifacts.append(artifact)
        artifact_raws.append(artifact_raw)
        records.append(record)

    _require_canonical_set(
        artifacts,
        path=path,
        order_key=lambda item: item["recordBinding"]["deviceUid"],
        unique_key=lambda item: item["recordBinding"]["deviceUid"],
    )
    snapshot_epochs = {
        artifact["recordBinding"]["snapshotEpoch"] for artifact in artifacts
    }
    require(
        len(snapshot_epochs) == 1,
        "PUBLICATION_CAPTURE_RECORD_SET_MISMATCH",
        path,
        "candidate DeviceRecords do not share one snapshotEpoch",
    )
    resource_versions = {
        artifact["recordBinding"]["resourceVersion"] for artifact in artifacts
    }
    require(
        len(resource_versions) == 1,
        "PUBLICATION_CAPTURE_COORDINATE_MISMATCH",
        path,
        "candidate DeviceRecords do not share one resourceVersion",
    )
    return tuple(artifacts), tuple(artifact_raws), tuple(records)


def _require_provider_envelope_metadata(
    envelope: Mapping[str, Any],
    provider: Mapping[str, Any],
    batch: Mapping[str, Any],
    *,
    path: str,
) -> None:
    expected = {
        "collectionBarrierId": batch["collectionBarrierId"],
        "hostId": batch["hostId"],
        "kernelBootId": batch["kernelBootId"],
        "hostEpoch": batch["hostEpoch"],
        "agentIdentity": batch["agentIdentity"],
        "agentGeneration": batch["agentGeneration"],
        "providerId": provider["providerId"],
        "providerVersion": provider["providerVersion"],
        "providerDefinitionDigest": provider["providerDefinitionDigest"],
        "captureStartedAt": provider["captureStartedAt"],
        "captureCompletedAt": provider["captureCompletedAt"],
    }
    for field_name, expected_value in expected.items():
        _require_equal(
            envelope[field_name],
            expected_value,
            code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
            path=f"{path}.{field_name}",
            description="provider envelope metadata mismatch",
        )


def _verify_provider_captures(
    schemas: ContractSchemas,
    *,
    batch: Mapping[str, Any],
    records: VerifiedCandidateDeviceRecordSet,
    limits: PublicationCaptureVerifierLimits,
    budget: _Budget,
) -> tuple[VerifiedProviderCaptureClosure, ...]:
    provider_captures = batch["providerCaptures"]
    path = "publicationCapture.captureBatch.providerCaptures"
    require(
        1 <= len(provider_captures) <= limits.max_provider_captures,
        "PUBLICATION_CAPTURE_TOO_LARGE",
        path,
        (
            "provider count is outside the closed "
            f"1..{limits.max_provider_captures} budget"
        ),
    )
    _require_canonical_set(
        provider_captures,
        path=path,
        order_key=_provider_key_json,
        unique_key=_provider_key_json,
    )

    facts_by_provider: dict[
        tuple[str, int, str],
        dict[str, list[dict[str, Any]]],
    ] = {}
    pci_provider_by_uid: dict[str, tuple[str, int, str]] = {}
    pci_fact_by_uid: dict[str, dict[str, Any]] = {}
    for record in records.device_records:
        document = _thaw_json(record.document)
        uid = record.device_uid
        facts = document["provenance"]["providerFacts"]
        for fact in facts:
            facts_by_provider.setdefault(_provider_key(fact), {}).setdefault(
                uid,
                [],
            ).append(fact)
        pci_fact_id = document["role"]["pciStructureFact"]["providerFactId"]
        matches = [fact for fact in facts if fact["factId"] == pci_fact_id]
        require(
            len(matches) == 1,
            "PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
            f"{path}.records[{uid!r}].providerFacts",
            "PCI structure providerFactId must resolve exactly once",
        )
        pci_fact_by_uid[uid] = matches[0]
        pci_provider_by_uid[uid] = _provider_key(matches[0])

    expected_provider_keys = set(facts_by_provider)
    actual_provider_keys = {_provider_key(item) for item in provider_captures}
    _require_equal(
        actual_provider_keys,
        expected_provider_keys,
        code="PUBLICATION_CAPTURE_PROVIDER_COVERAGE_MISMATCH",
        path=path,
        description=(
            "provider captures are not the exact provider identity set "
            "derived from DeviceRecord provenance"
        ),
    )

    batch_started = _timestamp(
        batch["captureStartedAt"],
        "publicationCapture.captureBatch.captureStartedAt",
    )
    batch_completed = _timestamp(
        batch["captureCompletedAt"],
        "publicationCapture.captureBatch.captureCompletedAt",
    )
    require(
        batch_started <= batch_completed,
        "PUBLICATION_CAPTURE_INTERVAL_INVALID",
        "publicationCapture.captureBatch",
        "captureStartedAt cannot be later than captureCompletedAt",
    )

    verified: list[VerifiedProviderCaptureClosure] = []
    global_binding_uids: set[str] = set()
    global_binding_bdfs: set[str] = set()
    aggregate_bindings = 0
    for provider_index, provider in enumerate(provider_captures):
        provider_path = f"{path}[{provider_index}]"
        key = _provider_key(provider)
        provider_started = _timestamp(
            provider["captureStartedAt"],
            f"{provider_path}.captureStartedAt",
        )
        provider_completed = _timestamp(
            provider["captureCompletedAt"],
            f"{provider_path}.captureCompletedAt",
        )
        require(
            batch_started <= provider_started <= provider_completed <= batch_completed,
            "PUBLICATION_CAPTURE_INTERVAL_INVALID",
            provider_path,
            "provider capture interval lies outside the batch interval",
        )
        require(
            provider["outputSchemaRef"] == HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF,
            "PUBLICATION_CAPTURE_PROVIDER_SCHEMA_UNSUPPORTED",
            f"{provider_path}.outputSchemaRef",
            (
                "the executable component profile requires the fixed portable "
                "provider output envelope"
            ),
        )
        require(
            provider["semanticFactsSchemaRef"]
            == HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF,
            "PUBLICATION_CAPTURE_PROVIDER_SCHEMA_UNSUPPORTED",
            f"{provider_path}.semanticFactsSchemaRef",
            (
                "the executable component profile requires the fixed portable "
                "provider semantic-facts envelope"
            ),
        )
        output_raw, output = _decode_canonical_object(
            provider["canonicalOutputBase64"],
            path=f"{provider_path}.canonicalOutputBase64",
            max_bytes=limits.max_decoded_provider_artifact_bytes,
            budget=budget,
        )
        semantic_raw, semantic = _decode_canonical_object(
            provider["semanticFactsBase64"],
            path=f"{provider_path}.semanticFactsBase64",
            max_bytes=limits.max_decoded_provider_artifact_bytes,
            budget=budget,
        )
        _preflight_provider_envelope_collections(
            output,
            path=f"{provider_path}.output",
            limits=limits,
            budget=budget,
        )
        _preflight_provider_envelope_collections(
            semantic,
            path=f"{provider_path}.semanticFacts",
            limits=limits,
            budget=budget,
        )
        schemas.validate_ref(
            HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF,
            output,
            f"{provider_path}.output",
        )
        schemas.validate_ref(
            HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF,
            semantic,
            f"{provider_path}.semanticFacts",
        )
        _require_equal(
            provider["outputBytesSha256"],
            sha256_digest(output_raw),
            code="PUBLICATION_CAPTURE_HASH_MISMATCH",
            path=f"{provider_path}.outputBytesSha256",
            description="provider output byte hash mismatch",
        )
        _require_equal(
            provider["semanticFactsDigest"],
            sha256_digest(_PROVIDER_SEMANTIC_FACTS_DOMAIN + semantic_raw),
            code="PUBLICATION_CAPTURE_HASH_MISMATCH",
            path=f"{provider_path}.semanticFactsDigest",
            description="provider semantic-facts digest mismatch",
        )
        _require_provider_envelope_metadata(
            output,
            provider,
            batch,
            path=f"{provider_path}.output",
        )
        _require_provider_envelope_metadata(
            semantic,
            provider,
            batch,
            path=f"{provider_path}.semanticFacts",
        )

        expected_uid_facts = facts_by_provider[key]
        expected_uids = sorted(expected_uid_facts, key=canonical_json_bytes)
        _require_equal(
            provider["coveredDeviceUids"],
            expected_uids,
            code="PUBLICATION_CAPTURE_PROVIDER_COVERAGE_MISMATCH",
            path=f"{provider_path}.coveredDeviceUids",
            description="provider coverage differs from DeviceRecord provenance",
        )
        _require_canonical_set(
            provider["coveredDeviceUids"],
            path=f"{provider_path}.coveredDeviceUids",
            order_key=lambda item: item,
        )

        output_rows = output["deviceRows"]
        semantic_rows = semantic["deviceRows"]
        _require_canonical_set(
            output_rows,
            path=f"{provider_path}.output.deviceRows",
            order_key=lambda item: [item["deviceUid"], item["currentBdf"]],
            unique_key=lambda item: item["deviceUid"],
        )
        _require_canonical_set(
            semantic_rows,
            path=f"{provider_path}.semanticFacts.deviceRows",
            order_key=lambda item: [item["deviceUid"], item["currentBdf"]],
            unique_key=lambda item: item["deviceUid"],
        )
        output_by_uid = {row["deviceUid"]: row for row in output_rows}
        semantic_by_uid = {row["deviceUid"]: row for row in semantic_rows}
        _require_equal(
            sorted(output_by_uid, key=canonical_json_bytes),
            expected_uids,
            code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
            path=f"{provider_path}.output.deviceRows",
            description="provider output row coverage mismatch",
        )
        _require_equal(
            sorted(semantic_by_uid, key=canonical_json_bytes),
            expected_uids,
            code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
            path=f"{provider_path}.semanticFacts.deviceRows",
            description="provider semantic row coverage mismatch",
        )

        bindings = provider["deviceFactBindings"]
        aggregate_bindings += len(bindings)
        require(
            aggregate_bindings <= limits.max_pci_bindings,
            "PUBLICATION_CAPTURE_TOO_LARGE",
            path,
            "aggregate PCI bindings exceed the closed verifier budget",
        )
        _require_canonical_set(
            bindings,
            path=f"{provider_path}.deviceFactBindings",
            order_key=lambda item: [
                item["deviceUid"],
                item["currentBdf"],
                item["providerFact"]["factId"],
            ],
            unique_key=lambda item: item["deviceUid"],
        )
        for selector, label in (
            (
                lambda item: item["currentBdf"],
                "currentBdf",
            ),
            (
                lambda item: item["providerFact"]["factId"],
                "providerFact.factId",
            ),
            (
                lambda item: item["pciStructureFact"]["structureFactDigest"],
                "pciStructureFact.structureFactDigest",
            ),
            (
                lambda item: item["pciFlrCapabilityFact"]["flrFactDigest"],
                "pciFlrCapabilityFact.flrFactDigest",
            ),
        ):
            selected = [selector(item) for item in bindings]
            require(
                len(selected) == len(set(selected)),
                "PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                f"{provider_path}.deviceFactBindings",
                f"PCI bindings contain duplicate {label}",
            )
        bindings_by_uid = {item["deviceUid"]: item for item in bindings}

        pci_uids: list[str] = []
        for uid in expected_uids:
            record = records.device_records_by_uid[uid]
            record_document = _thaw_json(record.document)
            output_row = output_by_uid[uid]
            semantic_row = semantic_by_uid[uid]
            _require_equal(
                output_row["currentBdf"],
                record.current_bdf,
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=f"{provider_path}.output.deviceRows[{uid!r}].currentBdf",
                description="provider output row BDF mismatch",
            )
            _require_equal(
                semantic_row["currentBdf"],
                record.current_bdf,
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=(f"{provider_path}.semanticFacts.deviceRows[{uid!r}].currentBdf"),
                description="provider semantic row BDF mismatch",
            )
            expected_facts = sorted(
                expected_uid_facts[uid],
                key=lambda item: canonical_json_bytes(_provider_fact_order_key(item)),
            )
            _require_canonical_set(
                output_row["providerFacts"],
                path=f"{provider_path}.output.deviceRows[{uid!r}].providerFacts",
                order_key=_provider_fact_order_key,
                unique_key=lambda item: item["factId"],
            )
            _require_canonical_set(
                semantic_row["providerFacts"],
                path=(
                    f"{provider_path}.semanticFacts.deviceRows[{uid!r}].providerFacts"
                ),
                order_key=_provider_fact_order_key,
                unique_key=lambda item: item["factId"],
            )
            _require_equal(
                output_row["providerFacts"],
                expected_facts,
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=f"{provider_path}.output.deviceRows[{uid!r}].providerFacts",
                description="provider output facts differ from DeviceRecord",
            )
            _require_equal(
                semantic_row["providerFacts"],
                expected_facts,
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=(
                    f"{provider_path}.semanticFacts.deviceRows[{uid!r}].providerFacts"
                ),
                description="semantic facts differ from DeviceRecord",
            )
            for fact_index, fact in enumerate(expected_facts):
                observed_at = _timestamp(
                    fact["observedAt"],
                    (
                        f"{provider_path}.deviceRows[{uid!r}]"
                        f".providerFacts[{fact_index}].observedAt"
                    ),
                )
                require(
                    provider_started <= observed_at <= provider_completed,
                    "PUBLICATION_CAPTURE_INTERVAL_INVALID",
                    (
                        f"{provider_path}.deviceRows[{uid!r}]"
                        f".providerFacts[{fact_index}].observedAt"
                    ),
                    "provider fact lies outside its provider capture interval",
                )

            is_pci_provider = pci_provider_by_uid[uid] == key
            binding = bindings_by_uid.get(uid)
            raw_pci = output_row["pciConfigCaptureOrNull"]
            semantic_structure = semantic_row["pciStructureFactOrNull"]
            semantic_flr = semantic_row["pciFlrCapabilityFactOrNull"]
            if not is_pci_provider:
                require(
                    binding is None
                    and raw_pci is None
                    and semantic_structure is None
                    and semantic_flr is None,
                    "PUBLICATION_CAPTURE_PROVIDER_KIND_MISMATCH",
                    f"{provider_path}.deviceRows[{uid!r}]",
                    (
                        "a non-PCI provider row cannot carry a PCI binding "
                        "or PCI replay facts"
                    ),
                )
                continue

            require(
                binding is not None
                and raw_pci is not None
                and semantic_structure is not None
                and semantic_flr is not None,
                "PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                f"{provider_path}.deviceRows[{uid!r}]",
                "the record's PCI provider requires one complete PCI binding",
            )
            assert binding is not None
            assert raw_pci is not None
            assert semantic_structure is not None
            assert semantic_flr is not None
            pci_uids.append(uid)
            expected_pci_fact = pci_fact_by_uid[uid]
            _require_equal(
                binding["currentBdf"],
                record.current_bdf,
                code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                path=f"{provider_path}.deviceFactBindings[{uid!r}].currentBdf",
                description="PCI binding BDF mismatch",
            )
            _require_equal(
                binding["providerFact"],
                expected_pci_fact,
                code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                path=f"{provider_path}.deviceFactBindings[{uid!r}].providerFact",
                description="PCI binding provider fact mismatch",
            )
            _require_equal(
                binding["pciStructureFact"],
                record_document["role"]["pciStructureFact"],
                code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                path=(f"{provider_path}.deviceFactBindings[{uid!r}].pciStructureFact"),
                description="PCI structure binding differs from DeviceRecord",
            )
            _require_equal(
                binding["pciFlrCapabilityFact"],
                record_document["resetContract"]["pciFlrCapabilityFact"],
                code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                path=(
                    f"{provider_path}.deviceFactBindings[{uid!r}].pciFlrCapabilityFact"
                ),
                description="PCI FLR binding differs from DeviceRecord",
            )
            _require_equal(
                raw_pci["providerFactId"],
                expected_pci_fact["factId"],
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=(
                    f"{provider_path}.output.deviceRows"
                    f"[{uid!r}].pciConfigCaptureOrNull.providerFactId"
                ),
                description="raw PCI capture fact selector mismatch",
            )
            raw_hex = raw_pci["rawConfigSpaceHexOrNull"]
            raw_config = bytes.fromhex(raw_hex) if raw_hex is not None else None
            replayed = normalize_pci_config_capture(
                device_uid=uid,
                current_bdf=record.current_bdf,
                captured_at=raw_pci["observedAt"],
                provider_fact_id=raw_pci["providerFactId"],
                provider_id=provider["providerId"],
                provider_version=provider["providerVersion"],
                provider_definition_digest=provider["providerDefinitionDigest"],
                raw_config_space=raw_config,
                failure_reason_code=raw_pci["failureReasonCodeOrNull"],
            )
            _require_equal(
                _thaw_json(replayed.provider_fact),
                expected_pci_fact,
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=f"{provider_path}.output.deviceRows[{uid!r}]",
                description="raw PCI capture does not replay provider fact",
            )
            _require_equal(
                _thaw_json(replayed.structure_fact),
                binding["pciStructureFact"],
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=f"{provider_path}.output.deviceRows[{uid!r}]",
                description="raw PCI capture does not replay structure fact",
            )
            _require_equal(
                _thaw_json(replayed.flr_fact),
                binding["pciFlrCapabilityFact"],
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=f"{provider_path}.output.deviceRows[{uid!r}]",
                description="raw PCI capture does not replay FLR fact",
            )
            _require_equal(
                semantic_structure,
                binding["pciStructureFact"],
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=(
                    f"{provider_path}.semanticFacts.deviceRows"
                    f"[{uid!r}].pciStructureFactOrNull"
                ),
                description="semantic PCI structure fact mismatch",
            )
            _require_equal(
                semantic_flr,
                binding["pciFlrCapabilityFact"],
                code="PUBLICATION_CAPTURE_PROVIDER_REPLAY_MISMATCH",
                path=(
                    f"{provider_path}.semanticFacts.deviceRows"
                    f"[{uid!r}].pciFlrCapabilityFactOrNull"
                ),
                description="semantic PCI FLR fact mismatch",
            )
            require(
                uid not in global_binding_uids
                and record.current_bdf not in global_binding_bdfs,
                "PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
                path,
                "PCI binding union contains a duplicate UID or BDF",
            )
            global_binding_uids.add(uid)
            global_binding_bdfs.add(record.current_bdf)

        _require_equal(
            set(bindings_by_uid),
            set(pci_uids),
            code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
            path=f"{provider_path}.deviceFactBindings",
            description="provider PCI bindings are not the exact PCI row subset",
        )
        verified.append(
            VerifiedProviderCaptureClosure._construct(
                provider_id=provider["providerId"],
                provider_version=provider["providerVersion"],
                provider_definition_digest=provider["providerDefinitionDigest"],
                covered_device_uids=tuple(expected_uids),
                output_document=_freeze_json(output),
                output_canonical_bytes=output_raw,
                output_bytes_sha256=provider["outputBytesSha256"],
                semantic_facts_document=_freeze_json(semantic),
                semantic_facts_canonical_bytes=semantic_raw,
                semantic_facts_digest=provider["semanticFactsDigest"],
                pci_binding_device_uids=tuple(pci_uids),
            )
        )

    expected_all_uids = set(records.device_records_by_uid)
    _require_equal(
        global_binding_uids,
        expected_all_uids,
        code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
        path=path,
        description="PCI binding union is not an exact candidate-record bijection",
    )
    _require_equal(
        aggregate_bindings,
        len(expected_all_uids),
        code="PUBLICATION_CAPTURE_PCI_BIJECTION_INVALID",
        path=path,
        description="aggregate PCI binding count differs from record count",
    )
    return tuple(verified)


def _verify_freshness(
    *,
    freshness_policy: Mapping[str, Any],
    batch: Mapping[str, Any],
    records: VerifiedCandidateDeviceRecordSet,
) -> datetime:
    observations_by_selector: dict[tuple[str, str], list[datetime]] = {}
    for record in records.device_records:
        for fact_index, fact in enumerate(
            record.document["provenance"]["providerFacts"]
        ):
            key = (fact["providerId"], fact["factId"])
            observations_by_selector.setdefault(key, []).append(
                _timestamp(
                    fact["observedAt"],
                    (
                        "publicationCapture.candidateDeviceRecords"
                        f"[{record.device_uid!r}].provenance."
                        f"providerFacts[{fact_index}].observedAt"
                    ),
                )
            )

    selected_observations: list[datetime] = []
    for index, selector in enumerate(freshness_policy["mandatoryProviderFacts"]):
        matches = observations_by_selector.get(
            (selector["providerId"], selector["factId"]),
            (),
        )
        require(
            bool(matches),
            "PUBLICATION_CAPTURE_MANDATORY_FACT_MISSING",
            (f"publicationCapture.freshnessPolicy.mandatoryProviderFacts[{index}]"),
            "mandatory provider fact is absent from the candidate record set",
        )
        selected_observations.extend(matches)
    oldest = min(selected_observations)
    completed = _timestamp(
        batch["captureCompletedAt"],
        "publicationCapture.captureBatch.captureCompletedAt",
    )
    delta = completed - oldest
    age_micros = (
        delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    )
    require(
        0 <= age_micros <= freshness_policy["maximumMandatoryEvidenceAgeMicros"],
        "PUBLICATION_CAPTURE_MANDATORY_FACT_STALE",
        "publicationCapture.freshnessPolicy.maximumMandatoryEvidenceAgeMicros",
        ("oldest mandatory candidate evidence exceeds the configured maximum age"),
    )
    return oldest


def _limits_subject(
    limits: PublicationCaptureVerifierLimits,
) -> dict[str, int]:
    return {
        "maxCaptureArtifactBytes": limits.max_capture_artifact_bytes,
        "maxDecodedCaptureBatchBytes": limits.max_decoded_capture_batch_bytes,
        "maxDeviceRecordArtifactBytes": (limits.max_device_record_artifact_bytes),
        "maxDecodedProviderArtifactBytes": (limits.max_decoded_provider_artifact_bytes),
        "maxTotalInputBytes": limits.max_total_input_bytes,
        "maxTotalDecodedBytes": limits.max_total_decoded_bytes,
        "maxJsonNodes": limits.max_json_nodes,
        "maxJsonDepth": limits.max_json_depth,
        "maxDeviceRecords": limits.max_device_records,
        "maxProviderCaptures": limits.max_provider_captures,
        "maxPciBindings": limits.max_pci_bindings,
        "maxMandatoryProviderFacts": limits.max_mandatory_provider_facts,
        "maxProviderFactsPerDevice": limits.max_provider_facts_per_device,
        "maxTotalRetainedProviderFactRows": (
            limits.max_total_retained_provider_fact_rows
        ),
        "maxTotalDependencyEdges": limits.max_total_dependency_edges,
    }


def _derive_capture_verifier_algorithm_identity(
    schemas: ContractSchemas,
) -> tuple[dict[str, Any], bytes, str]:
    bindings = [
        {
            "schemaRef": schema_ref,
            "schemaDigest": schemas.digest_for_ref(
                schema_ref,
                path="publicationCapture.algorithmIdentity.schemaBindings",
            ),
        }
        for schema_ref in _CAPTURE_VERIFIER_SCHEMA_REFS
    ]
    bindings.sort(key=lambda item: canonical_json_bytes(item["schemaRef"]))
    identity = {
        "subjectType": "HOST_SNAPSHOT_CAPTURE_CLOSURE_VERIFIER_ALGORITHM",
        "schemaVersion": 1,
        "algorithmId": HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_ID,
        "identityKind": "COMPONENT_ALGORITHM_IDENTITY_NOT_BINARY_ATTESTATION",
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "digestAlgorithm": "SHA-256",
        "schemaBindings": bindings,
        "validationStages": list(_CAPTURE_VERIFIER_VALIDATION_STAGES),
        "algorithmIdentityDigest": None,
    }
    identity_digest = sha256_digest(
        _CAPTURE_ALGORITHM_IDENTITY_DOMAIN + canonical_json_bytes(identity)
    )
    identity["algorithmIdentityDigest"] = identity_digest
    schemas.validate_ref(
        HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_SCHEMA_REF,
        identity,
        "publicationCapture.algorithmIdentity",
    )
    identity_raw = canonical_json_bytes(identity)
    return identity, identity_raw, identity_digest


def verify_host_snapshot_capture_closure(
    schemas: ContractSchemas,
    capability_policy: VerifiedCapabilityPolicy,
    *,
    capture_batch_artifact: JsonDocument,
    freshness_policy_artifact: JsonDocument,
    device_record_artifacts: Sequence[JsonDocument],
    limits: PublicationCaptureVerifierLimits | None = None,
) -> VerifiedHostSnapshotCaptureClosureContext:
    """Replay a complete candidate capture from exact retained artifacts."""

    require(
        isinstance(schemas, ContractSchemas),
        "PUBLICATION_CAPTURE_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        capability_policy,
        VerifiedCapabilityPolicy,
        code="PUBLICATION_CAPTURE_POLICY_INVALID",
        path="publicationCapture.capabilityPolicy",
        message="capability policy must come from verify_capability_policy",
    )
    current_policy_schema_digest = schemas.digest_for_ref(
        CAPABILITY_POLICY_SCHEMA_REF,
        path="publicationCapture.capabilityPolicy.schemaDigest",
    )
    _require_equal(
        capability_policy.capability_policy_schema_digest,
        current_policy_schema_digest,
        code="PUBLICATION_CAPTURE_POLICY_SCHEMA_MISMATCH",
        path="publicationCapture.capabilityPolicy.schemaDigest",
        description=(
            "capability policy was verified under a different schema identity"
        ),
    )
    capability_policy = verify_capability_policy(
        schemas,
        capability_policy.canonical_bytes,
        verified_at=capability_policy.verified_at,
    )
    (
        algorithm_identity,
        algorithm_identity_raw,
        algorithm_identity_digest,
    ) = _derive_capture_verifier_algorithm_identity(schemas)
    checked_limits = _checked_limits(limits)
    budget = _Budget(checked_limits)

    (
        batch_artifact,
        batch_artifact_raw,
        batch,
        batch_raw,
    ) = _verify_capture_batch_artifact(
        schemas,
        capture_batch_artifact,
        limits=checked_limits,
        budget=budget,
    )
    (
        freshness_artifact,
        freshness_artifact_raw,
        freshness_policy,
        freshness_policy_raw,
    ) = _verify_freshness_policy_artifact(
        schemas,
        freshness_policy_artifact,
        limits=checked_limits,
        budget=budget,
    )
    (
        record_artifacts,
        record_artifact_raws,
        record_documents,
    ) = _verify_device_record_artifacts(
        schemas,
        device_record_artifacts,
        batch=batch,
        limits=checked_limits,
        budget=budget,
    )

    snapshot_epoch = record_artifacts[0]["recordBinding"]["snapshotEpoch"]
    candidate_resource_version = record_artifacts[0]["recordBinding"]["resourceVersion"]
    candidate_inventory_limits = InventoryVerifierLimits(
        max_document_bytes=checked_limits.max_device_record_artifact_bytes,
        max_total_input_bytes=checked_limits.max_total_decoded_bytes,
        max_json_nodes=checked_limits.max_json_nodes,
        max_json_depth=checked_limits.max_json_depth,
        max_candidate_device_records=checked_limits.max_device_records,
        max_total_dependency_edges=checked_limits.max_total_dependency_edges,
    )
    candidate_records = verify_candidate_device_record_set(
        schemas,
        record_documents,
        host_id=batch["hostId"],
        host_epoch=batch["hostEpoch"],
        agent_generation=batch["agentGeneration"],
        snapshot_epoch=snapshot_epoch,
        captured_at=batch["captureCompletedAt"],
        path_prefix="publicationCapture.candidateDeviceRecords",
        limits=candidate_inventory_limits,
    )
    provider_contexts = _verify_provider_captures(
        schemas,
        batch=batch,
        records=candidate_records,
        limits=checked_limits,
        budget=budget,
    )

    completed_at = _timestamp(
        batch["captureCompletedAt"],
        "publicationCapture.captureBatch.captureCompletedAt",
    )
    require(
        capability_policy.effective_at <= completed_at < capability_policy.expires_at,
        "PUBLICATION_CAPTURE_POLICY_INVALID",
        "publicationCapture.captureBatch.captureCompletedAt",
        "capability policy is not effective at capture completion",
    )
    semantic_snapshot = {
        "hostId": batch["hostId"],
        "kernelBootId": batch["kernelBootId"],
        "hostEpoch": batch["hostEpoch"],
        "agentGeneration": batch["agentGeneration"],
        "policyHash": capability_policy.policy_hash,
        "snapshotFreshnessPolicyHash": freshness_policy["policyHash"],
    }
    snapshot_semantics = derive_host_snapshot_semantics(
        semantic_snapshot,
        tuple(
            _thaw_json(record.document) for record in candidate_records.device_records
        ),
    )
    topology_projection = _thaw_json(snapshot_semantics.topology_projection)
    provider_projection = _thaw_json(snapshot_semantics.provider_semantic_projection)
    schemas.validate_ref(
        HOST_SNAPSHOT_TOPOLOGY_PROJECTION_SCHEMA_REF,
        topology_projection,
        "publicationCapture.derivedTopologyProjection",
    )
    schemas.validate_ref(
        HOST_SNAPSHOT_PROVIDER_PROJECTION_SCHEMA_REF,
        provider_projection,
        "publicationCapture.derivedProviderProjection",
    )
    _require_equal(
        batch["topologyProjection"],
        topology_projection,
        code="PUBLICATION_CAPTURE_DEVICE_PROJECTION_MISMATCH",
        path="publicationCapture.captureBatch.topologyProjection",
        description="stored topology projection does not replay from records",
    )
    _require_equal(
        batch["providerSemanticProjection"],
        provider_projection,
        code="PUBLICATION_CAPTURE_PROVIDER_PROJECTION_MISMATCH",
        path="publicationCapture.captureBatch.providerSemanticProjection",
        description="stored provider projection does not replay from records",
    )
    no_change_projection = derive_no_change_projection(
        snapshot=semantic_snapshot,
        agent_identity=batch["agentIdentity"],
        topology_digest=snapshot_semantics.topology_digest,
        provider_facts_digest=snapshot_semantics.provider_facts_digest,
    )
    schemas.validate_ref(
        HOST_SNAPSHOT_NO_CHANGE_PROJECTION_SCHEMA_REF,
        no_change_projection,
        "publicationCapture.derivedNoChangeProjection",
    )
    _require_equal(
        batch["noChangeProjection"],
        no_change_projection,
        code="PUBLICATION_CAPTURE_NO_CHANGE_PROJECTION_MISMATCH",
        path="publicationCapture.captureBatch.noChangeProjection",
        description="stored no-change projection does not replay",
    )
    oldest_mandatory = _verify_freshness(
        freshness_policy=freshness_policy,
        batch=batch,
        records=candidate_records,
    )

    provider_receipts = [
        {
            "providerId": provider.provider_id,
            "providerVersion": provider.provider_version,
            "providerDefinitionDigest": provider.provider_definition_digest,
            "coveredDeviceUids": list(provider.covered_device_uids),
            "outputBytesSha256": provider.output_bytes_sha256,
            "semanticFactsDigest": provider.semantic_facts_digest,
            "pciBindingDeviceUids": list(provider.pci_binding_device_uids),
        }
        for provider in provider_contexts
    ]
    record_receipts = [
        {
            "deviceUid": artifact["recordBinding"]["deviceUid"],
            "deviceRecordHash": artifact["recordBinding"]["deviceRecordHash"],
            "instanceBytesSha256": artifact["instanceBytesSha256"],
            "artifactCanonicalSha256": sha256_digest(artifact_raw),
        }
        for artifact, artifact_raw in zip(
            record_artifacts,
            record_artifact_raws,
            strict=True,
        )
    ]
    receipt = {
        "subjectType": "HOST_SNAPSHOT_CAPTURE_CLOSURE_VERIFICATION",
        "schemaVersion": 2,
        "algorithmId": HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_ID,
        "algorithmIdentity": algorithm_identity,
        "limits": _limits_subject(checked_limits),
        "captureBatchArtifactCanonicalSha256": sha256_digest(batch_artifact_raw),
        "captureBatchCanonicalSha256": sha256_digest(batch_raw),
        "captureBatchDigest": batch["captureBatchDigest"],
        "capabilityPolicyHash": capability_policy.policy_hash,
        "freshnessPolicyArtifactCanonicalSha256": sha256_digest(freshness_artifact_raw),
        "freshnessPolicyCanonicalSha256": sha256_digest(freshness_policy_raw),
        "freshnessPolicyHash": freshness_policy["policyHash"],
        "hostId": batch["hostId"],
        "kernelBootId": batch["kernelBootId"],
        "hostEpoch": batch["hostEpoch"],
        "agentIdentity": batch["agentIdentity"],
        "agentGeneration": batch["agentGeneration"],
        "candidateSnapshotEpoch": snapshot_epoch,
        "candidateResourceVersion": candidate_resource_version,
        "coordinateAuthorityDisposition": (
            "CALLER_STAMPED_CANDIDATE_REQUIRES_REPOSITORY_CAS"
        ),
        "captureStartedAt": batch["captureStartedAt"],
        "captureCompletedAt": batch["captureCompletedAt"],
        "freshnessTimeBasis": "CALLER_SUPPLIED_CAPTURE_COMPLETION",
        "oldestMandatoryEvidenceObservedAt": oldest_mandatory.strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        "deviceRecords": record_receipts,
        "providers": provider_receipts,
        "topologyDigest": snapshot_semantics.topology_digest,
        "providerFactsDigest": snapshot_semantics.provider_facts_digest,
        "noChangeProjectionHash": no_change_projection["noChangeProjectionHash"],
        "authorityBoundary": HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY,
        "authorityDisposition": HOST_SNAPSHOT_CAPTURE_AUTHORITY_DISPOSITION,
        "productAuthorized": HOST_SNAPSHOT_CAPTURE_PRODUCT_AUTHORIZED,
        "productEvidenceBlockers": list(
            HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = _digest_subject(
        _CAPTURE_CONTEXT_DOMAIN,
        receipt,
        "contextDigest",
    )
    receipt["contextDigest"] = context_digest
    schemas.validate_ref(
        HOST_SNAPSHOT_CAPTURE_CLOSURE_RECEIPT_SCHEMA_REF,
        receipt,
        "publicationCapture.verificationReceipt",
    )
    receipt_raw = canonical_json_bytes(receipt)

    return VerifiedHostSnapshotCaptureClosureContext._construct(
        limits=checked_limits,
        algorithm_identity=_freeze_json(algorithm_identity),
        algorithm_identity_canonical_bytes=algorithm_identity_raw,
        algorithm_identity_digest=algorithm_identity_digest,
        capability_policy=capability_policy,
        capture_batch_artifact=_freeze_json(batch_artifact),
        capture_batch_artifact_canonical_bytes=batch_artifact_raw,
        capture_batch=_freeze_json(batch),
        capture_batch_canonical_bytes=batch_raw,
        capture_batch_digest=batch["captureBatchDigest"],
        candidate_snapshot_epoch=snapshot_epoch,
        candidate_resource_version=candidate_resource_version,
        coordinate_authority_disposition=(
            "CALLER_STAMPED_CANDIDATE_REQUIRES_REPOSITORY_CAS"
        ),
        freshness_policy_artifact=_freeze_json(freshness_artifact),
        freshness_policy_artifact_canonical_bytes=freshness_artifact_raw,
        freshness_policy=_freeze_json(freshness_policy),
        freshness_policy_canonical_bytes=freshness_policy_raw,
        freshness_policy_hash=freshness_policy["policyHash"],
        device_record_artifact_canonical_bytes=record_artifact_raws,
        candidate_device_records=candidate_records,
        snapshot_semantics=snapshot_semantics,
        provider_captures=provider_contexts,
        no_change_projection=_freeze_json(no_change_projection),
        oldest_mandatory_evidence_observed_at=oldest_mandatory,
        freshness_time_basis="CALLER_SUPPLIED_CAPTURE_COMPLETION",
        verification_receipt=_freeze_json(receipt),
        verification_receipt_canonical_bytes=receipt_raw,
        context_digest=context_digest,
        authority_boundary=HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY,
        authority_disposition=HOST_SNAPSHOT_CAPTURE_AUTHORITY_DISPOSITION,
        product_authorized=HOST_SNAPSHOT_CAPTURE_PRODUCT_AUTHORIZED,
        product_evidence_blockers=(HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS),
    )


def replay_host_snapshot_capture_closure(
    schemas: ContractSchemas,
    context: VerifiedHostSnapshotCaptureClosureContext,
) -> VerifiedHostSnapshotCaptureClosureContext:
    """Re-run the verifier from only the exact bytes retained in a context."""

    require_factory_verified(
        context,
        VerifiedHostSnapshotCaptureClosureContext,
        code="PUBLICATION_CAPTURE_CONTEXT_INVALID",
        path="publicationCapture.context",
        message=("context must come from verify_host_snapshot_capture_closure"),
    )
    replayed = verify_host_snapshot_capture_closure(
        schemas,
        context.capability_policy,
        capture_batch_artifact=context.capture_batch_artifact_canonical_bytes,
        freshness_policy_artifact=(context.freshness_policy_artifact_canonical_bytes),
        device_record_artifacts=(context.device_record_artifact_canonical_bytes),
        limits=context.limits,
    )
    _require_equal(
        replayed.verification_receipt_canonical_bytes,
        context.verification_receipt_canonical_bytes,
        code="PUBLICATION_CAPTURE_REPLAY_MISMATCH",
        path="publicationCapture.context.verificationReceipt",
        description="replayed capture context differs from retained context",
    )
    return replayed


__all__ = [
    "DEFAULT_PUBLICATION_CAPTURE_LIMITS",
    "HOST_SNAPSHOT_CAPTURE_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_CAPTURE_AUTHORITY_DISPOSITION",
    "HOST_SNAPSHOT_CAPTURE_BATCH_ARTIFACT_SCHEMA_REF",
    "HOST_SNAPSHOT_CAPTURE_BATCH_SCHEMA_REF",
    "HOST_SNAPSHOT_CAPTURE_CLOSURE_RECEIPT_SCHEMA_REF",
    "HOST_SNAPSHOT_CAPTURE_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_CAPTURE_PRODUCT_EVIDENCE_BLOCKERS",
    "HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_ID",
    "HOST_SNAPSHOT_CAPTURE_VERIFIER_ALGORITHM_SCHEMA_REF",
    "HOST_SNAPSHOT_DEVICE_RECORD_ARTIFACT_SCHEMA_REF",
    "HOST_SNAPSHOT_FRESHNESS_POLICY_ARTIFACT_SCHEMA_REF",
    "HOST_SNAPSHOT_PROVIDER_OUTPUT_SCHEMA_REF",
    "HOST_SNAPSHOT_PROVIDER_SEMANTIC_FACTS_SCHEMA_REF",
    "HOST_SNAPSHOT_PUBLICATION_TRACE_SCHEMA_REF",
    "PublicationCaptureVerifierLimits",
    "VerifiedHostSnapshotCaptureClosureContext",
    "VerifiedProviderCaptureClosure",
    "replay_host_snapshot_capture_closure",
    "verify_host_snapshot_capture_closure",
]
