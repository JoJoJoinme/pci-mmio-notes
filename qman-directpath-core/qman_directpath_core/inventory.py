"""Fail-closed verification of one current DirectPath host inventory.

This module verifies immutable bytes and relationships only.  It does not read
the HostAuthority repository, publish a snapshot, execute a compare-and-swap,
or prove that two caller-supplied reads were linearizable.  Product callers
must obtain ``host_authority_before`` and ``host_authority_after`` with
independent linearizable reads around all snapshot and DeviceRecord fetches,
and must repeat currentness checks at every later side-effect boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import copy
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, TypeVar

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
from .identity import VerifiedIdentity, verify_identity
from .pci_config import (
    VerifiedPciConfigFacts,
    verify_device_record_pci_facts,
)
from .snapshot_semantics import (
    VerifiedHostSnapshotSemantics,
    derive_host_snapshot_semantics,
)
from .trust import (
    VerifiedTrustContext,
    _verify_role_signed_document,
)
from ._verified import FactoryVerified, require_factory_verified


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview

_HOST_SNAPSHOT_DOMAIN = b"QMAN-DIRECTPATH/HOST-SNAPSHOT/V1\x00"
_VERIFIER_IDENTITY_DOMAIN = b"QMAN-DIRECTPATH/INVENTORY-VERIFIER-ALGORITHM/V2\x00"
_VERIFICATION_RECEIPT_DOMAIN = b"QMAN-DIRECTPATH/INVENTORY-VERIFICATION-RECEIPT/V1\x00"
_DEVICE_PROVIDER_FACTS_DOMAIN = b"QMAN-DIRECTPATH/DEVICE-PROVIDER-FACTS/V2\x00"
MAX_HOST_SNAPSHOT_DEVICE_RECORDS = 65_536
MAX_CURRENT_INVENTORY_DEVICE_RECORDS = 4_096
_DEPENDENCY_DOMAIN_KINDS = (
    "FUNCTIONAL",
    "IOMMU",
    "MULTIFUNCTION",
    "PF_VF",
    "PHYSICAL_ISOLATION",
    "PLATFORM",
    "REQUESTER_ALIAS",
)
_VERIFIER_SCHEMA_REFS = (
    "contracts/directpath-authority-entities.schema.json",
    "contracts/directpath-host-snapshot-publication-trace.schema.json",
    "contracts/directpath-identity-v1.schema.json",
    "contracts/directpath-inventory-verification-receipt.schema.json",
    "contracts/directpath-inventory-verifier-algorithm.schema.json",
    "contracts/directpath-portable-entities.schema.json",
    "contracts/directpath-portable-hash-subjects.schema.json",
)
_VERIFIER_VALIDATION_STAGES = (
    "CANONICAL_INPUT_BYTES_V1",
    "HOST_AUTHORITY_BEFORE_AFTER_EXACT_V1",
    "HOST_SNAPSHOT_CONTENT_HASH_ED25519_CURRENT_RING_V1",
    "HOST_AUTHORITY_EXACT_CURRENT_POINTER_V1",
    "DEVICE_RECORD_V3_HASH_IDENTITY_MEMBERSHIP_V1",
    "PCI_STRUCTURE_RESET_FACT_REPLAY_V1",
    "DEVICE_PROVIDER_FACT_SET_DIGEST_REPLAY_V2",
    "HOST_SNAPSHOT_SEMANTIC_PROJECTION_REPLAY_V1",
    "DEPENDENCY_DOMAINS_EXACT_SEVEN_V1",
    "DEPENDENCY_DOMAIN_IOMMU_BDF_UID_EQUIVALENCE_V1",
    "DEPENDENCY_DOMAIN_PHYSICAL_LEGACY_EQUIVALENCE_V1",
    "INVENTORY_VERIFICATION_RECEIPT_V1",
)
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class InventoryVerifierLimits:
    """Closed component resource ceilings; callers may only tighten them."""

    max_document_bytes: int = 2 * 1024 * 1024
    max_total_input_bytes: int = 256 * 1024 * 1024
    max_json_nodes: int = 20_000_000
    max_json_depth: int = 64
    max_current_device_records: int = MAX_CURRENT_INVENTORY_DEVICE_RECORDS
    max_candidate_device_records: int = MAX_HOST_SNAPSHOT_DEVICE_RECORDS
    max_total_dependency_edges: int = 4_194_304


DEFAULT_INVENTORY_VERIFIER_LIMITS = InventoryVerifierLimits()


@dataclass(slots=True)
class _InventoryBudget:
    limits: InventoryVerifierLimits
    input_bytes: int = 0
    json_nodes: int = 0
    dependency_edges: int = 0

    def add_input(self, amount: int, path: str) -> None:
        self.input_bytes += amount
        require(
            self.input_bytes <= self.limits.max_total_input_bytes,
            "INVENTORY_INPUT_TOO_LARGE",
            path,
            "aggregate canonical input bytes exceed the closed verifier budget",
        )

    def add_nodes(self, amount: int, path: str) -> None:
        self.json_nodes += amount
        require(
            self.json_nodes <= self.limits.max_json_nodes,
            "INVENTORY_INPUT_TOO_LARGE",
            path,
            "aggregate JSON nodes exceed the closed verifier budget",
        )

    def add_dependency_edges(self, amount: int, path: str) -> None:
        self.dependency_edges += amount
        require(
            self.dependency_edges <= self.limits.max_total_dependency_edges,
            "INVENTORY_INPUT_TOO_LARGE",
            path,
            "aggregate dependency edges exceed the closed verifier budget",
        )


def _checked_limits(
    value: InventoryVerifierLimits | None,
) -> InventoryVerifierLimits:
    limits = value or DEFAULT_INVENTORY_VERIFIER_LIMITS
    require(
        isinstance(limits, InventoryVerifierLimits),
        "INVENTORY_LIMIT_INVALID",
        "limits",
        "expected InventoryVerifierLimits",
    )
    hard = DEFAULT_INVENTORY_VERIFIER_LIMITS
    for field in fields(InventoryVerifierLimits):
        actual = getattr(limits, field.name)
        ceiling = getattr(hard, field.name)
        require(
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and 1 <= actual <= ceiling,
            "INVENTORY_LIMIT_INVALID",
            f"limits.{field.name}",
            (
                "limit must be a positive integer no greater than the "
                f"portable hard ceiling {ceiling}"
            ),
        )
    return limits


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return value


def _document(
    value: JsonDocument,
    path: str,
    *,
    limits: InventoryVerifierLimits,
    budget: _InventoryBudget,
) -> tuple[dict[str, Any], bytes]:
    """Load a JSON object and retain the exact canonical bytes it binds."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw_size = memoryview(value).nbytes
        require(
            raw_size <= limits.max_document_bytes,
            "INVENTORY_INPUT_TOO_LARGE",
            path,
            "canonical document exceeds the per-document byte budget",
        )
        budget.add_input(raw_size, path)
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
        remaining_nodes = limits.max_json_nodes - budget.json_nodes
        require(
            remaining_nodes >= 1,
            "INVENTORY_INPUT_TOO_LARGE",
            path,
            "aggregate JSON nodes exceed the closed verifier budget",
        )
        try:
            _, nodes = measure_canonical_json(
                loaded,
                max_bytes=raw_size,
                max_nodes=remaining_nodes,
                max_depth=limits.max_json_depth,
            )
        except CanonicalJsonLimitError as exc:
            fail("INVENTORY_INPUT_TOO_LARGE", path, str(exc))
        budget.add_nodes(nodes, path)
    elif isinstance(value, Mapping):
        try:
            remaining_bytes = min(
                limits.max_document_bytes,
                limits.max_total_input_bytes - budget.input_bytes,
            )
            remaining_nodes = limits.max_json_nodes - budget.json_nodes
            require(
                remaining_bytes >= 1 and remaining_nodes >= 1,
                "INVENTORY_INPUT_TOO_LARGE",
                path,
                "aggregate canonical input budget is exhausted",
            )
            measured_bytes, nodes = measure_canonical_json(
                value,
                max_bytes=remaining_bytes,
                max_nodes=remaining_nodes,
                max_depth=limits.max_json_depth,
            )
            budget.add_input(measured_bytes, path)
            budget.add_nodes(nodes, path)
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        except CanonicalJsonLimitError as exc:
            fail("INVENTORY_INPUT_TOO_LARGE", path, str(exc))
        except (
            CanonicalizationError,
            KeyError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
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


def _utc_time(value: datetime, path: str) -> datetime:
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None,
        "TIME_INVALID",
        path,
        "a timezone-aware datetime is required",
    )
    return value.astimezone(timezone.utc)


def _timestamp(value: Any, path: str) -> datetime:
    require(
        isinstance(value, str),
        "TIME_INVALID",
        path,
        "expected the contract timestamp string",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _projection_digest(
    document: Mapping[str, Any],
    *,
    null_field: str,
    path: str,
) -> str:
    projection = copy.deepcopy(dict(document))
    projection[null_field] = None
    try:
        return sha256_digest(canonical_json_bytes(projection))
    except (CanonicalizationError, TypeError, ValueError) as exc:
        fail("CANONICAL_JSON_INVALID", path, str(exc))


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


def _require_canonical_order(
    values: Sequence[_T],
    *,
    path: str,
    order_key: Callable[[_T], Any] = lambda value: value,
    unique_key: Callable[[_T], Any] | None = None,
) -> None:
    """Enforce schema ``x-qmanSetOrder`` rules that JSON Schema cannot."""

    order_bytes = tuple(canonical_json_bytes(order_key(value)) for value in values)
    require(
        order_bytes == tuple(sorted(order_bytes)),
        "NONCANONICAL_SET",
        path,
        "items are not in ascending CANONICAL-JSON-V1 key order",
    )
    uniqueness = unique_key or order_key
    unique_bytes = tuple(canonical_json_bytes(uniqueness(value)) for value in values)
    require(
        len(unique_bytes) == len(set(unique_bytes)),
        "NONCANONICAL_SET",
        path,
        "items contain a duplicate semantic set key",
    )


def _verify_record_order_rules(record: Mapping[str, Any], path: str) -> None:
    domains = record["dependencyDomains"]
    _require_canonical_order(
        domains,
        path=f"{path}.dependencyDomains",
        order_key=lambda item: item["kind"],
        unique_key=lambda item: item["kind"],
    )
    require(
        tuple(domain["kind"] for domain in domains) == _DEPENDENCY_DOMAIN_KINDS,
        "DEPENDENCY_DOMAIN_SET_INVALID",
        f"{path}.dependencyDomains",
        "expected exactly one domain of every closed kind",
    )
    for domain_index, domain in enumerate(domains):
        domain_path = f"{path}.dependencyDomains[{domain_index}]"
        _require_canonical_order(
            domain["edges"],
            path=f"{domain_path}.edges",
            order_key=lambda item: item,
        )
        if domain["state"] != "KNOWN":
            require(
                not domain["edges"],
                "DEPENDENCY_DOMAIN_STATE_INVALID",
                f"{domain_path}.edges",
                "UNKNOWN or CONFLICT domains cannot carry guessed edges",
            )

    _require_canonical_order(
        record["physicalIsolationDomain"]["memberDeviceUids"],
        path=f"{path}.physicalIsolationDomain.memberDeviceUids",
    )
    _require_canonical_order(
        record["iommuProvider"]["kernelIommuGroup"],
        path=f"{path}.iommuProvider.kernelIommuGroup",
    )
    _require_canonical_order(
        record["resetContract"]["resetAffectedSet"],
        path=f"{path}.resetContract.resetAffectedSet",
    )
    _require_canonical_order(
        record["owner"]["ownerActivationGroup"],
        path=f"{path}.owner.ownerActivationGroup",
    )
    _require_canonical_order(
        record["technicalTraits"],
        path=f"{path}.technicalTraits",
    )
    _require_canonical_order(
        record["interrupts"]["supportedModes"],
        path=f"{path}.interrupts.supportedModes",
    )
    _require_canonical_order(
        record["dependencyActions"],
        path=f"{path}.dependencyActions",
        order_key=lambda item: [
            item["deviceUid"],
            item["action"],
            item["provenanceDigest"],
        ],
        unique_key=lambda item: [item["deviceUid"], item["action"]],
    )
    _require_canonical_order(
        record["bars"],
        path=f"{path}.bars",
        order_key=lambda item: [item["barKind"], item["index"]],
    )
    _require_canonical_order(
        record["provenance"]["providerFacts"],
        path=f"{path}.provenance.providerFacts",
        order_key=lambda item: [
            item["factId"],
            item["providerId"],
            item["providerVersion"],
            item["evidenceHash"],
        ],
        unique_key=lambda item: item["factId"],
    )


def derive_device_provider_facts_digest(
    record: Mapping[str, Any],
) -> str:
    """Digest the exact retained provider rows for one DeviceRecord."""

    subject = {
        "subjectType": "DEVICE_PROVIDER_FACT_SET",
        "schemaVersion": 2,
        "deviceUid": record["deviceUid"],
        "captureStartedAt": record["provenance"]["captureStartedAt"],
        "capturedAt": record["provenance"]["capturedAt"],
        "providerFacts": [
            {
                "factId": fact["factId"],
                "providerId": fact["providerId"],
                "providerVersion": fact["providerVersion"],
                "providerDefinitionDigest": fact["providerDefinitionDigest"],
                "observedAt": fact["observedAt"],
                "evidenceHash": fact["evidenceHash"],
            }
            for fact in record["provenance"]["providerFacts"]
        ],
        "providerFactsDigest": None,
    }
    return sha256_digest(_DEVICE_PROVIDER_FACTS_DOMAIN + canonical_json_bytes(subject))


@dataclass(frozen=True, slots=True, init=False)
class InventoryVerifierAlgorithmIdentity(FactoryVerified):
    """Portable component algorithm identity, never a binary attestation."""

    definition: Mapping[str, Any]
    canonical_bytes: bytes
    digest: str


def derive_inventory_verifier_algorithm_identity(
    schemas: ContractSchemas,
) -> InventoryVerifierAlgorithmIdentity:
    """Bind the fixed verifier algorithm to the exact loaded schema bytes."""

    bindings = [
        {
            "schemaRef": schema_ref,
            "schemaDigest": schemas.digest_for_ref(
                schema_ref,
                path="inventory.verifierAlgorithm.schemaBindings",
            ),
        }
        for schema_ref in _VERIFIER_SCHEMA_REFS
    ]
    bindings.sort(key=lambda item: canonical_json_bytes(item["schemaRef"]))
    definition = {
        "subjectType": "PORTABLE_INVENTORY_VERIFIER_ALGORITHM",
        "schemaVersion": 2,
        "algorithmId": "PORTABLE_INVENTORY_VERIFIER_ALGORITHM_V2",
        "identityKind": ("COMPONENT_ALGORITHM_IDENTITY_NOT_BINARY_ATTESTATION"),
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "digestAlgorithm": "SHA-256",
        "hostSnapshotSignatureAlgorithm": "Ed25519",
        "requiredHostSnapshotSignerRole": "HOST_INVENTORY_EVIDENCE",
        "requireCurrentTrustRing": True,
        "hostSnapshotSignatureDomain": ("QMAN-DIRECTPATH/HOST-SNAPSHOT/V1"),
        "verifierIdentityHashDomain": (
            "QMAN-DIRECTPATH/INVENTORY-VERIFIER-ALGORITHM/V2"
        ),
        "inventoryReceiptHashDomain": (
            "QMAN-DIRECTPATH/INVENTORY-VERIFICATION-RECEIPT/V1"
        ),
        "schemaBindings": bindings,
        "validationStages": list(_VERIFIER_VALIDATION_STAGES),
        "algorithmIdentityDigest": None,
    }
    projection_raw = canonical_json_bytes(definition)
    identity_digest = sha256_digest(_VERIFIER_IDENTITY_DOMAIN + projection_raw)
    definition["algorithmIdentityDigest"] = identity_digest
    schemas.validate(
        "inventory_verifier_algorithm",
        definition,
        "inventory.verifierAlgorithm",
    )
    raw = canonical_json_bytes(definition)
    return InventoryVerifierAlgorithmIdentity._construct(
        definition=_deep_freeze(definition),
        canonical_bytes=raw,
        digest=identity_digest,
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedDeviceRecord(FactoryVerified):
    """One schema-valid, hash-valid record from the verified snapshot set."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    device_record_hash: str
    device_uid: str
    current_bdf: str
    identity: VerifiedIdentity
    pci_config_facts: VerifiedPciConfigFacts


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCandidateDeviceRecordSet(FactoryVerified):
    """Complete candidate DeviceRecord set before repository publication.

    This verifies the supplied record bytes and their closed cross-record
    topology only.  It does not prove repository currentness, publication,
    visibility, or compare-and-swap execution.
    """

    host_id: str
    host_epoch: int
    agent_generation: int
    snapshot_epoch: int
    captured_at: datetime
    device_records: tuple[VerifiedDeviceRecord, ...]
    device_records_by_digest: Mapping[str, VerifiedDeviceRecord]
    device_records_by_uid: Mapping[str, VerifiedDeviceRecord]
    device_records_by_bdf: Mapping[str, VerifiedDeviceRecord]


@dataclass(frozen=True, slots=True, init=False)
class VerifiedInventoryContext(FactoryVerified):
    """Immutable exact current-pointer inventory view.

    The context proves relationships among the supplied canonical documents.
    It is not a repository transaction receipt or an admission authority.
    """

    trust: VerifiedTrustContext
    host_authority: Mapping[str, Any]
    host_authority_canonical_bytes: bytes
    host_snapshot: Mapping[str, Any]
    host_snapshot_canonical_bytes: bytes
    host_id: str
    kernel_boot_id: str
    host_epoch: int
    agent_identity: str
    agent_generation: int
    observed_authority_resource_version: int
    snapshot_authority_resource_version: int
    snapshot_epoch: int
    snapshot_content_hash: str
    policy_hash: str
    captured_at: datetime
    inventory_signer_key_id: str
    inventory_signer_principal_id: str
    verified_at: datetime
    verifier_algorithm_identity: InventoryVerifierAlgorithmIdentity
    inventory_verifier_identity_digest: str
    inventory_verification_receipt: Mapping[str, Any]
    inventory_verification_receipt_canonical_bytes: bytes
    inventory_verification_receipt_digest: str
    device_records: tuple[VerifiedDeviceRecord, ...]
    device_records_by_digest: Mapping[str, VerifiedDeviceRecord]
    device_records_by_uid: Mapping[str, VerifiedDeviceRecord]
    device_records_by_bdf: Mapping[str, VerifiedDeviceRecord]
    snapshot_semantics: VerifiedHostSnapshotSemantics

    @property
    def authority_resource_version(self) -> int:
        """Compatibility alias for the observed current-pointer version."""

        return self.observed_authority_resource_version

    def device(self, device_uid: str) -> VerifiedDeviceRecord:
        """Return an exact member; absence is a closed inventory failure."""

        try:
            return self.device_records_by_uid[device_uid]
        except KeyError:
            fail(
                "DEVICE_NOT_IN_SNAPSHOT",
                "inventory.deviceRecords",
                f"device {device_uid!r} is absent from the verified snapshot",
            )


def _verify_device_record(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    index: int,
    snapshot: Mapping[str, Any],
    limits: InventoryVerifierLimits,
    budget: _InventoryBudget,
    path_prefix: str = "inventory.deviceRecords",
) -> VerifiedDeviceRecord:
    path = f"{path_prefix}[{index}]"
    record, raw = _document(
        value,
        path,
        limits=limits,
        budget=budget,
    )
    dependency_domains = record.get("dependencyDomains")
    if isinstance(dependency_domains, list):
        for domain_index, domain in enumerate(dependency_domains):
            if not isinstance(domain, Mapping):
                continue
            edges = domain.get("edges")
            if isinstance(edges, list):
                budget.add_dependency_edges(
                    len(edges),
                    f"{path}.dependencyDomains[{domain_index}].edges",
                )
    schemas.validate("portable_entities", record, path)
    expected_hash = _projection_digest(
        record,
        null_field="deviceRecordHash",
        path=f"{path}.deviceRecordHashProjection",
    )
    _require_equal(
        record["deviceRecordHash"],
        expected_hash,
        code="DEVICE_RECORD_HASH_INVALID",
        path=f"{path}.deviceRecordHash",
        description="DeviceRecord projection digest mismatch",
    )
    _verify_record_order_rules(record, path)
    provenance = record["provenance"]
    require(
        provenance["captureStartedAt"] <= provenance["capturedAt"],
        "DEVICE_CAPTURE_INTERVAL_INVALID",
        f"{path}.provenance",
        "capture start cannot be later than capture completion",
    )
    for fact_index, fact in enumerate(provenance["providerFacts"]):
        require(
            provenance["captureStartedAt"]
            <= fact["observedAt"]
            <= provenance["capturedAt"],
            "DEVICE_CAPTURE_INTERVAL_INVALID",
            f"{path}.provenance.providerFacts[{fact_index}].observedAt",
            "provider fact must lie inside the retained capture interval",
        )
    _require_equal(
        provenance["providerFactsDigest"],
        derive_device_provider_facts_digest(record),
        code="DEVICE_PROVIDER_FACTS_DIGEST_INVALID",
        path=f"{path}.provenance.providerFactsDigest",
        description=(
            "DeviceRecord provider fact-set digest does not bind the exact "
            "same-capture provider rows"
        ),
    )

    identity = verify_identity(schemas, record["immutableIdentity"])
    _require_equal(
        record["hostId"],
        snapshot["hostId"],
        code="DEVICE_SNAPSHOT_MISMATCH",
        path=f"{path}.hostId",
        description="DeviceRecord host does not match HostSnapshot",
    )
    _require_equal(
        record["hostId"],
        identity.host_stable_id,
        code="DEVICE_IDENTITY_MISMATCH",
        path=f"{path}.hostId",
        description="DeviceRecord host does not match immutable identity",
    )
    _require_equal(
        record["identityFingerprint"],
        identity.identity_fingerprint,
        code="DEVICE_IDENTITY_MISMATCH",
        path=f"{path}.identityFingerprint",
        description="identity fingerprint is not derived from immutableIdentity",
    )
    _require_equal(
        record["deviceUid"],
        identity.device_uid,
        code="DEVICE_IDENTITY_MISMATCH",
        path=f"{path}.deviceUid",
        description="device UID is not derived from immutableIdentity",
    )
    _require_equal(
        record["role"]["functionRole"],
        identity.function_role,
        code="DEVICE_IDENTITY_MISMATCH",
        path=f"{path}.role.functionRole",
        description="observed role does not match immutableIdentity",
    )
    if identity.identity_variant == "SLOT_BOUND":
        _require_equal(
            record["physicalPathProvider"],
            identity.document["physicalPathProvider"],
            code="DEVICE_IDENTITY_MISMATCH",
            path=f"{path}.physicalPathProvider",
            description="slot-bound path provider changed",
        )
        _require_equal(
            record["physicalPath"],
            identity.physical_path,
            code="DEVICE_IDENTITY_MISMATCH",
            path=f"{path}.physicalPath",
            description="slot-bound physical path changed",
        )

    pci_config_facts = verify_device_record_pci_facts(record, path=path)
    domains_by_kind = {domain["kind"]: domain for domain in record["dependencyDomains"]}
    for kind in ("IOMMU", "PHYSICAL_ISOLATION"):
        domain = domains_by_kind[kind]
        if domain["state"] == "KNOWN":
            require(
                record["deviceUid"]
                in {edge["targetDeviceUid"] for edge in domain["edges"]},
                "DEPENDENCY_DOMAIN_SELF_MISSING",
                f"{path}.dependencyDomains.{kind}.edges",
                f"a KNOWN {kind} domain must contain this device",
            )
    if domains_by_kind["IOMMU"]["state"] == "KNOWN":
        require(
            record["iommuProvider"]["dmaIsolationMode"] == "IOMMU",
            "DEPENDENCY_DOMAIN_STATE_MISMATCH",
            f"{path}.dependencyDomains.IOMMU.state",
            (
                "a KNOWN IOMMU dependency domain requires the verified "
                "IOMMU provider mode"
            ),
        )

    generations = record["generations"]
    for record_field, snapshot_field in (
        ("hostEpoch", "hostEpoch"),
        ("agentGeneration", "agentGeneration"),
        ("snapshotEpoch", "snapshotEpoch"),
    ):
        _require_equal(
            generations[record_field],
            snapshot[snapshot_field],
            code="DEVICE_SNAPSHOT_MISMATCH",
            path=f"{path}.generations.{record_field}",
            description="DeviceRecord generation is outside this snapshot",
        )
    _require_equal(
        provenance["capturedAt"],
        snapshot["capturedAt"],
        code="DEVICE_SNAPSHOT_MISMATCH",
        path=f"{path}.provenance.capturedAt",
        description="DeviceRecord provenance is outside this capture",
    )

    domain = record["physicalIsolationDomain"]
    if domain["state"] == "KNOWN":
        require(
            record["deviceUid"] in domain["memberDeviceUids"],
            "DEVICE_DOMAIN_INVALID",
            f"{path}.physicalIsolationDomain.memberDeviceUids",
            "a KNOWN physical isolation domain must contain this device",
        )
    if record["iommuProvider"]["dmaIsolationMode"] == "IOMMU":
        require(
            record["currentBdf"] in record["iommuProvider"]["kernelIommuGroup"],
            "DEVICE_DOMAIN_INVALID",
            f"{path}.iommuProvider.kernelIommuGroup",
            "the kernel IOMMU group must contain this current BDF",
        )
    if record["resetContract"]["state"] == "KNOWN":
        require(
            record["deviceUid"] in record["resetContract"]["resetAffectedSet"],
            "DEVICE_DOMAIN_INVALID",
            f"{path}.resetContract.resetAffectedSet",
            "a KNOWN reset affected set must contain this device",
        )
    require(
        record["deviceUid"] in record["owner"]["ownerActivationGroup"],
        "DEVICE_DOMAIN_INVALID",
        f"{path}.owner.ownerActivationGroup",
        "the owner activation group must contain this device",
    )

    return VerifiedDeviceRecord._construct(
        document=_deep_freeze(record),
        canonical_bytes=raw,
        device_record_hash=record["deviceRecordHash"],
        device_uid=record["deviceUid"],
        current_bdf=record["currentBdf"],
        identity=identity,
        pci_config_facts=pci_config_facts,
    )


def _require_complete_references(
    records: Sequence[VerifiedDeviceRecord],
    *,
    path_prefix: str = "inventory.deviceRecords",
) -> None:
    records_by_uid = {record.device_uid: record for record in records}
    known_uids = frozenset(records_by_uid)
    records_by_bdf = {record.current_bdf: record for record in records}
    known_bdfs = frozenset(records_by_bdf)
    domain_signatures: dict[
        tuple[str, str],
        tuple[str, frozenset[str], str],
    ] = {}
    for verified in records:
        for domain in verified.document["dependencyDomains"]:
            if domain["kind"] not in {"IOMMU", "PHYSICAL_ISOLATION"}:
                continue
            domain_signatures[(verified.device_uid, domain["kind"])] = (
                domain["state"],
                frozenset(edge["targetDeviceUid"] for edge in domain["edges"]),
                domain["provenanceDigest"],
            )
    for index, verified in enumerate(records):
        path = f"{path_prefix}[{index}]"
        record = verified.document
        uid_references: list[tuple[str, Sequence[str]]] = [
            (
                "physicalIsolationDomain.memberDeviceUids",
                record["physicalIsolationDomain"]["memberDeviceUids"],
            ),
            (
                "resetContract.resetAffectedSet",
                record["resetContract"]["resetAffectedSet"],
            ),
            (
                "owner.ownerActivationGroup",
                record["owner"]["ownerActivationGroup"],
            ),
            (
                "dependencyActions",
                tuple(action["deviceUid"] for action in record["dependencyActions"]),
            ),
        ]
        for domain_index, domain in enumerate(record["dependencyDomains"]):
            uid_references.append(
                (
                    f"dependencyDomains[{domain_index}].edges",
                    tuple(edge["targetDeviceUid"] for edge in domain["edges"]),
                )
            )
        for suffix, references in uid_references:
            missing = sorted(set(references) - known_uids)
            require(
                not missing,
                "INVENTORY_REFERENCE_OUTSIDE_SNAPSHOT",
                f"{path}.{suffix}",
                f"referenced device UIDs are absent: {missing!r}",
            )
        missing_bdfs = sorted(
            set(record["iommuProvider"]["kernelIommuGroup"]) - known_bdfs
        )
        require(
            not missing_bdfs,
            "INVENTORY_REFERENCE_OUTSIDE_SNAPSHOT",
            f"{path}.iommuProvider.kernelIommuGroup",
            f"referenced BDFs are absent: {missing_bdfs!r}",
        )

        domains_by_kind = {
            domain["kind"]: domain for domain in record["dependencyDomains"]
        }
        iommu = domains_by_kind["IOMMU"]
        if iommu["state"] == "KNOWN":
            expected_iommu_uids = {
                records_by_bdf[bdf].device_uid
                for bdf in record["iommuProvider"]["kernelIommuGroup"]
            }
            actual_iommu_uids = domain_signatures[
                (verified.device_uid, "IOMMU")
            ][1]
            require(
                actual_iommu_uids == expected_iommu_uids,
                "DEPENDENCY_DOMAIN_MEMBERSHIP_MISMATCH",
                f"{path}.dependencyDomains.IOMMU.edges",
                (
                    "KNOWN IOMMU target UIDs do not equal the verified "
                    "kernelIommuGroup BDF-to-deviceUid mapping"
                ),
            )

        physical = domains_by_kind["PHYSICAL_ISOLATION"]
        legacy_physical = record["physicalIsolationDomain"]
        require(
            physical["state"] == legacy_physical["state"],
            "DEPENDENCY_DOMAIN_STATE_MISMATCH",
            f"{path}.dependencyDomains.PHYSICAL_ISOLATION.state",
            "typed and compatibility physical-domain states differ",
        )
        require(
            physical["provenanceDigest"] == legacy_physical["provenanceDigest"],
            "DEPENDENCY_DOMAIN_PROVENANCE_MISMATCH",
            (f"{path}.dependencyDomains.PHYSICAL_ISOLATION.provenanceDigest"),
            "typed and compatibility physical-domain provenance differs",
        )
        physical_uids = domain_signatures[
            (verified.device_uid, "PHYSICAL_ISOLATION")
        ][1]
        require(
            physical_uids == set(legacy_physical["memberDeviceUids"]),
            "DEPENDENCY_DOMAIN_MEMBERSHIP_MISMATCH",
            f"{path}.dependencyDomains.PHYSICAL_ISOLATION.edges",
            ("typed and compatibility physical-domain UID sets differ"),
        )

        for kind in ("IOMMU", "PHYSICAL_ISOLATION"):
            domain = domains_by_kind[kind]
            if domain["state"] != "KNOWN":
                continue
            _, member_uids, provenance_digest = domain_signatures[
                (verified.device_uid, kind)
            ]
            for member_uid in member_uids:
                (
                    peer_state,
                    peer_uids,
                    peer_provenance_digest,
                ) = domain_signatures[
                    (member_uid, kind)
                ]
                require(
                    peer_state == "KNOWN" and peer_uids == member_uids,
                    "DEPENDENCY_DOMAIN_RECIPROCITY_MISMATCH",
                    f"{path}.dependencyDomains.{kind}.edges",
                    (
                        f"KNOWN {kind} membership must be the same "
                        "equivalence class from every member"
                    ),
                )
                require(
                    peer_provenance_digest == provenance_digest,
                    "DEPENDENCY_DOMAIN_PROVENANCE_MISMATCH",
                    (f"{path}.dependencyDomains.{kind}.provenanceDigest"),
                    (f"KNOWN {kind} members must bind one domain provenance digest"),
                )


def verify_candidate_device_record_set(
    schemas: ContractSchemas,
    device_records: Sequence[JsonDocument],
    *,
    host_id: str,
    host_epoch: int,
    agent_generation: int,
    snapshot_epoch: int,
    captured_at: str,
    path_prefix: str = "candidateDeviceRecords",
    limits: InventoryVerifierLimits | None = None,
) -> VerifiedCandidateDeviceRecordSet:
    """Verify one complete, canonically ordered candidate record set.

    The caller supplies the capture/generation coordinates that every record
    must exact-match.  This is the reusable publication-input stage; it does
    not sign a HostSnapshot or claim that the records were committed.
    """

    require(
        isinstance(schemas, ContractSchemas),
        "DEVICE_RECORD_SET_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    checked_limits = _checked_limits(limits)
    budget = _InventoryBudget(checked_limits)
    require(
        isinstance(path_prefix, str) and bool(path_prefix),
        "DEVICE_RECORD_SET_INPUT_INVALID",
        "pathPrefix",
        "path_prefix must be a non-empty string",
    )
    require(
        isinstance(device_records, Sequence)
        and not isinstance(
            device_records,
            (str, bytes, bytearray, memoryview),
        ),
        "DEVICE_RECORD_SET_INVALID",
        path_prefix,
        "expected the complete sequence of DeviceRecord documents",
    )
    require(
        1 <= len(device_records) <= checked_limits.max_candidate_device_records,
        "DEVICE_RECORD_SET_TOO_LARGE",
        path_prefix,
        (
            "candidate set must contain between 1 and "
            f"{checked_limits.max_candidate_device_records} records"
        ),
    )
    require(
        isinstance(host_id, str) and bool(host_id),
        "DEVICE_RECORD_SET_INPUT_INVALID",
        f"{path_prefix}.hostId",
        "host_id must be a non-empty string",
    )
    for field_name, value in (
        ("hostEpoch", host_epoch),
        ("agentGeneration", agent_generation),
        ("snapshotEpoch", snapshot_epoch),
    ):
        require(
            isinstance(value, int)
            and not isinstance(value, bool)
            and 1 <= value <= 9_007_199_254_740_991,
            "DEVICE_RECORD_SET_INPUT_INVALID",
            f"{path_prefix}.{field_name}",
            f"{field_name} must be a positive interoperable safe integer",
        )
    captured = _timestamp(captured_at, f"{path_prefix}.capturedAt")
    snapshot_binding = {
        "hostId": host_id,
        "hostEpoch": host_epoch,
        "agentGeneration": agent_generation,
        "snapshotEpoch": snapshot_epoch,
        "capturedAt": captured_at,
    }

    verified_records: list[VerifiedDeviceRecord] = []
    records_by_digest: dict[str, VerifiedDeviceRecord] = {}
    records_by_uid: dict[str, VerifiedDeviceRecord] = {}
    records_by_bdf: dict[str, VerifiedDeviceRecord] = {}
    for index, value in enumerate(device_records):
        record = _verify_device_record(
            schemas,
            value,
            index=index,
            snapshot=snapshot_binding,
            limits=checked_limits,
            budget=budget,
            path_prefix=path_prefix,
        )
        require(
            record.device_record_hash not in records_by_digest,
            "DEVICE_RECORD_DUPLICATE",
            f"{path_prefix}[{index}].deviceRecordHash",
            "duplicate DeviceRecord hash",
        )
        require(
            record.device_uid not in records_by_uid,
            "DEVICE_UID_DUPLICATE",
            f"{path_prefix}[{index}].deviceUid",
            "duplicate device UID in one candidate set",
        )
        require(
            record.current_bdf not in records_by_bdf,
            "DEVICE_BDF_DUPLICATE",
            f"{path_prefix}[{index}].currentBdf",
            "duplicate current BDF in one candidate set",
        )
        verified_records.append(record)
        records_by_digest[record.device_record_hash] = record
        records_by_uid[record.device_uid] = record
        records_by_bdf[record.current_bdf] = record

    _require_canonical_order(
        verified_records,
        path=path_prefix,
        order_key=lambda item: item.device_uid,
        unique_key=lambda item: item.device_uid,
    )
    frozen_records = tuple(verified_records)
    _require_complete_references(
        frozen_records,
        path_prefix=path_prefix,
    )
    return VerifiedCandidateDeviceRecordSet._construct(
        host_id=host_id,
        host_epoch=host_epoch,
        agent_generation=agent_generation,
        snapshot_epoch=snapshot_epoch,
        captured_at=captured,
        device_records=frozen_records,
        device_records_by_digest=MappingProxyType(
            {
                key: records_by_digest[key]
                for key in sorted(records_by_digest, key=canonical_json_bytes)
            }
        ),
        device_records_by_uid=MappingProxyType(
            {
                key: records_by_uid[key]
                for key in sorted(records_by_uid, key=canonical_json_bytes)
            }
        ),
        device_records_by_bdf=MappingProxyType(
            {
                key: records_by_bdf[key]
                for key in sorted(records_by_bdf, key=canonical_json_bytes)
            }
        ),
    )


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _build_inventory_verification_receipt(
    schemas: ContractSchemas,
    *,
    trust: VerifiedTrustContext,
    verifier_identity: InventoryVerifierAlgorithmIdentity,
    authority: Mapping[str, Any],
    authority_raw: bytes,
    snapshot: Mapping[str, Any],
    snapshot_raw: bytes,
    records: Sequence[VerifiedDeviceRecord],
    signer_key_id: str,
    signer_principal_id: str,
    verified_at: datetime,
) -> tuple[Mapping[str, Any], bytes, str]:
    record_bindings = [
        {
            "deviceUid": record.device_uid,
            "deviceRecordHash": record.device_record_hash,
            "canonicalDigest": sha256_digest(record.canonical_bytes),
        }
        for record in records
    ]
    record_bindings.sort(
        key=lambda item: canonical_json_bytes(
            [item["deviceUid"], item["deviceRecordHash"]]
        )
    )
    _require_canonical_order(
        record_bindings,
        path="inventory.verificationReceipt.deviceRecords",
        order_key=lambda item: [
            item["deviceUid"],
            item["deviceRecordHash"],
        ],
    )
    for field_name in (
        "deviceUid",
        "deviceRecordHash",
        "canonicalDigest",
    ):
        require(
            len({item[field_name] for item in record_bindings}) == len(record_bindings),
            "INVENTORY_RECEIPT_BINDING_INVALID",
            f"inventory.verificationReceipt.deviceRecords.{field_name}",
            f"receipt descriptors contain a duplicate {field_name}",
        )
    receipt_record_hashes = tuple(
        sorted(
            (item["deviceRecordHash"] for item in record_bindings),
            key=canonical_json_bytes,
        )
    )
    require(
        receipt_record_hashes == tuple(snapshot["deviceRecordDigests"]),
        "INVENTORY_RECEIPT_BINDING_INVALID",
        "inventory.verificationReceipt.deviceRecords",
        "receipt record hashes do not exactly equal HostSnapshot membership",
    )
    receipt = {
        "subjectType": "INVENTORY_VERIFICATION_RECEIPT",
        "schemaVersion": 1,
        "canonicalProfileId": "CANONICAL-JSON-V1",
        "inventoryVerifierAlgorithmIdentityDigest": (verifier_identity.digest),
        "trustContextDigest": trust.context_digest,
        "trustFreshnessReceiptDigest": (trust.freshness_receipt_digest),
        "trustFreshnessExpiresAt": _format_timestamp(trust.freshness_expires_at),
        "hostAuthorityCanonicalDigest": sha256_digest(authority_raw),
        "hostSnapshotCanonicalDigest": sha256_digest(snapshot_raw),
        "hostId": snapshot["hostId"],
        "kernelBootId": snapshot["kernelBootId"],
        "hostEpoch": snapshot["hostEpoch"],
        "agentGeneration": snapshot["agentGeneration"],
        "observedHostAuthorityResourceVersion": authority["resourceVersion"],
        "snapshotHostAuthorityResourceVersion": snapshot[
            "hostAuthorityResourceVersion"
        ],
        "snapshotEpoch": snapshot["snapshotEpoch"],
        "hostSnapshotContentHash": snapshot["contentHash"],
        "inventorySignerKeyId": signer_key_id,
        "inventorySignerPrincipalId": signer_principal_id,
        "deviceRecords": record_bindings,
        "verifiedAt": _format_timestamp(verified_at),
        "receiptDigest": None,
    }
    require(
        receipt["observedHostAuthorityResourceVersion"]
        == receipt["snapshotHostAuthorityResourceVersion"],
        "HOST_SNAPSHOT_NOT_CURRENT",
        "inventory.verificationReceipt.resourceVersion",
        "observed and signed HostAuthority resource versions differ",
    )
    projection_raw = canonical_json_bytes(receipt)
    receipt_digest = sha256_digest(_VERIFICATION_RECEIPT_DOMAIN + projection_raw)
    receipt["receiptDigest"] = receipt_digest
    schemas.validate(
        "inventory_verification_receipt",
        receipt,
        "inventory.verificationReceipt",
    )
    raw = canonical_json_bytes(receipt)
    return _deep_freeze(receipt), raw, receipt_digest


def verify_inventory_context(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    *,
    host_authority_before: JsonDocument,
    host_snapshot: JsonDocument,
    device_records: Sequence[JsonDocument],
    host_authority_after: JsonDocument,
    now: datetime,
    limits: InventoryVerifierLimits | None = None,
) -> VerifiedInventoryContext:
    """Verify a complete, stable current HostSnapshot inventory.

    ``host_authority_before`` and ``host_authority_after`` are mandatory so an
    integration cannot accidentally perform only one current-pointer check.
    Equality here still does not prove independent reads, repository
    linearizability, atomic publication, or CAS semantics; those are caller
    obligations.
    """

    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="TRUST_CONTEXT_INVALID",
        path="inventory.trust",
        message="trust context must come from verify_trust_context",
    )
    checked_limits = _checked_limits(limits)
    budget = _InventoryBudget(checked_limits)
    verified_now = _utc_time(now, "inventory.now")
    require(
        trust.verified_at <= verified_now <= trust.freshness_expires_at,
        "TRUST_CONTEXT_STALE",
        "inventory.now",
        "inventory verification is outside the trust freshness window",
    )

    authority_before, authority_before_raw = _document(
        host_authority_before,
        "inventory.hostAuthorityBefore",
        limits=checked_limits,
        budget=budget,
    )
    authority_after, authority_after_raw = _document(
        host_authority_after,
        "inventory.hostAuthorityAfter",
        limits=checked_limits,
        budget=budget,
    )
    schemas.validate(
        "authority_entities",
        authority_before,
        "inventory.hostAuthorityBefore",
    )
    schemas.validate(
        "authority_entities",
        authority_after,
        "inventory.hostAuthorityAfter",
    )
    require(
        authority_before_raw == authority_after_raw,
        "INVENTORY_AUTHORITY_CHANGED",
        "inventory.hostAuthorityAfter",
        "HostAuthority changed across the caller-supplied before/after reads",
    )

    snapshot, snapshot_raw = _document(
        host_snapshot,
        "inventory.hostSnapshot",
        limits=checked_limits,
        budget=budget,
    )
    schemas.validate(
        "portable_hash_subjects",
        snapshot,
        "inventory.hostSnapshot",
    )
    _require_canonical_order(
        snapshot["deviceRecordDigests"],
        path="inventory.hostSnapshot.deviceRecordDigests",
    )
    captured_at = _timestamp(
        snapshot["capturedAt"],
        "inventory.hostSnapshot.capturedAt",
    )
    require(
        captured_at <= verified_now,
        "HOST_SNAPSHOT_FROM_FUTURE",
        "inventory.hostSnapshot.capturedAt",
        "snapshot capture time is later than evaluator time",
    )
    snapshot_digest, signer = _verify_role_signed_document(
        snapshot,
        trust=trust,
        digest_field="contentHash",
        signature_field="signature",
        signer_field="signerKeyId",
        signed_time_field="capturedAt",
        domain=_HOST_SNAPSHOT_DOMAIN,
        required_role="HOST_INVENTORY_EVIDENCE",
        path="inventory.hostSnapshot",
        require_current_ring=True,
        evaluation_time=verified_now,
    )

    pointer_fields = (
        ("hostId", "hostId"),
        ("kernelBootId", "kernelBootId"),
        ("hostEpoch", "hostEpoch"),
        ("agentGeneration", "agentGeneration"),
        ("resourceVersion", "hostAuthorityResourceVersion"),
        ("lastSnapshotEpoch", "snapshotEpoch"),
        ("currentSnapshotContentHash", "contentHash"),
    )
    for authority_field, snapshot_field in pointer_fields:
        _require_equal(
            authority_before[authority_field],
            snapshot[snapshot_field],
            code="HOST_SNAPSHOT_NOT_CURRENT",
            path=f"inventory.hostSnapshot.{snapshot_field}",
            description=(
                "HostSnapshot does not match the exact HostAuthority "
                f"{authority_field} current pointer field"
            ),
        )

    require(
        isinstance(device_records, Sequence)
        and not isinstance(
            device_records,
            (str, bytes, bytearray, memoryview),
        ),
        "DEVICE_RECORD_SET_INVALID",
        "inventory.deviceRecords",
        "expected the complete sequence of DeviceRecord documents",
    )
    require(
        1 <= len(device_records) <= checked_limits.max_current_device_records,
        "DEVICE_RECORD_SET_TOO_LARGE",
        "inventory.deviceRecords",
        (
            "current inventory must contain between 1 and "
            f"{checked_limits.max_current_device_records} records"
        ),
    )
    verified_records: list[VerifiedDeviceRecord] = []
    records_by_digest: dict[str, VerifiedDeviceRecord] = {}
    records_by_uid: dict[str, VerifiedDeviceRecord] = {}
    records_by_bdf: dict[str, VerifiedDeviceRecord] = {}
    for index, value in enumerate(device_records):
        record = _verify_device_record(
            schemas,
            value,
            index=index,
            snapshot=snapshot,
            limits=checked_limits,
            budget=budget,
        )
        require(
            record.device_record_hash not in records_by_digest,
            "DEVICE_RECORD_DUPLICATE",
            f"inventory.deviceRecords[{index}].deviceRecordHash",
            "duplicate DeviceRecord hash",
        )
        require(
            record.device_uid not in records_by_uid,
            "DEVICE_UID_DUPLICATE",
            f"inventory.deviceRecords[{index}].deviceUid",
            "duplicate device UID in one HostSnapshot",
        )
        require(
            record.current_bdf not in records_by_bdf,
            "DEVICE_BDF_DUPLICATE",
            f"inventory.deviceRecords[{index}].currentBdf",
            "duplicate current BDF in one HostSnapshot",
        )
        verified_records.append(record)
        records_by_digest[record.device_record_hash] = record
        records_by_uid[record.device_uid] = record
        records_by_bdf[record.current_bdf] = record

    expected_membership = tuple(snapshot["deviceRecordDigests"])
    actual_membership = tuple(sorted(records_by_digest, key=canonical_json_bytes))
    require(
        actual_membership == expected_membership,
        "DEVICE_MEMBERSHIP_MISMATCH",
        "inventory.deviceRecords",
        (
            "supplied DeviceRecords are not the complete exact digest set "
            "named by HostSnapshot.deviceRecordDigests"
        ),
    )
    records_in_digest_order = tuple(
        records_by_digest[digest] for digest in expected_membership
    )
    _require_complete_references(records_in_digest_order)
    snapshot_semantics = derive_host_snapshot_semantics(
        snapshot,
        tuple(record.document for record in records_in_digest_order),
    )
    schemas.validate_ref(
        (
            "contracts/directpath-host-snapshot-publication-trace.schema.json"
            "#/$defs/topologyProjection"
        ),
        _deep_thaw(snapshot_semantics.topology_projection),
        "inventory.snapshotSemantics.topologyProjection",
    )
    schemas.validate_ref(
        (
            "contracts/directpath-host-snapshot-publication-trace.schema.json"
            "#/$defs/providerSemanticProjection"
        ),
        _deep_thaw(snapshot_semantics.provider_semantic_projection),
        "inventory.snapshotSemantics.providerSemanticProjection",
    )
    _require_equal(
        snapshot["topologyDigest"],
        snapshot_semantics.topology_digest,
        code="HOST_SNAPSHOT_TOPOLOGY_DIGEST_INVALID",
        path="inventory.hostSnapshot.topologyDigest",
        description=(
            "HostSnapshot topology digest does not replay from its complete "
            "V3 DeviceRecord semantic projections"
        ),
    )
    _require_equal(
        snapshot["providerFactsDigest"],
        snapshot_semantics.provider_facts_digest,
        code="HOST_SNAPSHOT_PROVIDER_FACTS_DIGEST_INVALID",
        path="inventory.hostSnapshot.providerFactsDigest",
        description=(
            "HostSnapshot provider digest does not replay from exact provider "
            "identity-to-device coverage"
        ),
    )
    verifier_algorithm_identity = derive_inventory_verifier_algorithm_identity(schemas)
    (
        verification_receipt,
        verification_receipt_raw,
        verification_receipt_digest,
    ) = _build_inventory_verification_receipt(
        schemas,
        trust=trust,
        verifier_identity=verifier_algorithm_identity,
        authority=authority_before,
        authority_raw=authority_before_raw,
        snapshot=snapshot,
        snapshot_raw=snapshot_raw,
        records=records_in_digest_order,
        signer_key_id=signer.key_id,
        signer_principal_id=signer.principal_id,
        verified_at=verified_now,
    )

    frozen_by_digest = MappingProxyType(
        {digest: records_by_digest[digest] for digest in expected_membership}
    )
    frozen_by_uid = MappingProxyType(
        {
            key: records_by_uid[key]
            for key in sorted(records_by_uid, key=canonical_json_bytes)
        }
    )
    frozen_by_bdf = MappingProxyType(
        {
            key: records_by_bdf[key]
            for key in sorted(records_by_bdf, key=canonical_json_bytes)
        }
    )
    return VerifiedInventoryContext._construct(
        trust=trust,
        host_authority=_deep_freeze(authority_before),
        host_authority_canonical_bytes=authority_before_raw,
        host_snapshot=_deep_freeze(snapshot),
        host_snapshot_canonical_bytes=snapshot_raw,
        host_id=snapshot["hostId"],
        kernel_boot_id=snapshot["kernelBootId"],
        host_epoch=snapshot["hostEpoch"],
        agent_identity=authority_before["agentIdentity"],
        agent_generation=snapshot["agentGeneration"],
        observed_authority_resource_version=authority_before["resourceVersion"],
        snapshot_authority_resource_version=snapshot["hostAuthorityResourceVersion"],
        snapshot_epoch=snapshot["snapshotEpoch"],
        snapshot_content_hash=snapshot_digest,
        policy_hash=snapshot["policyHash"],
        captured_at=captured_at,
        inventory_signer_key_id=signer.key_id,
        inventory_signer_principal_id=signer.principal_id,
        verified_at=verified_now,
        verifier_algorithm_identity=verifier_algorithm_identity,
        inventory_verifier_identity_digest=(verifier_algorithm_identity.digest),
        inventory_verification_receipt=verification_receipt,
        inventory_verification_receipt_canonical_bytes=(verification_receipt_raw),
        inventory_verification_receipt_digest=(verification_receipt_digest),
        device_records=records_in_digest_order,
        device_records_by_digest=frozen_by_digest,
        device_records_by_uid=frozen_by_uid,
        device_records_by_bdf=frozen_by_bdf,
        snapshot_semantics=snapshot_semantics,
    )


__all__ = [
    "DEFAULT_INVENTORY_VERIFIER_LIMITS",
    "InventoryVerifierLimits",
    "InventoryVerifierAlgorithmIdentity",
    "JsonDocument",
    "MAX_CURRENT_INVENTORY_DEVICE_RECORDS",
    "MAX_HOST_SNAPSHOT_DEVICE_RECORDS",
    "VerifiedCandidateDeviceRecordSet",
    "VerifiedDeviceRecord",
    "VerifiedInventoryContext",
    "derive_inventory_verifier_algorithm_identity",
    "derive_device_provider_facts_digest",
    "verify_candidate_device_record_set",
    "verify_inventory_context",
]
