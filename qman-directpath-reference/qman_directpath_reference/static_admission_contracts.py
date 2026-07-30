"""Closed, side-effect-free Static admission command and commit contracts.

This module performs only strict normalization, CANONICAL-JSON-V1 encoding, and
null-field hashing.  It imports no database client and cannot prove a
repository read, transaction, CAS, durable lease, or product integration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
import re
from typing import Any
import unicodedata


EVIDENCE_BOUNDARY = "REFERENCE_SQLITE_TRANSACTION_COMPONENT_ONLY"
SAFE_INTEGER = 9_007_199_254_740_991
IDEMPOTENCY_SCOPE_DOMAIN = b"QMAN-DIRECTPATH/IDEMPOTENCY-SCOPE/V1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class CanonicalizationError(ValueError):
    """A value is not representable as exact CANONICAL-JSON-V1."""


class ContractViolation(ValueError):
    """A wire value violates the closed command or commit contract."""


def _validate_string(value: str, path: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalizationError(f"{path}: string is not Unicode NFC")
    try:
        value.encode("utf-8", errors="strict")
        value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError as error:
        raise CanonicalizationError(f"{path}: unpaired Unicode surrogate") from error


def _utf16_sort_key(value: str) -> bytes:
    _validate_string(value, "object key")
    return value.encode("utf-16-be")


def _canonical_text(value: Any, path: str = "$") -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise CanonicalizationError(
                f"{path}: integer is outside the interoperable safe range"
            )
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floating-point values are forbidden")
    if isinstance(value, str):
        _validate_string(value, path)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return (
            "["
            + ",".join(
                _canonical_text(item, f"{path}[{index}]")
                for index, item in enumerate(value)
            )
            + "]"
        )
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: JSON object key is not a string")
        members: list[str] = []
        for key in sorted(value, key=_utf16_sort_key):
            _validate_string(key, f"{path} object key")
            encoded_key = json.dumps(
                key,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            members.append(
                encoded_key + ":" + _canonical_text(value[key], f"{path}.{key}")
            )
        return "{" + ",".join(members) + "}"
    raise CanonicalizationError(
        f"{path}: unsupported JSON value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return the repository contract's strict canonical UTF-8 bytes."""

    return _canonical_text(value).encode("utf-8")


def sha256_digest(data: bytes | bytearray | memoryview) -> str:
    """Return a lowercase ``sha256:`` digest."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256_digest requires bytes-like input")
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def _pairs_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(token: str) -> Any:
    raise CanonicalizationError(f"non-JSON numeric constant is forbidden: {token}")


def load_canonical_json(
    data: bytes | bytearray | memoryview,
) -> Any:
    """Parse JSON while requiring exact canonical input bytes."""

    raw = bytes(data)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalizationError(f"invalid UTF-8 JSON: {error}") from error
    if raw != canonical_json_bytes(value):
        raise CanonicalizationError("input is not exact CANONICAL-JSON-V1 bytes")
    return value


def _closed_mapping(
    value: object,
    expected_fields: frozenset[str],
    path: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractViolation(f"{path}: expected an object")
    actual = set(value)
    missing = sorted(expected_fields - actual)
    extra = sorted(actual - expected_fields)
    if missing or extra:
        raise ContractViolation(
            f"{path}: closed fields mismatch; missing={missing}, extra={extra}"
        )
    return value


def _id(value: object, path: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ContractViolation(f"{path}: invalid closed identifier")
    return value


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ContractViolation(f"{path}: expected sha256:<64 lowercase hex>")
    return value


def _positive(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > SAFE_INTEGER
    ):
        raise ContractViolation(
            f"{path}: expected an interoperable-safe positive integer"
        )
    return value


def _timestamp(value: object, path: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise ContractViolation(
            f"{path}: expected UTC timestamp with six fractional digits"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise ContractViolation(f"{path}: invalid UTC timestamp") from error
    return value


def _constant(
    actual: object,
    expected: object,
    path: str,
) -> None:
    if actual != expected:
        raise ContractViolation(f"{path}: expected {expected!r}")


def _null_field_hash(subject: Mapping[str, object]) -> str:
    return sha256_digest(canonical_json_bytes(subject))


def derive_idempotency_scope_hash(vm_id: str) -> str:
    """Derive the frozen operation/VM idempotency scope identity."""

    normalized_vm_id = _id(vm_id, "vmId")
    subject = {
        "operationId": "STATIC_ADMISSION",
        "vmId": normalized_vm_id,
    }
    return sha256_digest(
        IDEMPOTENCY_SCOPE_DOMAIN + b"\x00" + canonical_json_bytes(subject)
    )


@dataclass(frozen=True, slots=True)
class StaticAdmissionRequestReference:
    """Business reference to an immutable persisted Static request."""

    request_version: int
    request_hash: str

    def __post_init__(self) -> None:
        _positive(self.request_version, "requestReference.requestVersion")
        _digest(self.request_hash, "requestReference.requestHash")

    def to_wire(self) -> dict[str, object]:
        return {
            "requestVersion": self.request_version,
            "requestHash": self.request_hash,
        }

    @classmethod
    def from_wire(
        cls,
        value: object,
    ) -> "StaticAdmissionRequestReference":
        raw = _closed_mapping(
            value,
            frozenset({"requestVersion", "requestHash"}),
            "requestReference",
        )
        return cls(
            request_version=_positive(
                raw["requestVersion"],
                "requestReference.requestVersion",
            ),
            request_hash=_digest(
                raw["requestHash"],
                "requestReference.requestHash",
            ),
        )


@dataclass(frozen=True, slots=True)
class StaticAdmissionCommand:
    """Closed business command; never an authority or admission token."""

    command_id: str
    vm_id: str
    run_id: str
    idempotency_key: str
    actor: str
    deadline: str
    request_reference: StaticAdmissionRequestReference
    command_hash: str

    def __post_init__(self) -> None:
        for name in (
            "command_id",
            "vm_id",
            "run_id",
            "idempotency_key",
            "actor",
        ):
            _id(getattr(self, name), name)
        _timestamp(self.deadline, "deadline")
        if not isinstance(
            self.request_reference,
            StaticAdmissionRequestReference,
        ):
            raise ContractViolation(
                "request_reference: expected StaticAdmissionRequestReference"
            )
        _digest(self.command_hash, "commandHash")
        expected = _null_field_hash(self._subject(command_hash=None))
        if not hmac.compare_digest(self.command_hash, expected):
            raise ContractViolation(
                "commandHash: digest does not match null-field command"
            )

    @staticmethod
    def _subject_from_values(
        *,
        command_id: str,
        vm_id: str,
        run_id: str,
        idempotency_key: str,
        actor: str,
        deadline: str,
        request_reference: StaticAdmissionRequestReference,
        command_hash: str | None,
    ) -> dict[str, object]:
        return {
            "subjectType": "STATIC_ADMISSION_COMMAND",
            "schemaVersion": 1,
            "commandId": command_id,
            "vmId": vm_id,
            "runId": run_id,
            "idempotencyKey": idempotency_key,
            "actor": actor,
            "deadline": deadline,
            "requestReference": request_reference.to_wire(),
            "commandHash": command_hash,
        }

    def _subject(
        self,
        *,
        command_hash: str | None,
    ) -> dict[str, object]:
        return self._subject_from_values(
            command_id=self.command_id,
            vm_id=self.vm_id,
            run_id=self.run_id,
            idempotency_key=self.idempotency_key,
            actor=self.actor,
            deadline=self.deadline,
            request_reference=self.request_reference,
            command_hash=command_hash,
        )

    @classmethod
    def create(
        cls,
        *,
        command_id: str,
        vm_id: str,
        run_id: str,
        idempotency_key: str,
        actor: str,
        deadline: str,
        request_reference: StaticAdmissionRequestReference,
    ) -> "StaticAdmissionCommand":
        values = {
            "command_id": _id(command_id, "command_id"),
            "vm_id": _id(vm_id, "vm_id"),
            "run_id": _id(run_id, "run_id"),
            "idempotency_key": _id(
                idempotency_key,
                "idempotency_key",
            ),
            "actor": _id(actor, "actor"),
            "deadline": _timestamp(deadline, "deadline"),
            "request_reference": request_reference,
        }
        if not isinstance(
            request_reference,
            StaticAdmissionRequestReference,
        ):
            raise ContractViolation(
                "request_reference: expected StaticAdmissionRequestReference"
            )
        command_hash = _null_field_hash(
            cls._subject_from_values(**values, command_hash=None)
        )
        return cls(**values, command_hash=command_hash)

    def to_wire(self) -> dict[str, object]:
        return self._subject(command_hash=self.command_hash)

    def to_canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_wire())

    @classmethod
    def from_wire(cls, value: object) -> "StaticAdmissionCommand":
        raw = _closed_mapping(
            value,
            frozenset(
                {
                    "subjectType",
                    "schemaVersion",
                    "commandId",
                    "vmId",
                    "runId",
                    "idempotencyKey",
                    "actor",
                    "deadline",
                    "requestReference",
                    "commandHash",
                }
            ),
            "$",
        )
        _constant(
            raw["subjectType"],
            "STATIC_ADMISSION_COMMAND",
            "subjectType",
        )
        _constant(raw["schemaVersion"], 1, "schemaVersion")
        return cls(
            command_id=_id(raw["commandId"], "commandId"),
            vm_id=_id(raw["vmId"], "vmId"),
            run_id=_id(raw["runId"], "runId"),
            idempotency_key=_id(
                raw["idempotencyKey"],
                "idempotencyKey",
            ),
            actor=_id(raw["actor"], "actor"),
            deadline=_timestamp(raw["deadline"], "deadline"),
            request_reference=StaticAdmissionRequestReference.from_wire(
                raw["requestReference"]
            ),
            command_hash=_digest(raw["commandHash"], "commandHash"),
        )


def parse_static_admission_command(
    data: bytes | bytearray | memoryview,
) -> StaticAdmissionCommand:
    """Parse exact canonical command bytes and reject every extra field."""

    return StaticAdmissionCommand.from_wire(load_canonical_json(data))


@dataclass(frozen=True, slots=True)
class OperationLeaseMemberGeneration:
    """One exact member generation in a committed lease capability."""

    id: str
    generation: int

    def __post_init__(self) -> None:
        _id(self.id, "memberGeneration.id")
        _positive(self.generation, "memberGeneration.generation")

    def to_wire(self) -> dict[str, object]:
        return {"id": self.id, "generation": self.generation}

    @classmethod
    def from_wire(
        cls,
        value: object,
    ) -> "OperationLeaseMemberGeneration":
        raw = _closed_mapping(
            value,
            frozenset({"id", "generation"}),
            "memberGeneration",
        )
        return cls(
            id=_id(raw["id"], "memberGeneration.id"),
            generation=_positive(
                raw["generation"],
                "memberGeneration.generation",
            ),
        )


@dataclass(frozen=True, slots=True)
class CommittedOperationLeaseCapability:
    """Exact operation-envelope ASSIGNMENT_PREPARE capability projection."""

    operation_lease_id: str
    scope_hash: str
    run_id_or_intent_id: str
    bundle_ids: tuple[str, ...]
    member_generations: tuple[OperationLeaseMemberGeneration, ...]
    host_epoch: int
    run_generation_or_null: int
    holder_controller_generation: int
    operation_lease_resource_version: int
    admission_binding_hash_or_null: str

    def __post_init__(self) -> None:
        _id(self.operation_lease_id, "operationLeaseId")
        _digest(self.scope_hash, "scopeHash")
        _id(self.run_id_or_intent_id, "runIdOrIntentId")
        bundle_ids = tuple(self.bundle_ids)
        if len(bundle_ids) != 1:
            raise ContractViolation(
                "bundleIds: guarded Static admission requires one bundle"
            )
        _digest(bundle_ids[0], "bundleIds[0]")
        object.__setattr__(self, "bundle_ids", bundle_ids)

        members = tuple(self.member_generations)
        if not members or len(members) > 4096:
            raise ContractViolation("memberGenerations: expected 1..4096 members")
        for index, member in enumerate(members):
            if not isinstance(member, OperationLeaseMemberGeneration):
                raise ContractViolation(f"memberGenerations[{index}]: invalid member")
        ordered = tuple(
            sorted(
                members,
                key=lambda item: canonical_json_bytes([item.id, item.generation]),
            )
        )
        if members != ordered or len({item.id for item in members}) != len(members):
            raise ContractViolation(
                "memberGenerations: expected unique canonical member order"
            )
        object.__setattr__(self, "member_generations", members)
        for name in (
            "host_epoch",
            "run_generation_or_null",
            "holder_controller_generation",
            "operation_lease_resource_version",
        ):
            _positive(getattr(self, name), name)
        _digest(
            self.admission_binding_hash_or_null,
            "admissionBindingHashOrNull",
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "operationLeaseId": self.operation_lease_id,
            "leaseType": "ASSIGNMENT_PREPARE",
            "scopeHash": self.scope_hash,
            "runIdOrIntentId": self.run_id_or_intent_id,
            "bundleIds": list(self.bundle_ids),
            "memberGenerations": [
                member.to_wire() for member in self.member_generations
            ],
            "hostEpoch": self.host_epoch,
            "runGenerationOrNull": self.run_generation_or_null,
            "holderControllerGeneration": (self.holder_controller_generation),
            "operationLeaseResourceVersion": (self.operation_lease_resource_version),
            "admissionBindingHashOrNull": (self.admission_binding_hash_or_null),
        }

    @classmethod
    def from_wire(
        cls,
        value: object,
    ) -> "CommittedOperationLeaseCapability":
        raw = _closed_mapping(
            value,
            frozenset(
                {
                    "operationLeaseId",
                    "leaseType",
                    "scopeHash",
                    "runIdOrIntentId",
                    "bundleIds",
                    "memberGenerations",
                    "hostEpoch",
                    "runGenerationOrNull",
                    "holderControllerGeneration",
                    "operationLeaseResourceVersion",
                    "admissionBindingHashOrNull",
                }
            ),
            "operationLeaseCapability",
        )
        _constant(
            raw["leaseType"],
            "ASSIGNMENT_PREPARE",
            "operationLeaseCapability.leaseType",
        )
        bundle_ids_raw = raw["bundleIds"]
        if not isinstance(bundle_ids_raw, Sequence) or isinstance(
            bundle_ids_raw, (str, bytes)
        ):
            raise ContractViolation(
                "operationLeaseCapability.bundleIds: expected array"
            )
        members_raw = raw["memberGenerations"]
        if not isinstance(members_raw, Sequence) or isinstance(
            members_raw, (str, bytes)
        ):
            raise ContractViolation(
                "operationLeaseCapability.memberGenerations: expected array"
            )
        return cls(
            operation_lease_id=_id(
                raw["operationLeaseId"],
                "operationLeaseCapability.operationLeaseId",
            ),
            scope_hash=_digest(
                raw["scopeHash"],
                "operationLeaseCapability.scopeHash",
            ),
            run_id_or_intent_id=_id(
                raw["runIdOrIntentId"],
                "operationLeaseCapability.runIdOrIntentId",
            ),
            bundle_ids=tuple(
                _digest(
                    item,
                    f"operationLeaseCapability.bundleIds[{index}]",
                )
                for index, item in enumerate(bundle_ids_raw)
            ),
            member_generations=tuple(
                OperationLeaseMemberGeneration.from_wire(item) for item in members_raw
            ),
            host_epoch=_positive(
                raw["hostEpoch"],
                "operationLeaseCapability.hostEpoch",
            ),
            run_generation_or_null=_positive(
                raw["runGenerationOrNull"],
                "operationLeaseCapability.runGenerationOrNull",
            ),
            holder_controller_generation=_positive(
                raw["holderControllerGeneration"],
                ("operationLeaseCapability.holderControllerGeneration"),
            ),
            operation_lease_resource_version=_positive(
                raw["operationLeaseResourceVersion"],
                ("operationLeaseCapability.operationLeaseResourceVersion"),
            ),
            admission_binding_hash_or_null=_digest(
                raw["admissionBindingHashOrNull"],
                "operationLeaseCapability.admissionBindingHashOrNull",
            ),
        )


@dataclass(frozen=True, slots=True)
class CommittedResourceVersions:
    """Exact repository versions retained by the committed result."""

    controller_authority_resource_version: int
    host_authority_resource_version: int
    request_resource_version: int
    policy_authority_resource_version: int
    availability_authority_resource_version: int
    assignment_run_resource_version: int
    bundle_lease_resource_version: int
    operation_lease_resource_version: int

    def __post_init__(self) -> None:
        for name in (
            "controller_authority_resource_version",
            "host_authority_resource_version",
            "request_resource_version",
            "policy_authority_resource_version",
            "availability_authority_resource_version",
            "assignment_run_resource_version",
            "bundle_lease_resource_version",
            "operation_lease_resource_version",
        ):
            _positive(getattr(self, name), name)

    def to_wire(self) -> dict[str, object]:
        return {
            "controllerAuthorityResourceVersion": (
                self.controller_authority_resource_version
            ),
            "hostAuthorityResourceVersion": (self.host_authority_resource_version),
            "requestResourceVersion": self.request_resource_version,
            "policyAuthorityResourceVersion": (self.policy_authority_resource_version),
            "availabilityAuthorityResourceVersion": (
                self.availability_authority_resource_version
            ),
            "assignmentRunResourceVersion": (self.assignment_run_resource_version),
            "bundleLeaseResourceVersion": (self.bundle_lease_resource_version),
            "operationLeaseResourceVersion": (self.operation_lease_resource_version),
        }

    @classmethod
    def from_wire(cls, value: object) -> "CommittedResourceVersions":
        names = {
            "controllerAuthorityResourceVersion": (
                "controller_authority_resource_version"
            ),
            "hostAuthorityResourceVersion": ("host_authority_resource_version"),
            "requestResourceVersion": "request_resource_version",
            "policyAuthorityResourceVersion": ("policy_authority_resource_version"),
            "availabilityAuthorityResourceVersion": (
                "availability_authority_resource_version"
            ),
            "assignmentRunResourceVersion": ("assignment_run_resource_version"),
            "bundleLeaseResourceVersion": ("bundle_lease_resource_version"),
            "operationLeaseResourceVersion": ("operation_lease_resource_version"),
        }
        raw = _closed_mapping(
            value,
            frozenset(names),
            "committedResourceVersions",
        )
        return cls(
            **{
                attribute: _positive(
                    raw[wire],
                    f"committedResourceVersions.{wire}",
                )
                for wire, attribute in names.items()
            }
        )


@dataclass(frozen=True, slots=True)
class IdempotencyNaturalKey:
    """Natural key for one Static admission command stream."""

    idempotency_scope_hash: str
    idempotency_key: str

    def __post_init__(self) -> None:
        _digest(
            self.idempotency_scope_hash,
            "idempotency.naturalKey.idempotencyScopeHash",
        )
        _id(
            self.idempotency_key,
            "idempotency.naturalKey.idempotencyKey",
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "operationId": "STATIC_ADMISSION",
            "idempotencyScopeHash": self.idempotency_scope_hash,
            "idempotencyKey": self.idempotency_key,
        }

    @classmethod
    def from_wire(cls, value: object) -> "IdempotencyNaturalKey":
        raw = _closed_mapping(
            value,
            frozenset(
                {
                    "operationId",
                    "idempotencyScopeHash",
                    "idempotencyKey",
                }
            ),
            "idempotency.naturalKey",
        )
        _constant(
            raw["operationId"],
            "STATIC_ADMISSION",
            "idempotency.naturalKey.operationId",
        )
        return cls(
            idempotency_scope_hash=_digest(
                raw["idempotencyScopeHash"],
                "idempotency.naturalKey.idempotencyScopeHash",
            ),
            idempotency_key=_id(
                raw["idempotencyKey"],
                "idempotency.naturalKey.idempotencyKey",
            ),
        )


@dataclass(frozen=True, slots=True)
class CommittedIdempotency:
    """Committed natural key and row resource version."""

    natural_key: IdempotencyNaturalKey
    resource_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.natural_key, IdempotencyNaturalKey):
            raise ContractViolation("idempotency.naturalKey: invalid natural key")
        _positive(self.resource_version, "idempotency.resourceVersion")

    def to_wire(self) -> dict[str, object]:
        return {
            "naturalKey": self.natural_key.to_wire(),
            "resourceVersion": self.resource_version,
        }

    @classmethod
    def from_wire(cls, value: object) -> "CommittedIdempotency":
        raw = _closed_mapping(
            value,
            frozenset({"naturalKey", "resourceVersion"}),
            "idempotency",
        )
        return cls(
            natural_key=IdempotencyNaturalKey.from_wire(raw["naturalKey"]),
            resource_version=_positive(
                raw["resourceVersion"],
                "idempotency.resourceVersion",
            ),
        )


@dataclass(frozen=True, slots=True)
class CommittedStaticAdmission:
    """Closed post-commit result; not a live side-effect authorization."""

    command_id: str
    vm_id: str
    run_id: str
    command_hash: str
    operation_lease_capability: CommittedOperationLeaseCapability
    admission_binding_hash: str
    committed_resource_versions: CommittedResourceVersions
    idempotency: CommittedIdempotency
    repository_transaction_id: str
    commit_sequence: int
    committed_at: str
    result_hash: str

    def __post_init__(self) -> None:
        _id(self.command_id, "commandId")
        _id(self.vm_id, "vmId")
        _id(self.run_id, "runId")
        _digest(self.command_hash, "commandHash")
        if not isinstance(
            self.operation_lease_capability,
            CommittedOperationLeaseCapability,
        ):
            raise ContractViolation("operationLeaseCapability: invalid capability")
        _digest(self.admission_binding_hash, "admissionBindingHash")
        if not isinstance(
            self.committed_resource_versions,
            CommittedResourceVersions,
        ):
            raise ContractViolation("committedResourceVersions: invalid versions")
        if not isinstance(self.idempotency, CommittedIdempotency):
            raise ContractViolation("idempotency: invalid commit")
        _id(
            self.repository_transaction_id,
            "repositoryTransactionId",
        )
        _positive(self.commit_sequence, "commitSequence")
        _timestamp(self.committed_at, "committedAt")
        if self.run_id != self.operation_lease_capability.run_id_or_intent_id:
            raise ContractViolation("runId: does not match committed lease capability")
        expected_scope_hash = derive_idempotency_scope_hash(self.vm_id)
        if self.idempotency.natural_key.idempotency_scope_hash != expected_scope_hash:
            raise ContractViolation(
                "idempotencyScopeHash: does not match operationId/vmId"
            )
        if (
            self.operation_lease_capability.operation_lease_resource_version
            != self.committed_resource_versions.operation_lease_resource_version
        ):
            raise ContractViolation(
                "operationLeaseResourceVersion: committed copies differ"
            )
        if (
            self.operation_lease_capability.admission_binding_hash_or_null
            != self.admission_binding_hash
        ):
            raise ContractViolation(
                "admissionBindingHash: capability and result differ"
            )
        _digest(self.result_hash, "resultHash")
        expected = _null_field_hash(self._subject(result_hash=None))
        if not hmac.compare_digest(self.result_hash, expected):
            raise ContractViolation(
                "resultHash: digest does not match null-field result"
            )

    @staticmethod
    def _subject_from_values(
        *,
        command_id: str,
        vm_id: str,
        run_id: str,
        command_hash: str,
        operation_lease_capability: CommittedOperationLeaseCapability,
        admission_binding_hash: str,
        committed_resource_versions: CommittedResourceVersions,
        idempotency: CommittedIdempotency,
        repository_transaction_id: str,
        commit_sequence: int,
        committed_at: str,
        result_hash: str | None,
    ) -> dict[str, object]:
        return {
            "subjectType": "COMMITTED_STATIC_ADMISSION",
            "schemaVersion": 1,
            "commandId": command_id,
            "vmId": vm_id,
            "runId": run_id,
            "commandHash": command_hash,
            "operationLeaseCapability": (operation_lease_capability.to_wire()),
            "admissionBindingHash": admission_binding_hash,
            "committedResourceVersions": (committed_resource_versions.to_wire()),
            "idempotency": idempotency.to_wire(),
            "repositoryTransactionId": repository_transaction_id,
            "commitSequence": commit_sequence,
            "committedAt": committed_at,
            "resultHash": result_hash,
        }

    def _subject(
        self,
        *,
        result_hash: str | None,
    ) -> dict[str, object]:
        return self._subject_from_values(
            command_id=self.command_id,
            vm_id=self.vm_id,
            run_id=self.run_id,
            command_hash=self.command_hash,
            operation_lease_capability=self.operation_lease_capability,
            admission_binding_hash=self.admission_binding_hash,
            committed_resource_versions=self.committed_resource_versions,
            idempotency=self.idempotency,
            repository_transaction_id=self.repository_transaction_id,
            commit_sequence=self.commit_sequence,
            committed_at=self.committed_at,
            result_hash=result_hash,
        )

    @classmethod
    def create(
        cls,
        *,
        command_id: str,
        vm_id: str,
        run_id: str,
        command_hash: str,
        operation_lease_capability: CommittedOperationLeaseCapability,
        admission_binding_hash: str,
        committed_resource_versions: CommittedResourceVersions,
        idempotency: CommittedIdempotency,
        repository_transaction_id: str,
        commit_sequence: int,
        committed_at: str,
    ) -> "CommittedStaticAdmission":
        values = {
            "command_id": _id(command_id, "commandId"),
            "vm_id": _id(vm_id, "vmId"),
            "run_id": _id(run_id, "runId"),
            "command_hash": _digest(command_hash, "commandHash"),
            "operation_lease_capability": operation_lease_capability,
            "admission_binding_hash": _digest(
                admission_binding_hash,
                "admissionBindingHash",
            ),
            "committed_resource_versions": (committed_resource_versions),
            "idempotency": idempotency,
            "repository_transaction_id": _id(
                repository_transaction_id,
                "repositoryTransactionId",
            ),
            "commit_sequence": _positive(
                commit_sequence,
                "commitSequence",
            ),
            "committed_at": _timestamp(committed_at, "committedAt"),
        }
        for expected_type, name in (
            (
                CommittedOperationLeaseCapability,
                "operation_lease_capability",
            ),
            (CommittedResourceVersions, "committed_resource_versions"),
            (CommittedIdempotency, "idempotency"),
        ):
            if not isinstance(values[name], expected_type):
                raise ContractViolation(f"{name}: invalid typed value")
        result_hash = _null_field_hash(
            cls._subject_from_values(**values, result_hash=None)
        )
        return cls(**values, result_hash=result_hash)

    def to_wire(self) -> dict[str, object]:
        return self._subject(result_hash=self.result_hash)

    def to_canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_wire())

    @classmethod
    def from_wire(cls, value: object) -> "CommittedStaticAdmission":
        raw = _closed_mapping(
            value,
            frozenset(
                {
                    "subjectType",
                    "schemaVersion",
                    "commandId",
                    "vmId",
                    "runId",
                    "commandHash",
                    "operationLeaseCapability",
                    "admissionBindingHash",
                    "committedResourceVersions",
                    "idempotency",
                    "repositoryTransactionId",
                    "commitSequence",
                    "committedAt",
                    "resultHash",
                }
            ),
            "$",
        )
        _constant(
            raw["subjectType"],
            "COMMITTED_STATIC_ADMISSION",
            "subjectType",
        )
        _constant(raw["schemaVersion"], 1, "schemaVersion")
        return cls(
            command_id=_id(raw["commandId"], "commandId"),
            vm_id=_id(raw["vmId"], "vmId"),
            run_id=_id(raw["runId"], "runId"),
            command_hash=_digest(raw["commandHash"], "commandHash"),
            operation_lease_capability=(
                CommittedOperationLeaseCapability.from_wire(
                    raw["operationLeaseCapability"]
                )
            ),
            admission_binding_hash=_digest(
                raw["admissionBindingHash"],
                "admissionBindingHash",
            ),
            committed_resource_versions=CommittedResourceVersions.from_wire(
                raw["committedResourceVersions"]
            ),
            idempotency=CommittedIdempotency.from_wire(raw["idempotency"]),
            repository_transaction_id=_id(
                raw["repositoryTransactionId"],
                "repositoryTransactionId",
            ),
            commit_sequence=_positive(
                raw["commitSequence"],
                "commitSequence",
            ),
            committed_at=_timestamp(raw["committedAt"], "committedAt"),
            result_hash=_digest(raw["resultHash"], "resultHash"),
        )


def parse_committed_static_admission(
    data: bytes | bytearray | memoryview,
) -> CommittedStaticAdmission:
    """Parse exact canonical committed-result bytes and reject extras."""

    return CommittedStaticAdmission.from_wire(load_canonical_json(data))


__all__ = [
    "EVIDENCE_BOUNDARY",
    "CanonicalizationError",
    "CommittedIdempotency",
    "CommittedOperationLeaseCapability",
    "CommittedResourceVersions",
    "CommittedStaticAdmission",
    "ContractViolation",
    "IdempotencyNaturalKey",
    "OperationLeaseMemberGeneration",
    "StaticAdmissionCommand",
    "StaticAdmissionRequestReference",
    "canonical_json_bytes",
    "derive_idempotency_scope_hash",
    "load_canonical_json",
    "parse_committed_static_admission",
    "parse_static_admission_command",
    "sha256_digest",
]
