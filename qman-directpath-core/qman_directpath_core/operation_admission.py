"""Pure relationship binding for one guarded DirectPath operation admission.

The types in this module retain and hash exact caller-supplied values.  They do
not read a repository, establish a serializable transaction, prove that an
OperationLease is live, execute or prove a compare-and-swap, or fence a product
side effect.  A product adapter must supply those authorities and must consume
the resulting binding inside its own live lease/CAS transaction boundary.

``scope_hash`` remains the OperationLease scope identity.  It is deliberately
distinct from ``lease_spec_hash`` and ``binding_hash``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from ._verified import FactoryVerified
from .authority import (
    AvailabilityReadSet,
    BoundCapabilityAuthorization,
    CurrentAuthorityVector,
    RequestReadSet,
)
from .canonical import SAFE_INTEGER, canonical_json_bytes, sha256_digest
from .errors import fail
from .read_guard import GuardedCapabilityRead


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SCHEMA_REF_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    r"(?:#(?:/[A-Za-z0-9._~$-]+)+)?$"
)
_LEASE_TYPES = frozenset(
    {
        "OWNER_TRANSITION",
        "ASSIGNMENT_PREPARE",
        "RELEASE",
        "RELOCATION_HANDOFF",
        "QUARANTINE_REMEDIATION",
    }
)
_RUN_GENERATION_LEASE_TYPES = frozenset(
    {"ASSIGNMENT_PREPARE", "RELEASE", "RELOCATION_HANDOFF"}
)

OPERATION_ADMISSION_BINDING_SCHEMA_REF = (
    "contracts/directpath-operation-admission-binding.schema.json"
)
REQUEST_READ_SET_SCHEMA_REF = (
    OPERATION_ADMISSION_BINDING_SCHEMA_REF + "#/$defs/requestReadSet"
)
AVAILABILITY_READ_SET_SCHEMA_REF = (
    OPERATION_ADMISSION_BINDING_SCHEMA_REF + "#/$defs/availabilityReadSet"
)
CURRENT_AUTHORITY_VECTOR_SCHEMA_REF = (
    OPERATION_ADMISSION_BINDING_SCHEMA_REF + "#/$defs/currentAuthorityVector"
)
CAS_EXPECTATION_SCHEMA_REF = (
    "contracts/directpath-operation-payload.schema.json#/$defs/casExpectation"
)


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
        or value > SAFE_INTEGER
    ):
        fail(
            "INVALID_SEQUENCE",
            path,
            "expected an interoperable-safe positive integer",
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


def _timestamp(value: datetime, path: str) -> str:
    return _utc(value, path).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _schema_ref(value: object, path: str) -> str:
    if not isinstance(value, str) or _SCHEMA_REF_RE.fullmatch(value) is None:
        fail(
            "INVALID_SCHEMA_REF",
            path,
            "expected a closed repository-relative schema reference",
        )
    return value


def _canonical_blob_digest(subject: object) -> str:
    return sha256_digest(canonical_json_bytes(subject))


@dataclass(frozen=True, slots=True)
class ImmutableEvidenceBlobReference:
    """A content-addressed blob locator, not proof of how it was obtained."""

    schema_ref: str
    blob_sha256: str

    def __post_init__(self) -> None:
        _schema_ref(self.schema_ref, "evidence.schema_ref")
        _digest(self.blob_sha256, "evidence.blob_sha256")

    def to_subject(self) -> dict[str, object]:
        return {
            "schemaRef": self.schema_ref,
            "blobSha256": self.blob_sha256,
        }


@dataclass(frozen=True, slots=True)
class OperationLeaseMemberGeneration:
    """One exact member generation requested by an OperationLease."""

    id: str
    generation: int

    def __post_init__(self) -> None:
        _id(self.id, "operation_lease_spec.member_generations.id")
        _positive(
            self.generation,
            "operation_lease_spec.member_generations.generation",
        )

    def to_subject(self) -> dict[str, object]:
        return {"id": self.id, "generation": self.generation}


@dataclass(frozen=True, slots=True)
class OperationLeaseSpec:
    """Closed desired lease capability; this is not a live lease row."""

    operation_lease_id: str
    lease_type: str
    scope_hash: str
    run_id_or_intent_id: str
    bundle_ids: tuple[str, ...]
    member_generations: tuple[OperationLeaseMemberGeneration, ...]
    host_epoch: int
    run_generation_or_none: int | None
    holder_controller_generation: int
    operation_lease_resource_version: int
    lease_spec_hash: str

    def __post_init__(self) -> None:
        _id(
            self.operation_lease_id,
            "operation_lease_spec.operation_lease_id",
        )
        if self.lease_type not in _LEASE_TYPES:
            fail(
                "INVALID_OPERATION_LEASE_SPEC",
                "operation_lease_spec.lease_type",
                "unknown closed OperationLease type",
            )
        _digest(self.scope_hash, "operation_lease_spec.scope_hash")
        _id(
            self.run_id_or_intent_id,
            "operation_lease_spec.run_id_or_intent_id",
        )

        bundle_ids = tuple(self.bundle_ids)
        for index, bundle_id in enumerate(bundle_ids):
            _digest(
                bundle_id,
                f"operation_lease_spec.bundle_ids[{index}]",
            )
        if (
            not bundle_ids
            or len(bundle_ids) > 4096
            or bundle_ids != tuple(sorted(set(bundle_ids), key=canonical_json_bytes))
        ):
            fail(
                "NONCANONICAL_SET",
                "operation_lease_spec.bundle_ids",
                "bundle IDs must be non-empty, unique, and canonically ordered",
            )
        object.__setattr__(self, "bundle_ids", bundle_ids)

        members = tuple(self.member_generations)
        if not members or len(members) > 4096:
            fail(
                "INVALID_OPERATION_LEASE_SPEC",
                "operation_lease_spec.member_generations",
                "expected 1..4096 member generations",
            )
        for index, member in enumerate(members):
            if not isinstance(member, OperationLeaseMemberGeneration):
                fail(
                    "INVALID_OPERATION_LEASE_SPEC",
                    f"operation_lease_spec.member_generations[{index}]",
                    "expected OperationLeaseMemberGeneration",
                )
        expected_members = tuple(
            sorted(
                members,
                key=lambda member: canonical_json_bytes([member.id, member.generation]),
            )
        )
        if members != expected_members or len({member.id for member in members}) != len(
            members
        ):
            fail(
                "NONCANONICAL_SET",
                "operation_lease_spec.member_generations",
                "members must have unique IDs in canonical order",
            )
        object.__setattr__(self, "member_generations", members)

        _positive(self.host_epoch, "operation_lease_spec.host_epoch")
        if self.run_generation_or_none is not None:
            _positive(
                self.run_generation_or_none,
                "operation_lease_spec.run_generation_or_none",
            )
        if (
            self.lease_type in _RUN_GENERATION_LEASE_TYPES
            and self.run_generation_or_none is None
        ):
            fail(
                "INVALID_OPERATION_LEASE_SPEC",
                "operation_lease_spec.run_generation_or_none",
                f"{self.lease_type} requires a run generation",
            )
        _positive(
            self.holder_controller_generation,
            "operation_lease_spec.holder_controller_generation",
        )
        _positive(
            self.operation_lease_resource_version,
            "operation_lease_spec.operation_lease_resource_version",
        )
        _digest(
            self.lease_spec_hash,
            "operation_lease_spec.lease_spec_hash",
        )
        expected_hash = _canonical_blob_digest(self._subject(lease_spec_hash=None))
        if self.lease_spec_hash != expected_hash:
            fail(
                "DIGEST_MISMATCH",
                "operation_lease_spec.lease_spec_hash",
                "digest does not match the null-hash canonical subject",
            )

    @classmethod
    def create(
        cls,
        *,
        operation_lease_id: str,
        lease_type: str,
        scope_hash: str,
        run_id_or_intent_id: str,
        bundle_ids: tuple[str, ...],
        member_generations: tuple[OperationLeaseMemberGeneration, ...],
        host_epoch: int,
        run_generation_or_none: int | None,
        holder_controller_generation: int,
        operation_lease_resource_version: int,
    ) -> "OperationLeaseSpec":
        """Create a validated spec and derive its distinct null-hash digest."""

        values = {
            "operation_lease_id": operation_lease_id,
            "lease_type": lease_type,
            "scope_hash": scope_hash,
            "run_id_or_intent_id": run_id_or_intent_id,
            "bundle_ids": tuple(bundle_ids),
            "member_generations": tuple(member_generations),
            "host_epoch": host_epoch,
            "run_generation_or_none": run_generation_or_none,
            "holder_controller_generation": holder_controller_generation,
            "operation_lease_resource_version": (operation_lease_resource_version),
        }
        projection = cls._subject_from_values(
            **values,
            lease_spec_hash=None,
        )
        return cls(
            **values,
            lease_spec_hash=_canonical_blob_digest(projection),
        )

    @staticmethod
    def _subject_from_values(
        *,
        operation_lease_id: str,
        lease_type: str,
        scope_hash: str,
        run_id_or_intent_id: str,
        bundle_ids: tuple[str, ...],
        member_generations: tuple[OperationLeaseMemberGeneration, ...],
        host_epoch: int,
        run_generation_or_none: int | None,
        holder_controller_generation: int,
        operation_lease_resource_version: int,
        lease_spec_hash: str | None,
    ) -> dict[str, object]:
        return {
            "subjectType": "OPERATION_LEASE_SPEC",
            "schemaVersion": 1,
            "operationLeaseId": operation_lease_id,
            "leaseType": lease_type,
            "scopeHash": scope_hash,
            "runIdOrIntentId": run_id_or_intent_id,
            "bundleIds": list(bundle_ids),
            "memberGenerations": [member.to_subject() for member in member_generations],
            "hostEpoch": host_epoch,
            "runGenerationOrNull": run_generation_or_none,
            "holderControllerGeneration": holder_controller_generation,
            "operationLeaseResourceVersion": (operation_lease_resource_version),
            "leaseSpecHash": lease_spec_hash,
        }

    def _subject(
        self,
        *,
        lease_spec_hash: str | None,
    ) -> dict[str, object]:
        return self._subject_from_values(
            operation_lease_id=self.operation_lease_id,
            lease_type=self.lease_type,
            scope_hash=self.scope_hash,
            run_id_or_intent_id=self.run_id_or_intent_id,
            bundle_ids=self.bundle_ids,
            member_generations=self.member_generations,
            host_epoch=self.host_epoch,
            run_generation_or_none=self.run_generation_or_none,
            holder_controller_generation=self.holder_controller_generation,
            operation_lease_resource_version=(self.operation_lease_resource_version),
            lease_spec_hash=lease_spec_hash,
        )

    def to_subject(self) -> dict[str, object]:
        return self._subject(lease_spec_hash=self.lease_spec_hash)


@dataclass(frozen=True, slots=True)
class OperationAdmissionEvidenceReferences:
    """Exact immutable blob references retained by the relationship binding."""

    request_read_set: ImmutableEvidenceBlobReference
    availability_read_set: ImmutableEvidenceBlobReference
    before_current_authority_vector: ImmutableEvidenceBlobReference
    after_current_authority_vector: ImmutableEvidenceBlobReference
    cas_expectation: ImmutableEvidenceBlobReference

    def __post_init__(self) -> None:
        for field_name in (
            "request_read_set",
            "availability_read_set",
            "before_current_authority_vector",
            "after_current_authority_vector",
            "cas_expectation",
        ):
            if not isinstance(
                getattr(self, field_name),
                ImmutableEvidenceBlobReference,
            ):
                fail(
                    "INVALID_EVIDENCE_REFERENCE",
                    f"evidence_references.{field_name}",
                    "expected ImmutableEvidenceBlobReference",
                )

    def to_subject(self) -> dict[str, object]:
        return {
            "requestReadSet": self.request_read_set.to_subject(),
            "availabilityReadSet": self.availability_read_set.to_subject(),
            "beforeCurrentAuthorityVector": (
                self.before_current_authority_vector.to_subject()
            ),
            "afterCurrentAuthorityVector": (
                self.after_current_authority_vector.to_subject()
            ),
            "casExpectation": self.cas_expectation.to_subject(),
        }


def _authorization_subject(
    authorization: BoundCapabilityAuthorization,
) -> dict[str, object]:
    return {
        "subjectType": "BOUND_CAPABILITY_AUTHORIZATION",
        "schemaVersion": 1,
        "decisionDigest": authorization.decision_digest,
        "semanticDependencyDigest": (authorization.semantic_dependency_digest),
        "authorityVectorDigest": authorization.authority_vector_digest,
        "authorityDisposition": (
            authorization.authority_disposition.to_subject()
        ),
        "evaluatedAt": _timestamp(
            authorization.evaluated_at,
            "authorization.evaluated_at",
        ),
        "validUntil": _timestamp(
            authorization.valid_until,
            "authorization.valid_until",
        ),
    }


def _guarded_read_subject(
    guarded_read: GuardedCapabilityRead,
) -> dict[str, object]:
    evaluation = guarded_read.evaluation
    states = evaluation.states
    return {
        "subjectType": "GUARDED_CAPABILITY_READ",
        "schemaVersion": 1,
        "evaluation": {
            "decision": evaluation.decision.to_wire(),
            "states": {
                "hardwareCapable": states.hardware_capable.value,
                "technicallyAttachable": (states.technically_attachable.value),
                "qualified": states.qualified.value,
                "supported": states.supported.value,
                "policyEligible": states.policy_eligible.value,
                "adminEnabled": states.admin_enabled.value,
                "hostActive": states.host_active.value,
                "available": states.available.value,
                "attachable": states.attachable.value,
                "eligible": states.eligible.value,
            },
            "operationContext": evaluation.operation_context.value,
            "admissionRequirement": (evaluation.admission_requirement.value),
            "bundle": evaluation.bundle.to_wire(),
            "resetContract": evaluation.reset_contract.to_wire(),
            "snapshotSemanticHash": evaluation.snapshot_semantic_hash,
            "profileSemanticHash": evaluation.profile_semantic_hash,
            "semanticHash": evaluation.semantic_hash,
        },
        "authorization": _authorization_subject(guarded_read.authorization),
    }


def _binding_subject(
    *,
    guarded_read: GuardedCapabilityRead,
    before_current_vector: CurrentAuthorityVector,
    after_current_vector: CurrentAuthorityVector,
    request_read_set: RequestReadSet,
    availability_read_set: AvailabilityReadSet,
    operation_lease_spec: OperationLeaseSpec,
    cas_expectation_hash: str,
    evidence_references: OperationAdmissionEvidenceReferences,
    valid_until: datetime,
    binding_hash: str | None,
) -> dict[str, object]:
    authorization = guarded_read.authorization
    disposition = authorization.authority_disposition
    return {
        "subjectType": "OPERATION_ADMISSION_BINDING",
        "schemaVersion": 1,
        "guardedCapabilityReadDigest": _canonical_blob_digest(
            _guarded_read_subject(guarded_read)
        ),
        "capabilityDecisionHash": (guarded_read.evaluation.decision.decision_hash),
        "authorizationDigest": _canonical_blob_digest(
            _authorization_subject(authorization)
        ),
        "authorizationAuthorityVectorDigest": (authorization.authority_vector_digest),
        "authorizationEvaluatedAt": _timestamp(
            authorization.evaluated_at,
            "authorization.evaluated_at",
        ),
        "authorizationValidUntil": _timestamp(
            authorization.valid_until,
            "authorization.valid_until",
        ),
        "authorityDisposition": disposition.to_subject(),
        "authorityBoundary": disposition.authority_boundary,
        "productAuthorized": disposition.product_authorized,
        "authorizationBlockers": list(
            disposition.authorization_blockers
        ),
        "beforeAuthorityVectorDigest": before_current_vector.vector_digest,
        "afterAuthorityVectorDigest": after_current_vector.vector_digest,
        "requestReadSetDigest": request_read_set.read_set_digest,
        "availabilityReadSetDigest": (availability_read_set.read_set_digest),
        "operationLeaseSpec": operation_lease_spec.to_subject(),
        "casExpectationHash": cas_expectation_hash,
        "evidenceBlobReferences": evidence_references.to_subject(),
        "validUntil": _timestamp(valid_until, "valid_until"),
        "bindingHash": binding_hash,
    }


def _require_blob_reference(
    reference: ImmutableEvidenceBlobReference,
    *,
    expected_schema_ref: str,
    expected_blob_sha256: str,
    path: str,
) -> None:
    if reference.schema_ref != expected_schema_ref:
        fail(
            "EVIDENCE_REFERENCE_MISMATCH",
            f"{path}.schema_ref",
            "schema reference does not identify the exact bound blob type",
        )
    if reference.blob_sha256 != expected_blob_sha256:
        fail(
            "EVIDENCE_REFERENCE_MISMATCH",
            f"{path}.blob_sha256",
            "blob hash does not match the exact canonical supplied value",
        )


def _validate_relationships(
    *,
    guarded_read: GuardedCapabilityRead,
    before_current_vector: CurrentAuthorityVector,
    after_current_vector: CurrentAuthorityVector,
    request_read_set: RequestReadSet,
    availability_read_set: AvailabilityReadSet,
    operation_lease_spec: OperationLeaseSpec,
    cas_expectation_hash: str,
    evidence_references: OperationAdmissionEvidenceReferences,
    valid_until: datetime,
) -> None:
    if not isinstance(guarded_read, GuardedCapabilityRead):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "guarded_read",
            "expected GuardedCapabilityRead",
        )
    if not isinstance(before_current_vector, CurrentAuthorityVector):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "before_current_vector",
            "expected CurrentAuthorityVector",
        )
    if not isinstance(after_current_vector, CurrentAuthorityVector):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "after_current_vector",
            "expected CurrentAuthorityVector",
        )
    if not isinstance(request_read_set, RequestReadSet):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "request_read_set",
            "expected RequestReadSet",
        )
    if not isinstance(availability_read_set, AvailabilityReadSet):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "availability_read_set",
            "expected AvailabilityReadSet",
        )
    if not isinstance(operation_lease_spec, OperationLeaseSpec):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "operation_lease_spec",
            "expected OperationLeaseSpec",
        )
    if not isinstance(
        evidence_references,
        OperationAdmissionEvidenceReferences,
    ):
        fail(
            "INVALID_OPERATION_ADMISSION_INPUT",
            "evidence_references",
            "expected OperationAdmissionEvidenceReferences",
        )
    _digest(cas_expectation_hash, "cas_expectation_hash")
    normalized_valid_until = _utc(valid_until, "valid_until")

    before_bytes = canonical_json_bytes(before_current_vector.to_subject())
    after_bytes = canonical_json_bytes(after_current_vector.to_subject())
    if (
        before_bytes != after_bytes
        or before_current_vector.vector_digest != after_current_vector.vector_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "after_current_vector",
            (
                "before and after CurrentAuthorityVector must be "
                "canonical-byte and digest equal"
            ),
        )

    authorization = guarded_read.authorization
    if authorization.authority_disposition.product_authorized:
        fail(
            "AUTHORITY_DISPOSITION_INVALID",
            "guarded_read.authorization.authority_disposition",
            "portable operation admission cannot claim product authority",
        )
    decision = guarded_read.evaluation.decision
    if not decision.eligible or not decision.attachable:
        fail(
            "OPERATION_NOT_ADMITTED",
            "guarded_read.evaluation.decision.eligible",
            "only an attachable eligible guarded decision can be bound",
        )
    if authorization.authority_vector_digest != before_current_vector.vector_digest:
        fail(
            "STALE_AUTHORITY",
            "guarded_read.authorization.authority_vector_digest",
            "authorization does not bind the supplied authority vector",
        )
    if not (
        authorization.evaluated_at < normalized_valid_until <= authorization.valid_until
        and normalized_valid_until <= before_current_vector.evidence_valid_until
    ):
        fail(
            "AUTHORIZATION_WINDOW_INVALID",
            "valid_until",
            "binding validity exceeds authorization or evidence horizon",
        )

    if (
        request_read_set.authority_id != before_current_vector.request_authority_id
        or request_read_set.read_set_digest
        != before_current_vector.request_read_set_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "request_read_set",
            "request read set is not the one in the authority vector",
        )
    if request_read_set.request_hash != decision.request_hash:
        fail(
            "STALE_AUTHORITY",
            "request_read_set.request_hash",
            "request read set does not bind the guarded decision",
        )
    if (
        availability_read_set.authority_id
        != before_current_vector.availability_authority_id
        or availability_read_set.authority_resource_version
        != (before_current_vector.availability_authority_resource_version)
        or availability_read_set.read_set_digest
        != before_current_vector.availability_read_set_digest
    ):
        fail(
            "STALE_AUTHORITY",
            "availability_read_set",
            "availability read set is not the one in the authority vector",
        )
    if (
        decision.bundle_hash is None
        or availability_read_set.bundle_digest != decision.bundle_hash
    ):
        fail(
            "STALE_AUTHORITY",
            "availability_read_set.bundle_digest",
            "availability read set does not cover the guarded bundle",
        )
    if not availability_read_set.predicate_available:
        fail(
            "OPERATION_NOT_ADMITTED",
            "availability_read_set",
            "blocking claim or quarantine evidence forbids admission",
        )
    if operation_lease_spec.lease_type != "ASSIGNMENT_PREPARE":
        fail(
            "INVALID_OPERATION_LEASE_SPEC",
            "operation_lease_spec.lease_type",
            ("guarded STATIC_ADMISSION can bind only an ASSIGNMENT_PREPARE lease"),
        )
    if operation_lease_spec.bundle_ids != (decision.bundle_hash,):
        fail(
            "STALE_AUTHORITY",
            "operation_lease_spec.bundle_ids",
            "lease bundle scope must equal the one guarded bundle exactly",
        )

    observed_members = {
        member.device_uid: member.device_generation
        for member in availability_read_set.member_versions
    }
    leased_members = {
        member.id: member.generation
        for member in operation_lease_spec.member_generations
    }
    if leased_members != observed_members:
        fail(
            "STALE_AUTHORITY",
            "operation_lease_spec.member_generations",
            "lease member generations differ from the availability read set",
        )

    _require_blob_reference(
        evidence_references.request_read_set,
        expected_schema_ref=REQUEST_READ_SET_SCHEMA_REF,
        expected_blob_sha256=_canonical_blob_digest(request_read_set.to_subject()),
        path="evidence_references.request_read_set",
    )
    _require_blob_reference(
        evidence_references.availability_read_set,
        expected_schema_ref=AVAILABILITY_READ_SET_SCHEMA_REF,
        expected_blob_sha256=_canonical_blob_digest(availability_read_set.to_subject()),
        path="evidence_references.availability_read_set",
    )
    _require_blob_reference(
        evidence_references.before_current_authority_vector,
        expected_schema_ref=CURRENT_AUTHORITY_VECTOR_SCHEMA_REF,
        expected_blob_sha256=_canonical_blob_digest(before_current_vector.to_subject()),
        path="evidence_references.before_current_authority_vector",
    )
    _require_blob_reference(
        evidence_references.after_current_authority_vector,
        expected_schema_ref=CURRENT_AUTHORITY_VECTOR_SCHEMA_REF,
        expected_blob_sha256=_canonical_blob_digest(after_current_vector.to_subject()),
        path="evidence_references.after_current_authority_vector",
    )
    _require_blob_reference(
        evidence_references.cas_expectation,
        expected_schema_ref=CAS_EXPECTATION_SCHEMA_REF,
        expected_blob_sha256=cas_expectation_hash,
        path="evidence_references.cas_expectation",
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedOperationAdmissionBinding(FactoryVerified):
    """Verifier-only deterministic binding, never repository/CAS proof."""

    guarded_read: GuardedCapabilityRead
    before_current_vector: CurrentAuthorityVector
    after_current_vector: CurrentAuthorityVector
    request_read_set: RequestReadSet
    availability_read_set: AvailabilityReadSet
    operation_lease_spec: OperationLeaseSpec
    cas_expectation_hash: str
    evidence_references: OperationAdmissionEvidenceReferences
    valid_until: datetime
    binding_hash: str

    def __post_init__(self) -> None:
        _validate_relationships(
            guarded_read=self.guarded_read,
            before_current_vector=self.before_current_vector,
            after_current_vector=self.after_current_vector,
            request_read_set=self.request_read_set,
            availability_read_set=self.availability_read_set,
            operation_lease_spec=self.operation_lease_spec,
            cas_expectation_hash=self.cas_expectation_hash,
            evidence_references=self.evidence_references,
            valid_until=self.valid_until,
        )
        normalized_valid_until = _utc(
            self.valid_until,
            "valid_until",
        )
        object.__setattr__(
            self,
            "valid_until",
            normalized_valid_until,
        )
        _digest(self.binding_hash, "binding_hash")
        expected_hash = _canonical_blob_digest(self._subject(binding_hash=None))
        if self.binding_hash != expected_hash:
            fail(
                "DIGEST_MISMATCH",
                "binding_hash",
                "digest does not match the null-hash canonical subject",
            )

    def _subject(
        self,
        *,
        binding_hash: str | None,
    ) -> dict[str, object]:
        return _binding_subject(
            guarded_read=self.guarded_read,
            before_current_vector=self.before_current_vector,
            after_current_vector=self.after_current_vector,
            request_read_set=self.request_read_set,
            availability_read_set=self.availability_read_set,
            operation_lease_spec=self.operation_lease_spec,
            cas_expectation_hash=self.cas_expectation_hash,
            evidence_references=self.evidence_references,
            valid_until=self.valid_until,
            binding_hash=binding_hash,
        )

    def to_subject(self) -> dict[str, object]:
        """Return the closed canonical schema projection."""

        return self._subject(binding_hash=self.binding_hash)


def bind_operation_admission(
    *,
    guarded_read: GuardedCapabilityRead,
    before_current_vector: CurrentAuthorityVector,
    after_current_vector: CurrentAuthorityVector,
    request_read_set: RequestReadSet,
    availability_read_set: AvailabilityReadSet,
    operation_lease_spec: OperationLeaseSpec,
    cas_expectation_hash: str,
    evidence_references: OperationAdmissionEvidenceReferences,
    checked_at: datetime,
    valid_until: datetime,
) -> VerifiedOperationAdmissionBinding:
    """Bind supplied values without claiming repository, lease, or CAS proof."""

    _validate_relationships(
        guarded_read=guarded_read,
        before_current_vector=before_current_vector,
        after_current_vector=after_current_vector,
        request_read_set=request_read_set,
        availability_read_set=availability_read_set,
        operation_lease_spec=operation_lease_spec,
        cas_expectation_hash=cas_expectation_hash,
        evidence_references=evidence_references,
        valid_until=valid_until,
    )
    normalized_checked_at = _utc(checked_at, "checked_at")
    normalized_valid_until = _utc(valid_until, "valid_until")
    authorization = guarded_read.authorization
    if not (
        authorization.evaluated_at <= normalized_checked_at < normalized_valid_until
    ):
        fail(
            "STALE_AUTHORITY",
            "checked_at",
            "binding is outside its exclusive validity window",
        )

    values = {
        "guarded_read": guarded_read,
        "before_current_vector": before_current_vector,
        "after_current_vector": after_current_vector,
        "request_read_set": request_read_set,
        "availability_read_set": availability_read_set,
        "operation_lease_spec": operation_lease_spec,
        "cas_expectation_hash": cas_expectation_hash,
        "evidence_references": evidence_references,
        "valid_until": normalized_valid_until,
    }
    binding_hash = _canonical_blob_digest(_binding_subject(**values, binding_hash=None))
    return VerifiedOperationAdmissionBinding._construct(
        **values,
        binding_hash=binding_hash,
    )


__all__ = [
    "AVAILABILITY_READ_SET_SCHEMA_REF",
    "CAS_EXPECTATION_SCHEMA_REF",
    "CURRENT_AUTHORITY_VECTOR_SCHEMA_REF",
    "ImmutableEvidenceBlobReference",
    "OPERATION_ADMISSION_BINDING_SCHEMA_REF",
    "OperationAdmissionEvidenceReferences",
    "OperationLeaseMemberGeneration",
    "OperationLeaseSpec",
    "REQUEST_READ_SET_SCHEMA_REF",
    "VerifiedOperationAdmissionBinding",
    "bind_operation_admission",
]
