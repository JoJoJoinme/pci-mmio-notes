from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import unittest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.operation_admission import (
    AVAILABILITY_READ_SET_SCHEMA_REF,
    CAS_EXPECTATION_SCHEMA_REF,
    CURRENT_AUTHORITY_VECTOR_SCHEMA_REF,
    REQUEST_READ_SET_SCHEMA_REF,
    ImmutableEvidenceBlobReference,
    OperationAdmissionEvidenceReferences,
    OperationLeaseMemberGeneration,
    OperationLeaseSpec,
    VerifiedOperationAdmissionBinding,
    bind_operation_admission,
)
from qman_directpath_core.read_guard import evaluate_guarded_read
from tests.test_read_guard import (
    CHECKED_AT,
    VALID_UNTIL,
    authority,
    availability_read_set,
    capability_input,
    closure_arguments,
    dependencies,
    digest,
    request_read_set,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ContractSchemas(ROOT / "contracts")
CAS_EXPECTATION_HASH = digest("8")


def blob_ref(schema_ref: str, subject: object) -> ImmutableEvidenceBlobReference:
    return ImmutableEvidenceBlobReference(
        schema_ref=schema_ref,
        blob_sha256=sha256_digest(canonical_json_bytes(subject)),
    )


def guarded_read():
    return evaluate_guarded_read(
        before_current_vector=authority(),
        capability_input=capability_input(),
        dependencies=dependencies(),
        after_current_vector=authority(),
        availability_read_set=availability_read_set(),
        **closure_arguments(),
        checked_at=CHECKED_AT,
        valid_until=VALID_UNTIL,
    )


def lease_spec(
    *,
    member_generation: int = 2,
    scope_hash: str | None = None,
    lease_type: str = "ASSIGNMENT_PREPARE",
    bundle_ids: tuple[str, ...] | None = None,
) -> OperationLeaseSpec:
    return OperationLeaseSpec.create(
        operation_lease_id="operation-lease-a",
        lease_type=lease_type,
        scope_hash=scope_hash or digest("9"),
        run_id_or_intent_id="assignment-run-a",
        bundle_ids=(
            (dependencies().dependency_bundle_digest,)
            if bundle_ids is None
            else bundle_ids
        ),
        member_generations=(
            OperationLeaseMemberGeneration(
                id=availability_read_set().member_versions[0].device_uid,
                generation=member_generation,
            ),
        ),
        host_epoch=3,
        run_generation_or_none=1,
        holder_controller_generation=7,
        operation_lease_resource_version=11,
    )


def evidence_references(
    *,
    before=None,
    after=None,
    request=None,
    availability=None,
    cas_hash: str = CAS_EXPECTATION_HASH,
) -> OperationAdmissionEvidenceReferences:
    resolved_before = before or authority()
    resolved_after = after or authority()
    resolved_request = request or request_read_set()
    resolved_availability = availability or availability_read_set()
    return OperationAdmissionEvidenceReferences(
        request_read_set=blob_ref(
            REQUEST_READ_SET_SCHEMA_REF,
            resolved_request.to_subject(),
        ),
        availability_read_set=blob_ref(
            AVAILABILITY_READ_SET_SCHEMA_REF,
            resolved_availability.to_subject(),
        ),
        before_current_authority_vector=blob_ref(
            CURRENT_AUTHORITY_VECTOR_SCHEMA_REF,
            resolved_before.to_subject(),
        ),
        after_current_authority_vector=blob_ref(
            CURRENT_AUTHORITY_VECTOR_SCHEMA_REF,
            resolved_after.to_subject(),
        ),
        cas_expectation=ImmutableEvidenceBlobReference(
            schema_ref=CAS_EXPECTATION_SCHEMA_REF,
            blob_sha256=cas_hash,
        ),
    )


def binding_arguments() -> dict[str, object]:
    return {
        "guarded_read": guarded_read(),
        "before_current_vector": authority(),
        "after_current_vector": authority(),
        "request_read_set": request_read_set(),
        "availability_read_set": availability_read_set(),
        "operation_lease_spec": lease_spec(),
        "cas_expectation_hash": CAS_EXPECTATION_HASH,
        "evidence_references": evidence_references(),
        "checked_at": CHECKED_AT,
        "valid_until": VALID_UNTIL,
    }


class OperationAdmissionBindingTests(unittest.TestCase):
    def test_binding_is_deterministic_closed_and_self_hashed(self) -> None:
        first = bind_operation_admission(**binding_arguments())
        second = bind_operation_admission(**binding_arguments())

        self.assertEqual(first, second)
        self.assertEqual(first.to_subject(), second.to_subject())
        subject = first.to_subject()
        CONTRACTS.validate(
            "operation_admission_binding",
            subject,
            "operation_admission_binding",
        )
        null_hash_subject = copy.deepcopy(subject)
        null_hash_subject["bindingHash"] = None
        self.assertEqual(
            first.binding_hash,
            sha256_digest(canonical_json_bytes(null_hash_subject)),
        )
        self.assertNotEqual(
            first.binding_hash,
            first.operation_lease_spec.scope_hash,
        )
        self.assertNotEqual(
            first.operation_lease_spec.lease_spec_hash,
            first.operation_lease_spec.scope_hash,
        )
        self.assertFalse(subject["productAuthorized"])
        self.assertEqual(
            "COMPONENT_STATIC_CAPABILITY_RELATIONSHIP_ONLY",
            subject["authorityBoundary"],
        )
        self.assertEqual(
            subject["authorityDisposition"]["authorizationBlockers"],
            subject["authorizationBlockers"],
        )
        self.assertFalse(
            subject["authorityDisposition"]["premises"]["resourcePlan"][
                "productAuthorized"
            ]
        )
        self.assertEqual(
            [
                "PRODUCT_HOST_SNAPSHOT_AUTHORITY_ADAPTER_REQUIRED",
                "PRODUCT_INVENTORY_COLLECTOR_PUBLISHER_REQUIRED",
                "PRODUCT_REPOSITORY_LEASE_CAS_REQUIRED",
                "PRODUCT_RESOURCE_PLANNER_REQUIRED",
                "TRUSTED_E4_ADAPTER_REQUIRED",
            ],
            subject["authorizationBlockers"],
        )
        self.assertEqual(
            {
                "hardwarePremise": (
                    "COMPONENT_VERIFIED_INVENTORY_PREMISE_ONLY"
                ),
                "resourcePlan": (
                    "COMPONENT_CALLER_SUPPLIED_RESOURCE_PLAN_BYTES_ONLY"
                ),
                "qualification": "COMPONENT_ONLY",
                "hostSnapshotAnchor": (
                    "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY"
                ),
            },
            {
                name: premise["authorityBoundary"]
                for name, premise in subject["authorityDisposition"][
                    "premises"
                ].items()
            },
        )

    def test_verified_binding_is_factory_only(self) -> None:
        binding = bind_operation_admission(**binding_arguments())
        with self.assertRaises(TypeError):
            VerifiedOperationAdmissionBinding()
        with self.assertRaises(TypeError):
            replace(binding)

    def test_schema_rejects_unknown_fields(self) -> None:
        subject = bind_operation_admission(**binding_arguments()).to_subject()
        subject["repositoryTransactionProven"] = True
        with self.assertRaises(DirectPathVerificationError) as raised:
            CONTRACTS.validate(
                "operation_admission_binding",
                subject,
                "operation_admission_binding",
            )
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_schema_rejects_product_authority_laundering(self) -> None:
        subject = bind_operation_admission(**binding_arguments()).to_subject()
        subject["productAuthorized"] = True
        subject["authorityDisposition"]["productAuthorized"] = True
        with self.assertRaises(DirectPathVerificationError) as raised:
            CONTRACTS.validate(
                "operation_admission_binding",
                subject,
                "operation_admission_binding",
            )
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_schema_rejects_nested_premise_boundary_laundering(self) -> None:
        for premise_name in (
            "hardwarePremise",
            "resourcePlan",
            "qualification",
            "hostSnapshotAnchor",
        ):
            with self.subTest(premise=premise_name):
                subject = bind_operation_admission(
                    **binding_arguments()
                ).to_subject()
                subject["authorityDisposition"]["premises"][premise_name][
                    "authorityBoundary"
                ] = "PRODUCT_AUTHORITY"
                subject["bindingHash"] = None
                subject["bindingHash"] = sha256_digest(
                    canonical_json_bytes(subject)
                )
                with self.assertRaises(DirectPathVerificationError) as raised:
                    CONTRACTS.validate(
                        "operation_admission_binding",
                        subject,
                        "operation_admission_binding",
                    )
                self.assertEqual(
                    raised.exception.code,
                    "CONTRACT_SCHEMA_VIOLATION",
                )

    def test_schema_and_runtime_reject_incomplete_blocker_set(self) -> None:
        binding = bind_operation_admission(**binding_arguments())
        disposition = binding.guarded_read.authorization.authority_disposition
        with self.assertRaises(DirectPathVerificationError) as raised:
            replace(disposition, authorization_blockers=("NONE",))
        self.assertEqual(
            raised.exception.code,
            "AUTHORITY_DISPOSITION_INVALID",
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            replace(
                disposition,
                resource_plan_authority_boundary="PRODUCT_AUTHORITY",
            )
        self.assertEqual(
            raised.exception.code,
            "AUTHORITY_DISPOSITION_INVALID",
        )

        subject = binding.to_subject()
        subject["authorizationBlockers"] = ["NONE"]
        subject["authorityDisposition"]["authorizationBlockers"] = ["NONE"]
        subject["bindingHash"] = None
        subject["bindingHash"] = sha256_digest(canonical_json_bytes(subject))
        with self.assertRaises(DirectPathVerificationError) as raised:
            CONTRACTS.validate(
                "operation_admission_binding",
                subject,
                "operation_admission_binding",
            )
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_before_after_vector_drift_is_rejected(self) -> None:
        arguments = binding_arguments()
        after = replace(
            authority(),
            host_authority_resource_version=10,
        )
        arguments["after_current_vector"] = after
        arguments["evidence_references"] = evidence_references(after=after)

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(raised.exception.path, "after_current_vector")

    def test_authorization_must_bind_the_exact_vector(self) -> None:
        arguments = binding_arguments()
        changed = replace(
            authority(),
            trust_anchor_version=5,
            trust_anchor_digest=digest("0"),
        )
        arguments["before_current_vector"] = changed
        arguments["after_current_vector"] = changed
        arguments["evidence_references"] = evidence_references(
            before=changed,
            after=changed,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(
            raised.exception.path,
            "guarded_read.authorization.authority_vector_digest",
        )

    def test_request_read_set_mismatch_is_rejected(self) -> None:
        arguments = binding_arguments()
        changed_request = request_read_set(request_hash=digest("0"))
        arguments["request_read_set"] = changed_request
        arguments["evidence_references"] = evidence_references(request=changed_request)

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(raised.exception.path, "request_read_set")

    def test_availability_read_set_mismatch_is_rejected(self) -> None:
        arguments = binding_arguments()
        changed_availability = availability_read_set(authority_resource_version=20)
        arguments["availability_read_set"] = changed_availability
        arguments["evidence_references"] = evidence_references(
            availability=changed_availability
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(raised.exception.path, "availability_read_set")

    def test_blocked_availability_is_rejected(self) -> None:
        arguments = binding_arguments()
        blocked = availability_read_set(blocking_claim_digests=(digest("0"),))
        changed_vector = replace(
            authority(),
            availability_read_set_digest=blocked.read_set_digest,
        )
        arguments["before_current_vector"] = changed_vector
        arguments["after_current_vector"] = changed_vector
        arguments["availability_read_set"] = blocked
        arguments["evidence_references"] = evidence_references(
            before=changed_vector,
            after=changed_vector,
            availability=blocked,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")

    def test_lease_member_generation_mismatch_is_rejected(self) -> None:
        arguments = binding_arguments()
        arguments["operation_lease_spec"] = lease_spec(member_generation=3)

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
        self.assertEqual(
            raised.exception.path,
            "operation_lease_spec.member_generations",
        )

    def test_static_admission_rejects_wrong_lease_type(self) -> None:
        arguments = binding_arguments()
        arguments["operation_lease_spec"] = lease_spec(lease_type="RELEASE")

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(
            raised.exception.code,
            "INVALID_OPERATION_LEASE_SPEC",
        )
        self.assertEqual(
            raised.exception.path,
            "operation_lease_spec.lease_type",
        )

    def test_lease_bundle_scope_must_equal_guarded_bundle(self) -> None:
        cases = (
            (digest("0"),),
            tuple(
                sorted(
                    (
                        dependencies().dependency_bundle_digest,
                        digest("0"),
                    ),
                    key=canonical_json_bytes,
                )
            ),
        )
        for bundle_ids in cases:
            with self.subTest(bundle_ids=bundle_ids):
                arguments = binding_arguments()
                arguments["operation_lease_spec"] = lease_spec(bundle_ids=bundle_ids)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_operation_admission(**arguments)
                self.assertEqual(raised.exception.code, "STALE_AUTHORITY")
                self.assertEqual(
                    raised.exception.path,
                    "operation_lease_spec.bundle_ids",
                )

    def test_each_exact_blob_reference_is_checked(self) -> None:
        original = evidence_references()
        fields = (
            "request_read_set",
            "availability_read_set",
            "before_current_authority_vector",
            "after_current_authority_vector",
            "cas_expectation",
        )
        for field_name in fields:
            with self.subTest(field_name=field_name):
                arguments = binding_arguments()
                reference = getattr(original, field_name)
                changed_reference = replace(
                    reference,
                    blob_sha256=digest("0"),
                )
                arguments["evidence_references"] = replace(
                    original,
                    **{field_name: changed_reference},
                )
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_operation_admission(**arguments)
                self.assertEqual(
                    raised.exception.code,
                    "EVIDENCE_REFERENCE_MISMATCH",
                )

    def test_known_blob_reference_schema_is_exact(self) -> None:
        arguments = binding_arguments()
        original = evidence_references()
        changed_request_ref = replace(
            original.request_read_set,
            schema_ref=AVAILABILITY_READ_SET_SCHEMA_REF,
        )
        arguments["evidence_references"] = replace(
            original,
            request_read_set=changed_request_ref,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(
            raised.exception.code,
            "EVIDENCE_REFERENCE_MISMATCH",
        )

    def test_cas_expectation_schema_reference_is_exact(self) -> None:
        arguments = binding_arguments()
        original = evidence_references()
        changed_cas_ref = replace(
            original.cas_expectation,
            schema_ref=REQUEST_READ_SET_SCHEMA_REF,
        )
        arguments["evidence_references"] = replace(
            original,
            cas_expectation=changed_cas_ref,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(
            raised.exception.code,
            "EVIDENCE_REFERENCE_MISMATCH",
        )
        self.assertEqual(
            raised.exception.path,
            "evidence_references.cas_expectation.schema_ref",
        )

    def test_cas_expectation_hash_must_match_its_blob_reference(self) -> None:
        arguments = binding_arguments()
        arguments["cas_expectation_hash"] = digest("0")

        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_operation_admission(**arguments)
        self.assertEqual(
            raised.exception.code,
            "EVIDENCE_REFERENCE_MISMATCH",
        )
        self.assertEqual(
            raised.exception.path,
            "evidence_references.cas_expectation.blob_sha256",
        )

    def test_expired_or_overlong_binding_is_rejected(self) -> None:
        cases = (
            {
                "checked_at": VALID_UNTIL,
                "valid_until": VALID_UNTIL,
            },
            {
                "checked_at": CHECKED_AT,
                "valid_until": VALID_UNTIL + timedelta(microseconds=1),
            },
            {
                "checked_at": CHECKED_AT - timedelta(microseconds=1),
                "valid_until": VALID_UNTIL,
            },
        )
        for changes in cases:
            with self.subTest(changes=changes):
                arguments = binding_arguments()
                arguments.update(changes)
                with self.assertRaises(DirectPathVerificationError):
                    bind_operation_admission(**arguments)


if __name__ == "__main__":
    unittest.main()
