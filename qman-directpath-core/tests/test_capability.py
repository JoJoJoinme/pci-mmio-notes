from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.capability import (
    AdmissionRequirement,
    CapabilityInput,
    DocumentReference,
    EvaluationContext,
    GateAssessment,
    OperationContext,
    PolicyMode,
    Reason,
    ReasonDetail,
    ReasonProvenance,
    TriState,
    evaluate_capability,
)
from qman_directpath_core.errors import DirectPathVerificationError


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIRECTORY = REPOSITORY_ROOT / "contracts"


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def reason(
    code: str,
    stage: str,
    *,
    device: str = "device-0000:65:00.0",
    detail_key: str = "fact",
    detail_value: str = "pinned",
) -> Reason:
    return Reason(
        code=code,
        stage=stage,
        devices=(device,),
        details=(
            ReasonDetail(
                key=detail_key,
                value_type="TEXT",
                value=detail_value,
            ),
        ),
        provenance=(
            ReasonProvenance(
                artifact_type="HOST_SNAPSHOT",
                artifact_id="snapshot-7",
                schema_ref="directpath-host-snapshot.schema.json",
                artifact_sha256=digest("snapshot-artifact"),
            ),
        ),
    )


def document(kind: str, identifier: str, label: str) -> DocumentReference:
    schema = {
        "DEPENDENCY_BUNDLE": (
            "directpath-portable-hash-subjects.schema.json#/$defs/dependencyBundle"
        ),
        "RESET_CONTRACT": "directpath-reset-contract.schema.json",
    }[kind]
    return DocumentReference(
        document_kind=kind,
        document_id=identifier,
        document_version=1,
        schema_ref=schema,
        content_hash=digest(label),
    )


def production_vm_input() -> CapabilityInput:
    yes = GateAssessment.yes()
    return CapabilityInput(
        evaluation_context=EvaluationContext.VM_REQUEST,
        operation_context=OperationContext.STATIC_ADMISSION,
        policy_mode=PolicyMode.PRODUCTION,
        admission_requirement=AdmissionRequirement.SUPPORTED,
        request_hash=digest("request"),
        closure_request_hash=digest("closure-request"),
        snapshot_epoch=7,
        snapshot_semantic_hash=digest("snapshot-semantics"),
        policy_hash=digest("policy"),
        profile_hash=digest("profile"),
        profile_semantic_hash=digest("profile-semantics"),
        bundle=document("DEPENDENCY_BUNDLE", "bundle-1", "bundle"),
        reset_contract=document("RESET_CONTRACT", "reset-contract-1", "reset"),
        resource_plan_hash=digest("resource-plan"),
        hardware=yes,
        technical=yes,
        qualification=yes,
        catalog_support=yes,
        policy_gate=yes,
        lab_policy_gate=None,
        admin_gate=yes,
        owner_active_gate=yes,
        availability_gate=yes,
        current_request_gate=yes,
    )


def validator_for(schema_file: str, definition: str) -> Draft202012Validator:
    registry = Registry()
    for path in CONTRACT_DIRECTORY.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            registry = registry.with_resource(
                schema["$id"], Resource.from_contents(schema)
            )
    schema = json.loads((CONTRACT_DIRECTORY / schema_file).read_text(encoding="utf-8"))
    return Draft202012Validator(
        {"$ref": f"{schema['$id']}#/$defs/{definition}"},
        registry=registry,
    )


class CapabilityCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.decision_validator = validator_for(
            "directpath-portable-hash-subjects.schema.json",
            "capabilityDecision",
        )
        cls.operation_validator = validator_for(
            "directpath-operation-payload.schema.json",
            "output_OP_EVALUATE_CAPABILITY",
        )

    def test_vm_request_emits_closed_wire_and_tri_state_payload(self) -> None:
        result = evaluate_capability(production_vm_input())
        wire = result.to_wire()
        payload = result.to_operation_payload()

        self.decision_validator.validate(wire)
        self.operation_validator.validate(payload)
        self.assertEqual(
            set(wire),
            {
                "subjectType",
                "schemaVersion",
                "evaluationContext",
                "admissionMode",
                "requestHash",
                "snapshotEpoch",
                "policyHash",
                "profileHash",
                "bundleHashOrNull",
                "resourcePlanHashOrNull",
                "hardwareCapable",
                "technicallyAttachable",
                "qualified",
                "supported",
                "policyEligible",
                "adminEnabled",
                "hostActive",
                "available",
                "attachable",
                "eligible",
                "reasons",
                "warnings",
                "decisionHash",
            },
        )
        for field in (
            "hardwareCapable",
            "technicallyAttachable",
            "qualified",
            "supported",
            "policyEligible",
            "adminEnabled",
            "hostActive",
            "available",
            "attachable",
            "eligible",
        ):
            self.assertTrue(wire[field])
            self.assertEqual(payload[field], "YES")
        self.assertEqual(wire["eligible"], wire["attachable"])

        unhashed = dict(wire)
        unhashed["decisionHash"] = None
        self.assertEqual(
            wire["decisionHash"],
            sha256_digest(canonical_json_bytes(unhashed)),
        )

    def test_host_only_is_explicitly_not_a_vm_admission(self) -> None:
        source = replace(
            production_vm_input(),
            evaluation_context=EvaluationContext.HOST_ONLY,
            operation_context=OperationContext.RECONCILE,
            resource_plan_hash=None,
            technical=None,
            current_request_gate=None,
        )

        result = evaluate_capability(source)
        wire = result.to_wire()
        payload = result.to_operation_payload()

        self.decision_validator.validate(wire)
        self.operation_validator.validate(payload)
        self.assertIsNone(wire["technicallyAttachable"])
        self.assertFalse(wire["attachable"])
        self.assertFalse(wire["eligible"])
        self.assertEqual(payload["technicallyAttachable"], "UNKNOWN")
        self.assertEqual(payload["attachable"], "UNKNOWN")
        self.assertEqual(payload["eligible"], "UNKNOWN")
        self.assertEqual(payload["available"], "YES")

    def test_availability_only_change_keeps_semantic_hash_stable(self) -> None:
        free = evaluate_capability(production_vm_input())
        busy_reason = reason(
            "DEPENDENCY_BUSY",
            "reservation",
            detail_key="leaseState",
            detail_value="BUSY",
        )
        busy_source = replace(
            production_vm_input(),
            snapshot_epoch=8,
            availability_gate=GateAssessment.no(busy_reason),
        )
        busy = evaluate_capability(busy_source)

        self.assertEqual(free.semantic_hash, busy.semantic_hash)
        self.assertEqual(free.snapshot_semantic_hash, busy.snapshot_semantic_hash)
        for field in (
            "hardwareCapable",
            "technicallyAttachable",
            "qualified",
            "supported",
            "policyEligible",
            "adminEnabled",
            "hostActive",
            "policyHash",
            "profileHash",
            "bundleHashOrNull",
            "resourcePlanHashOrNull",
        ):
            self.assertEqual(free.to_wire()[field], busy.to_wire()[field])

        self.assertNotEqual(free.decision.decision_hash, busy.decision.decision_hash)
        self.assertTrue(free.decision.available)
        self.assertFalse(busy.decision.available)
        self.assertFalse(busy.decision.attachable)
        self.assertFalse(busy.decision.eligible)
        self.assertEqual(busy.to_operation_payload()["available"], TriState.NO.value)

    def test_unknown_is_preserved_at_op_boundary_and_denied_on_wire(self) -> None:
        missing = reason(
            "QUALIFICATION_EVIDENCE_MISSING",
            "qualification",
            detail_key="record",
            detail_value="not-resolved",
        )
        source = replace(
            production_vm_input(),
            qualification=GateAssessment.unknown(missing),
            catalog_support=GateAssessment.unknown(missing),
        )

        result = evaluate_capability(source)
        wire = result.to_wire()
        payload = result.to_operation_payload()

        self.assertFalse(wire["qualified"])
        self.assertFalse(wire["supported"])
        self.assertFalse(wire["policyEligible"])
        self.assertFalse(wire["attachable"])
        self.assertEqual(payload["qualified"], "UNKNOWN")
        self.assertEqual(payload["supported"], "UNKNOWN")
        self.assertEqual(payload["policyEligible"], "UNKNOWN")
        self.assertEqual(payload["attachable"], "UNKNOWN")
        self.assertEqual(len(wire["reasons"]), 1)

    def test_isolated_lab_can_admit_technical_but_unsupported_result(self) -> None:
        missing = reason(
            "QUALIFICATION_EVIDENCE_MISSING",
            "qualification",
            detail_key="record",
            detail_value="absent-in-lab",
        )
        no_profile = reason(
            "PROFILE_NO_MATCH",
            "qualification",
            detail_key="catalog",
            detail_value="not-listed",
        )
        source = replace(
            production_vm_input(),
            policy_mode=PolicyMode.ISOLATED_UNQUALIFIED_LAB,
            admission_requirement=AdmissionRequirement.TECHNICAL,
            qualification=GateAssessment.no(missing),
            catalog_support=GateAssessment.no(no_profile),
            lab_policy_gate=GateAssessment.yes(),
        )

        result = evaluate_capability(source)
        wire = result.to_wire()
        payload = result.to_operation_payload()

        self.assertFalse(wire["qualified"])
        self.assertFalse(wire["supported"])
        self.assertTrue(wire["policyEligible"])
        self.assertTrue(wire["attachable"])
        self.assertTrue(wire["eligible"])
        self.assertEqual(payload["admissionMode"], "TECHNICAL")
        self.assertEqual(payload["supported"], "NO")
        self.assertEqual(payload["attachable"], "YES")
        self.decision_validator.validate(wire)

    def test_reason_order_is_canonical_and_display_messages_are_absent(self) -> None:
        busy = reason(
            "DEPENDENCY_BUSY",
            "reservation",
            device="device-b",
            detail_key="leaseState",
            detail_value="BUSY",
        )
        quarantined = reason(
            "DEVICE_QUARANTINED",
            "policy",
            device="device-a",
            detail_key="quarantineState",
            detail_value="ACTIVE",
        )
        first = evaluate_capability(
            replace(
                production_vm_input(),
                availability_gate=GateAssessment.no(busy, quarantined),
            )
        )
        second = evaluate_capability(
            replace(
                production_vm_input(),
                availability_gate=GateAssessment.no(quarantined, busy),
            )
        )

        self.assertEqual(first.to_wire(), second.to_wire())
        self.assertEqual(first.decision.decision_hash, second.decision.decision_hash)

        def assert_no_message(value) -> None:
            if isinstance(value, dict):
                self.assertNotIn("message", value)
                for child in value.values():
                    assert_no_message(child)
            elif isinstance(value, list):
                for child in value:
                    assert_no_message(child)

        assert_no_message(first.to_wire()["reasons"])

    def test_repeated_evaluation_is_stable_and_outputs_are_defensive(self) -> None:
        source = production_vm_input()
        first = evaluate_capability(source)
        second = evaluate_capability(source)

        self.assertEqual(first, second)
        self.assertEqual(first.to_wire(), second.to_wire())
        self.assertEqual(first.to_operation_payload(), second.to_operation_payload())
        with self.assertRaises(FrozenInstanceError):
            source.snapshot_epoch = 99  # type: ignore[misc]

        caller_copy = first.to_wire()
        caller_copy["reasons"].append({"message": "caller mutation"})
        caller_copy["hardwareCapable"] = False
        self.assertEqual(first.to_wire(), second.to_wire())

    def test_semantic_dependencies_change_the_semantic_hash(self) -> None:
        baseline = evaluate_capability(production_vm_input())
        for changed in (
            replace(
                production_vm_input(),
                snapshot_semantic_hash=digest("new-snapshot-semantics"),
            ),
            replace(
                production_vm_input(),
                closure_request_hash=digest("new-closure-request"),
            ),
            replace(
                production_vm_input(),
                policy_hash=digest("new-policy"),
            ),
            replace(
                production_vm_input(),
                profile_semantic_hash=digest("new-profile-semantics"),
            ),
            replace(
                production_vm_input(),
                reset_contract=replace(
                    production_vm_input().reset_contract,
                    content_hash=digest("new-reset-contract"),
                ),
            ),
        ):
            self.assertNotEqual(
                baseline.semantic_hash,
                evaluate_capability(changed).semantic_hash,
            )

    def test_global_profile_revision_does_not_change_selected_semantics(self) -> None:
        baseline = evaluate_capability(production_vm_input())
        revised = evaluate_capability(
            replace(
                production_vm_input(),
                profile_hash=digest("new-global-profile"),
            )
        )

        self.assertEqual(baseline.semantic_hash, revised.semantic_hash)
        self.assertNotEqual(
            baseline.decision.decision_hash,
            revised.decision.decision_hash,
        )

    def test_invalid_or_unexplained_inputs_fail_closed(self) -> None:
        missing = reason(
            "SNAPSHOT_INCOMPLETE",
            "inventory",
            detail_key="field",
            detail_value="iommu",
        )
        with self.assertRaises(DirectPathVerificationError):
            GateAssessment(TriState.UNKNOWN)
        with self.assertRaises(DirectPathVerificationError):
            GateAssessment(TriState.YES, (missing,))
        with self.assertRaises(DirectPathVerificationError):
            Reason("HOST_IOMMU_MISSING", "policy")
        with self.assertRaises(DirectPathVerificationError):
            replace(
                production_vm_input(),
                resource_plan_hash=None,
            )
        with self.assertRaises(DirectPathVerificationError):
            replace(
                production_vm_input(),
                evaluation_context=EvaluationContext.HOST_ONLY,
            )
        with self.assertRaises(DirectPathVerificationError):
            replace(
                production_vm_input(),
                admission_requirement=AdmissionRequirement.TECHNICAL,
            )

    def test_unknown_hardware_never_leaks_as_true_boolean(self) -> None:
        incomplete = reason(
            "SNAPSHOT_INCOMPLETE",
            "inventory",
            detail_key="providerFact",
            detail_value="UNKNOWN",
        )
        result = evaluate_capability(
            replace(
                production_vm_input(),
                hardware=GateAssessment.unknown(incomplete),
            )
        )
        wire = result.to_wire()
        payload = result.to_operation_payload()

        for field in (
            "hardwareCapable",
            "technicallyAttachable",
            "qualified",
            "supported",
            "policyEligible",
            "adminEnabled",
            "hostActive",
            "available",
            "attachable",
            "eligible",
        ):
            self.assertFalse(wire[field])
            self.assertEqual(payload[field], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
