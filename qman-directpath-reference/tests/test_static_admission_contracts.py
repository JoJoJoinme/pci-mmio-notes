from __future__ import annotations

from dataclasses import replace
import inspect
import json
from pathlib import Path
import unittest

import qman_directpath_reference.static_admission_contracts as module
from qman_directpath_reference import (
    EVIDENCE_BOUNDARY,
    CanonicalizationError,
    CommittedIdempotency,
    CommittedOperationLeaseCapability,
    CommittedResourceVersions,
    CommittedStaticAdmission,
    ContractViolation,
    IdempotencyNaturalKey,
    OperationLeaseMemberGeneration,
    StaticAdmissionCommand,
    StaticAdmissionRequestReference,
    canonical_json_bytes,
    derive_idempotency_scope_hash,
    parse_committed_static_admission,
    parse_static_admission_command,
    sha256_digest,
)


ROOT = Path(__file__).resolve().parents[2]
COMMAND_SCHEMA = ROOT / "contracts" / "directpath-static-admission-command.schema.json"
COMMITTED_SCHEMA = (
    ROOT / "contracts" / "directpath-committed-static-admission.schema.json"
)
OPERATION_ENVELOPE_SCHEMA = (
    ROOT / "contracts" / "directpath-operation-envelope.schema.json"
)


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


class StaticAdmissionContractTests(unittest.TestCase):
    def make_command(self) -> StaticAdmissionCommand:
        return StaticAdmissionCommand.create(
            command_id="command-001",
            vm_id="vm-001",
            run_id="run-001",
            idempotency_key="idem-001",
            actor="controller:test",
            deadline="2026-07-24T12:30:00.000000Z",
            request_reference=StaticAdmissionRequestReference(
                request_version=7,
                request_hash=digest("request"),
            ),
        )

    def make_committed(
        self,
        command: StaticAdmissionCommand | None = None,
    ) -> CommittedStaticAdmission:
        command = command or self.make_command()
        capability = CommittedOperationLeaseCapability(
            operation_lease_id="operation-lease-001",
            scope_hash=digest("scope"),
            run_id_or_intent_id=command.run_id,
            bundle_ids=(digest("bundle"),),
            member_generations=(
                OperationLeaseMemberGeneration(
                    id="device-a",
                    generation=11,
                ),
                OperationLeaseMemberGeneration(
                    id="device-b",
                    generation=12,
                ),
            ),
            host_epoch=4,
            run_generation_or_null=3,
            holder_controller_generation=9,
            operation_lease_resource_version=1,
            admission_binding_hash_or_null=digest("binding"),
        )
        versions = CommittedResourceVersions(
            controller_authority_resource_version=13,
            host_authority_resource_version=21,
            request_resource_version=8,
            policy_authority_resource_version=5,
            availability_authority_resource_version=35,
            assignment_run_resource_version=1,
            bundle_lease_resource_version=1,
            operation_lease_resource_version=1,
        )
        idempotency = CommittedIdempotency(
            natural_key=IdempotencyNaturalKey(
                idempotency_scope_hash=derive_idempotency_scope_hash(command.vm_id),
                idempotency_key=command.idempotency_key,
            ),
            resource_version=2,
        )
        return CommittedStaticAdmission.create(
            command_id=command.command_id,
            vm_id=command.vm_id,
            run_id=command.run_id,
            command_hash=command.command_hash,
            operation_lease_capability=capability,
            admission_binding_hash=digest("binding"),
            committed_resource_versions=versions,
            idempotency=idempotency,
            repository_transaction_id="repository-transaction-001",
            commit_sequence=17,
            committed_at="2026-07-24T12:00:01.000000Z",
        )

    def test_command_round_trips_exact_canonical_bytes_and_hash(self) -> None:
        command = self.make_command()
        encoded = command.to_canonical_bytes()
        self.assertEqual(command, parse_static_admission_command(encoded))
        null_subject = command.to_wire()
        null_subject["commandHash"] = None
        self.assertEqual(
            command.command_hash,
            sha256_digest(canonical_json_bytes(null_subject)),
        )
        self.assertEqual(
            {
                "requestHash": digest("request"),
                "requestVersion": 7,
            },
            command.to_wire()["requestReference"],
        )

    def test_command_rejects_every_caller_authority_field(self) -> None:
        forbidden = (
            "requestReadSet",
            "availabilityReadSet",
            "currentAuthorityVector",
            "casExpectation",
            "operationLeaseSpec",
            "operationLease",
            "admissionBindingHash",
            "capabilityDecision",
            "resourceVersion",
        )
        for field in forbidden:
            with self.subTest(field=field):
                wire = self.make_command().to_wire()
                wire[field] = {}
                with self.assertRaisesRegex(
                    ContractViolation,
                    "extra=",
                ):
                    StaticAdmissionCommand.from_wire(wire)

    def test_command_hash_prevents_mutation_and_replace_relabeling(self) -> None:
        command = self.make_command()
        wire = command.to_wire()
        wire["actor"] = "controller:other"
        with self.assertRaisesRegex(ContractViolation, "commandHash"):
            StaticAdmissionCommand.from_wire(wire)
        with self.assertRaisesRegex(ContractViolation, "commandHash"):
            replace(command, actor="controller:other")

    def test_noncanonical_or_duplicate_command_bytes_are_rejected(self) -> None:
        command = self.make_command()
        pretty = json.dumps(command.to_wire(), indent=2).encode("utf-8")
        with self.assertRaises(CanonicalizationError):
            parse_static_admission_command(pretty)
        duplicate = b'{"subjectType":"STATIC_ADMISSION_COMMAND","subjectType":"X"}'
        with self.assertRaises(CanonicalizationError):
            parse_static_admission_command(duplicate)

    def test_committed_result_round_trips_and_hashes_full_commit(self) -> None:
        committed = self.make_committed()
        encoded = committed.to_canonical_bytes()
        self.assertEqual(
            committed,
            parse_committed_static_admission(encoded),
        )
        null_subject = committed.to_wire()
        null_subject["resultHash"] = None
        self.assertEqual(
            committed.result_hash,
            sha256_digest(canonical_json_bytes(null_subject)),
        )
        wire = committed.to_wire()
        self.assertEqual(
            "ASSIGNMENT_PREPARE",
            wire["operationLeaseCapability"]["leaseType"],
        )
        self.assertEqual(
            wire["admissionBindingHash"],
            wire["operationLeaseCapability"]["admissionBindingHashOrNull"],
        )
        self.assertEqual(
            committed.command_hash,
            wire["commandHash"],
        )

    def test_committed_result_rejects_uncommitted_decision_fields(self) -> None:
        forbidden = (
            "decision",
            "capabilityDecision",
            "guardedCapabilityRead",
            "authorization",
            "requestReadSet",
            "currentAuthorityVector",
            "casExpectation",
        )
        for field in forbidden:
            with self.subTest(field=field):
                wire = self.make_committed().to_wire()
                wire[field] = digest(field)
                with self.assertRaisesRegex(
                    ContractViolation,
                    "extra=",
                ):
                    CommittedStaticAdmission.from_wire(wire)

    def test_committed_cross_field_bindings_fail_closed(self) -> None:
        committed = self.make_committed()
        with self.assertRaisesRegex(ContractViolation, "runId"):
            replace(committed, run_id="run-other")
        with self.assertRaisesRegex(
            ContractViolation,
            "idempotencyScopeHash",
        ):
            replace(committed, vm_id="vm-other")
        mismatched_versions = replace(
            committed.committed_resource_versions,
            operation_lease_resource_version=2,
        )
        with self.assertRaisesRegex(
            ContractViolation,
            "operationLeaseResourceVersion",
        ):
            replace(
                committed,
                committed_resource_versions=mismatched_versions,
            )

    def test_result_hash_rejects_any_committed_field_mutation(self) -> None:
        wire = self.make_committed().to_wire()
        wire["commitSequence"] = 18
        with self.assertRaisesRegex(ContractViolation, "resultHash"):
            CommittedStaticAdmission.from_wire(wire)

    def test_schemas_are_closed_and_forbid_authority_in_command(self) -> None:
        command_schema = json.loads(COMMAND_SCHEMA.read_text("utf-8"))
        committed_schema = json.loads(COMMITTED_SCHEMA.read_text("utf-8"))
        operation_schema = json.loads(OPERATION_ENVELOPE_SCHEMA.read_text("utf-8"))
        self.assertFalse(command_schema["additionalProperties"])
        self.assertFalse(committed_schema["additionalProperties"])
        self.assertIn("commandHash", command_schema["required"])
        self.assertIn("requestReference", command_schema["required"])
        command_properties = set(command_schema["properties"])
        self.assertTrue(
            {
                "requestReadSet",
                "availabilityReadSet",
                "currentAuthorityVector",
                "casExpectation",
                "operationLeaseSpec",
                "admissionBindingHash",
            }.isdisjoint(command_properties)
        )
        self.assertIn(
            "represented as null",
            command_schema["x-qmanHashRule"],
        )
        self.assertIn(
            "represented as null",
            committed_schema["x-qmanHashRule"],
        )

        for definition in (
            "operationLeaseCapability",
            "committedResourceVersions",
            "idempotencyNaturalKey",
            "idempotencyCommit",
            "memberGeneration",
        ):
            self.assertFalse(
                committed_schema["$defs"][definition]["additionalProperties"]
            )
        self.assertNotIn(
            "decision",
            committed_schema["properties"],
        )
        committed_capability = committed_schema["$defs"]["operationLeaseCapability"]
        envelope_capability = operation_schema["$defs"]["operationLeaseCapability"]
        self.assertEqual(
            set(envelope_capability["required"]),
            set(committed_capability["required"]),
        )
        self.assertEqual(
            set(envelope_capability["properties"]),
            set(committed_capability["properties"]),
        )
        self.assertEqual(
            "ASSIGNMENT_PREPARE",
            committed_capability["properties"]["leaseType"]["const"],
        )

    def test_module_is_pure_and_evidence_boundary_is_explicit(self) -> None:
        source = inspect.getsource(module)
        self.assertNotIn("sqlite3", source)
        self.assertNotIn("psycopg", source)
        self.assertEqual(
            "REFERENCE_SQLITE_TRANSACTION_COMPONENT_ONLY",
            EVIDENCE_BOUNDARY,
        )


if __name__ == "__main__":
    unittest.main()
