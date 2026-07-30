from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path

from tools import generate_directpath_case_contracts as case_generator


ROOT = Path(__file__).resolve().parents[1]


def load(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{relative} is not an object")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


class DirectPathCaseAndEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load("contracts/directpath-acceptance-case-contracts.json")
        cls.portable = load("contracts/directpath-portable-control-contract.json")
        cls.scenario = load(
            "handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json"
        )

    def test_case_registry_is_current_and_exactly_101(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/generate_directpath_case_contracts.py", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        records = self.registry["records"]
        self.assertEqual(101, len(records))
        self.assertEqual(101, len({record["caseId"] for record in records}))
        self.assertEqual(
            Counter(
                {
                    "EXECUTABLE": 1,
                    "IMPLEMENTATION_BLOCKED": 94,
                    "HARDWARE_BLOCKED": 6,
                }
            ),
            Counter(record["classification"]["status"] for record in records),
        )

    def test_c10_c15_c20_fix_exact_read_trace_and_closed_ids(self) -> None:
        case_schema = load(
            "contracts/directpath-acceptance-case-contract.schema.json"
        )
        paired_trace = case_schema["$defs"]["caseContract"]["allOf"]
        self.assertEqual(
            [
                (
                    branch["if"]["required"],
                    branch["then"]["required"],
                )
                for branch in paired_trace
            ],
            [
                (["requiredEntityIds"], ["requiredReasonIds"]),
                (["requiredReasonIds"], ["requiredEntityIds"]),
            ],
        )
        records = {
            record["caseId"]: record for record in self.registry["records"]
        }
        expected = {
            "C10": {
                "requiredPortIds": [
                    "PORT-ASSIGNMENT-ORCHESTRATOR",
                    "PORT-CAPABILITY-ENGINE",
                    "PORT-CONTROL-API",
                    "PORT-GLOBAL-REPOSITORY",
                    "PORT-INVENTORY-SNAPSHOT",
                    "PORT-QUALIFICATION-CATALOG",
                ],
                "requiredOperationIds": [
                    "OP-CAPTURE-HOST-SNAPSHOT",
                    "OP-CAS-ACQUIRE-OPERATION-LEASE",
                    "OP-CAS-RESERVE-BUNDLES",
                    "OP-EVALUATE-CAPABILITY",
                    "OP-PLAN-STATIC",
                    "OP-QUERY-DIRECTPATH",
                    "OP-RESOLVE-QUALIFICATION-PROFILE",
                ],
                "requiredTransitionIds": [],
                "requiredEntityIds": [
                    "ENTITY-ASSIGNMENT-RUN",
                    "ENTITY-AVAILABILITY-AUTHORITY",
                    "ENTITY-BUNDLE-LEASE",
                    "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                    "ENTITY-DEPENDENCY-BUNDLE",
                    "ENTITY-DEVICE-RECORD",
                    "ENTITY-HOST-AUTHORITY",
                    "ENTITY-HOST-SNAPSHOT",
                    "ENTITY-OPERATION-ADMISSION-BINDING",
                    "ENTITY-OPERATION-LEASE",
                    "ENTITY-QUALIFICATION-PROFILE",
                    "ENTITY-QUALIFICATION-RECORD",
                    "ENTITY-SUPPORTED-CATALOG",
                    "ENTITY-TRUST-KEY-RING",
                    "ENTITY-VM-DIRECTPATH-REQUEST",
                ],
                "requiredReasonIds": [
                    "DEPENDENCY_BUSY",
                    "DEVICE_ERRATA_DENY",
                    "INVENTORY_EPOCH_CHANGED",
                    "PROFILE_NO_MATCH",
                    "QUALIFICATION_EVIDENCE_MISSING",
                    "STALE_HOST_EPOCH",
                    "STALE_RESOURCE_VERSION",
                ],
            },
            "C15": {
                "requiredPortIds": [
                    "PORT-AUDIT-EVIDENCE",
                    "PORT-CAPABILITY-ENGINE",
                    "PORT-CONTROL-API",
                    "PORT-INVENTORY-SNAPSHOT",
                ],
                "requiredOperationIds": [
                    "OP-CAPTURE-HOST-SNAPSHOT",
                    "OP-EMIT-AUDIT-EVIDENCE",
                    "OP-EVALUATE-CAPABILITY",
                    "OP-QUERY-DIRECTPATH",
                ],
                "requiredTransitionIds": [],
                "requiredEntityIds": [
                    "ENTITY-AUDIT-EVENT",
                    "ENTITY-AVAILABILITY-AUTHORITY",
                    "ENTITY-BUNDLE-LEASE",
                    "ENTITY-DEPENDENCY-BUNDLE",
                    "ENTITY-DEVICE-RECORD",
                    "ENTITY-HOST-ACTION-JOURNAL",
                    "ENTITY-HOST-AUTHORITY",
                    "ENTITY-HOST-SNAPSHOT",
                    "ENTITY-OPERATION-LEASE",
                    "ENTITY-QUARANTINE-RECORD",
                ],
                "requiredReasonIds": [
                    "INVENTORY_EPOCH_CHANGED",
                    "SNAPSHOT_INCOMPLETE",
                    "STALE_RESOURCE_VERSION",
                ],
            },
            "C20": {
                "requiredPortIds": [
                    "PORT-ASSIGNMENT-ORCHESTRATOR",
                    "PORT-CAPABILITY-ENGINE",
                    "PORT-GLOBAL-REPOSITORY",
                    "PORT-INVENTORY-SNAPSHOT",
                    "PORT-QUALIFICATION-CATALOG",
                ],
                "requiredOperationIds": [
                    "OP-CAPTURE-HOST-SNAPSHOT",
                    "OP-CAS-ACQUIRE-OPERATION-LEASE",
                    "OP-CAS-RESERVE-BUNDLES",
                    "OP-EVALUATE-CAPABILITY",
                    "OP-PLAN-STATIC",
                    "OP-RESOLVE-QUALIFICATION-PROFILE",
                ],
                "requiredTransitionIds": [],
                "requiredEntityIds": [
                    "ENTITY-ASSIGNMENT-RUN",
                    "ENTITY-AVAILABILITY-AUTHORITY",
                    "ENTITY-BUNDLE-LEASE",
                    "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                    "ENTITY-DEPENDENCY-BUNDLE",
                    "ENTITY-DEVICE-RECORD",
                    "ENTITY-HOST-AUTHORITY",
                    "ENTITY-HOST-SNAPSHOT",
                    "ENTITY-OPERATION-ADMISSION-BINDING",
                    "ENTITY-OPERATION-LEASE",
                    "ENTITY-QUALIFICATION-PROFILE",
                    "ENTITY-QUALIFICATION-RECORD",
                    "ENTITY-SUPPORTED-CATALOG",
                    "ENTITY-TRUST-KEY-RING",
                    "ENTITY-VM-DIRECTPATH-REQUEST",
                ],
                "requiredReasonIds": [
                    "DEPENDENCY_ACTION_CONFLICT",
                    "DEPENDENCY_ACTION_UNKNOWN",
                    "DEPENDENCY_BUSY",
                    "DEPENDENCY_CLOSURE_LIMIT",
                    "DEPENDENCY_PROVENANCE_UNKNOWN",
                    "DEVICE_QUARANTINED",
                    "INVENTORY_EPOCH_CHANGED",
                    "QUALIFICATION_EVIDENCE_MISSING",
                    "RESET_DOMAIN_CHANGED",
                    "RESET_DOMAIN_UNVERIFIED",
                    "RESET_NOT_SUPPORTED",
                    "SNAPSHOT_INCOMPLETE",
                    "STALE_HOST_EPOCH",
                    "STALE_RESOURCE_VERSION",
                ],
            },
        }
        for case_id, fields in expected.items():
            for field, values in fields.items():
                self.assertEqual(values, records[case_id][field], f"{case_id}.{field}")

        legacy = [
            record
            for record in records.values()
            if record["caseId"] not in expected
        ]
        self.assertEqual(98, len(legacy))
        self.assertTrue(all("requiredEntityIds" not in record for record in legacy))
        self.assertTrue(all("requiredReasonIds" not in record for record in legacy))

        ports = {item["id"] for item in self.portable["requiredPorts"]}
        operations = {
            item["id"]: item for item in self.portable["backendNeutralOperations"]
        }
        transitions = {
            item["id"]: item
            for machine in self.portable["stateMachines"]
            for item in machine["transitions"]
        }
        entities = {item["id"] for item in self.portable["dataEntities"]}
        reasons = {
            item["code"] for item in self.portable["errorContract"]["reasonCodes"]
        }
        matrix = {
            (item["kind"], item["contractItemId"]): item
            for item in self.portable["mappingSurface"]["verificationMatrix"]
        }
        field_kinds = {
            "requiredPortIds": "PORT",
            "requiredOperationIds": "OPERATION",
            "requiredTransitionIds": "TRANSITION",
            "requiredEntityIds": "ENTITY",
            "requiredReasonIds": "REASON",
        }
        for case_id in expected:
            record = records[case_id]
            self.assertTrue(set(record["requiredPortIds"]).issubset(ports))
            self.assertTrue(set(record["requiredOperationIds"]).issubset(operations))
            self.assertTrue(set(record["requiredTransitionIds"]).issubset(transitions))
            self.assertTrue(set(record["requiredEntityIds"]).issubset(entities))
            self.assertTrue(set(record["requiredReasonIds"]).issubset(reasons))
            self.assertEqual(
                set(record["requiredPortIds"]),
                {
                    operations[operation_id]["ownerPortId"]
                    for operation_id in record["requiredOperationIds"]
                },
            )
            for transition_id in record["requiredTransitionIds"]:
                self.assertTrue(
                    set(transitions[transition_id]["operationIds"]).issubset(
                        set(record["requiredOperationIds"])
                    )
                )
            for field, kind in field_kinds.items():
                for item_id in record[field]:
                    identity = (kind, item_id)
                    self.assertIn(identity, matrix, f"{case_id}.{field}")
                    self.assertIn(
                        case_id,
                        matrix[identity]["requiredCaseIds"],
                        f"{case_id}.{field} verification overlay",
                    )

    def test_explicit_case_trace_rejects_partial_unknown_and_owner_drift(self) -> None:
        definition = load("acceptance/cases/C10.json")
        ports = {
            item["id"]: item for item in self.portable["requiredPorts"]
        }
        operations = {
            item["id"]: item for item in self.portable["backendNeutralOperations"]
        }
        transitions = {
            item["id"]: item
            for machine in self.portable["stateMachines"]
            for item in machine["transitions"]
        }
        entities = {
            item["id"]: item for item in self.portable["dataEntities"]
        }
        reasons = {
            item["code"]: item
            for item in self.portable["errorContract"]["reasonCodes"]
        }

        def resolve(candidate: dict[str, object]) -> object:
            return case_generator.resolve_required_trace(
                candidate,
                derived_ports=[],
                port_by_id=ports,
                operation_by_id=operations,
                transition_by_id=transitions,
                entity_by_id=entities,
                reason_by_id=reasons,
            )

        partial = copy.deepcopy(definition)
        del partial["requiredReasonIds"]
        with self.assertRaisesRegex(ValueError, "explicit trace is partial"):
            resolve(partial)

        unknown = copy.deepcopy(definition)
        unknown["requiredReasonIds"] = ["NOT-A-PORTABLE-REASON"]
        with self.assertRaisesRegex(ValueError, "references unknown IDs"):
            resolve(unknown)

        owner_drift = copy.deepcopy(definition)
        owner_drift["requiredPortIds"] = [
            "PORT-INVENTORY-SNAPSHOT",
            "PORT-QUALIFICATION-CATALOG",
        ]
        with self.assertRaisesRegex(ValueError, "required operation owners"):
            resolve(owner_drift)

        transition_drift = copy.deepcopy(definition)
        transition_drift["requiredTransitionIds"] = [
            "TR-RUN-PREPARING-ATTACHED"
        ]
        with self.assertRaisesRegex(
            ValueError, "operations outside requiredOperationIds"
        ):
            resolve(transition_drift)

    def test_explicit_case_artifact_schema_refs_are_closed_and_additive(self) -> None:
        registry_c = load("acceptance/cases/registry-C.json")
        c_records = {
            record["id"]: record
            for record in registry_c["records"]
            if record["id"] in {"C00", "C01", "C02", "C03"}
        }
        common_inventory_closure = {
            "contracts/directpath-host-snapshot-publication-trace.schema.json",
            "contracts/directpath-inventory-verification-receipt.schema.json",
            "contracts/directpath-inventory-verifier-algorithm.schema.json",
            "contracts/directpath-portable-entities.schema.json",
            "contracts/directpath-portable-hash-subjects.schema.json",
        }
        self.assertEqual({"C00", "C01", "C02", "C03"}, set(c_records))
        for case_id, record in c_records.items():
            artifact_refs = record["requiredArtifactSchemaRefs"]
            self.assertEqual(sorted(artifact_refs), artifact_refs, case_id)
            self.assertTrue(
                common_inventory_closure.issubset(artifact_refs),
                (case_id, common_inventory_closure - set(artifact_refs)),
            )
        self.assertIn(
            "contracts/directpath-reset-contract-set.schema.json",
            c_records["C03"]["requiredArtifactSchemaRefs"],
        )

        definition = load("acceptance/cases/C10.json")
        explicit = definition["requiredArtifactSchemaRefs"]
        resolved = case_generator.required_artifact_schemas(
            definition,
            "qualification catalog",
        )
        self.assertTrue(set(explicit).issubset(resolved))
        self.assertIn(
            "contracts/directpath-acceptance-scenario.schema.json",
            resolved,
        )

        c15 = load("acceptance/cases/C15.json")
        self.assertEqual("PRODUCT", c15["scope"])
        self.assertEqual("IMPLEMENTATION_BLOCKED", c15["status"])
        self.assertTrue(
            {
                "contracts/directpath-operation-envelope.schema.json",
                "contracts/directpath-operation-payload.schema.json",
                "contracts/directpath-query-read-trace.schema.json",
            }.issubset(c15["requiredArtifactSchemaRefs"])
        )

        unsorted = copy.deepcopy(definition)
        unsorted["requiredArtifactSchemaRefs"] = list(reversed(explicit))
        with self.assertRaisesRegex(ValueError, "ascending schema-ref order"):
            case_generator.required_artifact_schemas(unsorted, "")

        missing = copy.deepcopy(definition)
        missing["requiredArtifactSchemaRefs"] = [
            "contracts/not-a-real-directpath-schema.json"
        ]
        with self.assertRaisesRegex(ValueError, "references missing schema"):
            case_generator.required_artifact_schemas(missing, "")

    def test_case_and_registry_digests_use_explicit_null_projection(self) -> None:
        for record in self.registry["records"]:
            projection = dict(record)
            declared = projection["caseContractDigest"]
            projection["caseContractDigest"] = None
            self.assertEqual(declared, digest(projection), record["caseId"])
        projection = dict(self.registry)
        declared = projection["registryDigest"]
        projection["registryDigest"] = None
        self.assertEqual(declared, digest(projection))

    def test_s05_binds_case_predicates_faults_and_repository_acceptance(self) -> None:
        record = next(
            item for item in self.registry["records"] if item["caseId"] == "S05"
        )
        self.assertEqual(record["caseContractDigest"], self.scenario["caseContractDigest"])
        expected_predicates = {
            (item["assertionId"], item["assertionDigest"], item["requiredOracleClass"])
            for item in record["assertions"]
        }
        actual_predicates = {
            (item["assertionId"], item["assertionDigest"], item["oracleClass"])
            for item in self.scenario["casePredicateBindings"]
        }
        self.assertEqual(expected_predicates, actual_predicates)
        fault_classes = {
            fault_class
            for step in self.scenario["steps"]
            for fault_class in step.get("faultInjection", {}).get("faultClasses", [])
        }
        self.assertTrue(set(record["requiredFaultClasses"]).issubset(fault_classes))
        self.assertIn(
            "ENTITY-CLEAN-RELEASE-ACCEPTANCE",
            self.scenario["traceability"]["entityIds"],
        )
        self.assertTrue(
            any(
                artifact["formatOrSchema"] == "ENTITY-CLEAN-RELEASE-ACCEPTANCE"
                for artifact in self.scenario["artifacts"]
            )
        )

    def test_execution_and_qualification_dag_is_acyclic_by_schema(self) -> None:
        evidence = load("contracts/directpath-execution-evidence-index.schema.json")
        subject = load("contracts/directpath-qualification-subject-manifest.schema.json")
        evidence_properties = evidence["properties"]
        subject_properties = subject["properties"]
        self.assertIn("scenarioExecutionCoreDigest", evidence_properties)
        self.assertNotIn("executionResultDigest", evidence_properties)
        self.assertIn("scenarioExecutionCoreDigests", subject_properties)
        self.assertNotIn("executionEvidenceIndexDigests", subject_properties)
        source_kinds = set(
            subject["$defs"]["measurement"]["properties"]["sourceKind"]["enum"]
        )
        self.assertIn("SCENARIO_EXECUTION_CORE", source_kinds)
        self.assertNotIn("EXECUTION_EVIDENCE_INDEX", source_kinds)

    def test_completion_records_resolve_raw_scenario_index_and_runner(self) -> None:
        completion = load("contracts/directpath-case-completion-record.schema.json")
        self.assertTrue(
            {
                "platformProfileId",
                "platformProfileDigest",
                "backendProfileDigest",
                "exactQualificationKey",
            }.issubset(set(completion["required"]))
        )
        required = set(completion["$defs"]["scenarioEvidence"]["required"])
        self.assertTrue(
            {
                "scenarioPath",
                "scenarioSha256",
                "executionEvidenceIndexPath",
                "evidenceIndexRecordSha256",
                "runnerManifestPath",
                "runnerManifestSha256",
                "executionEvidenceIndexDigest",
                "runnerManifestDigest",
            }.issubset(required)
        )
        integration = load("contracts/directpath-integration-report.schema.json")
        implementation = integration["$defs"]["implementationTestReport"]
        self.assertIn("caseCompletionRecords", implementation["required"])
        qualification = load(
            "contracts/directpath-qualification-release-index.schema.json"
        )
        self.assertIn("e4CaseCompletionRecords", qualification["required"])
        self.assertNotIn("e4EvidenceResults", qualification["properties"])

        evaluator_required = set(completion["$defs"]["evaluator"]["required"])
        self.assertIn("toolManifest", evaluator_required)
        evaluator_descriptor = completion["$defs"]["evaluatorToolManifest"]
        self.assertEqual(
            "contracts/directpath-case-evaluator-tool-manifest.schema.json",
            evaluator_descriptor["properties"]["schemaRef"]["const"],
        )

    def test_case_evaluator_has_independent_signed_provenance(self) -> None:
        sources = set(self.portable["normativeSources"])
        self.assertIn(
            "contracts/directpath-case-evaluator-tool-manifest.schema.json", sources
        )
        manifest = load(
            "contracts/directpath-case-evaluator-tool-manifest.schema.json"
        )
        self.assertTrue(
            {
                "targetRepositoryCommit",
                "mappingCoreId",
                "caseContractRegistryDigest",
                "evaluator",
                "sourceTree",
                "executionEnvironment",
                "manifestDigest",
                "signature",
            }.issubset(set(manifest["required"]))
        )
        runtime_required = set(
            manifest["$defs"]["executionEnvironment"]["required"]
        )
        self.assertEqual(
            {
                "mode",
                "runtimeBinary",
                "dependencyLock",
                "environmentManifest",
                "buildLog",
            },
            runtime_required,
        )
        self.assertIn(
            "CASE-EVALUATOR-TOOL-MANIFEST/V1", manifest["x-qmanSignatureRule"]
        )

    def test_runner_source_tree_and_qualification_measurements_are_typed(self) -> None:
        sources = set(self.portable["normativeSources"])
        self.assertTrue(
            {
                "contracts/directpath-source-tree-manifest.schema.json",
                "contracts/directpath-build-attestation.schema.json",
                "contracts/directpath-qualification-measurement.schema.json",
                "contracts/directpath-qualification-run-request.schema.json",
                "contracts/directpath-qualification-workload-definition.schema.json",
                "contracts/directpath-qualification-workload-result.schema.json",
                "contracts/directpath-qualification-run-manifest.schema.json",
            }.issubset(sources)
        )
        runner = load("contracts/directpath-runner-manifest.schema.json")
        build_required = set(runner["$defs"]["build"]["required"])
        self.assertTrue(
            {
                "sourceTreeManifestPath",
                "sourceTreeManifestSha256",
                "sourceTreeManifestSchemaSha256",
                "sourceTreeSha256",
                "buildAttestation",
            }.issubset(build_required)
        )
        tree = load("contracts/directpath-source-tree-manifest.schema.json")
        self.assertEqual("GIT-TRACKED-TREE-CLOSURE-V1", tree["properties"]["algorithm"]["const"])
        self.assertIn("dirty-working-tree", tree["x-qmanTreeProjectionRule"])

        build = load("contracts/directpath-build-attestation.schema.json")
        self.assertIn("replayEvidence", build["required"])
        self.assertIn("attestedAt", build["required"])
        self.assertIn("builderInstanceId", build["$defs"]["environment"]["required"])
        hermetic = next(
            rule["then"]["properties"]
            for rule in build["allOf"]
            if rule["if"]["properties"]["mode"]["const"]
            == "HERMETIC_REPRODUCIBLE"
            and "replayEvidence" in rule["then"]["properties"]
        )
        self.assertEqual(1, hermetic["replayEvidence"]["minItems"])

        measurement = load(
            "contracts/directpath-qualification-measurement.schema.json"
        )
        subject = load("contracts/directpath-qualification-subject-manifest.schema.json")
        self.assertIn("qualificationRunId", subject["required"])
        self.assertIn("bootId", subject["required"])
        self.assertIn("qualificationRunManifest", subject["required"])
        descriptor_required = set(subject["$defs"]["measurement"]["required"])
        self.assertTrue(
            {
                "measurementPath",
                "measurementSha256",
                "measurementDigest",
                "schemaRef",
                "schemaSha256",
                "valueProjection",
                "qualificationRunId",
                "bootId",
            }.issubset(descriptor_required)
        )
        self.assertEqual(8, len(measurement["allOf"]))
        self.assertIn("bootId", measurement["required"])
        self.assertIn(
            "deviceArchetype",
            measurement["$defs"]["subjectField"]["enum"],
        )
        run = load("contracts/directpath-qualification-run-manifest.schema.json")
        self.assertTrue(
            {
                "qualificationRunId",
                "bootId",
                "currentInventorySnapshot",
                "qualificationMeasurements",
                "scenarioExecutionCoreDigests",
                "runDigest",
                "attestations",
            }.issubset(set(run["required"]))
        )
        self.assertEqual(2, run["$defs"]["attestationSet"]["minItems"])
        request = load("contracts/directpath-qualification-run-request.schema.json")
        self.assertIn("workloadDefinition", request["required"])
        self.assertEqual(
            "contracts/directpath-qualification-workload-definition.schema.json",
            request["$defs"]["workloadDefinition"]["properties"]["schemaRef"]["const"],
        )
        workload = load(
            "contracts/directpath-qualification-workload-result.schema.json"
        )
        self.assertIn("assertionResults", workload["required"])
        self.assertIn("evidenceArtifactSha256s", workload["$defs"]["assertionResult"]["required"])
        index = load("contracts/directpath-execution-evidence-index.schema.json")
        self.assertEqual(
            {
                "sourceTreeManifest",
                "buildAttestation",
                "buildLog",
                "testLog",
                "toolManifest",
                "runnerBinary",
            },
            set(index["$defs"]["controlArtifacts"]["required"]),
        )
        self.assertIn("bijection", subject["x-qmanMeasurementRule"])

    def test_product_case_dependencies_never_depend_on_reference_scope(self) -> None:
        records = {record["caseId"]: record for record in self.registry["records"]}
        for record in records.values():
            if record["classification"]["scope"] != "PRODUCT":
                continue
            for dependency_id in record["classification"]["dependsOnCaseIds"]:
                self.assertEqual(
                    "PRODUCT",
                    records[dependency_id]["classification"]["scope"],
                    f"{record['caseId']} -> {dependency_id}",
                )
        self.assertEqual("PRODUCT", records["C20"]["classification"]["scope"])
        self.assertEqual(
            "IMPLEMENTATION_BLOCKED", records["C20"]["classification"]["status"]
        )

    def test_trust_history_and_live_nonce_freshness_are_normative(self) -> None:
        sources = set(self.portable["normativeSources"])
        self.assertIn("contracts/directpath-trust-key-ring-history.schema.json", sources)
        self.assertIn("contracts/directpath-anchor-freshness-envelope.schema.json", sources)
        freshness = load("contracts/directpath-anchor-freshness-envelope.schema.json")
        required = set(freshness["required"])
        self.assertTrue(
            {
                "verifierNonce",
                "observedAt",
                "expiresAt",
                "anchorDigest",
                "anchorVersion",
                "resourceVersion",
                "rootSignatures",
            }.issubset(required)
        )
        self.assertIn("300 seconds", freshness["x-qmanFreshnessRule"])
        self.assertIn(
            "evaluatorTime+30 seconds",
            freshness["x-qmanFreshnessRule"],
        )

    def test_portable_surface_includes_repository_acceptance(self) -> None:
        self.assertEqual(299, len(self.portable["mappingSurface"]["verificationMatrix"]))
        entities = {item["id"] for item in self.portable["dataEntities"]}
        self.assertIn("ENTITY-CLEAN-RELEASE-ACCEPTANCE", entities)


if __name__ == "__main__":
    unittest.main()
