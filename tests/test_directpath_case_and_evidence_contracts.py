from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path


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

    def test_portable_surface_includes_repository_acceptance(self) -> None:
        self.assertEqual(295, len(self.portable["mappingSurface"]["verificationMatrix"]))
        entities = {item["id"] for item in self.portable["dataEntities"]}
        self.assertIn("ENTITY-CLEAN-RELEASE-ACCEPTANCE", entities)


if __name__ == "__main__":
    unittest.main()
