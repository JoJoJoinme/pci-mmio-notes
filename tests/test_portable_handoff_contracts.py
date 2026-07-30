from __future__ import annotations

import copy
import hashlib
import inspect
import json
import re
import unittest
from pathlib import Path
from typing import Any, Iterable
from unittest import mock

from tools import validate_portable_handoff as handoff_validator


ROOT = Path(__file__).resolve().parents[1]


def load(relative: str) -> dict[str, Any]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def unique(values: Iterable[str]) -> set[str]:
    items = list(values)
    if len(items) != len(set(items)):
        duplicates = sorted({item for item in items if items.count(item) > 1})
        raise AssertionError(f"duplicate IDs: {duplicates}")
    return set(items)


def canonical_digest(value: Any) -> str:
    """Independent CANONICAL-JSON-V1 digest for these ASCII-keyed fixtures."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def resolve_schema_ref(
    reference: str, *, relative_to: Path = ROOT
) -> tuple[dict[str, Any], Path]:
    path_text, separator, fragment = reference.partition("#")
    path = Path(path_text)
    if not path.is_absolute():
        path = relative_to / path
    path = path.resolve()
    node: Any = json.loads(path.read_text(encoding="utf-8"))
    if separator and fragment:
        if not fragment.startswith("/"):
            raise AssertionError(f"unsupported schema fragment: {reference}")
        for raw_token in fragment[1:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            node = node[token]
    if not isinstance(node, dict):
        raise AssertionError(f"schema reference does not resolve to an object: {reference}")
    return node, path


def effective_object_shape(
    node: dict[str, Any], schema_path: Path
) -> tuple[set[str], set[str], bool]:
    """Resolve the small $ref/allOf subset used by persisted entity schemas."""

    required = set(node.get("required", []))
    properties = set(node.get("properties", {}))
    closed = node.get("additionalProperties") is False
    if "$ref" in node:
        referenced, referenced_path = resolve_schema_ref(
            node["$ref"], relative_to=schema_path.parent
        )
        nested_required, nested_properties, nested_closed = effective_object_shape(
            referenced, referenced_path
        )
        required.update(nested_required)
        properties.update(nested_properties)
        closed = closed or nested_closed
    for branch in node.get("allOf", []):
        nested_required, nested_properties, nested_closed = effective_object_shape(
            branch, schema_path
        )
        required.update(nested_required)
        properties.update(nested_properties)
        closed = closed or nested_closed
    return required, properties, closed


def collect_case_ids() -> set[str]:
    result: list[str] = []
    for path in sorted((ROOT / "acceptance" / "cases").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if "id" in document:
            result.append(document["id"])
        result.extend(record["id"] for record in document.get("records", []))
    return unique(result)


def collect_tech_story_ids(ipd: dict[str, Any]) -> set[str]:
    return unique(
        story["id"]
        for feature in ipd["features"]
        for story in feature["techStories"]
    )


def derive_mapping_items(contract: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        *[("CANONICALIZATION", item["id"]) for item in contract["canonicalizationContract"]["profiles"]],
        *[("GUARD", item["id"]) for item in contract["safetyGuards"]],
        [("EQUIVALENCE", contract["dynamicCandidateEquivalence"]["id"])][0],
        *[("PORT", item["id"]) for item in contract["requiredPorts"]],
        *[("ENTITY", item["id"]) for item in contract["dataEntities"]],
        *[("OPERATION", item["id"]) for item in contract["backendNeutralOperations"]],
        *[("STATE_MACHINE", item["id"]) for item in contract["stateMachines"]],
        *[
            ("TRANSITION", transition["id"])
            for machine in contract["stateMachines"]
            for transition in machine["transitions"]
        ],
        *[("CAS_RULE", item["id"]) for item in contract["casRules"]],
        *[("REASON", item["code"]) for item in contract["errorContract"]["reasonCodes"]],
        *[("CONFIG", item["id"]) for item in contract["configurationContract"]["settings"]],
        *[("MIGRATION", item["id"]) for item in contract["migrationContract"]["steps"]],
        *[("TELEMETRY", item["id"]) for item in contract["telemetryContract"]["metrics"]],
        *[("TEST", item["id"]) for item in contract["acceptanceObligations"]],
        *[("PARITY_OBLIGATION", item["id"]) for item in contract["vmwareParityObligations"]],
    ]


class PortableHandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load("contracts/directpath-portable-control-contract.json")
        cls.mapping_schema = load("contracts/qman-integration-map.schema.json")
        cls.mapping_template = load("contracts/qman-integration-map.template.json")
        cls.authority_entity_schema = load(
            "contracts/directpath-authority-entities.schema.json"
        )
        cls.portable_entity_schema = load(
            "contracts/directpath-portable-entities.schema.json"
        )
        cls.operation_schema = load(
            "contracts/directpath-operation-envelope.schema.json"
        )
        cls.operation_payload_schema = load(
            "contracts/directpath-operation-payload.schema.json"
        )
        cls.workload_evaluator_schema = load(
            "contracts/directpath-workload-evaluator-manifest.schema.json"
        )
        cls.workload_evaluation_report_schema = load(
            "contracts/directpath-workload-evaluation-report.schema.json"
        )
        cls.device_taxonomy_schema = load(
            "contracts/directpath-device-taxonomy-definition.schema.json"
        )
        cls.device_classification_schema = load(
            "contracts/directpath-device-classification-record.schema.json"
        )
        cls.identity_schema = load("contracts/directpath-identity-v1.schema.json")
        cls.identity_vectors = load(
            "contracts/directpath-identity-v1.golden-vectors.json"
        )
        cls.compatibility_policy = load("contracts/compatibility-profile-policy.json")
        cls.trust_root_schema = load("contracts/directpath-trust-root-set.schema.json")
        cls.trust_key_ring_schema = load(
            "contracts/directpath-trust-key-ring.schema.json"
        )
        cls.trust_rollback_schema = load(
            "contracts/directpath-trust-rollback-anchor.schema.json"
        )
        cls.catalog_schema = load("contracts/directpath-supported-catalog.schema.json")
        cls.catalog_anchor_schema = load(
            "contracts/directpath-catalog-rollback-anchor.schema.json"
        )
        cls.qualification_index_schema = load(
            "contracts/directpath-qualification-release-index.schema.json"
        )
        cls.acceptance_schema = load(
            "contracts/directpath-acceptance-scenario.schema.json"
        )
        cls.acceptance_example = load(
            "handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json"
        )
        cls.vmware = load("contracts/vmware-behavior-model.json")
        cls.ipd = load("contracts/ipd-tree.json")
        cls.project_status = load("contracts/project-status.json")
        cls.risk_status = load("contracts/risk-status.json")
        cls.case_ids = collect_case_ids()
        cls.tech_story_ids = collect_tech_story_ids(cls.ipd)

    def test_status_axes_do_not_transfer_mapping_implementation_or_qualification(self) -> None:
        axes = self.contract["statusAxes"]
        self.assertEqual(
            {
                "portableSpecification": ("PORTABLE_SPEC_READY", "READY"),
                "targetCodeMapping": ("TARGET_CODE_MAPPED", "UNMAPPED"),
                "productImplementation": ("PRODUCT_IMPLEMENTED", "NOT_PROVEN"),
                "qualification": ("QUALIFIED", "NOT_PROVEN"),
            },
            {
                key: (value["criterion"], value["status"])
                for key, value in axes.items()
            },
        )
        self.assertIn("doesNotProve", axes["portableSpecification"])
        self.assertIn("doesNotProve", axes["targetCodeMapping"])
        self.assertIn("doesNotProve", axes["productImplementation"])
        self.assertIn("doesNotProve", axes["qualification"])

        self.assertEqual(
            {
                "PORTABLE_SPEC_READY": True,
                "TARGET_CODE_MAPPED": False,
                "PRODUCT_IMPLEMENTED": False,
                "QUALIFIED": False,
            },
            self.mapping_template["statusAxes"],
        )
        self.assertTrue(
            all(value is None for value in self.mapping_template["targetRepository"].values())
        )
        self.assertTrue(
            all(value is None for value in self.mapping_template["completionEvidence"].values())
        )
        self.assertEqual([], self.mapping_template["approvals"])

    def test_vmware_baseline_is_frozen_and_matches_behavior_model(self) -> None:
        expected = {
            "esxiVersion": "8.0.3",
            "build": "24280767",
            "apiVersion": "8.0.3.0",
            "virtualHardware": "20",
            "environmentClass": "NESTED_INSTRUMENTED_REFERENCE",
        }
        baseline = self.contract["frozenVmwareBaseline"]
        self.assertEqual(expected, {key: baseline[key] for key in expected})
        self.assertEqual(expected, self.vmware["referenceBaseline"])
        self.assertTrue(baseline["latestApiDeltaPolicy"]["baselineUnaffected"])
        self.assertIn("cannot silently change", baseline["freezePolicy"])
        self.assertIn(
            "VMWARE_EVIDENCE_NEVER_CLOSES_QMAN_IMPLEMENTATION",
            self.contract["alignmentPolicy"]["nonTransference"],
        )

    def test_canonical_identity_candidate_equivalence_and_manifest_v2_are_explicit(self) -> None:
        profiles = {
            item["id"]: item for item in self.contract["canonicalizationContract"]["profiles"]
        }
        self.assertEqual(
            {"CANONICAL-JSON-V1", "TIMESTAMP-UTC-US-V1", "IDENTITY-V1", "SIGNED-ENVELOPE-V1"},
            set(profiles),
        )
        self.assertEqual("CANONICAL-JSON-V1", profiles["IDENTITY-V1"]["canonicalProfileId"])
        self.assertIn("currentBdf", profiles["IDENTITY-V1"]["locatorFieldsExcluded"])
        self.assertEqual(
            {"STRONG_SERIAL", "SLOT_BOUND"},
            set(profiles["IDENTITY-V1"]["fingerprintVariants"]),
        )
        self.assertIn("RFC 8785", profiles["CANONICAL-JSON-V1"]["standard"])
        self.assertEqual(2, len(profiles["CANONICAL-JSON-V1"]["goldenVectors"]))
        for vector in profiles["CANONICAL-JSON-V1"]["goldenVectors"]:
            observed = "sha256:" + hashlib.sha256(
                vector["canonicalUtf8"].encode("utf-8")
            ).hexdigest()
            self.assertEqual(vector["sha256"], observed, vector["id"])
        self.assertIn(
            "floating-point values are forbidden",
            " ".join(profiles["CANONICAL-JSON-V1"]["rules"]).lower(),
        )
        signed = profiles["SIGNED-ENVELOPE-V1"]
        self.assertEqual("Ed25519", signed["algorithm"])
        self.assertIn("0x00", signed["preimageRule"])
        self.assertEqual(
            {
                "QualificationRecord",
                "SupportedCatalog",
                "CleanReleaseReceipt",
                "CleanReleaseAcceptance",
                "AcceptanceExecutionResult",
                "RunnerManifest",
                "BuildAttestation",
                "ExecutionEvidenceIndex",
                "QualificationSubjectManifest",
                "QualificationMeasurement",
                "QualificationWorkloadDefinition",
                "QualificationRunRequest",
                "QualificationWorkloadResult",
                "QualificationRunManifest",
                "CaseCompletionRecord",
                "CaseEvaluatorToolManifest",
                "IntegrationApproval",
                "QualificationReleaseIndex",
                "TargetSymbolIndex",
                "HostSnapshot",
                "HostSnapshotPublicationRepositoryReceipt",
                "WorkloadEvaluatorManifest",
                "WorkloadEvaluationContext",
                "WorkloadEvaluationReport",
                "DeviceTaxonomyDefinition",
                "DeviceClassificationContext",
                "DeviceClassificationRecord",
            },
            {item["subject"] for item in signed["documentProfiles"]},
        )

        equivalence = self.contract["dynamicCandidateEquivalence"]
        self.assertEqual("DYNAMIC-CANDIDATE-EQUIVALENCE-V1", equivalence["id"])
        self.assertGreaterEqual(len(equivalence["signatureFields"]), 10)
        self.assertIn("dependencyBundleClosureHash", equivalence["signatureFields"])
        self.assertIn("BARAndROMResourceEnvelope", equivalence["signatureFields"])
        self.assertIn("RMRRContract", equivalence["signatureFields"])
        self.assertIn("bundleId alone never proves", equivalence["bundleIdRule"])

        manifest = next(
            item
            for item in self.contract["dataEntities"]
            if item["id"] == "ENTITY-ASSIGNMENT-MANIFEST"
        )
        self.assertEqual(2, manifest["writeSchemaVersion"])
        self.assertIn("bindings", manifest["requiredFields"])
        self.assertIn("requirementId", manifest["bindingRequiredFields"])
        self.assertIn("resourcePlanSliceHash", manifest["bindingRequiredFields"])
        self.assertIn("one ordered binding", manifest["multiBindingRule"])

    def test_typed_operation_lease_and_release_ownership_guard_fail_closed(self) -> None:
        guards = {item["id"]: item for item in self.contract["safetyGuards"]}
        self.assertEqual(
            {"GUARD-TYPED-OPERATION-LEASE", "GUARD-RELEASE-OWNERSHIP"},
            set(guards),
        )
        operation_guard = guards["GUARD-TYPED-OPERATION-LEASE"]
        self.assertIn("OWNER_TRANSITION", operation_guard["leaseTypes"])
        self.assertIn("before the first owner", operation_guard["rule"])

        release_guard = guards["GUARD-RELEASE-OWNERSHIP"]
        self.assertEqual("ReleaseOwnershipGuard", release_guard["name"])
        self.assertIn("Before requesting QEMU stop", release_guard["acquireRule"])
        self.assertIn("is duplicated", release_guard["fdLifetimeRule"])
        self.assertIn("reacquires", release_guard["contextRule"])
        self.assertIn("Legacy reopens exact group/device paths", release_guard["contextRule"])
        self.assertIn("quarantines", release_guard["failureRule"])

        entities = {item["id"] for item in self.contract["dataEntities"]}
        self.assertIn("ENTITY-OPERATION-LEASE", entities)
        self.assertIn("ENTITY-RELEASE-OWNERSHIP-GUARD", entities)
        operations = {item["id"]: item for item in self.contract["backendNeutralOperations"]}
        self.assertIn("OP-CAS-ACQUIRE-OPERATION-LEASE", operations)
        self.assertIn("OP-ACQUIRE-RELEASE-OWNERSHIP-GUARD", operations)
        self.assertIn(
            "no QEMU-owned backend fd is retained cross-process",
            " ".join(operations["OP-TEARDOWN-HOST-BUNDLE"]["preconditions"]),
        )
        cas_ids = {item["id"] for item in self.contract["casRules"]}
        self.assertIn("CAS-OPERATION-LEASE", cas_ids)
        self.assertIn("CAS-RELEASE-GUARD", cas_ids)

    def test_required_ports_and_operations_form_one_backend_neutral_surface(self) -> None:
        ports = self.contract["requiredPorts"]
        operations = self.contract["backendNeutralOperations"]
        port_ids = unique(item["id"] for item in ports)
        operation_ids = unique(item["id"] for item in operations)
        self.assertEqual(17, len(port_ids))

        listed: list[str] = []
        for port in ports:
            self.assertTrue(port["responsibility"])
            self.assertTrue(port["authority"])
            self.assertTrue(port["mustNot"])
            self.assertTrue(port["operationIds"])
            listed.extend(port["operationIds"])
        self.assertEqual(operation_ids, set(listed))
        self.assertEqual(len(operation_ids), len(listed))

        owner_by_operation = {item["id"]: item["ownerPortId"] for item in operations}
        for port in ports:
            for operation_id in port["operationIds"]:
                self.assertEqual(port["id"], owner_by_operation[operation_id])
        for operation in operations:
            self.assertIn(operation["ownerPortId"], port_ids)
            self.assertTrue(operation["input"])
            self.assertTrue(operation["output"])
            self.assertTrue(operation["preconditions"])
            self.assertTrue(operation["postconditions"])
            self.assertTrue(operation["failureReasonCodes"])

        backend = self.contract["backendPolicy"]
        self.assertEqual("ONE_CONTROL_PLANE_ONE_FSM_ONE_REASON_REGISTRY", backend["businessContract"])
        self.assertFalse(backend["silentFallback"])
        self.assertEqual("REJECT", backend["noIommu"])
        adapters = {item["id"]: item for item in backend["adapters"]}
        self.assertEqual(
            {"BACKEND-LEGACY-VFIO-TYPE1", "BACKEND-IOMMUFD-CDEV"}, set(adapters)
        )
        self.assertEqual("CURRENT_REQUIRED_FIRST", adapters["BACKEND-LEGACY-VFIO-TYPE1"]["role"])
        self.assertEqual("FUTURE_SEPARATELY_QUALIFIED", adapters["BACKEND-IOMMUFD-CDEV"]["role"])
        for adapter in adapters.values():
            self.assertIn("ReleaseOwnershipGuard", adapter["releaseRecovery"])
            self.assertIn("no qemu-owned", adapter["releaseRecovery"].lower())

    def test_qualification_and_supported_catalog_have_separate_signed_authorities(self) -> None:
        entities = {item["id"]: item for item in self.contract["dataEntities"]}
        qualification = entities["ENTITY-QUALIFICATION-RECORD"]
        catalog = entities["ENTITY-SUPPORTED-CATALOG"]
        self.assertIn("qualificationSignerKeyId", qualification["requiredFields"])
        self.assertIn("e4EvidenceHashes", qualification["requiredFields"])
        self.assertIn("Product Release", catalog["immutability"])
        self.assertIn("catalogSequence", catalog["requiredFields"])
        self.assertIn("previousCatalogDigest", catalog["requiredFields"])
        self.assertNotIn("rollbackAnchorReceipt", catalog["requiredFields"])
        self.assertNotIn(
            "rollbackAnchorReceipt", self.catalog_schema["properties"]
        )
        self.assertIn("receipt", self.catalog_anchor_schema["required"])
        self.assertIn(
            "out of band",
            self.catalog_anchor_schema["x-qmanOutOfBandAuthorityRule"].lower(),
        )

        operation = next(
            item
            for item in self.contract["backendNeutralOperations"]
            if item["id"] == "OP-RESOLVE-QUALIFICATION-PROFILE"
        )
        self.assertIn("external rollback-anchor state", operation["input"])
        self.assertIn("Qualification Engineering", " ".join(operation["preconditions"]))

    def test_workload_evaluator_taxonomy_and_measured_prerequisites_are_closed(self) -> None:
        normative_sources = set(self.contract["normativeSources"])
        self.assertTrue(
            {
                "contracts/directpath-workload-evaluator-manifest.schema.json",
                "contracts/directpath-workload-evaluation-report.schema.json",
                "contracts/directpath-device-taxonomy-definition.schema.json",
                "contracts/directpath-device-classification-record.schema.json",
                "tools/validate_portable_handoff.py",
            }.issubset(normative_sources)
        )

        build = load("contracts/directpath-build-attestation.schema.json")
        self.assertEqual(
            [
                "RUNNER",
                "CASE_EVALUATOR",
                "WORKLOAD_EVALUATOR",
                "TAXONOMY_CLASSIFIER",
            ],
            build["properties"]["consumerKind"]["enum"],
        )
        typed_roles: dict[str, set[str]] = {}
        for rule in build["allOf"]:
            consumer = (
                rule.get("if", {})
                .get("properties", {})
                .get("consumerKind", {})
                .get("const")
            )
            if consumer is None:
                continue
            typed_roles[consumer] = {
                branch["allOf"][1]["properties"]["role"]["const"]
                for branch in rule["then"]["properties"]["output"]["oneOf"]
            }
        self.assertEqual(
            {
                "RUNNER": {"RUNNER_BINARY", "RUNNER_SOURCE"},
                "CASE_EVALUATOR": {
                    "CASE_EVALUATOR_BINARY",
                    "CASE_EVALUATOR_SOURCE",
                },
                "WORKLOAD_EVALUATOR": {
                    "WORKLOAD_EVALUATOR_BINARY",
                    "WORKLOAD_EVALUATOR_SOURCE",
                },
                "TAXONOMY_CLASSIFIER": {
                    "TAXONOMY_CLASSIFIER_BINARY",
                    "TAXONOMY_CLASSIFIER_SOURCE",
                },
            },
            typed_roles,
        )

        evaluator = self.workload_evaluator_schema
        self.assertTrue(
            {
                "targetRepositoryCommit",
                "mappingCoreId",
                "portableContractSha256",
                "evaluator",
                "sourceTree",
                "buildAttestation",
                "executionEnvironment",
                "inputContracts",
                "observationArtifactAccess",
                "outputContract",
                "numericSemantics",
            }.issubset(evaluator["required"])
        )
        self.assertTrue(
            {"path", "symbol", "blobSha256", "symbolSemanticHash", "interfaceContractDigest"}.issubset(
                evaluator["$defs"]["evaluator"]["required"]
            )
        )
        expected_inputs = {
            "workloadDefinition": "contracts/directpath-qualification-workload-definition.schema.json",
            "runRequest": "contracts/directpath-qualification-run-request.schema.json",
            "artifactObservationSet": "contracts/directpath-workload-evaluation-report.schema.json#/$defs/artifactObservationSet",
            "evaluationContext": "contracts/directpath-workload-evaluation-report.schema.json#/$defs/evaluationContext",
        }
        input_contracts = evaluator["$defs"]["inputContracts"]
        self.assertFalse(input_contracts["additionalProperties"])
        self.assertEqual(set(expected_inputs), set(input_contracts["required"]))
        for field, schema_ref in expected_inputs.items():
            self.assertEqual(
                schema_ref,
                input_contracts["properties"][field]["allOf"][1]["properties"][
                    "schemaRef"
                ]["const"],
            )
        numeric = evaluator["$defs"]["numericSemantics"]["properties"]
        self.assertEqual(128, numeric["maxInputEncodedBytes"]["const"])
        self.assertEqual(128, numeric["maxInputCoefficientDigits"]["const"])
        self.assertEqual(127, numeric["maxInputFractionalDigits"]["const"])
        self.assertEqual(1_000_000, numeric["maxSamplesPerMetric"]["const"])
        self.assertEqual(256, numeric["maxWorkingCoefficientDigits"]["const"])
        self.assertEqual(
            "ROUND_HALF_EVEN_AT_METRIC_OUTPUT_SCALE",
            numeric["roundingMode"]["const"],
        )
        self.assertIn(
            "materialization paths/evidence-root location are excluded",
            evaluator["x-qmanEvaluationRule"],
        )
        self.assertEqual(
            "EXACT_DESCRIPTOR_SET_READ_ONLY",
            evaluator["properties"]["observationArtifactAccess"]["const"],
        )
        self.assertIn("--evidence-root", evaluator["x-qmanInterfaceRule"])
        self.assertIn("nearest rank", evaluator["x-qmanNumericRule"].lower())
        self.assertIn("MUST NOT execute", evaluator["x-qmanReplayIsolationRule"])
        self.assertIn("deny-all network", evaluator["x-qmanReplayIsolationRule"])

        report = self.workload_evaluation_report_schema
        self.assertEqual(
            ["PASSED", "FAILED", "EVALUATION_ERROR"],
            report["properties"]["evaluationOutcome"]["enum"],
        )
        self.assertIn("evaluationContext", report["required"])
        self.assertIn("signedAt", report["required"])
        self.assertIn("exact bijection", report["x-qmanCompletenessRule"])
        self.assertIn("transient projection", report["x-qmanSignatureRule"])
        metric = report["$defs"]["metric"]
        self.assertIn("outputScale", metric["required"])
        self.assertEqual(38, metric["properties"]["outputScale"]["maximum"])

        workload_definition = load(
            "contracts/directpath-qualification-workload-definition.schema.json"
        )
        self.assertIn("evaluatorManifest", workload_definition["required"])
        oracle = workload_definition["$defs"]["oracle"]["properties"]
        self.assertEqual(
            "QMAN-WORKLOAD-PINNED-EVALUATOR-CONFIG-V1",
            oracle["expressionLanguage"]["const"],
        )
        self.assertIn("expressionSha256", workload_definition["$defs"]["oracle"]["required"])
        metric_definition = workload_definition["$defs"]["metricDefinition"]
        self.assertTrue(
            {"evaluatorId", "evaluatorDefinitionDigest", "outputScale"}.issubset(
                metric_definition["required"]
            )
        )

        workload_result = load(
            "contracts/directpath-qualification-workload-result.schema.json"
        )
        evaluation_report = workload_result["$defs"]["evaluationReport"]
        self.assertEqual(
            "contracts/directpath-workload-evaluation-report.schema.json",
            evaluation_report["properties"]["schemaRef"]["const"],
        )
        self.assertTrue(
            {"evaluationOutcome", "evaluatedAt", "reportSignedAt", "reportDigest"}.issubset(
                evaluation_report["required"]
            )
        )
        self.assertIn("byte-equal", workload_result["x-qmanArtifactAndMetricRule"])

        taxonomy = self.device_taxonomy_schema
        classifier = taxonomy["$defs"]["classifier"]
        self.assertTrue(
            {"path", "symbol", "blobSha256", "symbolSemanticHash", "interfaceContractDigest"}.issubset(
                classifier["required"]
            )
        )
        archetype_set = taxonomy["$defs"]["archetypeSet"]
        archetypes = {
            branch["contains"]["properties"]["archetype"]["const"]
            for branch in archetype_set["allOf"]
        }
        self.assertEqual(
            {
                "CONSUMER_GPU",
                "PROFESSIONAL_GPU",
                "HBA",
                "ACCELERATOR",
                "GENERIC_PCI",
            },
            archetypes,
        )
        self.assertEqual(
            {"hostSnapshot", "deviceRecord", "classificationContext"},
            set(taxonomy["$defs"]["inputContracts"]["required"]),
        )
        self.assertIn("classificationContext,output", taxonomy["x-qmanClassifierRule"])
        self.assertIn("MUST NOT execute", taxonomy["x-qmanReplayIsolationRule"])
        classification = self.device_classification_schema
        self.assertEqual(
            archetypes,
            set(classification["properties"]["deviceArchetype"]["enum"]),
        )
        classification_refs: list[str] = []

        def collect_refs(node: Any) -> None:
            if isinstance(node, dict):
                if isinstance(node.get("$ref"), str):
                    classification_refs.append(node["$ref"])
                for value in node.values():
                    collect_refs(value)
            elif isinstance(node, list):
                for value in node:
                    collect_refs(value)

        collect_refs(classification)
        self.assertFalse(
            any(
                "qualification-record" in reference
                or "supported-catalog" in reference
                for reference in classification_refs
            )
        )
        self.assertIn("unique ascending precedence", classification["x-qmanClassificationRule"])
        self.assertIn("classificationContext", classification["required"])
        self.assertIn("hostAuthorityPointerReceipt", classification["required"])
        self.assertIn("signedAt", classification["required"])
        context = classification["$defs"]["classificationContext"]
        self.assertFalse(context["additionalProperties"])
        self.assertTrue(
            {
                "classificationId",
                "targetRepositoryCommit",
                "mappingCoreId",
                "portableContractSha256",
                "taxonomyDefinition",
                "inventorySnapshot",
                "deviceRecord",
                "hostAuthorityPointerReceipt",
                "deviceRecordHash",
                "classifiedAt",
                "keyRingVersion",
                "signerKeyId",
                "contextDigest",
                "signature",
            }.issubset(context["required"])
        )
        self.assertIn(
            "no QualificationRunRequest/Result/Manifest",
            classification["x-qmanNoSelfQualificationRule"],
        )

        qualification = load("contracts/directpath-qualification-record.schema.json")
        platform = qualification["$defs"]["platformRuntime"]
        guest = qualification["$defs"]["guestWorkload"]
        self.assertIn("runtimeCapabilities", platform["required"])
        self.assertTrue(
            {
                "guestArchitecture",
                "guestVcpuCount",
                "guestMemoryMiB",
                "guestCapabilities",
            }.issubset(guest["required"])
        )
        subject = load("contracts/directpath-qualification-subject-manifest.schema.json")
        observation = subject["$defs"]["workloadObservation"]
        self.assertIn("monotonicDurationNanoseconds", observation["required"])
        self.assertIn("1000000000", subject["x-qmanDurationRule"])

        guest_prerequisites = workload_definition["$defs"]["guestPrerequisites"]
        self.assertEqual(
            {"requiredGuestCapabilities"},
            set(guest_prerequisites["required"]),
        )
        self.assertNotIn("supportedGuestTuples", guest_prerequisites["properties"])
        self.assertIn("supportedQualificationTuples", workload_definition["required"])
        self.assertEqual(
            {
                "guestAbiClass",
                "guestArchitecture",
                "guestOs",
                "guestKernel",
                "driverName",
                "driverVersion",
                "driverDigest",
            },
            set(workload_definition["$defs"]["guestTuple"]["required"]),
        )
        runtime_prerequisites = workload_definition["$defs"]["runtimePrerequisites"]
        self.assertNotIn("supportedRuntimeTuples", runtime_prerequisites["properties"])
        self.assertEqual(
            {
                "platformProfileId",
                "backendFamily",
                "configuredIommuType",
                "machineType",
                "firmwareKind",
            },
            set(workload_definition["$defs"]["runtimeTuple"]["required"]),
        )
        self.assertEqual(
            {"guest", "runtime"},
            set(workload_definition["$defs"]["qualificationTuple"]["required"]),
        )
        self.assertIn(
            "never matched independently",
            workload_definition["x-qmanPrerequisiteRule"],
        )
        validator_source = inspect.getsource(
            handoff_validator._validate_qualification_subject_manifest
        )
        self.assertIn(
            "_validate_device_classification_record(", validator_source
        )

        run_request = load(
            "contracts/directpath-qualification-run-request.schema.json"
        )
        run_manifest = load(
            "contracts/directpath-qualification-run-manifest.schema.json"
        )
        subject_manifest = load(
            "contracts/directpath-qualification-subject-manifest.schema.json"
        )
        measurement = load(
            "contracts/directpath-qualification-measurement.schema.json"
        )
        for schema in (run_request, run_manifest, subject_manifest, measurement):
            self.assertTrue(
                {"deviceUid", "deviceRecordHash"}.issubset(schema["required"])
            )
        self.assertIn(
            "DEVICE_INVENTORY_RECORD",
            measurement["$defs"]["evidenceBinding"]["properties"][
                "evidenceRole"
            ]["enum"],
        )
        device_record = load("contracts/directpath-portable-entities.schema.json")[
            "$defs"
        ]["ENTITY-DEVICE-RECORD"]
        self.assertIn("technicalTraits", device_record["required"])
        self.assertEqual(
            "NONE",
            load("contracts/directpath-qualification-record.schema.json")[
                "$defs"
            ]["pciIdentity"]["properties"]["errataProfileId"]["const"],
        )

    def test_device_record_identity_projection_matches_both_golden_variants(self) -> None:
        vectors = self.identity_schema["x-qmanGoldenVectors"]
        self.assertEqual(2, len(vectors))
        for vector in vectors:
            immutable = json.loads(vector["canonicalUtf8"])
            identity_fingerprint = vector["sha256"]
            device: dict[str, Any] = {
                "hostId": immutable["hostStableId"],
                "deviceUid": (
                    "urn:qman:directpath:device:v1:"
                    f"{immutable['hostStableId']}:{identity_fingerprint}"
                ),
                "immutableIdentity": immutable,
                "identityFingerprint": identity_fingerprint,
                "role": {
                    "functionRole": immutable["pciIds"]["functionRole"]
                },
                "technicalTraits": ["reset"],
                "deviceRecordHash": None,
            }
            if immutable["identityVariant"] == "SLOT_BOUND":
                device["physicalPathProvider"] = immutable[
                    "physicalPathProvider"
                ]
                device["physicalPath"] = immutable["physicalPath"]
            device["deviceRecordHash"] = handoff_validator.sha256(
                handoff_validator.canonical_json_bytes(device)
            )
            errors: list[str] = []
            actual = handoff_validator._derive_qualification_pci_identity(
                device,
                "NONE",
                label=vector["id"],
                errors=errors,
            )
            self.assertEqual([], errors)
            self.assertIsNotNone(actual)
            assert actual is not None
            self.assertEqual(immutable["pciIds"]["vendorId"], actual["vendorId"])
            self.assertEqual(
                immutable["identityVariant"], actual["identityVariant"]
            )
            self.assertEqual("NONE", actual["errataProfileId"])

    def test_subject_validation_reaches_device_classification_helper(self) -> None:
        classification_blob = b"{}"
        measurement_schema_path = (
            ROOT / "contracts/directpath-qualification-measurement.schema.json"
        )
        measurement_schema_sha = handoff_validator.sha256(
            measurement_schema_path.read_bytes()
        )
        classification_schema_sha = handoff_validator.sha256(
            (
                ROOT
                / "contracts/directpath-device-classification-record.schema.json"
            ).read_bytes()
        )
        device_uid = (
            "urn:qman:directpath:device:v1:host-001:sha256:" + ("1" * 64)
        )
        device_record_hash = "sha256:" + ("2" * 64)
        binding = {
            "evidenceRole": "QUALIFICATION_TAXONOMY_RECORD",
            "path": "classification.json",
            "sha256": handoff_validator.sha256(classification_blob),
            "mediaType": "application/json",
            "byteLength": len(classification_blob),
            "schemaRefOrNull": (
                "contracts/directpath-device-classification-record.schema.json"
            ),
            "schemaSha256OrNull": classification_schema_sha,
            "valueProjectionOrNull": "/deviceArchetype",
        }
        measurement = {
            "qualificationRunId": "run-001",
            "subjectField": "deviceArchetype",
            "sourceKind": "QUALIFICATION_TAXONOMY_CLASSIFICATION",
            "hostId": "host-001",
            "hostEpoch": 1,
            "bootId": "boot-001",
            "deviceUid": device_uid,
            "deviceRecordHash": device_record_hash,
            "inventorySnapshotDigestOrNull": "sha256:" + ("3" * 64),
            "observedAt": "2026-07-22T00:00:01.000000Z",
            "signerRole": "QUALIFICATION_ENGINEERING",
            "evidenceBindings": [binding],
            "measuredValue": "GENERIC_PCI",
        }
        measurement_blob = handoff_validator.canonical_json_bytes(measurement)
        source = {
            "qualificationRunId": "run-001",
            "subjectField": "deviceArchetype",
            "sourceKind": "QUALIFICATION_TAXONOMY_CLASSIFICATION",
            "measurementPath": "measurement.json",
            "measurementSha256": handoff_validator.sha256(measurement_blob),
            "measurementDigest": "sha256:" + ("4" * 64),
            "schemaRef": (
                "contracts/directpath-qualification-measurement.schema.json"
            ),
            "schemaSha256": measurement_schema_sha,
            "valueProjection": "/measuredValue",
            "observedAt": "2026-07-22T00:00:01.000000Z",
            "hostId": "host-001",
            "hostEpoch": 1,
            "bootId": "boot-001",
            "deviceUid": device_uid,
            "deviceRecordHash": device_record_hash,
        }
        subject = {
            "qualificationRunId": "run-001",
            "hostId": "host-001",
            "hostEpoch": 1,
            "bootId": "boot-001",
            "deviceUid": device_uid,
            "deviceRecordHash": device_record_hash,
            "inventorySnapshotDigest": "sha256:" + ("3" * 64),
            "deviceArchetype": "GENERIC_PCI",
            "measurementSources": [source],
            "scenarioExecutionCoreDigests": [],
            "caseIds": [],
            "issuedAt": "2026-07-22T00:00:02.000000Z",
        }

        class FakeEvidenceGit:
            def blob(
                self, path: Any, _label: str, _errors: list[str]
            ) -> bytes | None:
                return {
                    "measurement.json": measurement_blob,
                    "classification.json": classification_blob,
                }.get(path)

        run = {
            "qualificationRunId": "run-001",
            "hostId": "host-001",
            "hostEpoch": 1,
            "bootId": "boot-001",
            "deviceUid": device_uid,
            "deviceRecordHash": device_record_hash,
        }
        bundle = {
            "subject": subject,
            "subjectBlob": handoff_validator.canonical_json_bytes(subject),
            "index": {},
            "artifacts": {},
            "blobs": {},
        }
        errors: list[str] = []
        with (
            mock.patch.object(
                handoff_validator,
                "_validate_qualification_run_manifest",
                return_value=run,
            ),
            mock.patch.object(
                handoff_validator,
                "_verify_signed_envelope",
            ),
            mock.patch.object(
                handoff_validator,
                "_verify_history_signed_envelope",
            ),
            mock.patch.object(
                handoff_validator,
                "_validate_device_classification_record",
            ) as classification_validator,
        ):
            handoff_validator._validate_qualification_subject_manifest(
                {},
                [bundle],
                None,
                None,
                ROOT,
                None,
                FakeEvidenceGit(),
                None,
                "qualification",
                errors,
            )
        classification_validator.assert_called_once()
        call = classification_validator.call_args
        self.assertEqual("GENERIC_PCI", call.kwargs["measured_archetype"])
        self.assertEqual(run, call.kwargs["run"])

    def test_signed_artifact_replay_is_hook_only_and_fails_closed(self) -> None:
        source = inspect.getsource(
            handoff_validator._execute_signed_artifact_replay
        )
        self.assertNotIn("subprocess", source)

        errors: list[str] = []
        handoff_validator.configure_signed_artifact_replay_hook(None)
        handoff_validator._execute_signed_artifact_replay(
            consumer_kind="WORKLOAD_EVALUATOR",
            consumer_protocol="QMAN-TEST/V1",
            consumer_artifact_digest="sha256:" + ("1" * 64),
            consumer_manifest_descriptor={
                "path": "evidence/evaluator.json",
                "sha256": "sha256:" + ("2" * 64),
                "byteLength": 1,
            },
            interface_contract_digest="sha256:" + ("3" * 64),
            target_repository_commit="4" * 40,
            mapping_core_id="QMAN-DIRECTPATH-MAPPING-CORE-TEST",
            portable_contract_sha256="sha256:" + ("5" * 64),
            target_architecture="x86_64",
            runtime_identity={},
            closure=[],
            inputs=[],
            evidence_root_artifacts=[],
            semantic_argv_order=["output"],
            output_role="output",
            output_schema_ref=(
                "contracts/directpath-qualification-workload-result.schema.json"
            ),
            output_schema_sha256="sha256:" + ("6" * 64),
            expected_output={},
            root=ROOT,
            label="replay",
            errors=errors,
        )
        self.assertTrue(
            any("requires a configured trusted" in item for item in errors),
            errors,
        )

    def test_signed_artifact_replay_detects_raw_byte_mutation(self) -> None:
        original_bytes = b"before"

        def mutating_hook(request: dict[str, Any]) -> dict[str, Any]:
            request["closure"][0]["bytes"] = b"after!"
            return {}

        errors: list[str] = []
        handoff_validator.configure_signed_artifact_replay_hook(mutating_hook)
        try:
            handoff_validator._execute_signed_artifact_replay(
                consumer_kind="TAXONOMY_CLASSIFIER",
                consumer_protocol="QMAN-TEST/V1",
                consumer_artifact_digest="sha256:" + ("1" * 64),
                consumer_manifest_descriptor={
                    "path": "evidence/classifier.json",
                    "sha256": "sha256:" + ("2" * 64),
                    "byteLength": 1,
                },
                interface_contract_digest="sha256:" + ("3" * 64),
                target_repository_commit="4" * 40,
                mapping_core_id="QMAN-DIRECTPATH-MAPPING-CORE-TEST",
                portable_contract_sha256="sha256:" + ("5" * 64),
                target_architecture="x86_64",
                runtime_identity={},
                closure=[
                    {
                        "role": "TAXONOMY_CLASSIFIER_BINARY",
                        "repository": "TARGET",
                        "path": "bin/classifier",
                        "sha256": handoff_validator.sha256(original_bytes),
                        "byteLength": len(original_bytes),
                        "mediaType": "application/octet-stream",
                        "modeOrNull": "100755",
                        "readOnly": True,
                        "bytes": original_bytes,
                    }
                ],
                inputs=[],
                evidence_root_artifacts=[],
                semantic_argv_order=["output"],
                output_role="output",
                output_schema_ref=(
                    "contracts/directpath-device-classification-record.schema.json"
                ),
                output_schema_sha256="sha256:" + ("6" * 64),
                expected_output={},
                root=ROOT,
                label="replay",
                errors=errors,
            )
        finally:
            handoff_validator.configure_signed_artifact_replay_hook(None)
        self.assertIn("replay: replay hook mutated the bound request", errors)

    def test_signed_artifact_replay_does_not_invoke_hook_after_preflight_error(self) -> None:
        hook_calls = 0

        def forbidden_hook(_request: dict[str, Any]) -> dict[str, Any]:
            nonlocal hook_calls
            hook_calls += 1
            return {}

        original_bytes = b"classifier"
        errors: list[str] = []
        handoff_validator.configure_signed_artifact_replay_hook(forbidden_hook)
        try:
            handoff_validator._execute_signed_artifact_replay(
                consumer_kind="TAXONOMY_CLASSIFIER",
                consumer_protocol="QMAN-TEST/V1",
                consumer_artifact_digest="sha256:" + ("1" * 64),
                consumer_manifest_descriptor={
                    "path": "evidence/classifier.json",
                    "sha256": "sha256:" + ("2" * 64),
                    "byteLength": 1,
                },
                interface_contract_digest="sha256:" + ("3" * 64),
                target_repository_commit="4" * 40,
                mapping_core_id="QMAN-DIRECTPATH-MAPPING-CORE-TEST",
                portable_contract_sha256="sha256:" + ("5" * 64),
                target_architecture="x86_64",
                runtime_identity={},
                closure=[
                    {
                        "role": "TAXONOMY_CLASSIFIER_BINARY",
                        "repository": "TARGET",
                        "path": "bin/classifier",
                        "sha256": "sha256:" + ("0" * 64),
                        "byteLength": len(original_bytes),
                        "mediaType": "application/octet-stream",
                        "modeOrNull": "100755",
                        "readOnly": True,
                        "bytes": original_bytes,
                    }
                ],
                inputs=[],
                evidence_root_artifacts=[],
                semantic_argv_order=["output"],
                output_role="output",
                output_schema_ref=(
                    "contracts/directpath-device-classification-record.schema.json"
                ),
                output_schema_sha256="sha256:" + ("6" * 64),
                expected_output={},
                root=ROOT,
                label="replay",
                errors=errors,
            )
        finally:
            handoff_validator.configure_signed_artifact_replay_hook(None)
        self.assertEqual(0, hook_calls)
        self.assertTrue(
            any("preflight is invalid" in item for item in errors), errors
        )

    def test_signed_artifact_replay_rejects_boolean_exit_code(self) -> None:
        def boolean_exit_hook(request: dict[str, Any]) -> dict[str, Any]:
            output = b"{}"
            return {
                "protocol": request["protocol"],
                "requestDigest": request["requestDigest"],
                "consumerKind": request["consumerKind"],
                "targetArchitecture": request["targetArchitecture"],
                "exitCode": False,
                "outputBytes": output,
                "outputSha256": handoff_validator.sha256(output),
                "attestation": {},
            }

        errors: list[str] = []
        handoff_validator.configure_signed_artifact_replay_hook(boolean_exit_hook)
        try:
            handoff_validator._execute_signed_artifact_replay(
                consumer_kind="WORKLOAD_EVALUATOR",
                consumer_protocol="QMAN-TEST/V1",
                consumer_artifact_digest="sha256:" + ("1" * 64),
                consumer_manifest_descriptor={
                    "path": "evidence/evaluator.json",
                    "sha256": "sha256:" + ("2" * 64),
                    "byteLength": 1,
                },
                interface_contract_digest="sha256:" + ("3" * 64),
                target_repository_commit="4" * 40,
                mapping_core_id="QMAN-DIRECTPATH-MAPPING-CORE-TEST",
                portable_contract_sha256="sha256:" + ("5" * 64),
                target_architecture="x86_64",
                runtime_identity={},
                closure=[],
                inputs=[],
                evidence_root_artifacts=[],
                semantic_argv_order=["output"],
                output_role="output",
                output_schema_ref=(
                    "contracts/directpath-qualification-workload-result.schema.json"
                ),
                output_schema_sha256="sha256:" + ("6" * 64),
                expected_output={},
                root=ROOT,
                label="replay",
                errors=errors,
            )
        finally:
            handoff_validator.configure_signed_artifact_replay_hook(None)
        self.assertTrue(
            any("expected integer deterministic exit 0" in item for item in errors),
            errors,
        )

    def test_signed_artifact_replay_accepts_fully_bound_attested_response(self) -> None:
        expected_output = json.loads(
            self.identity_schema["x-qmanGoldenVectors"][0]["canonicalUtf8"]
        )

        def valid_hook(request: dict[str, Any]) -> dict[str, Any]:
            output = handoff_validator.canonical_json_bytes(expected_output)
            output_sha = handoff_validator.sha256(output)
            attestation_bytes = b"verified-isolation-attestation"
            attestation = {
                "protocol": (
                    handoff_validator._SIGNED_ARTIFACT_ATTESTATION_PROTOCOL
                ),
                "runnerId": "trusted-runner-001",
                "requestDigest": request["requestDigest"],
                "consumerKind": request["consumerKind"],
                "targetArchitecture": request["targetArchitecture"],
                "targetRepositoryCommit": request["targetRepositoryCommit"],
                "mappingCoreId": request["mappingCoreId"],
                "portableContractSha256": request["portableContractSha256"],
                "consumerArtifactDigest": request["consumerArtifact"][
                    "internalDigest"
                ],
                "interfaceContractDigest": request[
                    "interfaceContractDigest"
                ],
                "closureDigest": request["closureDigest"],
                "inputSetDigest": request["inputSetDigest"],
                "evidenceRootArtifactSetDigest": request[
                    "evidenceRootArtifactSetDigest"
                ],
                "outputContractDigest": request["outputContractDigest"],
                "isolationPolicyDigest": request["isolationPolicyDigest"],
                "enforcedPolicy": copy.deepcopy(request["isolationPolicy"]),
                "exitCode": 0,
                "outputSha256": output_sha,
                "attestationBytes": attestation_bytes,
                "attestationSha256": handoff_validator.sha256(
                    attestation_bytes
                ),
            }
            return {
                "protocol": request["protocol"],
                "requestDigest": request["requestDigest"],
                "consumerKind": request["consumerKind"],
                "targetArchitecture": request["targetArchitecture"],
                "exitCode": 0,
                "outputBytes": output,
                "outputSha256": output_sha,
                "attestation": attestation,
            }

        errors: list[str] = []
        handoff_validator.configure_signed_artifact_replay_hook(valid_hook)
        try:
            handoff_validator._execute_signed_artifact_replay(
                consumer_kind="TAXONOMY_CLASSIFIER",
                consumer_protocol="QMAN-TEST/V1",
                consumer_artifact_digest="sha256:" + ("1" * 64),
                consumer_manifest_descriptor={
                    "path": "evidence/classifier.json",
                    "sha256": "sha256:" + ("2" * 64),
                    "byteLength": 1,
                },
                interface_contract_digest="sha256:" + ("3" * 64),
                target_repository_commit="4" * 40,
                mapping_core_id="QMAN-DIRECTPATH-MAPPING-CORE-TEST",
                portable_contract_sha256="sha256:" + ("5" * 64),
                target_architecture="x86_64",
                runtime_identity={},
                closure=[],
                inputs=[],
                evidence_root_artifacts=[],
                semantic_argv_order=["output"],
                output_role="output",
                output_schema_ref="contracts/directpath-identity-v1.schema.json",
                output_schema_sha256=handoff_validator.sha256(
                    (ROOT / "contracts/directpath-identity-v1.schema.json").read_bytes()
                ),
                expected_output=expected_output,
                root=ROOT,
                label="replay",
                errors=errors,
            )
        finally:
            handoff_validator.configure_signed_artifact_replay_hook(None)
        self.assertEqual([], errors)

    def test_state_machines_cas_and_reasons_are_closed_and_cross_referenced(self) -> None:
        operations = unique(item["id"] for item in self.contract["backendNeutralOperations"])
        entities = unique(item["id"] for item in self.contract["dataEntities"])
        cas_rules = unique(item["id"] for item in self.contract["casRules"])
        reasons = unique(item["code"] for item in self.contract["errorContract"]["reasonCodes"])

        reason_references: set[str] = set()
        for operation in self.contract["backendNeutralOperations"]:
            reason_references.update(operation["failureReasonCodes"])
        transition_ids: list[str] = []
        for machine in self.contract["stateMachines"]:
            self.assertIn(machine["entityId"], entities)
            states = set(machine["states"])
            self.assertIn(machine["initialState"], states)
            self.assertTrue(set(machine["terminalStates"]).issubset(states))
            self.assertTrue(machine["commitRule"])
            for transition in machine["transitions"]:
                transition_ids.append(transition["id"])
                if not transition["from"].startswith("ANY_"):
                    self.assertIn(transition["from"], states)
                self.assertIn(transition["to"], states)
                self.assertTrue(set(transition["operationIds"]).issubset(operations))
                self.assertTrue(set(transition["casRuleIds"]).issubset(cas_rules))
                reason_references.update(transition["failureReasonCodes"])
        unique(transition_ids)

        for rule in self.contract["casRules"]:
            self.assertIn(rule["conflictReasonCode"], reasons)
            reason_references.add(rule["conflictReasonCode"])
            self.assertTrue(rule["invariant"])
        self.assertTrue(reason_references.issubset(reasons))

        retryable = {
            item["code"]
            for item in self.contract["errorContract"]["reasonCodes"]
            if item["retryable"]
        }
        self.assertEqual(
            {
                "INVENTORY_EPOCH_CHANGED",
                "STALE_RESOURCE_VERSION",
                "STALE_CONTROLLER_GENERATION",
                "DEPENDENCY_BUSY",
            },
            retryable,
        )

    def test_cold_relocation_fsm_requires_source_clean_release_before_target(self) -> None:
        machine = next(
            item
            for item in self.contract["stateMachines"]
            if item["id"] == "FSM-COLD-RELOCATION"
        )
        guarded_stop = next(
            item
            for item in machine["transitions"]
            if item["id"] == "TR-RELOCATE-SOURCE-STOP-RELEASING"
        )
        self.assertIn("OP-ACQUIRE-RELEASE-OWNERSHIP-GUARD", guarded_stop["operationIds"])
        self.assertIn("CAS-RELEASE-GUARD", guarded_stop["casRuleIds"])

        transition = next(
            item
            for item in machine["transitions"]
            if item["id"] == "TR-RELOCATE-SOURCE-RELEASING-TARGET-SOLVE"
        )
        self.assertIn("OP-PROVE-CLEAN-RELEASE", transition["operationIds"])
        self.assertIn("OP-CAS-REVOKE-LEASE", transition["operationIds"])
        self.assertIn("CAS-RELEASE-GUARD", transition["casRuleIds"])
        self.assertIn("CAS-CLEAN-RELEASE", transition["casRuleIds"])
        self.assertIn("CAS-RELOCATION-HANDOFF", transition["casRuleIds"])
        self.assertIn("receipt", " ".join(transition["guards"]).lower())
        self.assertIn("HOST_UNREACHABLE", machine["states"])
        self.assertIn("STOPPED_UNSAT", machine["states"])
        retry = next(
            item
            for item in machine["transitions"]
            if item["id"] == "TR-RELOCATE-STOPPED-UNSAT-TARGET-SOLVE"
        )
        self.assertIn("CAS-RELOCATION-HANDOFF", retry["casRuleIds"])
        self.assertNotIn("STOPPED_UNSAT", machine["terminalStates"])
        self.assertIn("TARGET_SOLVE is unreachable", machine["commitRule"])

        receipt = next(
            item
            for item in self.contract["dataEntities"]
            if item["id"] == "ENTITY-CLEAN-RELEASE-RECEIPT"
        )
        for required in (
            "receiptNonce",
            "sourceHostEpoch",
            "leaseSetHash",
            "leaseBindings",
            "bundleMembers",
            "qemuExitProof",
            "dmaIrqTeardownProof",
            "iommuInvalidateProof",
            "resetStateProof",
            "ownerRestoreProof",
            "evidenceHash",
            "signerKeyId",
            "signature",
        ):
            self.assertIn(required, receipt["requiredFields"])

    def test_all_case_and_tech_story_references_exist(self) -> None:
        referenced_cases: set[str] = set()
        referenced_stories: set[str] = set()
        for port in self.contract["requiredPorts"]:
            referenced_cases.update(port["caseIds"])
            referenced_stories.update(port["techStoryIds"])
        for obligation in self.contract["acceptanceObligations"]:
            referenced_cases.update(obligation["caseIds"])
            referenced_stories.update(obligation["techStoryIds"])
            self.assertTrue(obligation["evidenceMinimum"])
        self.assertTrue(referenced_cases)
        self.assertTrue(referenced_stories)
        self.assertEqual(self.case_ids, referenced_cases)
        self.assertEqual(self.tech_story_ids, referenced_stories)

    def test_vmware_core_parity_is_exact_and_bound_to_ports_and_tests(self) -> None:
        vmware = {
            item["id"]: (item["classification"], item["requiredQmanMeaning"])
            for item in self.vmware["coreParity"]
        }
        portable = {
            item["id"]: (item["classification"], item["portableRequirement"])
            for item in self.contract["vmwareParityObligations"]
        }
        self.assertEqual(vmware, portable)

        port_ids = {item["id"] for item in self.contract["requiredPorts"]}
        test_ids = {item["id"] for item in self.contract["acceptanceObligations"]}
        for item in self.contract["vmwareParityObligations"]:
            self.assertTrue(item["implementationPortIds"])
            self.assertTrue(item["testObligationIds"])
            self.assertTrue(set(item["implementationPortIds"]).issubset(port_ids))
            self.assertTrue(set(item["testObligationIds"]).issubset(test_ids))
        classifications = {
            item["classification"] for item in self.contract["vmwareParityObligations"]
        }
        self.assertEqual(
            {"MUST_MATCH", "ACCEPTABLE_DIFFERENCE", "OUT_OF_SCOPE"}, classifications
        )

    def test_configuration_migration_and_telemetry_are_fail_closed(self) -> None:
        settings = {
            item["id"]: item for item in self.contract["configurationContract"]["settings"]
        }
        self.assertEqual("REJECT", settings["CONFIG-VFIO-NOIOMMU"]["requiredValue"])
        self.assertFalse(settings["CONFIG-BACKEND-SILENT-FALLBACK"]["requiredValue"])
        self.assertEqual("DENY", settings["CONFIG-UNMANAGED-ATTACH"]["requiredValue"])
        self.assertEqual(
            "DUAL_ONLINE_COOPERATIVE_ONLY",
            settings["CONFIG-COLD-RELOCATION-MODE"]["requiredValue"],
        )

        migration_ids = [item["id"] for item in self.contract["migrationContract"]["steps"]]
        self.assertEqual(
            [
                "MIGRATION-01-ADD-DURABLE-SCHEMA",
                "MIGRATION-02-BACKFILL-UNKNOWN",
                "MIGRATION-03-SHADOW-EVALUATION",
                "MIGRATION-04-ENABLE-STATIC",
                "MIGRATION-05-ENABLE-MANAGED-OWNER",
                "MIGRATION-06-ENABLE-DYNAMIC-AND-RELOCATION",
                "MIGRATION-07-IOMMUFD-CDEV-FUTURE",
            ],
            migration_ids,
        )
        for migration in self.contract["migrationContract"]["steps"]:
            self.assertTrue(migration["preconditions"])
            self.assertTrue(migration["verification"])
            self.assertTrue(migration["rollback"])

        forbidden_metric_labels = {
            "deviceUid",
            "bdf",
            "assignmentId",
            "runId",
            "leaseId",
            "evidenceHash",
            "device",
            "assignment",
            "bundle",
        }
        metrics = self.contract["telemetryContract"]["metrics"]
        unique(item["id"] for item in metrics)
        unique(item["name"] for item in metrics)
        for metric in metrics:
            self.assertEqual(set(), set(metric["labels"]) & forbidden_metric_labels)

    def test_authoritative_mapping_count_narratives_match_machine_contracts(self) -> None:
        mapping_count = len(self.mapping_template["mappings"])
        verification_count = len(
            self.contract["mappingSurface"]["verificationMatrix"]
        )
        portable_status = self.project_status["observations"][
            "portableImplementationContract"
        ]

        self.assertEqual(mapping_count, len(derive_mapping_items(self.contract)))
        self.assertEqual(mapping_count, verification_count)
        self.assertEqual(mapping_count, portable_status["mappingItems"])
        self.assertEqual(
            verification_count, portable_status["verificationMatrixRows"]
        )

        narrative_claims = {
            "README.md": [
                r"signed qualification/catalog trust, and "
                r"(?P<mapping>\d+) ordered mapping requirements",
            ],
            "contracts/README.md": [
                r"`mappingSurface` 当前确定性导出 (?P<mapping>\d+) 个 item",
                r"normative closure、(?P<mapping>\d+) 项 mapping/verification matrix",
            ],
            "handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md": [
                r"portable contract 当前导出 \*\*"
                r"(?P<mapping>\d+) 个有序 mapping item\*\*",
                r"(?P<mapping>\d+) 个 mapping item 与 "
                r"(?P<verification>\d+) 条 verification requirement",
            ],
            "qemu-static-dynamic-directpath-design.md": [
                r"确定性导出 (?P<mapping>\d+) 个\s+mapping item",
            ],
        }
        expected_counts = {
            "mapping": mapping_count,
            "verification": verification_count,
        }
        for relative_path, patterns in narrative_claims.items():
            narrative = (ROOT / relative_path).read_text(encoding="utf-8")
            for pattern in patterns:
                match = re.search(pattern, narrative)
                self.assertIsNotNone(
                    match, f"{relative_path} is missing mapping count claim: {pattern}"
                )
                assert match is not None
                for count_kind, declared_count in match.groupdict().items():
                    self.assertEqual(
                        expected_counts[count_kind],
                        int(declared_count),
                        f"{relative_path} has a stale {count_kind} count",
                    )

    def test_mapping_template_covers_every_surface_item_exactly_and_starts_empty(self) -> None:
        expected_derivation = [
            ("CANONICALIZATION", "canonicalizationContract.profiles[*].id"),
            ("GUARD", "safetyGuards[*].id"),
            ("EQUIVALENCE", "dynamicCandidateEquivalence.id"),
            ("PORT", "requiredPorts[*].id"),
            ("ENTITY", "dataEntities[*].id"),
            ("OPERATION", "backendNeutralOperations[*].id"),
            ("STATE_MACHINE", "stateMachines[*].id"),
            ("TRANSITION", "stateMachines[*].transitions[*].id"),
            ("CAS_RULE", "casRules[*].id"),
            ("REASON", "errorContract.reasonCodes[*].code"),
            ("CONFIG", "configurationContract.settings[*].id"),
            ("MIGRATION", "migrationContract.steps[*].id"),
            ("TELEMETRY", "telemetryContract.metrics[*].id"),
            ("TEST", "acceptanceObligations[*].id"),
            ("PARITY_OBLIGATION", "vmwareParityObligations[*].id"),
        ]
        self.assertEqual(
            expected_derivation,
            [
                (item["kind"], item["source"])
                for item in self.contract["mappingSurface"]["derivation"]
            ],
        )

        expected = derive_mapping_items(self.contract)
        actual = [
            (item["kind"], item["contractItemId"])
            for item in self.mapping_template["mappings"]
        ]
        self.assertEqual(expected, actual)
        self.assertEqual(299, len(actual))
        self.assertEqual(len(actual), len(set(actual)))
        verification_matrix = self.contract["mappingSurface"]["verificationMatrix"]
        self.assertEqual(1, self.contract["mappingSurface"]["verificationMatrixVersion"])
        self.assertEqual(299, len(verification_matrix))
        self.assertEqual(
            actual,
            [(row["kind"], row["contractItemId"]) for row in verification_matrix],
        )
        required_oracles = {
            "authoritativeWrites",
            "cleanup",
            "finalStates",
            "idempotencyOracle",
            "immediateResults",
            "mustNotOccur",
            "mustOccur",
            "physicalOracle",
        }
        for index, (row, mapping) in enumerate(
            zip(verification_matrix, self.mapping_template["mappings"])
        ):
            projection = dict(row)
            declared_digest = projection.pop("requirementDigest")
            self.assertEqual(
                canonical_digest(projection), declared_digest, f"matrix row {index}"
            )
            self.assertEqual(
                declared_digest,
                mapping["verificationRequirementDigest"],
                f"mapping row {index}",
            )
            self.assertTrue(row["requiredTestObligationIds"])
            self.assertTrue(row["requiredCaseIds"])
            self.assertEqual(
                required_oracles, set(row["requiredOracleClasses"]), f"row {index}"
            )
            for field in (
                "requiredTestObligationIds",
                "requiredCaseIds",
                "requiredOracleClasses",
            ):
                self.assertEqual(
                    len(row[field]), len(set(row[field])), f"{field} row {index}"
                )
        for item in self.mapping_template["mappings"]:
            if item["releaseTrack"] == "FUTURE_SEPARATELY_QUALIFIED":
                self.assertEqual("DEFERRED", item["mappingStatus"])
                self.assertEqual("DEFERRED", item["disposition"])
                self.assertEqual(
                    "NOT_APPLICABLE_CURRENT_RELEASE", item["implementationStatus"]
                )
                self.assertIsNotNone(item["deferDecision"])
            else:
                self.assertEqual("UNMAPPED", item["mappingStatus"])
                self.assertEqual("UNMAPPED", item["disposition"])
                self.assertEqual("NOT_STARTED", item["implementationStatus"])
                self.assertIsNone(item["deferDecision"])
            self.assertEqual([], item["targetBindings"])
            self.assertEqual([], item["targetTestBindings"])
            self.assertIsNone(item["conflict"])

        source = self.mapping_template["sourceContract"]
        self.assertEqual(self.contract["contractId"], source["contractId"])
        self.assertEqual(self.contract["revision"], source["revision"])
        self.assertIsNone(source["sha256"])

        schema_mappings = self.mapping_schema["properties"]["mappings"]
        self.assertEqual(299, schema_mappings["minItems"])
        self.assertEqual(299, schema_mappings["maxItems"])
        self.assertEqual(299, len(schema_mappings["prefixItems"]))
        for index, prefix in enumerate(schema_mappings["prefixItems"]):
            constants = prefix["allOf"][1]["properties"]
            row = verification_matrix[index]
            self.assertEqual(row["kind"], constants["kind"]["const"])
            self.assertEqual(
                row["contractItemId"], constants["contractItemId"]["const"]
            )
            self.assertEqual(
                row["requirementDigest"],
                constants["verificationRequirementDigest"]["const"],
            )

    def test_explicit_case_trace_is_overlaid_on_verification_matrix(self) -> None:
        registry = load("contracts/directpath-acceptance-case-contracts.json")
        rows = {
            (row["kind"], row["contractItemId"]): row
            for row in self.contract["mappingSurface"]["verificationMatrix"]
        }
        field_kinds = {
            "requiredPortIds": "PORT",
            "requiredOperationIds": "OPERATION",
            "requiredTransitionIds": "TRANSITION",
            "requiredEntityIds": "ENTITY",
            "requiredReasonIds": "REASON",
        }
        explicit_case_ids = {"C10", "C15", "C20"}
        records = {
            record["caseId"]: record
            for record in registry["records"]
            if record["caseId"] in explicit_case_ids
        }
        self.assertEqual(explicit_case_ids, set(records))
        for case_id, record in records.items():
            for field, kind in field_kinds.items():
                for item_id in record[field]:
                    row = rows[(kind, item_id)]
                    self.assertIn(
                        case_id,
                        row["requiredCaseIds"],
                        f"{case_id}.{field} missing from {kind}/{item_id}",
                    )
        self.assertIn(
            "source Case",
            self.contract["mappingSurface"]["verificationMatrixRule"],
        )
        self.assertIn(
            "never the generated Case registry",
            self.contract["mappingSurface"]["verificationMatrixRule"],
        )

    def test_persisted_entity_wire_schemas_are_closed_and_exact(self) -> None:
        authority_ids = {
            "ENTITY-CONTROLLER-AUTHORITY",
            "ENTITY-HOST-AUTHORITY",
            "ENTITY-CAPABILITY-POLICY-AUTHORITY",
            "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY",
            "ENTITY-AVAILABILITY-AUTHORITY",
            "ENTITY-OWNER-ACTIVATION-RUN",
            "ENTITY-ASSIGNMENT-RUN",
            "ENTITY-ASSIGNMENT-BINDING",
            "ENTITY-BUNDLE-LEASE",
            "ENTITY-HOST-ACTION-JOURNAL",
            "ENTITY-RESERVATION-CANCEL-RECEIPT",
            "ENTITY-QUARANTINE-RECORD",
            "ENTITY-REMEDIATION-RUN",
            "ENTITY-RELOCATION-RUN",
            "ENTITY-IDEMPOTENCY-RECORD",
            "ENTITY-OPERATION-LEASE",
            "ENTITY-RELEASE-OWNERSHIP-GUARD",
            "ENTITY-CLEAN-RELEASE-ACCEPTANCE",
            "ENTITY-AUDIT-EVENT",
            "ENTITY-OUTBOX-EVENT",
        }
        portable_ids = {
            "ENTITY-DEVICE-RECORD",
            "ENTITY-QUALIFICATION-PROFILE",
            "ENTITY-VM-DIRECTPATH-REQUEST",
            "ENTITY-DEPENDENCY-BUNDLE",
        }
        authority_defs = {
            key
            for key in self.authority_entity_schema["$defs"]
            if key.startswith("ENTITY-")
        }
        portable_defs = {
            key
            for key in self.portable_entity_schema["$defs"]
            if key.startswith("ENTITY-")
        }
        self.assertEqual(authority_ids, authority_defs)
        self.assertEqual(portable_ids, portable_defs)
        self.assertEqual(
            sorted(f"#/$defs/{item}" for item in authority_ids),
            sorted(branch["$ref"] for branch in self.authority_entity_schema["oneOf"]),
        )
        self.assertEqual(
            sorted(f"#/$defs/{item}" for item in portable_ids),
            sorted(branch["$ref"] for branch in self.portable_entity_schema["oneOf"]),
        )

        entities = {item["id"]: item for item in self.contract["dataEntities"]}
        for entity_id, schema_path in (
            *[(item, "contracts/directpath-authority-entities.schema.json") for item in sorted(authority_ids)],
            *[(item, "contracts/directpath-portable-entities.schema.json") for item in sorted(portable_ids)],
        ):
            entity = entities[entity_id]
            expected_ref = f"{schema_path}#/$defs/{entity_id}"
            self.assertEqual(expected_ref, entity["wireSchema"])
            node, resolved_path = resolve_schema_ref(expected_ref)
            required, properties, closed = effective_object_shape(node, resolved_path)
            contract_fields = set(entity["key"]) | set(entity["requiredFields"])
            self.assertTrue(closed, entity_id)
            self.assertEqual(contract_fields, required, entity_id)
            self.assertEqual(contract_fields, properties, entity_id)

        mutated = copy.deepcopy(self.contract)
        controller = next(
            item
            for item in mutated["dataEntities"]
            if item["id"] == "ENTITY-CONTROLLER-AUTHORITY"
        )
        controller["requiredFields"].remove("controllerGeneration")
        errors: list[str] = []
        handoff_validator._validate_wire_schema_closure(mutated, ROOT, errors)
        self.assertTrue(
            any("ENTITY-CONTROLLER-AUTHORITY wire schema" in error for error in errors),
            errors,
        )

    def test_inventory_v3_closure_is_normative_and_version_consistent(self) -> None:
        normative_sources = set(self.contract["normativeSources"])
        required_sources = {
            "contracts/directpath-capability-policy.schema.json",
            "contracts/directpath-inventory-verification-receipt.schema.json",
            "contracts/directpath-inventory-verifier-algorithm.schema.json",
            "contracts/directpath-dependency-closure-request.schema.json",
            "contracts/directpath-reset-contract-set.schema.json",
            "tools/generate_directpath_portable_package.py",
        }
        self.assertTrue(
            required_sources.issubset(normative_sources),
            required_sources - normative_sources,
        )

        subjects = {
            item["subject"]: item
            for item in self.contract["canonicalizationContract"]["hashSubjects"]
        }
        expected_subjects = {
            "DeviceRecord": (
                "deviceRecordHash",
                "contracts/directpath-portable-entities.schema.json"
                "#/$defs/ENTITY-DEVICE-RECORD",
            ),
            "InventoryVerifierAlgorithmIdentity": (
                "algorithmIdentityDigest",
                "contracts/directpath-inventory-verifier-algorithm.schema.json",
            ),
            "InventoryVerificationReceipt": (
                "receiptDigest",
                "contracts/directpath-inventory-verification-receipt.schema.json",
            ),
            "CapabilityPolicy": (
                "policyHash",
                "contracts/directpath-capability-policy.schema.json",
            ),
            "DependencyClosureRequest": (
                "requestDigest (derived output)",
                "contracts/directpath-dependency-closure-request.schema.json",
            ),
            "ResetContractSet": (
                "contentHash (derived output)",
                "contracts/directpath-reset-contract-set.schema.json",
            ),
        }
        for subject, (digest_field, schema_ref) in expected_subjects.items():
            self.assertEqual(digest_field, subjects[subject]["digestField"])
            self.assertEqual(schema_ref, subjects[subject]["schemaRef"])

        device_record = self.portable_entity_schema["$defs"]["ENTITY-DEVICE-RECORD"]
        self.assertEqual(3, device_record["properties"]["schemaVersion"]["const"])
        self.assertIn("dependencyDomains", device_record["required"])
        device_role = self.portable_entity_schema["$defs"]["deviceRole"]
        self.assertIn("pciStructureFact", device_role["required"])
        self.assertEqual(
            "#/$defs/pciStructureFact",
            device_role["properties"]["pciStructureFact"]["$ref"],
        )
        self.assertIs(
            False,
            self.portable_entity_schema["$defs"]["pciStructureFact"][
                "additionalProperties"
            ],
        )
        reset_contract = self.portable_entity_schema["$defs"]["resetContract"]
        self.assertIn("pciFlrCapabilityFact", reset_contract["required"])
        self.assertIn("resetProviderFactId", reset_contract["required"])
        self.assertIn("state", reset_contract["required"])
        self.assertEqual(
            ["KNOWN", "UNKNOWN", "CONFLICT"],
            reset_contract["properties"]["state"]["enum"],
        )
        self.assertEqual(
            "#/$defs/pciFlrCapabilityFact",
            reset_contract["properties"]["pciFlrCapabilityFact"]["$ref"],
        )
        self.assertIs(
            False,
            self.portable_entity_schema["$defs"]["pciFlrCapabilityFact"][
                "additionalProperties"
            ],
        )
        domains = self.portable_entity_schema["$defs"]["dependencyDomains"]
        self.assertEqual(7, domains["minItems"])
        self.assertEqual(7, domains["maxItems"])
        self.assertIs(False, domains["items"])
        self.assertEqual(
            [
                "FUNCTIONAL",
                "IOMMU",
                "MULTIFUNCTION",
                "PF_VF",
                "PHYSICAL_ISOLATION",
                "PLATFORM",
                "REQUESTER_ALIAS",
            ],
            [
                next(
                    branch["properties"]["kind"]["const"]
                    for branch in item["allOf"]
                    if "properties" in branch
                )
                for item in domains["prefixItems"]
            ],
        )

        entity = next(
            item
            for item in self.contract["dataEntities"]
            if item["id"] == "ENTITY-DEVICE-RECORD"
        )
        self.assertEqual(
            set(device_record["required"]),
            set(entity["key"]) | set(entity["requiredFields"]),
        )

        snapshot_schema = load(
            "contracts/directpath-portable-hash-subjects.schema.json"
        )
        receipt_schema = load(
            "contracts/directpath-inventory-verification-receipt.schema.json"
        )
        algorithm_schema = load(
            "contracts/directpath-inventory-verifier-algorithm.schema.json"
        )
        self.assertEqual(2, algorithm_schema["properties"]["schemaVersion"]["const"])
        self.assertEqual(
            "PORTABLE_INVENTORY_VERIFIER_ALGORITHM_V2",
            algorithm_schema["properties"]["algorithmId"]["const"],
        )
        self.assertEqual(
            "QMAN-DIRECTPATH/INVENTORY-VERIFIER-ALGORITHM/V2",
            algorithm_schema["properties"]["verifierIdentityHashDomain"]["const"],
        )
        schema_bindings = algorithm_schema["properties"]["schemaBindings"]
        self.assertEqual(7, schema_bindings["minItems"])
        self.assertEqual(7, schema_bindings["maxItems"])
        self.assertEqual(7, len(schema_bindings["prefixItems"]))
        validation_stages = [
            item["const"]
            for item in algorithm_schema["properties"]["validationStages"][
                "prefixItems"
            ]
        ]
        validation_stage_schema = algorithm_schema["properties"][
            "validationStages"
        ]
        self.assertEqual(
            validation_stage_schema["minItems"],
            validation_stage_schema["maxItems"],
        )
        self.assertEqual(
            validation_stage_schema["minItems"],
            len(validation_stages),
        )
        self.assertIn(
            "DEVICE_RECORD_V3_HASH_IDENTITY_MEMBERSHIP_V1",
            validation_stages,
        )
        self.assertIn("PCI_STRUCTURE_RESET_FACT_REPLAY_V1", validation_stages)
        self.assertIn(
            "DEVICE_PROVIDER_FACT_SET_DIGEST_REPLAY_V2",
            validation_stages,
        )
        self.assertIn(
            "HOST_SNAPSHOT_SEMANTIC_PROJECTION_REPLAY_V1",
            validation_stages,
        )
        self.assertIn(
            "PORTABLE_INVENTORY_VERIFIER_ALGORITHM_V2",
            receipt_schema["x-qmanVerifierIdentityRule"],
        )
        self.assertIn(
            "exactly seven",
            receipt_schema["x-qmanVerifierIdentityRule"],
        )
        self.assertIn("r+1", snapshot_schema["$defs"]["hostSnapshot"]["x-qmanCurrentPointerRule"])
        self.assertIn(
            "resourceVersion",
            " ".join(
                self.authority_entity_schema["$defs"]["ENTITY-HOST-AUTHORITY"][
                    "x-qmanCrossFieldRules"
                ]
            ),
        )
        self.assertIn(
            "committed",
            self.portable_entity_schema["$defs"]["hostSnapshotBinding"][
                "x-qmanCommittedVersionRule"
            ],
        )
        self.assertIn("committed", receipt_schema["x-qmanCurrentPointerRule"])

        mutated = copy.deepcopy(self.contract)
        mutated["normativeSources"].remove(
            "contracts/directpath-inventory-verification-receipt.schema.json"
        )
        errors: list[str] = []
        handoff_validator._validate_wire_schema_closure(mutated, ROOT, errors)
        self.assertTrue(
            any(
                "hash subject InventoryVerificationReceipt" in error
                and "absent from normativeSources" in error
                for error in errors
            ),
            errors,
        )

    def test_qualification_profile_projection_receipt_hash_chain_is_closed(self) -> None:
        normative_sources = set(self.contract["normativeSources"])
        self.assertTrue(
            {
                "contracts/directpath-qualification-profile-projection.schema.json",
                "contracts/directpath-qualification-verification-receipt.schema.json",
            }.issubset(normative_sources)
        )
        subjects = {
            item["subject"]: item
            for item in self.contract["canonicalizationContract"]["hashSubjects"]
        }
        self.assertEqual(
            {
                "schemaRef": (
                    "contracts/directpath-qualification-verification-receipt"
                    ".schema.json"
                ),
                "digestField": "receiptDigest",
            },
            {
                key: subjects["QualificationVerificationReceipt"][key]
                for key in ("schemaRef", "digestField")
            },
        )
        hash_subjects = load(
            "contracts/directpath-portable-hash-subjects.schema.json"
        )
        profile = hash_subjects["$defs"]["qualificationProfile"]
        projection = load(
            "contracts/directpath-qualification-profile-projection.schema.json"
        )
        receipt = load(
            "contracts/directpath-qualification-verification-receipt.schema.json"
        )
        supported_catalog = load(
            "contracts/directpath-supported-catalog.schema.json"
        )

        profile_fields = set(profile["required"])
        projection_fields = profile_fields - {
            "verificationReceiptHash",
            "profileHash",
        }
        self.assertFalse(projection["additionalProperties"])
        self.assertEqual(projection_fields, set(projection["required"]))
        self.assertEqual(projection_fields, set(projection["properties"]))
        self.assertEqual(projection_fields, set(projection["x-qmanFieldProjection"]))
        self.assertNotIn("projectionDigest", projection["properties"])
        self.assertNotIn("verificationReceiptHash", projection["properties"])
        self.assertNotIn("profileHash", projection["properties"])
        self.assertEqual(
            "QualificationRecord.exactQualificationKey",
            projection["x-qmanFieldProjection"]["profileId"],
        )
        semantic = projection["x-qmanProfileSemanticProjection"]
        self.assertEqual(
            "QMAN-DIRECTPATH/QUALIFICATION-PROFILE-SEMANTICS/V1",
            semantic["hashDomain"],
        )
        self.assertEqual(
            {
                "profileId",
                "platformProfileId",
                "platformDigest",
                "kernelDigest",
                "qemuDigest",
                "machineDigest",
                "firmwareDigest",
                "backendDigest",
                "deviceTraitsDigest",
                "guestAbiClass",
                "workloadDigest",
                "revocationSeverity",
                "revocationBehavior",
                "supportStatus",
            },
            set(semantic["includedProfileFields"]),
        )
        self.assertEqual(
            {
                "qualificationRecordDigests",
                "supportedCatalogDigest",
                "catalogSequence",
                "verificationReceiptHash",
                "profileHash",
            },
            set(semantic["excludedCurrentnessFields"]),
        )
        self.assertEqual(
            "SINGLETON_SET(QualificationRecord.recordDigest)",
            projection["x-qmanFieldProjection"]["qualificationRecordDigests"],
        )
        self.assertEqual(
            "SupportedCatalog.catalogDigest",
            projection["x-qmanFieldProjection"]["supportedCatalogDigest"],
        )
        self.assertEqual(
            "SupportedCatalog.catalogSequence",
            projection["x-qmanFieldProjection"]["catalogSequence"],
        )
        self.assertEqual(
            "SUPPORTED",
            projection["properties"]["supportStatus"]["const"],
        )
        self.assertEqual(
            {"NORMAL", "CRITICAL"},
            set(projection["properties"]["revocationSeverity"]["enum"]),
        )
        self.assertEqual(
            {
                "DENY_NEW_AND_NEXT_POWER_ON",
                "DENY_NEW_AND_REQUIRE_CONTROLLED_STOP",
            },
            set(projection["properties"]["revocationBehavior"]["enum"]),
        )
        self.assertEqual(
            set(projection["properties"]["revocationBehavior"]["enum"]),
            set(
                supported_catalog["properties"]["revocationBehavior"]["enum"]
            ),
        )
        self.assertEqual(
            "DERIVE_FROM(SupportedCatalog.revocationBehavior)",
            projection["x-qmanFieldProjection"]["revocationSeverity"],
        )
        severity_behavior_pairs = {
            (
                branch["if"]["properties"]["revocationSeverity"]["const"],
                branch["then"]["properties"]["revocationBehavior"]["const"],
            )
            for branch in projection["allOf"]
        }
        self.assertEqual(
            {
                ("NORMAL", "DENY_NEW_AND_NEXT_POWER_ON"),
                ("CRITICAL", "DENY_NEW_AND_REQUIRE_CONTROLLED_STOP"),
            },
            severity_behavior_pairs,
        )
        self.assertIn(
            "total bijection",
            projection["x-qmanRevocationProjectionRule"],
        )
        self.assertIn(
            "affects supportStatus only",
            projection["x-qmanRevocationProjectionRule"],
        )

        expected_derived_fields = {
            "machineDigest": [
                "QualificationRecord.kernelQemuFirmwareBackend.machineType",
                "QualificationRecord.kernelQemuFirmwareBackend.machineVersion",
            ],
            "firmwareDigest": [
                "QualificationRecord.deviceFirmwareAndRom",
                "QualificationRecord.kernelQemuFirmwareBackend.firmwareKind",
                "QualificationRecord.kernelQemuFirmwareBackend.firmwareCodeDigest",
                "QualificationRecord.kernelQemuFirmwareBackend.firmwareVarsBaseDigestOrNull",
            ],
            "backendDigest": [
                "QualificationRecord.kernelQemuFirmwareBackend.backendFamily",
                "QualificationRecord.kernelQemuFirmwareBackend.configuredIommuType",
                "QualificationRecord.kernelQemuFirmwareBackend.runtimeCapabilities",
                "QualificationRecord.iommuInterruptResetProviders",
            ],
            "deviceTraitsDigest": [
                "QualificationRecord.deviceTraits",
            ],
        }
        self.assertEqual(
            set(expected_derived_fields),
            set(projection["x-qmanDerivedDigestRules"]),
        )
        for field, source_fields in expected_derived_fields.items():
            rule = projection["x-qmanDerivedDigestRules"][field]
            self.assertEqual(source_fields, rule["projectionFields"], field)
            self.assertTrue(
                rule["domain"].startswith(
                    "QMAN-DIRECTPATH/QUALIFICATION-PROFILE-"
                ),
                field,
            )
        self.assertIn(
            "directpath-qualification-record.schema.json",
            projection["x-qmanSourceRule"],
        )
        self.assertIn(
            "directpath-supported-catalog.schema.json",
            projection["x-qmanSourceRule"],
        )
        self.assertIn(
            "ASCII(QMAN-DIRECTPATH/QUALIFICATION-PROFILE-PROJECTION/V1)",
            projection["x-qmanProjectionDigestRule"],
        )

        self.assertFalse(receipt["additionalProperties"])
        self.assertEqual(set(receipt["required"]), set(receipt["properties"]))
        self.assertNotIn("profileHash", receipt["properties"])
        self.assertNotIn("verificationReceiptHash", receipt["properties"])
        self.assertEqual(
            "PORTABLE_QUALIFICATION_PROFILE_VERIFIER_V1",
            receipt["properties"]["verifierAlgorithmId"]["const"],
        )
        schema_bindings = receipt["properties"]["schemaBindings"]
        self.assertEqual(10, schema_bindings["minItems"])
        self.assertEqual(10, schema_bindings["maxItems"])
        self.assertIs(False, schema_bindings["items"])
        self.assertEqual(
            [
                "contracts/directpath-qualification-profile-projection.schema.json",
                "contracts/directpath-qualification-verification-receipt.schema.json",
                "contracts/directpath-portable-hash-subjects.schema.json#/$defs/qualificationProfile",
                "contracts/directpath-qualification-record.schema.json",
                "contracts/directpath-supported-catalog.schema.json",
                "contracts/directpath-catalog-rollback-anchor.schema.json",
                "contracts/directpath-anchor-freshness-envelope.schema.json",
                "contracts/directpath-trust-root-set.schema.json",
                "contracts/directpath-trust-key-ring.schema.json",
                "contracts/directpath-trust-rollback-anchor.schema.json",
            ],
            [
                item["allOf"][1]["properties"]["schemaRef"]["const"]
                for item in schema_bindings["prefixItems"]
            ],
        )

        for definition_name in (
            "schemaBinding",
            "qualificationRecordBinding",
            "e4Closure",
            "catalogBinding",
            "catalogAnchorBinding",
            "catalogFreshnessBinding",
            "trustBinding",
        ):
            definition = receipt["$defs"][definition_name]
            self.assertFalse(definition["additionalProperties"], definition_name)
            self.assertEqual(
                set(definition["required"]),
                set(definition["properties"]),
                definition_name,
            )
        self.assertEqual(
            {
                "qualificationSubjectManifestDigest",
                "qualificationCaseMatrixSha256",
                "caseIds",
                "e4EvidenceHashes",
                "e4ClosureDigest",
            },
            set(receipt["$defs"]["e4Closure"]["required"]),
        )
        self.assertIn(
            "receiptDigest as null",
            receipt["x-qmanReceiptRule"],
        )
        self.assertIn(
            "QMAN-DIRECTPATH/QUALIFICATION-VERIFICATION-RECEIPT/V1",
            receipt["x-qmanReceiptRule"],
        )
        self.assertIn(
            "profileHash=null",
            receipt["x-qmanReceiptRule"],
        )
        profile_hash_rule = profile["x-qmanHashRule"]
        self.assertIn(
            "directpath-qualification-profile-projection.schema.json",
            profile_hash_rule,
        )
        self.assertIn(
            "directpath-qualification-verification-receipt.schema.json",
            profile_hash_rule,
        )
        self.assertIn("verificationReceiptHash", profile_hash_rule)
        self.assertIn("profileHash to null", profile_hash_rule)
        self.assertIn("acyclic", profile_hash_rule)

        mutated = copy.deepcopy(self.contract)
        mutated["normativeSources"].remove(
            "contracts/directpath-qualification-verification-receipt.schema.json"
        )
        errors: list[str] = []
        handoff_validator._validate_wire_schema_closure(mutated, ROOT, errors)
        self.assertTrue(
            any(
                "hash subject QualificationVerificationReceipt" in error
                and "absent from normativeSources" in error
                for error in errors
            ),
            errors,
        )

    def test_operation_admission_binding_is_closed_normative_and_non_authoritative(self) -> None:
        schema_path = "contracts/directpath-operation-admission-binding.schema.json"
        self.assertIn(schema_path, self.contract["normativeSources"])
        schema = load(schema_path)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertIn("not proof", schema["description"])
        self.assertIn("UNIQUE", schema["x-qmanAuthorityBoundary"])
        self.assertIn("same transaction", schema["x-qmanAuthorityBoundary"])
        self.assertIn("scopeHash", schema["x-qmanHashRule"])

        for definition_name in (
            "operationLeaseSpec",
            "availabilityReadSet",
            "requestReadSet",
            "currentAuthorityVector",
        ):
            definition = schema["$defs"][definition_name]
            self.assertFalse(definition["additionalProperties"], definition_name)
            self.assertEqual(
                set(definition["required"]),
                set(definition["properties"]),
                definition_name,
            )

        subjects = {
            item["subject"]: item
            for item in self.contract["canonicalizationContract"]["hashSubjects"]
        }
        self.assertEqual(
            {
                "schemaRef": schema_path,
                "digestField": "bindingHash",
            },
            {
                key: subjects["OperationAdmissionBinding"][key]
                for key in ("schemaRef", "digestField")
            },
        )
        entity = next(
            item
            for item in self.contract["dataEntities"]
            if item["id"] == "ENTITY-OPERATION-ADMISSION-BINDING"
        )
        self.assertEqual(schema_path, entity["wireSchema"])
        self.assertEqual(
            set(schema["required"]),
            set(entity["key"]) | set(entity["requiredFields"]),
        )
        self.assertEqual(["bindingHash"], entity["key"])

        mutated = copy.deepcopy(self.contract)
        mutated["normativeSources"].remove(schema_path)
        errors: list[str] = []
        handoff_validator._validate_wire_schema_closure(mutated, ROOT, errors)
        self.assertTrue(
            any(
                "OperationAdmissionBinding" in error
                and "absent from normativeSources" in error
                for error in errors
            ),
            errors,
        )

    def test_static_admission_command_commit_and_authorities_are_closed(self) -> None:
        command_path = (
            "contracts/directpath-static-admission-command.schema.json"
        )
        commit_path = (
            "contracts/directpath-committed-static-admission.schema.json"
        )
        normative_sources = set(self.contract["normativeSources"])
        self.assertTrue({command_path, commit_path} <= normative_sources)

        command = load(command_path)
        committed = load(commit_path)
        for schema in (command, committed):
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(
                set(schema["required"]),
                set(schema["properties"]),
            )

        forbidden = " ".join(command["x-qmanForbiddenCallerInputs"])
        for value in (
            "CurrentAuthorityVector",
            "CAS expectation",
            "OperationLease",
            "OperationAdmissionBinding",
            "resourceVersion",
        ):
            self.assertIn(value, forbidden)

        capability = committed["$defs"]["operationLeaseCapability"]
        envelope_capability = self.operation_schema["$defs"][
            "operationLeaseCapability"
        ]
        self.assertEqual(
            set(envelope_capability["required"]),
            set(capability["required"]),
        )
        self.assertEqual(
            "ASSIGNMENT_PREPARE",
            capability["properties"]["leaseType"]["const"],
        )
        self.assertIn(
            "admissionBindingHashOrNull",
            capability["required"],
        )
        self.assertEqual(
            {"operationId", "idempotencyScopeHash", "idempotencyKey"},
            set(
                committed["$defs"]["idempotencyNaturalKey"]["required"]
            ),
        )
        self.assertIn(
            "policyAuthorityResourceVersion",
            committed["$defs"]["committedResourceVersions"]["required"],
        )

        subjects = {
            item["subject"]: item
            for item in self.contract["canonicalizationContract"][
                "hashSubjects"
            ]
        }
        self.assertEqual(
            (command_path, "commandHash"),
            (
                subjects["StaticAdmissionCommand"]["schemaRef"],
                subjects["StaticAdmissionCommand"]["digestField"],
            ),
        )
        self.assertEqual(
            (commit_path, "resultHash"),
            (
                subjects["CommittedStaticAdmission"]["schemaRef"],
                subjects["CommittedStaticAdmission"]["digestField"],
            ),
        )

        entities = {
            entity["id"]: entity
            for entity in self.contract["dataEntities"]
        }
        for entity_id in (
            "ENTITY-CAPABILITY-POLICY-AUTHORITY",
            "ENTITY-AVAILABILITY-AUTHORITY",
            "ENTITY-IDEMPOTENCY-RECORD",
            "ENTITY-OPERATION-LEASE",
        ):
            with self.subTest(entity_id=entity_id):
                entity = entities[entity_id]
                authority = self.authority_entity_schema["$defs"][
                    entity_id
                ]
                self.assertEqual(
                    set(authority["required"]),
                    set(entity["key"]) | set(entity["requiredFields"]),
                )
        self.assertIn(
            "admissionBindingHashOrNull",
            entities["ENTITY-OPERATION-LEASE"]["requiredFields"],
        )

    def test_query_read_trace_and_query_output_are_closed_and_non_authoritative(
        self,
    ) -> None:
        schema_path = "contracts/directpath-query-read-trace.schema.json"
        self.assertIn(schema_path, self.contract["normativeSources"])
        schema = load(schema_path)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertIn("actual canonical bytes", schema["description"])

        for definition_name in (
            "repositoryTransaction",
            "selectedScope",
            "observedInstance",
            "availabilityFence",
            "noFence",
            "predicateObservation",
            "readState",
            "capturedReadState",
            "outputInstance",
            "zeroWriteWitness",
        ):
            definition = schema["$defs"][definition_name]
            self.assertFalse(definition["additionalProperties"], definition_name)
            self.assertEqual(
                set(definition["required"]),
                set(definition["properties"]),
                definition_name,
            )

        observed = schema["$defs"]["observedInstance"]
        self.assertTrue(
            {
                "canonicalInstanceBase64",
                "instanceBytesSha256",
                "schemaRef",
                "sourcePrimaryKey",
                "observationDigest",
            }.issubset(observed["required"])
        )
        self.assertIn("not a decoder", observed["x-qmanObservedInstanceRule"])

        predicates = schema["$defs"]["predicateObservation"]["properties"][
            "predicateId"
        ]["enum"]
        self.assertEqual(9, len(predicates))
        predicate_set = schema["$defs"]["readState"]["properties"][
            "predicateObservations"
        ]
        self.assertEqual(9, predicate_set["minItems"])
        self.assertEqual(9, predicate_set["maxItems"])

        witness = schema["$defs"]["zeroWriteWitness"]
        self.assertTrue(
            witness["properties"]["databaseEnforcedReadOnly"]["const"]
        )
        self.assertEqual(0, witness["properties"]["writeStatementCount"]["const"])
        self.assertEqual(0, witness["properties"]["affectedRowCount"]["const"])
        self.assertEqual(
            0,
            witness["properties"]["repositoryMutationInstances"]["maxItems"],
        )
        self.assertEqual(
            0,
            witness["properties"]["hostSideEffectInvocations"]["maxItems"],
        )

        output_instance = schema["$defs"]["outputInstance"]
        self.assertNotIn("traceDigest", output_instance["properties"])
        self.assertIn("no fixed point", output_instance["x-qmanOutputRule"])
        self.assertTrue(
            any(
                "before.state and after.state must be byte-equal" in rule
                for rule in schema["x-qmanEqualityRules"]
            )
        )
        self.assertIn("PRODUCT C15 remains blocked", schema["x-qmanAuthorityBoundary"])

        subjects = {
            item["subject"]: item
            for item in self.contract["canonicalizationContract"]["hashSubjects"]
        }
        self.assertEqual(
            {
                "schemaRef": schema_path,
                "digestField": "traceDigest",
            },
            {
                key: subjects["QueryReadTrace"][key]
                for key in ("schemaRef", "digestField")
            },
        )

        query_output = self.operation_payload_schema["$defs"][
            "output_OP_QUERY_DIRECTPATH"
        ]
        self.assertTrue(
            {
                "capabilityDecisionHash",
                "semanticDependencyHash",
                "queryStateHash",
            }.issubset(query_output["required"])
        )
        for field in (
            "bundleSummaries",
            "leaseSummaries",
            "reasons",
            "evidenceRefs",
        ):
            self.assertIn(
                "CANONICAL-JSON-V1",
                query_output["properties"][field]["x-qmanSetOrder"],
                field,
            )
        self.assertIn(
            "no traceDigest",
            query_output["x-qmanDeterministicOutputRule"],
        )

        query_operation = next(
            operation
            for operation in self.contract["backendNeutralOperations"]
            if operation["id"] == "OP-QUERY-DIRECTPATH"
        )
        self.assertEqual("NONE", query_operation["sideEffect"])
        self.assertEqual("READ_ONLY", query_operation["idempotency"])
        self.assertIn(
            "database-enforced read-only",
            " ".join(query_operation["postconditions"]),
        )

        mutated = copy.deepcopy(self.contract)
        mutated["normativeSources"].remove(schema_path)
        errors: list[str] = []
        handoff_validator._validate_wire_schema_closure(mutated, ROOT, errors)
        self.assertTrue(
            any(
                "QueryReadTrace" in error
                and "absent from normativeSources" in error
                for error in errors
            ),
            errors,
        )

    def test_verification_matrix_and_mapping_mutations_fail_semantic_validation(self) -> None:
        mutated_map = copy.deepcopy(self.mapping_template)
        mutated_map["mappings"][0]["verificationRequirementDigest"] = (
            "sha256:" + "f" * 64
        )
        errors = handoff_validator.validate_mapping_document(
            mutated_map,
            self.contract,
            root=ROOT,
            expect_baseline=True,
        )
        self.assertTrue(
            any("mappings[0].verificationRequirementDigest" in error for error in errors),
            errors,
        )

        mutated_contract = copy.deepcopy(self.contract)
        mutated_contract["mappingSurface"]["verificationMatrix"][0][
            "requiredCaseIds"
        ] = mutated_contract["mappingSurface"]["verificationMatrix"][0][
            "requiredCaseIds"
        ][1:]
        errors = handoff_validator.validate_mapping_document(
            self.mapping_template,
            mutated_contract,
            root=ROOT,
            expect_baseline=True,
        )
        self.assertTrue(
            any("verificationMatrix" in error and "mismatch" in error for error in errors),
            errors,
        )

        missing_mapping = copy.deepcopy(self.mapping_template)
        missing_mapping["mappings"].pop()
        errors = handoff_validator.validate_mapping_document(
            missing_mapping,
            self.contract,
            root=ROOT,
            expect_baseline=True,
        )
        self.assertTrue(
            any("closed ordered surface mismatch" in error for error in errors), errors
        )

    def test_mapping_schema_requires_exact_commit_symbol_hash_and_status_separation(self) -> None:
        schema = self.mapping_schema
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(3, len(schema["allOf"]))
        self.assertIn(
            "TARGET_CODE_MAPPED",
            schema["allOf"][0]["if"]["properties"]["statusAxes"]["properties"],
        )
        self.assertIn(
            "PRODUCT_IMPLEMENTED",
            schema["allOf"][1]["if"]["properties"]["statusAxes"]["properties"],
        )
        self.assertIn(
            "QUALIFIED",
            schema["allOf"][2]["if"]["properties"]["statusAxes"]["properties"],
        )
        self.assertEqual(True, schema["properties"]["statusAxes"]["properties"]["PORTABLE_SPEC_READY"]["const"])

        mapping = schema["$defs"]["mapping"]
        self.assertFalse(mapping["additionalProperties"])
        self.assertEqual(
            {
                "CANONICALIZATION",
                "GUARD",
                "EQUIVALENCE",
                "PORT",
                "ENTITY",
                "OPERATION",
                "STATE_MACHINE",
                "TRANSITION",
                "CAS_RULE",
                "REASON",
                "CONFIG",
                "MIGRATION",
                "TELEMETRY",
                "TEST",
                "PARITY_OBLIGATION",
            },
            set(mapping["properties"]["kind"]["enum"]),
        )
        target_binding = schema["$defs"]["targetBinding"]
        self.assertEqual(
            {
                "service",
                "path",
                "symbol",
                "symbolKind",
                "symbolResolver",
                "symbolLocator",
                "hashScope",
                "interfaceHash",
                "symbolSemanticHash",
                "resolverEvidencePath",
                "resolverEvidenceSha256",
            },
            set(target_binding["required"]),
        )
        self.assertEqual(
            "^sha256:[0-9a-f]{64}$",
            target_binding["properties"]["interfaceHash"]["pattern"],
        )
        self.assertEqual(5, len(mapping["allOf"]))

        template_keys = set(self.mapping_template)
        self.assertEqual(set(schema["properties"]), template_keys)
        self.assertEqual(1, self.mapping_template["schemaVersion"])
        self.assertEqual(
            "contracts/directpath-portable-control-contract.json",
            self.mapping_template["sourceContract"]["path"],
        )

    def test_c_m_external_anchor_e_and_detached_final_map_are_acyclic(self) -> None:
        topology = self.mapping_template["artifactTopology"]
        schema_topology = self.mapping_schema["properties"]["artifactTopology"]
        for field, definition in schema_topology["properties"].items():
            self.assertEqual(definition["const"], topology[field], field)
        self.assertEqual(
            "TARGET_CODE_C_TO_MAPPING_CORE_M_TO_CATALOG_AND_EVIDENCE_CONTENT_TO_EXTERNAL_CATALOG_ANCHOR_A_TO_EVIDENCE_REVISION_E_TO_DETACHED_FINAL_MAP",
            topology["graph"],
        )
        self.assertEqual("DETACHED_CONTENT_ADDRESS", topology["mappingCoreStorage"])
        self.assertEqual(
            "EXTERNAL_MONOTONIC_AUTHORITY_NOT_IN_C_OR_E_OR_MAP",
            topology["catalogAnchorStorage"],
        )
        self.assertEqual("DETACHED_NOT_IN_C_OR_E", topology["finalMapStorage"])

        populated = copy.deepcopy(self.mapping_template)
        populated["scenarioBindingDigest"] = "sha256:" + "1" * 64
        populated["mapDigest"] = "sha256:" + "2" * 64
        populated["targetRepository"] = {
            "repositoryId": "C",
            "repositoryLocation": "target-code",
            "objectFormat": "SHA1",
            "commit": "1" * 40,
            "branch": "main",
            "language": "mixed",
            "buildCommand": "build",
            "testCommand": "test",
        }
        populated["evidenceRepository"] = {
            "repositoryId": "E",
            "repositoryLocation": "evidence",
            "objectFormat": "SHA1",
            "commit": "2" * 40,
            "artifactRoot": "evidence",
        }
        populated["trustPolicy"] = {
            "rootSet": {"path": "root"},
            "expectedTrustRootDigest": "sha256:" + "3" * 64,
            "rollbackAnchor": {"path": "trust-anchor"},
            "catalogRollbackAnchor": {"path": "catalog-anchor"},
        }
        populated["completionEvidence"] = {
            key: {"path": key} for key in populated["completionEvidence"]
        }
        populated["approvals"] = [{"role": "TEST"}]
        populated["mappings"][0]["targetTestBindings"] = [{"path": "test"}]

        mapping_core = handoff_validator._scenario_binding_projection(populated)
        self.assertEqual(populated["targetRepository"], mapping_core["targetRepository"])
        self.assertIsNone(mapping_core["evidenceRepository"])
        self.assertIsNone(mapping_core["scenarioBindingDigest"])
        self.assertIsNone(mapping_core["mapDigest"])
        self.assertEqual([], mapping_core["approvals"])
        self.assertTrue(
            all(value is None for value in mapping_core["completionEvidence"].values())
        )
        self.assertIsNone(mapping_core["trustPolicy"]["catalogRollbackAnchor"])
        self.assertEqual([], mapping_core["mappings"][0]["targetTestBindings"])

        final_map_projection = handoff_validator._map_approval_projection(populated)
        self.assertEqual(populated["evidenceRepository"], final_map_projection["evidenceRepository"])
        self.assertEqual(
            populated["scenarioBindingDigest"],
            final_map_projection["scenarioBindingDigest"],
        )
        self.assertIsNone(final_map_projection["mapDigest"])
        self.assertEqual([], final_map_projection["approvals"])

        invalid = copy.deepcopy(self.mapping_template)
        invalid["artifactTopology"]["graph"] = "CYCLE"
        errors = handoff_validator.validate_mapping_document(
            invalid, self.contract, root=ROOT, expect_baseline=True
        )
        self.assertTrue(
            any("artifactTopology.graph: expected" in error for error in errors), errors
        )

    def test_identity_provider_registry_and_golden_vectors_are_closed(self) -> None:
        expected_provider_ids = {
            "PCI_DSN_EUI64_V1",
            "PCI_VPD_SN_UTF8_V1",
            "VENDOR_QUALIFIED_BYTES_V1",
            "ACPI_FIRMWARE_PATH_V1",
            "SMBIOS_SYSTEM_SLOT_V1",
            "DEVICETREE_FULL_PATH_V1",
        }
        schema_providers = self.identity_schema["x-qmanProviderDefinitions"]
        vector_providers = self.identity_vectors["providerDefinitionVectors"]
        self.assertEqual(schema_providers, vector_providers)
        self.assertEqual(
            expected_provider_ids, {item["providerId"] for item in schema_providers}
        )
        for provider in schema_providers:
            preimage = (
                b"QMAN-DIRECTPATH/IDENTITY-PROVIDER-DEFINITION/V1"
                + b"\x00"
                + provider["providerId"].encode("ascii")
                + b"\x00"
                + str(provider["providerVersion"]).encode("ascii")
                + b"\x00"
                + provider["definitionUtf8"].encode("utf-8")
            )
            self.assertEqual(
                "sha256:" + hashlib.sha256(preimage).hexdigest(),
                provider["providerDefinitionDigest"],
                provider["providerId"],
            )

        vector_projection = copy.deepcopy(self.identity_vectors)
        declared_vector_digest = vector_projection["vectorSetDigest"]
        vector_projection["vectorSetDigest"] = None
        self.assertEqual(canonical_digest(vector_projection), declared_vector_digest)
        self.assertEqual(
            declared_vector_digest,
            self.identity_schema["x-qmanGoldenVectorSet"]["vectorSetDigest"],
        )
        self.assertEqual(
            self.identity_vectors["identityFingerprintVectors"],
            self.identity_schema["x-qmanGoldenVectors"],
        )

        for vector in self.identity_vectors["identityFingerprintVectors"]:
            semantic = json.loads(vector["canonicalUtf8"])
            self.assertEqual(
                vector["canonicalUtf8"],
                json.dumps(
                    semantic,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            self.assertEqual(
                vector["sha256"],
                "sha256:"
                + hashlib.sha256(vector["canonicalUtf8"].encode("utf-8")).hexdigest(),
            )

        for vector in self.identity_vectors["serialVectors"]:
            source = bytes.fromhex(vector["sourceBytesHex"])
            offset = vector["extractionOffsetBytes"]
            length = vector["extractionLengthBytes"]
            self.assertEqual(
                vector["extractedBytesHex"], source[offset : offset + length].hex()
            )
            serial_preimage = (
                b"QMAN-DIRECTPATH/SERIAL-VALUE/V1"
                + b"\x00"
                + vector["providerId"].encode("ascii")
                + b"\x00"
                + bytes.fromhex(vector["canonicalSerialBytesHex"])
            )
            self.assertEqual(
                vector["serialValueHash"],
                "sha256:" + hashlib.sha256(serial_preimage).hexdigest(),
            )

        path_patterns = {
            "ACPI_FIRMWARE_PATH_V1": self.identity_schema["$defs"]["acpiPhysicalPath"]["pattern"],
            "SMBIOS_SYSTEM_SLOT_V1": self.identity_schema["$defs"]["smbiosPhysicalPath"]["pattern"],
            "DEVICETREE_FULL_PATH_V1": self.identity_schema["$defs"]["deviceTreePhysicalPath"]["pattern"],
        }
        for vector in self.identity_vectors["physicalPathVectors"]:
            self.assertIsNotNone(
                re.fullmatch(path_patterns[vector["providerId"]], vector["accepted"])
            )
        for rejected in self.identity_vectors["rejectedPhysicalPaths"]:
            self.assertFalse(
                any(re.fullmatch(pattern, rejected) for pattern in path_patterns.values()),
                rejected,
            )

    def test_external_trust_and_catalog_rollback_authorities_fail_closed(self) -> None:
        root_policy = self.trust_root_schema["properties"]["verificationPolicy"]
        self.assertFalse(self.trust_root_schema["additionalProperties"])
        self.assertIn("verificationPolicy", self.trust_root_schema["required"])
        self.assertEqual(
            {"policyId", "requiredSignatures", "allowedKeyIds"},
            set(root_policy["required"]),
        )
        self.assertIn("inside rootSetDigest", root_policy["x-qmanPolicyRule"])
        map_trust = self.mapping_schema["$defs"]["trustPolicy"]
        self.assertNotIn("requiredRootSignatures", map_trust["properties"])
        self.assertIn("catalogRollbackAnchor", map_trust["required"])
        self.assertNotIn("externalRollbackAnchorReceipt", self.trust_key_ring_schema["properties"])
        self.assertNotIn("rollbackAnchorReceipt", self.catalog_schema["properties"])
        self.assertIn("receipt", self.catalog_anchor_schema["required"])
        self.assertIn("casPrecondition", self.catalog_anchor_schema["required"])
        self.assertIn(
            "not writable or selectable",
            self.catalog_anchor_schema["x-qmanOutOfBandAuthorityRule"],
        )

        errors: list[str] = []
        handoff_validator._validate_catalog_rollback_anchor(
            None, None, None, None, None, ROOT, None, errors
        )
        self.assertTrue(
            any("independently supplied external authority input is required" in error for error in errors),
            errors,
        )

        invalid_root = {
            "schemaVersion": 1,
            "rootSetId": "root-set",
            "verificationPolicy": {
                "policyId": "N_OF_M_ED25519_DISTINCT_KEYS_V1",
                "requiredSignatures": 2,
                "allowedKeyIds": ["root-a"],
            },
            "keys": [
                {
                    "keyId": "root-a",
                    "principalId": "root-principal-a",
                    "algorithm": "Ed25519",
                    "publicKeyBase64Url": "A" * 43,
                    "notBefore": "2026-01-01T00:00:00.000000Z",
                    "notAfter": "2027-01-01T00:00:00.000000Z",
                }
            ],
            "rootSetDigest": None,
        }
        errors = []
        handoff_validator._validate_root_set(
            invalid_root, None, "test root set", errors
        )
        self.assertTrue(
            any("requiredSignatures: expected 1..1" in error for error in errors),
            errors,
        )

    def test_qualification_case_matrix_is_independently_derived_and_complete(self) -> None:
        matrix = self.compatibility_policy["qualificationCaseMatrix"]
        self.assertEqual("EXACT_UNION", matrix["derivationMode"])
        self.assertEqual("DENY_QUALIFIED", matrix["missingRule"])
        self.assertEqual("E4_EXACT_CASE_SET", matrix["evidenceRule"])

        covered_cases = set(matrix["globalMandatoryCaseIds"])
        for rule_family in (
            "platformRules",
            "backendRules",
            "machineFirmwareRules",
            "configuredIommuTypeRules",
            "identityVariantRules",
            "deviceArchetypeRules",
            "deviceTraitRules",
        ):
            for rule in matrix[rule_family]:
                covered_cases.update(rule["caseIds"])
        self.assertEqual(self.case_ids, covered_cases)
        self.assertEqual(
            {item["id"] for item in self.compatibility_policy["platforms"]},
            {item["platformProfileId"] for item in matrix["platformRules"]},
        )
        self.assertEqual(
            {
                (entry["machine"], entry["firmware"])
                for platform in self.compatibility_policy["platforms"]
                for entry in platform["machineFirmware"]
            },
            {
                (item["machine"], item["firmware"])
                for item in matrix["machineFirmwareRules"]
            },
        )
        self.assertEqual(
            {
                self.compatibility_policy["backendPolicy"]["currentProductFamily"],
                *self.compatibility_policy["backendPolicy"]["futureFamilies"],
            },
            {item["backendFamily"] for item in matrix["backendRules"]},
        )

        errors: list[str] = []
        matrix_info = handoff_validator._validate_qualification_case_matrix(
            matrix, self.compatibility_policy, self.case_ids, errors
        )
        self.assertEqual([], errors)
        self.assertEqual(canonical_digest(matrix), matrix_info["digest"])

        qualification_schema = load("contracts/directpath-qualification-record.schema.json")
        self.assertIn("qualificationCaseMatrixSha256", qualification_schema["required"])
        self.assertIn("deviceArchetype", qualification_schema["required"])
        self.assertIn(
            "qualificationCaseMatrixSha256",
            self.qualification_index_schema["required"],
        )
        self.assertIn(
            "exactly",
            self.qualification_index_schema["x-qmanE4ExactCoverageRule"].lower(),
        )

        invalid = copy.deepcopy(matrix)
        invalid["globalMandatoryCaseIds"].append("Z99-NOT-A-CLOSED-CASE")
        errors = []
        handoff_validator._validate_qualification_case_matrix(
            invalid, self.compatibility_policy, self.case_ids, errors
        )
        self.assertTrue(
            any("unknown Case IDs" in error for error in errors), errors
        )

    def test_operation_envelope_and_typed_scenario_trace_are_closed(self) -> None:
        operation_ids = [
            item["id"] for item in self.contract["backendNeutralOperations"]
        ]
        self.assertEqual(
            operation_ids, self.operation_schema["$defs"]["operationId"]["enum"]
        )
        self.assertEqual(35, len(operation_ids))
        profile_index = self.operation_payload_schema["x-operationProfileIndex"]
        self.assertEqual(operation_ids, [item["operationId"] for item in profile_index])
        self.assertEqual(35, len(profile_index))

        expected_profile_refs: set[str] = set()
        operations_by_id = {
            item["id"]: item for item in self.contract["backendNeutralOperations"]
        }
        for item in profile_index:
            operation_id = item["operationId"]
            for direction in ("REQUEST", "RESULT"):
                lower = direction.lower()
                profile_id = item[f"{lower}ProfileId"]
                schema_ref = item[f"{lower}SchemaRef"]
                expected_profile_refs.add("#/" + schema_ref.split("#/", 1)[1])
                definition_name = schema_ref.rsplit("/", 1)[1]
                profile = self.operation_payload_schema["$defs"][definition_name]
                self.assertFalse(profile["additionalProperties"])
                self.assertEqual(set(profile["required"]), set(profile["properties"]))
                self.assertEqual(operation_id, profile["properties"]["operationId"]["const"])
                self.assertEqual(direction, profile["properties"]["direction"]["const"])
                self.assertEqual(profile_id, profile["properties"]["profileId"]["const"])
                self.assertEqual(
                    "CANONICAL-JSON-V1",
                    profile["properties"]["canonicalProfile"]["const"],
                )
                body_name = profile["properties"]["body"]["$ref"].rsplit("/", 1)[1]
                body = self.operation_payload_schema["$defs"][body_name]
                self.assertFalse(body["additionalProperties"])
                self.assertEqual(set(body["required"]), set(body["properties"]))
                if direction == "RESULT":
                    failure_branch = body["properties"]["errorOrNull"]["oneOf"][1]
                    observed_reasons = failure_branch["allOf"][1]["properties"][
                        "reasonCode"
                    ]["enum"]
                    self.assertEqual(
                        operations_by_id[operation_id]["failureReasonCodes"],
                        observed_reasons,
                    )

        self.assertEqual(70, len(expected_profile_refs))
        self.assertEqual(
            expected_profile_refs,
            {item["$ref"] for item in self.operation_payload_schema["oneOf"]},
        )

        payload_raw_sha256 = "sha256:" + hashlib.sha256(
            (ROOT / "contracts/directpath-operation-payload.schema.json").read_bytes()
        ).hexdigest()
        request_bindings = self.operation_schema["$defs"][
            "requestPayloadSchemaBinding"
        ]["oneOf"]
        result_bindings = self.operation_schema["$defs"][
            "resultPayloadSchemaBinding"
        ]["oneOf"]
        for direction, bindings in (
            ("request", request_bindings),
            ("result", result_bindings),
        ):
            expected = {
                item["operationId"]: item[f"{direction}SchemaRef"]
                for item in profile_index
            }
            observed = {
                item["properties"]["operationId"]["const"]: item["properties"][
                    "payloadSchemaRef"
                ]["const"]
                for item in bindings
            }
            self.assertEqual(expected, observed)
            envelope = self.operation_schema["$defs"][f"{direction}Envelope"]
            self.assertEqual(
                "PORTABLE_CONTRACT",
                envelope["properties"]["payloadSchemaAuthority"]["const"],
            )
            self.assertEqual(
                payload_raw_sha256,
                envelope["properties"]["payloadSchemaSha256"]["const"],
            )

        profiles_by_operation = {item["operationId"]: item for item in profile_index}
        for step in self.acceptance_example["steps"]:
            profile = profiles_by_operation[step["operationId"]]
            for field, direction in (
                ("request", "request"),
                ("expectedImmediateResult", "result"),
            ):
                binding = step[field]
                self.assertEqual(step["operationId"], binding["operationId"])
                self.assertEqual(profile[f"{direction}SchemaRef"], binding["payloadSchemaRef"])
                self.assertEqual(payload_raw_sha256, binding["payloadSchemaSha256"])
                self.assertEqual("PORTABLE_CONTRACT", binding["payloadSchemaAuthority"])
        iteration_result = self.acceptance_schema["$defs"]["iterationResult"]
        self.assertIn("operationExchanges", iteration_result["required"])
        exchange = self.acceptance_schema["$defs"]["operationExchange"]
        self.assertFalse(exchange["additionalProperties"])
        self.assertEqual(set(exchange["required"]), set(exchange["properties"]))
        self.assertEqual(
            "contracts/directpath-operation-envelope.schema.json#/$defs/requestEnvelope",
            self.acceptance_schema["$defs"]["operationRequestEnvelopeArtifact"][
                "properties"
            ]["schemaRef"]["const"],
        )
        self.assertEqual(
            "contracts/directpath-operation-envelope.schema.json#/$defs/resultEnvelope",
            self.acceptance_schema["$defs"]["operationResultEnvelopeArtifact"][
                "properties"
            ]["schemaRef"]["const"],
        )
        self.assertTrue(
            {
                "operation-request-envelope",
                "operation-result-envelope",
            }.issubset(
                {item["artifactType"] for item in self.acceptance_example["artifacts"]}
            )
        )
        self.assertEqual(
            ["#/$defs/requestEnvelope", "#/$defs/resultEnvelope"],
            [item["$ref"] for item in self.operation_schema["oneOf"]],
        )
        for name in ("requestEnvelope", "resultEnvelope"):
            envelope = self.operation_schema["$defs"][name]
            self.assertFalse(envelope["additionalProperties"])
            self.assertEqual(set(envelope["required"]), set(envelope["properties"]))

        entities = {item["id"]: item for item in self.contract["dataEntities"]}
        release_entity = entities["ENTITY-RELEASE-OWNERSHIP-GUARD"]
        release_capability = self.operation_schema["$defs"][
            "releaseOwnershipGuardCapability"
        ]
        self.assertEqual(
            set(release_entity["key"]) | set(release_entity["requiredFields"]),
            set(release_capability["required"]),
        )
        proof_kinds = {
            branch["properties"]["kind"]["const"]
            for branch in release_capability["properties"]["qemuExistenceProof"]["oneOf"]
        }
        self.assertEqual({"DURABLE_NEVER_CREATED", "EXIT_PROVEN"}, proof_kinds)

        release_operations = {
            "OP-STOP-QEMU",
            "OP-TEARDOWN-HOST-BUNDLE",
            "OP-RELEASE-BACKEND-GRANT",
            "OP-PROVE-CLEAN-RELEASE",
            "OP-CAS-REVOKE-LEASE",
        }
        request_conditions = self.operation_schema["$defs"]["requestEnvelope"]["allOf"]
        guarded_condition = next(
            item
            for item in request_conditions
            if set(
                item.get("if", {})
                .get("properties", {})
                .get("operationId", {})
                .get("enum", [])
            )
            == release_operations
        )
        self.assertIn(
            "releaseOwnershipGuardCapabilityOrNull",
            guarded_condition["then"]["properties"],
        )

        trace_schema = self.acceptance_schema["$defs"]["traceability"]
        typed_trace_fields = {
            "contractItemIds",
            "portIds",
            "operationIds",
            "entityIds",
            "stateMachineIds",
            "transitionIds",
            "testObligationIds",
            "parityObligationIds",
            "expectedReasonCodes",
        }
        self.assertTrue(typed_trace_fields.issubset(trace_schema["required"]))
        self.assertFalse(trace_schema["additionalProperties"])
        self.assertEqual(
            [],
            handoff_validator.validate_scenario_document(
                self.acceptance_example,
                self.contract,
                root=ROOT,
                mapping_document=self.mapping_template,
            ),
        )

        invalid_trace = copy.deepcopy(self.acceptance_example)
        invalid_trace["traceability"]["transitionIds"] = ["TR-NOT-REAL"]
        errors = handoff_validator.validate_scenario_document(
            invalid_trace,
            self.contract,
            root=ROOT,
            mapping_document=self.mapping_template,
        )
        self.assertTrue(
            any("unknown closed IDs ['TR-NOT-REAL']" in error for error in errors),
            errors,
        )

    def test_iteration_fault_oracle_and_artifact_evidence_cannot_be_reused(self) -> None:
        iteration_schema = self.acceptance_schema["$defs"]["iterationResult"]
        execution_schema = self.acceptance_schema["$defs"]["executionResult"]
        artifact_schema = self.acceptance_schema["$defs"]["artifactInstance"]
        self.assertFalse(iteration_schema["additionalProperties"])
        self.assertEqual(set(iteration_schema["required"]), set(iteration_schema["properties"]))
        self.assertIn("iterationRunId", iteration_schema["required"])
        self.assertIn("faultPointOrNull", iteration_schema["required"])
        self.assertIn("oracleResults", iteration_schema["required"])
        self.assertIn("artifactHashes", iteration_schema["required"])
        self.assertIn("cleanupProofArtifactHash", iteration_schema["required"])
        self.assertIn("iterationResults", execution_schema["required"])
        self.assertNotIn("oracleResults", execution_schema["properties"])
        correlation = artifact_schema["properties"]["correlation"]
        self.assertFalse(correlation["additionalProperties"])
        self.assertEqual(
            {
                "scenarioId",
                "caseId",
                "scenarioRunId",
                "iterationRunId",
                "iteration",
                "faultPointOrNull",
                "commandIdOrNull",
                "assignmentIdOrNull",
                "runIdOrNull",
                "subjectBindings",
            },
            set(correlation["required"]),
        )

        artifact_hash = "sha256:" + "a" * 64
        empty_oracles = {
            category: [] for category in handoff_validator.ORACLE_CATEGORY_FIELDS
        }

        def iteration(number: int) -> dict[str, Any]:
            return {
                "iteration": number,
                "iterationRunId": "reused-iteration-run",
                "faultPointOrNull": None,
                "verdict": "PASS",
                "startedAt": f"2026-07-22T00:00:0{number}.000000Z",
                "finishedAt": f"2026-07-22T00:00:1{number}.000000Z",
                "artifactHashes": [artifact_hash],
                "scheduleTraceArtifactHash": artifact_hash,
                "barrierObservationArtifactHashes": [artifact_hash],
                "cleanupProofArtifactHash": artifact_hash,
                "oracleResults": copy.deepcopy(empty_oracles),
            }

        result = {
            "runId": "scenario-run",
            "verdict": "PASS",
            "limitations": [],
            "resultCanonicalization": "CANONICAL-JSON-V1",
            "targetRepositoryCommit": "1" * 40,
            "scenarioInputSha256": "sha256:" + "b" * 64,
            "startedAt": "2026-07-22T00:00:00.000000Z",
            "finishedAt": "2026-07-22T00:00:20.000000Z",
            "artifactInstances": [
                {
                    "path": "evidence/reused.json",
                    "sha256": artifact_hash,
                    "artifactType": "TRACE",
                    "producer": "runner",
                    "correlation": {
                        "scenarioId": self.acceptance_example["scenarioId"],
                        "caseId": self.acceptance_example["caseId"],
                        "scenarioRunId": "scenario-run",
                        "iterationRunId": "reused-iteration-run",
                        "iteration": 1,
                        "faultPointOrNull": None,
                        "commandIdOrNull": None,
                        "assignmentIdOrNull": None,
                        "runIdOrNull": None,
                        "subjectBindings": [],
                    },
                }
            ],
            "runnerSha256": artifact_hash,
            "evidenceIndexRecordSha256": artifact_hash,
            "iterationResults": [iteration(1), iteration(2)],
            "keyRingVersion": 1,
            "signerKeyId": "test-signer",
            "resultDigest": "sha256:" + "c" * 64,
            "signature": "ed25519:" + "A" * 86,
        }
        errors: list[str] = []
        executed_scenario = copy.deepcopy(self.acceptance_example)
        executed_scenario["targetBinding"] = {"repositoryCommit": "1" * 40}
        handoff_validator._validate_execution_result(
            executed_scenario,
            result,
            self.contract,
            None,
            None,
            2,
            {None: 2},
            self.acceptance_example["artifacts"],
            errors,
        )
        self.assertTrue(
            any("duplicate iteration run identity" in error for error in errors), errors
        )
        self.assertTrue(
            any(
                "iterationResults[1].artifactHashes: must exactly equal" in error
                for error in errors
            ),
            errors,
        )

    def test_acceptance_scenario_schema_and_s05_template_define_closed_oracles(self) -> None:
        schema = self.acceptance_schema
        scenario = self.acceptance_example

        self.assertEqual(
            "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(
            {"TEMPLATE", "BOUND", "EXECUTED_PASS"},
            set(schema["properties"]["definitionStatus"]["enum"]),
        )
        self.assertIn(
            "cannot close",
            schema["properties"]["definitionStatus"]["description"],
        )
        for definition in schema["$defs"].values():
            if definition.get("type") == "object":
                self.assertFalse(definition["additionalProperties"])

        self.assertEqual(set(schema["properties"]), set(scenario))
        self.assertEqual("TEMPLATE", scenario["definitionStatus"])
        self.assertIn(scenario["caseId"], self.case_ids)
        self.assertIn(
            scenario["targetMilestone"],
            {item["id"] for item in self.project_status["milestones"]},
        )
        self.assertTrue(
            set(scenario["traceability"]["techStoryIds"]).issubset(
                self.tech_story_ids
            )
        )
        self.assertTrue(
            set(scenario["traceability"]["riskIds"]).issubset(
                {item["id"] for item in self.risk_status["records"]}
            )
        )

        operations = {
            item["id"]: item for item in self.contract["backendNeutralOperations"]
        }
        ports = {item["id"] for item in self.contract["requiredPorts"]}
        entities = {item["id"] for item in self.contract["dataEntities"]}
        reasons = {
            item["code"] for item in self.contract["errorContract"]["reasonCodes"]
        }
        machines = {
            item["id"]: set(item["states"])
            for item in self.contract["stateMachines"]
        }

        trace = scenario["traceability"]
        self.assertTrue(set(trace["portIds"]).issubset(ports))
        self.assertTrue(set(trace["operationIds"]).issubset(operations))
        self.assertTrue(set(trace["expectedReasonCodes"]).issubset(reasons))
        step_operation_ids = [item["operationId"] for item in scenario["steps"]]
        self.assertEqual(list(range(1, len(step_operation_ids) + 1)), [
            item["sequence"] for item in scenario["steps"]
        ])
        self.assertEqual(set(trace["operationIds"]), set(step_operation_ids))
        self.assertTrue(
            {operations[item]["ownerPortId"] for item in step_operation_ids}.issubset(
                set(trace["portIds"])
            )
        )

        expected = scenario["expected"]
        self.assertIn(expected["reasonCode"], reasons)
        self.assertTrue(
            {item["entityId"] for item in expected["authoritativeWrites"]}.issubset(
                entities
            )
        )
        for machine_id, state in {
            **scenario["preconditions"]["initialStates"],
            **expected["finalStates"],
            **scenario["cleanup"]["expectedStates"],
        }.items():
            self.assertIn(machine_id, machines)
            self.assertIn(state, machines[machine_id])
        self.assertTrue(all(item["hashRequired"] for item in scenario["artifacts"]))
        self.assertTrue(scenario["execution"]["targetTestBindingRequired"])
        self.assertTrue(
            any(
                item["digest"] == "sha256:" + "0" * 64
                for item in scenario["preconditions"]["fixtures"]
            )
        )
        self.assertTrue(
            any("TEMPLATE-only" in fact for fact in scenario["preconditions"]["facts"])
        )
        self.assertIn(
            "contracts/directpath-acceptance-scenario.schema.json",
            self.contract["normativeSources"],
        )
        oracle_contract = schema["x-qmanOracleIdContract"]
        self.assertIn("STEP-%03d-IMMEDIATE", oracle_contract["immediateResults"])
        self.assertIn("CLEANUP-PROOF:%03d", oracle_contract["cleanup"])
        execution_result = schema["$defs"]["executionResult"]
        self.assertIn("iterationResults", execution_result["required"])
        target = schema["$defs"]["targetBinding"]
        self.assertIn("hashScope", target["required"])


if __name__ == "__main__":
    unittest.main()
