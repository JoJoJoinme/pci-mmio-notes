import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "tools" / "evaluate_release.py"
sys.path.insert(0, str(EVALUATOR.parent))
import evaluate_release  # noqa: E402


class ReleaseGateTests(unittest.TestCase):
    def invoke(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(EVALUATOR), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_status_is_structurally_valid_and_explicitly_blocked(self) -> None:
        result = self.invoke("status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Contract: VALID", result.stdout)
        self.assertIn("Current milestone: G1", result.stdout)
        self.assertIn("Target release: V3 (SINGLE_TARGET_MULTI_WAVE)", result.stdout)
        self.assertIn(
            "IPD: epics=1, features=8, user_stories=28, tech_stories=40",
            result.stdout,
        )
        self.assertIn(
            "VMware reference: sources=24, experiments=37, tech_stories=40 "
            "(NOT_APPLICABLE=5, PARTIAL=28, UNKNOWN=3, VERIFIED=4)",
            result.stdout,
        )
        self.assertIn(
            "Qman evidence: records=10 (E2=2, E3=8; reference=5, component=5, "
            "end_to_end=0, "
            "product_case_closures=0, risk_closures=0)",
            result.stdout,
        )
        self.assertIn("Risks: 39", result.stdout)
        self.assertIn("Acceptance: 101/101 defined", result.stdout)
        self.assertIn("0 unclassified", result.stdout)
        self.assertIn("EXECUTABLE=1", result.stdout)
        self.assertIn("IMPLEMENTATION_BLOCKED=94", result.stdout)
        self.assertIn("HARDWARE_BLOCKED=6", result.stdout)
        self.assertIn(
            "implementation-blocked acceptance cases: C00, C01, C02, C03",
            result.stdout,
        )
        self.assertIn(
            "hardware-blocked acceptance cases: C12, M08, M12, M13, S06, S08",
            result.stdout,
        )
        self.assertIn(
            "reference-only executable cases do not close product gates: O09",
            result.stdout,
        )
        self.assertIn(
            "acceptance dependency is not closure-ready: C21 -> C10 "
            "(IMPLEMENTATION_BLOCKED)",
            result.stdout,
        )
        self.assertIn(
            "acceptance dependency is not closure-ready: C21 -> C20 "
            "(IMPLEMENTATION_BLOCKED)",
            result.stdout,
        )
        self.assertIn(
            "acceptance dependency is not closure-ready: S15 -> C21 "
            "(IMPLEMENTATION_BLOCKED)",
            result.stdout,
        )
        self.assertIn("Open decisions: 0", result.stdout)
        self.assertIn("unfinished milestones: G1, G2, G3, G4, G5, G6", result.stdout)
        self.assertIn("Release: BLOCKED", result.stdout)

        with patch.object(
            evaluate_release,
            "_evaluate_unchecked",
            side_effect=TypeError("malformed membership value"),
        ):
            malformed = evaluate_release.evaluate()
        self.assertTrue(malformed.errors)
        self.assertIn("stopped safely", malformed.errors[0])
        self.assertEqual({}, malformed.executable_cases)

        with patch.object(
            evaluate_release,
            "_evaluate_unchecked",
            side_effect=RecursionError("malformed nesting"),
        ):
            malformed = evaluate_release.evaluate()
        self.assertTrue(malformed.errors)
        self.assertIn("stopped safely", malformed.errors[0])

        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            for name, payload in (
                ("duplicate.json", '{"a": 1, "a": 2}\n'),
                ("nan.json", '{"value": NaN}\n'),
                ("infinity.json", '{"value": Infinity}\n'),
                (
                    "deeply-nested.json",
                    '{"value":' + "[" * 5000 + "0" + "]" * 5000 + "}\n",
                ),
            ):
                path = temporary_root / name
                path.write_text(payload, encoding="utf-8")
                with self.subTest(invalid_json=name), patch.object(
                    evaluate_release, "ROOT", temporary_root
                ):
                    with self.assertRaisesRegex(ValueError, "invalid JSON"):
                        evaluate_release.load_json(path)

    def test_release_gate_fails_closed(self) -> None:
        result = self.invoke("release")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Release: BLOCKED", result.stdout)
        self.assertIn("Portable release gate: BLOCKED", result.stdout)
        self.assertNotIn("Case O09: PASS", result.stdout)

    def test_o09_is_executable(self) -> None:
        result = self.invoke("run-cases", "--case", "O09")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Case O09: PASS", result.stdout)

    def test_c20_e2_runner_does_not_make_product_case_executable(self) -> None:
        result = self.invoke("run-cases", "--case", "C20")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Not executable or unknown: C20", result.stdout)

    def test_project_evidence_snapshot_cannot_drift_from_index(self) -> None:
        counts = Counter(
            {
                "records": 7,
                "E2": 2,
                "E3": 5,
                "reference": 5,
                "component": 2,
                "boundary:REFERENCE_ONLY": 5,
                "boundary:COMPONENT_ONLY": 2,
            }
        )
        observed = {
            "records": 7,
            "grades": {"E2": 2, "E3": 5, "E4": 0},
            "claimBoundaries": {
                "REFERENCE_ONLY": 5,
                "COMPONENT_ONLY": 2,
                "END_TO_END_PRODUCT": 0,
                "PHYSICAL_QUALIFICATION": 0,
            },
            "productCasesClosed": 0,
            "risksClosed": 0,
            "statusUpdated": False,
        }
        project = {"observations": {"qmanTechnicalEvidence": observed}}
        errors: list[str] = []
        evaluate_release.validate_project_qman_evidence_observation(
            project, counts, errors
        )
        self.assertEqual(errors, [])

        observed["records"] = 5
        evaluate_release.validate_project_qman_evidence_observation(
            project, counts, errors
        )
        self.assertTrue(any("records drift" in item for item in errors))


class QmanEvidenceClosurePolicyTests(unittest.TestCase):
    @staticmethod
    def result(
        *,
        subject: str,
        grade: str,
        product_cases: list[str],
        risks: list[str],
        status_updated: bool = True,
    ) -> dict[str, object]:
        if subject.endswith("REFERENCE") or subject == "QMAN_REFERENCE_MODEL":
            claim_boundary = "REFERENCE_ONLY"
        elif subject == "QMAN_COMPONENT":
            claim_boundary = "COMPONENT_ONLY"
        else:
            claim_boundary = "END_TO_END_PRODUCT"
        return {
            "subject": subject,
            "evidenceGrade": grade,
            "claimBoundary": claim_boundary,
            "verdict": "PASS",
            "mapping": {
                "caseIds": ["S15"],
                "riskIds": ["R17", "R27"],
            },
            "sourceState": {"dirtyWorkingTree": False},
            "artifacts": [
                {
                    "path": "evidence/committed.json",
                    "sha256": "0" * 64,
                    "retention": "COMMITTED",
                }
            ],
            "closureEffect": {
                "productCasesClosed": product_cases,
                "risksClosed": risks,
                "statusUpdated": status_updated,
            },
        }

    def validate(self, result: dict[str, object]) -> list[str]:
        errors: list[str] = []
        evaluate_release.validate_qman_closure_effect(
            "QMAN-TEST-001",
            result,
            {"QEMU_CONTROL_REFERENCE", "QMAN_REFERENCE_MODEL"},
            {"R27"},
            errors,
        )
        return errors

    def test_reference_subject_cannot_close_product_state(self) -> None:
        errors = self.validate(
            self.result(
                subject="QEMU_CONTROL_REFERENCE",
                grade="E3",
                product_cases=["S15"],
                risks=["R17"],
            )
        )
        self.assertTrue(any("reference subject cannot close" in item for item in errors))

    def test_e2_component_evidence_cannot_close_product_state(self) -> None:
        errors = self.validate(
            self.result(
                subject="QMAN_COMPONENT",
                grade="E2",
                product_cases=["S15"],
                risks=["R17"],
            )
        )
        self.assertTrue(any("E2 cannot close" in item for item in errors))

    def test_e3_cannot_close_e4_required_risk(self) -> None:
        errors = self.validate(
            self.result(
                subject="QMAN_END_TO_END",
                grade="E3",
                product_cases=[],
                risks=["R27"],
            )
        )
        self.assertTrue(any("E4-required risks" in item for item in errors))

        index = json.loads(
            (ROOT / "contracts" / "qman-evidence-index.json").read_text(
                encoding="utf-8"
            )
        )
        index["closurePolicy"]["e4RequiredRisks"].remove("R27")
        schema = json.loads(
            (ROOT / "contracts" / "qman-technical-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        ipd = json.loads(
            (ROOT / "contracts" / "ipd-tree.json").read_text(encoding="utf-8")
        )
        design = evaluate_release.extract_design_contracts(
            ROOT / "qemu-static-dynamic-directpath-design.md"
        )
        policy_errors: list[str] = []
        evaluate_release.validate_qman_evidence(
            index, schema, ipd, design, policy_errors
        )
        self.assertTrue(
            any("frozen physical-risk set" in error for error in policy_errors),
            policy_errors,
        )

    def test_component_subject_cannot_close_product_state(self) -> None:
        errors = self.validate(
            self.result(
                subject="QMAN_COMPONENT",
                grade="E3",
                product_cases=["S15"],
                risks=["R17"],
            )
        )
        self.assertTrue(any("non-end-to-end subject" in item for item in errors))

    def test_subject_and_claim_boundary_must_be_compatible(self) -> None:
        component = self.result(
            subject="QMAN_COMPONENT",
            grade="E3",
            product_cases=[],
            risks=[],
            status_updated=False,
        )
        component["claimBoundary"] = "END_TO_END_PRODUCT"
        self.assertTrue(
            any("component subject must use COMPONENT_ONLY" in item for item in self.validate(component))
        )

        end_to_end = self.result(
            subject="QMAN_END_TO_END",
            grade="E3",
            product_cases=[],
            risks=[],
            status_updated=False,
        )
        end_to_end["claimBoundary"] = "COMPONENT_ONLY"
        self.assertTrue(
            any("end-to-end subject" in item for item in self.validate(end_to_end))
        )

        physical = self.result(
            subject="QMAN_END_TO_END",
            grade="E3",
            product_cases=[],
            risks=[],
            status_updated=False,
        )
        physical["claimBoundary"] = "PHYSICAL_QUALIFICATION"
        self.assertTrue(any("requires E4" in item for item in self.validate(physical)))

        valid_result_path = ROOT / "evidence" / "qman-reference-model-20260721-summary.json"
        valid_result = json.loads(valid_result_path.read_text(encoding="utf-8"))
        shape_errors: list[str] = []
        evaluate_release.validate_qman_result_shape(
            valid_result["id"], valid_result, shape_errors
        )
        self.assertEqual([], shape_errors)

        mutations = (
            (("observedAt",), 123, "observedAt"),
            (("sut",), [], "sut must be an object"),
            (("hypotheses",), [], "hypotheses"),
            (("observations",), [], "observations"),
            (("limitations",), [], "limitations"),
            (("artifacts", 0, "closureAuthority"), "FULL", "artifact fields"),
            (("schemaVersion",), True, "integer 1"),
        )
        for path, value, expected_error in mutations:
            with self.subTest(shape_path=path):
                candidate = copy.deepcopy(valid_result)
                target = candidate
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                errors = []
                evaluate_release.validate_qman_result_shape(
                    candidate["id"], candidate, errors
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

        candidate = copy.deepcopy(valid_result)
        candidate["mapping"]["caseIds"] = ["O05a"]
        errors = []
        evaluate_release.validate_qman_result_shape(
            candidate["id"], candidate, errors
        )
        self.assertFalse(any("mapping.caseIds" in error for error in errors), errors)

    def test_e4_risk_closure_requires_physical_claim_boundary(self) -> None:
        result = self.result(
            subject="QMAN_END_TO_END",
            grade="E4",
            product_cases=[],
            risks=["R27"],
        )
        result["claimBoundary"] = "END_TO_END_PRODUCT"
        errors = self.validate(result)
        self.assertTrue(any("requires E4 physical qualification" in item for item in errors))

        result["claimBoundary"] = "PHYSICAL_QUALIFICATION"
        errors = self.validate(result)
        self.assertTrue(any("review-only" in item for item in errors), errors)

        e3_hardware = self.result(
            subject="QMAN_END_TO_END",
            grade="E3",
            product_cases=["C12"],
            risks=[],
        )
        e3_hardware["mapping"]["caseIds"] = ["C12"]
        errors = self.validate(e3_hardware)
        self.assertTrue(any("hardware-blocked cases" in item for item in errors))

    def test_risk_or_status_closure_requires_end_to_end_boundary(self) -> None:
        for risks, status_updated in ((["R17"], False), ([], True)):
            with self.subTest(risks=risks, status_updated=status_updated):
                result = self.result(
                    subject="QMAN_END_TO_END",
                    grade="E3",
                    product_cases=[],
                    risks=risks,
                    status_updated=status_updated,
                )
                result["claimBoundary"] = "COMPONENT_ONLY"
                errors = self.validate(result)
                self.assertTrue(
                    any("requires an end-to-end claim boundary" in item for item in errors)
                )

    def test_e3_product_evidence_may_close_non_e4_risk(self) -> None:
        errors = self.validate(
            self.result(
                subject="QMAN_END_TO_END",
                grade="E3",
                product_cases=["S15"],
                risks=["R17"],
            )
        )
        self.assertEqual(errors, [])

    def test_input_hash_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.json").write_text("{}\n", encoding="utf-8")
            errors: list[str] = []
            with patch.object(evaluate_release, "ROOT", root):
                evaluate_release.validate_qman_input_hashes(
                    "QMAN-TEST-001",
                    {"fixture.json": "0" * 64},
                    errors,
                )

        self.assertTrue(any("input hash drift" in item for item in errors))


class AcceptanceDependencyPolicyTests(unittest.TestCase):
    @staticmethod
    def case(
        case_id: str,
        *,
        dependencies: list[str],
        status: str = "IMPLEMENTATION_BLOCKED",
        scope: str = "PRODUCT",
        tech_stories: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "id": case_id,
            "status": status,
            "scope": scope,
            "requiredTechStories": tech_stories or ["TS-F1-01"],
            "dependsOnCaseIds": dependencies,
        }

    def validate(
        self,
        definitions: dict[str, dict[str, object]],
        design_cases: set[str],
        known_tech_stories: set[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        blockers: list[str] = []
        evaluate_release.validate_acceptance_dependencies(
            definitions,
            design_cases,
            known_tech_stories or {"TS-F1-01"},
            errors,
            blockers,
        )
        return errors, blockers

    def test_undefined_and_unready_design_dependencies_are_only_blockers(self) -> None:
        definitions = {
            "C21": self.case("C21", dependencies=["C10"]),
            "S15": self.case("S15", dependencies=["C21"]),
        }
        errors, blockers = self.validate(definitions, {"C10", "C21", "S15"})

        self.assertEqual(errors, [])
        self.assertIn("acceptance dependency is not defined: C21 -> C10", blockers)
        self.assertIn(
            "acceptance dependency is not closure-ready: "
            "S15 -> C21 (IMPLEMENTATION_BLOCKED)",
            blockers,
        )

    def test_reference_executable_cannot_satisfy_product_dependency(self) -> None:
        definitions = {
            "C20": self.case(
                "C20",
                dependencies=[],
                status="EXECUTABLE",
                scope="REFERENCE_MODEL",
            ),
            "C21": self.case("C21", dependencies=["C20"]),
        }
        errors, blockers = self.validate(definitions, {"C20", "C21"})

        self.assertEqual(errors, [])
        self.assertIn(
            "product acceptance dependency is reference-only: C21 -> C20",
            blockers,
        )

    def test_unknown_ts_unknown_case_and_self_dependency_are_invalid(self) -> None:
        definitions = {
            "C21": self.case(
                "C21",
                dependencies=["C21", "C99"],
                tech_stories=["TS-NOT-DEFINED"],
            )
        }
        errors, _ = self.validate(definitions, {"C21"})

        self.assertTrue(any("unknown tech stories" in item for item in errors))
        self.assertTrue(any("cannot depend on itself" in item for item in errors))
        self.assertTrue(any("unknown dependency cases" in item for item in errors))

    def test_dependency_graph_cycle_is_invalid(self) -> None:
        definitions = {
            "C21": self.case(
                "C21", dependencies=["S15"], status="EXECUTABLE"
            ),
            "S15": self.case(
                "S15", dependencies=["C21"], status="EXECUTABLE"
            ),
        }
        errors, blockers = self.validate(definitions, {"C21", "S15"})

        self.assertTrue(any("dependency graph contains a cycle" in item for item in errors))
        self.assertEqual(blockers, [])

    def test_dependency_fields_are_required_even_when_empty(self) -> None:
        definitions = {
            "C20": {
                "id": "C20",
                "status": "EXECUTABLE",
                "scope": "REFERENCE_MODEL",
            }
        }
        errors, _ = self.validate(definitions, {"C20"})

        self.assertTrue(any("requiredTechStories must be a string list" in item for item in errors))
        self.assertTrue(any("dependsOnCaseIds must be a string list" in item for item in errors))

    def test_dependency_arrays_may_be_empty(self) -> None:
        definitions = {
            "C20": {
                "id": "C20",
                "status": "EXECUTABLE",
                "scope": "REFERENCE_MODEL",
                "requiredTechStories": [],
                "dependsOnCaseIds": [],
            }
        }
        errors, blockers = self.validate(definitions, {"C20"})

        self.assertEqual(errors, [])
        self.assertEqual(blockers, [])


class RiskEvidencePolicyTests(unittest.TestCase):
    @staticmethod
    def design() -> evaluate_release.DesignContracts:
        return evaluate_release.DesignContracts(
            risks={
                "R17": {
                    "title": "runtime eject",
                    "impact": "unsafe release",
                    "prevention": "gate",
                    "detection": "negative case",
                }
            },
            cases=("S15",),
        )

    def test_closed_risk_rejects_unknown_grade_test_and_unindexed_hash(self) -> None:
        policy = {
            "schemaVersion": 1,
            "expectedRiskCount": 1,
            "records": [
                {
                    "id": "R17",
                    "status": "VERIFIED",
                    "owner": "security",
                    "containmentRecovery": "disable runtime eject",
                    "testIds": ["NOT-A-CASE"],
                    "evidenceGrade": "BANANA",
                    "artifactHashes": ["0" * 64],
                }
            ],
        }
        errors: list[str] = []
        blockers: list[str] = []
        evaluate_release.validate_risks(
            policy,
            self.design(),
            {},
            errors,
            blockers,
        )
        self.assertTrue(any("unknown product test IDs" in item for item in errors))
        self.assertTrue(any("invalid evidenceGrade" in item for item in errors))
        self.assertTrue(any("Qman-closure-evidence" in item for item in blockers))

    def test_risks_consume_only_fully_validated_qman_receipts(self) -> None:
        index = json.loads(
            (ROOT / "contracts" / "qman-evidence-index.json").read_text(
                encoding="utf-8"
            )
        )
        schema = json.loads(
            (ROOT / "contracts" / "qman-technical-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        ipd = json.loads(
            (ROOT / "contracts" / "ipd-tree.json").read_text(encoding="utf-8")
        )
        design = evaluate_release.extract_design_contracts(
            ROOT / "qemu-static-dynamic-directpath-design.md"
        )
        record = copy.deepcopy(
            next(
                item
                for item in index["records"]
                if item["id"] == "QMAN-E3-QMP-GATE-001"
            )
        )
        index["records"] = [record]
        source_result_path = ROOT / record["resultPath"]
        baseline = json.loads(source_result_path.read_text(encoding="utf-8"))
        baseline["subject"] = "QMAN_END_TO_END"
        baseline["claimBoundary"] = "END_TO_END_PRODUCT"
        baseline["sourceState"]["dirtyWorkingTree"] = False
        committed_path = ROOT / "tools" / "evaluate_release.py"
        baseline["artifacts"] = [
            {
                "path": "tools/evaluate_release.py",
                "sha256": hashlib.sha256(committed_path.read_bytes()).hexdigest(),
                "retention": "COMMITTED",
            }
        ]
        baseline["closureEffect"] = {
            "productCasesClosed": [],
            "risksClosed": ["R17"],
            "statusUpdated": False,
        }
        record["subject"] = "QMAN_END_TO_END"

        with tempfile.TemporaryDirectory(
            prefix=".qman-receipt-", dir=ROOT / "evidence"
        ) as temporary:
            result_path = Path(temporary) / "result.json"
            result_relative = result_path.relative_to(ROOT).as_posix()
            record["resultPath"] = result_relative

            def payload_for(candidate: dict) -> bytes:
                return (
                    json.dumps(candidate, sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")

            def produce(
                result_mutation=None,
                record_mutation=None,
            ) -> tuple[
                dict[str, list[evaluate_release.QmanRiskClosureReceipt]],
                list[str],
                str,
            ]:
                candidate = copy.deepcopy(baseline)
                candidate_record = copy.deepcopy(record)
                if result_mutation is not None:
                    result_mutation(candidate)
                payload = payload_for(candidate)
                result_path.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                candidate_record["resultSha256"] = digest
                if record_mutation is not None:
                    record_mutation(candidate_record)
                candidate_index = copy.deepcopy(index)
                candidate_index["records"] = [candidate_record]
                receipts: dict[
                    str, list[evaluate_release.QmanRiskClosureReceipt]
                ] = {}
                evidence_errors: list[str] = []
                evaluate_release.validate_qman_evidence(
                    candidate_index,
                    schema,
                    ipd,
                    design,
                    evidence_errors,
                    receipts,
                )
                return receipts, evidence_errors, digest

            receipts, evidence_errors, expected_digest = produce()
            self.assertEqual([], evidence_errors)
            self.assertEqual(1, len(receipts["R17"]))
            self.assertEqual(expected_digest, receipts["R17"][0].result_sha256)

            invalid_mutations = (
                (
                    "component",
                    lambda result: result.update(
                        subject="QMAN_COMPONENT", claimBoundary="COMPONENT_ONLY"
                    ),
                    lambda item: item.update(subject="QMAN_COMPONENT"),
                ),
                (
                    "fail-verdict",
                    lambda result: result.update(verdict="FAIL"),
                    lambda item: item.update(verdict="FAIL"),
                ),
                (
                    "hash-drift",
                    None,
                    lambda item: item.update(resultSha256="0" * 64),
                ),
                (
                    "e4-review-only",
                    lambda result: (
                        result.update(
                            evidenceGrade="E4",
                            claimBoundary="PHYSICAL_QUALIFICATION",
                        ),
                        result["mapping"].update(riskIds=["R27"]),
                        result["closureEffect"].update(risksClosed=["R27"]),
                    ),
                    lambda item: item.update(
                        evidenceGrade="E4", riskIds=["R27"]
                    ),
                ),
            )
            for name, result_mutation, record_mutation in invalid_mutations:
                with self.subTest(invalid_qman_record=name):
                    invalid_receipts, evidence_errors, _ = produce(
                        result_mutation, record_mutation
                    )
                    self.assertTrue(evidence_errors)
                    self.assertEqual({}, invalid_receipts)

            safe_candidate = copy.deepcopy(baseline)
            safe_candidate["closureEffect"] = {
                "productCasesClosed": [],
                "risksClosed": [],
                "statusUpdated": False,
            }
            safe_payload = payload_for(safe_candidate)
            malicious_payload = payload_for(baseline)
            result_path.write_bytes(malicious_payload)
            changing_record = copy.deepcopy(record)
            changing_record["resultSha256"] = hashlib.sha256(
                safe_payload
            ).hexdigest()
            changing_index = copy.deepcopy(index)
            changing_index["records"] = [changing_record]
            original_read_bytes = Path.read_bytes
            result_reads = 0

            def changing_read(path: Path) -> bytes:
                nonlocal result_reads
                if path.resolve() == result_path.resolve():
                    result_reads += 1
                    return safe_payload if result_reads == 1 else malicious_payload
                return original_read_bytes(path)

            changing_receipts: dict[
                str, list[evaluate_release.QmanRiskClosureReceipt]
            ] = {}
            changing_errors: list[str] = []
            with patch.object(Path, "read_bytes", autospec=True, side_effect=changing_read):
                evaluate_release.validate_qman_evidence(
                    changing_index,
                    schema,
                    ipd,
                    design,
                    changing_errors,
                    changing_receipts,
                )
            self.assertEqual([], changing_errors)
            self.assertEqual(1, result_reads)
            self.assertEqual({}, changing_receipts)

            policy = {
                "schemaVersion": 1,
                "expectedRiskCount": 1,
                "records": [
                    {
                        "id": "R17",
                        "status": "VERIFIED",
                        "owner": "Security Owner",
                        "containmentRecovery": "disable runtime eject",
                        "testIds": ["S15"],
                        "evidenceGrade": "E3",
                        "artifactHashes": [expected_digest],
                    }
                ],
            }
            receipt_errors: list[str] = []
            receipt_blockers: list[str] = []
            counts = evaluate_release.validate_risks(
                policy,
                self.design(),
                receipts,
                receipt_errors,
                receipt_blockers,
            )
            self.assertEqual([], receipt_errors)
            self.assertEqual([], receipt_blockers)
            self.assertEqual(1, counts["VERIFIED"])

            no_receipt_blockers: list[str] = []
            evaluate_release.validate_risks(
                policy,
                self.design(),
                {},
                [],
                no_receipt_blockers,
            )
            self.assertTrue(
                any(
                    "Qman-closure-evidence" in item
                    for item in no_receipt_blockers
                )
            )


if __name__ == "__main__":
    unittest.main()
