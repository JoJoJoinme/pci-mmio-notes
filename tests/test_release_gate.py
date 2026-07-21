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
        self.assertIn("Target release: V3 (SINGLE_TARGET_MULTI_WAVE)", result.stdout)
        self.assertIn(
            "IPD: epics=1, features=8, user_stories=28, tech_stories=39",
            result.stdout,
        )
        self.assertIn(
            "VMware reference: sources=24, experiments=33, tech_stories=39 "
            "(NOT_APPLICABLE=5, PARTIAL=26, UNKNOWN=4, VERIFIED=4)",
            result.stdout,
        )
        self.assertIn(
            "Qman evidence: records=7 (E2=2, E3=5; reference=5, component=2, "
            "end_to_end=0, "
            "product_case_closures=0, risk_closures=0)",
            result.stdout,
        )
        self.assertIn("Risks: 39", result.stdout)
        self.assertIn("Acceptance: 5/101 defined", result.stdout)
        self.assertIn("EXECUTABLE=2", result.stdout)
        self.assertIn("IMPLEMENTATION_BLOCKED=3", result.stdout)
        self.assertIn("96 unclassified", result.stdout)
        self.assertIn(
            "implementation-blocked acceptance cases: C21, F09, S15",
            result.stdout,
        )
        self.assertIn(
            "reference-only executable cases do not close product gates: C20, O09",
            result.stdout,
        )
        self.assertIn(
            "acceptance dependency is not defined: C21 -> C10",
            result.stdout,
        )
        self.assertIn(
            "product acceptance dependency is reference-only: C21 -> C20",
            result.stdout,
        )
        self.assertIn(
            "acceptance dependency is not closure-ready: S15 -> C21 "
            "(IMPLEMENTATION_BLOCKED)",
            result.stdout,
        )
        self.assertIn("Release: BLOCKED", result.stdout)

    def test_release_gate_fails_closed(self) -> None:
        result = self.invoke("release")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Release: BLOCKED", result.stdout)
        self.assertIn("Case C20: PASS", result.stdout)
        self.assertIn("Case O09: PASS", result.stdout)

    def test_o09_is_executable(self) -> None:
        result = self.invoke("run-cases", "--case", "O09")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Case O09: PASS", result.stdout)

    def test_c20_is_executable_reference_scope(self) -> None:
        result = self.invoke("run-cases", "--case", "C20")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Case C20: PASS", result.stdout)

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
            {"records": []},
            errors,
            blockers,
        )
        self.assertTrue(any("unknown product test IDs" in item for item in errors))
        self.assertTrue(any("invalid evidenceGrade" in item for item in errors))
        self.assertTrue(any("Qman-closure-evidence" in item for item in blockers))


if __name__ == "__main__":
    unittest.main()
