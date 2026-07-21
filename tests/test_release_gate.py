import subprocess
import sys
import tempfile
import unittest
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
            "Qman evidence: records=5 (E2=2, E3=3; reference=5, "
            "product_case_closures=0, risk_closures=0)",
            result.stdout,
        )
        self.assertIn("Risks: 39", result.stdout)
        self.assertIn("Acceptance: 3/101 defined", result.stdout)
        self.assertIn("EXECUTABLE=2", result.stdout)
        self.assertIn("IMPLEMENTATION_BLOCKED=1", result.stdout)
        self.assertIn(
            "reference-only executable cases do not close product gates: C20, O09",
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
        return {
            "subject": subject,
            "evidenceGrade": grade,
            "claimBoundary": (
                "REFERENCE_ONLY"
                if subject.endswith("REFERENCE") or subject == "QMAN_REFERENCE_MODEL"
                else "END_TO_END_PRODUCT"
            ),
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
