import io
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import evaluate_release  # noqa: E402


class PortableReleaseGateTests(unittest.TestCase):
    @staticmethod
    def valid_evaluation() -> evaluate_release.Evaluation:
        """Return a small valid result so main() tests do not run the full evaluator."""

        return evaluate_release.Evaluation(
            errors=[],
            blockers=[],
            project={},
            ipd_counts=Counter(),
            vmware_counts=Counter(),
            qman_evidence_counts=Counter(),
            risk_counts=Counter(),
            acceptance_counts=Counter(),
            risk_total=0,
            case_total=0,
            missing_cases=[],
            executable_cases={},
        )

    @staticmethod
    def successful_portable_process() -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["validate_portable_handoff.py"],
            returncode=0,
            stdout="portable handoff semantic validation PASS\n",
            stderr="",
        )

    def invoke_main(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with patch.object(sys, "argv", ["evaluate_release.py", *args]), redirect_stdout(
            output
        ):
            return evaluate_release.main(), output.getvalue()

    def test_status_evaluation_calls_valid_repository_baseline_gate(self) -> None:
        """The status path must execute, and accept, the checked-in baseline map."""

        completed = evaluate_release.run_portable_handoff_gate("baseline")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("PASS (baseline)", completed.stdout)
        with patch.object(
            evaluate_release,
            "run_portable_handoff_gate",
            return_value=completed,
        ) as portable_gate:
            result = evaluate_release._evaluate_unchecked()

        portable_gate.assert_called_once_with("baseline")
        portable_errors = [
            error for error in result.errors if error.startswith("portable handoff:")
        ]
        self.assertEqual(portable_errors, [], "\n".join(portable_errors))

    def test_default_unmapped_template_blocks_release_before_cases(self) -> None:
        with (
            patch.object(evaluate_release, "evaluate", return_value=self.valid_evaluation()),
            patch.object(
                evaluate_release,
                "run_portable_handoff_gate",
                return_value=self.successful_portable_process(),
            ) as portable_gate,
            patch.object(evaluate_release, "run_case") as run_case,
        ):
            returncode, output = self.invoke_main("release")

        self.assertNotEqual(returncode, 0)
        self.assertIn("Portable release gate: BLOCKED", output)
        self.assertIn("TARGET_CODE_MAPPED", output)
        portable_gate.assert_called_once_with(
            "all",
            map_path="contracts/qman-integration-map.template.json",
            trusted_root_digest=None,
            external_rollback_anchor=None,
            external_catalog_anchor=None,
            trust_anchor_freshness_envelope=None,
            catalog_anchor_freshness_envelope=None,
            verifier_nonce=None,
        )
        run_case.assert_not_called()

    def test_release_axes_require_each_of_four_axes_to_be_true(self) -> None:
        expected = {
            "PORTABLE_SPEC_READY": True,
            "TARGET_CODE_MAPPED": True,
            "PRODUCT_IMPLEMENTED": True,
            "QUALIFIED": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            map_path = Path(directory) / "detached-map.json"
            with patch.object(evaluate_release, "ROOT", Path(directory)):
                map_path.write_text(
                    json.dumps({"statusAxes": expected}), encoding="utf-8"
                )
                self.assertEqual(
                    evaluate_release.validate_portable_release_axes(str(map_path)), []
                )

                all_false = dict.fromkeys(expected, False)
                map_path.write_text(
                    json.dumps({"statusAxes": all_false}), encoding="utf-8"
                )
                errors = evaluate_release.validate_portable_release_axes(str(map_path))
                self.assertEqual(len(errors), 1)
                self.assertIn("must exactly equal", errors[0])

                for axis in expected:
                    with self.subTest(false_axis=axis):
                        one_false = dict(expected)
                        one_false[axis] = False
                        map_path.write_text(
                            json.dumps({"statusAxes": one_false}), encoding="utf-8"
                        )
                        errors = evaluate_release.validate_portable_release_axes(
                            str(map_path)
                        )
                        self.assertEqual(len(errors), 1)
                        self.assertIn(axis, errors[0])

    def test_unresolvable_external_map_path_fails_release_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_map = Path(directory) / "not-created.json"
            with (
                patch.object(
                    evaluate_release, "evaluate", return_value=self.valid_evaluation()
                ),
                patch.object(
                    evaluate_release,
                    "run_portable_handoff_gate",
                    return_value=self.successful_portable_process(),
                ),
                patch.object(evaluate_release, "run_case") as run_case,
            ):
                returncode, output = self.invoke_main(
                    "release", "--map", str(missing_map)
                )

        self.assertNotEqual(returncode, 0)
        self.assertIn("Portable release gate: BLOCKED", output)
        self.assertIn("cannot load detached integration map", output)
        self.assertIn(str(missing_map), output)
        run_case.assert_not_called()


if __name__ == "__main__":
    unittest.main()
