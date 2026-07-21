from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "acceptance" / "cases"
sys.path.insert(0, str(ROOT / "tools"))
import evaluate_release  # noqa: E402
import generate_vmware_evidence_index  # noqa: E402


def load_case_definitions() -> dict[str, dict[str, object]]:
    definitions: dict[str, dict[str, object]] = {}
    for path in sorted(CASES.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload.get("records", [payload])
        if not isinstance(records, list):
            raise AssertionError(f"{path.name} records is not a list")
        for record in records:
            if not isinstance(record, dict):
                raise AssertionError(f"{path.name} contains a non-object record")
            case_id = record.get("id")
            if not isinstance(case_id, str):
                raise AssertionError(f"{path.name} contains a record without an ID")
            if case_id in definitions:
                raise AssertionError(f"duplicate Case ID {case_id}")
            definitions[case_id] = record
    return definitions


class AcceptanceGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (ROOT / "contracts" / "acceptance-policy.json").read_text(
                encoding="utf-8"
            )
        )
        cls.design = evaluate_release.extract_design_contracts(
            ROOT / cls.policy["sourceDocument"]
        )
        cls.cases = load_case_definitions()
        tree = json.loads(
            (ROOT / "contracts" / "ipd-tree.json").read_text(encoding="utf-8")
        )
        cls.tech_story_ids = {
            story["id"]
            for feature in tree["features"]
            for story in feature.get("techStories", [])
        }
        risk_policy = json.loads(
            (ROOT / "contracts" / "risk-status.json").read_text(encoding="utf-8")
        )
        cls.risk_ids = {record["id"] for record in risk_policy["records"]}

    def test_all_101_design_cases_are_explicitly_classified(self) -> None:
        self.assertEqual(101, self.policy["expectedCaseCount"])
        self.assertFalse(self.policy["wildcardsAllowed"])
        self.assertEqual(set(self.design.cases), set(self.cases))
        self.assertEqual(101, len(self.cases))
        self.assertTrue(all("*" not in case_id for case_id in self.cases))
        self.assertEqual(
            Counter(
                {
                    "EXECUTABLE": 2,
                    "IMPLEMENTATION_BLOCKED": 93,
                    "HARDWARE_BLOCKED": 6,
                }
            ),
            Counter(case["status"] for case in self.cases.values()),
        )

    def test_evaluator_expands_single_objects_and_explicit_records_arrays(self) -> None:
        errors: list[str] = []
        blockers: list[str] = []
        counts, missing, executable = evaluate_release.validate_acceptance(
            self.policy,
            self.design,
            self.risk_ids,
            self.tech_story_ids,
            errors,
            blockers,
        )
        self.assertEqual([], errors)
        self.assertEqual([], missing)
        self.assertEqual(101, sum(counts.values()))
        self.assertEqual({"C20", "O09"}, set(executable))
        self.assertTrue(blockers, "classified cases must still block release until closed")

        candidate = copy.deepcopy(self.policy)
        candidate["caseDefinitionDirectory"] = (
            f"../{ROOT.name}/acceptance/cases"
        )
        errors = []
        evaluate_release.validate_acceptance(
            candidate,
            self.design,
            self.risk_ids,
            self.tech_story_ids,
            errors,
            [],
        )
        self.assertTrue(any("path traversal" in error for error in errors), errors)

        cwd_errors: list[str] = []
        self.assertIsNone(
            evaluate_release.repository_directory(
                f"../{ROOT.name}/pci-resource-model",
                "runner cwd",
                cwd_errors,
            )
        )
        self.assertTrue(any("path traversal" in error for error in cwd_errors))

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            repository = temporary_root / "repository"
            case_directory = repository / "cases"
            case_directory.mkdir(parents=True)
            outside = temporary_root / "outside.json"
            outside.write_text('{"id": "C00"}\n', encoding="utf-8")
            invalid_json = repository / "duplicate.json"
            invalid_json.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate object key"):
                generate_vmware_evidence_index.load_json(invalid_json)
            linked_case = case_directory / "linked.json"
            try:
                linked_case.symlink_to(outside)
            except OSError:
                linked_case = None
            if linked_case is not None:
                candidate = copy.deepcopy(self.policy)
                candidate["caseDefinitionDirectory"] = "cases"
                errors = []
                with mock.patch.object(evaluate_release, "ROOT", repository):
                    _, _, executable = evaluate_release.validate_acceptance(
                        candidate,
                        self.design,
                        self.risk_ids,
                        self.tech_story_ids,
                        errors,
                        [],
                    )
                    derived = (
                        evaluate_release._acceptance_definitions_for_vmware_trace(
                            candidate, errors
                        )
                    )
                self.assertEqual({}, executable)
                self.assertEqual({}, derived)
                self.assertTrue(
                    any("symbolic link" in error for error in errors), errors
                )
                with mock.patch.object(
                    generate_vmware_evidence_index, "ROOT", repository
                ):
                    with self.assertRaisesRegex(ValueError, "symbolic link"):
                        generate_vmware_evidence_index.acceptance_definitions(
                            candidate
                        )
                contract_directory = repository / "contracts"
                contract_directory.mkdir()
                outside_output = temporary_root / "outside-index.json"
                outside_output.write_text("{}\n", encoding="utf-8")
                linked_output = contract_directory / "vmware-evidence-index.json"
                linked_output.symlink_to(outside_output)
                with mock.patch.object(
                    generate_vmware_evidence_index, "ROOT", repository
                ):
                    with self.assertRaisesRegex(ValueError, "symbolic link"):
                        generate_vmware_evidence_index.repository_output_file(
                            "contracts/vmware-evidence-index.json",
                            "VMware evidence index",
                        )

    def test_every_case_has_management_and_traceability_fields(self) -> None:
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                self.assertIn(case["status"], self.policy["allowedStatuses"])
                self.assertIn(case["scope"], {"PRODUCT", "REFERENCE_MODEL"})
                self.assertTrue(case["riskIds"])
                self.assertEqual(len(case["riskIds"]), len(set(case["riskIds"])))
                self.assertTrue(set(case["riskIds"]) <= self.risk_ids)
                self.assertIsInstance(case["requiredTechStories"], list)
                self.assertEqual(
                    len(case["requiredTechStories"]),
                    len(set(case["requiredTechStories"])),
                )
                self.assertTrue(
                    set(case["requiredTechStories"]) <= self.tech_story_ids
                )
                self.assertIsInstance(case["dependsOnCaseIds"], list)
                self.assertEqual(
                    len(case["dependsOnCaseIds"]),
                    len(set(case["dependsOnCaseIds"])),
                )
                self.assertNotIn(case_id, case["dependsOnCaseIds"])
                self.assertTrue(set(case["dependsOnCaseIds"]) <= set(self.cases))
                self.assertTrue(str(case["blocker"]).strip())
                self.assertRegex(str(case["targetMilestone"]), r"^G[0-6]$")

    def test_hardware_blocked_is_limited_to_physical_final_qualification(self) -> None:
        hardware_blocked = {
            case_id
            for case_id, case in self.cases.items()
            if case["status"] == "HARDWARE_BLOCKED"
        }
        self.assertEqual(
            {"C12", "M08", "M12", "M13", "S06", "S08"},
            hardware_blocked,
        )
        out_of_scope_without_product_negative_gate = {
            "S09",
            "S10",
            "S13",
            "S14",
            "S15",
            "S16",
            "F03",
            "F07",
            "F08",
            "F09",
        }
        for case_id in out_of_scope_without_product_negative_gate:
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    "IMPLEMENTATION_BLOCKED", self.cases[case_id]["status"]
                )
        self.assertNotIn(
            "FEATURE_DISABLED", {case["status"] for case in self.cases.values()}
        )

    def test_latest_multi_host_boundary_is_explicit(self) -> None:
        required_terms = {
            "F03": ("stopped", "takeover", "reassignment"),
            "F04": ("stale", "logical", "epoch"),
            "F05": ("both hosts online", "source release", "target reserve"),
            "F06": ("exhaustion", "stopped"),
            "F08": ("migration backend", "disabled", "negative gate"),
        }
        for case_id, terms in required_terms.items():
            text = (
                f"{self.cases[case_id]['title']} {self.cases[case_id]['blocker']}"
            ).lower()
            with self.subTest(case_id=case_id):
                for term in terms:
                    self.assertIn(term, text)


class RiskGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (ROOT / "contracts" / "risk-status.json").read_text(encoding="utf-8")
        )
        cls.cases = load_case_definitions()

    def test_all_39_risks_have_open_governance_without_false_evidence(self) -> None:
        records = self.policy["records"]
        self.assertEqual(39, len(records))
        self.assertEqual(
            {f"R{index:02d}" for index in range(1, 40)},
            {record["id"] for record in records},
        )
        for record in records:
            with self.subTest(risk_id=record["id"]):
                self.assertEqual("OPEN", record["status"])
                self.assertRegex(record["owner"], r"Owner$")
                self.assertTrue(record["containmentRecovery"].strip())
                self.assertTrue(record["testIds"])
                self.assertEqual(len(record["testIds"]), len(set(record["testIds"])))
                self.assertTrue(set(record["testIds"]) <= set(self.cases))
                for case_id in record["testIds"]:
                    self.assertIn(record["id"], self.cases[case_id]["riskIds"])
                self.assertEqual("NONE", record["evidenceGrade"])
                self.assertEqual([], record["artifactHashes"])

    def test_evaluator_rejects_ungoverned_or_evidence_claiming_open_risk(self) -> None:
        design = evaluate_release.DesignContracts(
            risks={
                "R01": {
                    "title": "isolation",
                    "impact": "unsafe DMA",
                    "prevention": "deny",
                    "detection": "negative case",
                }
            },
            cases=("C00",),
        )
        policy = {
            "schemaVersion": 1,
            "expectedRiskCount": 1,
            "records": [
                {
                    "id": "R01",
                    "status": "OPEN",
                    "owner": None,
                    "containmentRecovery": "",
                    "testIds": [],
                    "evidenceGrade": "E3",
                    "artifactHashes": ["0" * 64],
                }
            ],
        }
        errors: list[str] = []
        blockers: list[str] = []
        evaluate_release.validate_risks(
            policy, design, {}, errors, blockers
        )
        expected_fragments = (
            "accountable owner role",
            "containmentRecovery",
            "at least one design Case ID",
            "evidenceGrade must be NONE",
            "artifactHashes must be empty",
        )
        for fragment in expected_fragments:
            self.assertTrue(
                any(fragment in error for error in errors),
                f"missing evaluator error containing {fragment!r}: {errors}",
            )
        self.assertIn("blocking risk states: 1/1 records", blockers)


if __name__ == "__main__":
    unittest.main()
