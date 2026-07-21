from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "acceptance" / "cases"


class StaticFaultAcceptanceContractsTest(unittest.TestCase):
    EXPECTED = {
        "S03": {
            "dependencies": ["C21"],
            "techStories": {
                "TS-F3-02",
                "TS-F3-03",
                "TS-F3-05",
                "TS-F5-02",
                "TS-F5-04",
            },
        },
        "S04": {
            "dependencies": ["S03"],
            "techStories": {"TS-F3-05", "TS-F5-01", "TS-F5-04"},
        },
        "S05": {
            "dependencies": ["S03", "S04"],
            "techStories": {"TS-F3-03", "TS-F3-05", "TS-F5-02", "TS-F5-04"},
        },
        "F00": {
            "dependencies": ["S05"],
            "techStories": {"TS-F3-05", "TS-F5-02", "TS-F5-03", "TS-F5-04"},
        },
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (ROOT / "contracts" / "acceptance-policy.json").read_text(encoding="utf-8")
        )
        tree = json.loads((ROOT / "contracts" / "ipd-tree.json").read_text(encoding="utf-8"))
        cls.tech_story_ids = {
            story["id"]
            for feature in tree["features"]
            for story in feature.get("techStories", [])
        }
        risks = json.loads(
            (ROOT / "contracts" / "risk-status.json").read_text(encoding="utf-8")
        )
        cls.risk_ids = {record["id"] for record in risks["records"]}

    def load_case(self, case_id: str) -> dict[str, object]:
        return json.loads((CASES / f"{case_id}.json").read_text(encoding="utf-8"))

    def test_policy_requires_v2_dependency_fields(self) -> None:
        self.assertEqual(2, self.policy["schemaVersion"])
        self.assertEqual(
            {"requiredTechStories", "dependsOnCaseIds"},
            set(self.policy["dependencyPolicy"]["requiredFields"]),
        )

    def test_static_fault_cases_are_product_blocked_component_premises(self) -> None:
        for case_id in self.EXPECTED:
            with self.subTest(case_id=case_id):
                case = self.load_case(case_id)
                self.assertEqual(case_id, case["id"])
                self.assertEqual("IMPLEMENTATION_BLOCKED", case["status"])
                self.assertEqual("PRODUCT", case["scope"])
                self.assertEqual("G2", case["targetMilestone"])
                self.assertEqual(
                    "COMPONENT_ONLY_PREMISE_NOT_PRODUCT_CLOSURE",
                    case["proofBoundary"],
                )
                self.assertTrue(case["blocker"])
                self.assertGreaterEqual(len(case["assertions"]), 4)

    def test_dependency_chain_is_exact_and_acyclic(self) -> None:
        for case_id, expected in self.EXPECTED.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    expected["dependencies"], self.load_case(case_id)["dependsOnCaseIds"]
                )

        visited: set[str] = set()
        active: set[str] = set()

        def visit(case_id: str) -> None:
            self.assertNotIn(case_id, active, f"dependency cycle at {case_id}")
            if case_id in visited or case_id not in self.EXPECTED:
                return
            active.add(case_id)
            for dependency in self.load_case(case_id)["dependsOnCaseIds"]:
                visit(dependency)
            active.remove(case_id)
            visited.add(case_id)

        for case_id in self.EXPECTED:
            visit(case_id)

    def test_tech_stories_and_risks_are_known(self) -> None:
        for case_id, expected in self.EXPECTED.items():
            with self.subTest(case_id=case_id):
                case = self.load_case(case_id)
                self.assertEqual(expected["techStories"], set(case["requiredTechStories"]))
                self.assertTrue(set(case["requiredTechStories"]) <= self.tech_story_ids)
                self.assertTrue(case["riskIds"])
                self.assertTrue(set(case["riskIds"]) <= self.risk_ids)


if __name__ == "__main__":
    unittest.main()
