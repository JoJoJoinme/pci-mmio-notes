from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evaluate_release  # noqa: E402
import generate_vmware_evidence_index  # noqa: E402


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class VMwareEvidenceIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = load("contracts/vmware-evidence-index.json")
        cls.model = load("contracts/vmware-behavior-model.json")
        cls.acceptance = load("contracts/acceptance-policy.json")
        cls.project = load("contracts/project-status.json")
        cls.sources = load("contracts/vmware-source-register.json")
        cls.result_schema = load("contracts/vmware-experiment-result.schema.json")
        cls.ipd = load("contracts/ipd-tree.json")

    def validate(
        self,
        candidate: dict,
        model: dict | None = None,
        project: dict | None = None,
    ) -> tuple[dict, list[str]]:
        errors: list[str] = []
        counts = evaluate_release.validate_vmware_evidence_index(
            candidate,
            self.model if model is None else model,
            self.acceptance,
            self.project if project is None else project,
            errors,
        )
        return counts, errors

    def test_index_is_complete_hash_checked_and_non_closing(self) -> None:
        counts, errors = self.validate(self.index)
        self.assertEqual([], errors)
        self.assertEqual(36, counts["records"])
        self.assertEqual(28, counts["evidence_bound"])
        self.assertEqual(8, counts["no_run"])
        self.assertGreater(counts["artifacts"], counts["evidence_bound"])
        policy = self.index["tracePolicy"]
        self.assertEqual("NONE", policy["acceptanceClosureAuthority"])
        self.assertEqual("NONE", policy["qmanImplementationClosureAuthority"])
        self.assertEqual("NONE", policy["qmanQualificationClosureAuthority"])

    def test_trace_experiment_is_partial_not_observed(self) -> None:
        experiments = {item["id"]: item for item in self.model["experiments"]}
        trace = experiments["VMW-TRACE-001"]
        self.assertEqual("PARTIAL", trace["executionState"])
        self.assertIn("pyvmomi-task-id-and-actor-chain-incomplete", trace["limitations"])
        coverage = {
            item["techStoryId"]: item for item in self.model["techStoryCoverage"]
        }
        self.assertEqual("PARTIAL", coverage["TS-F8-03"]["status"])

    def test_acceptance_links_are_derived_reference_links_only(self) -> None:
        records = {item["experimentId"]: item for item in self.index["records"]}
        self.assertIn("C00", records["VMW-CAP-001"]["derivedAcceptanceCaseIds"])
        self.assertEqual(
            ["F03", "F04", "F05", "F06"],
            records["VMW-COLD-CLEAN-001"]["derivedAcceptanceCaseIds"],
        )
        self.assertEqual([], records["VMW-TRACE-001"]["derivedAcceptanceCaseIds"])

    def test_hash_drift_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.index)
        record = next(item for item in candidate["records"] if item["evidence"])
        record["evidence"][0]["sha256"] = "0" * 64
        _, errors = self.validate(candidate)
        self.assertTrue(any("artifact hash drift" in error for error in errors), errors)

        for alias_kind in ("absolute", "parent"):
            with self.subTest(alias_kind=alias_kind):
                candidate = copy.deepcopy(self.index)
                model = copy.deepcopy(self.model)
                record = next(item for item in candidate["records"] if item["evidence"])
                artifact = record["evidence"][0]
                original = artifact["path"]
                if alias_kind == "absolute":
                    alias = str((ROOT / original).resolve())
                else:
                    alias = f"../{ROOT.name}/{original}"
                artifact["path"] = alias
                experiment = next(
                    item
                    for item in model["experiments"]
                    if item["id"] == record["experimentId"]
                )
                experiment["evidencePaths"] = [
                    alias if path == original else path
                    for path in experiment["evidencePaths"]
                ]
                experiment["evidenceSha256"][alias] = experiment[
                    "evidenceSha256"
                ].pop(original)
                _, errors = self.validate(candidate, model)
                self.assertTrue(
                    any(
                        "repository-relative" in error or "path traversal" in error
                        for error in errors
                    ),
                    errors,
                )

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            repository = temporary_root / "repository"
            repository.mkdir()
            outside = temporary_root / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = repository / "evidence-link"
            try:
                link.symlink_to(outside)
            except OSError:
                link = None
            if link is not None:
                errors = []
                with mock.patch.object(evaluate_release, "ROOT", repository):
                    resolved = evaluate_release.repository_file(
                        "evidence-link", "test evidence path", errors
                    )
                self.assertIsNone(resolved)
                self.assertTrue(
                    any(
                        "escapes the repository" in error
                        or "must not be a symbolic link" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_missing_experiment_and_derived_case_drift_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.index)
        candidate["records"].pop()
        candidate["recordCount"] -= 1
        _, errors = self.validate(candidate)
        self.assertTrue(any("missing experiments" in error for error in errors), errors)

        candidate = copy.deepcopy(self.index)
        candidate["records"][0]["derivedAcceptanceCaseIds"] = []
        _, errors = self.validate(candidate)
        self.assertTrue(
            any("derivedAcceptanceCaseIds drift" in error for error in errors),
            errors,
        )

    def test_no_run_and_non_closure_policies_fail_closed(self) -> None:
        candidate = copy.deepcopy(self.index)
        planned = next(
            item
            for item in candidate["records"]
            if item["executionState"] == "PLANNED"
        )
        planned["runIds"] = ["invented-run"]
        _, errors = self.validate(candidate)
        self.assertTrue(any("cannot bind runs or artifacts" in error for error in errors))

        candidate = copy.deepcopy(self.index)
        candidate["tracePolicy"]["qmanImplementationClosureAuthority"] = "ALLOW"
        _, errors = self.validate(candidate)
        self.assertTrue(any("non-closing semantics" in error for error in errors))

        mutations = (
            ("root", lambda item: item.__setitem__("productCasesClosed", ["C00"])),
            (
                "record",
                lambda item: item["records"][0].__setitem__(
                    "productCasesClosed", ["C00"]
                ),
            ),
            (
                "artifact",
                lambda item: next(
                    record for record in item["records"] if record["evidence"]
                )["evidence"][0].__setitem__("closureAuthority", "FULL"),
            ),
        )
        for level, mutate in mutations:
            with self.subTest(level=level):
                candidate = copy.deepcopy(self.index)
                mutate(candidate)
                _, errors = self.validate(candidate)
                self.assertTrue(
                    any("fields must" in error for error in errors),
                    errors,
                )

        candidate = copy.deepcopy(self.index)
        trace = next(
            record
            for record in candidate["records"]
            if record["experimentId"] == "VMW-TRACE-001"
        )
        trace["evidence"][0] = {}
        _, errors = self.validate(candidate)
        self.assertTrue(any("artifact" in error for error in errors), errors)

        with mock.patch.dict(generate_vmware_evidence_index.RUN_IDS, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "missing runs"):
                generate_vmware_evidence_index.build()
        with self.assertRaisesRegex(ValueError, "path traversal"):
            generate_vmware_evidence_index.acceptance_definitions(
                {"caseDefinitionDirectory": f"../{ROOT.name}/acceptance/cases"}
            )

        with tempfile.TemporaryDirectory() as temporary:
            deeply_nested = Path(temporary) / "deeply-nested.json"
            deeply_nested.write_text(
                '{"value":' + "[" * 5000 + "0" + "]" * 5000 + "}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "nesting is too deep"):
                generate_vmware_evidence_index.load_json(deeply_nested)

        malformed_models = []
        model = copy.deepcopy(self.model)
        model["techStoryCoverage"] = None
        malformed_models.append(model)
        model = copy.deepcopy(self.model)
        model["techStoryCoverage"][0]["experimentIds"] = None
        malformed_models.append(model)
        model = copy.deepcopy(self.model)
        executed = next(
            experiment
            for experiment in model["experiments"]
            if experiment["executionState"] not in evaluate_release.VMWARE_NO_RUN_STATES
        )
        executed["evidencePaths"] = 123
        malformed_models.append(model)
        for model in malformed_models:
            with self.subTest(malformed_model=True):
                _, errors = self.validate(self.index, model)
                self.assertTrue(errors)

        trace_summary = load("evidence/vmware-trace-index-20260722-summary.json")
        trace_summary["closureAuthority"]["release"] = "FULL"
        original_load_json = evaluate_release.load_json

        def load_with_mutated_trace(path: Path) -> dict:
            if path.name == "vmware-trace-index-20260722-summary.json":
                return trace_summary
            return original_load_json(path)

        with mock.patch.object(
            evaluate_release, "load_json", side_effect=load_with_mutated_trace
        ):
            _, errors = self.validate(self.index)
        self.assertTrue(
            any("closureAuthority must remain NONE" in error for error in errors),
            errors,
        )

        for field in ("coverageStatuses", "truthKinds"):
            with self.subTest(malformed_reference_field=field):
                model = copy.deepcopy(self.model)
                model[field] = 42
                errors = []
                evaluate_release.validate_vmware_reference(
                    model,
                    self.sources,
                    self.result_schema,
                    self.ipd,
                    self.project,
                    errors,
                )
                self.assertTrue(errors)

        model = copy.deepcopy(self.model)
        model["techStoryCoverage"][0]["experimentIds"] = [{}]
        _, errors = self.validate(self.index, model)
        self.assertTrue(errors)

        candidate = copy.deepcopy(self.index)
        candidate["records"][0]["executionState"] = {}
        _, errors = self.validate(candidate)
        self.assertTrue(errors)

        project = copy.deepcopy(self.project)
        project["observations"] = []
        _, errors = self.validate(self.index, project=project)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
