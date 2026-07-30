from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator


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
        self.assertEqual(37, counts["records"])
        self.assertEqual(29, counts["evidence_bound"])
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

    def test_qemu_control_reference_is_typed_and_not_vmware_evidence(self) -> None:
        experiments = {item["id"]: item for item in self.model["experiments"]}
        aer = experiments["VMW-AER-COR-001"]
        controls = aer["controlReferences"]
        self.assertEqual(1, len(controls))
        control = controls[0]
        self.assertEqual("QEMU_CONTROL_REFERENCE", control["subject"])
        self.assertEqual("NONE", control["closureAuthority"])
        self.assertNotIn(control["evidencePath"], aer["evidencePaths"])

        record = next(
            item
            for item in self.index["records"]
            if item["experimentId"] == "VMW-AER-COR-001"
        )
        self.assertNotIn(control["evidencePath"], {
            item["path"] for item in record["evidence"]
        })
        self.assertTrue(
            all("qemu" not in run_id.lower() for run_id in record["runIds"])
        )

        model = copy.deepcopy(self.model)
        mutated = next(
            item
            for item in model["experiments"]
            if item["id"] == "VMW-AER-COR-001"
        )
        mutated["controlReferences"][0]["closureAuthority"] = "FULL"
        errors: list[str] = []
        evaluate_release.validate_vmware_reference(
            model,
            self.sources,
            self.result_schema,
            self.ipd,
            self.project,
            errors,
        )
        self.assertTrue(
            any("closureAuthority must remain NONE" in error for error in errors),
            errors,
        )

    def test_v17_o4_root_slice_is_schema_valid_hash_bound_and_non_closing(self) -> None:
        summary_relative = (
            "evidence/esxi8-aer-root-o4-v17-full1-20260729-summary.json"
        )
        result_relative = (
            "evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json"
        )
        campaign_relative = (
            "evidence/esxi8-aer-root-o4-v17-full1-20260729-campaign-result.json"
        )
        summary = load(summary_relative)
        result = load(result_relative)
        schema_errors = sorted(
            Draft202012Validator(self.result_schema).iter_errors(result),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual([], schema_errors)

        self.assertEqual("VMW-AER-COR-001", result["caseId"])
        self.assertEqual("20260729-esxi8-aer-root-o4-v17-full1", result["runId"])
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertEqual("PARTIAL", summary["observationStatus"])
        self.assertTrue(summary["usedForBehaviorInference"])
        self.assertEqual("NONE", summary["closureAuthority"])
        self.assertEqual("O4", summary["canonicalSlice"]["ownerPhase"])
        self.assertEqual("g101", summary["canonicalSlice"]["gate"])
        self.assertEqual("0x0101", summary["canonicalSlice"]["requesterId"])
        self.assertEqual(12, summary["run"]["plannedCaseCount"])
        self.assertEqual(12, summary["run"]["completedCaseCount"])
        self.assertEqual(12, summary["run"]["matchCount"])
        self.assertEqual("FULL_PLAN", summary["run"]["completionClass"])
        self.assertTrue(summary["run"]["fullPlanComplete"])
        self.assertTrue(summary["run"]["fullPlanExecuted"])
        self.assertTrue(summary["run"]["fullProfileConclusionEligible"])
        self.assertTrue(summary["verifier"]["verified"])
        self.assertTrue(summary["verifier"]["requireCompleteSatisfied"])
        self.assertEqual(822, summary["verifier"]["caseManifestEntryCount"])
        self.assertEqual(840, summary["verifier"]["rootManifestEntryCount"])
        self.assertEqual(
            {
                "bit-or": (
                    "96708e7d8e7c9efdfaa94e9db5ee335e"
                    "6f3ba1ed7db5d475480bca1778aa5eb7"
                ),
                "first-multiple": (
                    "9a416d636ab74f9aaaff4265fe6da4cb6"
                    "3e28c3f210463fd983821f60da3d3b1"
                ),
                "independent-w1c": (
                    "c6fe1374e720d82ce6c9edade0fe52a2"
                    "89fcb11b7fa332914c37a095d59eb21b"
                ),
                "rearm": (
                    "7a595815777fd2a9d2f882e3e2624a0a"
                    "933b9b84d3c7a04e02bb9021208d9d27"
                ),
            },
            {
                sequence: record["observationDigest"]
                for sequence, record in summary["observations"]["sequences"].items()
            },
        )

        campaign_path = ROOT / campaign_relative
        campaign_sha256 = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
        self.assertEqual(
            "847a2500ae868a47d1abe8ae976584808"
            "5f8c31605afaa74b78cbc1923d40b7f",
            campaign_sha256,
        )
        self.assertEqual(
            campaign_sha256,
            summary["frozenIntegrity"]["committedCampaignResult"]["sha256"],
        )
        for artifact in result["artifacts"]:
            actual = hashlib.sha256((ROOT / artifact["path"]).read_bytes()).hexdigest()
            self.assertEqual(artifact["sha256"], actual, artifact["path"])

        experiment = next(
            item
            for item in self.model["experiments"]
            if item["id"] == "VMW-AER-COR-001"
        )
        self.assertEqual("PARTIAL", experiment["executionState"])
        self.assertIn(summary_relative, experiment["evidencePaths"])
        self.assertIn(result_relative, experiment["evidencePaths"])
        self.assertIn(
            "vmware-esxi8-lab/test_esxi_aer_root_sequence.py",
            experiment["runnerPaths"],
        )
        for relative in (summary_relative, result_relative):
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(experiment["evidenceSha256"][relative], actual)

        parity = next(
            item
            for item in self.model["coreParity"]
            if item["id"] == "PARITY-PCI-ERROR-POLICY"
        )
        self.assertEqual("PARTIAL", parity["vmwareReferenceStatus"])
        self.assertIn(
            "esxi-o4-g101-root-first-multiple-independent-w1c-bit-or-rearm",
            parity["verifiedSlices"],
        )
        self.assertNotIn(
            "esxi-o0-g101-root-first-multiple-independent-w1c-bit-or-rearm",
            parity["unverifiedSlices"],
        )
        self.assertIn(
            "esxi-o0-g101-root-first-multiple-independent-w1c-bit-or-rearm",
            parity["verifiedSlices"],
        )

        record = next(
            item
            for item in self.index["records"]
            if item["experimentId"] == "VMW-AER-COR-001"
        )
        self.assertIn(result["runId"], record["runIds"])
        self.assertIn(summary_relative, {item["path"] for item in record["evidence"]})
        self.assertIn(result_relative, {item["path"] for item in record["evidence"]})

        candidate = load(
            "contracts/vmware-aer-root-sequence-public-model-candidate-v1.json"
        )
        self.assertEqual("CANDIDATE_NOT_OBSERVED", candidate["profileState"])
        self.assertEqual([], summary["closureEffects"]["qmanProductCasesClosed"])
        self.assertEqual([], summary["closureEffects"]["qmanRisksClosed"])
        self.assertFalse(summary["closureEffects"]["qmanGateAdvanced"])
        self.assertFalse(summary["closureEffects"]["qmanStatusUpdated"])
        self.assertEqual("G1", self.project["currentMilestone"])
        milestones = {item["id"]: item["status"] for item in self.project["milestones"]}
        self.assertEqual("NOT_STARTED", milestones["G6"])
        m06 = next(
            item
            for item in load("acceptance/cases/registry-M.json")["records"]
            if item["id"] == "M06"
        )
        self.assertEqual("IMPLEMENTATION_BLOCKED", m06["status"])
        r13 = next(
            item
            for item in load("contracts/risk-status.json")["records"]
            if item["id"] == "R13"
        )
        self.assertEqual("OPEN", r13["status"])

    def test_v19_o0_and_cross_owner_profile_are_exact_and_non_closing(self) -> None:
        summary_relative = (
            "evidence/esxi8-aer-root-o0-v19-full1-20260730-summary.json"
        )
        result_relative = (
            "evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json"
        )
        campaign_relative = (
            "evidence/esxi8-aer-root-o0-v19-full1-20260730-campaign-result.json"
        )
        profile_relative = (
            "contracts/"
            "vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json"
        )
        promotion_relative = (
            "evidence/"
            "esxi8-aer-root-g101-o0-o4-profile-promotion-20260730-summary.json"
        )
        candidate_relative = (
            "contracts/vmware-aer-root-sequence-public-model-candidate-v1.json"
        )

        summary = load(summary_relative)
        result = load(result_relative)
        schema_errors = sorted(
            Draft202012Validator(self.result_schema).iter_errors(result),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual([], schema_errors)
        self.assertEqual("VMW-AER-COR-001", result["caseId"])
        self.assertEqual("20260730-esxi8-aer-root-o0-v19-full1", result["runId"])
        self.assertEqual("PARTIAL", result["verdict"])

        self.assertEqual("PARTIAL", summary["observationStatus"])
        self.assertEqual("NONE", summary["closureAuthority"])
        self.assertEqual("O0", summary["canonicalSlice"]["ownerPhase"])
        self.assertEqual("VMkernel", summary["canonicalSlice"]["currentOwner"])
        self.assertEqual([], summary["canonicalSlice"]["activePassthroughUsers"])
        self.assertEqual("None", summary["canonicalSlice"]["targetModuleName"])
        self.assertEqual(12, summary["run"]["completedCaseCount"])
        self.assertEqual(12, summary["run"]["matchCount"])
        self.assertEqual("FULL_PLAN", summary["run"]["completionClass"])
        self.assertTrue(summary["verifier"]["verified"])
        self.assertTrue(summary["verifier"]["requireCompleteSatisfied"])
        self.assertEqual(738, summary["verifier"]["caseManifestEntryCount"])
        self.assertEqual(756, summary["verifier"]["rootManifestEntryCount"])
        self.assertEqual(
            0.038855193997733295,
            summary["observations"]["safetyAndCleanup"][
                "maximumObservedSafetyPollGapSeconds"
            ],
        )
        owner = summary["observations"]["ownerAndGuest"]
        self.assertEqual(24, owner["ownerObservationCount"])
        self.assertTrue(owner["activePassthroughUsersAlwaysEmpty"])
        self.assertEqual("NOT_APPLICABLE_O0", owner["guestClassification"])
        self.assertEqual(0, owner["guestSerialArtifactCount"])

        expected_digests = {
            "bit-or": (
                "0f2cd1201a78ecfde13996cb8c1a9b5cd"
                "7c37f2051c3fc01891c6e8c25dbaf76"
            ),
            "first-multiple": (
                "45a10045be47114ae60e0e94bcba168a1"
                "7f8d2decf4f7a0c1ce693217bcaf789"
            ),
            "independent-w1c": (
                "eea7d12f357b5d5c8914ec6616294790"
                "06cd3c4a476fc0caee27c6451e2623ce"
            ),
            "rearm": (
                "301577d34f3f1b5bcec3df2ee769ac6d"
                "5c9bc96a394c779dc22c138cc5ed5fed"
            ),
        }
        self.assertEqual(
            expected_digests,
            {
                sequence: record["observationDigest"]
                for sequence, record in summary["observations"]["sequences"].items()
            },
        )
        expected_snapshot_hashes = {
            "first-multiple": (
                "57f5d016add1da431dfe475818e80920c"
                "b35fbd766a85f8d422e1db75d26f772"
            ),
            "independent-w1c": (
                "21ee0c21d3a8b6e8a7429fb44599df9"
                "7b72da3f79d48f843f42fff3a2d229df2"
            ),
            "bit-or": (
                "d121036d96f1c5fab9bdd0bc405058ae"
                "35b05065a0f3ca6b7ccc3a87b6e8ca90"
            ),
            "rearm": (
                "80370cc89885af9c70d982e4cec376de"
                "d05d4b3ea28f3c60c753f599c48625c4"
            ),
        }
        comparison = summary["crossOwnerComparison"]
        self.assertEqual(12, comparison["comparedCasePairCount"])
        self.assertEqual(12, comparison["exactCasePairCount"])
        self.assertTrue(comparison["registerSnapshotsExact"])
        self.assertEqual(
            expected_snapshot_hashes, comparison["sequenceSnapshotSha256"]
        )

        campaign_sha256 = hashlib.sha256(
            (ROOT / campaign_relative).read_bytes()
        ).hexdigest()
        self.assertEqual(
            "b2ab49a200822c4b283f6122521f2211"
            "742dab8536cd6fda6d1b980e1223c6d6",
            campaign_sha256,
        )
        self.assertEqual(
            campaign_sha256,
            summary["frozenIntegrity"]["committedCampaignResult"]["sha256"],
        )
        for artifact in result["artifacts"]:
            actual = hashlib.sha256((ROOT / artifact["path"]).read_bytes()).hexdigest()
            self.assertEqual(artifact["sha256"], actual, artifact["path"])

        oracle_schema = load(
            "contracts/vmware-aer-root-sequence-oracle-profile.schema.json"
        )
        candidate = load(candidate_relative)
        profile = load(profile_relative)
        profile_errors = sorted(
            Draft202012Validator(oracle_schema).iter_errors(profile),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual([], profile_errors)
        self.assertEqual("CANDIDATE_NOT_OBSERVED", candidate["profileState"])
        self.assertEqual("FROZEN_OBSERVED_PROFILE", profile["profileState"])
        self.assertEqual(
            "663221aed0100e95652ce7277fdfe48bd"
            "0877d338545801346b6fe45583a4d3a",
            hashlib.sha256((ROOT / candidate_relative).read_bytes()).hexdigest(),
        )
        normalized_profile = copy.deepcopy(profile)
        normalized_profile["id"] = candidate["id"]
        normalized_profile["profileState"] = candidate["profileState"]
        normalized_profile["environmentBinding"]["expectedSystemUuid"] = None
        normalized_profile["environmentBinding"]["outerQemuBinarySha256"] = None
        self.assertEqual(candidate, normalized_profile)

        promotion = load(promotion_relative)
        self.assertEqual("FROZEN_OBSERVED_PROFILE", promotion["profileState"])
        self.assertEqual("NONE", promotion["closureAuthority"])
        self.assertEqual(
            expected_snapshot_hashes,
            promotion["crossOwnerComparison"]["sequenceSnapshotSha256"],
        )
        self.assertEqual(
            [
                "/id",
                "/profileState",
                "/environmentBinding/expectedSystemUuid",
                "/environmentBinding/outerQemuBinarySha256",
            ],
            promotion["promotionDelta"]["exactChangedJsonPointers"],
        )
        for binding in promotion["evidenceBindings"].values():
            for prefix in ("summary", "canonicalResult", "campaignResult"):
                actual = hashlib.sha256(
                    (ROOT / binding[f"{prefix}Path"]).read_bytes()
                ).hexdigest()
                self.assertEqual(binding[f"{prefix}Sha256"], actual)
        derived = promotion["derivedObservedProfile"]
        self.assertEqual(
            derived["sha256"],
            hashlib.sha256((ROOT / derived["path"]).read_bytes()).hexdigest(),
        )

        experiment = next(
            item
            for item in self.model["experiments"]
            if item["id"] == "VMW-AER-COR-001"
        )
        self.assertEqual("PARTIAL", experiment["executionState"])
        for relative in (
            summary_relative,
            result_relative,
            profile_relative,
            promotion_relative,
        ):
            self.assertIn(relative, experiment["evidencePaths"])
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(experiment["evidenceSha256"][relative], actual)
        self.assertIn("esxi-o0-target-native-driver-unbound", experiment["limitations"])

        parity = next(
            item
            for item in self.model["coreParity"]
            if item["id"] == "PARITY-PCI-ERROR-POLICY"
        )
        self.assertIn(
            "esxi-o0-o4-g101-external-register-snapshot-equivalence",
            parity["verifiedSlices"],
        )
        self.assertNotIn(
            "esxi-o0-g101-root-first-multiple-independent-w1c-bit-or-rearm",
            parity["unverifiedSlices"],
        )
        record = next(
            item
            for item in self.index["records"]
            if item["experimentId"] == "VMW-AER-COR-001"
        )
        self.assertIn(result["runId"], record["runIds"])

        closure = summary["closureEffects"]
        self.assertEqual([], closure["qmanProductCasesClosed"])
        self.assertEqual([], closure["qmanRisksClosed"])
        self.assertFalse(closure["qmanGateAdvanced"])
        self.assertFalse(closure["qmanStatusUpdated"])
        self.assertEqual("G1", self.project["currentMilestone"])

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

        trace_experiment = next(
            experiment
            for experiment in self.model["experiments"]
            if experiment["id"] == "VMW-TRACE-001"
        )
        trace_relative = trace_experiment["evidencePaths"][0]
        trace_summary = load(trace_relative)
        trace_name = Path(trace_relative).name
        trace_summary["closureAuthority"]["release"] = "FULL"
        original_load_json = evaluate_release.load_json

        def load_with_mutated_trace(path: Path) -> dict:
            if path.name == trace_name:
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
