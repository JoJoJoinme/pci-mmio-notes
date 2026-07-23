from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evaluate_release  # noqa: E402


def load(relative: str) -> dict[str, Any]:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class G0MachineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = load("contracts/project-status.json")
        cls.decisions = load("contracts/product-decisions.json")
        cls.profile = load("contracts/compatibility-profile-policy.json")
        cls.launch_surface = load("contracts/qemu-vfio-launch-surface.json")
        cls.ipd = load("contracts/ipd-tree.json")
        cls.design = evaluate_release.extract_design_contracts(
            ROOT / "qemu-static-dynamic-directpath-design.md"
        )
        cls.tech_story_ids = evaluate_release.collect_ipd_tech_story_ids(cls.ipd)

    def validate_decisions(
        self, contract: dict[str, Any]
    ) -> tuple[list[str], bool, list[str]]:
        errors: list[str] = []
        unresolved, ready = evaluate_release.validate_product_decisions(
            contract,
            self.tech_story_ids,
            set(self.design.cases),
            set(self.design.risks),
            errors,
        )
        return unresolved, ready, errors

    def test_five_required_decisions_are_accepted_and_project_derives_no_open_ids(self) -> None:
        unresolved, ready, errors = self.validate_decisions(self.decisions)
        self.assertTrue(ready)
        self.assertEqual([], unresolved)
        self.assertEqual([], errors)

        project_errors: list[str] = []
        blockers: list[str] = []
        evaluate_release.validate_project_status(
            self.project, unresolved, project_errors, blockers
        )
        self.assertEqual([], project_errors)
        self.assertEqual(
            ["unfinished milestones: G1, G2, G3, G4, G5, G6"], blockers
        )
        self.assertEqual([], self.project["openDecisions"])

    def test_decision_field_mutations_are_unresolved_and_invalid(self) -> None:
        mutations: list[tuple[str, tuple[object, ...], object, str]] = [
            ("status", ("records", 0, "status"), "PROPOSED", "must be ACCEPTED"),
            ("owner", ("records", 0, "owner"), "", "non-empty owner"),
            ("date", ("records", 0, "decidedAt"), "2026-02-30", "decidedAt"),
            ("decision", ("records", 0, "decision"), "", "non-empty decision"),
            (
                "association",
                ("records", 0, "techStories"),
                ["TS-NOT-DEFINED"],
                "unknown IDs",
            ),
        ]

        for name, path, value, expected_error in mutations:
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.decisions)
                target: Any = candidate
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                unresolved, ready, errors = self.validate_decisions(candidate)
                self.assertFalse(ready)
                self.assertIn("ADR-002", unresolved)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

    def test_open_decisions_must_equal_the_derived_unresolved_list(self) -> None:
        candidate = copy.deepcopy(self.decisions)
        candidate["records"][0]["status"] = "PROPOSED"
        unresolved, _, _ = self.validate_decisions(candidate)
        self.assertEqual(["ADR-002"], unresolved)

        project_errors: list[str] = []
        evaluate_release.validate_project_status(
            self.project, unresolved, project_errors, []
        )
        self.assertTrue(
            any("must equal unresolved product decisions" in error for error in project_errors)
        )

        matching_project = copy.deepcopy(self.project)
        matching_project["openDecisions"] = ["ADR-002"]
        matching_errors: list[str] = []
        evaluate_release.validate_project_status(
            matching_project, unresolved, matching_errors, []
        )
        self.assertFalse(
            any("must equal unresolved product decisions" in error for error in matching_errors)
        )

    def test_project_registers_contracts_and_advances_only_to_g1(self) -> None:
        documents = self.project["authoritativeDocuments"]
        for name, path in evaluate_release.G0_AUTHORITATIVE_DOCUMENTS.items():
            self.assertEqual(path, documents[name])
            self.assertTrue((ROOT / path).exists())
        milestones = {item["id"]: item for item in self.project["milestones"]}
        self.assertEqual("2026-07-23", self.project["asOf"])
        self.assertEqual("G1", self.project["currentMilestone"])
        self.assertEqual("DONE", milestones["G0"]["status"])
        self.assertEqual("IN_PROGRESS", milestones["G1"]["status"])
        for milestone_id in ("G2", "G3", "G4", "G5", "G6"):
            self.assertEqual("NOT_STARTED", milestones[milestone_id]["status"])

        project_mutations: list[tuple[tuple[object, ...], object, str]] = [
            (("currentClaim",), "SUPPORTED", "currentClaim"),
            (("freezeRules",), [], "freezeRules"),
            (("milestones", 6, "id"), "GX", "G0 through G6"),
            (("milestones", 1, "status"), {}, "invalid status"),
            (("currentMilestone",), {}, "currentMilestone"),
        ]
        for path, value, expected_error in project_mutations:
            with self.subTest(project_path=path):
                candidate = copy.deepcopy(self.project)
                target: Any = candidate
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                errors: list[str] = []
                evaluate_release.validate_project_status(
                    candidate, [], errors, []
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

        mutations: list[tuple[tuple[object, ...], object, str]] = [
            (
                ("productBoundary", "technicalScope"),
                "ANYTHING",
                "technicalScope",
            ),
            (
                ("productBoundary", "explicitlyUnsupportedOperations"),
                ["LIVE_MIGRATION"],
                "explicitlyUnsupportedOperations",
            ),
            (
                ("capabilityDimensions", "invariants"),
                ["ARBITRARY"],
                "invariants",
            ),
            (
                ("capabilityDimensions", "SUPPORTED"),
                "Everything is supported.",
                "SUPPORTED",
            ),
        ]
        for path, value, expected_error in mutations:
            with self.subTest(ipd_path=path):
                candidate = copy.deepcopy(self.ipd)
                target: Any = candidate
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                errors: list[str] = []
                evaluate_release.validate_ipd_tree(candidate, self.project, errors)
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

    def test_frozen_compatibility_profile_is_valid(self) -> None:
        errors: list[str] = []
        self.assertTrue(
            evaluate_release.validate_compatibility_profile_policy(
                self.profile, errors
            )
        )
        self.assertEqual([], errors)

    def test_profile_mutations_fail_closed(self) -> None:
        def remove_platform(candidate: dict[str, Any]) -> None:
            candidate["platforms"].pop()

        def break_v3(candidate: dict[str, Any]) -> None:
            candidate["platforms"][0]["capabilityModel"] = "V2"

        def change_current_backend(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["currentProductFamily"] = "VFIO_CDEV_IOMMUFD"

        def remove_type1(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["allowedConfiguredTypes"] = [
                "VFIO_TYPE1V2_IOMMU"
            ]

        def enable_fallback(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["silentFallback"] = True

        def enable_noiommu(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["noIommu"] = "ALLOW"

        def shrink_c86_matrix(candidate: dict[str, Any]) -> None:
            candidate["platforms"][1]["machineFirmware"].pop()

        def expand_arm_matrix(candidate: dict[str, Any]) -> None:
            candidate["platforms"][0]["machineFirmware"].append(
                {"machine": "virt", "firmware": "SeaBIOS"}
            )

        def split_control_plane(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["sharedControlPlane"] = False

        def drift_adapter_boundary(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["adapterOnlyDifferences"] = ["arbitrary"]

        def drift_legacy_isolation(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["legacyLaunchAuthorization"][
                "requiredIsolation"
            ] = ["arbitrary"]

        def drift_spawn_receipt(candidate: dict[str, Any]) -> None:
            candidate["backendPolicy"]["legacyLaunchAuthorization"][
                "postSpawnReceipt"
            ] = ["arbitrary"]

        def allow_hcl_wildcard(candidate: dict[str, Any]) -> None:
            candidate["hclPolicy"]["wildcardSupportEntryAllowed"] = True

        def drift_hcl_traits(candidate: dict[str, Any]) -> None:
            candidate["hclPolicy"]["archetypes"][0]["requiredTraitCoverage"] = [
                "arbitrary"
            ]

        def drift_qualification_role(candidate: dict[str, Any]) -> None:
            candidate["hclPolicy"]["qualificationIssuer"] = "Arbitrary Team"

        def drift_release_role(candidate: dict[str, Any]) -> None:
            candidate["hclPolicy"]["supportedCatalogApprover"] = "Another Team"

        def allow_offline_relocation(candidate: dict[str, Any]) -> None:
            candidate["clusterPolicy"]["supportedRelocation"] = "HOST_FAILURE_RESTART"

        def enable_bmc(candidate: dict[str, Any]) -> None:
            candidate["clusterPolicy"]["bmcOrPowerFenceIntegration"] = True

        def enable_automatic_ha(candidate: dict[str, Any]) -> None:
            candidate["clusterPolicy"]["hostFailureAutomaticRestart"] = True

        mutations: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            ("six-platform matrix", remove_platform, "exactly six platform rows"),
            ("all V3", break_v3, "V3 capability model"),
            ("Legacy current", change_current_backend, "currentProductFamily"),
            ("TYPE1 exact pin", remove_type1, "exactly pin TYPE1v2 and TYPE1"),
            ("no silent fallback", enable_fallback, "silentFallback"),
            ("no-IOMMU rejection", enable_noiommu, "noIommu"),
            ("C86 four-cell", shrink_c86_matrix, "four-cell"),
            ("ARM virt UEFI", expand_arm_matrix, "virt+UEFI"),
            ("single control plane", split_control_plane, "sharedControlPlane"),
            (
                "adapter boundary",
                drift_adapter_boundary,
                "adapterOnlyDifferences",
            ),
            (
                "Legacy isolation boundary",
                drift_legacy_isolation,
                "requiredIsolation",
            ),
            ("post-spawn receipt", drift_spawn_receipt, "postSpawnReceipt"),
            ("HCL no wildcard", allow_hcl_wildcard, "wildcardSupportEntryAllowed"),
            ("HCL trait map", drift_hcl_traits, "required trait coverage"),
            (
                "qualification role",
                drift_qualification_role,
                "qualificationIssuer",
            ),
            ("release role", drift_release_role, "supportedCatalogApprover"),
            ("online relocation", allow_offline_relocation, "supportedRelocation"),
            ("no BMC", enable_bmc, "bmcOrPowerFenceIntegration"),
            ("no automatic HA", enable_automatic_ha, "hostFailureAutomaticRestart"),
        ]
        for name, mutate, expected_error in mutations:
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.profile)
                mutate(candidate)
                errors: list[str] = []
                self.assertFalse(
                    evaluate_release.validate_compatibility_profile_policy(
                        candidate, errors
                    )
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

    def test_frozen_qemu_launch_surface_is_valid(self) -> None:
        errors: list[str] = []
        self.assertTrue(
            evaluate_release.validate_qemu_vfio_launch_surface(
                self.launch_surface, self.profile, errors
            )
        )
        self.assertEqual([], errors)
        self.assertEqual(
            "QUALIFICATION_PROFILE_ALLOWLIST",
            self.launch_surface["devicePropertiesSemantics"]["kind"],
        )
        profiles = {
            (profile["qemu"], profile["backend"]): profile
            for profile in self.launch_surface["profiles"]
        }
        self.assertEqual(4, len(profiles))
        qemu10_legacy = profiles[("10.2", "LEGACY_VFIO_TYPE1")]
        self.assertEqual("CURRENT_PRODUCT", qemu10_legacy["qualificationUsage"])
        self.assertEqual({"host", "sysfsdev"}, set(qemu10_legacy["deviceProperties"]))
        self.assertEqual(
            {"fd", "iommufd"},
            set(qemu10_legacy["binaryMayExposeAdditionalProperties"]),
        )
        self.assertEqual(
            {"fd", "iommufd"}, set(qemu10_legacy["profileForbiddenProperties"])
        )
        self.assertEqual(
            "FUTURE_QUALIFICATION_ONLY",
            profiles[("10.2", "VFIO_CDEV_IOMMUFD")]["qualificationUsage"],
        )
        self.assertEqual("LEGACY_VFIO_TYPE1", self.launch_surface["qmanDecision"]["currentBackend"])

    def test_qemu_launch_surface_mutations_fail_closed(self) -> None:
        def claim_qemu5_fd(candidate: dict[str, Any]) -> None:
            candidate["profiles"][0]["externalDeviceFdProperty"] = True
            candidate["profiles"][0]["deviceProperties"].append("fd")

        def allow_qemu10_legacy_fd(candidate: dict[str, Any]) -> None:
            candidate["profiles"][2]["externalDeviceFdProperty"] = True
            candidate["profiles"][2]["deviceProperties"].append("fd")

        def expose_fd_on_non_iommufd_backend(candidate: dict[str, Any]) -> None:
            candidate["profiles"][3]["backend"] = "LEGACY_VFIO_WITH_FD"

        def remove_qemu10_fd(candidate: dict[str, Any]) -> None:
            candidate["profiles"][3]["deviceProperties"].remove("fd")

        def remove_qemu10_legacy_profile(candidate: dict[str, Any]) -> None:
            candidate["profiles"].pop(2)

        def claim_binary_complete(candidate: dict[str, Any]) -> None:
            candidate["devicePropertiesSemantics"]["binarySurfaceComplete"] = True

        def mislabel_external_fd_field(candidate: dict[str, Any]) -> None:
            candidate["devicePropertiesSemantics"][
                "externalDeviceFdPropertyMeaning"
            ] = "BINARY_EXPOSES_EXTERNAL_DEVICE_FD"

        def omit_qemu10_legacy_forbidden_properties(candidate: dict[str, Any]) -> None:
            candidate["profiles"][2]["profileForbiddenProperties"] = []

        def allow_silent_fallback(candidate: dict[str, Any]) -> None:
            candidate["qmanDecision"]["forbidden"].remove(
                "SILENT_LEGACY_TO_IOMMUFD_FALLBACK"
            )

        mutations: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            ("QEMU 5 Legacy fd claim", claim_qemu5_fd, "must not allow"),
            ("QEMU 10 Legacy fd claim", allow_qemu10_legacy_fd, "must not allow"),
            (
                "QEMU 10 fd on non-IOMMUFD backend",
                expose_fd_on_non_iommufd_backend,
                "may expose fd only for VFIO_CDEV_IOMMUFD",
            ),
            ("QEMU 10 missing fd", remove_qemu10_fd, "properties must be exactly"),
            (
                "missing QEMU 10 Legacy current profile",
                remove_qemu10_legacy_profile,
                "exactly four profiles",
            ),
            (
                "deviceProperties confused with binary surface",
                claim_binary_complete,
                "must not claim to be the complete",
            ),
            (
                "external fd permission confused with binary exposure",
                mislabel_external_fd_field,
                "must describe profile permission",
            ),
            (
                "QEMU 10 Legacy forbidden properties omitted",
                omit_qemu10_legacy_forbidden_properties,
                "must explicitly forbid",
            ),
            ("silent fallback", allow_silent_fallback, "four forbidden paths"),
        ]
        for name, mutate, expected_error in mutations:
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.launch_surface)
                mutate(candidate)
                errors: list[str] = []
                self.assertFalse(
                    evaluate_release.validate_qemu_vfio_launch_surface(
                        candidate, self.profile, errors
                    )
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

    def test_g0_done_requires_every_convergence_input(self) -> None:
        errors: list[str] = []
        evaluate_release.validate_g0_completion(
            self.project,
            decisions_ready=True,
            profile_ready=True,
            launch_surface_ready=True,
            acceptance_ready=True,
            risk_governance_ready=True,
            errors=errors,
        )
        self.assertEqual([], errors)

        readiness_fields = {
            "decisions_ready": "accepted product decisions",
            "profile_ready": "compatibility profile policy",
            "launch_surface_ready": "QEMU VFIO launch surface",
            "acceptance_ready": "101 classified acceptance cases",
            "risk_governance_ready": "39 governed risks",
        }
        for field, expected in readiness_fields.items():
            with self.subTest(field=field):
                values = {name: True for name in readiness_fields}
                values[field] = False
                mutation_errors: list[str] = []
                evaluate_release.validate_g0_completion(
                    self.project, errors=mutation_errors, **values
                )
                self.assertTrue(
                    any(expected in error for error in mutation_errors),
                    mutation_errors,
                )


if __name__ == "__main__":
    unittest.main()
