import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pci_resource_model.capability as capability_module
from pci_resource_model.capability import (
    REFERENCE_FACT_VERIFIER,
    CapabilityPolicy,
    evaluate_passthrough,
    seal_reference_device_facts,
)
from pci_resource_model.model import (
    AddressRange,
    Bar,
    DeviceInventory,
    DmaIsolationMode,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
    MemberAction,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "c20-capability-closure.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
TARGET = FIXTURE["target"]
DEPENDENCY = FIXTURE["dependency"]
RESET_PEER = FIXTURE["resetPeer"]
INVENTORY_EPOCH = 20
TOPOLOGY_HASH = "c" * 64


def endpoint(
    bdf: str,
    *,
    platform_dependencies: tuple[str, ...] = (),
    dependency_action: MemberAction = MemberAction.LOCK_ONLY,
    qualified_actions: tuple[MemberAction, ...] = (
        MemberAction.ASSIGN_TO_GUEST,
        MemberAction.LOCK_ONLY,
    ),
    reset_methods: tuple[str, ...] = ("flr",),
    reset_domain: tuple[str, ...] | None = None,
    reset_domain_source: str = "pci-config-flr",
) -> DeviceInventory:
    device = DeviceInventory(
        bdf=bdf,
        vendor_id=0x1AF4,
        device_id=0x1041,
        class_code=0x020000,
        header_type=0,
        function_role=FunctionRole.ENDPOINT,
        iommu_group=(bdf,),
        physical_isolation_domain=(bdf,),
        physical_isolation_domain_source="qualification-snapshot",
        reset_methods=reset_methods,
        reset_domain=(bdf,) if reset_domain is None else reset_domain,
        reset_domain_source=reset_domain_source,
        platform_dependencies=platform_dependencies,
        multifunction_source="qualification-snapshot",
        platform_dependency_source="qualification-snapshot",
        dependency_action=dependency_action,
        qualified_actions=qualified_actions,
        owner_activation_group=f"c20:{bdf}",
        exclusive_attach_group=f"c20:{bdf}",
        isolation_provenance=IsolationProvenance.KERNEL_GROUP,
        dma_isolation_mode=DmaIsolationMode.IOMMU,
        dma_isolation_source="reference-iommu-provider",
        driver="vfio-pci",
    )
    return seal_reference_device_facts(
        device,
        inventory_epoch=INVENTORY_EPOCH,
        topology_hash=TOPOLOGY_HASH,
    )


def inventory_for(case: dict) -> HostInventory:
    action = (
        MemberAction.ASSIGN_TO_GUEST
        if case["dependencyActionFact"] == "valid"
        else MemberAction.UNKNOWN
    )
    if case["dependencyResetContract"] == "valid":
        reset_methods = ("bus",)
        reset_domain = (DEPENDENCY, RESET_PEER)
        reset_source = "vfio-hot-reset-info"
    else:
        reset_methods = ()
        reset_domain = ()
        reset_source = "missing"

    devices = {
        TARGET: endpoint(TARGET, platform_dependencies=(DEPENDENCY,)),
        DEPENDENCY: endpoint(
            DEPENDENCY,
            dependency_action=action,
            reset_methods=reset_methods,
            reset_domain=reset_domain,
            reset_domain_source=reset_source,
        ),
        RESET_PEER: endpoint(
            RESET_PEER,
            qualified_actions=(MemberAction.LOCK_ONLY,),
        ),
    }
    leases = (
        {DEPENDENCY: case["dependencyOwner"]}
        if case["dependencyOwner"] != "free"
        else {}
    )
    return HostInventory(
        iommu_present=True,
        interrupt_remapping=True,
        no_iommu_mode=False,
        acs_override_active=False,
        devices=devices,
        leases=leases,
        source="c20-executable-fixture",
        host_id="c20-reference-host",
        kernel_boot_id="c20-reference-boot",
        inventory_epoch=INVENTORY_EPOCH,
        topology_hash=TOPOLOGY_HASH,
        metadata={
            "bindCounter": 0,
            "resetCounter": 0,
            "leaseWriteCounter": 0,
        },
    )


def evaluate(inventory: HostInventory):
    return evaluate_passthrough(
        inventory,
        TARGET,
        low_windows=(AddressRange(0xC0000000, 0x100000000),),
        fact_verifier=REFERENCE_FACT_VERIFIER,
    )


class C20CapabilityClosureTests(unittest.TestCase):
    def test_four_cell_fixed_point_matrix_and_owner_independent_hashes(self) -> None:
        results = {}
        for case in FIXTURE["matrix"]:
            with self.subTest(case=case["name"]):
                result = evaluate(inventory_for(case))
                expected = case["expect"]
                self.assertEqual(result.eligible, expected["capable"])
                self.assertEqual(result.available, expected["available"])
                if reason := expected.get("reason"):
                    self.assertIn(reason, [item.code for item in result.reasons])
                if expected["capable"]:
                    self.assertEqual(
                        result.required_lease,
                        tuple(sorted((TARGET, DEPENDENCY, RESET_PEER))),
                    )
                    self.assertEqual(
                        result.member_actions[DEPENDENCY],
                        MemberAction.ASSIGN_TO_GUEST.value,
                    )
                    self.assertEqual(result.reset_methods[DEPENDENCY], "bus")
                results[case["name"]] = result

        free = results["dependency-qualified-and-free"]
        busy = results["same-bundle-busy"]
        self.assertEqual(free.bundle_hash, busy.bundle_hash)
        self.assertEqual(free.capability_hash, busy.capability_hash)
        self.assertEqual(free.policy_hash, busy.policy_hash)
        self.assertEqual(free.snapshot_hash, busy.snapshot_hash)
        self.assertNotEqual(free.decision_hash, busy.decision_hash)
        self.assertTrue(free.attachable)
        self.assertFalse(busy.attachable)

        self.assertEqual(
            {
                "snapshotHash": free.snapshot_hash,
                "bundleHash": free.bundle_hash,
                "capabilityHash": free.capability_hash,
                "policyHash": free.policy_hash,
            },
            FIXTURE["expectedHashes"],
        )

    def test_exact_member_action_qualification_is_fail_closed(self) -> None:
        case = FIXTURE["matrix"][0]
        inventory = inventory_for(case)
        dependency = replace(
            inventory.devices[DEPENDENCY],
            qualified_actions=(MemberAction.LOCK_ONLY,),
        )
        inventory = replace(
            inventory,
            devices={**inventory.devices, DEPENDENCY: dependency},
        )

        result = evaluate(inventory)

        self.assertFalse(result.eligible)
        qualification = next(
            reason for reason in result.reasons if reason.code == "QUALIFICATION_MISSING"
        )
        self.assertEqual(qualification.devices, (DEPENDENCY,))
        self.assertEqual(
            qualification.details["requiredAction"],
            MemberAction.ASSIGN_TO_GUEST.value,
        )

    def test_query_is_repeatable_and_has_no_modeled_side_effect(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        before = copy.deepcopy(inventory.to_dict())

        with patch(
            "builtins.open",
            side_effect=AssertionError("capability query attempted host I/O"),
        ):
            first = evaluate(inventory)
            second = evaluate(inventory)

        self.assertEqual(inventory.to_dict(), before)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(inventory.metadata["bindCounter"], 0)
        self.assertEqual(inventory.metadata["resetCounter"], 0)
        self.assertEqual(inventory.metadata["leaseWriteCounter"], 0)

    def test_action_and_qualification_facts_round_trip(self) -> None:
        original = inventory_for(FIXTURE["matrix"][0]).devices[DEPENDENCY]

        restored = DeviceInventory.from_dict(original.to_dict())

        self.assertEqual(restored.dependency_action, original.dependency_action)
        self.assertEqual(restored.qualified_actions, original.qualified_actions)

    def test_full_schema_v2_inventory_and_hashes_round_trip(self) -> None:
        original = inventory_for(FIXTURE["matrix"][0])

        restored = HostInventory.from_dict(original.to_dict())

        self.assertEqual(restored.to_dict(), original.to_dict())
        self.assertEqual(evaluate(restored).to_dict(), evaluate(original).to_dict())

    def test_initial_payload_dependency_action_conflict_is_not_skipped(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        conflicting = endpoint(
            DEPENDENCY,
            dependency_action=MemberAction.QUIESCE_HOST,
            qualified_actions=(
                MemberAction.ASSIGN_TO_GUEST,
                MemberAction.QUIESCE_HOST,
            ),
        )
        inventory = replace(
            inventory,
            devices={**inventory.devices, DEPENDENCY: conflicting},
        )

        result = evaluate_passthrough(
            inventory,
            TARGET,
            payload_devices=(DEPENDENCY,),
            low_windows=(AddressRange(0xC0000000, 0x100000000),),
            fact_verifier=REFERENCE_FACT_VERIFIER,
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEPENDENCY_ACTION_CONFLICT",
            [reason.code for reason in result.reasons],
        )

    def test_untrusted_reset_contract_provenance_is_rejected(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        dependency = endpoint(
            DEPENDENCY,
            dependency_action=MemberAction.ASSIGN_TO_GUEST,
            reset_methods=("bus",),
            reset_domain=(DEPENDENCY, RESET_PEER),
            reset_domain_source="self-asserted-string",
        )
        inventory = replace(
            inventory,
            devices={**inventory.devices, DEPENDENCY: dependency},
        )

        result = evaluate(inventory)

        self.assertFalse(result.eligible)
        self.assertIn(
            "RESET_CONTRACT_PROVENANCE_UNTRUSTED",
            [reason.code for reason in result.reasons],
        )

    def test_untrusted_dependency_and_qualification_facts_are_rejected(self) -> None:
        baseline = inventory_for(FIXTURE["matrix"][0])
        dependency = baseline.devices[DEPENDENCY]
        assert dependency.dependency_action_fact is not None
        bad_dependency = replace(
            dependency,
            dependency_action_fact=replace(
                dependency.dependency_action_fact,
                source="self-asserted-string",
            ),
        )
        target = baseline.devices[TARGET]
        assert target.qualification_fact is not None
        bad_qualification = replace(
            target,
            qualification_fact=replace(
                target.qualification_fact,
                source="self-asserted-string",
            ),
        )
        bad_domain = replace(
            target,
            platform_dependency_source="self-asserted-string",
        )

        cases = (
            (
                {**baseline.devices, DEPENDENCY: bad_dependency},
                "DEPENDENCY_ACTION_PROVENANCE_UNTRUSTED",
            ),
            (
                {**baseline.devices, TARGET: bad_qualification},
                "QUALIFICATION_PROVENANCE_UNTRUSTED",
            ),
            (
                {**baseline.devices, TARGET: bad_domain},
                "DEPENDENCY_PROVENANCE_UNKNOWN",
            ),
        )
        for devices, expected in cases:
            with self.subTest(expected=expected):
                result = evaluate(replace(baseline, devices=devices))
                self.assertFalse(result.eligible)
                self.assertIn(expected, [reason.code for reason in result.reasons])

    def test_reset_source_is_normalized_before_trust_check(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        target = endpoint(TARGET, reset_domain_source="UNKNOWN")
        inventory = replace(
            inventory,
            devices={**inventory.devices, TARGET: target},
        )

        result = evaluate(inventory)

        self.assertEqual(target.reset_domain_source, "unknown")
        self.assertFalse(result.eligible)
        self.assertIn(
            "RESET_CONTRACT_PROVENANCE_UNTRUSTED",
            [reason.code for reason in result.reasons],
        )

    def test_identity_drift_invalidates_facts_and_capability_hash(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        baseline = evaluate(inventory)
        changed_dependency = replace(
            inventory.devices[DEPENDENCY],
            vendor_id=0xDEAD,
            device_id=0xBEEF,
        )
        changed = replace(
            inventory,
            devices={**inventory.devices, DEPENDENCY: changed_dependency},
        )

        result = evaluate(changed)

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEPENDENCY_ACTION_STALE",
            [reason.code for reason in result.reasons],
        )
        self.assertNotEqual(result.snapshot_hash, baseline.snapshot_hash)
        self.assertNotEqual(result.bundle_hash, baseline.bundle_hash)
        self.assertNotEqual(result.capability_hash, baseline.capability_hash)

    def test_missing_snapshot_identity_is_fail_closed(self) -> None:
        inventory = replace(
            inventory_for(FIXTURE["matrix"][0]),
            inventory_epoch=None,
            host_id="unknown",
        )

        result = evaluate(inventory)

        self.assertFalse(result.eligible)
        self.assertIn(
            "SNAPSHOT_IDENTITY_INCOMPLETE",
            [reason.code for reason in result.reasons],
        )

    def test_dependency_member_and_edge_limits_are_fail_closed(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        for policy in (
            CapabilityPolicy(max_dependency_members=2),
            CapabilityPolicy(max_dependency_edges=2),
        ):
            with self.subTest(policy=policy):
                result = evaluate_passthrough(
                    inventory,
                    TARGET,
                    low_windows=(AddressRange(0xC0000000, 0x100000000),),
                    policy=policy,
                    fact_verifier=REFERENCE_FACT_VERIFIER,
                )
                self.assertFalse(result.eligible)
                self.assertIn(
                    "DEPENDENCY_CLOSURE_LIMIT",
                    [reason.code for reason in result.reasons],
                )

    def test_large_dependency_domain_is_rejected_before_materialization(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        peers = tuple(f"peer-{index:05d}" for index in range(20_000))
        target = replace(
            inventory.devices[TARGET],
            iommu_group=(TARGET, *peers),
        )
        inventory = replace(
            inventory,
            devices={**inventory.devices, TARGET: target},
        )

        result = evaluate_passthrough(
            inventory,
            TARGET,
            low_windows=(AddressRange(0xC0000000, 0x100000000),),
            policy=CapabilityPolicy(
                max_dependency_members=2,
                max_dependency_edges=2,
            ),
            fact_verifier=REFERENCE_FACT_VERIFIER,
        )

        limit = next(
            reason
            for reason in result.reasons
            if reason.code == "DEPENDENCY_CLOSURE_LIMIT"
        )
        self.assertFalse(result.eligible)
        self.assertLessEqual(len(result.required_lease), 2)
        self.assertLessEqual(len(result.bundle_edges), 2)
        self.assertLessEqual(len(limit.devices), 1)

    def test_fact_evidence_requires_explicit_authenticity_verifier(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])

        no_verifier = evaluate_passthrough(
            inventory,
            TARGET,
            low_windows=(AddressRange(0xC0000000, 0x100000000),),
        )
        verified = evaluate(inventory)

        self.assertFalse(no_verifier.eligible)
        self.assertTrue(verified.eligible)
        self.assertIn(
            "RESET_CONTRACT_PROVENANCE_UNTRUSTED",
            [reason.code for reason in no_verifier.reasons],
        )
        self.assertNotEqual(no_verifier.policy_hash, verified.policy_hash)

    def test_verifier_contract_rejects_truthy_or_invalid_results(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])

        class TruthyVerifier:
            identifier = "truthy-verifier-v1"

            def verify(self, fact):
                return "yes"

        class InvalidIdentifierVerifier:
            identifier = None

            def verify(self, fact):
                return True

        class ExplodingTruthValue:
            def __bool__(self):
                raise RuntimeError("truth conversion must not escape")

        class ObjectVerifier:
            identifier = "object-verifier-v1"

            def verify(self, fact):
                return ExplodingTruthValue()

        for verifier in (
            TruthyVerifier(),
            InvalidIdentifierVerifier(),
            ObjectVerifier(),
        ):
            with self.subTest(verifier=type(verifier).__name__):
                result = evaluate_passthrough(
                    inventory,
                    TARGET,
                    low_windows=(AddressRange(0xC0000000, 0x100000000),),
                    fact_verifier=verifier,
                )
                self.assertFalse(result.eligible)
                self.assertTrue(
                    any(
                        reason.code.endswith("PROVENANCE_UNTRUSTED")
                        for reason in result.reasons
                    )
                )

    def test_arbitrary_evidence_hash_is_not_accepted(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        dependency = inventory.devices[DEPENDENCY]
        assert dependency.dependency_action_fact is not None
        forged = replace(
            dependency,
            dependency_action_fact=replace(
                dependency.dependency_action_fact,
                evidence_hash="0" * 64,
            ),
        )

        result = evaluate(
            replace(
                inventory,
                devices={**inventory.devices, DEPENDENCY: forged},
            )
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEPENDENCY_ACTION_PROVENANCE_UNTRUSTED",
            [reason.code for reason in result.reasons],
        )

    def test_action_fact_from_old_snapshot_is_stale(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        old_dependency = seal_reference_device_facts(
            inventory.devices[DEPENDENCY],
            inventory_epoch=INVENTORY_EPOCH - 1,
            topology_hash="d" * 64,
        )

        result = evaluate(
            replace(
                inventory,
                devices={**inventory.devices, DEPENDENCY: old_dependency},
            )
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEPENDENCY_ACTION_STALE",
            [reason.code for reason in result.reasons],
        )

    def test_inventory_rejects_key_identity_substitution_and_duplicate_bdf(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        target = inventory.devices[TARGET]

        with self.assertRaisesRegex(ValueError, "does not match embedded bdf"):
            replace(inventory, devices={"0000:de:ad.0": target})

        encoded = inventory.to_dict()
        encoded["devices"].append(copy.deepcopy(encoded["devices"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate inventory device bdf"):
            HostInventory.from_dict(encoded)

        case_device = endpoint("0000:aa:00.0")
        with self.assertRaisesRegex(ValueError, "duplicate inventory device bdf"):
            replace(
                inventory,
                devices={
                    "0000:AA:00.0": case_device,
                    "0000:aa:00.0": case_device,
                },
            )

    def test_inventory_device_and_lease_maps_are_immutable(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])

        with self.assertRaises(TypeError):
            inventory.devices["0000:de:ad.0"] = inventory.devices[TARGET]
        with self.assertRaises(TypeError):
            inventory.leases[TARGET] = "other-vm"

    def test_decision_hash_binds_exact_attach_and_activation_groups(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        baseline = evaluate(inventory)
        changed_target = replace(
            inventory.devices[TARGET],
            exclusive_attach_group="c20:replacement-attach-group",
            owner_activation_group="c20:replacement-owner-group",
        )
        changed = evaluate(
            replace(
                inventory,
                devices={**inventory.devices, TARGET: changed_target},
            )
        )

        self.assertTrue(baseline.attachable)
        self.assertTrue(changed.attachable)
        self.assertEqual(baseline.capability_hash, changed.capability_hash)
        self.assertNotEqual(baseline.decision_hash, changed.decision_hash)

    def test_decision_hash_binds_mmio_without_changing_capability_hash(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][0])
        target = replace(
            inventory.devices[TARGET],
            bars=(Bar(TARGET, 0, 2 << 30, is_64=True, prefetchable=True),),
        )
        inventory = replace(
            inventory,
            devices={**inventory.devices, TARGET: target},
        )

        insufficient = evaluate_passthrough(
            inventory,
            TARGET,
            low_windows=(AddressRange(0xC0000000, 0x100000000),),
            fact_verifier=REFERENCE_FACT_VERIFIER,
        )
        sufficient = evaluate_passthrough(
            inventory,
            TARGET,
            low_windows=(AddressRange(0xC0000000, 0x100000000),),
            high_windows=(AddressRange(0x100000000, 0x200000000),),
            fact_verifier=REFERENCE_FACT_VERIFIER,
        )

        self.assertFalse(insufficient.attachable)
        self.assertTrue(sufficient.attachable)
        self.assertEqual(insufficient.capability_hash, sufficient.capability_hash)
        self.assertNotEqual(insufficient.decision_hash, sufficient.decision_hash)

    def test_localized_reason_message_does_not_change_semantic_hashes(self) -> None:
        inventory = inventory_for(FIXTURE["matrix"][3])
        baseline = evaluate(inventory)
        original_reason = capability_module._reason

        def localized_reason(*args, **kwargs):
            reason = original_reason(*args, **kwargs)
            return replace(reason, message="localized: " + reason.message)

        with patch(
            "pci_resource_model.capability._reason",
            side_effect=localized_reason,
        ):
            localized = evaluate(inventory)

        self.assertNotEqual(
            baseline.reasons[0].message,
            localized.reasons[0].message,
        )
        self.assertEqual(baseline.bundle_hash, localized.bundle_hash)
        self.assertEqual(baseline.capability_hash, localized.capability_hash)
        self.assertEqual(baseline.decision_hash, localized.decision_hash)


if __name__ == "__main__":
    unittest.main()
