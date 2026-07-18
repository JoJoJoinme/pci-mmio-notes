import unittest
from dataclasses import replace

from pci_resource_model.allocator import GIB
from pci_resource_model.capability import CapabilityPolicy, evaluate_passthrough
from pci_resource_model.model import (
    AddressRange,
    Bar,
    DeviceInventory,
    DmaIsolationMode,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
)


TARGET = "0000:01:00.0"


def endpoint(**changes):
    values = {
        "bdf": TARGET,
        "vendor_id": 0x1AF4,
        "device_id": 0x1041,
        "class_code": 0x020000,
        "header_type": 0,
        "function_role": FunctionRole.ENDPOINT,
        "bars": (Bar(TARGET, 0, 2 * GIB, is_64=True),),
        "iommu_group": (TARGET,),
        "physical_isolation_domain": (TARGET,),
        "reset_methods": ("flr",),
        "reset_domain": (TARGET,),
        "owner_activation_group": f"conservative:{TARGET}",
        "exclusive_attach_group": f"conservative:{TARGET}",
        "isolation_provenance": IsolationProvenance.KERNEL_GROUP,
        "dma_isolation_mode": DmaIsolationMode.IOMMU,
        "dma_isolation_source": "test-iommu-domain",
    }
    values.update(changes)
    return DeviceInventory(**values)


def host(device=None, **changes):
    device = device or endpoint()
    values = {
        "iommu_present": True,
        "interrupt_remapping": True,
        "no_iommu_mode": False,
        "acs_override_active": False,
        "devices": {device.bdf: device},
    }
    values.update(changes)
    return HostInventory(**values)


def dependency_device(bdf, members):
    group = "conservative:" + ",".join(sorted(members))
    return replace(
        endpoint(),
        bdf=bdf,
        bars=(),
        iommu_group=tuple(members),
        physical_isolation_domain=tuple(members),
        reset_domain=(bdf,),
        owner_activation_group=group,
        exclusive_attach_group=group,
    )


def evaluate(inventory, **changes):
    values = {
        "low_windows": (AddressRange(0xC0000000, 0x100000000),),
        "high_windows": (AddressRange(0x100000000, 0x300000000),),
    }
    values.update(changes)
    return evaluate_passthrough(inventory, TARGET, **values)


class CapabilityTests(unittest.TestCase):
    def test_legacy_noiommu_host_field_round_trips_with_explicit_name(self):
        inventory = HostInventory.from_dict(
            {
                "schemaVersion": 1,
                "host": {"noIommuMode": True},
                "devices": [],
            }
        )

        self.assertTrue(inventory.no_iommu_mode)
        self.assertTrue(inventory.to_dict()["host"]["unsafeNoIommuModeEnabled"])
        self.assertNotIn("noIommuMode", inventory.to_dict()["host"])

    def test_happy_path_is_attachable(self):
        result = evaluate(host())

        self.assertTrue(result.eligible)
        self.assertTrue(result.available)
        self.assertTrue(result.attachable)
        self.assertEqual(result.verdict, "true")
        self.assertEqual(result.reset_methods[TARGET], "flr")
        self.assertEqual(result.allocation.high_aperture_bytes, 2 * GIB)

    def test_missing_exclusive_attach_group_fails_closed(self):
        result = evaluate(host(endpoint(exclusive_attach_group=None)))

        self.assertTrue(result.eligible)
        self.assertTrue(result.available)
        self.assertFalse(result.attachable)
        self.assertIn(
            "EXCLUSIVE_ATTACH_GROUP_UNKNOWN",
            [item.code for item in result.reasons],
        )

    def test_class_code_does_not_override_type0_endpoint_role(self):
        device = endpoint(class_code=0x060400)

        result = evaluate(host(device))

        self.assertTrue(result.eligible)

    def test_type1_bridge_is_rejected_even_with_flr(self):
        device = endpoint(
            header_type=1,
            function_role=FunctionRole.FABRIC,
            class_code=0x060400,
        )

        result = evaluate(host(device))

        self.assertFalse(result.eligible)
        self.assertIn("STRUCTURAL_FABRIC_NODE", [item.code for item in result.reasons])

    def test_missing_iommu_is_static_capability_failure(self):
        result = evaluate(host(iommu_present=False))

        self.assertFalse(result.eligible)
        self.assertIn("HOST_IOMMU_MISSING", [item.code for item in result.reasons])

    def test_global_unsafe_noiommu_switch_does_not_reject_iommu_device(self):
        result = evaluate(host(no_iommu_mode=True))

        self.assertTrue(result.attachable)
        self.assertIn(
            "HOST_UNSAFE_NOIOMMU_MODE_ENABLED",
            [item.code for item in result.warnings],
        )
        self.assertNotIn(
            "DEVICE_NO_IOMMU_DMA_ISOLATION",
            [item.code for item in result.reasons],
        )

    def test_noiommu_target_is_rejected_even_when_host_switch_allows_it(self):
        device = endpoint(
            dma_isolation_mode=DmaIsolationMode.NO_IOMMU,
            dma_isolation_source="vfio-noiommu-devnode",
        )

        result = evaluate(host(device, no_iommu_mode=True))

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEVICE_NO_IOMMU_DMA_ISOLATION",
            [item.code for item in result.reasons],
        )

    def test_unknown_device_iommu_backing_fails_closed(self):
        device = endpoint(
            dma_isolation_mode=DmaIsolationMode.UNKNOWN,
            dma_isolation_source="missing-provider-proof",
        )

        result = evaluate(host(device))

        self.assertFalse(result.eligible)
        self.assertIn(
            "DEVICE_IOMMU_BACKING_UNKNOWN",
            [item.code for item in result.reasons],
        )

    def test_host_dataplane_reservation_never_enters_vm_candidate_pool(self):
        device = endpoint(host_reservation="dataplane-dpdk")

        result = evaluate(host(device, no_iommu_mode=True))

        self.assertTrue(result.eligible)
        self.assertFalse(result.available)
        self.assertFalse(result.attachable)
        reservation = next(
            item for item in result.reasons if item.code == "HOST_DEVICE_RESERVED"
        )
        self.assertEqual(reservation.stage, "available")
        self.assertEqual(
            reservation.details["reservations"],
            {TARGET: "dataplane-dpdk"},
        )

    def test_host_reserved_dependency_blocks_candidate_not_capability(self):
        peer = "0000:01:00.1"
        device = endpoint(
            reset_methods=("bus",),
            reset_domain=(TARGET, peer),
            reset_domain_source="vfio-hot-reset-info",
        )
        reserved_peer = replace(
            dependency_device(peer, (TARGET, peer)),
            host_reservation="dataplane-dpdk",
        )
        inventory = host(
            device,
            devices={TARGET: device, peer: reserved_peer},
        )

        result = evaluate(inventory)

        self.assertTrue(result.eligible)
        self.assertFalse(result.available)
        self.assertFalse(result.attachable)
        reservation = next(
            item for item in result.reasons if item.code == "HOST_DEVICE_RESERVED"
        )
        self.assertEqual(reservation.devices, (peer,))

    def test_no_reset_is_static_capability_failure(self):
        device = endpoint(reset_methods=(), reset_domain=())

        result = evaluate(host(device))

        self.assertFalse(result.eligible)
        self.assertIn("NO_ACCEPTED_RESET", [item.code for item in result.reasons])

    def test_bus_reset_adds_complete_affected_set_to_lease(self):
        peer = "0000:01:00.1"
        device = endpoint(
            reset_methods=("bus",),
            reset_domain=(TARGET, peer),
            reset_domain_source="vfio-hot-reset-info",
        )
        inventory = host(
            device,
            devices={
                TARGET: device,
                peer: dependency_device(peer, (TARGET, peer)),
            },
        )

        result = evaluate(inventory)

        self.assertTrue(result.attachable)
        self.assertEqual(result.reset_methods[TARGET], "bus")
        self.assertIn(peer, result.required_lease)

    def test_busy_dependency_preserves_eligible_but_blocks_available(self):
        peer = "0000:01:00.1"
        device = endpoint(
            reset_methods=("bus",),
            reset_domain=(TARGET, peer),
            reset_domain_source="vfio-hot-reset-info",
        )
        inventory = host(
            device,
            devices={
                TARGET: device,
                peer: dependency_device(peer, (TARGET, peer)),
            },
            leases={peer: "other-vm"},
        )

        result = evaluate(inventory)

        self.assertTrue(result.eligible)
        self.assertFalse(result.available)
        self.assertFalse(result.attachable)
        self.assertIn("DEPENDENCY_BUSY", [item.code for item in result.reasons])

    def test_same_exclusive_attach_group_is_not_coalesced_by_default(self):
        peer = "0000:01:00.1"
        group = "dependent:0000:00:08.0"
        device = endpoint(exclusive_attach_group=group)
        peer_device = replace(
            endpoint(),
            bdf=peer,
            bars=(),
            iommu_group=(peer,),
            physical_isolation_domain=(peer,),
            reset_domain=(peer,),
            exclusive_attach_group=group,
        )
        inventory = host(device, devices={TARGET: device, peer: peer_device})

        result = evaluate(inventory, payload_devices=[peer])

        self.assertTrue(result.eligible)
        self.assertTrue(result.available)
        self.assertFalse(result.attachable)
        self.assertIn(
            "EXCLUSIVE_ATTACH_GROUP_COLLISION",
            [item.code for item in result.reasons],
        )

    def test_shared_attach_group_requires_explicit_qualified_policy(self):
        peer = "0000:01:00.1"
        group = "dependent:0000:00:08.0"
        device = endpoint(exclusive_attach_group=group)
        peer_device = replace(
            endpoint(),
            bdf=peer,
            bars=(),
            iommu_group=(peer,),
            physical_isolation_domain=(peer,),
            reset_domain=(peer,),
            exclusive_attach_group=group,
        )
        inventory = host(device, devices={TARGET: device, peer: peer_device})

        result = evaluate(
            inventory,
            payload_devices=[peer],
            policy=CapabilityPolicy(qualified_shared_attach_groups=(group,)),
        )

        self.assertTrue(result.attachable)

    def test_qualified_shared_attach_group_does_not_open_another_group(self):
        peer = "0000:01:00.1"
        actual_group = "dependent:0000:00:08.0"
        device = endpoint(exclusive_attach_group=actual_group)
        peer_device = replace(
            endpoint(),
            bdf=peer,
            bars=(),
            iommu_group=(peer,),
            physical_isolation_domain=(peer,),
            reset_domain=(peer,),
            exclusive_attach_group=actual_group,
        )
        inventory = host(device, devices={TARGET: device, peer: peer_device})

        result = evaluate(
            inventory,
            payload_devices=[peer],
            policy=CapabilityPolicy(
                qualified_shared_attach_groups=("dependent:0000:00:09.0",)
            ),
        )

        self.assertFalse(result.attachable)
        self.assertIn(
            "EXCLUSIVE_ATTACH_GROUP_COLLISION",
            [item.code for item in result.reasons],
        )

    def test_acs_override_can_be_denied_by_policy(self):
        device = endpoint(
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
            physical_isolation_domain=(TARGET, "0000:02:00.0"),
            physical_isolation_domain_source=(
                "kernel-acs-provenance-topology-conservative"
            ),
        )

        result = evaluate(
            host(device, acs_override_active=True),
            policy=CapabilityPolicy(allow_acs_override=False),
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "ACS_OVERRIDE_NOT_ALLOWED", [item.code for item in result.reasons]
        )

    def test_acs_override_requires_known_whole_domain(self):
        device = endpoint(
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
            physical_isolation_domain=(),
        )

        result = evaluate(
            host(device, acs_override_active=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "PHYSICAL_ISOLATION_DOMAIN_UNKNOWN",
            [item.code for item in result.reasons],
        )

    def test_known_override_domain_is_conditional_and_leased(self):
        peer = "0000:02:00.0"
        device = endpoint(
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
            physical_isolation_domain=(TARGET, peer),
            physical_isolation_domain_source=(
                "kernel-acs-provenance-topology-conservative"
            ),
        )

        peer_device = replace(
            dependency_device(peer, (TARGET, peer)),
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
        )
        result = evaluate(
            host(
                device,
                acs_override_active=True,
                devices={TARGET: device, peer: peer_device},
            ),
        )

        self.assertTrue(result.attachable)
        self.assertEqual(result.verdict, "conditional")
        self.assertIn(peer, result.required_lease)

    def test_override_domain_without_provenance_is_rejected(self):
        device = endpoint(
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
            physical_isolation_domain=(TARGET,),
            physical_isolation_domain_source="unknown",
        )

        result = evaluate(host(device, acs_override_active=True))

        self.assertFalse(result.eligible)
        self.assertIn(
            "PHYSICAL_ISOLATION_DOMAIN_UNTRUSTED",
            [item.code for item in result.reasons],
        )

    def test_estimated_bus_reset_domain_fails_closed(self):
        peer = "0000:01:00.1"
        device = endpoint(
            reset_methods=("bus",),
            reset_domain=(TARGET, peer),
            reset_domain_source="sysfs-parent-topology-estimate",
        )
        inventory = host(
            device,
            devices={
                TARGET: device,
                peer: dependency_device(peer, (TARGET, peer)),
            },
        )

        result = evaluate(inventory)

        self.assertFalse(result.eligible)
        self.assertIn("RESET_DOMAIN_UNVERIFIED", [item.code for item in result.reasons])

    def test_missing_dependency_inventory_blocks_availability(self):
        peer = "0000:02:00.0"
        device = endpoint(
            physical_isolation_domain=(TARGET, peer),
        )

        result = evaluate(host(device))

        self.assertTrue(result.eligible)
        self.assertFalse(result.available)
        self.assertIn(
            "DEPENDENCY_NOT_IN_INVENTORY",
            [item.code for item in result.reasons],
        )

    def test_mmio_failure_is_late_attachable_gate(self):
        device = endpoint(
            bars=(Bar(TARGET, 0, 2 * GIB, is_64=False),),
        )

        result = evaluate(host(device), high_windows=())

        self.assertTrue(result.eligible)
        self.assertTrue(result.available)
        self.assertFalse(result.attachable)
        self.assertIn("MMIO32_EXHAUSTED", [item.code for item in result.reasons])

    def test_unknown_interrupt_remapping_fails_closed(self):
        result = evaluate(host(interrupt_remapping=None))

        self.assertFalse(result.eligible)
        self.assertIn("INTERRUPT_REMAP_UNKNOWN", [item.code for item in result.reasons])

    def test_host_driver_can_be_rebound_without_changing_capable(self):
        device = endpoint(driver="ixgbe")

        result = evaluate(host(device))

        self.assertTrue(result.attachable)
        self.assertIn(
            "HOST_DRIVER_REBIND_REQUIRED",
            [item.code for item in result.warnings],
        )


if __name__ == "__main__":
    unittest.main()
