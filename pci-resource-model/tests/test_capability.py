import unittest
from dataclasses import replace

from pci_resource_model.allocator import GIB
from pci_resource_model.capability import CapabilityPolicy, evaluate_passthrough
from pci_resource_model.model import (
    AddressRange,
    Bar,
    DeviceInventory,
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
        "isolation_provenance": IsolationProvenance.KERNEL_GROUP,
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
    return replace(
        endpoint(),
        bdf=bdf,
        bars=(),
        iommu_group=tuple(members),
        physical_isolation_domain=tuple(members),
        reset_domain=(bdf,),
    )


def evaluate(inventory, **changes):
    values = {
        "low_windows": (AddressRange(0xC0000000, 0x100000000),),
        "high_windows": (AddressRange(0x100000000, 0x300000000),),
    }
    values.update(changes)
    return evaluate_passthrough(inventory, TARGET, **values)


class CapabilityTests(unittest.TestCase):
    def test_happy_path_is_attachable(self):
        result = evaluate(host())

        self.assertTrue(result.eligible)
        self.assertTrue(result.available)
        self.assertTrue(result.attachable)
        self.assertEqual(result.verdict, "true")
        self.assertEqual(result.reset_methods[TARGET], "flr")
        self.assertEqual(result.allocation.high_aperture_bytes, 2 * GIB)

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

    def test_acs_override_is_rejected_by_default(self):
        device = endpoint(
            isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
            physical_isolation_domain=(TARGET, "0000:02:00.0"),
        )

        result = evaluate(host(device, acs_override_active=True))

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
            policy=CapabilityPolicy(allow_acs_override=True),
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
            policy=CapabilityPolicy(allow_acs_override=True),
        )

        self.assertTrue(result.attachable)
        self.assertEqual(result.verdict, "conditional")
        self.assertIn(peer, result.required_lease)

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
