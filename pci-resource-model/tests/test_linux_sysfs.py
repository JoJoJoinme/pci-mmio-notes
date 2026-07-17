import unittest

from pci_resource_model.linux_sysfs import parse_acs_state, parse_resource_lines
from pci_resource_model.linux_sysfs import (
    add_conservative_assignment_groups,
    parse_pcie_type,
    reconstruct_physical_isolation_domains,
)
from pci_resource_model.model import (
    DeviceInventory,
    FunctionRole,
    IsolationProvenance,
)


def inventory_device(
    bdf,
    *,
    parent=None,
    role=FunctionRole.ENDPOINT,
    native=True,
    effective=True,
    override_source="none",
    group=None,
):
    return DeviceInventory(
        bdf=bdf,
        vendor_id=0x1AF4,
        device_id=0x1000,
        class_code=0x060400 if role == FunctionRole.FABRIC else 0x020000,
        header_type=1 if role == FunctionRole.FABRIC else 0,
        function_role=role,
        iommu_group=tuple(group or (bdf,)),
        parent=parent,
        acs_native_isolation=native,
        acs_effective_isolation=effective,
        acs_override_source=override_source,
        metadata={"pcieType": 4 if role == FunctionRole.FABRIC else 0},
    )


class LinuxSysfsParserTests(unittest.TestCase):
    def test_parses_one_64bit_bar_without_emitting_upper_slot(self):
        config = bytearray(4096)
        config[0x0E] = 0
        config[0x18:0x1C] = (0x0000000C).to_bytes(4, "little")
        config[0x1C:0x20] = (0x00000001).to_bytes(4, "little")
        lines = ["0x0 0x0 0x0"] * 6
        lines[2] = "0x100000000 0x17fffffff 0x102200"

        bars = parse_resource_lines(
            "\n".join(lines),
            bdf="0000:01:00.0",
            header_type=0,
            config=bytes(config),
        )

        self.assertEqual(len(bars), 1)
        self.assertEqual(bars[0].index, 2)
        self.assertEqual(bars[0].size, 2 << 30)
        self.assertTrue(bars[0].is_64)
        self.assertTrue(bars[0].prefetchable)

    def test_parses_acs_extended_capability_and_control(self):
        config = bytearray(4096)
        config[0x100:0x104] = (0x0000000D).to_bytes(4, "little")
        config[0x104:0x106] = (0x001C).to_bytes(2, "little")
        config[0x106:0x108] = (0x001C).to_bytes(2, "little")

        acs = parse_acs_state(bytes(config))

        self.assertIsNotNone(acs)
        self.assertEqual(acs.offset, 0x100)
        self.assertTrue(acs.redirect_enabled)

    def test_invalid_extended_capability_chain_stops_safely(self):
        config = bytearray(4096)
        # next pointer points backwards and is rejected.
        config[0x100:0x104] = ((0x080 << 20) | 0x0001).to_bytes(4, "little")

        self.assertIsNone(parse_acs_state(bytes(config)))

    def test_parses_pcie_device_port_type(self):
        config = bytearray(256)
        config[0x06:0x08] = (0x10).to_bytes(2, "little")
        config[0x34] = 0x40
        config[0x40] = 0x10
        config[0x42:0x44] = (4 << 4).to_bytes(2, "little")

        self.assertEqual(parse_pcie_type(bytes(config)), 4)

    def test_override_rebuilds_domain_below_nonisolating_root_port(self):
        root_port = "0000:00:01.0"
        left = "0000:01:00.0"
        right = "0000:01:00.1"
        devices = {
            root_port: inventory_device(
                root_port,
                role=FunctionRole.FABRIC,
                native=False,
                effective=True,
                override_source="downstream",
            ),
            left: inventory_device(left, parent=root_port),
            right: inventory_device(right, parent=root_port),
        }

        result = reconstruct_physical_isolation_domains(
            devices,
            acs_override_active=True,
        )

        expected = (root_port, left, right)
        self.assertEqual(result[left].physical_isolation_domain, expected)
        self.assertEqual(
            result[left].physical_isolation_domain_source,
            "kernel-acs-provenance-topology-conservative",
        )
        self.assertEqual(
            result[left].isolation_provenance,
            IsolationProvenance.ACS_OVERRIDE,
        )

        grouped = add_conservative_assignment_groups(result)
        self.assertEqual(
            grouped[left].exclusive_attach_group,
            grouped[right].exclusive_attach_group,
        )
        self.assertEqual(
            grouped[left].owner_activation_group,
            grouped[root_port].owner_activation_group,
        )

    def test_missing_kernel_provenance_invalidates_every_shadow_domain(self):
        root_port = "0000:00:01.0"
        endpoint = "0000:01:00.0"
        devices = {
            root_port: inventory_device(
                root_port,
                role=FunctionRole.FABRIC,
                native=False,
                effective=True,
                override_source="downstream",
            ),
            endpoint: inventory_device(endpoint, parent=root_port, native=None),
        }

        result = reconstruct_physical_isolation_domains(
            devices,
            acs_override_active=True,
        )

        self.assertEqual(result[endpoint].physical_isolation_domain, ())
        self.assertEqual(result[root_port].physical_isolation_domain, ())

    def test_inconsistent_kernel_provenance_invalidates_every_shadow_domain(self):
        root_port = "0000:00:01.0"
        endpoint = "0000:01:00.0"
        devices = {
            root_port: inventory_device(
                root_port,
                role=FunctionRole.FABRIC,
                native=True,
                effective=False,
            ),
            endpoint: inventory_device(endpoint, parent=root_port),
        }

        result = reconstruct_physical_isolation_domains(
            devices,
            acs_override_active=True,
        )

        self.assertEqual(result[endpoint].physical_isolation_domain, ())
        self.assertEqual(result[root_port].physical_isolation_domain, ())

    def test_global_override_does_not_taint_an_independent_native_path(self):
        endpoint = "0000:01:00.0"
        devices = {endpoint: inventory_device(endpoint)}

        result = reconstruct_physical_isolation_domains(
            devices,
            acs_override_active=True,
        )

        self.assertEqual(result[endpoint].physical_isolation_domain, (endpoint,))
        self.assertEqual(
            result[endpoint].physical_isolation_domain_source,
            "kernel-no-override-iommu-group",
        )
        self.assertEqual(
            result[endpoint].isolation_provenance,
            IsolationProvenance.KERNEL_GROUP,
        )


if __name__ == "__main__":
    unittest.main()
