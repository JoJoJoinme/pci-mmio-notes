import hashlib
import json
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pci_resource_model.capability import TRUSTED_PHYSICAL_DOMAIN_SOURCES
from pci_resource_model.linux_sysfs import (
    _dma_isolation,
    parse_acs_state,
    parse_resource_lines,
)
from pci_resource_model.linux_sysfs import (
    SOFTWARE_TOPOLOGY_ESTIMATE_SOURCE,
    add_conservative_assignment_groups,
    parse_pcie_type,
    reconstruct_physical_isolation_domains,
)
from pci_resource_model.model import (
    DeviceInventory,
    DmaIsolationMode,
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
    aliases=None,
    pcie_type="default",
):
    resolved_pcie_type = (
        4 if role == FunctionRole.FABRIC else 0
    ) if pcie_type == "default" else pcie_type
    return DeviceInventory(
        bdf=bdf,
        vendor_id=0x1AF4,
        device_id=0x1000,
        class_code=0x060400 if role == FunctionRole.FABRIC else 0x020000,
        header_type=1 if role == FunctionRole.FABRIC else 0,
        function_role=role,
        iommu_group=tuple(group or (bdf,)),
        multifunction_aliases=tuple(aliases or ()),
        parent=parent,
        acs_native_isolation=native,
        acs_effective_isolation=effective,
        acs_override_source=override_source,
        metadata={"pcieType": resolved_pcie_type},
    )


def device_projection_hash(devices, members):
    projection = {
        bdf: devices[bdf].to_dict()
        for bdf in sorted(members)
    }
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class LinuxSysfsParserTests(unittest.TestCase):
    def test_vfio_noiommu_devnode_is_per_device_negative_proof(self):
        with TemporaryDirectory() as directory:
            vfio_root = Path(directory)
            (vfio_root / "noiommu-7").touch()
            with patch(
                "pci_resource_model.linux_sysfs._iommu_group_id",
                return_value="7",
            ):
                mode, source = _dma_isolation(
                    Path("/synthetic/0000:01:00.0"),
                    ("0000:01:00.0",),
                    vfio_root=vfio_root,
                )

        self.assertEqual(mode, DmaIsolationMode.NO_IOMMU)
        self.assertEqual(source, "vfio-noiommu-devnode")

    def test_real_group_without_noiommu_devnode_is_iommu_backed(self):
        with TemporaryDirectory() as directory:
            with patch(
                "pci_resource_model.linux_sysfs._iommu_group_id",
                return_value="9",
            ):
                mode, source = _dma_isolation(
                    Path("/synthetic/0000:01:00.0"),
                    ("0000:01:00.0",),
                    vfio_root=Path(directory),
                )

        self.assertEqual(mode, DmaIsolationMode.IOMMU)
        self.assertEqual(source, "linux-iommu-group")

    def test_unsafe_switch_and_vfio_without_provider_node_is_unknown(self):
        with TemporaryDirectory() as directory:
            with (
                patch(
                    "pci_resource_model.linux_sysfs._iommu_group_id",
                    return_value="9",
                ),
                patch(
                    "pci_resource_model.linux_sysfs._driver_name",
                    return_value="vfio-pci",
                ),
            ):
                mode, source = _dma_isolation(
                    Path("/synthetic/0000:01:00.0"),
                    ("0000:01:00.0",),
                    vfio_root=Path(directory),
                    unsafe_noiommu_mode_enabled=True,
                )

        self.assertEqual(mode, DmaIsolationMode.UNKNOWN)
        self.assertEqual(source, "ambiguous-vfio-group")

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
            SOFTWARE_TOPOLOGY_ESTIMATE_SOURCE,
        )
        self.assertNotIn(
            result[left].physical_isolation_domain_source,
            TRUSTED_PHYSICAL_DOMAIN_SOURCES,
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

    def test_missing_kernel_provenance_invalidates_affected_topology_component(self):
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

    def test_inconsistent_kernel_provenance_invalidates_affected_topology_component(self):
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

    def test_missing_provenance_does_not_taint_disjoint_complete_component(self):
        bad_root = "0000:00:01.0"
        bad_endpoint = "0000:01:00.0"
        good_root = "0000:00:02.0"
        good_endpoint = "0000:02:00.0"
        good_devices = {
            good_root: inventory_device(
                good_root,
                role=FunctionRole.FABRIC,
                native=False,
                effective=True,
                override_source="downstream",
            ),
            good_endpoint: inventory_device(good_endpoint, parent=good_root),
        }
        combined_devices = {
            bad_root: inventory_device(
                bad_root,
                role=FunctionRole.FABRIC,
                native=False,
                effective=True,
                override_source="downstream",
            ),
            bad_endpoint: inventory_device(
                bad_endpoint,
                parent=bad_root,
                native=None,
            ),
            **good_devices,
        }

        baseline = reconstruct_physical_isolation_domains(
            good_devices,
            acs_override_active=True,
        )
        combined = reconstruct_physical_isolation_domains(
            combined_devices,
            acs_override_active=True,
        )

        self.assertEqual(combined[bad_root].physical_isolation_domain, ())
        self.assertEqual(combined[bad_endpoint].physical_isolation_domain, ())
        expected_bad_component = [bad_root, bad_endpoint]
        expected_reason = (
            f"{bad_endpoint}:acs-native-isolation:missing"
        )
        for bdf in expected_bad_component:
            self.assertEqual(
                combined[bdf].metadata["physicalIsolationUnknownComponent"],
                expected_bad_component,
            )
            self.assertIn(
                expected_reason,
                combined[bdf].metadata["physicalIsolationUnknownReasons"],
            )
        expected_good_domain = (good_root, good_endpoint)
        self.assertEqual(
            combined[good_root].physical_isolation_domain,
            expected_good_domain,
        )
        self.assertEqual(
            combined[good_endpoint].physical_isolation_domain,
            expected_good_domain,
        )
        for bdf in expected_good_domain:
            self.assertEqual(combined[bdf].to_dict(), baseline[bdf].to_dict())
        self.assertEqual(
            device_projection_hash(combined, expected_good_domain),
            device_projection_hash(baseline, expected_good_domain),
        )

        expected_full_hash = device_projection_hash(combined, combined)
        items = list(combined_devices.items())
        randomizer = random.Random(0xC16)
        for iteration in range(16):
            randomizer.shuffle(items)
            reordered = reconstruct_physical_isolation_domains(
                dict(items),
                acs_override_active=True,
            )
            with self.subTest(insertion_order=iteration):
                for bdf in combined:
                    self.assertEqual(
                        reordered[bdf].to_dict(),
                        combined[bdf].to_dict(),
                    )
                self.assertEqual(
                    device_projection_hash(reordered, expected_good_domain),
                    device_projection_hash(combined, expected_good_domain),
                )
                self.assertEqual(
                    device_projection_hash(reordered, reordered),
                    expected_full_hash,
                )

    def test_incomplete_topology_relationships_fail_closed_per_component(self):
        dangling = "0000:03:00.0"
        missing_parent = "0000:00:03.0"
        cycle_left = "0000:04:00.0"
        cycle_right = "0000:04:00.1"
        missing_group_member = "0000:05:00.1"
        group_endpoint = "0000:05:00.0"
        missing_alias_member = "0000:06:00.1"
        alias_endpoint = "0000:06:00.0"
        asymmetric_group_left = "0000:09:00.0"
        asymmetric_group_right = "0000:09:00.1"
        asymmetric_alias_left = "0000:0a:00.0"
        asymmetric_alias_right = "0000:0a:00.1"
        overlap_group_left = "0000:0b:00.0"
        overlap_group_middle = "0000:0b:00.1"
        overlap_group_right = "0000:0b:00.2"
        missing_self_alias_left = "0000:0c:00.0"
        missing_self_alias_right = "0000:0c:00.1"
        cases = {
            "dangling-parent": (
                {
                    dangling: inventory_device(
                        dangling,
                        parent=missing_parent,
                    )
                },
                (dangling,),
                f"{dangling}:parent:missing:{missing_parent}",
            ),
            "parent-cycle": (
                {
                    cycle_left: inventory_device(
                        cycle_left,
                        parent=cycle_right,
                    ),
                    cycle_right: inventory_device(
                        cycle_right,
                        parent=cycle_left,
                    ),
                },
                (cycle_left, cycle_right),
                f"parent-cycle:{cycle_left},{cycle_right}",
            ),
            "missing-group-member": (
                {
                    group_endpoint: inventory_device(
                        group_endpoint,
                        group=(group_endpoint, missing_group_member),
                    )
                },
                (group_endpoint,),
                (
                    f"{group_endpoint}:iommu-group:missing:"
                    f"{missing_group_member}"
                ),
            ),
            "missing-alias-member": (
                {
                    alias_endpoint: inventory_device(
                        alias_endpoint,
                        aliases=(alias_endpoint, missing_alias_member),
                    )
                },
                (alias_endpoint,),
                (
                    f"{alias_endpoint}:multifunction-alias:missing:"
                    f"{missing_alias_member}"
                ),
            ),
            "asymmetric-group": (
                {
                    asymmetric_group_left: inventory_device(
                        asymmetric_group_left,
                        group=(
                            asymmetric_group_left,
                            asymmetric_group_right,
                        ),
                    ),
                    asymmetric_group_right: inventory_device(
                        asymmetric_group_right,
                    ),
                },
                (asymmetric_group_left, asymmetric_group_right),
                (
                    f"{asymmetric_group_left}:iommu-group:asymmetric:"
                    f"{asymmetric_group_right}"
                ),
            ),
            "asymmetric-alias": (
                {
                    asymmetric_alias_left: inventory_device(
                        asymmetric_alias_left,
                        aliases=(
                            asymmetric_alias_left,
                            asymmetric_alias_right,
                        ),
                    ),
                    asymmetric_alias_right: inventory_device(
                        asymmetric_alias_right,
                    ),
                },
                (asymmetric_alias_left, asymmetric_alias_right),
                (
                    f"{asymmetric_alias_left}:multifunction-alias:"
                    f"asymmetric:{asymmetric_alias_right}"
                ),
            ),
            "reciprocal-overlapping-groups": (
                {
                    overlap_group_left: inventory_device(
                        overlap_group_left,
                        group=(
                            overlap_group_left,
                            overlap_group_middle,
                            overlap_group_right,
                        ),
                    ),
                    overlap_group_middle: inventory_device(
                        overlap_group_middle,
                        group=(
                            overlap_group_left,
                            overlap_group_middle,
                        ),
                    ),
                    overlap_group_right: inventory_device(
                        overlap_group_right,
                        group=(
                            overlap_group_left,
                            overlap_group_right,
                        ),
                    ),
                },
                (
                    overlap_group_left,
                    overlap_group_middle,
                    overlap_group_right,
                ),
                (
                    f"{overlap_group_left}:iommu-group:set-mismatch:"
                    f"{overlap_group_middle}"
                ),
            ),
            "alias-set-missing-self": (
                {
                    missing_self_alias_left: inventory_device(
                        missing_self_alias_left,
                        aliases=(missing_self_alias_right,),
                    ),
                    missing_self_alias_right: inventory_device(
                        missing_self_alias_right,
                        aliases=(missing_self_alias_left,),
                    ),
                },
                (missing_self_alias_left, missing_self_alias_right),
                (
                    f"{missing_self_alias_left}:multifunction-alias:"
                    f"self-missing"
                ),
            ),
        }

        for name, (devices, affected, expected_reason) in cases.items():
            with self.subTest(name=name):
                result = reconstruct_physical_isolation_domains(
                    devices,
                    acs_override_active=True,
                )
                for bdf in affected:
                    self.assertEqual(result[bdf].physical_isolation_domain, ())
                    self.assertEqual(
                        result[bdf].metadata[
                            "physicalIsolationUnknownComponent"
                        ],
                        list(affected),
                    )
                    self.assertIn(
                        expected_reason,
                        result[bdf].metadata[
                            "physicalIsolationUnknownReasons"
                        ],
                    )

    def test_incomplete_shared_legacy_anchor_taints_the_whole_bus_component(self):
        left = "0000:00:10.0"
        right = "0000:00:11.0"

        def legacy_device(bdf, **changes):
            return inventory_device(
                bdf,
                native=False,
                effective=True,
                override_source="downstream",
                pcie_type=None,
                **changes,
            )

        complete_devices = {
            left: legacy_device(left),
            right: legacy_device(right),
        }
        complete = reconstruct_physical_isolation_domains(
            complete_devices,
            acs_override_active=True,
        )
        expected_domain = (left, right)
        for bdf in expected_domain:
            self.assertEqual(
                complete[bdf].physical_isolation_domain,
                expected_domain,
            )

        incomplete_variants = {
            "missing-native": inventory_device(
                right,
                native=None,
                effective=True,
                override_source="downstream",
                pcie_type=None,
            ),
            "invalid-source": inventory_device(
                right,
                native=False,
                effective=True,
                override_source="unknown",
                pcie_type=None,
            ),
        }
        for name, incomplete_right in incomplete_variants.items():
            with self.subTest(name=name):
                devices = {
                    left: legacy_device(left),
                    right: incomplete_right,
                }
                result = reconstruct_physical_isolation_domains(
                    devices,
                    acs_override_active=True,
                )
                reverse = reconstruct_physical_isolation_domains(
                    dict(reversed(tuple(devices.items()))),
                    acs_override_active=True,
                )
                for bdf in expected_domain:
                    self.assertEqual(result[bdf].physical_isolation_domain, ())
                    self.assertEqual(
                        result[bdf].metadata[
                            "physicalIsolationUnknownComponent"
                        ],
                        list(expected_domain),
                    )
                    self.assertEqual(
                        reverse[bdf].to_dict(),
                        result[bdf].to_dict(),
                    )
                self.assertEqual(
                    device_projection_hash(result, result),
                    device_projection_hash(reverse, reverse),
                )

    def test_shared_kernel_group_propagates_unknown_across_topology_roots(self):
        bad_endpoint = "0000:07:00.0"
        peer_endpoint = "0000:08:00.0"
        shared_group = (bad_endpoint, peer_endpoint)
        devices = {
            bad_endpoint: inventory_device(
                bad_endpoint,
                native=None,
                group=shared_group,
            ),
            peer_endpoint: inventory_device(
                peer_endpoint,
                group=shared_group,
            ),
        }

        result = reconstruct_physical_isolation_domains(
            devices,
            acs_override_active=True,
        )

        for bdf in shared_group:
            self.assertEqual(result[bdf].physical_isolation_domain, ())
            self.assertEqual(
                result[bdf].metadata["physicalIsolationUnknownComponent"],
                list(shared_group),
            )

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
