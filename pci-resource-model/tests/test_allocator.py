import unittest

from pci_resource_model.allocator import GIB, AllocationPolicy, plan_mmio
from pci_resource_model.model import AddressRange, Bar


def memory_bar(index, size, *, is_64=True, bdf="0000:01:00.0"):
    return Bar(bdf=bdf, index=index, size=size, is_64=is_64)


class AllocatorTests(unittest.TestCase):
    def test_one_gib_bar_fits_low_and_emits_zero_high_aperture(self):
        result = plan_mmio(
            [memory_bar(0, GIB)],
            low_windows=[AddressRange(0x80000000, 0xC0000000)],
            high_windows=[AddressRange(0x100000000, 0x200000000)],
        )

        self.assertTrue(result.success)
        self.assertEqual(result.allocations[0].pool, "mmio32")
        self.assertEqual(result.allocations[0].address, 0x80000000)
        self.assertEqual(result.high_aperture_bytes, 0)
        self.assertEqual(
            result.qemu_arguments(),
            [
                "-fw_cfg",
                "name=opt/ovmf/X-PciMmio64Mb,string=0",
                "-global",
                "q35-pcihost.pci-hole64-size=0",
            ],
        )

    def test_two_gib_bar_falls_back_to_high(self):
        result = plan_mmio(
            [memory_bar(0, 2 * GIB)],
            low_windows=[AddressRange(0x80000000, 0xC0000000)],
            high_windows=[AddressRange(0x100000000, 0x200000000)],
        )

        self.assertTrue(result.success)
        self.assertEqual(result.allocations[0].pool, "mmio64")
        self.assertEqual(result.allocations[0].address, 0x100000000)
        self.assertEqual(result.high_aperture_bytes, 2 * GIB)
        self.assertIn(
            "name=opt/ovmf/X-PciMmio64Mb,string=2048",
            result.qemu_arguments(),
        )
        self.assertIn(
            "q35-pcihost.pci-hole64-size=2G",
            result.qemu_arguments(),
        )

    def test_32bit_bar_is_placed_before_flexible_bar(self):
        bars = [
            memory_bar(0, GIB, is_64=True),
            memory_bar(2, GIB, is_64=False, bdf="0000:02:00.0"),
        ]
        result = plan_mmio(
            bars,
            low_windows=[AddressRange(0x80000000, 0xC0000000)],
            high_windows=[AddressRange(0x100000000, 0x200000000)],
        )

        allocations = {item.bar.key: item for item in result.allocations}
        self.assertTrue(result.success)
        self.assertEqual(allocations["0000:02:00.0/BAR2"].pool, "mmio32")
        self.assertEqual(allocations["0000:01:00.0/BAR0"].pool, "mmio64")

    def test_32bit_failure_is_transactional(self):
        result = plan_mmio(
            [memory_bar(0, 2 * GIB, is_64=False)],
            low_windows=[AddressRange(0xC0000000, 0x100000000)],
            high_windows=[AddressRange(0x100000000, 0x300000000)],
        )

        self.assertFalse(result.success)
        self.assertEqual(result.allocations, ())
        self.assertEqual(result.issues[0].code, "MMIO32_EXHAUSTED")

    def test_failed_multi_bar_plan_restores_reported_free_list(self):
        window = AddressRange(0x80000000, 0xD0000000)
        result = plan_mmio(
            [
                memory_bar(0, GIB, is_64=False),
                memory_bar(2, 512 << 20, is_64=False, bdf="0000:02:00.0"),
            ],
            low_windows=[window],
        )

        self.assertFalse(result.success)
        self.assertEqual(result.allocations, ())
        self.assertEqual(result.low_free, (window,))

    def test_reserved_range_is_removed_before_allocation(self):
        result = plan_mmio(
            [memory_bar(0, 512 << 20, is_64=False)],
            low_windows=[AddressRange(0x80000000, 0x100000000)],
            reserved=[AddressRange(0x80000000, 0xC0000000)],
        )

        self.assertTrue(result.success)
        self.assertEqual(result.allocations[0].address, 0xC0000000)

    def test_high_aperture_rounds_up_for_alignment(self):
        result = plan_mmio(
            [
                memory_bar(0, 2 * GIB),
                memory_bar(2, 512 << 20, bdf="0000:02:00.0"),
            ],
            low_windows=[AddressRange(0xF0000000, 0x100000000)],
            high_windows=[AddressRange(0x200000000, 0x400000000)],
            policy=AllocationPolicy(force_64bit_high=True),
        )

        self.assertTrue(result.success)
        self.assertEqual(result.high_aperture_bytes, 4 * GIB)

    def test_rejects_high_window_below_four_gib(self):
        result = plan_mmio(
            [memory_bar(0, GIB)],
            low_windows=[AddressRange(0xC0000000, 0x100000000)],
            high_windows=[AddressRange(0x80000000, 0x100000000)],
            policy=AllocationPolicy(force_64bit_high=True),
        )

        self.assertFalse(result.success)
        self.assertEqual(result.issues[0].code, "INVALID_MMIO64_WINDOW")


if __name__ == "__main__":
    unittest.main()
