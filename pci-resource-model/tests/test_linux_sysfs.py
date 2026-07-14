import unittest

from pci_resource_model.linux_sysfs import parse_acs_state, parse_resource_lines


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


if __name__ == "__main__":
    unittest.main()
