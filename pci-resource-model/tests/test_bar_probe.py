import tempfile
import unittest
from pathlib import Path

from pci_resource_model.bar_probe import (
    LinuxSysfsConfigSpace,
    ProbeError,
    probe_standard_bars,
    probe_unbound_linux_device,
)
from pci_resource_model.model import BarSpace


class SizingConfig:
    def __init__(self, *, header_type=0, command=0x0007, bars=None, masks=None):
        self.data = bytearray(256)
        self.data[0x0E] = header_type
        self.data[0x04:0x06] = command.to_bytes(2, "little")
        for index, value in enumerate(bars or [0] * 6):
            offset = 0x10 + index * 4
            self.data[offset : offset + 4] = value.to_bytes(4, "little")
        self.masks = {0x10 + index * 4: value for index, value in (masks or {}).items()}
        self.probing = set()
        self.history = []
        self.fail_probe_offset = None
        self.fail_restore_offset = None

    def read(self, offset, width):
        if offset in self.probing:
            if self.fail_probe_offset == offset:
                self.fail_probe_offset = None
                raise OSError("injected config read failure")
            return self.masks.get(offset, 0)
        return int.from_bytes(self.data[offset : offset + width], "little")

    def write(self, offset, width, value):
        self.history.append((offset, width, value))
        if width == 4 and offset in self.masks and value == 0xFFFFFFFF:
            self.probing.add(offset)
            return
        if width == 4 and self.fail_restore_offset == offset:
            raise OSError("injected config restore failure")
        self.probing.discard(offset)
        self.data[offset : offset + width] = value.to_bytes(width, "little")

    def dword(self, index):
        offset = 0x10 + index * 4
        return int.from_bytes(self.data[offset : offset + 4], "little")

    @property
    def command(self):
        return int.from_bytes(self.data[0x04:0x06], "little")


class BarProbeTests(unittest.TestCase):
    def test_probes_32bit_memory_bar_and_restores_state(self):
        config = SizingConfig(
            bars=[0x80000008, 0, 0, 0, 0, 0],
            masks={0: 0xFF000008},
        )

        result = probe_standard_bars(config, "0000:01:00.0")

        self.assertEqual(len(result.bars), 1)
        bar = result.bars[0]
        self.assertEqual(bar.index, 0)
        self.assertEqual(bar.size, 16 << 20)
        self.assertEqual(bar.address, 0x80000000)
        self.assertTrue(bar.prefetchable)
        self.assertFalse(bar.is_64)
        self.assertEqual(config.command, 0x0007)
        self.assertEqual(config.dword(0), 0x80000008)
        self.assertIn((0x04, 2, 0), config.history)

    def test_64bit_bar_consumes_two_slots(self):
        config = SizingConfig(
            bars=[0, 0, 0x0000000C, 0x00000004, 0, 0],
            masks={2: 0x0000000C, 3: 0xFFFFFFFE},
        )

        result = probe_standard_bars(config, "0000:02:00.0")

        self.assertEqual([bar.index for bar in result.bars], [2])
        bar = result.bars[0]
        self.assertEqual(bar.size, 8 << 30)
        self.assertEqual(bar.address, 16 << 30)
        self.assertTrue(bar.is_64)
        self.assertTrue(bar.prefetchable)
        self.assertEqual(config.dword(2), 0x0000000C)
        self.assertEqual(config.dword(3), 0x00000004)

    def test_type1_probes_only_two_standard_slots(self):
        config = SizingConfig(
            header_type=1,
            bars=[0x90000000, 0, 0xA0000000, 0, 0, 0],
            masks={0: 0xFFF00000, 2: 0xFFF00000},
        )

        result = probe_standard_bars(config, "0000:00:01.0")

        self.assertEqual(result.slot_count, 2)
        self.assertEqual([bar.index for bar in result.bars], [0])

    def test_io_bar_is_optional(self):
        config = SizingConfig(
            bars=[0x0000C001, 0, 0, 0, 0, 0],
            masks={0: 0xFFFFFF01},
        )
        self.assertEqual(
            probe_standard_bars(config, "0000:03:00.0").bars,
            (),
        )

        included = probe_standard_bars(config, "0000:03:00.0", include_io=True).bars
        self.assertEqual(len(included), 1)
        self.assertEqual(included[0].space, BarSpace.IO)
        self.assertEqual(included[0].size, 0x100)

    def test_probe_failure_still_restores_every_bar_and_command(self):
        original = [0x80000000, 0, 0, 0, 0, 0]
        config = SizingConfig(bars=original, masks={0: 0xFFF00000})
        config.fail_probe_offset = 0x10

        with self.assertRaises(OSError):
            probe_standard_bars(config, "0000:04:00.0")

        self.assertEqual(config.command, 0x0007)
        self.assertEqual([config.dword(i) for i in range(6)], original)

    def test_truncated_64bit_bar_is_rejected_and_restored(self):
        config = SizingConfig(
            header_type=1,
            bars=[0, 0x00000004, 0, 0, 0, 0],
            masks={1: 0xFFFFFFF4},
        )

        with self.assertRaises(ProbeError) as raised:
            probe_standard_bars(config, "0000:00:02.0")

        self.assertEqual(raised.exception.code, "TRUNCATED_64BIT_BAR")
        self.assertEqual(config.command, 0x0007)
        self.assertEqual(config.dword(1), 0x00000004)

    def test_reserved_memory_type_is_rejected_and_restored(self):
        config = SizingConfig(
            bars=[0x80000006, 0, 0, 0, 0, 0],
            masks={0: 0xFFF00006},
        )

        with self.assertRaises(ProbeError) as raised:
            probe_standard_bars(config, "0000:05:00.0")

        self.assertEqual(raised.exception.code, "UNSUPPORTED_MEMORY_BAR_TYPE")
        self.assertEqual(config.command, 0x0007)
        self.assertEqual(config.dword(0), 0x80000006)

    def test_restore_failure_has_a_distinct_error_code(self):
        config = SizingConfig(
            bars=[0x80000000, 0, 0, 0, 0, 0],
            masks={0: 0xFFF00000},
        )
        config.fail_restore_offset = 0x10

        with self.assertRaises(ProbeError) as raised:
            probe_standard_bars(config, "0000:05:00.0")

        self.assertEqual(raised.exception.code, "CONFIG_RESTORE_FAILED")
        self.assertEqual(config.command, 0x0007)

    def test_linux_config_backend_performs_exact_width_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_bytes(bytes(64))
            with LinuxSysfsConfigSpace(path, writable=True) as accessor:
                accessor.write(0x10, 4, 0x12345678)
                self.assertEqual(accessor.read(0x10, 4), 0x12345678)
            with LinuxSysfsConfigSpace(path) as accessor:
                with self.assertRaises(PermissionError):
                    accessor.write(0x10, 4, 0)

    def test_live_linux_probe_requires_explicit_acknowledgement(self):
        with self.assertRaises(ProbeError) as raised:
            probe_unbound_linux_device("0000:01:00.0")

        self.assertEqual(raised.exception.code, "LIVE_WRITE_NOT_ACKNOWLEDGED")


if __name__ == "__main__":
    unittest.main()
