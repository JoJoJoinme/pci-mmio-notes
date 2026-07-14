import json
import tempfile
import unittest
from pathlib import Path

from pci_resource_model.cli import main


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "two-gib-endpoint.json"


class CliTests(unittest.TestCase):
    def test_capable_inherits_interrupt_remapping_from_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            rc = main(
                [
                    "capable",
                    "--inventory",
                    str(EXAMPLE),
                    "--target",
                    "0000:65:00.0",
                    "--mmio32",
                    "0x80000000:0xc0000000",
                    "--mmio64",
                    "0x100000000:0x200000000",
                    "--output",
                    str(output),
                ]
            )
            result = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertTrue(result["passthroughCapable"])
        self.assertTrue(result["attachable"])

    def test_allocate_emits_linked_ovmf_and_qemu_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            rc = main(
                [
                    "allocate",
                    "--inventory",
                    str(EXAMPLE),
                    "--device",
                    "0000:65:00.0",
                    "--mmio32",
                    "0x80000000:0xc0000000",
                    "--mmio64",
                    "0x100000000:0x200000000",
                    "--output",
                    str(output),
                ]
            )
            result = json.loads(output.read_text(encoding="utf-8"))["result"]

        self.assertEqual(rc, 0)
        self.assertEqual(result["highApertureBytes"], 2 << 30)
        self.assertIn(
            "name=opt/ovmf/X-PciMmio64Mb,string=2048",
            result["qemuArguments"],
        )
        self.assertIn(
            "q35-pcihost.pci-hole64-size=2G",
            result["qemuArguments"],
        )


if __name__ == "__main__":
    unittest.main()
