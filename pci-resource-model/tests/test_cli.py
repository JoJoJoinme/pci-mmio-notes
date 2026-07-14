import json
import tempfile
import unittest
from pathlib import Path

from pci_resource_model.cli import build_parser, main


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "two-gib-endpoint.json"
OVERRIDE_EXAMPLE = ROOT / "examples" / "mandatory-acs-override.json"


class CliTests(unittest.TestCase):
    def test_mandatory_override_is_allowed_by_default_but_can_be_denied(self):
        base = [
            "capable",
            "--inventory",
            str(EXAMPLE),
            "--target",
            "0000:65:00.0",
            "--mmio32",
            "0x80000000:0xc0000000",
        ]
        parser = build_parser()

        self.assertTrue(parser.parse_args(base).allow_acs_override)
        self.assertFalse(
            parser.parse_args([*base, "--deny-acs-override"]).allow_acs_override
        )

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

    def test_mandatory_override_requires_the_complete_physical_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            rc = main(
                [
                    "capable",
                    "--inventory",
                    str(OVERRIDE_EXAMPLE),
                    "--target",
                    "0000:01:00.0",
                    "--mmio32",
                    "0x80000000:0xc0000000",
                    "--output",
                    str(output),
                ]
            )
            result = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertTrue(result["attachable"])
        self.assertEqual(result["verdict"], "conditional")
        self.assertEqual(
            result["requiredLease"],
            ["0000:00:01.0", "0000:01:00.0", "0000:01:00.1"],
        )

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
