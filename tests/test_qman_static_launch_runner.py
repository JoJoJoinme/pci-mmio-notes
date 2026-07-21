from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "qman-lab" / "test_qman_static_launch.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("qman_static_launch_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Static launch runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StaticLaunchRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def test_outer_qemu_uses_a_dedicated_evidence_serial_port(self) -> None:
        output = Path("/qman-evidence")
        args = SimpleNamespace(
            qemu=Path("/qemu-system-x86_64"),
            qemu_source_root=Path("/qemu-source"),
            ovmf_code=Path("/OVMF_CODE.fd"),
        )

        command = self.runner.qemu_command(args, output)

        serial_values = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "-serial"
        ]
        self.assertEqual(
            serial_values,
            ["stdio", f"file:{output / 'evidence-serial.log'}"],
        )

    def test_guest_evidence_never_uses_the_boot_console(self) -> None:
        wrapper = self.runner._guest_wrapper_source()

        self.assertIn("exec >/dev/ttyS1 2>&1", wrapper)
        self.assertNotIn("exec >/dev/ttyS0 2>&1", wrapper)

    def test_embedded_sources_are_syntax_valid(self) -> None:
        compile(
            self.runner._guest_orchestrator_source(),
            "<guest-orchestrator>",
            "exec",
        )


if __name__ == "__main__":
    unittest.main()
