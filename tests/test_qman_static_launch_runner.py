from __future__ import annotations

import importlib.util
import base64
import hashlib
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
        self.assertIn("stty -F /dev/ttyS1 115200", wrapper)
        self.assertIn("QMAN_STATIC_LAUNCH_TRANSPORT_SETUP_FAILED", wrapper)
        self.assertIn("QMAN_STATIC_LAUNCH_TRANSPORT_BAUD=115200", wrapper)
        self.assertIn("base64 -w 768", wrapper)
        self.assertIn("QMAN_STATIC_LAUNCH_FRAME_BEGIN", wrapper)
        self.assertIn("QMAN_STATIC_LAUNCH_FRAME_CHUNK", wrapper)
        self.assertIn("QMAN_STATIC_LAUNCH_FRAME_END", wrapper)
        self.assertNotIn("base64 -w0", wrapper)
        self.assertNotIn("sleep 0.005", wrapper)

    @staticmethod
    def framed_log(
        marker: str,
        payload: bytes,
        *,
        sequences: list[int] | None = None,
        declared_sha256: str | None = None,
    ) -> str:
        encoded = base64.b64encode(payload).decode("ascii")
        chunks = [encoded[index : index + 768] for index in range(0, len(encoded), 768)]
        if sequences is None:
            sequences = list(range(len(chunks)))
        digest = declared_sha256 or hashlib.sha256(payload).hexdigest()
        lines = [
            f"QMAN_STATIC_LAUNCH_FRAME_BEGIN|{marker}|1|{len(payload)}|{digest}"
        ]
        lines.extend(
            f"QMAN_STATIC_LAUNCH_FRAME_CHUNK|{marker}|{sequence:08d}|{chunk}"
            for sequence, chunk in zip(sequences, chunks)
        )
        lines.append(
            f"QMAN_STATIC_LAUNCH_FRAME_END|{marker}|{len(chunks):08d}"
        )
        return "\n".join(lines)

    def test_long_framed_marker_round_trips(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_RESULT_B64"
        payload = bytes(range(256)) * 1024

        decoded, error = self.runner.decode_marker(
            self.framed_log(marker, payload), marker
        )

        self.assertIsNone(error)
        self.assertEqual(decoded, payload)

    def test_framed_marker_rejects_missing_or_out_of_order_chunk(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_IOCTL_TRACE_B64"
        payload = b"x" * 2000
        log = self.framed_log(marker, payload, sequences=[0, 2, 3, 4])

        decoded, error = self.runner.decode_marker(log, marker)

        self.assertEqual(decoded, b"")
        self.assertIn("sequence mismatch", error or "")

    def test_framed_marker_rejects_duplicate_chunk(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_IOCTL_TRACE_B64"
        payload = b"x" * 2000
        log = self.framed_log(marker, payload, sequences=[0, 0, 2, 3])

        decoded, error = self.runner.decode_marker(log, marker)

        self.assertEqual(decoded, b"")
        self.assertIn("sequence mismatch", error or "")

    def test_framed_marker_rejects_hash_mismatch(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_QMP_B64"
        log = self.framed_log(marker, b"qmp", declared_sha256="0" * 64)

        decoded, error = self.runner.decode_marker(log, marker)

        self.assertEqual(decoded, b"")
        self.assertEqual(error, f"{marker} frame sha256 mismatch")

    def test_framed_marker_rejects_truncated_frame(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_STDOUT_B64"
        log = "\n".join(self.framed_log(marker, b"stdout").splitlines()[:-1])

        decoded, error = self.runner.decode_marker(log, marker)

        self.assertEqual(decoded, b"")
        self.assertEqual(error, f"incomplete {marker} frame")

    def test_partial_frame_never_falls_back_to_legacy_marker(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_STDOUT_B64"
        framed = "\n".join(self.framed_log(marker, b"partial").splitlines()[:-1])
        legacy = base64.b64encode(b"legacy").decode("ascii")

        decoded, error = self.runner.decode_marker(
            f"{framed}\n{marker}={legacy}\n", marker
        )

        self.assertEqual(decoded, b"")
        self.assertEqual(error, f"incomplete {marker} frame")

    def test_legacy_single_line_marker_remains_readable(self) -> None:
        marker = "QMAN_STATIC_LAUNCH_RESULT_B64"
        payload = b'{"status":"PASS"}'
        encoded = base64.b64encode(payload).decode("ascii")

        decoded, error = self.runner.decode_marker(f"{marker}={encoded}\n", marker)

        self.assertIsNone(error)
        self.assertEqual(decoded, payload)

    def test_embedded_sources_are_syntax_valid(self) -> None:
        compile(
            self.runner._guest_orchestrator_source(),
            "<guest-orchestrator>",
            "exec",
        )


if __name__ == "__main__":
    unittest.main()
