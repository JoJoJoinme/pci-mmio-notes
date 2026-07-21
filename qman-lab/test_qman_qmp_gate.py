#!/usr/bin/env python3
"""Unit and WSL/QEMU integration checks for the Qman QMP gate."""

from __future__ import annotations

import argparse
import collections
import errno
import hashlib
import json
import os
import select
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from qman_qmp_gate import (
    ABSENT,
    ALLOWED_COMMANDS,
    BACKEND_ID_PREFIX,
    RequestDenied,
    backend_request,
    canonical_json,
    client_response,
    decode_request,
    encode_frame,
    load_policy,
    stable_error,
)


HERE = Path(__file__).resolve().parent
POLICY_PATH = HERE / "qmp-gate-policy-v1.json"
GATE_PATH = HERE / "qman_qmp_gate.py"
DEFAULT_QEMU = Path("/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class GateUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy(POLICY_PATH)

    def admit(self, value: Any):
        return decode_request(canonical_json(value), self.policy)

    def assert_denied(self, frame: bytes, reason: str) -> RequestDenied:
        with self.assertRaises(RequestDenied) as caught:
            decode_request(frame, self.policy)
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_policy_is_the_exact_six_command_allowlist(self) -> None:
        raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(tuple(raw["allowedCommands"]), ALLOWED_COMMANDS)
        self.assertEqual(self.policy.client_socket_mode, 0o600)
        self.assertEqual(self.policy.backend_directory_mode, 0o700)
        self.assertEqual(self.policy.backend_root, Path("/tmp"))
        self.assertEqual(len(self.policy.policy_hash), 64)

    def test_each_exact_command_is_admitted_without_arguments(self) -> None:
        for command in ALLOWED_COMMANDS:
            with self.subTest(command=command):
                admitted = self.admit({"execute": command, "id": f"client-{command}"})
                self.assertEqual(admitted.command, command)

    def test_arguments_are_empty_only_even_for_allowed_commands(self) -> None:
        denial = self.assert_denied(
            canonical_json(
                {
                    "execute": "qmp_capabilities",
                    "arguments": {"enable": ["oob"]},
                    "id": 7,
                }
            ),
            "arguments-not-allowed",
        )
        self.assertEqual(denial.client_id, 7)

    def test_mutating_and_expansive_commands_are_default_denied(self) -> None:
        commands = (
            "device_add",
            "device_del",
            "human-monitor-command",
            "getfd",
            "add-fd",
            "remove-fd",
            "qom-get",
            "qom-set",
            "query-commands",
            "quit",
        )
        for command in commands:
            with self.subTest(command=command):
                denial = self.assert_denied(
                    canonical_json({"execute": command, "id": command}),
                    "command-not-allowed",
                )
                self.assertEqual(denial.command, command)

    def test_duplicate_keys_are_rejected_before_dispatch(self) -> None:
        self.assert_denied(
            b'{"execute":"query-status","execute":"device_add","id":1}',
            "duplicate-key",
        )
        self.assert_denied(
            b'{"execute":"query-status","arguments":{"x":1,"x":2}}',
            "duplicate-key",
        )

    def test_exec_oob_is_rejected(self) -> None:
        denial = self.assert_denied(
            canonical_json({"exec-oob": "query-status", "id": "oob"}),
            "exec-oob-not-allowed",
        )
        self.assertEqual(denial.client_id, "oob")

    def test_non_object_invalid_json_and_nonfinite_number_are_rejected(self) -> None:
        for frame, reason in (
            (b"[]", "non-object"),
            (b'"query-status"', "non-object"),
            (b'{"execute":', "invalid-json"),
            (b'{"execute":"query-status","id":NaN}', "invalid-json"),
        ):
            with self.subTest(frame=frame):
                self.assert_denied(frame, reason)

    def test_oversize_frame_is_rejected_and_marks_connection_for_close(self) -> None:
        frame = b"{" + b" " * self.policy.max_frame_bytes
        denial = self.assert_denied(frame, "frame-too-long")
        self.assertTrue(denial.close)

    def test_unicode_is_rejected_after_json_unescaping(self) -> None:
        raw = '{"execute":"query-státus","id":"unicode-raw"}'.encode("utf-8")
        escaped = b'{"execute":"query-st\\u00e1tus","id":"unicode-escaped"}'
        for frame in (raw, escaped):
            with self.subTest(frame=frame):
                self.assert_denied(frame, "unicode-not-allowed")
        admitted = decode_request(
            b'{"execute":"query-st\\u0061tus","id":"ascii-after-parse"}',
            self.policy,
        )
        self.assertEqual(admitted.command, "query-status")

    def test_unknown_top_level_member_is_not_forwarded(self) -> None:
        self.assert_denied(
            canonical_json(
                {"execute": "query-status", "id": 1, "future-extension": {}}
            ),
            "unexpected-member",
        )

    def test_client_and_backend_ids_use_separate_namespaces(self) -> None:
        admitted = self.admit({"execute": "query-status", "id": "client-42"})
        private_id = BACKEND_ID_PREFIX + "nonce:1:1"
        rewritten = backend_request(admitted, private_id)
        self.assertEqual(rewritten, {"execute": "query-status", "id": private_id})
        self.assertNotIn("client-42", canonical_json(rewritten).decode("ascii"))
        restored = client_response(
            {"return": {"status": "paused"}, "id": private_id},
            admitted,
            self.policy,
        )
        self.assertEqual(restored["id"], "client-42")
        self.assertNotIn(private_id, canonical_json(restored).decode("ascii"))
        self.assert_denied(
            canonical_json(
                {"execute": "query-status", "id": private_id}
            ),
            "invalid-id",
        )

    def test_denials_have_one_stable_generic_error_surface(self) -> None:
        expected = {
            "error": {
                "class": "GenericError",
                "desc": "QMP request denied by Qman gate",
            },
            "id": "client-id",
        }
        self.assertEqual(stable_error(self.policy, "client-id"), expected)
        self.assertEqual(
            client_response(
                {
                    "error": {"class": "CommandNotFound", "desc": "backend text"},
                    "id": "private",
                },
                self.admit({"execute": "query-status", "id": "client-id"}),
                self.policy,
            ),
            expected,
        )

    def test_parse_then_reencode_drops_formatting_and_never_forwards_arguments(self) -> None:
        admitted = decode_request(
            b'{  "id" : 9, "arguments" : {}, "execute" : "query-name" }',
            self.policy,
        )
        encoded = encode_frame(backend_request(admitted, BACKEND_ID_PREFIX + "n:1:2"))
        self.assertEqual(
            encoded,
            b'{"execute":"query-name","id":"qman-backend:n:1:2"}\n',
        )

    def test_pipelined_frames_are_authorized_independently(self) -> None:
        pipeline = (
            b'{"execute":"query-status","id":1}\n'
            b'{"execute":"device_add","id":2}\n'
            b'{"execute":"query-pci","id":3}\n'
        )
        frames = pipeline.splitlines()
        self.assertEqual(self.admit(json.loads(frames[0])).command, "query-status")
        self.assert_denied(frames[1], "command-not-allowed")
        self.assertEqual(self.admit(json.loads(frames[2])).command, "query-pci")


class QmpConnection:
    def __init__(
        self,
        path: Path,
        transcript: list[dict[str, Any]],
        label: str,
        *,
        negotiate: bool = True,
        sent_frames: dict[str, list[bytes]] | None = None,
    ) -> None:
        self.path = path
        self.transcript = transcript
        self.label = label
        self.sent_frames = sent_frames
        self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream.settimeout(10)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.stream.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        self.buffer = bytearray()
        greeting = self.receive()
        if "QMP" not in greeting:
            raise RuntimeError(f"{label} received no QMP greeting: {greeting!r}")
        if negotiate:
            response = self.request("qmp_capabilities", request_id=f"{label}-caps")
            assert_success(response)

    def _record(self, direction: str, payload: Any) -> None:
        self.transcript.append(
            {"connection": self.label, "direction": direction, "payload": payload}
        )

    def send_bytes(self, payload: bytes) -> None:
        self._record("send-raw", payload.decode("utf-8", errors="backslashreplace"))
        if self.sent_frames is not None:
            if not payload.endswith(b"\n"):
                raise AssertionError("test client only sends complete QMP frames")
            self.sent_frames.setdefault(self.label, []).extend(
                frame for frame in payload.split(b"\n")[:-1]
            )
        self.stream.sendall(payload)

    def capture_external_frame(self, frame: bytes) -> None:
        if self.sent_frames is not None:
            self.sent_frames.setdefault(self.label, []).append(frame)

    def receive(self) -> dict[str, Any]:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                value = json.loads(frame.decode("utf-8"))
                self._record("receive", value)
                return value
            chunk = self.stream.recv(65536)
            if not chunk:
                raise EOFError(f"{self.label} socket closed")
            self.buffer.extend(chunk)

    def request(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        *,
        request_id: Any,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {"execute": command, "id": request_id}
        if arguments is not None:
            request["arguments"] = arguments
        self.send_bytes(encode_frame(request))
        while True:
            response = self.receive()
            if "event" in response:
                continue
            if response.get("id") == request_id:
                return response

    def raw_round_trip(self, payload: bytes) -> dict[str, Any]:
        self.send_bytes(payload if payload.endswith(b"\n") else payload + b"\n")
        while True:
            response = self.receive()
            if "event" not in response:
                return response

    def close(self) -> None:
        self.stream.close()


class RecordingQmpProxy:
    """Test-only byte proxy that records requests actually sent to QEMU."""

    def __init__(self, listen_path: Path, qemu_path: Path) -> None:
        self.listen_path = listen_path
        self.qemu_path = qemu_path
        self.records: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.error: BaseException | None = None
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(listen_path))
        os.chmod(listen_path, 0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(
            target=self._serve,
            name="test-only-qmp-recording-proxy",
            daemon=False,
        )

    def start(self) -> None:
        self.thread.start()

    def _record_frames(
        self, connection: int, buffer: bytearray, data: bytes
    ) -> None:
        buffer.extend(data)
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                return
            frame = bytes(buffer[:newline])
            del buffer[: newline + 1]
            payload = json.loads(frame.decode("ascii"))
            if not isinstance(payload, dict):
                raise AssertionError(f"gate sent non-object QMP frame: {payload!r}")
            with self.lock:
                sequence = 1 + sum(
                    1
                    for item in self.records
                    if item["connection"] == connection
                )
                self.records.append(
                    {
                        "connection": connection,
                        "sequence": sequence,
                        "execute": payload.get("execute"),
                        "id": payload.get("id"),
                        "rawSha256": hashlib.sha256(frame).hexdigest(),
                        "payload": payload,
                    }
                )

    def _relay(self, front: socket.socket, connection: int) -> None:
        back = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        front.settimeout(None)
        back.settimeout(10)
        back.connect(str(self.qemu_path))
        back.settimeout(None)
        request_buffer = bytearray()
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([front, back], [], [], 0.2)
                for source in ready:
                    destination = back if source is front else front
                    data = source.recv(65536)
                    if not data:
                        return
                    destination.sendall(data)
                    if source is front:
                        # Record only after the entire chunk has been accepted
                        # by the QEMU-facing socket, not merely seen at the
                        # proxy's client side.
                        self._record_frames(connection, request_buffer, data)
        finally:
            front.close()
            back.close()

    def _serve(self) -> None:
        connection = 0
        try:
            while not self.stop.is_set():
                try:
                    front, _ = self.listener.accept()
                except socket.timeout:
                    continue
                connection += 1
                self._relay(front, connection)
        except BaseException as error:
            if not self.stop.is_set():
                self.error = error
        finally:
            self.listener.close()
            try:
                self.listen_path.unlink()
            except FileNotFoundError:
                pass

    def close(self) -> None:
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise AssertionError("recording proxy did not stop")
        if self.error is not None:
            raise AssertionError("recording proxy failed") from self.error


def assert_success(response: dict[str, Any]) -> None:
    if "return" not in response or "error" in response:
        raise AssertionError(f"expected QMP success, got {response!r}")


def assert_generic_error(response: dict[str, Any], request_id: Any = ABSENT) -> None:
    expected: dict[str, Any] = {
        "error": {
            "class": "GenericError",
            "desc": "QMP request denied by Qman gate",
        }
    }
    if request_id is not ABSENT:
        expected["id"] = request_id
    if response != expected:
        raise AssertionError(f"expected stable GenericError {expected!r}, got {response!r}")


def assert_connection_closed(stream: socket.socket, label: str) -> None:
    stream.settimeout(2)
    try:
        trailing = stream.recv(1)
    except ConnectionResetError:
        return
    if trailing != b"":
        raise AssertionError(f"{label} connection remained open")


def flatten_pci(buses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []

    def visit(bus: dict[str, Any]) -> None:
        bus_number = bus.get("bus", bus.get("secondary", bus.get("number", 0)))
        for device in bus.get("devices", []):
            identity = device.get("id", {})
            flattened.append(
                {
                    "bdf": (
                        f"0000:{int(device.get('bus', bus_number)):02x}:"
                        f"{int(device['slot']):02x}.{int(device['function'])}"
                    ),
                    "qdevId": device.get("qdev_id", ""),
                    "vendor": identity.get("vendor"),
                    "device": identity.get("device"),
                    "childCount": len(device.get("pci_bridge", {}).get("devices", [])),
                }
            )
            bridge = device.get("pci_bridge")
            if isinstance(bridge, dict) and isinstance(bridge.get("bus"), dict):
                child = dict(bridge["bus"])
                child["devices"] = bridge.get("devices", [])
                visit(child)

    for root in buses:
        visit(root)
    return sorted(flattened, key=lambda item: (item["bdf"], item["qdevId"]))


def process_fd_multiset(pid: int) -> list[dict[str, Any]]:
    counts: collections.Counter[str] = collections.Counter()
    for entry in (Path("/proc") / str(pid) / "fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        counts[target] += 1
    return [
        {"target": target, "count": count}
        for target, count in sorted(counts.items())
    ]


def qemu_fd_multiset(pid: int) -> list[dict[str, Any]]:
    return process_fd_multiset(pid)


def wait_for_path(path: Path, process: subprocess.Popen[Any], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise RuntimeError(f"process exited before creating {path}: {process.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError(path)
        time.sleep(0.05)


def wait_for_fd_multiset(pid: int, expected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deadline = time.monotonic() + 5
    current = qemu_fd_multiset(pid)
    while current != expected and time.monotonic() < deadline:
        time.sleep(0.05)
        current = qemu_fd_multiset(pid)
    return current


def wait_for_stable_fd_multiset(pid: int) -> list[dict[str, Any]]:
    deadline = time.monotonic() + 5
    previous: list[dict[str, Any]] | None = None
    stable_samples = 0
    while time.monotonic() < deadline:
        current = process_fd_multiset(pid)
        if current == previous:
            stable_samples += 1
            if stable_samples >= 4:
                return current
        else:
            previous = current
            stable_samples = 0
        time.sleep(0.05)
    raise AssertionError(f"PID {pid} FD multiset did not stabilize: {previous!r}")


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(value, sort_keys=True, ensure_ascii=True) + "\n"
            for value in values
        ),
        encoding="ascii",
    )


def nobody_eacces(socket_path: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("nobody EACCES test requires root")
    runuser = shutil.which("runuser")
    if runuser is None:
        raise RuntimeError("runuser is required for the nobody EACCES test")
    program = (
        "import errno,json,socket,sys; "
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
        "code=0; result={}; "
        "\ntry:\n s.connect(sys.argv[1]); result={'connected':True}; code=2"
        "\nexcept OSError as e:\n result={'connected':False,'errno':e.errno}; "
        "code=0 if e.errno==errno.EACCES else 3"
        "\nprint(json.dumps(result,sort_keys=True)); sys.exit(code)"
    )
    completed = subprocess.run(
        [runuser, "-u", "nobody", "--", sys.executable, "-c", program, str(socket_path)],
        text=True,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"nobody access check failed rc={completed.returncode}: "
            f"{completed.stdout!r} {completed.stderr!r}"
        )
    result = json.loads(completed.stdout)
    if result != {"connected": False, "errno": errno.EACCES}:
        raise AssertionError(f"unexpected nobody result: {result!r}")
    return result


def exercise_scm_rights(
    gate_path: Path,
    transcript: list[dict[str, Any]],
    sent_frames: dict[str, list[bytes]],
) -> dict[str, Any]:
    if not hasattr(socket, "SCM_RIGHTS") or not hasattr(socket.socket, "sendmsg"):
        raise RuntimeError("SCM_RIGHTS is unavailable")
    connection = QmpConnection(
        gate_path,
        transcript,
        "scm-rights",
        sent_frames=sent_frames,
    )
    descriptor = os.open("/dev/null", os.O_RDONLY)
    try:
        request = encode_frame(
            {"execute": "getfd", "arguments": {"fdname": "blocked"}, "id": "fd"}
        )
        import array

        payload = array.array("i", [descriptor])
        connection._record("send-scm-rights", {"id": "fd", "fdCount": 1})
        connection.capture_external_frame(request[:-1])
        connection.stream.sendmsg(
            [request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)]
        )
        response = connection.receive()
        assert_generic_error(response)
        assert_connection_closed(connection.stream, "SCM_RIGHTS")
        return {"genericError": True, "connectionClosed": True}
    finally:
        os.close(descriptor)
        connection.close()


def expected_client_audit(
    sent_frames: dict[str, list[bytes]], policy: Any
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    peer = {"pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid()}
    connection_labels = ("gate-main", "oversize", "scm-rights")
    if set(sent_frames) != set(connection_labels):
        raise AssertionError(f"unexpected client connection set: {sent_frames!r}")

    for connection, label in enumerate(connection_labels, 1):
        for sequence, frame in enumerate(sent_frames[label], 1):
            ancillary = label == "scm-rights" and sequence == 2
            if ancillary:
                digest_input = frame + b"\n"
            elif label == "oversize" and sequence == 2:
                # The bounded recv path deliberately hashes only the first
                # maximum+1 bytes; it never buffers an attacker-sized frame.
                digest_input = frame[: policy.max_frame_bytes + 1]
            else:
                digest_input = frame
            common = {
                "connection": connection,
                "sequence": sequence,
                "requestDigest": hashlib.sha256(digest_input).hexdigest(),
                "policyHash": policy.policy_hash,
                "peerCredential": peer,
            }
            if ancillary:
                expected.append(
                    {
                        **common,
                        "verdict": "deny",
                        "reason": "ancillary-data-not-allowed",
                        "command": None,
                    }
                )
                continue
            try:
                admitted = decode_request(frame, policy)
            except RequestDenied as denial:
                expected.append(
                    {
                        **common,
                        "verdict": "deny",
                        "reason": denial.reason,
                        "command": (
                            denial.command
                            if denial.command in ALLOWED_COMMANDS
                            else None
                        ),
                    }
                )
                continue
            if admitted.command == "qmp_capabilities":
                expected.append(
                    {
                        **common,
                        "verdict": "local",
                        "reason": "local-capabilities",
                        "command": admitted.command,
                    }
                )
                continue
            expected.extend(
                [
                    {
                        **common,
                        "verdict": "forward-attempt",
                        "reason": "backend-send-attempt",
                        "command": admitted.command,
                    },
                    {
                        **common,
                        "verdict": "forward-success",
                        "reason": "backend-return-success",
                        "command": admitted.command,
                    },
                ]
            )
    return expected


def integration_run(qemu: Path, output: Path, policy_path: Path) -> dict[str, Any]:
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise RuntimeError("integration run requires Linux /proc and Unix sockets")
    if not qemu.is_file():
        raise FileNotFoundError(qemu)
    if output.exists():
        raise FileExistsError(f"integration output must be new: {output}")
    output.mkdir(parents=True)

    transcript: list[dict[str, Any]] = []
    observer_transcript: list[dict[str, Any]] = []
    sent_frames: dict[str, list[bytes]] = {}
    denial_results: list[dict[str, Any]] = []
    policy = load_policy(policy_path)
    qemu_log_path = output / "qemu.log"
    gate_log_path = output / "gate.log"
    audit_path = output / "audit.jsonl"
    qemu_process: subprocess.Popen[Any] | None = None
    gate_process: subprocess.Popen[Any] | None = None
    observer: QmpConnection | None = None
    client: QmpConnection | None = None
    recording_proxy: RecordingQmpProxy | None = None
    runtime_mode = None
    listen_mode = None
    gate_exit: dict[str, Any] | None = None

    with tempfile.TemporaryDirectory(prefix="qman-qmp-gate-", dir="/tmp") as temporary:
        runtime = Path(temporary)
        os.chmod(runtime, 0o700)
        runtime_mode = stat.S_IMODE(runtime.stat().st_mode)
        backend_path = runtime / "backend.qmp"
        recorder_path = runtime / "recorded-backend.qmp"
        observer_path = runtime / "observer.qmp"
        gate_path = runtime / "client.qmp"
        qemu_command = [
            str(qemu),
            "-name",
            "qman-qmp-gate-lab",
            "-machine",
            "q35,accel=kvm:tcg",
            "-m",
            "256M",
            "-nodefaults",
            "-display",
            "none",
            "-serial",
            "none",
            "-monitor",
            "none",
            "-qmp",
            f"unix:{backend_path},server=on,wait=off",
            "-qmp",
            f"unix:{observer_path},server=on,wait=off",
            "-device",
            "pcie-root-port,id=rp1,bus=pcie.0,addr=0x02,chassis=1",
            "-device",
            "pcie-root-port,id=rp2,bus=pcie.0,addr=0x03,chassis=2",
            "-device",
            "e1000e,id=static-endpoint,bus=rp1,addr=0x0",
        ]

        with qemu_log_path.open("w", encoding="utf-8") as qemu_log, gate_log_path.open(
            "w", encoding="utf-8"
        ) as gate_log:
            try:
                qemu_process = subprocess.Popen(
                    qemu_command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=qemu_log,
                    text=True,
                )
                wait_for_path(observer_path, qemu_process)
                wait_for_path(backend_path, qemu_process)
                observer = QmpConnection(
                    observer_path, observer_transcript, "observer"
                )
                time.sleep(1)
                assert_success(observer.request("stop", request_id="observer-stop"))

                recording_proxy = RecordingQmpProxy(recorder_path, backend_path)
                recording_proxy.start()

                gate_command = [
                    sys.executable,
                    str(GATE_PATH),
                    "--listen",
                    str(gate_path),
                    "--backend",
                    str(recorder_path),
                    "--policy",
                    str(policy_path),
                    "--audit",
                    str(audit_path),
                ]
                gate_process = subprocess.Popen(
                    gate_command,
                    stdin=subprocess.DEVNULL,
                    stdout=gate_log,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                wait_for_path(gate_path, gate_process)
                listen_mode = stat.S_IMODE(gate_path.stat().st_mode)

                client = QmpConnection(
                    gate_path,
                    transcript,
                    "gate-main",
                    sent_frames=sent_frames,
                )
                allowed_results: dict[str, Any] = {}
                for command in ALLOWED_COMMANDS[1:]:
                    response = client.request(
                        command, request_id=f"allowed-{command}"
                    )
                    assert_success(response)
                    allowed_results[command] = response["return"]

                before_tree = observer.request(
                    "query-pci", request_id="observer-tree-before"
                )["return"]
                before_flat = flatten_pci(before_tree)
                ids = {item["qdevId"]: item for item in before_flat}
                if "rp1" not in ids or "rp2" not in ids or "static-endpoint" not in ids:
                    raise AssertionError(f"expected rp1/rp2/static endpoint: {before_flat!r}")
                if ids["rp2"]["childCount"] != 0:
                    raise AssertionError(f"rp2 is not empty: {ids['rp2']!r}")
                before_tree_hash = canonical_hash(before_tree)
                before_fds = qemu_fd_multiset(qemu_process.pid)

                denied_commands = [
                    (
                        "device_add",
                        {
                            "driver": "e1000e",
                            "id": "blocked-add",
                            "bus": "rp2",
                            "addr": "0x0",
                        },
                    ),
                    ("device_del", {"id": "static-endpoint"}),
                    ("human-monitor-command", {"command-line": "device_add e1000e"}),
                    ("getfd", {"fdname": "blocked"}),
                    ("add-fd", {}),
                    ("remove-fd", {"fdset-id": 1}),
                    ("qom-get", {"path": "/machine", "property": "type"}),
                    (
                        "qom-set",
                        {"path": "/machine", "property": "type", "value": "pc"},
                    ),
                ]
                for index, (command, arguments) in enumerate(denied_commands, 1):
                    request_id = f"deny-{index}-{command}"
                    response = client.request(
                        command, arguments, request_id=request_id
                    )
                    assert_generic_error(response, request_id)
                    denial_results.append(
                        {"category": command, "id": request_id, "denied": True}
                    )

                raw_denials = [
                    (
                        "duplicate-key",
                        b'{"execute":"query-status","execute":"device_add","id":"dup"}\n',
                    ),
                    ("non-object", b'[{"execute":"query-status"}]\n'),
                    ("invalid-json", b'{"execute":\n'),
                    (
                        "unicode-raw",
                        '{"execute":"query-státus","id":"unicode-raw"}\n'.encode(
                            "utf-8"
                        ),
                    ),
                    (
                        "unicode-escaped",
                        b'{"execute":"query-st\\u00e1tus","id":"unicode-escaped"}\n',
                    ),
                    (
                        "exec-oob",
                        b'{"exec-oob":"query-status","id":"oob"}\n',
                    ),
                ]
                for category, frame in raw_denials:
                    response = client.raw_round_trip(frame)
                    request_id = {
                        "unicode-raw": "unicode-raw",
                        "unicode-escaped": "unicode-escaped",
                        "exec-oob": "oob",
                    }.get(category, ABSENT)
                    assert_generic_error(response, request_id)
                    denial_results.append({"category": category, "denied": True})

                pipeline = (
                    encode_frame({"execute": "query-status", "id": "pipe-before"})
                    + encode_frame(
                        {
                            "execute": "device_add",
                            "arguments": {
                                "driver": "e1000e",
                                "id": "blocked-pipeline",
                                "bus": "rp2",
                            },
                            "id": "pipe-deny",
                        }
                    )
                    + encode_frame({"execute": "query-pci", "id": "pipe-after"})
                )
                client.send_bytes(pipeline)
                pipeline_responses = [client.receive(), client.receive(), client.receive()]
                if [item.get("id") for item in pipeline_responses] != [
                    "pipe-before",
                    "pipe-deny",
                    "pipe-after",
                ]:
                    raise AssertionError(f"pipeline response ordering changed: {pipeline_responses!r}")
                assert_success(pipeline_responses[0])
                assert_generic_error(pipeline_responses[1], "pipe-deny")
                assert_success(pipeline_responses[2])
                denial_results.append(
                    {"category": "pipelined-device-add", "denied": True}
                )

                main_after_tree = observer.request(
                    "query-pci", request_id="observer-tree-after-main"
                )["return"]
                main_after_fds = wait_for_fd_multiset(qemu_process.pid, before_fds)
                if canonical_hash(main_after_tree) != before_tree_hash:
                    raise AssertionError("PCI tree changed across main gate denials")
                if main_after_fds != before_fds:
                    raise AssertionError(
                        "QEMU FD multiset changed while the main gate connection "
                        f"remained open: {before_fds!r} -> {main_after_fds!r}"
                    )

                # One QEMU unix QMP chardev services one backend connection at a
                # time.  Close the main gate client before the two fatal-frame
                # checks, then prove that each short-lived backend connection
                # returns QEMU to the exact same idle FD multiset.
                client.close()
                client = None
                time.sleep(0.2)
                idle_before_fatal_checks = qemu_fd_multiset(qemu_process.pid)

                oversize = QmpConnection(
                    gate_path,
                    transcript,
                    "oversize",
                    sent_frames=sent_frames,
                )
                try:
                    frame = b'{' + b'"padding":"' + (
                        b"x" * policy.max_frame_bytes
                    ) + b'"}\n'
                    response = oversize.raw_round_trip(frame)
                    assert_generic_error(response)
                    assert_connection_closed(oversize.stream, "oversize")
                finally:
                    oversize.close()
                denial_results.append(
                    {"category": "frame-too-long", "denied": True, "closed": True}
                )
                idle_after_oversize = wait_for_fd_multiset(
                    qemu_process.pid, idle_before_fatal_checks
                )
                if idle_after_oversize != idle_before_fatal_checks:
                    raise AssertionError(
                        "oversize frame left a QEMU FD delta: "
                        f"{idle_before_fatal_checks!r} -> {idle_after_oversize!r}"
                    )

                gate_fds_before_scm = wait_for_stable_fd_multiset(
                    gate_process.pid
                )
                scm_result = exercise_scm_rights(
                    gate_path, transcript, sent_frames
                )
                denial_results.append(
                    {"category": "SCM_RIGHTS", "denied": True, **scm_result}
                )
                gate_fds_after_scm = wait_for_fd_multiset(
                    gate_process.pid, gate_fds_before_scm
                )
                if gate_fds_after_scm != gate_fds_before_scm:
                    raise AssertionError(
                        "SCM_RIGHTS attempt left a QMP gate FD delta: "
                        f"{gate_fds_before_scm!r} -> {gate_fds_after_scm!r}"
                    )
                idle_after_scm = wait_for_fd_multiset(
                    qemu_process.pid, idle_before_fatal_checks
                )
                if idle_after_scm != idle_before_fatal_checks:
                    raise AssertionError(
                        "SCM_RIGHTS attempt left a QEMU FD delta: "
                        f"{idle_before_fatal_checks!r} -> {idle_after_scm!r}"
                    )
                nobody_result = nobody_eacces(gate_path)

                after_tree = observer.request(
                    "query-pci", request_id="observer-tree-after"
                )["return"]
                after_tree_hash = canonical_hash(after_tree)
                after_fds = wait_for_fd_multiset(
                    qemu_process.pid, idle_before_fatal_checks
                )
                tree_unchanged = before_tree_hash == after_tree_hash
                fds_unchanged = (
                    before_fds == main_after_fds
                    and idle_before_fatal_checks == idle_after_oversize
                    and idle_before_fatal_checks == idle_after_scm
                    and idle_before_fatal_checks == after_fds
                )
                if not tree_unchanged:
                    raise AssertionError("PCI tree changed across denied commands")
                if not fds_unchanged:
                    raise AssertionError(
                        f"QEMU FD multiset changed: {before_fds!r} -> {after_fds!r}"
                    )

                gate_process.terminate()
                try:
                    gate_return_code = gate_process.wait(timeout=15)
                except subprocess.TimeoutExpired as error:
                    gate_process.kill()
                    gate_process.wait(timeout=5)
                    raise AssertionError("QMP gate did not stop cleanly") from error
                gate_log.flush()
                gate_log_lines = gate_log_path.read_text(
                    encoding="utf-8"
                ).splitlines()
                if gate_return_code != 0:
                    raise AssertionError(
                        f"QMP gate exited {gate_return_code}: {gate_log_lines!r}"
                    )
                if not gate_log_lines:
                    raise AssertionError("QMP gate produced no listening record")
                try:
                    listening_record = json.loads(gate_log_lines[0])
                except json.JSONDecodeError as error:
                    raise AssertionError(
                        f"QMP gate log is not structured: {gate_log_lines!r}"
                    ) from error
                if listening_record.get("status") != "listening" or any(
                    "Traceback" in line for line in gate_log_lines
                ):
                    raise AssertionError(f"QMP gate log is not clean: {gate_log_lines!r}")
                gate_exit = {
                    "returnCode": gate_return_code,
                    "clean": True,
                    "listeningRecord": listening_record,
                }

                recording_proxy.close()
                recorded_backend_requests = list(recording_proxy.records)
                recording_proxy = None

                audit_events = [
                    json.loads(line)
                    for line in audit_path.read_text(encoding="ascii").splitlines()
                    if line
                ]
                required_audit_keys = {
                    "connection",
                    "sequence",
                    "verdict",
                    "reason",
                    "command",
                    "requestDigest",
                    "policyHash",
                    "peerCredential",
                }
                for event in audit_events:
                    if set(event) != required_audit_keys:
                        raise AssertionError(f"non-minimal audit event: {event!r}")
                    if len(event["requestDigest"]) != 64:
                        raise AssertionError(f"invalid request digest: {event!r}")
                    if event["policyHash"] != policy.policy_hash:
                        raise AssertionError(f"policy hash drift in audit: {event!r}")
                    if set(event["peerCredential"]) != {"pid", "uid", "gid"}:
                        raise AssertionError(f"invalid peer credential: {event!r}")
                expected_audit = expected_client_audit(sent_frames, policy)
                if audit_events != expected_audit:
                    mismatch = next(
                        (
                            (index, expected, actual)
                            for index, (expected, actual) in enumerate(
                                zip(expected_audit, audit_events), 1
                            )
                            if expected != actual
                        ),
                        None,
                    )
                    raise AssertionError(
                        "client audit does not exactly match every request: "
                        f"expected-count={len(expected_audit)}, "
                        f"actual-count={len(audit_events)}, first-mismatch={mismatch!r}"
                    )
                verdict_counts = collections.Counter(
                    event["verdict"] for event in audit_events
                )
                if verdict_counts != {
                    "local": 3,
                    "forward-attempt": 7,
                    "forward-success": 7,
                    "deny": 17,
                }:
                    raise AssertionError(
                        f"unexpected audit verdict counts: {verdict_counts!r}"
                    )
                if any(
                    event["command"] is not None
                    for event in audit_events
                    if event["verdict"] == "deny"
                ):
                    raise AssertionError("untrusted denied execute leaked into audit")

                expected_backend_commands = [
                    "qmp_capabilities",
                    "query-version",
                    "query-status",
                    "query-kvm",
                    "query-name",
                    "query-pci",
                    "query-status",
                    "query-pci",
                    "qmp_capabilities",
                    "qmp_capabilities",
                ]
                actual_backend_commands = [
                    record["execute"] for record in recorded_backend_requests
                ]
                if actual_backend_commands != expected_backend_commands:
                    raise AssertionError(
                        "recording proxy saw an unexpected QEMU request set: "
                        f"{actual_backend_commands!r}"
                    )
                expected_backend_counts = collections.Counter(
                    {
                        "qmp_capabilities": 3,
                        "query-version": 1,
                        "query-status": 2,
                        "query-kvm": 1,
                        "query-name": 1,
                        "query-pci": 2,
                    }
                )
                if collections.Counter(actual_backend_commands) != expected_backend_counts:
                    raise AssertionError("recording proxy request counts changed")
                for record in recorded_backend_requests:
                    if set(record["payload"]) != {"execute", "id"}:
                        raise AssertionError(
                            f"gate forwarded unexpected QMP members: {record!r}"
                        )
                    if not str(record["id"]).startswith(BACKEND_ID_PREFIX):
                        raise AssertionError(
                            f"gate did not use a private backend id: {record!r}"
                        )

                artifact_values = {
                    "allowed-results.json": allowed_results,
                    "denial-results.json": denial_results,
                    "pci-before.json": {"hash": before_tree_hash, "tree": before_tree},
                    "pci-after.json": {"hash": after_tree_hash, "tree": after_tree},
                    "fd-before.json": {
                        "mainConnection": before_fds,
                        "idleBoundary": idle_before_fatal_checks,
                    },
                    "fd-after.json": {
                        "mainConnection": main_after_fds,
                        "afterOversize": idle_after_oversize,
                        "afterScmRights": idle_after_scm,
                        "idleBoundary": after_fds,
                    },
                    "gate-fd-before.json": gate_fds_before_scm,
                    "gate-fd-after.json": gate_fds_after_scm,
                    "gate-exit.json": gate_exit,
                    "nobody-eacces.json": nobody_result,
                }
                for name, value in artifact_values.items():
                    write_json(output / name, value)
                write_jsonl(output / "client-transcript.jsonl", transcript)
                write_jsonl(
                    output / "backend-recording.jsonl",
                    recorded_backend_requests,
                )
                write_jsonl(
                    output / "observer-transcript.jsonl", observer_transcript
                )

                summary_core = {
                    "schemaVersion": 1,
                    "id": "QMAN-E3-QMP-GATE-001",
                    "generatedAt": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    ),
                    "subject": "QMAN_COMPONENT",
                    "claimScope": "COMPONENT_ONLY",
                    "evidenceGrade": "E3",
                    "policy": {
                        "path": str(policy_path),
                        "sha256": sha256_file(policy_path),
                        "policyHash": policy.policy_hash,
                        "allowedCommands": list(ALLOWED_COMMANDS),
                        "maxFrameBytes": policy.max_frame_bytes,
                    },
                    "qemu": {
                        "path": str(qemu),
                        "version": subprocess.check_output(
                            [str(qemu), "--version"], text=True
                        ).splitlines()[0],
                        "sha256": sha256_file(qemu),
                        "pid": qemu_process.pid,
                        "command": qemu_command,
                    },
                    "socketBoundary": {
                        "backendDirectory": str(runtime),
                        "backendDirectoryMode": f"{runtime_mode:04o}",
                        "clientSocketMode": f"{listen_mode:04o}",
                        "nobodyConnectErrno": nobody_result["errno"],
                        "scmRightsForwardingAllowed": False,
                    },
                    "claims": {
                        "exactReadOnlyAllowlist": True,
                        "defaultDenyStableGenericError": True,
                        "duplicateKeysRejected": True,
                        "execOobRejected": True,
                        "nonObjectAndInvalidJsonRejected": True,
                        "unicodeRejectedAfterParse": True,
                        "oversizeFrameRejectedAndClosed": True,
                        "scmRightsRejectedAndClosed": True,
                        "clientBackendIdsSeparated": True,
                        "qmpCapabilitiesHandledLocally": True,
                        "minimalPeerCredentialAudit": True,
                        "twoPhaseForwardAudit": True,
                        "allClientRequestsExactlyAudited": True,
                        "deniedCommandsNeverForwarded": True,
                        "recordingProxyObservedExactBackendSet": True,
                        "pipelinedMutationRejectedInOrder": True,
                        "pciTreeHashUnchanged": tree_unchanged,
                        "qemuFdMultisetUnchanged": fds_unchanged,
                        "gateFdMultisetReturnedToBaselineAfterScmRights": (
                            gate_fds_before_scm == gate_fds_after_scm
                        ),
                        "gateExitedCleanly": gate_exit == {
                            "returnCode": 0,
                            "clean": True,
                            "listeningRecord": listening_record,
                        },
                        "nobodyGetsEacces": nobody_result["errno"] == errno.EACCES,
                        "staticEndpointOnRp1AndRp2Empty": True,
                    },
                    "measurements": {
                        "clientRequestCount": sum(
                            len(frames) for frames in sent_frames.values()
                        ),
                        "deniedRequestCount": verdict_counts["deny"],
                        "backendRequestCount": len(recorded_backend_requests),
                        "deniedOrMalformedBackendRequestCount": 0,
                    },
                    "mapping": {
                        "techStories": ["TS-F4-05", "TS-F5-05"],
                        "casePremisesOnly": ["S15", "F09"],
                        "riskPremisesOnly": ["R17", "R26", "R37"],
                        "caseClosures": [],
                        "riskClosures": [],
                    },
                    "verdict": "pass",
                    "limitations": [
                        "This proves only the Qman lab component boundary around one emulated QEMU process.",
                        "The observer QMP socket and recording proxy are test-only bypass paths and must not exist in production.",
                        "Alternative QEMU control paths such as CLI arguments, other monitors, libvirt, storage APIs, and host APIs are outside this component proof.",
                        "No VFIO or physical PCI device was used; production authorization, daemon hardening, and cluster fencing remain unproven.",
                        "Listener and audit-parent lifecycle/ownership, backend socket inode pinning, and backend PID identity are not production-hardened or proven here.",
                        "It does not close S15, F09, R17, R26, or R37.",
                    ],
                }
            finally:
                if client is not None:
                    client.close()
                if gate_process is not None and gate_process.poll() is None:
                    gate_process.terminate()
                    try:
                        gate_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        gate_process.kill()
                        gate_process.wait(timeout=5)
                if recording_proxy is not None:
                    recording_proxy.close()
                if observer is not None:
                    try:
                        observer.request("quit", request_id="observer-quit")
                    except (EOFError, OSError):
                        pass
                    observer.close()
                if qemu_process is not None:
                    try:
                        qemu_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        qemu_process.terminate()
                        qemu_process.wait(timeout=5)

    artifact_hashes = {
        path.name: sha256_file(path)
        for path in sorted(output.iterdir())
        if path.name != "summary.json" and path.is_file()
    }
    summary_core["artifacts"] = artifact_hashes
    write_json(output / "summary.json", summary_core)
    return summary_core


def main() -> None:
    if "--integration" not in sys.argv:
        unittest.main()
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true", required=True)
    parser.add_argument("--qemu", type=Path, default=DEFAULT_QEMU)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    args = parser.parse_args()
    summary = integration_run(args.qemu, args.output, args.policy)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
