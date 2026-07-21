#!/usr/bin/env python3
"""A small fail-closed QMP observation gate for the Qman component lab.

The gate is intentionally not a general QMP proxy.  It accepts only the six
commands fixed by ``qmp-gate-policy-v1.json``, gives every forwarded request a
private backend id, and reconstructs both requests and responses from parsed
JSON.  It never forwards ancillary file descriptors.
"""

from __future__ import annotations

import argparse
import array
import hashlib
import json
import os
import secrets
import signal
import socket
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ALLOWED_COMMANDS = (
    "qmp_capabilities",
    "query-version",
    "query-status",
    "query-kvm",
    "query-name",
    "query-pci",
)
BACKEND_ID_PREFIX = "qman-backend:"
ABSENT = object()


class DuplicateKeyError(ValueError):
    pass


class RequestDenied(Exception):
    def __init__(
        self,
        reason: str,
        *,
        client_id: Any = ABSENT,
        command: str | None = None,
        close: bool = False,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.client_id = client_id
        self.command = command
        self.close = close


@dataclass(frozen=True)
class GatePolicy:
    policy_id: str
    policy_hash: str
    max_frame_bytes: int
    max_backend_frame_bytes: int
    client_socket_mode: int
    backend_directory_mode: int
    backend_root: Path
    error_class: str
    error_description: str


@dataclass(frozen=True)
class AdmittedRequest:
    command: str
    client_id: Any
    has_client_id: bool


@dataclass(frozen=True)
class BackendOutcome:
    response: dict[str, Any]
    succeeded: bool


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def _parse_mode(value: Any, field_name: str) -> int:
    if not isinstance(value, str) or len(value) != 4 or not value.startswith("0"):
        raise ValueError(f"{field_name} must be a four-digit octal string")
    try:
        mode = int(value, 8)
    except ValueError as error:
        raise ValueError(f"{field_name} is not octal") from error
    if mode < 0 or mode > 0o7777:
        raise ValueError(f"{field_name} is outside the permission range")
    return mode


def load_policy(path: Path) -> GatePolicy:
    raw = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(raw, dict):
        raise ValueError("gate policy must be a JSON object")
    if raw.get("schemaVersion") != 1:
        raise ValueError("unsupported gate policy schemaVersion")
    commands = raw.get("allowedCommands")
    if not isinstance(commands, list) or any(
        not isinstance(command, str) for command in commands
    ):
        raise ValueError("allowedCommands must be a string array")
    if tuple(commands) != ALLOWED_COMMANDS or len(set(commands)) != len(commands):
        raise ValueError("allowedCommands must equal the built-in exact allowlist")

    max_frame = raw.get("maxFrameBytes")
    max_backend = raw.get("maxBackendFrameBytes")
    if not isinstance(max_frame, int) or isinstance(max_frame, bool):
        raise ValueError("maxFrameBytes must be an integer")
    if not 256 <= max_frame <= 1024 * 1024:
        raise ValueError("maxFrameBytes is outside the fail-closed range")
    if not isinstance(max_backend, int) or isinstance(max_backend, bool):
        raise ValueError("maxBackendFrameBytes must be an integer")
    if not max_frame <= max_backend <= 16 * 1024 * 1024:
        raise ValueError("maxBackendFrameBytes is outside the fail-closed range")

    denial = raw.get("denial")
    if not isinstance(denial, dict):
        raise ValueError("denial must be an object")
    if denial.get("class") != "GenericError":
        raise ValueError("denial.class must remain GenericError")
    description = denial.get("description")
    if not isinstance(description, str) or not description or not description.isascii():
        raise ValueError("denial.description must be non-empty ASCII")

    backend_root = raw.get("backendRoot")
    if backend_root != "/tmp":
        raise ValueError("backendRoot must remain /tmp")
    backend_mode = _parse_mode(
        raw.get("backendDirectoryMode"), "backendDirectoryMode"
    )
    if backend_mode != 0o700:
        raise ValueError("backendDirectoryMode must remain 0700")
    client_mode = _parse_mode(raw.get("clientSocketMode"), "clientSocketMode")
    if client_mode != 0o600:
        raise ValueError("clientSocketMode must remain 0600")

    policy_id = raw.get("id")
    if policy_id != "qman-qmp-gate-policy-v1":
        raise ValueError("unexpected policy id")
    return GatePolicy(
        policy_id=policy_id,
        policy_hash=hashlib.sha256(canonical_json(raw)).hexdigest(),
        max_frame_bytes=max_frame,
        max_backend_frame_bytes=max_backend,
        client_socket_mode=client_mode,
        backend_directory_mode=backend_mode,
        backend_root=Path(backend_root),
        error_class="GenericError",
        error_description=description,
    )


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def encode_frame(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def _contains_non_ascii(value: Any) -> bool:
    if isinstance(value, str):
        return not value.isascii()
    if isinstance(value, list):
        return any(_contains_non_ascii(item) for item in value)
    if isinstance(value, dict):
        return any(
            not key.isascii() or _contains_non_ascii(item)
            for key, item in value.items()
        )
    return False


def _safe_client_id(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return (
        isinstance(value, str)
        and len(value) <= 256
        and value.isascii()
        and not value.startswith(BACKEND_ID_PREFIX)
    )


def decode_request(frame: bytes, policy: GatePolicy) -> AdmittedRequest:
    if len(frame) > policy.max_frame_bytes:
        raise RequestDenied("frame-too-long", close=True)
    try:
        text = frame.decode("utf-8", errors="strict")
        request = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DuplicateKeyError as error:
        raise RequestDenied("duplicate-key") from error
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise RequestDenied("invalid-json") from error

    if not isinstance(request, dict):
        raise RequestDenied("non-object")
    client_id = request.get("id", ABSENT)
    if client_id is not ABSENT and not _safe_client_id(client_id):
        raise RequestDenied("invalid-id")
    if _contains_non_ascii(request):
        raise RequestDenied("unicode-not-allowed", client_id=client_id)
    command_value = request.get("execute")
    command = command_value if isinstance(command_value, str) else None
    if "exec-oob" in request:
        raise RequestDenied(
            "exec-oob-not-allowed", client_id=client_id, command=command
        )
    if set(request) - {"execute", "arguments", "id"}:
        raise RequestDenied(
            "unexpected-member", client_id=client_id, command=command
        )
    if not isinstance(command_value, str):
        raise RequestDenied("execute-required", client_id=client_id)
    if command_value not in ALLOWED_COMMANDS:
        raise RequestDenied(
            "command-not-allowed", client_id=client_id, command=command_value
        )
    arguments = request.get("arguments", {})
    if not isinstance(arguments, dict) or arguments:
        raise RequestDenied(
            "arguments-not-allowed", client_id=client_id, command=command_value
        )
    return AdmittedRequest(
        command=command_value,
        client_id=None if client_id is ABSENT else client_id,
        has_client_id=client_id is not ABSENT,
    )


def backend_request(request: AdmittedRequest, backend_id: str) -> dict[str, Any]:
    if not backend_id.startswith(BACKEND_ID_PREFIX):
        raise ValueError("backend id is outside the private namespace")
    return {"execute": request.command, "id": backend_id}


def stable_error(policy: GatePolicy, client_id: Any = ABSENT) -> dict[str, Any]:
    response: dict[str, Any] = {
        "error": {
            "class": policy.error_class,
            "desc": policy.error_description,
        }
    }
    if client_id is not ABSENT:
        response["id"] = client_id
    return response


def client_response(
    backend_response: Mapping[str, Any],
    request: AdmittedRequest,
    policy: GatePolicy,
) -> dict[str, Any]:
    if "return" not in backend_response or "error" in backend_response:
        return stable_error(
            policy, request.client_id if request.has_client_id else ABSENT
        )
    response: dict[str, Any] = {"return": backend_response["return"]}
    if request.has_client_id:
        response["id"] = request.client_id
    return response


class JsonLineReader:
    def __init__(self, stream: socket.socket, maximum: int) -> None:
        self.stream = stream
        self.maximum = maximum
        self.buffer = bytearray()

    def read(self) -> dict[str, Any]:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                if len(frame) > self.maximum:
                    raise RuntimeError("backend QMP frame exceeds configured maximum")
                try:
                    value = json.loads(
                        frame.decode("utf-8", errors="strict"),
                        object_pairs_hook=_unique_object,
                        parse_constant=_reject_constant,
                    )
                except (UnicodeDecodeError, ValueError, RecursionError) as error:
                    raise RuntimeError("invalid backend QMP JSON") from error
                if not isinstance(value, dict):
                    raise RuntimeError("backend QMP frame is not an object")
                return value
            if len(self.buffer) > self.maximum:
                raise RuntimeError("backend QMP frame exceeds configured maximum")
            chunk = self.stream.recv(min(65536, self.maximum + 1))
            if not chunk:
                raise EOFError("backend QMP socket closed")
            self.buffer.extend(chunk)


class AuditLog:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.stream = os.fdopen(descriptor, "w", encoding="ascii", newline="\n")
        self.lock = threading.Lock()

    def write(self, event: Mapping[str, Any]) -> None:
        line = canonical_json(dict(event)).decode("ascii")
        with self.lock:
            self.stream.write(line + "\n")
            self.stream.flush()

    def close(self) -> None:
        with self.lock:
            self.stream.close()


def validate_backend_path(path: Path, policy: GatePolicy) -> Path:
    resolved_root = policy.backend_root.resolve(strict=True)
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError("backend QMP socket must be below /tmp") from error
    parent = resolved.parent
    parent_stat = parent.stat()
    if stat.S_IMODE(parent_stat.st_mode) != policy.backend_directory_mode:
        raise ValueError("backend QMP parent directory must have mode 0700")
    if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
        raise ValueError("backend QMP parent directory must be owned by the gate user")
    socket_stat = resolved.stat()
    if not stat.S_ISSOCK(socket_stat.st_mode):
        raise ValueError("backend QMP path is not a Unix socket")
    if hasattr(os, "geteuid") and socket_stat.st_uid != os.geteuid():
        raise ValueError("backend QMP socket must be owned by the gate user")
    return resolved


def _recv_client(stream: socket.socket, maximum: int) -> tuple[bytes, bool]:
    if not hasattr(stream, "recvmsg") or not hasattr(socket, "SCM_RIGHTS"):
        return stream.recv(min(65536, maximum + 1)), False
    integer_size = array.array("i").itemsize
    ancillary_size = socket.CMSG_SPACE(integer_size * 64)
    data, ancillary, flags, _ = stream.recvmsg(
        min(65536, maximum + 1), ancillary_size
    )
    rejected_control = bool(flags & getattr(socket, "MSG_CTRUNC", 0))
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            rejected_control = True
            continue
        descriptors = array.array("i")
        usable = len(payload) - (len(payload) % integer_size)
        descriptors.frombytes(payload[:usable])
        rejected_control = True
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return data, rejected_control


def peer_credential(stream: socket.socket) -> dict[str, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        return {"pid": -1, "uid": -1, "gid": -1}
    size = struct.calcsize("3i")
    payload = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    pid, uid, gid = struct.unpack("3i", payload)
    return {"pid": pid, "uid": uid, "gid": gid}


class QmpGate:
    def __init__(
        self,
        *,
        listen_path: Path,
        backend_path: Path,
        policy: GatePolicy,
        audit: AuditLog,
    ) -> None:
        self.listen_path = listen_path
        self.backend_path = backend_path
        self.policy = policy
        self.audit = audit
        self.stop = threading.Event()
        self.counter_lock = threading.Lock()
        self.connection_counter = 0
        self.backend_nonce = secrets.token_hex(16)
        self.worker_lock = threading.Lock()
        self.workers: set[threading.Thread] = set()
        self.active_sockets: set[socket.socket] = set()

    def _next_connection(self) -> int:
        with self.counter_lock:
            self.connection_counter += 1
            return self.connection_counter

    def _audit(
        self,
        connection: int,
        sequence: int,
        verdict: str,
        reason: str,
        *,
        command: str | None,
        request_digest: str,
        peer: Mapping[str, int],
    ) -> None:
        # Never persist an untrusted execute string.  An unknown command is
        # represented by null and remains correlatable through its digest.
        safe_command = command if command in ALLOWED_COMMANDS else None
        self.audit.write(
            {
                "connection": connection,
                "sequence": sequence,
                "verdict": verdict,
                "reason": reason,
                "command": safe_command,
                "requestDigest": request_digest,
                "policyHash": self.policy.policy_hash,
                "peerCredential": dict(peer),
            }
        )

    def _negotiate_backend(
        self,
        backend: socket.socket,
        reader: JsonLineReader,
        connection: int,
    ) -> None:
        backend_id = (
            f"{BACKEND_ID_PREFIX}{self.backend_nonce}:{connection}:capabilities"
        )
        backend.sendall(
            encode_frame({"execute": "qmp_capabilities", "id": backend_id})
        )
        while True:
            response = reader.read()
            if "event" in response:
                continue
            if response.get("id") != backend_id:
                raise RuntimeError("backend QMP capability response id mismatch")
            if "return" not in response or "error" in response:
                raise RuntimeError("backend QMP capability negotiation failed")
            return

    def _backend_round_trip(
        self,
        backend: socket.socket,
        reader: JsonLineReader,
        request: AdmittedRequest,
        backend_id: str,
    ) -> BackendOutcome:
        backend.sendall(encode_frame(backend_request(request, backend_id)))
        while True:
            response = reader.read()
            if "event" in response:
                continue
            if response.get("id") != backend_id:
                raise RuntimeError("backend QMP response id mismatch")
            succeeded = "return" in response and "error" not in response
            return BackendOutcome(
                response=client_response(response, request, self.policy),
                succeeded=succeeded,
            )

    def _track_socket(self, stream: socket.socket) -> None:
        with self.worker_lock:
            self.active_sockets.add(stream)

    def _untrack_socket(self, stream: socket.socket) -> None:
        with self.worker_lock:
            self.active_sockets.discard(stream)

    def request_stop(self) -> None:
        self.stop.set()
        with self.worker_lock:
            streams = tuple(self.active_sockets)
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _run_client(self, client: socket.socket, connection: int) -> None:
        try:
            self._handle_client(client, connection)
        finally:
            self._untrack_socket(client)
            with self.worker_lock:
                self.workers.discard(threading.current_thread())

    def _handle_client(self, client: socket.socket, connection: int) -> None:
        sequence = 0
        backend: socket.socket | None = None
        peer = peer_credential(client)
        try:
            client.settimeout(30)
            backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._track_socket(backend)
            backend.settimeout(30)
            backend.connect(str(self.backend_path))
            reader = JsonLineReader(backend, self.policy.max_backend_frame_bytes)
            greeting = reader.read()
            if "QMP" not in greeting:
                raise RuntimeError("backend did not send a QMP greeting")
            self._negotiate_backend(backend, reader, connection)
            client.sendall(encode_frame(greeting))

            buffer = bytearray()
            while not self.stop.is_set():
                chunk, rejected_control = _recv_client(
                    client, self.policy.max_frame_bytes
                )
                if rejected_control:
                    sequence += 1
                    self._audit(
                        connection,
                        sequence,
                        "deny",
                        "ancillary-data-not-allowed",
                        command=None,
                        request_digest=hashlib.sha256(chunk).hexdigest(),
                        peer=peer,
                    )
                    client.sendall(encode_frame(stable_error(self.policy)))
                    return
                if not chunk:
                    return
                buffer.extend(chunk)
                while True:
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        if len(buffer) > self.policy.max_frame_bytes:
                            sequence += 1
                            self._audit(
                                connection,
                                sequence,
                                "deny",
                                "frame-too-long",
                                command=None,
                                request_digest=hashlib.sha256(buffer).hexdigest(),
                                peer=peer,
                            )
                            client.sendall(encode_frame(stable_error(self.policy)))
                            return
                        break
                    frame = bytes(buffer[:newline])
                    del buffer[: newline + 1]
                    sequence += 1
                    request_digest = hashlib.sha256(frame).hexdigest()
                    try:
                        admitted = decode_request(frame, self.policy)
                    except RequestDenied as denial:
                        self._audit(
                            connection,
                            sequence,
                            "deny",
                            denial.reason,
                            command=denial.command,
                            request_digest=request_digest,
                            peer=peer,
                        )
                        client.sendall(
                            encode_frame(stable_error(self.policy, denial.client_id))
                        )
                        if denial.close:
                            return
                        continue

                    if admitted.command == "qmp_capabilities":
                        response = client_response(
                            {"return": {}}, admitted, self.policy
                        )
                        self._audit(
                            connection,
                            sequence,
                            "local",
                            "local-capabilities",
                            command=admitted.command,
                            request_digest=request_digest,
                            peer=peer,
                        )
                        client.sendall(encode_frame(response))
                        continue

                    backend_id = (
                        f"{BACKEND_ID_PREFIX}{self.backend_nonce}:"
                        f"{connection}:{sequence}"
                    )
                    # This record is flushed before the send.  Once present,
                    # the request can never be represented as a pure denial:
                    # it receives a success or error outcome record below.
                    self._audit(
                        connection,
                        sequence,
                        "forward-attempt",
                        "backend-send-attempt",
                        command=admitted.command,
                        request_digest=request_digest,
                        peer=peer,
                    )
                    try:
                        outcome = self._backend_round_trip(
                            backend, reader, admitted, backend_id
                        )
                    except (EOFError, OSError, RuntimeError):
                        self._audit(
                            connection,
                            sequence,
                            "forward-error",
                            "backend-protocol-error",
                            command=admitted.command,
                            request_digest=request_digest,
                            peer=peer,
                        )
                        client.sendall(
                            encode_frame(
                                stable_error(
                                    self.policy,
                                    admitted.client_id
                                    if admitted.has_client_id
                                    else ABSENT,
                                )
                            )
                        )
                        return
                    self._audit(
                        connection,
                        sequence,
                        "forward-success" if outcome.succeeded else "forward-error",
                        (
                            "backend-return-success"
                            if outcome.succeeded
                            else "backend-return-error"
                        ),
                        command=admitted.command,
                        request_digest=request_digest,
                        peer=peer,
                    )
                    client.sendall(encode_frame(outcome.response))
        except (EOFError, OSError, RuntimeError):
            return
        finally:
            if backend is not None:
                self._untrack_socket(backend)
                backend.close()
            client.close()

    def serve(self) -> None:
        if self.listen_path.exists():
            raise FileExistsError(self.listen_path)
        self.listen_path.parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.listen_path))
        os.chmod(self.listen_path, self.policy.client_socket_mode)
        listener.listen(16)
        listener.settimeout(0.5)
        print(
            json.dumps(
                {
                    "status": "listening",
                    "policy": self.policy.policy_id,
                    "listen": str(self.listen_path),
                    "backend": str(self.backend_path),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        try:
            while not self.stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                connection = self._next_connection()
                thread = threading.Thread(
                    target=self._run_client,
                    args=(client, connection),
                    name=f"qmp-gate-{connection}",
                    daemon=False,
                )
                self._track_socket(client)
                with self.worker_lock:
                    self.workers.add(thread)
                thread.start()
        finally:
            listener.close()
            self.request_stop()
            with self.worker_lock:
                workers = tuple(self.workers)
            for worker in workers:
                worker.join(timeout=10)
            alive = [worker.name for worker in workers if worker.is_alive()]
            if alive:
                raise RuntimeError(f"QMP gate workers did not stop: {alive!r}")
            try:
                self.listen_path.unlink()
            except FileNotFoundError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Qman read-only QMP gate")
    parser.add_argument("--listen", type=Path, required=True)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args()

    policy = load_policy(args.policy)
    backend_path = validate_backend_path(args.backend, policy)
    audit = AuditLog(args.audit)
    gate = QmpGate(
        listen_path=args.listen,
        backend_path=backend_path,
        policy=policy,
        audit=audit,
    )

    def request_stop(_signum: int, _frame: Any) -> None:
        gate.request_stop()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        gate.serve()
    finally:
        audit.close()


if __name__ == "__main__":
    main()
