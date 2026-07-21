#!/usr/bin/env python3
"""Run the Qman Static launch envelope against nested stock QEMU 11.

The outer QEMU creates one Ubuntu guest with an Intel vIOMMU and a virtual
e1000e endpoint.  Inside that guest this runner exercises the production
sysfs/VFIO-cdev opener, the durable Static lease and launch envelope, and the
fd-only stock-QEMU launch contract.  The inner QEMU is deliberately started
paused (``-S``), observed over its unique private QMP socket, and then
quarantined because this lab has no independent DMA observer.

No fake descriptor fallback exists.  Missing nested KVM, 9p, dynamic-library,
VFIO cdev, or IOMMUFD prerequisites produce ``ENVIRONMENT_BLOCKED`` rather
than a passing artifact.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
MODEL_ROOT = REPO_ROOT / "pci-resource-model" / "pci_resource_model"
DEFAULT_QEMU = Path("/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64")
DEFAULT_QEMU_SOURCE_ROOT = Path("/root/src/qemu-11.0.2")
DEFAULT_BASE_IMAGE = Path(
    "/mnt/e/Code/PCI/_artifacts/noble-server-cloudimg-amd64.img"
)
DEFAULT_OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE.fd")
DEFAULT_OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS.fd")

EVIDENCE_ID = "QMAN-E3-STATIC-LAUNCH-ENVELOPE-001"
SOURCE_NAMES = (
    "static_lease.py",
    "vfio_provider.py",
    "vfio_launch_handles.py",
    "qemu_launch_contract.py",
    "static_launch_envelope.py",
)
GLIBC_RUNTIME_SONAMES = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libanl.so.1",
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libmemusage.so",
        "libnsl.so.1",
        "libnss_compat.so.2",
        "libnss_dns.so.2",
        "libnss_files.so.2",
        "libnss_hesiod.so.2",
        "libpthread.so.0",
        "libresolv.so.2",
        "librt.so.1",
        "libthread_db.so.1",
        "libutil.so.1",
    }
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def command_output(command: list[str]) -> str:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.strip()


def yaml_base64_block(payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return "\n".join(
        f"      {encoded[index:index + 76]}"
        for index in range(0, len(encoded), 76)
    )


def _guest_orchestrator_source() -> str:
    return r'''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/local/lib/qman")

from pci_resource_model import qemu_launch_contract as launch
from pci_resource_model import static_launch_envelope as envelope
from pci_resource_model import static_lease as leases
from pci_resource_model import vfio_launch_handles as handles
from pci_resource_model import vfio_provider as vfio


CONFIG_PATH = Path("/etc/qman-static-launch.json")
SOURCE_MANIFEST_PATH = Path("/usr/local/lib/qman/source-manifest.json")
RESULT_PATH = Path("/run/qman-static-launch-result.json")
COMMANDS_PATH = Path("/run/qman-static-launch-commands.json")
INNER_LOG_PATH = Path("/run/qman-inner-qemu.log")
QMP_TRANSCRIPT_PATH = Path("/run/qman-qmp-transcript.json")
TRACE_PATH = Path("/run/qman-ioctl-trace.log")

HOST_ID = "qman-nested-host"
AUTHORITY_ID = "qman-lab-inventory-v1"
INVENTORY_EPOCH = 2026072101
QMP_OBSERVER = "qmp-component-observer-v1"
DMA_OBSERVER = "dma-component-observer-unused-v1"
QMP_KEY = b"qman-qmp-component-observer-key-v1-20260721"
DMA_KEY = b"qman-dma-component-observer-key-v1-unused-20260721"
EVIDENCE_ID = "QMAN-E3-STATIC-LAUNCH-ENVELOPE-001"
IOCTL_REQUESTS = {
    "VFIO_DEVICE_BIND_IOMMUFD": 0x3B76,
    "VFIO_DEVICE_ATTACH_IOMMUFD_PT": 0x3B77,
    "IOMMU_IOAS_ALLOC": 0x3B81,
}


class EnvironmentBlocked(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def qman_hash(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def json_write(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class Context:
    def __init__(self) -> None:
        self.commands: list[dict[str, Any]] = []
        self.lease_store = None
        self.envelope_store = None
        self.lease_record = None
        self.envelope_record = None
        self.raw_handles = None
        self.process = None
        self.inner_log = None
        self.trace_root = None
        self.cleanup_complete = False

    def command(
        self,
        argv: list[str],
        *,
        check: bool = True,
        env: dict[str, str] | None = None,
        cwd: str = "/",
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        entry: dict[str, Any] = {
            "argv": argv,
            "cwd": cwd,
            "env": {} if env == {} else "INHERITED",
        }
        self.commands.append(entry)
        completed = subprocess.run(
            argv,
            check=False,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        entry["returnCode"] = completed.returncode
        entry["output"] = completed.stdout
        if check and completed.returncode != 0:
            raise RuntimeError(
                f"command failed ({completed.returncode}): {argv!r}: "
                f"{completed.stdout[-1000:]}"
            )
        return completed


def base_result(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "evidenceId": EVIDENCE_ID,
        "claimScope": "COMPONENT_ONLY",
        "caseClosures": [],
        "riskClosures": [],
        "status": "FAIL",
        "passed": False,
        "environmentBlocked": False,
        "failures": [],
        "environmentBlockers": [],
        "dmaReceiptSubmitted": False,
        "attachedCommitted": False,
        "qmpReceiptSubmitted": False,
        "qmpObservation": None,
        "ioctlTrace": {
            "available": False,
            "unavailableReason": "not attempted",
            "successfulPairs": [],
        },
        "sourceSemantics": {},
        "sourceHashes": {},
        "actualNodes": {},
        "productionProvenance": False,
        "innerSpawn": {},
        "final": {},
        "limitations": [
            "No independent DMA observer is available in this nested lab.",
            "The HMAC QMP receipt authenticates a component observer only.",
            "QMP plus QEMU source semantics infer bind/attach but cannot prove DMA isolation.",
            "No product Case or Risk closure is claimed by this artifact.",
        ],
        "config": config,
        "kernel": {
            "release": os.uname().release,
            "commandLine": Path("/proc/cmdline").read_text(
                encoding="ascii"
            ).strip(),
            "bootId": Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip(),
        },
    }


def verify_embedded_sources(result: dict[str, Any]) -> None:
    expected = json.loads(SOURCE_MANIFEST_PATH.read_text(encoding="utf-8"))
    package = Path("/usr/local/lib/qman/pci_resource_model")
    observed: dict[str, Any] = {}
    failures: list[str] = []
    for name, item in sorted(expected["sources"].items()):
        path = package / name
        digest = sha256_file(path)
        match = digest == item["sha256"]
        observed[name] = {
            "path": str(path),
            "expectedSha256": item["sha256"],
            "observedSha256": digest,
            "match": match,
        }
        if not match:
            failures.append(name)
    result["sourceHashes"] = observed
    if failures:
        raise RuntimeError(f"embedded source hash mismatch: {failures}")


def mount_readonly_9p(
    context: Context,
    tag: str,
    destination: Path,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if context.command(["mountpoint", "-q", str(destination)], check=False).returncode == 0:
        return
    completed = context.command(
        [
            "mount",
            "-t",
            "9p",
            "-o",
            "trans=virtio,version=9p2000.L,ro",
            tag,
            str(destination),
        ],
        check=False,
    )
    if completed.returncode != 0:
        raise EnvironmentBlocked(
            f"readonly 9p mount {tag} unavailable: {completed.stdout[-800:]}"
        )


def install_qemu_runtime(context: Context, config: dict[str, Any]) -> Path:
    context.command(["modprobe", "9pnet_virtio"], check=False)
    source_root = Path(config["innerQemuSourceRoot"])
    mount_readonly_9p(context, "qemu-source", source_root)
    shared_libs = Path("/mnt/qman-qemu-libs-ro")
    mount_readonly_9p(context, "qemu-libs", shared_libs)
    try:
        manifest = json.loads((shared_libs / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise EnvironmentBlocked(f"QEMU dependency manifest unavailable: {error}") from error

    destination = Path("/usr/local/lib/qman-qemu11")
    destination.mkdir(parents=True, exist_ok=True)
    installed: list[dict[str, Any]] = []
    for item in manifest["bundled"]:
        source = shared_libs / item["guestFileName"]
        target = destination / item["guestFileName"]
        if not source.is_file() or sha256_file(source) != item["sha256"]:
            raise EnvironmentBlocked(
                f"QEMU dependency is absent or hash-mismatched: {source}"
            )
        shutil.copyfile(source, target)
        target.chmod(0o755)
        if sha256_file(target) != item["sha256"]:
            raise RuntimeError(f"copied dependency hash mismatch: {target}")
        installed.append(
            {
                "path": str(target),
                "sha256": item["sha256"],
                "soname": item["soname"],
            }
        )
    Path("/etc/ld.so.conf.d/00-qman-qemu11.conf").write_text(
        str(destination) + "\n",
        encoding="ascii",
    )
    context.command(["ldconfig"])

    qemu = Path(config["innerQemuBinary"])
    if not qemu.is_file() or qemu.is_symlink() or not os.access(qemu, os.X_OK):
        raise EnvironmentBlocked(f"inner QEMU is not a regular executable: {qemu}")
    version = context.command([str(qemu), "--version"], env={}, timeout=30)
    if "QEMU emulator version 11." not in version.stdout:
        raise EnvironmentBlocked(
            f"mounted binary is not stock QEMU 11: {version.stdout[:300]}"
        )
    config["installedQemuLibraries"] = installed
    config["innerQemuVersion"] = version.stdout.strip()
    return qemu


def find_target() -> Path:
    matches: list[Path] = []
    for path in sorted(Path("/sys/bus/pci/devices").iterdir()):
        try:
            vendor = (path / "vendor").read_text().strip().lower()
            device = (path / "device").read_text().strip().lower()
        except OSError:
            continue
        if vendor == "0x8086" and device == "0x10d3":
            matches.append(path)
    if len(matches) != 1:
        raise EnvironmentBlocked(
            f"expected one outer e1000e endpoint, observed {len(matches)}"
        )
    return matches[0]


def bind_target_to_vfio(context: Context) -> tuple[str, vfio.DeviceState]:
    context.command(["modprobe", "kvm_intel"], check=False)
    context.command(["modprobe", "iommufd"], check=False)
    context.command(["modprobe", "vfio"], check=False)
    unsafe = Path("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
    if unsafe.exists():
        try:
            unsafe.write_text("0", encoding="ascii")
        except OSError as error:
            raise EnvironmentBlocked(f"cannot disable VFIO no-IOMMU mode: {error}")
    context.command(["modprobe", "vfio-pci"], check=False)
    target = find_target()
    bdf = target.name.lower()
    try:
        (target / "driver_override").write_text("vfio-pci", encoding="ascii")
        driver_link = target / "driver"
        if driver_link.is_symlink():
            (driver_link.resolve() / "unbind").write_text(bdf, encoding="ascii")
        Path("/sys/bus/pci/drivers/vfio-pci/bind").write_text(
            bdf,
            encoding="ascii",
        )
    except OSError as error:
        raise EnvironmentBlocked(f"cannot bind {bdf} to vfio-pci: {error}") from error
    time.sleep(2)
    try:
        state = vfio.LinuxSysfsStateReader().capture(bdf)
    except vfio.ProviderError as error:
        raise EnvironmentBlocked(f"production sysfs capture failed: {error}") from error
    if state.driver != "vfio-pci":
        raise EnvironmentBlocked(f"target driver is {state.driver!r}, not vfio-pci")
    if state.noiommu_node_present:
        raise RuntimeError("target resolved to a no-IOMMU VFIO group")
    if state.cdev_node is None or not state.cdev_node.is_char_device():
        raise EnvironmentBlocked("real /dev/vfio/devices/vfioX cdev is unavailable")
    iommufd = Path("/dev/iommu")
    if not iommufd.is_char_device():
        raise EnvironmentBlocked("real /dev/iommu character device is unavailable")
    kvm = Path("/dev/kvm")
    if not kvm.is_char_device():
        raise EnvironmentBlocked("nested /dev/kvm character device is unavailable")
    return bdf, state


def source_semantics(config: dict[str, Any]) -> dict[str, Any]:
    root = Path(config["innerQemuSourceRoot"])
    candidates = (
        root / "hw/vfio/iommufd.c",
        root / "linux-headers/linux/vfio.h",
        root / "linux-headers/linux/iommufd.h",
    )
    files: list[dict[str, Any]] = []
    combined = ""
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        combined += "\n" + text
        files.append({"path": str(path), "sha256": sha256_file(path)})
    return {
        "files": files,
        "bindSymbolPresent": "VFIO_DEVICE_BIND_IOMMUFD" in combined,
        "attachSymbolPresent": "VFIO_DEVICE_ATTACH_IOMMUFD_PT" in combined,
        "ioasAllocSymbolPresent": "IOMMU_IOAS_ALLOC" in combined,
        "interpretation": (
            "QEMU source symbols plus a realized QMP VFIO device support a "
            "bind/attach inference; they are not an independent DMA receipt."
        ),
    }


def start_ioctl_trace(context: Context) -> dict[str, Any]:
    roots = (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing"))
    trace_root = next(
        (root for root in roots if (root / "events/syscalls").is_dir()),
        None,
    )
    if trace_root is None:
        Path("/sys/kernel/tracing").mkdir(parents=True, exist_ok=True)
        mount = context.command(
            ["mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing"],
            check=False,
        )
        if mount.returncode == 0:
            trace_root = Path("/sys/kernel/tracing")
    if trace_root is None:
        return {
            "available": False,
            "unavailableReason": "tracefs or syscall trace events are unavailable",
            "successfulPairs": [],
        }
    enter = trace_root / "events/syscalls/sys_enter_ioctl/enable"
    leave = trace_root / "events/syscalls/sys_exit_ioctl/enable"
    try:
        if not enter.is_file() or not leave.is_file():
            raise OSError("ioctl syscall events do not exist")
        (trace_root / "tracing_on").write_text("0", encoding="ascii")
        (trace_root / "trace").write_text("", encoding="ascii")
        enter.write_text("1", encoding="ascii")
        leave.write_text("1", encoding="ascii")
        (trace_root / "tracing_on").write_text("1", encoding="ascii")
    except OSError as error:
        return {
            "available": False,
            "unavailableReason": f"cannot enable ioctl syscall tracing: {error}",
            "successfulPairs": [],
        }
    context.trace_root = trace_root
    return {
        "available": True,
        "traceRoot": str(trace_root),
        "unavailableReason": None,
        "successfulPairs": [],
    }


def collect_ioctl_trace(context: Context, pid: int) -> dict[str, Any]:
    root = context.trace_root
    if root is None:
        return {
            "available": False,
            "unavailableReason": "ioctl trace was not enabled",
            "successfulPairs": [],
        }
    task_root = Path(f"/proc/{pid}/task")
    tids: set[int] = {pid}
    comm_by_tid: dict[int, str] = {}
    try:
        for task in task_root.iterdir():
            tid = int(task.name)
            tids.add(tid)
            comm_by_tid[tid] = (task / "comm").read_text().strip()
    except (OSError, ValueError):
        pass
    try:
        (root / "tracing_on").write_text("0", encoding="ascii")
        (root / "events/syscalls/sys_enter_ioctl/enable").write_text(
            "0", encoding="ascii"
        )
        (root / "events/syscalls/sys_exit_ioctl/enable").write_text(
            "0", encoding="ascii"
        )
        raw = (root / "trace").read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return {
            "available": False,
            "unavailableReason": f"cannot retain ioctl trace: {error}",
            "successfulPairs": [],
        }
    TRACE_PATH.write_text(raw, encoding="utf-8")

    task_re = re.compile(r"^\s*(?P<comm>.+)-(?P<tid>[0-9]+)\s+\[[0-9]+\]")
    cmd_re = re.compile(r"\bcmd\s*[:=]\s*(?:0x)?([0-9a-fA-F]+)")
    ret_re = re.compile(
        r"(?:\bret\s*[:=]|\bsys_ioctl\s*->)\s*(0x[0-9a-fA-F]+|-?[0-9]+)"
    )
    pending: dict[int, tuple[str, int]] = {}
    pairs: list[dict[str, Any]] = []
    filtered_lines: list[str] = []
    for line in raw.splitlines():
        task_match = task_re.search(line)
        if task_match is None:
            continue
        tid = int(task_match.group("tid"))
        if tid not in tids:
            continue
        filtered_lines.append(line)
        if "sys_enter_ioctl:" in line or ": sys_ioctl(" in line:
            command = cmd_re.search(line)
            if command is not None:
                pending[tid] = (
                    task_match.group("comm").strip(),
                    int(command.group(1), 16),
                )
        elif ("sys_exit_ioctl:" in line or ": sys_ioctl ->" in line) and tid in pending:
            returned = ret_re.search(line)
            if returned is not None:
                comm, command = pending.pop(tid)
                raw_return = int(returned.group(1), 0)
                if raw_return >= 1 << 63:
                    raw_return -= 1 << 64
                pairs.append(
                    {
                        "comm": comm,
                        "tid": tid,
                        "request": f"0x{command:04x}",
                        "return": raw_return,
                    }
                )
    relevant = [
        pair
        for pair in pairs
        if int(pair["request"], 16) in set(IOCTL_REQUESTS.values())
    ]
    successful = [pair for pair in relevant if pair["return"] == 0]
    observed_requests = {int(pair["request"], 16) for pair in successful}
    expected = {
        name: {
            "request": f"0x{request:04x}",
            "successful": request in observed_requests,
        }
        for name, request in IOCTL_REQUESTS.items()
    }
    complete = (
        expected["VFIO_DEVICE_BIND_IOMMUFD"]["successful"]
        and expected["VFIO_DEVICE_ATTACH_IOMMUFD_PT"]["successful"]
    )
    return {
        "available": True,
        "unavailableReason": None,
        "qemuPid": pid,
        "qemuTids": sorted(tids),
        "qemuCommByTid": {str(key): value for key, value in comm_by_tid.items()},
        "filteredLineCount": len(filtered_lines),
        "pairedIoctlCount": len(pairs),
        "relevantPairs": relevant,
        "successfulPairs": successful,
        "expectedRequests": expected,
        "bindAndAttachObservedSuccessful": complete,
        "rawTracePath": str(TRACE_PATH),
    }


class QmpClient:
    def __init__(self, path: Path, process: subprocess.Popen[Any]) -> None:
        deadline = time.monotonic() + 90
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"inner QEMU exited before QMP, rc={process.returncode}"
                )
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(5)
            try:
                connection.connect(str(path))
            except OSError as error:
                last_error = error
                connection.close()
                time.sleep(0.1)
                continue
            stream = connection.makefile("rwb", buffering=0)
            try:
                line = stream.readline()
                if not line:
                    raise RuntimeError("QMP connection closed before greeting")
                greeting = json.loads(line.decode("utf-8"))
                if not isinstance(greeting, dict):
                    raise RuntimeError("QMP greeting is not an object")
            except (OSError, RuntimeError, json.JSONDecodeError) as error:
                last_error = error
                stream.close()
                connection.close()
                time.sleep(0.1)
                continue
            if "QMP" not in greeting:
                stream.close()
                connection.close()
                raise RuntimeError("QMP greeting is missing QMP capabilities")
            # QEMU can publish the greeting before slow VFIO/IOMMUFD machine
            # realization has returned to the main loop.  Keep every command
            # bounded, but do not turn a transient three-second initialization
            # delay into a false component failure.
            connection.settimeout(60)
            self.connection = connection
            self.stream = stream
            self.transcript: list[dict[str, Any]] = []
            self.transcript.append({"direction": "receive", "message": greeting})
            return
        raise RuntimeError(f"private QMP socket did not become ready: {last_error}")

    def _read(self) -> dict[str, Any]:
        line = self.stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        value = json.loads(line.decode("utf-8"))
        if not isinstance(value, dict):
            raise RuntimeError("QMP message is not an object")
        return value

    def execute(
        self,
        command: str,
        sequence: int,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        request = {"execute": command, "id": sequence}
        if arguments is not None:
            request["arguments"] = arguments
        self.transcript.append({"direction": "send", "message": request})
        self.stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        while True:
            try:
                response = self._read()
            except TimeoutError as error:
                raise RuntimeError(
                    f"QMP {command} response timed out after 60 seconds"
                ) from error
            self.transcript.append({"direction": "receive", "message": response})
            if response.get("id") != sequence:
                continue
            if "error" in response:
                raise RuntimeError(f"QMP {command} failed: {response['error']}")
            return response.get("return")

    def close(self) -> None:
        self.stream.close()
        self.connection.close()


def contains_exact_string(value: Any, expected: str) -> bool:
    if value == expected:
        return True
    if isinstance(value, dict):
        return any(contains_exact_string(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(contains_exact_string(item, expected) for item in value)
    return False


def contains_qom_child(value: Any, *, name: str, type_fragment: str) -> bool:
    return isinstance(value, list) and any(
        isinstance(item, dict)
        and item.get("name") == name
        and type_fragment in str(item.get("type", ""))
        for item in value
    )


def envelope_view(record: Any) -> dict[str, Any]:
    return {
        "transactionId": record.transaction_id,
        "state": record.state.value,
        "revision": record.revision,
        "plannedPreparingRevision": record.planned_preparing_revision,
        "launchPlanHash": record.launch_plan_hash,
        "fdBindingHash": record.fd_binding_hash,
        "qemuPid": record.qemu_pid,
        "qemuStartToken": record.qemu_start_token,
        "qmpObserverId": record.qmp_observer_id,
        "dmaObserverId": record.dma_observer_id,
        "reasonCode": record.reason_code,
    }


def lease_view(record: Any) -> dict[str, Any]:
    return {
        "transactionId": record.transaction_id,
        "state": record.state.value,
        "revision": record.revision,
        "vmGeneration": record.vm_generation,
        "members": list(record.members),
        "inventoryEpoch": record.inventory_epoch,
        "storeInstanceId": None,
        "reasonCode": record.reason_code,
    }


def stop_inner(context: Context) -> None:
    process = context.process
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    if context.inner_log is not None:
        context.inner_log.flush()
        context.inner_log.close()
        context.inner_log = None


def quarantine_cleanup(context: Context, reason: str) -> list[str]:
    errors: list[str] = []
    if context.trace_root is not None:
        try:
            (context.trace_root / "tracing_on").write_text("0", encoding="ascii")
        except OSError:
            pass
    if context.envelope_store is not None and context.envelope_record is not None:
        try:
            current = context.envelope_store.get(
                context.envelope_record.transaction_id
            )
            if current.state not in {
                envelope.EnvelopeState.CLEANING,
                envelope.EnvelopeState.QUARANTINED,
                envelope.EnvelopeState.RECOVERY_REQUIRED,
            }:
                current = context.envelope_store.start_cleaning(
                    current.transaction_id,
                    current.revision,
                    reason_code="STATIC_LAUNCH_ABORTED",
                    reason_detail=reason[:512],
                )
            context.envelope_record = current
        except Exception as error:
            errors.append(f"envelope start_cleaning failed: {error}")
    try:
        stop_inner(context)
    except Exception as error:
        errors.append(f"inner QEMU cleanup failed: {error}")
    if context.raw_handles is not None and not context.raw_handles.closed:
        try:
            context.raw_handles.close()
        except Exception as error:
            errors.append(f"raw handle cleanup failed: {error}")
    if context.lease_store is not None and context.lease_record is not None:
        try:
            current_lease = context.lease_store.get(
                context.lease_record.transaction_id
            )
            if current_lease.state not in {
                leases.LeaseState.QUARANTINED,
                leases.LeaseState.RELEASED,
            }:
                current_lease = context.lease_store.quarantine(
                    current_lease.transaction_id,
                    current_lease.vm_generation,
                    current_lease.revision,
                    reason_code="INDEPENDENT_DMA_RECEIPT_UNAVAILABLE",
                    reason_detail=reason[:512],
                )
            context.lease_record = current_lease
        except Exception as error:
            errors.append(f"lease quarantine failed: {error}")
    if context.envelope_store is not None and context.envelope_record is not None:
        try:
            current = context.envelope_store.get(
                context.envelope_record.transaction_id
            )
            current_lease = (
                None
                if context.lease_store is None or context.lease_record is None
                else context.lease_store.get(context.lease_record.transaction_id)
            )
            if (
                current.state in {
                    envelope.EnvelopeState.CLEANING,
                    envelope.EnvelopeState.RECOVERY_REQUIRED,
                }
                and current_lease is not None
                and current_lease.state is leases.LeaseState.QUARANTINED
            ):
                current = context.envelope_store.confirm_quarantined(
                    current.transaction_id,
                    current.revision,
                )
            context.envelope_record = current
        except Exception as error:
            errors.append(f"envelope quarantine confirmation failed: {error}")
    context.cleanup_complete = not errors
    return errors


def retain_runtime_diagnostics(context: Context, result: dict[str, Any]) -> None:
    """Best-effort retention before failure cleanup stops QEMU and tracefs."""

    current = result.get("ioctlTrace")
    process = context.process
    if (
        context.trace_root is None
        or process is None
        or (isinstance(current, dict) and "rawTracePath" in current)
    ):
        return
    try:
        result["ioctlTrace"] = collect_ioctl_trace(context, process.pid)
    except Exception as error:
        result.setdefault("diagnosticRetentionErrors", []).append(
            f"ioctl trace retention failed: {error}"
        )


def execute_component(
    context: Context,
    config: dict[str, Any],
    result: dict[str, Any],
) -> None:
    verify_embedded_sources(result)
    qemu = install_qemu_runtime(context, config)
    bdf, state = bind_target_to_vfio(context)
    identity_hash = vfio.compute_identity_hash(bdf, state.identity)
    group_hash = vfio.compute_group_hash(
        bdf,
        state.iommu_group,
        state.group_members,
    )
    result["actualNodes"] = {
        "bdf": bdf,
        "driver": state.driver,
        "iommuGroup": state.iommu_group,
        "groupMembers": list(state.group_members),
        "vfioCdev": str(state.cdev_node),
        "vfioCdevIsCharacterDevice": bool(
            state.cdev_node and state.cdev_node.is_char_device()
        ),
        "iommufd": "/dev/iommu",
        "iommufdIsCharacterDevice": Path("/dev/iommu").is_char_device(),
        "kvm": "/dev/kvm",
        "kvmIsCharacterDevice": Path("/dev/kvm").is_char_device(),
        "noIommuNodePresent": state.noiommu_node_present,
        "identityHash": identity_hash,
        "groupHash": group_hash,
    }
    result["sourceSemantics"] = source_semantics(config)

    boot_id = result["kernel"]["bootId"]
    work_root = Path("/var/lib/qman-static-launch") / boot_id
    work_root.mkdir(parents=True, exist_ok=False)
    # AF_UNIX sun_path is only 108 bytes including the terminator.  Keep the
    # authoritative databases under /var/lib, but put the nonce-bound runtime
    # directory under the short-lived /run namespace.
    nonce = secrets.token_hex(16)
    runtime = Path("/run") / f"qm-{nonce[:12]}"
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    qmp_path = runtime / f"backend-{nonce}.qmp"

    members = tuple(state.group_members)
    generations = {member: 1 for member in members}
    bundle_id = "bundle-e1000e-iommu-group"
    decision_hash = qman_hash("qman-static-launch-lab-decision-v1")
    policy_hash = qman_hash("qman-static-launch-lab-policy-v1")
    lease_store = leases.StaticLeaseStore(
        work_root / "static-lease.sqlite3",
        local_host_id=HOST_ID,
        trusted_authority_id=AUTHORITY_ID,
        transaction_id_factory=lambda: "tx-static-launch-e1000e-v1",
    )
    context.lease_store = lease_store
    lease_store.publish_authoritative_device_generations(
        HOST_ID,
        generations,
        expected_current={member: None for member in members},
        authority_id=AUTHORITY_ID,
        authority_epoch=INVENTORY_EPOCH,
    )
    bundle_hash = lease_store.publish_authoritative_bundle(
        HOST_ID,
        bundle_id,
        members,
        expected_current_hash=None,
        authority_id=AUTHORITY_ID,
        authority_epoch=INVENTORY_EPOCH,
    )
    reserved = lease_store.begin(
        leases.BeginRequest(
            idempotency_key="idem-static-launch-e1000e-v1",
            host_id=HOST_ID,
            vm_id="vm-static-launch-v1",
            run_id="run-static-launch-e1000e-v1",
            bundle_id=bundle_id,
            expected_bundle_hash=bundle_hash,
            members=members,
            inventory_epoch=INVENTORY_EPOCH,
            expected_vm_generation=0,
            expected_device_generations=generations,
            decision_hash=decision_hash,
            policy_hash=policy_hash,
        )
    )
    context.lease_record = reserved

    envelope_store = envelope.StaticLaunchEnvelopeStore(
        work_root / "static-launch-envelope.sqlite3",
        local_host_id=HOST_ID,
        trusted_authority_id=AUTHORITY_ID,
        authoritative_lease_store=lease_store,
        verifier_keys={
            envelope.ReceiptRole.QMP: {QMP_OBSERVER: QMP_KEY},
            envelope.ReceiptRole.DMA: {DMA_OBSERVER: DMA_KEY},
        },
    )
    context.envelope_store = envelope_store
    intent = envelope_store.begin(
        envelope.LaunchIntent(
            transaction_id=reserved.transaction_id,
            host_id=reserved.host_id,
            vm_id=reserved.vm_id,
            run_id=reserved.run_id,
            bundle_id=reserved.bundle_id,
            vm_generation=reserved.vm_generation,
            planned_preparing_revision=reserved.revision + 1,
            decision_hash=reserved.decision_hash,
            policy_hash=reserved.policy_hash,
            qmp_endpoint=str(qmp_path),
        )
    )
    context.envelope_record = intent
    preparing = lease_store.prepare(
        reserved.transaction_id,
        reserved.vm_generation,
        reserved.revision,
    )
    context.lease_record = preparing
    prepared_envelope = envelope_store.mark_lease_prepared(
        intent.transaction_id,
        intent.revision,
    )
    context.envelope_record = prepared_envelope

    raw = handles.open_vfio_launch_handles(
        handles.VfioLaunchRequest(
            bdf=bdf,
            snapshot_epoch=INVENTORY_EPOCH,
            topology_hash=group_hash,
            expected_identity_hash=identity_hash,
            expected_group_hash=group_hash,
        )
    )
    context.raw_handles = raw
    result["productionProvenance"] = handles.is_production_launch_result(raw)
    if not result["productionProvenance"]:
        raise RuntimeError("raw VFIO launch result lacks production provenance")
    result["rawHandleMetadata"] = raw.metadata.to_json()

    trace_status = start_ioctl_trace(context)
    result["ioctlTrace"] = trace_status
    qemu_identity = launch.capture_qemu_binary_identity(qemu)
    runtime_stat = launch.DirectoryStatToken.from_stat(os.stat(runtime))
    qmp_binding = launch.QmpSocketBinding(
        runtime_directory=runtime,
        runtime_stat=runtime_stat,
        socket_path=qmp_path,
        nonce=nonce,
    )
    profile = launch.MachineProfile(
        profile_id="q35-static-component-v1",
        machine_type="pc-q35-11.0",
        memory_mib=512,
        vcpu_count=1,
    )

    with lease_store.authorize_launch(
        preparing.transaction_id,
        preparing.vm_generation,
        preparing.revision,
    ) as authorization:
        lease_binding = launch.lease_binding_from_launch_authorization(
            authorization
        )
        device_binding = launch.device_binding_from_vfio_launch_result(
            raw,
            launch.GuestSlot(index=0, root_port_address=2),
            lease_binding,
        )
        plan = launch.DirectPathLaunchPlan(
            qemu=qemu_identity,
            lease=lease_binding,
            profile=profile,
            qmp=qmp_binding,
            devices=(device_binding,),
        )
        spec = launch.render_launch(plan)
        context.envelope_record = envelope_store.mark_handles_open(
            prepared_envelope.transaction_id,
            prepared_envelope.revision,
            fd_binding_hash=spec.fd_binding_hash,
            launch_plan_hash=spec.plan_hash,
        )
        launch.validate_before_spawn(spec)
        kwargs = spec.popen_kwargs()
        if kwargs.get("env") != {} or kwargs.get("cwd") != "/":
            raise RuntimeError("SpawnSpec did not preserve env={} and cwd=/")
        result["innerSpawn"] = {
            "argv": list(spec.argv),
            "argvHash": spec.argv_hash,
            "fdBindingHash": spec.fd_binding_hash,
            "launchPlanHash": spec.plan_hash,
            "passFds": list(spec.pass_fds),
            "environment": kwargs["env"],
            "cwd": kwargs["cwd"],
            "closeFds": kwargs["close_fds"],
            "shell": kwargs["shell"],
            "qemuBinarySha256": spec.qemu_binary_hash,
            "leaseAuthorizationActiveAtSpawn": authorization.is_active,
        }
        context.commands.append(
            {
                "argv": list(spec.argv),
                "cwd": kwargs["cwd"],
                "env": kwargs["env"],
                "passFds": list(spec.pass_fds),
                "source": "canonical SpawnSpec",
            }
        )
        context.inner_log = INNER_LOG_PATH.open("wb")
        process = subprocess.Popen(
            **kwargs,
            stdout=context.inner_log,
            stderr=subprocess.STDOUT,
        )
        context.process = process
        start_token = envelope.StaticLaunchEnvelopeStore.capture_linux_process_start_token(
            process.pid
        )
        context.envelope_record = envelope_store.mark_qemu_running(
            context.envelope_record.transaction_id,
            context.envelope_record.revision,
            qemu_pid=process.pid,
            qemu_start_token=start_token,
        )

    process = context.process
    if process is None:
        raise RuntimeError("inner QEMU process was not created")
    try:
        qmp = QmpClient(qmp_path, process)
    except RuntimeError as error:
        if context.inner_log is not None:
            context.inner_log.flush()
        log = (
            INNER_LOG_PATH.read_text(encoding="utf-8", errors="replace")
            if INNER_LOG_PATH.exists()
            else ""
        )
        lowered = log.lower()
        if "kvm" in lowered and any(
            marker in lowered
            for marker in ("not available", "permission denied", "failed", "cannot")
        ):
            raise EnvironmentBlocked(f"nested KVM launch unavailable: {log[-1000:]}")
        raise RuntimeError(f"QMP readiness failed: {error}; QEMU log: {log[-1000:]}")
    try:
        qmp.execute("qmp_capabilities", 1)
        status = qmp.execute("query-status", 2)
        kvm = qmp.execute("query-kvm", 3)
        pci = qmp.execute("query-pci", 4)
        peripherals = qmp.execute(
            "qom-list", 5, {"path": "/machine/peripheral"}
        )
        realized = qmp.execute(
            "qom-get",
            6,
            {"path": "/machine/peripheral/dp0", "property": "realized"},
        )
    finally:
        transcript = list(qmp.transcript)
        try:
            qmp.close()
        finally:
            json_write(QMP_TRANSCRIPT_PATH, transcript)
    # query-pci reflects guest/firmware bus numbering.  Under -S, firmware has
    # not enumerated the root-port secondary bus yet, so QOM is the authoritative
    # QEMU object-realization observation for this prelaunch gate.
    endpoint_observed = contains_qom_child(
        peripherals, name="dp0", type_fragment="vfio-pci"
    )
    qmp_ok = (
        isinstance(status, dict)
        and status.get("status") == "prelaunch"
        and status.get("running") is False
        and isinstance(kvm, dict)
        and kvm.get("enabled") is True
        and kvm.get("present") is True
        and endpoint_observed
        and realized is True
        and process.poll() is None
    )
    result["qmpObservation"] = {
        "queryStatus": status,
        "queryKvm": kvm,
        "queryPci": pci,
        "qomPeripheralList": peripherals,
        "qomRealized": realized,
        "vfioEndpointId": "dp0",
        "vfioEndpointObserved": endpoint_observed,
        "innerProcessAlive": process.poll() is None,
        "passed": qmp_ok,
    }
    if result["ioctlTrace"]["available"]:
        result["ioctlTrace"] = collect_ioctl_trace(context, process.pid)

    if not qmp_ok:
        raise RuntimeError("QMP did not prove paused KVM plus realized VFIO endpoint")

    if result["ioctlTrace"]["available"]:
        if not result["ioctlTrace"].get("bindAndAttachObservedSuccessful"):
            raise RuntimeError(
                "available tracefs did not record successful VFIO bind and attach ioctls"
            )

    running = context.envelope_record
    receipt = envelope.SignedReceipt.sign(
        key=QMP_KEY,
        role=envelope.ReceiptRole.QMP,
        observer_id=QMP_OBSERVER,
        envelope_store_id=running.envelope_store_id,
        lease_store_binding_hash=running.lease_store_binding_hash,
        receipt_challenge=running.receipt_challenge,
        transaction_id=running.transaction_id,
        host_id=running.host_id,
        authority_id=running.authority_id,
        lease_revision=running.planned_preparing_revision,
        vm_generation=running.vm_generation,
        decision_hash=running.decision_hash,
        policy_hash=running.policy_hash,
        launch_plan_hash=running.launch_plan_hash,
        fd_binding_hash=running.fd_binding_hash,
        qemu_pid=running.qemu_pid,
        qemu_start_token=running.qemu_start_token,
        outcome=envelope.ReceiptOutcome.QMP_DEVICE_OBSERVED,
        nonce=secrets.token_hex(16),
    )
    qmp_verified = envelope_store.mark_qmp_receipt_verified(
        running.transaction_id,
        running.revision,
        receipt,
    )
    context.envelope_record = qmp_verified
    result["qmpReceiptSubmitted"] = True
    result["qmpReceipt"] = {
        "payload": dict(receipt.canonical_payload()),
        "signature": receipt.signature,
        "semantics": "COMPONENT_AUTHENTICITY_ONLY",
    }

    cleaning = envelope_store.start_cleaning(
        qmp_verified.transaction_id,
        qmp_verified.revision,
        reason_code="INDEPENDENT_DMA_OBSERVER_UNAVAILABLE",
        reason_detail="QMP receipt exists; no independent DMA receipt is available",
    )
    context.envelope_record = cleaning
    stop_inner(context)
    raw.close()
    quarantined_lease = lease_store.quarantine(
        preparing.transaction_id,
        preparing.vm_generation,
        preparing.revision,
        reason_code="INDEPENDENT_DMA_RECEIPT_UNAVAILABLE",
        reason_detail="Inner QEMU stopped after component QMP observation",
    )
    context.lease_record = quarantined_lease
    quarantined_envelope = envelope_store.confirm_quarantined(
        cleaning.transaction_id,
        cleaning.revision,
    )
    context.envelope_record = quarantined_envelope

    member_claims = dict(lease_store.claimed_members(HOST_ID))
    bundle_claims = dict(lease_store.claimed_bundles(HOST_ID))
    claims_retained = (
        all(member_claims.get(member) == preparing.transaction_id for member in members)
        and bundle_claims.get(bundle_id) == preparing.transaction_id
    )
    final_ok = (
        quarantined_lease.state is leases.LeaseState.QUARANTINED
        and quarantined_envelope.state is envelope.EnvelopeState.QUARANTINED
        and raw.closed
        and process.poll() is not None
        and claims_retained
        and result["dmaReceiptSubmitted"] is False
        and result["attachedCommitted"] is False
    )
    result["final"] = {
        "lease": lease_view(quarantined_lease),
        "leaseStoreInstanceId": lease_store.store_instance_id,
        "envelope": envelope_view(quarantined_envelope),
        "rawHandlesClosed": raw.closed,
        "innerQemuReturnCode": process.returncode,
        "claimsRetained": claims_retained,
        "memberClaims": member_claims,
        "bundleClaims": bundle_claims,
    }
    if not final_ok:
        raise RuntimeError("final quarantine/claim invariants were not satisfied")
    context.cleanup_complete = True


def main() -> int:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    context = Context()
    result = base_result(config)
    try:
        execute_component(context, config, result)
        result["status"] = "PASS"
        result["passed"] = True
        return_code = 0
    except EnvironmentBlocked as error:
        result["status"] = "ENVIRONMENT_BLOCKED"
        result["environmentBlocked"] = True
        result["environmentBlockers"].append(str(error))
        retain_runtime_diagnostics(context, result)
        result["failures"].extend(quarantine_cleanup(context, str(error)))
        return_code = 2
    except Exception as error:
        result["status"] = "FAIL"
        result["failures"].append(f"{type(error).__name__}: {error}")
        retain_runtime_diagnostics(context, result)
        result["failures"].extend(quarantine_cleanup(context, str(error)))
        result["traceback"] = traceback.format_exc()
        return_code = 1
    finally:
        if context.lease_store is not None and context.lease_record is not None:
            try:
                result["final"]["lease"] = lease_view(
                    context.lease_store.get(context.lease_record.transaction_id)
                )
                result["final"]["leaseStoreInstanceId"] = (
                    context.lease_store.store_instance_id
                )
            except Exception as error:
                result["failures"].append(f"final lease read failed: {error}")
        if context.envelope_store is not None and context.envelope_record is not None:
            try:
                result["final"]["envelope"] = envelope_view(
                    context.envelope_store.get(
                        context.envelope_record.transaction_id
                    )
                )
            except Exception as error:
                result["failures"].append(f"final envelope read failed: {error}")
        try:
            stop_inner(context)
        except Exception as error:
            result["failures"].append(f"final process cleanup failed: {error}")
        if context.raw_handles is not None and not context.raw_handles.closed:
            try:
                context.raw_handles.close()
            except Exception as error:
                result["failures"].append(f"final handle cleanup failed: {error}")
        if context.envelope_store is not None:
            try:
                context.envelope_store.close()
            except Exception as error:
                result["failures"].append(f"envelope close failed: {error}")
        if context.lease_store is not None:
            try:
                context.lease_store.close()
            except Exception as error:
                result["failures"].append(f"lease close failed: {error}")
        json_write(COMMANDS_PATH, context.commands)
        json_write(RESULT_PATH, result)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _guest_wrapper_source() -> str:
    return r'''#!/usr/bin/env bash
set -u
# ttyS0 is the boot/system console.  A dedicated second serial port prevents
# systemd/kernel output from corrupting long, hash-checked Base64 evidence lines.
exec >/dev/ttyS1 2>&1

echo QMAN_STATIC_LAUNCH_BEGIN
echo QMAN_STATIC_LAUNCH_KERNEL="$(uname -r)"
echo QMAN_STATIC_LAUNCH_CMDLINE="$(cat /proc/cmdline)"

target=
for candidate in /sys/bus/pci/devices/*; do
    [ "$(cat "$candidate/vendor" 2>/dev/null)" = "0x8086" ] || continue
    [ "$(cat "$candidate/device" 2>/dev/null)" = "0x10d3" ] || continue
    target=$candidate
done
reboot_marker=/var/lib/qman-static-launch-iommu-rebooted
if [ -n "$target" ] && [ ! -L "$target/iommu_group" ] \
   && [ ! -e "$reboot_marker" ]; then
    mkdir -p /etc/default/grub.d
    printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"' \
        > /etc/default/grub.d/99-qman-static-launch-iommu.cfg
    if update-grub; then
        touch "$reboot_marker"
        echo QMAN_STATIC_LAUNCH_IOMMU_REBOOT_REQUESTED
        sync
        reboot
        exit 0
    fi
fi

python3 /usr/local/sbin/qman-static-launch-orchestrator.py \
    > /run/qman-static-launch.stdout \
    2> /run/qman-static-launch.stderr
orchestrator_rc=$?

if [ ! -s /run/qman-static-launch-result.json ]; then
    python3 - "$orchestrator_rc" > /run/qman-static-launch-result.json <<'PY'
import json
import sys
print(json.dumps({
    "schemaVersion": 1,
    "evidenceId": "QMAN-E3-STATIC-LAUNCH-ENVELOPE-001",
    "claimScope": "COMPONENT_ONLY",
    "caseClosures": [],
    "riskClosures": [],
    "status": "FAIL",
    "passed": False,
    "environmentBlocked": False,
    "dmaReceiptSubmitted": False,
    "attachedCommitted": False,
    "failures": [f"orchestrator did not write a result; rc={sys.argv[1]}"],
}, sort_keys=True))
PY
fi

for specification in \
    "QMAN_STATIC_LAUNCH_RESULT_B64:/run/qman-static-launch-result.json" \
    "QMAN_STATIC_LAUNCH_COMMANDS_B64:/run/qman-static-launch-commands.json" \
    "QMAN_STATIC_LAUNCH_INNER_LOG_B64:/run/qman-inner-qemu.log" \
    "QMAN_STATIC_LAUNCH_QMP_B64:/run/qman-qmp-transcript.json" \
    "QMAN_STATIC_LAUNCH_IOCTL_TRACE_B64:/run/qman-ioctl-trace.log" \
    "QMAN_STATIC_LAUNCH_STDOUT_B64:/run/qman-static-launch.stdout" \
    "QMAN_STATIC_LAUNCH_STDERR_B64:/run/qman-static-launch.stderr"; do
    marker=${specification%%:*}
    file=${specification#*:}
    if [ -f "$file" ]; then
        echo "$marker=$(base64 -w0 "$file")"
    else
        echo "$marker="
    fi
done
echo QMAN_STATIC_LAUNCH_RC="$orchestrator_rc"
echo QMAN_STATIC_LAUNCH_END
sync
poweroff -f
'''


def collect_sources() -> dict[str, bytes]:
    return {name: (MODEL_ROOT / name).read_bytes() for name in SOURCE_NAMES}


def source_manifest(sources: Mapping[str, bytes]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "sources": {
            name: {
                "repositoryPath": str((MODEL_ROOT / name).resolve()),
                "sha256": sha256_bytes(payload),
            }
            for name, payload in sorted(sources.items())
        },
    }


def write_seed(
    seed_dir: Path,
    seed_image: Path,
    sources: Mapping[str, bytes],
    manifest: dict[str, Any],
    guest_config: dict[str, Any],
) -> None:
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(
        f"instance-id: qman-static-launch-{time.time_ns()}\n"
        "local-hostname: qman-static-launch\n",
        encoding="ascii",
    )
    files: list[tuple[str, str, bytes]] = [
        (
            "/usr/local/lib/qman/pci_resource_model/__init__.py",
            "0644",
            b'"""Minimal package for the embedded Qman launch proof."""\n',
        )
    ]
    files.extend(
        (
            f"/usr/local/lib/qman/pci_resource_model/{name}",
            "0644",
            payload,
        )
        for name, payload in sorted(sources.items())
    )
    files.extend(
        (
            path,
            mode,
            content,
        )
        for path, mode, content in (
            (
                "/usr/local/lib/qman/source-manifest.json",
                "0644",
                (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"),
            ),
            (
                "/etc/qman-static-launch.json",
                "0644",
                (json.dumps(guest_config, sort_keys=True) + "\n").encode("utf-8"),
            ),
            (
                "/usr/local/sbin/qman-static-launch-orchestrator.py",
                "0755",
                _guest_orchestrator_source().encode("utf-8"),
            ),
            (
                "/usr/local/sbin/qman-static-launch-proof.sh",
                "0755",
                _guest_wrapper_source().encode("utf-8"),
            ),
            (
                "/etc/systemd/system/qman-static-launch-proof.service",
                "0644",
                b"[Unit]\nDescription=Qman Static launch component proof\n"
                b"After=cloud-final.service\n\n[Service]\nType=oneshot\n"
                b"ExecStart=/usr/local/sbin/qman-static-launch-proof.sh\n\n"
                b"[Install]\nWantedBy=multi-user.target\n",
            ),
        )
    )
    write_files = []
    for path, mode, payload in files:
        write_files.append(
            f"  - path: {path}\n"
            f"    permissions: '{mode}'\n"
            "    encoding: b64\n"
            "    content: |\n"
            f"{yaml_base64_block(payload)}"
        )
    user_data = (
        "#cloud-config\n"
        "datasource_list: [ NoCloud, None ]\n"
        "network:\n  config: disabled\n"
        'output:\n  all: "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"\n'
        "write_files:\n"
        + "\n".join(write_files)
        + "\nruncmd:\n"
        "  - [ systemctl, enable, qman-static-launch-proof.service ]\n"
        "  - [ /usr/local/sbin/qman-static-launch-proof.sh ]\n"
    )
    (seed_dir / "user-data").write_text(user_data, encoding="ascii")
    subprocess.run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-output",
            str(seed_image),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "user-data",
            "meta-data",
        ],
        cwd=seed_dir,
        check=True,
    )


def dependency_records(qemu: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    output = command_output(["ldd", str(qemu)])
    bundled: dict[str, dict[str, str]] = {}
    excluded: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("linux-vdso"):
            continue
        if "=> not found" in line:
            raise FileNotFoundError(f"QEMU dependency is unresolved: {line}")
        arrow = re.match(r"^(\S+)\s+=>\s+(/\S+)\s+\(", line)
        direct = re.match(r"^(/\S+)\s+\(", line)
        if arrow:
            soname, raw_path = arrow.group(1), arrow.group(2)
        elif direct:
            raw_path = direct.group(1)
            soname = Path(raw_path).name
        else:
            continue
        source = Path(raw_path).resolve(strict=True)
        if soname in GLIBC_RUNTIME_SONAMES or soname.startswith("libnss_"):
            excluded.append(
                {
                    "soname": soname,
                    "sourcePath": str(source),
                    "reason": "guest glibc runtime boundary",
                }
            )
            continue
        digest = sha256_file(source)
        current = bundled.get(soname)
        if current is not None and current["sha256"] != digest:
            raise RuntimeError(f"conflicting QEMU dependency SONAME: {soname}")
        bundled[soname] = {
            "soname": soname,
            "sourcePath": str(source),
            "guestFileName": soname,
            "sha256": digest,
        }
    return list(sorted(bundled.values(), key=lambda item: item["soname"])), excluded


def create_dependency_bundle(qemu: Path, bundle: Path) -> dict[str, Any]:
    bundle.mkdir(parents=True, exist_ok=False)
    bundled, excluded = dependency_records(qemu)
    for item in bundled:
        target = bundle / item["guestFileName"]
        shutil.copyfile(item["sourcePath"], target)
        target.chmod(0o755)
        if sha256_file(target) != item["sha256"]:
            raise RuntimeError(f"dependency copy hash mismatch: {target}")
    manifest = {
        "schemaVersion": 1,
        "qemu": str(qemu),
        "bundled": bundled,
        "excluded": excluded,
    }
    write_json(bundle / "manifest.json", manifest)
    return manifest


def qemu_command(args: argparse.Namespace, output: Path) -> list[str]:
    source_root = str(args.qemu_source_root)
    lib_bundle = str(output / "inner-qemu-libs")
    return [
        str(args.qemu),
        "-machine",
        "q35,accel=kvm,kernel-irqchip=split",
        "-cpu",
        "host",
        "-m",
        "3072",
        "-smp",
        "2",
        "-nodefaults",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-serial",
        f"file:{output / 'evidence-serial.log'}",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on",
        "-device",
        "pcie-root-port,id=test_rp,bus=pcie.0,addr=0x02,chassis=2",
        "-device",
        "e1000e,id=testnic,bus=test_rp,addr=0x00",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={output / 'OVMF_VARS.fd'}",
        "-drive",
        f"if=none,id=osdisk,format=qcow2,file={output / 'os.qcow2'}",
        "-device",
        "virtio-blk-pci,drive=osdisk",
        "-drive",
        f"if=none,id=cidata,format=raw,readonly=on,file={output / 'seed.iso'}",
        "-device",
        "virtio-blk-pci,drive=cidata",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-fsdev",
        (
            f"local,id=qemusrc,path={source_root},security_model=none,"
            "readonly=on,multidevs=remap"
        ),
        "-device",
        "virtio-9p-pci,fsdev=qemusrc,mount_tag=qemu-source",
        "-fsdev",
        (
            f"local,id=qemulibs,path={lib_bundle},security_model=none,"
            "readonly=on,multidevs=remap"
        ),
        "-device",
        "virtio-9p-pci,fsdev=qemulibs,mount_tag=qemu-libs",
    ]


def extract_marker(log: str, marker: str) -> str | None:
    prefix = marker + "="
    matches: list[str] = []
    for raw_line in log.splitlines():
        line = raw_line.strip()
        position = line.find(prefix)
        if position >= 0:
            matches.append(line[position + len(prefix) :].strip())
    return matches[-1] if matches else None


def decode_marker(log: str, marker: str) -> tuple[bytes, str | None]:
    encoded = extract_marker(log, marker)
    if encoded is None:
        return b"", f"missing {marker}"
    try:
        return base64.b64decode(encoded, validate=True), None
    except ValueError as error:
        return b"", f"invalid {marker}: {error}"


def retained_artifact_hashes(output: Path) -> dict[str, str]:
    excluded = {
        "os.qcow2",
        "OVMF_VARS.fd",
        "seed.iso",
    }
    hashes: dict[str, str] = {}
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        if "inner-qemu-libs" in path.parts and path.name != "manifest.json":
            continue
        if path.name in {"summary.json", "hashes.json"}:
            continue
        hashes[path.relative_to(output).as_posix()] = sha256_file(path)
    return hashes


def evaluate_guest(
    guest: dict[str, Any] | None,
    manifest: dict[str, Any],
    parse_errors: list[str],
) -> tuple[str, list[str]]:
    failures = list(parse_errors)
    if guest is None:
        return "fail", failures
    if guest.get("status") == "ENVIRONMENT_BLOCKED":
        if guest.get("passed") is True:
            failures.append("environment-blocked guest also claimed passed=true")
            return "fail", failures
        return "environment-blocked", failures
    if guest.get("status") != "PASS" or guest.get("passed") is not True:
        failures.append("guest did not report PASS")
    if guest.get("claimScope") != "COMPONENT_ONLY":
        failures.append("claim scope is not COMPONENT_ONLY")
    if guest.get("caseClosures") != [] or guest.get("riskClosures") != []:
        failures.append("component artifact claimed a Case or Risk closure")
    if guest.get("dmaReceiptSubmitted") is not False:
        failures.append("DMA receipt was submitted or omitted")
    if guest.get("attachedCommitted") is not False:
        failures.append("Static ATTACHED was committed or omitted")
    if guest.get("productionProvenance") is not True:
        failures.append("production raw-handle provenance is absent")
    nodes = guest.get("actualNodes")
    if not isinstance(nodes, dict):
        failures.append("actual character-device facts are absent")
        nodes = {}
    if not re.fullmatch(r"/dev/vfio/devices/vfio[0-9]+", str(nodes.get("vfioCdev"))):
        failures.append("real VFIO cdev path is absent")
    if nodes.get("vfioCdevIsCharacterDevice") is not True:
        failures.append("VFIO cdev was not a character device")
    if nodes.get("iommufd") != "/dev/iommu" or nodes.get(
        "iommufdIsCharacterDevice"
    ) is not True:
        failures.append("real /dev/iommu character device is absent")
    if nodes.get("kvmIsCharacterDevice") is not True:
        failures.append("nested /dev/kvm character device is absent")
    qmp = guest.get("qmpObservation")
    if not isinstance(qmp, dict) or qmp.get("passed") is not True:
        failures.append("inner QMP paused/KVM/VFIO observation did not pass")
    final = guest.get("final")
    if not isinstance(final, dict):
        failures.append("final quarantine facts are absent")
        final = {}
    if not isinstance(final.get("lease"), dict) or final["lease"].get(
        "state"
    ) != "QUARANTINED":
        failures.append("final lease is not QUARANTINED")
    if not isinstance(final.get("envelope"), dict) or final["envelope"].get(
        "state"
    ) != "QUARANTINED":
        failures.append("final envelope is not QUARANTINED")
    if final.get("claimsRetained") is not True:
        failures.append("quarantine did not retain bundle/member claims")
    trace = guest.get("ioctlTrace")
    if isinstance(trace, dict) and trace.get("available") is True:
        if trace.get("bindAndAttachObservedSuccessful") is not True:
            failures.append("available trace lacks successful bind/attach ioctl pairs")
    source_hashes = guest.get("sourceHashes")
    if not isinstance(source_hashes, dict):
        failures.append("guest source hashes are absent")
    else:
        for name, item in manifest["sources"].items():
            observed = source_hashes.get(name)
            if not isinstance(observed, dict) or observed.get(
                "observedSha256"
            ) != item["sha256"]:
                failures.append(f"guest source hash mismatch: {name}")
    return ("pass" if not failures else "fail"), failures


def validate_prerequisites(args: argparse.Namespace) -> None:
    for name, path in (
        ("outer QEMU", args.qemu),
        ("QEMU source root", args.qemu_source_root),
        ("inner QEMU", args.inner_qemu),
        ("base image", args.base_image),
        ("OVMF code", args.ovmf_code),
        ("OVMF vars", args.ovmf_vars),
    ):
        predicate = path.is_dir if name == "QEMU source root" else path.is_file
        if not predicate():
            raise FileNotFoundError(f"{name} is unavailable: {path}")
    for name in SOURCE_NAMES:
        if not (MODEL_ROOT / name).is_file():
            raise FileNotFoundError(f"Qman source is unavailable: {MODEL_ROOT / name}")
    if args.qemu.is_symlink() or args.inner_qemu.is_symlink():
        raise ValueError("outer and inner QEMU paths must not be symlinks")
    if not os.access(args.qemu, os.X_OK) or not os.access(args.inner_qemu, os.X_OK):
        raise PermissionError("outer and inner QEMU must be executable")
    try:
        args.inner_qemu.relative_to(args.qemu_source_root)
    except ValueError as error:
        raise ValueError("inner QEMU must be inside the shared source root") from error
    for value in (str(args.qemu_source_root), str(args.output)):
        if "," in value or "\n" in value:
            raise ValueError("QEMU 9p source/output paths cannot contain comma/newline")
    for command in ("ldd", "qemu-img", "xorriso"):
        if shutil.which(command) is None:
            raise FileNotFoundError(f"required command is missing: {command}")
    if args.output.exists():
        raise FileExistsError(f"output must not already exist: {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the nested-QEMU Static launch component evidence case"
    )
    parser.add_argument("--qemu", type=Path, default=DEFAULT_QEMU)
    parser.add_argument(
        "--qemu-source-root",
        type=Path,
        default=DEFAULT_QEMU_SOURCE_ROOT,
    )
    parser.add_argument("--inner-qemu", type=Path, default=DEFAULT_QEMU)
    parser.add_argument("--base-image", type=Path, default=DEFAULT_BASE_IMAGE)
    parser.add_argument("--ovmf-code", type=Path, default=DEFAULT_OVMF_CODE)
    parser.add_argument("--ovmf-vars", type=Path, default=DEFAULT_OVMF_VARS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    args.qemu = args.qemu.resolve()
    args.qemu_source_root = args.qemu_source_root.resolve()
    args.inner_qemu = args.inner_qemu.resolve()
    args.base_image = args.base_image.resolve()
    args.ovmf_code = args.ovmf_code.resolve()
    args.ovmf_vars = args.ovmf_vars.resolve()
    args.output = args.output.resolve()
    validate_prerequisites(args)

    args.output.mkdir(parents=True)
    sources = collect_sources()
    manifest = source_manifest(sources)
    write_json(args.output / "source-manifest.json", manifest)
    embedded = args.output / "embedded-sources"
    embedded.mkdir()
    for name, payload in sources.items():
        (embedded / name).write_bytes(payload)
    dependency_manifest = create_dependency_bundle(
        args.inner_qemu,
        args.output / "inner-qemu-libs",
    )

    shutil.copyfile(args.ovmf_vars, args.output / "OVMF_VARS.fd")
    image_info = json.loads(
        command_output(["qemu-img", "info", "--output=json", str(args.base_image)])
    )
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            image_info["format"],
            "-b",
            str(args.base_image),
            str(args.output / "os.qcow2"),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    guest_config = {
        "schemaVersion": 1,
        "evidenceId": EVIDENCE_ID,
        "innerQemuSourceRoot": str(args.qemu_source_root),
        "innerQemuBinary": str(args.inner_qemu),
        "claimScope": "COMPONENT_ONLY",
    }
    write_seed(
        args.output / "seed",
        args.output / "seed.iso",
        sources,
        manifest,
        guest_config,
    )
    command = qemu_command(args, args.output)
    write_json(args.output / "outer-qemu-command.json", command)

    serial_log = args.output / "serial.log"
    evidence_serial_log = args.output / "evidence-serial.log"
    attempts: list[dict[str, Any]] = []
    started = time.monotonic()
    timed_out = False
    for attempt in range(1, 3):
        with serial_log.open("a", encoding="utf-8") as stream:
            stream.write(f"\n===== QMAN OUTER QEMU ATTEMPT {attempt} =====\n")
            stream.flush()
            attempt_started = time.monotonic()
            try:
                completed = subprocess.run(
                    command,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=args.timeout,
                )
                return_code: int | None = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                return_code = None
            attempts.append(
                {
                    "attempt": attempt,
                    "qemuReturnCode": return_code,
                    "timedOut": timed_out,
                    "durationSeconds": round(time.monotonic() - attempt_started, 3),
                }
            )
        evidence_log = (
            evidence_serial_log.read_text(encoding="utf-8", errors="replace")
            if evidence_serial_log.is_file()
            else ""
        )
        needs_reboot = (
            "QMAN_STATIC_LAUNCH_IOMMU_REBOOT_REQUESTED" in evidence_log
            and "QMAN_STATIC_LAUNCH_END" not in evidence_log
            and not timed_out
        )
        if needs_reboot and attempt == 1:
            continue
        break

    evidence_log = (
        evidence_serial_log.read_text(encoding="utf-8", errors="replace")
        if evidence_serial_log.is_file()
        else ""
    )
    parse_errors: list[str] = []
    outputs = (
        ("QMAN_STATIC_LAUNCH_RESULT_B64", "guest-result.json"),
        ("QMAN_STATIC_LAUNCH_COMMANDS_B64", "guest-commands.json"),
        ("QMAN_STATIC_LAUNCH_INNER_LOG_B64", "inner-qemu.log"),
        ("QMAN_STATIC_LAUNCH_QMP_B64", "qmp-transcript.json"),
        ("QMAN_STATIC_LAUNCH_IOCTL_TRACE_B64", "ioctl-trace.log"),
        ("QMAN_STATIC_LAUNCH_STDOUT_B64", "guest-orchestrator.stdout"),
        ("QMAN_STATIC_LAUNCH_STDERR_B64", "guest-orchestrator.stderr"),
    )
    decoded: dict[str, bytes] = {}
    for marker, filename in outputs:
        payload, error = decode_marker(evidence_log, marker)
        decoded[marker] = payload
        (args.output / filename).write_bytes(payload)
        if error is not None:
            parse_errors.append(error)
    if timed_out:
        parse_errors.append("outer QEMU timed out")
    if "QMAN_STATIC_LAUNCH_END" not in evidence_log:
        parse_errors.append("guest completion marker is absent")

    guest: dict[str, Any] | None = None
    try:
        parsed = json.loads(decoded["QMAN_STATIC_LAUNCH_RESULT_B64"])
        if not isinstance(parsed, dict):
            raise ValueError("guest result is not an object")
        guest = parsed
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        parse_errors.append(f"guest result parse failed: {error}")
    verdict, failures = evaluate_guest(guest, manifest, parse_errors)

    inputs = {
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "outerQemu": {"path": str(args.qemu), "sha256": sha256_file(args.qemu)},
        "innerQemu": {
            "path": str(args.inner_qemu),
            "sha256": sha256_file(args.inner_qemu),
        },
        "qemuSourceRoot": {"path": str(args.qemu_source_root)},
        "baseImage": {
            "path": str(args.base_image),
            "sha256": sha256_file(args.base_image),
        },
        "ovmfCode": {
            "path": str(args.ovmf_code),
            "sha256": sha256_file(args.ovmf_code),
        },
        "ovmfVars": {
            "path": str(args.ovmf_vars),
            "sha256": sha256_file(args.ovmf_vars),
        },
        "qmanSources": manifest["sources"],
        "dependencyManifest": dependency_manifest,
    }
    hashes = {
        "schemaVersion": 1,
        "algorithm": "sha256",
        "inputs": inputs,
        "retainedArtifacts": retained_artifact_hashes(args.output),
    }
    write_json(args.output / "hashes.json", hashes)
    summary = {
        "schemaVersion": 1,
        "evidenceId": EVIDENCE_ID,
        "test": "qman-static-launch-envelope-nested-qemu",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "invocation": sys.argv,
        "durationSeconds": round(time.monotonic() - started, 3),
        "environment": (
            "WSL2/KVM outer QEMU 11 -> Ubuntu Intel-vIOMMU guest -> "
            "production VFIO cdev/IOMMUFD -> paused stock inner QEMU 11"
        ),
        "claimScope": "COMPONENT_ONLY",
        "caseClosures": [],
        "riskClosures": [],
        "outerQemuAttempts": attempts,
        "guestStatus": guest.get("status") if guest is not None else None,
        "guestResult": str(args.output / "guest-result.json"),
        "failures": failures,
        "inputs": inputs,
        "retainedEvidence": {
            "outerCommand": str(args.output / "outer-qemu-command.json"),
            "guestCommands": str(args.output / "guest-commands.json"),
            "serialLog": str(serial_log),
            "evidenceSerialLog": str(evidence_serial_log),
            "innerQemuLog": str(args.output / "inner-qemu.log"),
            "qmpTranscript": str(args.output / "qmp-transcript.json"),
            "ioctlTrace": str(args.output / "ioctl-trace.log"),
            "hashes": str(args.output / "hashes.json"),
        },
        "evidenceBoundary": {
            "dmaReceiptSubmitted": False,
            "attachedCommitted": False,
            "qmpReceiptSemantics": "COMPONENT_AUTHENTICITY_ONLY",
            "traceSemantics": (
                "Successful bind/attach ioctl pairs, when available, are strong "
                "stock-QEMU component observations but not an independent DMA receipt."
            ),
            "productClosureClaimed": False,
        },
        "verdict": verdict,
    }
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if verdict == "pass" else 2 if verdict == "environment-blocked" else 1)


if __name__ == "__main__":
    main()
