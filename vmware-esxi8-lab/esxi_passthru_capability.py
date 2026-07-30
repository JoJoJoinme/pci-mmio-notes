#!/usr/bin/env python3
"""Public-interface collectors for the ESXi DirectPath capability matrix."""

from __future__ import annotations

import hashlib
import argparse
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


CAPABILITY_NAMES = {
    0x01: "power-management",
    0x05: "msi",
    0x10: "pci-express",
    0x11: "msi-x",
}
EXTENDED_CAPABILITY_NAMES = {
    0x0001: "advanced-error-reporting",
    0x0003: "device-serial-number",
    0x000D: "access-control-services",
    0x000E: "alternative-routing-id",
    0x0010: "single-root-io-virtualization",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def caveat_field(caveat_id: str, label: str) -> str:
    text = subprocess.run(
        ["caveat", "show", caveat_id],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(
        rf"(?m)^\s*(?:-\s*)?{re.escape(label)}:\s*(\S+)\s*$",
        text,
    )
    if not match:
        raise RuntimeError(f"Caveat {caveat_id!r} does not contain {label!r}")
    return match.group(1)


class EsxiSsh:
    def __init__(
        self,
        host: str,
        password: str,
        user: str = "root",
        retries: int = 4,
    ) -> None:
        self.host = host
        self.password = password
        self.user = user
        self.retries = retries

    def run(
        self,
        command: str,
        *,
        check: bool = True,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["SSHPASS"] = self.password
        argv = [
            "sshpass",
            "-e",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=12",
            f"{self.user}@{self.host}",
            command,
        ]
        last: subprocess.CompletedProcess[str] | None = None
        for attempt in range(1, self.retries + 1):
            last = subprocess.run(
                argv,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if last.returncode == 0 or not check:
                return last
            if attempt < self.retries:
                time.sleep(attempt * 2)
        assert last is not None
        raise RuntimeError(
            f"ESXi SSH command failed ({last.returncode}): {last.stderr.strip()}"
        )


def nfs_datastore_state(ssh: EsxiSsh, volume: str) -> dict[str, Any]:
    result = ssh.run("esxcli storage nfs list", timeout=60)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 7 and fields[0] == volume:
            return {
                "present": True,
                "host": fields[1],
                "share": fields[2],
                "vmknic": fields[3],
                "accessible": fields[4].lower() == "true",
                "mounted": fields[5].lower() == "true",
                "connections": fields[6],
            }
    return {"present": False, "accessible": False, "mounted": False}


def ensure_nfs_datastore(
    ssh: EsxiSsh,
    volume: str = "qemu-shared",
    host: str = "172.31.91.1",
    share: str = "/root/vm/esxi8-mf/nfsds",
) -> dict[str, Any]:
    before = nfs_datastore_state(ssh, volume)
    actions: list[str] = []
    if not (before["accessible"] and before["mounted"]):
        if before["present"]:
            ssh.run(
                f"esxcli storage nfs remove -v {shlex.quote(volume)}",
                check=False,
                timeout=90,
            )
            actions.append("remove-stale-mount")
        ssh.run(
            "esxcli storage nfs add "
            f"-H {shlex.quote(host)} -s {shlex.quote(share)} "
            f"-v {shlex.quote(volume)}",
            timeout=90,
        )
        actions.append("add-mount")
    after = nfs_datastore_state(ssh, volume)
    if not (after["accessible"] and after["mounted"]):
        raise RuntimeError(
            f"NFS datastore {volume!r} is not accessible after remount: {after}"
        )
    return {"before": before, "actions": actions, "after": after}


def wait_for_esxi(ssh: EsxiSsh, timeout: int = 600) -> str:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            result = ssh.run(
                "vim-cmd hostsvc/hostsummary >/dev/null && vmware -vl",
                timeout=30,
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            last_error = str(error)
        time.sleep(5)
    raise TimeoutError(f"ESXi did not become SSH-ready: {last_error}")


def _recv_hmp_prompt(sock: socket.socket) -> bytes:
    response = bytearray()
    marker = b"(qemu)"
    while marker not in response:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError(
                "HMP socket closed before the QEMU prompt was observed"
            )
        response.extend(chunk)
    return bytes(response)


def hmp_command(monitor: str | Path, *commands: str) -> str:
    """Execute HMP commands without inserting an artificial runnable gap."""

    output = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(str(monitor))
        output.extend(_recv_hmp_prompt(sock))
        for command in commands:
            if "\r" in command or "\n" in command:
                raise ValueError("HMP commands must be exactly one line")
            sock.sendall(command.encode("ascii") + b"\n")
            output.extend(_recv_hmp_prompt(sock))
    text = output.decode("utf-8", errors="replace")
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def qemu_command_line(name: str) -> list[str]:
    result = subprocess.run(
        ["pgrep", "-f", f"qemu-system-x86_64.*-name {name}"],
        capture_output=True,
        text=True,
        check=False,
    )
    pids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not pids:
        return []
    data = Path(f"/proc/{pids[0]}/cmdline").read_bytes()
    return [item.decode("utf-8", errors="replace") for item in data.split(b"\0") if item]


def parse_esxcli_pci(text: str) -> dict[str, dict[str, Any]]:
    devices: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s*$", line)
        if match:
            bdf = match.group(1).lower()
            current = {"Address": bdf}
            devices[bdf] = current
            continue
        if current is None:
            continue
        match = re.match(r"^\s+([^:]+):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.group(1).strip(), match.group(2).strip()
        if key == "Address" and value.lower() == current["Address"]:
            continue
        if key not in current:
            current[key] = value
        elif isinstance(current[key], list):
            current[key].append(value)
        else:
            current[key] = [current[key], value]
    return devices


def parse_lspci_dump(text: str) -> dict[str, bytes]:
    devices: dict[str, bytearray] = {}
    current: bytearray | None = None
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s+", line)
        if match:
            bdf = match.group(1).lower()
            current = devices.setdefault(bdf, bytearray())
            continue
        match = re.match(r"^([0-9a-fA-F]{2,3}):\s+((?:[0-9a-fA-F]{2}\s*)+)$", line)
        if current is None or not match:
            continue
        offset = int(match.group(1), 16)
        values = bytes.fromhex(match.group(2))
        if len(current) < offset + len(values):
            current.extend(b"\x00" * (offset + len(values) - len(current)))
        current[offset : offset + len(values)] = values
    return {bdf: bytes(config) for bdf, config in devices.items()}


def _u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def decode_capabilities(config: bytes) -> dict[str, Any]:
    if len(config) < 64:
        return {"length": len(config), "error": "short-config"}
    status = _u16(config, 0x06) or 0
    result: dict[str, Any] = {
        "length": len(config),
        "vendorId": f"0x{(_u16(config, 0x00) or 0):04x}",
        "deviceId": f"0x{(_u16(config, 0x02) or 0):04x}",
        "command": f"0x{(_u16(config, 0x04) or 0):04x}",
        "status": f"0x{status:04x}",
        "headerType": f"0x{config[0x0e]:02x}",
        "romBar": f"0x{(_u32(config, 0x30) or 0):08x}",
        "standard": [],
        "extended": [],
    }

    seen: set[int] = set()
    pointer = config[0x34] & 0xFC if status & 0x10 else 0
    while pointer >= 0x40 and pointer + 2 <= min(len(config), 0x100):
        if pointer in seen:
            result["standardLoopAt"] = f"0x{pointer:02x}"
            break
        seen.add(pointer)
        capability_id = config[pointer]
        next_pointer = config[pointer + 1] & 0xFC
        item: dict[str, Any] = {
            "id": f"0x{capability_id:02x}",
            "name": CAPABILITY_NAMES.get(capability_id, "unknown"),
            "offset": f"0x{pointer:02x}",
        }
        if capability_id == 0x01:
            pmc = _u16(config, pointer + 2) or 0
            pmcsr = _u16(config, pointer + 4) or 0
            item.update(
                {
                    "version": pmc & 0x7,
                    "d1Support": bool(pmc & (1 << 9)),
                    "d2Support": bool(pmc & (1 << 10)),
                    "pmeSupportMask": f"0x{(pmc >> 11) & 0x1f:02x}",
                    "powerState": pmcsr & 0x3,
                    "pmeEnable": bool(pmcsr & (1 << 8)),
                    "pmeStatus": bool(pmcsr & (1 << 15)),
                }
            )
        elif capability_id == 0x10:
            pcie_flags = _u16(config, pointer + 2) or 0
            device_capabilities = _u32(config, pointer + 4) or 0
            device_control = _u16(config, pointer + 8) or 0
            item.update(
                {
                    "version": pcie_flags & 0xF,
                    "devicePortType": (pcie_flags >> 4) & 0xF,
                    "slotImplemented": bool(pcie_flags & (1 << 8)),
                    "deviceCapabilities": f"0x{device_capabilities:08x}",
                    "functionLevelResetCapable": bool(device_capabilities & (1 << 28)),
                    "functionLevelResetInitiated": bool(device_control & (1 << 15)),
                }
            )
        elif capability_id in (0x05, 0x11):
            message_control = _u16(config, pointer + 2) or 0
            item["messageControl"] = f"0x{message_control:04x}"
            item["enabled"] = bool(
                message_control & ((1 << 15) if capability_id == 0x11 else 1)
            )
        result["standard"].append(item)
        if not next_pointer:
            break
        pointer = next_pointer

    pointer = 0x100
    seen.clear()
    while pointer + 4 <= len(config):
        if pointer in seen:
            result["extendedLoopAt"] = f"0x{pointer:03x}"
            break
        seen.add(pointer)
        header = _u32(config, pointer) or 0
        if header in (0, 0xFFFFFFFF):
            break
        capability_id = header & 0xFFFF
        version = (header >> 16) & 0xF
        next_pointer = (header >> 20) & 0xFFF
        item = {
            "id": f"0x{capability_id:04x}",
            "name": EXTENDED_CAPABILITY_NAMES.get(capability_id, "unknown"),
            "offset": f"0x{pointer:03x}",
            "version": version,
        }
        if capability_id == 0x000D:
            acs_capability = _u16(config, pointer + 4) or 0
            acs_control = _u16(config, pointer + 6) or 0
            item["acsCapability"] = f"0x{acs_capability:04x}"
            item["acsControl"] = f"0x{acs_control:04x}"
        result["extended"].append(item)
        if not next_pointer or next_pointer < 0x100 or next_pointer % 4:
            break
        pointer = next_pointer
    return result


def _vmomi_fields(item: Any, names: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in names:
        value = getattr(item, name, None)
        if value is None:
            continue
        if isinstance(value, (str, int, bool, float)):
            result[name] = value
        elif isinstance(value, (list, tuple)):
            result[name] = [str(entry) for entry in value]
        else:
            result[name] = str(value)
    return result


def collect_vsphere_api(host: str, user: str, password: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=host,
        user=user,
        pwd=password,
        sslContext=context,
        connectionPoolTimeout=20,
    )
    try:
        content = service_instance.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        try:
            host_system = list(view.view)[0]
        finally:
            view.Destroy()
        passthru = [
            _vmomi_fields(
                item,
                (
                    "id",
                    "passthruCapable",
                    "passthruEnabled",
                    "passthruActive",
                    "dependentDevice",
                    "resetMethod",
                ),
            )
            for item in (host_system.config.pciPassthruInfo or [])
        ]
        pci_devices = [
            _vmomi_fields(
                item,
                (
                    "id",
                    "classId",
                    "vendorId",
                    "deviceId",
                    "subVendorId",
                    "subDeviceId",
                    "bus",
                    "slot",
                    "function",
                    "vendorName",
                    "deviceName",
                    "parentBridge",
                ),
            )
            for item in (host_system.hardware.pciDevice or [])
        ]
        return {
            "hostName": host_system.name,
            "product": _vmomi_fields(
                host_system.config.product,
                ("name", "fullName", "version", "build", "osType"),
            ),
            "pciPassthruInfo": passthru,
            "pciDevice": pci_devices,
        }
    finally:
        Disconnect(service_instance)


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_case(
    output_dir: Path,
    *,
    case_id: str,
    host: str,
    user: str,
    password: str,
    qemu_name: str,
    monitor: Path,
    targets: list[str],
    requested: dict[str, Any],
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ssh = EsxiSsh(host, password, user)
    commands = {
        "esxi-version.txt": "vmware -vl",
        "esxcli-pci-list.txt": "esxcli hardware pci list",
        "esxcli-passthru-list.txt": "esxcli hardware pci pcipassthru list",
        "lspci-verbose.txt": "lspci -v",
        "lspci-config.txt": "lspci -d",
        "lspci-extended-config.txt": "lspci -e",
        "acs-settings.txt": (
            "esxcfg-advcfg -l | grep -i ACS || true; "
            "grep -i 'enableACSCheckForRP' /bootbank/boot.cfg /altbootbank/boot.cfg 2>/dev/null || true"
        ),
        "boot-config.txt": (
            "printf '%s\\n' '=== /bootbank/boot.cfg ==='; "
            "cat /bootbank/boot.cfg 2>/dev/null || true; "
            "printf '%s\\n' '=== /altbootbank/boot.cfg ==='; "
            "cat /altbootbank/boot.cfg 2>/dev/null || true"
        ),
        "passthru-map.txt": (
            "cat /etc/vmware/passthru.map 2>/dev/null || true; "
            "printf '%s  %s\\n' "
            "\"$(sha256sum /etc/vmware/passthru.map 2>/dev/null | awk '{print $1}')\" "
            "'/etc/vmware/passthru.map'"
        ),
        "vmkernel-pci-log.txt": (
            "grep -Ei 'PCI|ACS|IOMMU|passthru|reset' /var/log/vmkernel.log | "
            "tail -2000 || true"
        ),
        "hostd-passthru-log.txt": (
            "grep -Ei 'PCI|passthru|DirectPath|reset' /var/log/hostd.log | "
            "tail -1000 || true"
        ),
    }
    raw: dict[str, str] = {}
    for filename, command in commands.items():
        completed = ssh.run(command, timeout=180)
        raw[filename] = completed.stdout
        write_text(output_dir / filename, completed.stdout)

    hmp = hmp_command(monitor, "info status", "info pci", "info qtree")
    write_text(output_dir / "qemu-hmp.txt", hmp)
    command_line = qemu_command_line(qemu_name)
    write_text(
        output_dir / "qemu-command.json",
        json.dumps(command_line, indent=2, ensure_ascii=False) + "\n",
    )
    qemu_binary = command_line[0] if command_line else "qemu-system-x86_64"
    qemu_version = subprocess.run(
        [qemu_binary, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    write_text(output_dir / "qemu-version.txt", qemu_version)

    standard_dump = parse_lspci_dump(raw["lspci-config.txt"])
    extended_dump = parse_lspci_dump(raw["lspci-extended-config.txt"])
    esxcli_devices = parse_esxcli_pci(raw["esxcli-pci-list.txt"])
    api: dict[str, Any]
    try:
        api = collect_vsphere_api(host, user, password)
    except Exception as error:  # CLI evidence remains valid if SOAP is transient.
        api = {"error": f"{type(error).__name__}: {error}"}
    write_text(
        output_dir / "vsphere-api.json",
        json.dumps(api, indent=2, ensure_ascii=False) + "\n",
    )

    devices: dict[str, Any] = {}
    for bdf in targets:
        bdf = bdf.lower()
        config = extended_dump.get(bdf) or standard_dump.get(bdf, b"")
        devices[bdf] = {
            "esxcli": esxcli_devices.get(bdf),
            "config": decode_capabilities(config),
            "standardConfigSha256": hashlib.sha256(
                standard_dump.get(bdf, b"")
            ).hexdigest(),
            "extendedConfigSha256": hashlib.sha256(
                extended_dump.get(bdf, b"")
            ).hexdigest(),
        }

    result: dict[str, Any] = {
        "caseId": case_id,
        "observedAt": utc_now(),
        "requested": requested,
        "qemu": {
            "name": qemu_name,
            "version": qemu_version.splitlines()[0],
            "binarySha256": (
                sha256_file(Path(qemu_binary)) if Path(qemu_binary).is_file() else None
            ),
            "command": command_line,
            "hmpEvidence": "qemu-hmp.txt",
        },
        "esxi": {
            "host": host,
            "version": raw["esxi-version.txt"].strip().splitlines(),
            "api": api,
        },
        "devices": devices,
        "rawEvidence": sorted(commands) + [
            "qemu-command.json",
            "qemu-hmp.txt",
            "qemu-version.txt",
            "vsphere-api.json",
        ],
    }
    write_text(
        output_dir / "result.json",
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
    )
    hashes = {
        path.name: sha256_file(path)
        for path in sorted(output_dir.iterdir())
        if path.is_file() and path.name != "sha256.json"
    }
    write_text(
        output_dir / "sha256.json",
        json.dumps(hashes, indent=2, ensure_ascii=False) + "\n",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--case-id", default="collect-only")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--targets", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    password = caveat_field(args.caveat, "Password")
    result = collect_case(
        Path(args.output).resolve(),
        case_id=args.case_id,
        host=args.host,
        user=args.user,
        password=password,
        qemu_name=args.qemu_name,
        monitor=Path(args.monitor),
        targets=args.targets,
        requested={"mode": "collect-only"},
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
