#!/usr/bin/env python3
"""Run a fail-closed ESXi Correctable AER behavior matrix.

The runner deliberately exposes no uncorrectable injection path.  Every HMP
command is constructed from a closed allow-list of PCIe Correctable Error
Status bits and always uses ``pcie_aer_inject_error -c``.

The default oracle captures the ESXi 8.0.3 behavior already observed by this
lab: the physical Correctable Error Status changes, while an active DirectPath
guest sees a hidden AER header with the raw status body preserved.  Use the
``delivery-only`` oracle when characterising another ESXi build without
asserting that guest projection.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shlex
import ssl
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl

from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field,
    hmp_command,
    qemu_command_line,
)
import test_qemu_aer_correctable_matrix as qemu_aer


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BASE_VMX = SCRIPT_DIR / "mf-passthru-probe-local.vmx"

# Linux pci_regs.h names.  Advisory Non-Fatal is included because it is a
# Correctable Error Status bit and is injected with the same ``-c`` HMP path;
# this runner still exposes no Uncorrectable Status injection surface.
SAFE_CORRECTABLE_BITS: dict[str, int] = {
    "receiver_error": 0x00000001,
    "bad_tlp": 0x00000040,
    "bad_dllp": 0x00000080,
    "replay_number_rollover": 0x00000100,
    "replay_timer_timeout": 0x00001000,
    "advisory_nonfatal": 0x00002000,
    "corrected_internal_error": 0x00004000,
    "header_log_overflow": 0x00008000,
}
BIT_ALIASES = {
    "receiver": "receiver_error",
    "bad-tlp": "bad_tlp",
    "bad-dllp": "bad_dllp",
    "replay_rollover": "replay_number_rollover",
    "replay_timer": "replay_timer_timeout",
    "advisory": "advisory_nonfatal",
    "internal": "corrected_internal_error",
    "header_overflow": "header_log_overflow",
}
SAFE_VALUE_TO_NAME = {value: name for name, value in SAFE_CORRECTABLE_BITS.items()}

OWNER_CHOICES = ("Native", "PassthruIdle", "PassthruActive")
EXPECTED_CURRENT_OWNER = {
    "Native": "VMkernel",
    "PassthruIdle": "VM Passthru",
    "PassthruActive": "VM Passthru",
}
VERDICTS = ("PASS", "FAIL", "FAIL_SAFETY", "INCONCLUSIVE", "BLOCKED_ENV")

BDF_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SAFE_DATASTORE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class BlockedEnvironment(RuntimeError):
    """The requested case cannot safely run in the current environment."""


class InconclusiveObservation(RuntimeError):
    """The case ran or was observable, but cannot support a conclusion."""


class InjectionFailure(RuntimeError):
    """A post-preflight execution or safety assertion failed."""


class SafetyViolation(RuntimeError):
    """A non-Correctable state changed during a Correctable-only case."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def save_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256s(root: Path) -> None:
    checksum_path = root / "SHA256SUMS"
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path != checksum_path
    )
    lines = [
        f"{sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in files
    ]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_safe_id(value: str, label: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise ValueError(f"{label} contains unsafe characters: {value!r}")
    return value


def canonical_bdf(value: str) -> str | None:
    match = re.fullmatch(
        r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)\.([0-7])",
        value.strip(),
    )
    if not match:
        return None
    domain, bus, slot, function = (int(item, 16) for item in match.groups())
    if domain > 0xFFFF or bus > 0xFF or slot > 0x1F:
        return None
    return f"{domain:04x}:{bus:02x}:{slot:02x}.{function:x}"


def vmx_pci_id(bdf: str) -> str:
    canonical = canonical_bdf(bdf)
    if canonical is None:
        raise ValueError(f"invalid PCI BDF: {bdf!r}")
    domain, bus, rest = canonical.split(":")
    slot, function = rest.split(".")
    return f"{int(domain, 16):05x}:{int(bus, 16):03x}:{int(slot, 16):02x}.{function}"


def parse_error_bits(raw: str) -> list[tuple[str, int]]:
    selected: list[tuple[str, int]] = []
    seen: set[int] = set()
    for original in (item.strip() for item in raw.split(",")):
        if not original:
            continue
        token = original.lower().replace(" ", "_")
        token = BIT_ALIASES.get(token, token)
        if token.startswith("0x"):
            try:
                value = int(token, 16)
            except ValueError as error:
                raise ValueError(f"invalid Correctable AER bit: {original!r}") from error
            name = SAFE_VALUE_TO_NAME.get(value)
        else:
            value = SAFE_CORRECTABLE_BITS.get(token, -1)
            name = token if value >= 0 else None
        if name is None or value not in SAFE_VALUE_TO_NAME:
            allowed = ", ".join(SAFE_CORRECTABLE_BITS)
            raise ValueError(
                f"AER bit {original!r} is outside the safe Correctable allow-list; "
                f"allowed values: {allowed}"
            )
        if value not in seen:
            selected.append((SAFE_VALUE_TO_NAME[value], value))
            seen.add(value)
    if not selected:
        raise ValueError("at least one safe Correctable AER bit is required")
    return selected


def build_injection_command(qemu_device: str, mask: int) -> str:
    validate_safe_id(qemu_device, "QEMU device id")
    if mask not in SAFE_VALUE_TO_NAME:
        raise ValueError(f"unsafe or unsupported Correctable AER mask: 0x{mask:08x}")
    # This is intentionally the only injection command constructor in the file.
    return f"pcie_aer_inject_error -c {qemu_device} 0x{mask:08x}"


def extract_esxcli_device(text: str, bdf: str) -> dict[str, str] | None:
    canonical = canonical_bdf(bdf)
    if canonical is None:
        return None
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip().rstrip(":").lower() == canonical:
            start = index + 1
            break
    if start is None:
        return None
    fields: dict[str, str] = {"Address": canonical}
    for line in lines[start:]:
        if re.match(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]:?\s*$", line.strip()):
            break
        match = re.match(r"^\s+([^:]+):\s*(.*)$", line)
        if match:
            fields[match.group(1).strip()] = match.group(2).strip()
    return fields


def extract_lspci_bytes(text: str, bdf: str) -> dict[int, int] | None:
    canonical = canonical_bdf(bdf)
    if canonical is None:
        return None
    lines = text.splitlines()
    start = None
    header_pattern = re.compile(rf"^{re.escape(canonical)}(?:\s|$)", re.IGNORECASE)
    next_device = re.compile(
        r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7](?:\s|$)"
    )
    for index, line in enumerate(lines):
        if header_pattern.match(line):
            start = index + 1
            break
    if start is None:
        return None
    values: dict[int, int] = {}
    for line in lines[start:]:
        if next_device.match(line):
            break
        match = re.match(
            r"^([0-9a-fA-F]{2,3}):\s+((?:[0-9a-fA-F]{2}(?:\s+|$)){1,16})",
            line,
        )
        if not match:
            continue
        offset = int(match.group(1), 16)
        octets = re.findall(r"[0-9a-fA-F]{2}", match.group(2))
        for relative, octet in enumerate(octets):
            values[offset + relative] = int(octet, 16)
    return values or None


def read_le(values: dict[int, int], offset: int, width: int) -> int | None:
    octets = [values.get(offset + index) for index in range(width)]
    if any(item is None for item in octets):
        return None
    return sum(int(item) << (index * 8) for index, item in enumerate(octets))


def find_aer_offset(values: dict[int, int]) -> int | None:
    offset = 0x100
    visited: set[int] = set()
    for _ in range(64):
        if offset in visited or offset < 0x100 or offset > 0xFFC or offset % 4:
            return None
        visited.add(offset)
        header = read_le(values, offset, 4)
        if header in (None, 0, 0xFFFFFFFF):
            return None
        if header & 0xFFFF == 0x0001:
            return offset
        offset = (header >> 20) & 0xFFF
        if offset == 0:
            return None
    return None


def aer_snapshot(values: dict[int, int] | None) -> dict[str, Any] | None:
    if values is None:
        return None
    offset = find_aer_offset(values)
    if offset is None:
        return None
    return {
        "offset": offset,
        "header": read_le(values, offset, 4),
        "uncorrectableStatus": read_le(values, offset + 0x04, 4),
        "uncorrectableMask": read_le(values, offset + 0x08, 4),
        "uncorrectableSeverity": read_le(values, offset + 0x0C, 4),
        "correctableStatus": read_le(values, offset + 0x10, 4),
        "correctableMask": read_le(values, offset + 0x14, 4),
        "capabilityControl": read_le(values, offset + 0x18, 4),
        "rootErrorCommand": read_le(values, offset + 0x2C, 4),
        "rootErrorStatus": read_le(values, offset + 0x30, 4),
        "errorSourceIdentification": read_le(values, offset + 0x34, 4),
    }


def bdf_tuple(value: str) -> tuple[int, int, int]:
    canonical = canonical_bdf(value)
    if canonical is None:
        raise ValueError(f"invalid PCI BDF: {value!r}")
    _, bus_text, slot_function = canonical.split(":")
    slot_text, function_text = slot_function.split(".")
    return int(bus_text, 16), int(slot_text, 16), int(function_text, 16)


def outer_qemu_aer_snapshot(
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
) -> dict[str, Any]:
    if not socket_path.is_socket():
        raise BlockedEnvironment(f"QTest socket is not ready: {socket_path}")
    client = qemu_aer.QTestClient(socket_path)
    try:
        pciexbar = qemu_aer.legacy_config_read32(
            client, 0, 0, 0, qemu_aer.Q35_PCIEXBAR_OFFSET
        )
        expected_pciexbar = qemu_aer.MCFG_BASE | qemu_aer.Q35_PCIEXBAR_ENABLE
        if pciexbar != expected_pciexbar:
            raise BlockedEnvironment(
                "live Q35 ECAM base does not match the read-only lab accessor: "
                f"observed=0x{pciexbar:08x}, expected=0x{expected_pciexbar:08x}"
            )
        endpoint = qemu_aer.discover_device(
            client,
            bus=bdf_tuple(endpoint_bdf)[0],
            device=bdf_tuple(endpoint_bdf)[1],
            function=bdf_tuple(endpoint_bdf)[2],
            expected_type=qemu_aer.PCI_EXP_TYPE_ENDPOINT,
        )
        root = qemu_aer.discover_device(
            client,
            bus=bdf_tuple(root_bdf)[0],
            device=bdf_tuple(root_bdf)[1],
            function=bdf_tuple(root_bdf)[2],
            expected_type=qemu_aer.PCI_EXP_TYPE_ROOT_PORT,
        )
        endpoint_state = qemu_aer.endpoint_snapshot(client, endpoint)
        root_state = qemu_aer.root_snapshot(client, root)
        eb, ed, ef = endpoint["bus"], endpoint["device"], endpoint["function"]
        rb, rd, rf = root["bus"], root["device"], root["function"]
        eaer = endpoint["aerCapabilityOffset"]
        raer = root["aerCapabilityOffset"]
        endpoint_state.update(
            {
                "aerHeader": qemu_aer.config_read32(client, eb, ed, ef, eaer),
                "uncorrectableErrorStatus": qemu_aer.config_read32(
                    client, eb, ed, ef, eaer + 0x04
                ),
                "uncorrectableErrorMask": qemu_aer.config_read32(
                    client, eb, ed, ef, eaer + 0x08
                ),
            }
        )
        root_state.update(
            {
                "aerHeader": qemu_aer.config_read32(client, rb, rd, rf, raer),
                "uncorrectableErrorStatus": qemu_aer.config_read32(
                    client, rb, rd, rf, raer + 0x04
                ),
                "correctableErrorStatus": qemu_aer.config_read32(
                    client, rb, rd, rf, raer + qemu_aer.PCI_ERR_COR_STATUS
                ),
                "correctableErrorMask": qemu_aer.config_read32(
                    client, rb, rd, rf, raer + qemu_aer.PCI_ERR_COR_MASK
                ),
                "primaryBus": qemu_aer.config_read8(
                    client, rb, rd, rf, qemu_aer.PCI_PRIMARY_BUS
                ),
                "secondaryBus": qemu_aer.config_read8(
                    client, rb, rd, rf, qemu_aer.PCI_PRIMARY_BUS + 1
                ),
                "subordinateBus": qemu_aer.config_read8(
                    client, rb, rd, rf, qemu_aer.PCI_PRIMARY_BUS + 2
                ),
            }
        )
        return {
            "q35Pciexbar": pciexbar,
            "endpoint": endpoint,
            "endpointState": endpoint_state,
            "root": root,
            "rootState": root_state,
        }
    finally:
        client.close()


def clear_outer_qemu_aer_baseline(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    policy: str,
) -> dict[str, Any]:
    paused = False
    try:
        stop_output = hmp_command(monitor, "stop")
        paused = True
        status_output = hmp_command(monitor, "info status")
        if "paused" not in status_output.lower():
            raise InconclusiveObservation(
                f"QEMU did not confirm paused state before QTest writes: {status_output!r}"
            )
        before = outer_qemu_aer_snapshot(socket_path, endpoint_bdf, root_bdf)
        client = qemu_aer.QTestClient(socket_path)
        try:
            endpoint = before["endpoint"]
            root = before["root"]
            eb, ed, ef = endpoint["bus"], endpoint["device"], endpoint["function"]
            rb, rd, rf = root["bus"], root["device"], root["function"]
            epcie = endpoint["pcieCapabilityOffset"]
            eaer = endpoint["aerCapabilityOffset"]
            rpcie = root["pcieCapabilityOffset"]
            raer = root["aerCapabilityOffset"]
            endpoint_control = qemu_aer.config_read16(
                client, eb, ed, ef, epcie + 0x08
            )
            qemu_aer.config_write32(
                client,
                eb,
                ed,
                ef,
                epcie + 0x08,
                endpoint_control | (0x000F << 16),
            )
            qemu_aer.config_write32(client, eb, ed, ef, eaer + 0x10, 0xFFFFFFFF)
            qemu_aer.config_write32(
                client,
                eb,
                ed,
                ef,
                eaer + qemu_aer.PCI_ERR_UNCOR_STATUS,
                0xFFFFFFFF,
            )
            root_control = qemu_aer.config_read16(
                client, rb, rd, rf, rpcie + 0x08
            )
            qemu_aer.config_write32(
                client,
                rb,
                rd,
                rf,
                rpcie + 0x08,
                root_control | (0x000F << 16),
            )
            qemu_aer.config_write32(client, rb, rd, rf, raer + 0x10, 0xFFFFFFFF)
            qemu_aer.config_write32(
                client,
                rb,
                rd,
                rf,
                raer + qemu_aer.PCI_ERR_UNCOR_STATUS,
                0xFFFFFFFF,
            )
            qemu_aer.config_write32(
                client,
                rb,
                rd,
                rf,
                raer + qemu_aer.PCI_ERR_ROOT_STATUS,
                qemu_aer.PCI_ERR_ROOT_STATUS_W1C,
            )
        finally:
            client.close()
        after = outer_qemu_aer_snapshot(socket_path, endpoint_bdf, root_bdf)
        checks = {
            "endpointCorrectableStatusClean": (
                after["endpointState"]["correctableErrorStatus"] == 0
            ),
            "endpointDeviceStatusClean": (
                not (
                    after["endpointState"]["deviceStatus"]
                    & qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                )
            ),
            "endpointDeviceStatusHasOnlyStickyCed": not bool(
                after["endpointState"]["deviceStatus"]
                & (
                    qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                    ^ qemu_aer.PCI_EXP_DEVSTA_CED
                )
            ),
            "endpointUncorrectableStatusClean": (
                after["endpointState"]["uncorrectableErrorStatus"] == 0
            ),
            "rootCorrectableStatusClean": (
                after["rootState"]["correctableErrorStatus"] == 0
            ),
            "rootUncorrectableStatusClean": (
                after["rootState"]["uncorrectableErrorStatus"] == 0
            ),
            "rootDeviceStatusClean": not bool(
                after["rootState"]["deviceStatus"]
                & qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
            ),
            "rootErrorStatusClean": after["rootState"]["rootErrorStatus"] == 0,
            "rootErrorSourceClean": (
                after["rootState"]["errorSourceIdentification"] == 0
            ),
            "rootIsUpstreamOfEndpoint": (
                after["rootState"]["secondaryBus"]
                <= after["endpoint"]["bus"]
                <= after["rootState"]["subordinateBus"]
            ),
        }
        status_routing_clean = all(
            checks[name]
            for name in (
                "endpointCorrectableStatusClean",
                "endpointDeviceStatusHasOnlyStickyCed",
                "endpointUncorrectableStatusClean",
                "rootCorrectableStatusClean",
                "rootUncorrectableStatusClean",
                "rootDeviceStatusClean",
                "rootErrorStatusClean",
                "rootErrorSourceClean",
                "rootIsUpstreamOfEndpoint",
            )
        )
        clean = status_routing_clean and (
            policy == "status-routing" or checks["endpointDeviceStatusClean"]
        )
        if not clean:
            raise InconclusiveObservation(
                "QTest W1C baseline clear did not satisfy "
                f"policy={policy}: checks={checks}; after={after}"
            )
        return {
            "hmpStop": stop_output,
            "hmpStatusAfterStop": status_output,
            "before": before,
            "after": after,
            "policy": policy,
            "checks": checks,
            "stickyDeviceStatusAccepted": (
                policy == "status-routing"
                and not checks["endpointDeviceStatusClean"]
            ),
            "clean": clean,
        }
    finally:
        if paused:
            hmp_command(monitor, "cont")


def guest_phase_block(text: str, phase: str) -> str | None:
    if phase == "before-injection":
        end_marker = "=== AER injection window open ==="
    elif phase == "after-injection":
        end_marker = "=== AER guest probe done ==="
    else:
        raise ValueError(f"unknown guest phase: {phase}")
    start_marker = f"=== AER state: {phase} ==="
    start = text.find(start_marker)
    if start < 0:
        return None
    end = text.find(end_marker, start)
    return text[start : end if end >= 0 else len(text)]


def parse_hexdump(block: str, dump_base: int = 0xE0) -> dict[int, int]:
    values: dict[int, int] = {}
    for line in block.splitlines():
        match = re.match(r"^([0-9a-fA-F]{8})\s+(.+?)(?:\s+\|.*)?$", line)
        if not match:
            continue
        relative = int(match.group(1), 16)
        octets = re.findall(r"\b[0-9a-fA-F]{2}\b", match.group(2))
        for index, octet in enumerate(octets[:16]):
            values[dump_base + relative + index] = int(octet, 16)
    return values


def parse_guest_targets(text: str, phase: str, aer_offset: int) -> list[dict[str, Any]]:
    phase_text = guest_phase_block(text, phase)
    if phase_text is None:
        return []
    header = re.compile(
        r"^--- target (\S+) vendor=(0x[0-9a-fA-F]+) device=(0x[0-9a-fA-F]+) ---$",
        re.MULTILINE,
    )
    matches = list(header.finditer(phase_text))
    targets: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(phase_text)
        block = phase_text[match.end() : end]
        values = parse_hexdump(block)
        targets.append(
            {
                "bdf": match.group(1),
                "vendorId": int(match.group(2), 16),
                "deviceId": int(match.group(3), 16),
                "aerHeader": read_le(values, aer_offset, 4),
                "uncorrectableStatus": read_le(values, aer_offset + 0x04, 4),
                "correctableStatus": read_le(values, aer_offset + 0x10, 4),
            }
        )
    return targets


def guest_aer_event_lines(text: str) -> list[str]:
    event = re.compile(
        r"PCIe Bus Error|severity=(?:Corrected|Uncorrected|Fatal)|aer_dev_(?:correctable|nonfatal|fatal)",
        re.IGNORECASE,
    )
    return [line for line in text.splitlines() if event.search(line)]


def new_lines(before: str, after: str) -> list[str]:
    """Return an order-preserving multiset difference for tail snapshots."""
    remaining = collections.Counter(before.splitlines())
    result = []
    for line in after.splitlines():
        if remaining[line]:
            remaining[line] -= 1
        else:
            result.append(line)
    return result


def aer_log_lines(lines: Iterable[str]) -> list[str]:
    pattern = re.compile(
        r"AER|PCIe Bus Error|Corrected|Receiver Error|Bad TLP|Bad DLLP|Replay",
        re.IGNORECASE,
    )
    return [
        line
        for line in lines
        if pattern.search(line)
        and "PCI-AER-MATRIX" not in line
        and not ("sshd-session" in line and "AER" in line)
    ]


@dataclass
class ApiSession:
    host_address: str
    user: str
    password: str

    def __post_init__(self) -> None:
        saved: dict[str, str | None] = {}
        names = (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        )
        for name in names:
            saved[name] = os.environ.get(name)
        try:
            for name in names[:6]:
                os.environ.pop(name, None)
            os.environ["NO_PROXY"] = self.host_address
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.service_instance = SmartConnect(
                host=self.host_address,
                user=self.user,
                pwd=self.password,
                sslContext=context,
            )
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.content = self.service_instance.RetrieveContent()
        hosts = self._inventory(vim.HostSystem)
        if len(hosts) != 1:
            Disconnect(self.service_instance)
            raise BlockedEnvironment(
                f"direct ESXi endpoint exposed {len(hosts)} hosts; expected exactly one"
            )
        self.host = hosts[0]

    def close(self) -> None:
        Disconnect(self.service_instance)

    def _inventory(self, object_type: type) -> list[Any]:
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [object_type], True
        )
        try:
            return list(view.view)
        finally:
            view.Destroy()

    @property
    def system_uuid(self) -> str:
        self.host.Reload()
        return self.host.hardware.systemInfo.uuid

    def active_passthrough_users(self, bdf: str) -> list[dict[str, Any]]:
        target = canonical_bdf(bdf)
        if target is None:
            raise ValueError(f"invalid BDF: {bdf}")
        users: list[dict[str, Any]] = []
        for vm in self._inventory(vim.VirtualMachine):
            try:
                if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
                    continue
                config = vm.config
                if config is None or config.hardware is None:
                    continue
                for device in config.hardware.device:
                    if not isinstance(device, vim.vm.device.VirtualPCIPassthrough):
                        continue
                    backing = device.backing
                    identifiers = (
                        getattr(backing, "id", None),
                        getattr(backing, "assignedId", None),
                    )
                    if target not in {canonical_bdf(item) for item in identifiers if item}:
                        continue
                    users.append(
                        {
                            "vm": vm.name,
                            "vmMoId": vm._moId,
                            "deviceKey": device.key,
                            "label": device.deviceInfo.label if device.deviceInfo else None,
                            "backingType": type(backing).__name__,
                            "backingIds": [item for item in identifiers if item],
                        }
                    )
            except vmodl.fault.ManagedObjectNotFound:
                # ContainerView can race with deletion of an unrelated VM.  A
                # deleted managed object cannot still own a powered-on
                # passthrough device; ignore only this precise SOAP fault.
                continue
            except Exception as error:  # One unreadable VM must fail evidence closed.
                users.append(
                    {
                        "vmMoId": getattr(vm, "_moId", None),
                        "inspectionError": f"{type(error).__name__}: {error}",
                    }
                )
        return users


class EsxiScp:
    def __init__(self, host: str, user: str, password: str) -> None:
        self.host = host
        self.user = user
        self.password = password

    def _run(self, operands: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["SSHPASS"] = self.password
        command = [
            "sshpass",
            "-e",
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=12",
            *operands,
        ]
        return subprocess.run(
            command,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def to_esxi(self, source: Path, destination: str) -> None:
        result = self._run([str(source), f"{self.user}@{self.host}:{destination}"])
        if result.returncode != 0:
            raise BlockedEnvironment(f"SCP upload failed: {result.stderr.strip()}")

    def from_esxi(self, source: str, destination: Path, *, required: bool) -> bool:
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = self._run([f"{self.user}@{self.host}:{source}", str(destination)])
        if result.returncode == 0:
            return True
        if required:
            raise InconclusiveObservation(
                f"required ESXi artifact {source!r} could not be copied: "
                f"{result.stderr.strip()}"
            )
        return False


def run_remote_capture(
    ssh: EsxiSsh,
    command: str,
    stdout_path: Path,
    *,
    timeout: int = 180,
) -> dict[str, Any]:
    result = ssh.run(command, check=False, timeout=timeout)
    save_text(stdout_path, result.stdout)
    if result.stderr:
        save_text(stdout_path.with_suffix(stdout_path.suffix + ".stderr"), result.stderr)
    return {
        "command": command,
        "returnCode": result.returncode,
        "stdout": stdout_path.name,
        "stderr": (
            stdout_path.with_suffix(stdout_path.suffix + ".stderr").name
            if result.stderr
            else None
        ),
    }


COLLECTOR_COMMANDS = (
    ("lspci-ext.txt", "lspci -e"),
    ("pci.txt", "localcli hardware pci list"),
    ("pcipassthru.txt", "localcli hardware pci pcipassthru list"),
    (
        "kernel-enable-pcie-errors.txt",
        "localcli system settings kernel list -o enablePCIErrors",
    ),
    (
        "kernel-passthru-reporting.txt",
        "localcli system settings kernel list -o pcipDisablePciErrReporting",
    ),
    ("vm-process.txt", "esxcli vm process list"),
    ("uptime.txt", "uptime"),
    ("vmkernel-tail.log", "tail -n {log_lines} /var/run/log/vmkernel.log"),
    ("vobd-tail.log", "tail -n {log_lines} /var/run/log/vobd.log"),
    ("syslog-tail.log", "tail -n {log_lines} /var/run/log/syslog.log"),
)


def collect_phase(
    case_dir: Path,
    phase: str,
    ssh: EsxiSsh,
    api: ApiSession,
    bdf: str,
    root_bdf: str,
    monitor: Path,
    qtest_socket: Path | None,
    outer_endpoint_bdf: str,
    outer_root_bdf: str,
    log_lines: int,
) -> dict[str, Any]:
    phase_dir = case_dir / phase
    phase_dir.mkdir(parents=True, exist_ok=False)
    record: dict[str, Any] = {
        "phase": phase,
        "startedAt": utc_now(),
        "commands": {},
    }
    # Capture the outer register surface first.  ESXi commands are deliberately
    # collected afterwards because a status bit may be serviced or W1C-cleared
    # while several SSH round trips are in progress.  A later second snapshot
    # is retained to make that observation window explicit.
    if qtest_socket is not None:
        try:
            record["outerQemuAer"] = outer_qemu_aer_snapshot(
                qtest_socket, outer_endpoint_bdf, outer_root_bdf
            )
            record["outerQemuAerCapturedAt"] = utc_now()
        except Exception as error:
            record["outerQemuAerError"] = f"{type(error).__name__}: {error}"
    for filename, template in COLLECTOR_COMMANDS:
        command = template.format(log_lines=log_lines)
        record["commands"][filename] = run_remote_capture(
            ssh, command, phase_dir / filename
        )
    try:
        qemu_pci = hmp_command(monitor, "info pci")
        save_text(phase_dir / "qemu-info-pci.txt", qemu_pci)
        record["qemuInfoPci"] = "qemu-info-pci.txt"
    except Exception as error:
        record["qemuInfoPciError"] = f"{type(error).__name__}: {error}"

    pci_text = (phase_dir / "pci.txt").read_text(encoding="utf-8", errors="replace")
    lspci_text = (phase_dir / "lspci-ext.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    target = extract_esxcli_device(pci_text, bdf)
    config = extract_lspci_bytes(lspci_text, bdf)
    root_config = extract_lspci_bytes(lspci_text, root_bdf)
    record["target"] = target
    record["aer"] = aer_snapshot(config)
    record["rootAer"] = aer_snapshot(root_config)
    if qtest_socket is not None:
        try:
            record["outerQemuAerPostRemote"] = outer_qemu_aer_snapshot(
                qtest_socket, outer_endpoint_bdf, outer_root_bdf
            )
        except Exception as error:
            record["outerQemuAerPostRemoteError"] = (
                f"{type(error).__name__}: {error}"
            )
    try:
        record["activePassthroughUsers"] = api.active_passthrough_users(bdf)
    except Exception as error:
        record["activePassthroughUsersError"] = f"{type(error).__name__}: {error}"
    record["finishedAt"] = utc_now()
    save_json(phase_dir / "phase.json", record)
    return record


def phase_log_text(case_dir: Path, phase: str, name: str) -> str:
    path = case_dir / phase / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def target_ids(target: dict[str, str]) -> tuple[int, int]:
    try:
        return int(target["Vendor ID"], 16), int(target["Device ID"], 16)
    except (KeyError, ValueError) as error:
        raise BlockedEnvironment("target PCI inventory lacks usable Vendor/Device IDs") from error


def create_single_passthrough_vmx(
    base_vmx: Path,
    output: Path,
    vm_name: str,
    serial_name: str,
    iso_path: str,
    bdf: str,
    vendor_id: int,
    device_id: int,
    system_uuid: str,
) -> None:
    lines = base_vmx.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        if re.match(r"^pciPassthru\d+\.", line):
            continue
        if re.match(r"^displayName\s*=", line):
            rewritten.append(f'displayName = "{vm_name}"')
        elif re.match(r"^serial0\.fileName\s*=", line):
            rewritten.append(f'serial0.fileName = "{serial_name}"')
        elif re.match(r"^ide1:0\.fileName\s*=", line):
            rewritten.append(f'ide1:0.fileName = "{iso_path}"')
        else:
            rewritten.append(line)
    rewritten.extend(
        [
            f'pciPassthru0.id = "{vmx_pci_id(bdf)}"',
            f'pciPassthru0.deviceId = "0x{device_id:04x}"',
            f'pciPassthru0.vendorId = "0x{vendor_id:04x}"',
            f'pciPassthru0.systemId = "{system_uuid}"',
            'pciPassthru0.present = "TRUE"',
        ]
    )
    output.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


@dataclass
class ActiveVm:
    ssh: EsxiSsh
    transfer: EsxiScp
    api: ApiSession
    case_dir: Path
    run_id: str
    case_id: str
    datastore: str
    remote_iso: str
    base_vmx: Path
    bdf: str
    vendor_id: int
    device_id: int
    marker_timeout: int

    vmid: str | None = None
    remote_dir: str | None = None
    serial_name: str | None = None
    vm_name: str | None = None

    def start(self) -> dict[str, Any]:
        self.vm_name = validate_safe_id(f"aer-{self.run_id}-{self.case_id}", "VM name")
        self.serial_name = f"guest-serial-{self.case_id}.log"
        self.remote_dir = (
            f"/vmfs/volumes/{self.datastore}/directpath-cases/"
            f"aer-correctable/{self.run_id}/{self.case_id}"
        )
        remote_vmx = f"{self.remote_dir}/{self.case_id}.vmx"
        local_vmx = self.case_dir / "active-vm-input.vmx"
        iso_probe = self.ssh.run(
            f"test -f {shlex.quote(self.remote_iso)}", check=False
        )
        if iso_probe.returncode != 0:
            raise BlockedEnvironment(
                f"AER guest probe ISO is absent: {self.remote_iso}"
            )
        create_single_passthrough_vmx(
            self.base_vmx,
            local_vmx,
            self.vm_name,
            self.serial_name,
            self.remote_iso,
            self.bdf,
            self.vendor_id,
            self.device_id,
            self.api.system_uuid,
        )
        quoted_dir = shlex.quote(self.remote_dir)
        quoted_vmx = shlex.quote(remote_vmx)
        prepare = self.ssh.run(
            f"mkdir -p {quoted_dir} && test ! -e {quoted_vmx}",
            check=False,
        )
        if prepare.returncode != 0:
            raise BlockedEnvironment(
                f"remote evidence VM path already exists or cannot be created: {self.remote_dir}"
            )
        self.transfer.to_esxi(local_vmx, remote_vmx)
        registration = self.ssh.run(f"vim-cmd solo/registervm {quoted_vmx}")
        candidates = [line.strip() for line in registration.stdout.splitlines()]
        candidates = [line for line in candidates if re.fullmatch(r"\d+", line)]
        if not candidates:
            raise BlockedEnvironment(
                f"could not parse VMID from register output: {registration.stdout!r}"
            )
        self.vmid = candidates[-1]
        power = self.ssh.run(f"vim-cmd vmsvc/power.on {self.vmid}", check=False, timeout=180)
        save_text(self.case_dir / "active-vm-power-on.txt", power.stdout + power.stderr)
        if power.returncode != 0:
            raise BlockedEnvironment(
                f"active DirectPath VM failed to power on: {power.stdout} {power.stderr}"
            )

        # ``vim-cmd vmsvc/power.on`` commonly returns ``Powering on VM:``
        # even when the asynchronous operation succeeds.  Treat the API/VM
        # state as authoritative instead of matching that progress string.
        power_deadline = time.monotonic() + min(self.marker_timeout, 180)
        last_power_state = ""
        while time.monotonic() < power_deadline:
            state = self.ssh.run(
                f"vim-cmd vmsvc/power.getstate {self.vmid}",
                check=False,
                timeout=30,
            )
            last_power_state = state.stdout + state.stderr
            if state.returncode == 0 and "Powered on" in state.stdout:
                break
            time.sleep(2)
        else:
            raise BlockedEnvironment(
                "active DirectPath VM did not reach powered-on state: "
                f"{last_power_state.strip()}"
            )

        serial_path = f"{self.remote_dir}/{self.serial_name}"
        deadline = time.monotonic() + self.marker_timeout
        while time.monotonic() < deadline:
            probe = self.ssh.run(
                f"grep -F '=== AER injection window open ===' "
                f"{shlex.quote(serial_path)} 2>/dev/null",
                check=False,
                timeout=30,
            )
            if probe.returncode == 0 and "injection window open" in probe.stdout:
                break
            time.sleep(2)
        else:
            raise BlockedEnvironment(
                "active DirectPath guest did not open the AER injection window"
            )

        users = self.api.active_passthrough_users(self.bdf)
        if not any(item.get("vm") == self.vm_name for item in users):
            raise BlockedEnvironment(
                "API did not correlate the runner-created powered-on VM with the target BDF"
            )
        return {
            "vmName": self.vm_name,
            "vmid": self.vmid,
            "remoteDirectory": self.remote_dir,
            "remoteVmx": remote_vmx,
            "serial": serial_path,
            "activeUsers": users,
        }

    def copy_guest_serial(self, destination: Path, *, required: bool) -> bool:
        if not self.remote_dir or not self.serial_name:
            return False
        return self.transfer.from_esxi(
            f"{self.remote_dir}/{self.serial_name}", destination, required=required
        )

    def wait_complete(self, timeout: int) -> None:
        if not self.remote_dir or not self.serial_name:
            raise InconclusiveObservation("active VM serial path is unavailable")
        serial_path = f"{self.remote_dir}/{self.serial_name}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            probe = self.ssh.run(
                f"grep -F '=== AER guest probe done ===' "
                f"{shlex.quote(serial_path)} 2>/dev/null",
                check=False,
                timeout=30,
            )
            if probe.returncode == 0 and "guest probe done" in probe.stdout:
                return
            time.sleep(2)
        raise InconclusiveObservation(
            "active DirectPath guest did not produce its post-injection marker"
        )

    def cleanup(self) -> dict[str, Any]:
        result: dict[str, Any] = {"startedAt": utc_now(), "actions": []}
        if self.remote_dir:
            for remote_name, local_name in (
                (self.serial_name, "guest-serial-final.log"),
                ("vmware.log", "vmware.log"),
                (f"{self.case_id}.vmx", "effective.vmx"),
            ):
                if remote_name:
                    copied = self.transfer.from_esxi(
                        f"{self.remote_dir}/{remote_name}",
                        self.case_dir / local_name,
                        required=False,
                    )
                    result["actions"].append(
                        {"copy": remote_name, "destination": local_name, "success": copied}
                    )
        if self.vmid:
            state = self.ssh.run(
                f"vim-cmd vmsvc/power.getstate {self.vmid}", check=False
            )
            if "Powered on" in state.stdout:
                power = self.ssh.run(
                    f"vim-cmd vmsvc/power.off {self.vmid}", check=False, timeout=180
                )
                result["actions"].append(
                    {"powerOffReturnCode": power.returncode, "output": power.stdout.strip()}
                )
            unregister = self.ssh.run(
                f"vim-cmd vmsvc/unregister {self.vmid}", check=False
            )
            result["actions"].append(
                {"unregisterReturnCode": unregister.returncode}
            )
        try:
            deadline = time.monotonic() + 30
            remaining: list[dict[str, Any]] = []
            while time.monotonic() < deadline:
                remaining = self.api.active_passthrough_users(self.bdf)
                if not remaining:
                    break
                time.sleep(1)
            result["remainingActiveUsers"] = remaining
        except Exception as error:
            result["remainingActiveUsersError"] = f"{type(error).__name__}: {error}"
        result["finishedAt"] = utc_now()
        save_json(self.case_dir / "cleanup.json", result)
        return result


def kernel_preconditions(phase_dir: Path) -> dict[str, bool]:
    enable = (phase_dir / "kernel-enable-pcie-errors.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    passthru = (phase_dir / "kernel-passthru-reporting.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    return {
        "enablePCIErrorsRuntimeTrue": bool(
            re.search(r"enablePCIErrors\s+Bool\s+\S+\s+TRUE", enable)
        ),
        "pcipDisablePciErrReportingRuntimeFalse": bool(
            re.search(r"pcipDisablePciErrReporting\s+Bool\s+\S+\s+FALSE", passthru)
        ),
    }


def owner_from_phase(phase: dict[str, Any]) -> str | None:
    target = phase.get("target")
    return target.get("Current Owner") if isinstance(target, dict) else None


def evaluate_observation(
    *,
    owner_state: str,
    mask: int,
    oracle: str,
    before: dict[str, Any],
    injection: dict[str, Any],
    after: dict[str, Any],
    injection_accepted: bool,
    host_responsive: bool,
    guest_text: str | None,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    expected_owner = EXPECTED_CURRENT_OWNER[owner_state]
    safety_checks: list[str] = []
    checks: dict[str, Any] = {
        "injectionUsedCorrectableHmpForm": injection_accepted,
        "hostResponsiveAfterInjection": host_responsive,
        "ownerStable": all(
            owner_from_phase(phase) == expected_owner
            for phase in (before, injection, after)
        ),
    }
    observations: dict[str, Any] = {}
    active_user_timelines = [
        phase.get("activePassthroughUsers") for phase in (before, injection, after)
    ]
    observations["activePassthroughUsersTimeline"] = active_user_timelines
    if all(isinstance(users, list) for users in active_user_timelines):
        active_user_keys = [
            {
                (item.get("vm"), item.get("vmMoId"), item.get("deviceKey"))
                for item in users
                if isinstance(item, dict) and not item.get("inspectionError")
            }
            for users in active_user_timelines
        ]
        no_inspection_errors = all(
            not any(
                isinstance(item, dict) and item.get("inspectionError")
                for item in users
            )
            for users in active_user_timelines
        )
        if owner_state == "PassthruActive":
            checks["activeVmUseStableThroughInjection"] = (
                no_inspection_errors
                and len(active_user_keys[0]) == 1
                and active_user_keys[0] == active_user_keys[1]
            )
            # The probe guest powers itself off immediately after emitting its
            # post-injection marker.  Depending on collection timing, the
            # after phase may still see the same owner or may see the expected
            # release; a different non-empty owner is never acceptable.
            checks["activeVmReleasedOrStillSameAfter"] = (
                no_inspection_errors
                and (
                    active_user_keys[2] == active_user_keys[0]
                    or not active_user_keys[2]
                )
            )
        else:
            checks["noActiveVmUsers"] = no_inspection_errors and all(
                not keys for keys in active_user_keys
            )
    else:
        checks["activeUserEvidenceComplete"] = False
    snapshots = [phase.get("aer") for phase in (before, injection, after)]
    if any(item is None for item in snapshots):
        checks["hostAerSnapshotsComplete"] = False
        return "INCONCLUSIVE", checks, observations
    before_aer, injection_aer, after_aer = snapshots
    assert before_aer is not None and injection_aer is not None and after_aer is not None
    before_ces = before_aer.get("correctableStatus")
    injection_ces = injection_aer.get("correctableStatus")
    after_ces = after_aer.get("correctableStatus")
    ues_values = [item.get("uncorrectableStatus") for item in snapshots]
    observations["host"] = {
        "beforeCorrectableStatus": before_ces,
        "injectionCorrectableStatus": injection_ces,
        "afterCorrectableStatus": after_ces,
        "uncorrectableStatusTimeline": ues_values,
    }
    checks["hostAerSnapshotsComplete"] = all(
        value is not None for value in (before_ces, injection_ces, after_ces, *ues_values)
    )
    if not checks["hostAerSnapshotsComplete"]:
        return "INCONCLUSIVE", checks, observations
    checks["requestedBitClearBefore"] = not bool(int(before_ces) & mask)
    checks["requestedBitObserved"] = bool(
        (int(injection_ces) | int(after_ces)) & mask
    )
    checks["uncorrectableStatusUnchanged"] = len(set(int(value) for value in ues_values)) == 1
    checks["hostUncorrectableStatusRemainsZero"] = all(
        int(value) == 0 for value in ues_values
    )
    safety_checks.append("hostUncorrectableStatusRemainsZero")

    root_present = any("rootAer" in phase for phase in (before, injection, after))
    if root_present:
        root_snapshots = [phase.get("rootAer") for phase in (before, injection, after)]
        observations["esxiRoot"] = root_snapshots
        if all(isinstance(item, dict) for item in root_snapshots):
            root_ces = [int(item["correctableStatus"]) for item in root_snapshots]
            root_ues = [int(item["uncorrectableStatus"]) for item in root_snapshots]
            root_status = [int(item["rootErrorStatus"]) for item in root_snapshots]
            observations["esxiRootTimeline"] = {
                "correctableStatus": root_ces,
                "uncorrectableStatus": root_ues,
                "rootErrorStatus": root_status,
                "rootErrorCommand": [
                    int(item["rootErrorCommand"]) for item in root_snapshots
                ],
                "errorSourceIdentification": [
                    int(item["errorSourceIdentification"]) for item in root_snapshots
                ],
            }
            checks["esxiRootUncorrectableStatusUnchanged"] = len(set(root_ues)) == 1
            checks["esxiRootUncorrectableStatusRemainsZero"] = all(
                value == 0 for value in root_ues
            )
            checks["esxiRootHasNoUncorrectableReception"] = all(
                not (value & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK)
                for value in root_status
            )
            safety_checks.extend(
                (
                    "esxiRootUncorrectableStatusRemainsZero",
                    "esxiRootHasNoUncorrectableReception",
                )
            )
            if oracle == "esxi803":
                checks["esxiRootCorrectableSurfaceUnchanged"] = (
                    len(set(root_ces)) == 1 and len(set(root_status)) == 1
                )
        else:
            checks["esxiRootAerSnapshotsComplete"] = False

    outer_present = any(
        "outerQemuAer" in phase or "outerQemuAerError" in phase
        for phase in (before, injection, after)
    )
    if outer_present:
        outer_snapshots = [
            phase.get("outerQemuAer") for phase in (before, injection, after)
        ]
        checks["outerQemuAerSnapshotsComplete"] = all(
            isinstance(item, dict) for item in outer_snapshots
        )
        observations["outerQemuAerTimeline"] = outer_snapshots
        if checks["outerQemuAerSnapshotsComplete"]:
            outer_endpoint = [item["endpointState"] for item in outer_snapshots]
            outer_root = [item["rootState"] for item in outer_snapshots]
            checks["outerRequestedBitClearBefore"] = not bool(
                int(outer_endpoint[0]["correctableErrorStatus"]) & mask
            )
            checks["outerRequestedBitObserved"] = bool(
                (
                    int(outer_endpoint[1]["correctableErrorStatus"])
                    | int(outer_endpoint[2]["correctableErrorStatus"])
                )
                & mask
            )
            checks["outerUncorrectableStatusUnchanged"] = len(
                {
                    int(item["uncorrectableErrorStatus"])
                    for item in outer_endpoint
                }
            ) == 1
            checks["outerEndpointUncorrectableStatusRemainsZero"] = all(
                int(item["uncorrectableErrorStatus"]) == 0
                for item in outer_endpoint
            )
            checks["outerEndpointDeviceStatusCorrectableOnly"] = all(
                not (
                    int(item["deviceStatus"])
                    & (
                        qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                        ^ qemu_aer.PCI_EXP_DEVSTA_CED
                    )
                )
                for item in outer_endpoint
            )
            checks["outerRootUncorrectableStatusRemainsZero"] = all(
                int(item["uncorrectableErrorStatus"]) == 0
                for item in outer_root
            )
            checks["outerRootDeviceStatusRemainsZero"] = all(
                not (
                    int(item["deviceStatus"])
                    & qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                )
                for item in outer_root
            )
            checks["outerRootHasNoUncorrectableReception"] = all(
                not (
                    int(item["rootErrorStatus"])
                    & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK
                )
                for item in outer_root
            )
            checks["outerUncorrectableSourceRemainsZero"] = all(
                not (int(item["errorSourceIdentification"]) & 0xFFFF0000)
                for item in outer_root
            )
            checks["outerRootIsUpstreamOfEndpoint"] = all(
                int(item["rootState"]["secondaryBus"])
                <= int(item["endpoint"]["bus"])
                <= int(item["rootState"]["subordinateBus"])
                for item in outer_snapshots
            )
            safety_checks.extend(
                (
                    "outerEndpointUncorrectableStatusRemainsZero",
                    "outerEndpointDeviceStatusCorrectableOnly",
                    "outerRootUncorrectableStatusRemainsZero",
                    "outerRootDeviceStatusRemainsZero",
                    "outerRootHasNoUncorrectableReception",
                    "outerUncorrectableSourceRemainsZero",
                )
            )
            first_endpoint = outer_endpoint[0]
            first_root = outer_root[0]
            root_received = any(
                int(item["rootErrorStatus"]) & qemu_aer.PCI_ERR_ROOT_COR_RCV
                for item in outer_root[1:]
            )
            source_matches = any(
                (
                    int(item["errorSourceIdentification"]) & 0xFFFF
                )
                == int(outer_snapshots[0]["endpoint"]["requesterId"])
                for item in outer_root[1:]
            )
            endpoint_cere = bool(
                int(first_endpoint["deviceControl"])
                & qemu_aer.PCI_EXP_DEVCTL_CERE
            )
            requested_bit_masked = bool(
                int(first_endpoint["correctableErrorMask"]) & mask
            )
            if not endpoint_cere:
                routing_conclusion = "NOT_TESTABLE_ENDPOINT_CERE_DISABLED"
            elif requested_bit_masked:
                routing_conclusion = "BLOCKED_BY_EFFECTIVE_ENDPOINT_MASK"
            elif root_received and source_matches:
                routing_conclusion = "ROOT_RECEPTION_OBSERVED"
            else:
                routing_conclusion = "NOT_OBSERVED_WITHIN_SAMPLING_WINDOW"
            observations["messageRouting"] = {
                "endpointCereEnabled": endpoint_cere,
                "requestedBitMasked": requested_bit_masked,
                "rootBridgeSerrEnabled": bool(
                    int(first_root["bridgeControl"])
                    & qemu_aer.PCI_BRIDGE_CTL_SERR
                ),
                "rootCereEnabled": bool(
                    int(first_root["deviceControl"])
                    & qemu_aer.PCI_EXP_DEVCTL_CERE
                ),
                "rootCorrectableCommandEnabled": bool(
                    int(first_root["rootErrorCommand"])
                    & qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
                ),
                "rootReceptionObserved": root_received,
                "correctableSourceMatches": source_matches,
                "conclusion": routing_conclusion,
            }
            if oracle == "esxi803":
                checks["outerRootCorrectableSurfaceUnchanged"] = (
                    len(
                        {
                            int(item["correctableErrorStatus"])
                            for item in outer_root
                        }
                    )
                    == 1
                    and len(
                        {int(item["rootErrorStatus"]) for item in outer_root}
                    )
                    == 1
                )

    if owner_state == "PassthruActive":
        if guest_text is None:
            checks["guestPairedEvidenceComplete"] = False
            return "INCONCLUSIVE", checks, observations
        aer_offset = int(before_aer["offset"])
        vendor_id = int(before["target"]["Vendor ID"], 16)
        device_id = int(before["target"]["Device ID"], 16)
        before_targets = [
            item
            for item in parse_guest_targets(guest_text, "before-injection", aer_offset)
            if item["vendorId"] == vendor_id and item["deviceId"] == device_id
        ]
        after_targets = [
            item
            for item in parse_guest_targets(guest_text, "after-injection", aer_offset)
            if item["vendorId"] == vendor_id and item["deviceId"] == device_id
        ]
        observations["guest"] = {
            "beforeCandidates": before_targets,
            "afterCandidates": after_targets,
            "aerEventLines": guest_aer_event_lines(guest_text),
        }
        checks["guestPairedEvidenceComplete"] = (
            len(before_targets) == 1 and len(after_targets) == 1
        )
        if not checks["guestPairedEvidenceComplete"]:
            return "INCONCLUSIVE", checks, observations
        guest_before = before_targets[0]
        guest_after = after_targets[0]
        checks["guestUncorrectableStatusUnchanged"] = (
            guest_before["uncorrectableStatus"] is not None
            and guest_before["uncorrectableStatus"]
            == guest_after["uncorrectableStatus"]
        )
        checks["guestUncorrectableStatusRemainsZero"] = (
            guest_before["uncorrectableStatus"] == 0
            and guest_after["uncorrectableStatus"] == 0
        )
        safety_checks.append("guestUncorrectableStatusRemainsZero")
        if oracle == "esxi803":
            checks["guestRequestedBitClearBefore"] = (
                guest_before["correctableStatus"] is not None
                and not bool(int(guest_before["correctableStatus"]) & mask)
            )
            checks["guestRequestedBitObservedAfter"] = (
                guest_after["correctableStatus"] is not None
                and bool(int(guest_after["correctableStatus"]) & mask)
            )
            checks["guestAerHeaderHidden"] = (
                guest_before["aerHeader"] == 0 and guest_after["aerHeader"] == 0
            )
            checks["guestNativeAerEventSuppressed"] = not observations["guest"][
                "aerEventLines"
            ]

    if not checks["requestedBitClearBefore"]:
        return "INCONCLUSIVE", checks, observations
    failed_safety = [name for name in safety_checks if checks.get(name) is not True]
    if failed_safety:
        observations["safetyViolationChecks"] = failed_safety
        return "FAIL_SAFETY", checks, observations
    if not injection_accepted or not host_responsive or not checks["ownerStable"]:
        return "FAIL", checks, observations
    required = [value for value in checks.values() if isinstance(value, bool)]
    return ("PASS" if all(required) else "FAIL"), checks, observations


def result_log_observations(case_dir: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("vmkernel-tail.log", "vobd-tail.log", "syslog-tail.log"):
        before = phase_log_text(case_dir, "before", name)
        after = phase_log_text(case_dir, "after", name)
        result[name] = aer_log_lines(new_lines(before, after))
    return result


def run_case(
    *,
    args: argparse.Namespace,
    run_id: str,
    bit_name: str,
    mask: int,
    ssh: EsxiSsh,
    transfer: EsxiScp,
    api: ApiSession,
    output_dir: Path,
) -> dict[str, Any]:
    case_id = validate_safe_id(
        f"{args.owner_state.lower()}-{bit_name}", "case id"
    )
    case_dir = output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=False)
    command = build_injection_command(args.qemu_device, mask)
    record: dict[str, Any] = {
        "caseId": case_id,
        "runId": run_id,
        "startedAt": utc_now(),
        "ownerState": args.owner_state,
        "errorClass": "Correctable",
        "errorBit": bit_name,
        "errorMask": f"0x{mask:08x}",
        "qemuDevice": args.qemu_device,
        "esxiBdf": args.esxi_bdf,
        "oracle": args.oracle,
        "claimScope": "ENDPOINT_STATUS_PROJECTION_AND_BOUNDED_OBSERVATION",
        "claimsExcluded": [
            "VMware private implementation",
            "physical-link error generation",
            "ERR_COR delivery unless root reception and source are observed",
            "host service or interrupt handling from log absence",
            "device recovery, reset, health, or quarantine",
        ],
        "injectionAttempted": False,
        "verdict": "BLOCKED_ENV",
    }
    save_json(case_dir / "case.json", record)
    active_vm: ActiveVm | None = None
    injection_accepted = False
    before: dict[str, Any] | None = None
    injection_phase: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    try:
        initial_users = api.active_passthrough_users(args.esxi_bdf)
        if initial_users:
            raise BlockedEnvironment(
                f"target BDF already has powered-on VM users: {initial_users}"
            )
        monitor = Path(args.qemu_monitor)
        if not monitor.exists():
            raise BlockedEnvironment(f"QEMU monitor is not present: {monitor}")
        info_pci = hmp_command(monitor, "info pci")
        save_text(case_dir / "qemu-info-pci-preflight.txt", info_pci)
        if not re.search(rf'id\s+"{re.escape(args.qemu_device)}"', info_pci):
            raise BlockedEnvironment(
                f"QEMU device {args.qemu_device!r} is absent from info pci"
            )

        if args.qtest_clean_baseline:
            if not args.qtest_socket:
                raise BlockedEnvironment(
                    "--qtest-clean-baseline requires --qtest-socket"
                )
            baseline_clear = clear_outer_qemu_aer_baseline(
                monitor,
                Path(args.qtest_socket),
                args.outer_endpoint_bdf,
                args.outer_root_bdf,
                args.qtest_baseline_policy,
            )
            save_json(case_dir / "qtest-baseline-clear.json", baseline_clear)
            record["qtestBaselineClear"] = "qtest-baseline-clear.json"
            time.sleep(1)

        initial_pci = ssh.run("localcli hardware pci list").stdout
        initial_target = extract_esxcli_device(initial_pci, args.esxi_bdf)
        if initial_target is None:
            raise BlockedEnvironment(f"ESXi PCI inventory lacks {args.esxi_bdf}")
        expected_owner = EXPECTED_CURRENT_OWNER[args.owner_state]
        if initial_target.get("Current Owner") != expected_owner:
            raise BlockedEnvironment(
                f"{args.esxi_bdf} Current Owner is "
                f"{initial_target.get('Current Owner')!r}, expected {expected_owner!r}"
            )
        if initial_target.get("Passthru Capable", "").lower() != "true":
            raise BlockedEnvironment(f"{args.esxi_bdf} is not passthru capable")
        vendor_id, device_id = target_ids(initial_target)

        if args.owner_state == "PassthruActive":
            active_vm = ActiveVm(
                ssh=ssh,
                transfer=transfer,
                api=api,
                case_dir=case_dir,
                run_id=run_id,
                case_id=case_id,
                datastore=args.datastore,
                remote_iso=args.remote_iso,
                base_vmx=Path(args.base_vmx),
                bdf=args.esxi_bdf,
                vendor_id=vendor_id,
                device_id=device_id,
                marker_timeout=args.guest_marker_timeout,
            )
            record["activeVm"] = active_vm.start()
            if args.qtest_clean_baseline:
                final_owner_clear = clear_outer_qemu_aer_baseline(
                    monitor,
                    Path(args.qtest_socket),
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                    args.qtest_baseline_policy,
                )
                save_json(
                    case_dir / "qtest-final-owner-baseline-clear.json",
                    final_owner_clear,
                )
                record["qtestFinalOwnerBaselineClear"] = (
                    "qtest-final-owner-baseline-clear.json"
                )
                time.sleep(1)

        marker = validate_safe_id(
            f"{run_id}-{case_id}-BEFORE", "remote log marker"
        )
        ssh.run(f"logger -t PCI-AER-MATRIX {shlex.quote(marker)}", check=False)
        before = collect_phase(
            case_dir,
            "before",
            ssh,
            api,
            args.esxi_bdf,
            args.esxi_root_bdf,
            monitor,
            Path(args.qtest_socket) if args.qtest_socket else None,
            args.outer_endpoint_bdf,
            args.outer_root_bdf,
            args.log_lines,
        )
        record["kernelPreconditions"] = kernel_preconditions(case_dir / "before")
        if not all(record["kernelPreconditions"].values()):
            raise BlockedEnvironment(
                "ESXi AER runtime kernel preconditions are not enabled"
            )
        if before.get("aer") is None:
            raise BlockedEnvironment("target has no parseable AER capability")
        before_ces = before["aer"].get("correctableStatus")
        if before_ces is None:
            raise InconclusiveObservation("baseline Correctable Error Status is unreadable")
        baseline_faults: list[str] = []
        before_ues = before["aer"].get("uncorrectableStatus")
        if before_ues is None or int(before_ues) != 0:
            baseline_faults.append(f"endpoint UES={before_ues!r}")
        before_root_aer = before.get("rootAer")
        if not isinstance(before_root_aer, dict):
            baseline_faults.append("ESXi root AER snapshot missing")
        else:
            for key in ("uncorrectableStatus", "rootErrorStatus"):
                value = before_root_aer.get(key)
                if value is None or int(value) != 0:
                    baseline_faults.append(f"ESXi root {key}={value!r}")
            source = before_root_aer.get("errorSourceIdentification")
            if source is None or int(source) != 0:
                baseline_faults.append(f"ESXi root source={source!r}")
        before_outer = before.get("outerQemuAer")
        if args.qtest_socket:
            if not isinstance(before_outer, dict):
                baseline_faults.append("outer QTest AER snapshot missing")
            else:
                endpoint_state = before_outer["endpointState"]
                root_state = before_outer["rootState"]
                if int(endpoint_state["uncorrectableErrorStatus"]) != 0:
                    baseline_faults.append("outer endpoint UES is non-zero")
                if int(endpoint_state["deviceStatus"]) & (
                    qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                    ^ qemu_aer.PCI_EXP_DEVSTA_CED
                ):
                    baseline_faults.append(
                        "outer endpoint Device Status has a non-CED error bit"
                    )
                if int(root_state["uncorrectableErrorStatus"]) != 0:
                    baseline_faults.append("outer root UES is non-zero")
                if int(root_state["deviceStatus"]) & qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK:
                    baseline_faults.append("outer root Device Status is non-zero")
                if int(root_state["rootErrorStatus"]) != 0:
                    baseline_faults.append("outer Root Error Status is non-zero")
                if int(root_state["errorSourceIdentification"]) != 0:
                    baseline_faults.append("outer Root Error Source is non-zero")
                if not (
                    int(root_state["secondaryBus"])
                    <= int(before_outer["endpoint"]["bus"])
                    <= int(root_state["subordinateBus"])
                ):
                    baseline_faults.append(
                        "declared outer root is not upstream of the endpoint"
                    )
        if baseline_faults:
            raise InconclusiveObservation(
                "Correctable-only baseline is not safety-clean: "
                + "; ".join(baseline_faults)
            )
        if int(before_ces) & mask:
            after = collect_phase(
                case_dir,
                "after",
                ssh,
                api,
                args.esxi_bdf,
                args.esxi_root_bdf,
                monitor,
                Path(args.qtest_socket) if args.qtest_socket else None,
                args.outer_endpoint_bdf,
                args.outer_root_bdf,
                args.log_lines,
            )
            raise InconclusiveObservation(
                f"requested bit 0x{mask:08x} was already set before injection"
            )
        if active_vm:
            active_vm.copy_guest_serial(
                case_dir / "before" / "guest-serial.log", required=True
            )
            guest_before_text = (
                case_dir / "before" / "guest-serial.log"
            ).read_text(encoding="utf-8", errors="replace")
            guest_before_targets = [
                item
                for item in parse_guest_targets(
                    guest_before_text,
                    "before-injection",
                    int(before["aer"]["offset"]),
                )
                if item["vendorId"] == vendor_id and item["deviceId"] == device_id
            ]
            if len(guest_before_targets) != 1:
                raise InconclusiveObservation(
                    "guest pre-injection target identity is not unique"
                )
            guest_before_target = guest_before_targets[0]
            if guest_before_target["uncorrectableStatus"] != 0:
                raise InconclusiveObservation(
                    "guest pre-injection UES is not safety-clean"
                )
            if (
                guest_before_target["correctableStatus"] is None
                or int(guest_before_target["correctableStatus"]) & mask
            ):
                raise InconclusiveObservation(
                    "guest requested Correctable bit is dirty before injection"
                )

        record["injectionAttempted"] = True
        record["injection"] = {
            "startedAt": utc_now(),
            "command": command,
            "safetyClass": "CORRECTABLE_ALLOW_LIST_ONLY",
        }
        save_json(case_dir / "case.json", record)
        injection_output = hmp_command(monitor, command)
        save_text(case_dir / "injection-hmp.txt", injection_output)
        injection_accepted = bool(
            re.search(
                rf"OK id:\s*{re.escape(args.qemu_device)}(?:\s|$)",
                injection_output,
            )
        )
        record["injection"].update(
            {
                "finishedAt": utc_now(),
                "accepted": injection_accepted,
                "output": "injection-hmp.txt",
            }
        )
        if not injection_accepted:
            raise InjectionFailure("QEMU did not acknowledge Correctable AER injection")
        ssh.run(
            f"logger -t PCI-AER-MATRIX "
            f"{shlex.quote(run_id + '-' + case_id + '-INJECTED')}",
            check=False,
        )
        injection_phase = collect_phase(
            case_dir,
            "injection",
            ssh,
            api,
            args.esxi_bdf,
            args.esxi_root_bdf,
            monitor,
            Path(args.qtest_socket) if args.qtest_socket else None,
            args.outer_endpoint_bdf,
            args.outer_root_bdf,
            args.log_lines,
        )
        if active_vm:
            active_vm.copy_guest_serial(
                case_dir / "injection" / "guest-serial.log", required=True
            )

        if active_vm:
            active_vm.wait_complete(args.guest_complete_timeout)
        else:
            time.sleep(args.settle_seconds)
        after = collect_phase(
            case_dir,
            "after",
            ssh,
            api,
            args.esxi_bdf,
            args.esxi_root_bdf,
            monitor,
            Path(args.qtest_socket) if args.qtest_socket else None,
            args.outer_endpoint_bdf,
            args.outer_root_bdf,
            args.log_lines,
        )
        if active_vm:
            active_vm.copy_guest_serial(
                case_dir / "after" / "guest-serial.log", required=True
            )
        alive = ssh.run("printf AER-MATRIX-ALIVE", check=False, timeout=30)
        host_responsive = alive.returncode == 0 and "AER-MATRIX-ALIVE" in alive.stdout
        guest_text = None
        if active_vm:
            guest_text = (case_dir / "after" / "guest-serial.log").read_text(
                encoding="utf-8", errors="replace"
            )
        verdict, checks, observations = evaluate_observation(
            owner_state=args.owner_state,
            mask=mask,
            oracle=args.oracle,
            before=before,
            injection=injection_phase,
            after=after,
            injection_accepted=injection_accepted,
            host_responsive=host_responsive,
            guest_text=guest_text,
        )
        record["verdict"] = verdict
        record["checks"] = checks
        record["observations"] = observations
        record["observations"]["hostLogDelta"] = result_log_observations(case_dir)
        matched_logs = record["observations"]["hostLogDelta"]
        record["observations"]["boundedHostLogObservation"] = {
            "matchingEventObserved": any(matched_logs.values()),
            "conclusion": (
                "MATCH_OBSERVED"
                if any(matched_logs.values())
                else "NOT_OBSERVED_IN_CAPTURED_TAIL_WINDOW"
            ),
            "notEquivalentTo": "proof that ESXi did not service the event",
        }
    except BlockedEnvironment as error:
        record["verdict"] = "BLOCKED_ENV"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    except InconclusiveObservation as error:
        record["verdict"] = "INCONCLUSIVE"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    except InjectionFailure as error:
        record["verdict"] = "FAIL"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    except SafetyViolation as error:
        record["verdict"] = "FAIL_SAFETY"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    except Exception as error:
        record["verdict"] = "INCONCLUSIVE" if record["injectionAttempted"] else "BLOCKED_ENV"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if active_vm is not None:
            try:
                record["cleanup"] = active_vm.cleanup()
                if record["cleanup"].get("remainingActiveUsers"):
                    record["verdict"] = (
                        "FAIL" if record["injectionAttempted"] else "BLOCKED_ENV"
                    )
            except Exception as error:
                record["cleanup"] = {
                    "error": f"{type(error).__name__}: {error}",
                }
                if record["injectionAttempted"]:
                    record["verdict"] = "FAIL"
        record["finishedAt"] = utc_now()
        save_json(case_dir / "result.json", record)
        write_sha256s(case_dir)
    return record


def aggregate_verdict(cases: Iterable[dict[str, Any]]) -> str:
    values = [case["verdict"] for case in cases]
    if any(value == "FAIL_SAFETY" for value in values):
        return "FAIL_SAFETY"
    if any(value == "FAIL" for value in values):
        return "FAIL"
    if any(value == "INCONCLUSIVE" for value in values):
        return "INCONCLUSIVE"
    if any(value == "BLOCKED_ENV" for value in values):
        return "BLOCKED_ENV"
    return "PASS"


def synthetic_lspci(ces: int, ues: int = 0) -> str:
    data = bytearray(0x130)
    data[0x100:0x104] = (0x00020001).to_bytes(4, "little")
    data[0x104:0x108] = ues.to_bytes(4, "little")
    data[0x110:0x114] = ces.to_bytes(4, "little")
    lines = ["0000:01:00.1 Ethernet controller: selftest"]
    for offset in range(0, len(data), 16):
        lines.append(
            f"{offset:02x}: " + " ".join(f"{item:02x}" for item in data[offset : offset + 16])
        )
    return "\n".join(lines) + "\n"


def synthetic_guest(before_ces: int, after_ces: int) -> str:
    def target(ces: int) -> str:
        data = bytearray(0x60)
        data[0x20:0x24] = (0).to_bytes(4, "little")
        data[0x24:0x28] = (0).to_bytes(4, "little")
        data[0x30:0x34] = ces.to_bytes(4, "little")
        lines = [
            "--- target 0000:02:00.0 vendor=0x8086 device=0x10d3 ---",
            "-- config 0xe0-0x13f --",
        ]
        for offset in range(0, len(data), 16):
            chunk = " ".join(f"{item:02x}" for item in data[offset : offset + 16])
            lines.append(f"{offset:08x}  {chunk}  |................|")
        return "\n".join(lines)

    return (
        "=== AER state: before-injection ===\n"
        + target(before_ces)
        + "\n=== AER injection window open ===\n"
        + "=== AER injection window closed ===\n"
        + "=== AER state: after-injection ===\n"
        + target(after_ces)
        + "\n=== AER guest probe done ===\n"
    )


def selftest() -> None:
    assert parse_error_bits("receiver_error,0x40,bad_tlp") == [
        ("receiver_error", 0x1),
        ("bad_tlp", 0x40),
    ]
    for unsafe in ("0x00100000", "nonfatal", "fatal", "0x0"):
        try:
            parse_error_bits(unsafe)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe AER token was accepted: {unsafe}")
    assert parse_error_bits("advisory_nonfatal,0x2000") == [
        ("advisory_nonfatal", 0x2000)
    ]
    command = build_injection_command("test_fn1", 0x1)
    assert command == "pcie_aer_inject_error -c test_fn1 0x00000001"
    try:
        build_injection_command("test_fn1", 0x00100000)
    except ValueError:
        pass
    else:
        raise AssertionError("uncorrectable mask reached the command builder")

    before_text = synthetic_lspci(0)
    after_text = synthetic_lspci(1)
    before = aer_snapshot(extract_lspci_bytes(before_text, "0000:01:00.1"))
    after = aer_snapshot(extract_lspci_bytes(after_text, "0000:01:00.1"))
    assert before and before["correctableStatus"] == 0
    assert after and after["correctableStatus"] == 1
    owner = extract_esxcli_device(
        "0000:01:00.1:\n   Current Owner: VM Passthru\n   Vendor ID: 0x8086\n",
        "0000:01:00.1",
    )
    assert owner and owner["Current Owner"] == "VM Passthru"
    guest = synthetic_guest(0, 1)
    guest_before = parse_guest_targets(guest, "before-injection", 0x100)
    guest_after = parse_guest_targets(guest, "after-injection", 0x100)
    assert guest_before[0]["correctableStatus"] == 0
    assert guest_after[0]["correctableStatus"] == 1
    assert guest_after[0]["aerHeader"] == 0
    active_user = {"vm": "selftest", "vmMoId": "vm-1", "deviceKey": 16000}
    target = {
        "Current Owner": "VM Passthru",
        "Vendor ID": "0x8086",
        "Device ID": "0x10d3",
    }
    phase_before = {
        "target": target,
        "aer": before,
        "activePassthroughUsers": [active_user],
    }
    phase_after = {
        "target": target,
        "aer": after,
        "activePassthroughUsers": [active_user],
    }
    verdict, checks, _ = evaluate_observation(
        owner_state="PassthruActive",
        mask=0x1,
        oracle="esxi803",
        before=phase_before,
        injection=phase_after,
        after=phase_after,
        injection_accepted=True,
        host_responsive=True,
        guest_text=guest,
    )
    assert verdict == "PASS"
    assert checks["activeVmUseStableThroughInjection"]
    assert checks["activeVmReleasedOrStillSameAfter"]
    changed_owner = dict(phase_after)
    changed_owner["activePassthroughUsers"] = [
        {"vm": "other", "vmMoId": "vm-2", "deviceKey": 16000}
    ]
    verdict, checks, _ = evaluate_observation(
        owner_state="PassthruActive",
        mask=0x1,
        oracle="esxi803",
        before=phase_before,
        injection=phase_after,
        after=changed_owner,
        injection_accepted=True,
        host_responsive=True,
        guest_text=guest,
    )
    assert verdict == "FAIL"
    assert not checks["activeVmReleasedOrStillSameAfter"]
    assert aggregate_verdict([{"verdict": "PASS"}]) == "PASS"
    assert aggregate_verdict(
        [{"verdict": "PASS"}, {"verdict": "INCONCLUSIVE"}]
    ) == "INCONCLUSIVE"
    print(
        json.dumps(
            {
                "selftest": "PASS",
                "safeCorrectableBits": SAFE_CORRECTABLE_BITS,
                "command": command,
            },
            indent=2,
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run safe Correctable-only AER cases against the nested ESXi lab."
    )
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--run-id")
    parser.add_argument("--host", default="169.254.239.77")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--owner-state", choices=OWNER_CHOICES, default="PassthruActive")
    parser.add_argument("--error-bits", default="receiver_error")
    parser.add_argument("--qemu-device", default="test_fn1")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--qtest-socket")
    parser.add_argument("--qtest-clean-baseline", action="store_true")
    parser.add_argument(
        "--qtest-baseline-policy",
        choices=("strict", "status-routing"),
        default="strict",
        help=(
            "strict also requires PCIe Device Status to clear; status-routing "
            "requires endpoint CES plus root status surfaces to clear and records "
            "a sticky Device Status as an observation limitation"
        ),
    )
    parser.add_argument("--outer-endpoint-bdf", default="0000:01:00.1")
    parser.add_argument("--outer-root-bdf", default="0000:00:08.0")
    parser.add_argument("--esxi-bdf", default="0000:01:00.1")
    parser.add_argument("--esxi-root-bdf", default="0000:00:08.0")
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument(
        "--remote-iso",
        default="/vmfs/volumes/pci-mmio-local/iso/esxi-l3-aer-probe.iso",
    )
    parser.add_argument("--base-vmx", default=str(DEFAULT_BASE_VMX))
    parser.add_argument("--guest-marker-timeout", type=int, default=360)
    parser.add_argument("--guest-complete-timeout", type=int, default=180)
    parser.add_argument("--settle-seconds", type=int, default=8)
    parser.add_argument("--log-lines", type=int, default=2400)
    parser.add_argument(
        "--oracle", choices=("esxi803", "delivery-only"), default="esxi803"
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    if not args.output:
        parser.error("--output is required unless --selftest is used")
    try:
        bits = parse_error_bits(args.error_bits)
        for label, value in (
            ("ESXi BDF", args.esxi_bdf),
            ("ESXi root BDF", args.esxi_root_bdf),
            ("outer endpoint BDF", args.outer_endpoint_bdf),
            ("outer root BDF", args.outer_root_bdf),
        ):
            if not BDF_RE.fullmatch(value):
                raise ValueError(f"invalid {label}: {value!r}")
        if args.qtest_clean_baseline and not args.qtest_socket:
            raise ValueError("--qtest-clean-baseline requires --qtest-socket")
        validate_safe_id(args.qemu_device, "QEMU device id")
        if not SAFE_DATASTORE_RE.fullmatch(args.datastore):
            raise ValueError(f"invalid datastore name: {args.datastore!r}")
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.remote_iso):
            raise ValueError(f"invalid remote ISO path: {args.remote_iso!r}")
        if args.guest_marker_timeout <= 0 or args.guest_complete_timeout <= 0:
            raise ValueError("guest timeouts must be positive")
        if args.settle_seconds < 0 or args.log_lines < 100:
            raise ValueError("settle seconds must be non-negative and log-lines >= 100")
        base_vmx = Path(args.base_vmx)
        if args.owner_state == "PassthruActive" and not base_vmx.is_file():
            raise ValueError(f"base VMX is missing: {base_vmx}")
    except ValueError as error:
        parser.error(str(error))

    run_id = args.run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    try:
        validate_safe_id(run_id, "run id")
    except ValueError as error:
        parser.error(str(error))
    output_dir = Path(args.output).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        parser.error(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    run_result: dict[str, Any] = {
        "schemaVersion": 1,
        "runId": run_id,
        "startedAt": utc_now(),
        "safetyBoundary": {
            "errorClass": "Correctable-only",
            "closedAllowList": SAFE_CORRECTABLE_BITS,
            "hmpForm": "pcie_aer_inject_error -c DEVICE MASK",
            "uncorrectableInjectionSurface": False,
        },
        "input": {
            "host": args.host,
            "ownerState": args.owner_state,
            "errorBits": [name for name, _ in bits],
            "qemuDevice": args.qemu_device,
            "esxiBdf": args.esxi_bdf,
            "esxiRootBdf": args.esxi_root_bdf,
            "qtestSocket": args.qtest_socket,
            "qtestCleanBaseline": args.qtest_clean_baseline,
            "qtestBaselinePolicy": args.qtest_baseline_policy,
            "outerEndpointBdf": args.outer_endpoint_bdf,
            "outerRootBdf": args.outer_root_bdf,
            "oracle": args.oracle,
        },
        "cases": {},
        "verdict": "BLOCKED_ENV",
    }
    save_json(output_dir / "result.json", run_result)

    password: str | None = None
    api: ApiSession | None = None
    try:
        password = caveat_field(args.caveat, "Password")
        ssh = EsxiSsh(args.host, password, user=args.user)
        transfer = EsxiScp(args.host, args.user, password)
        api = ApiSession(args.host, args.user, password)
        run_result["environment"] = {
            "esxiProduct": api.host.config.product.fullName,
            "systemUuid": api.system_uuid,
            "qemuCommand": qemu_command_line(args.qemu_name),
        }
        save_json(output_dir / "result.json", run_result)
        for bit_name, mask in bits:
            case = run_case(
                args=args,
                run_id=run_id,
                bit_name=bit_name,
                mask=mask,
                ssh=ssh,
                transfer=transfer,
                api=api,
                output_dir=output_dir,
            )
            run_result["cases"][case["caseId"]] = case
            run_result["verdict"] = aggregate_verdict(run_result["cases"].values())
            save_json(output_dir / "result.json", run_result)
            if case["verdict"] == "FAIL_SAFETY":
                run_result["safetyStop"] = {
                    "triggered": True,
                    "afterCase": case["caseId"],
                    "remainingCasesSkipped": [
                        name
                        for name, _ in bits
                        if f"{args.owner_state.lower()}-{name}"
                        not in run_result["cases"]
                    ],
                }
                break
    except Exception as error:
        run_result["verdict"] = "BLOCKED_ENV"
        run_result["fault"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if api is not None:
            api.close()
        run_result["finishedAt"] = utc_now()
        if run_result["cases"]:
            run_result["verdict"] = aggregate_verdict(run_result["cases"].values())
        save_json(output_dir / "result.json", run_result)
        write_sha256s(output_dir)
        password = None

    print(json.dumps(run_result, indent=2, ensure_ascii=False, sort_keys=True))
    exit_codes = {
        "PASS": 0,
        "FAIL": 1,
        "FAIL_SAFETY": 4,
        "INCONCLUSIVE": 2,
        "BLOCKED_ENV": 3,
    }
    raise SystemExit(exit_codes[run_result["verdict"]])


if __name__ == "__main__":
    main()
