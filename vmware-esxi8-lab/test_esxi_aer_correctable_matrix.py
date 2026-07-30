#!/usr/bin/env python3
"""Run a fail-closed ESXi Correctable AER behavior matrix.

The runner deliberately exposes no uncorrectable injection path.  Every HMP
command is constructed from a closed allow-list of PCIe Correctable Error
Status bits and always uses ``pcie_aer_inject_error -c``.

The default oracle captures profile-specific ESXi 8.0.3 behavior.  The
historical e1000e profile hides the guest AER header while preserving raw
status projection; a controlled virtio profile may expose the capability while
still withholding a guest kernel AER service event.  Use the ``delivery-only``
oracle when characterising another ESXi build.  Capability visibility, status
projection and service/interrupt delivery are deliberately evaluated
separately.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import copy
import hashlib
import json
import multiprocessing
import os
import re
import shlex
import ssl
import subprocess
import threading
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
GATE_STABILITY_DELAYS = (0.0, 0.1, 1.0)
OWNER_PROBE_HTTP_TIMEOUT_SECONDS = 5
OWNER_PROBE_HARD_TIMEOUT_SECONDS = 10.0
OWNER_PROBE_TERMINATE_GRACE_SECONDS = 1.0

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


class GateLeaseApplyFailure(RuntimeError):
    """Gate writes started, so the caller must retain and restore the lease."""

    def __init__(
        self,
        message: str,
        lease: dict[str, Any],
        *,
        safety: bool,
    ) -> None:
        super().__init__(message)
        self.lease = lease
        numeric_safety_faults = _partial_numeric_safety_faults(lease)
        if numeric_safety_faults:
            lease["numericSafetyFaults"] = numeric_safety_faults
        self.safety = bool(safety or numeric_safety_faults)


class GateLeaseRestoreFailure(RuntimeError):
    """Restore began or resumed, so partial evidence must reach the caller."""

    def __init__(
        self,
        message: str,
        result: dict[str, Any],
        *,
        safety: bool,
    ) -> None:
        super().__init__(message)
        self.result = result
        numeric_safety_faults = _partial_numeric_safety_faults(result)
        if numeric_safety_faults:
            result["numericSafetyFaults"] = numeric_safety_faults
        self.safety = bool(safety or numeric_safety_faults)


class BaselineClearFailure(RuntimeError):
    """Baseline clear failed; retain every numeric snapshot already read."""

    def __init__(
        self,
        message: str,
        result: dict[str, Any],
        *,
        safety: bool,
    ) -> None:
        super().__init__(message)
        self.result = result
        numeric_safety_faults = _partial_numeric_safety_faults(result)
        if numeric_safety_faults:
            result["numericSafetyFaults"] = numeric_safety_faults
        self.safety = bool(safety or numeric_safety_faults)


@dataclass(frozen=True)
class GateTuple:
    """Requested Correctable-only gate values.

    E is Endpoint Device Control.CERE, M is the selected bit in the Endpoint
    Correctable Error Mask, and R is Root Error Command.COR_EN.
    """

    endpoint_cere: bool
    endpoint_masked: bool
    root_cor_enabled: bool

    @property
    def label(self) -> str:
        return "".join(
            "1" if value else "0"
            for value in (
                self.endpoint_cere,
                self.endpoint_masked,
                self.root_cor_enabled,
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "E": int(self.endpoint_cere),
            "M": int(self.endpoint_masked),
            "R": int(self.root_cor_enabled),
        }


@dataclass(frozen=True)
class RootPathState:
    """Auxiliary Root Port gates, deliberately kept separate from R."""

    bridge_serr: bool
    root_cere: bool

    @property
    def open(self) -> bool:
        return self.bridge_serr and self.root_cere

    def as_dict(self) -> dict[str, Any]:
        return {
            "bridgeControlSerr": int(self.bridge_serr),
            "rootDeviceControlCere": int(self.root_cere),
            "open": self.open,
        }


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


def parse_gate_tuples(raw: str | None) -> list[GateTuple]:
    if raw is None:
        return []
    tokens = [item.strip() for item in raw.split(",")]
    if not tokens or any(not token for token in tokens):
        raise ValueError("--gate-tuples must be a comma-separated list of 000-111")
    result: list[GateTuple] = []
    seen: set[str] = set()
    for token in tokens:
        if not re.fullmatch(r"[01]{3}", token):
            raise ValueError(
                f"invalid gate tuple {token!r}; expected exactly three bits E,M,R"
            )
        if token in seen:
            raise ValueError(f"duplicate gate tuple: {token}")
        seen.add(token)
        result.append(
            GateTuple(
                endpoint_cere=token[0] == "1",
                endpoint_masked=token[1] == "1",
                root_cor_enabled=token[2] == "1",
            )
        )
    return result


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
    *,
    topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read the outer-QEMU AER surface.

    A paused full read discovers and binds the immutable topology.  Runnable
    safety polls pass that read back as ``topology`` so every poll reads only
    the dynamic gate/status surface.  Repeating PCIEXBAR and capability-list
    discovery on every 25 ms poll made the 50 ms fail-stop envelope depend on
    scheduler jitter instead of the safety registers themselves.
    """

    if not socket_path.is_socket():
        raise BlockedEnvironment(f"QTest socket is not ready: {socket_path}")
    cached_endpoint: dict[str, Any] | None = None
    cached_root: dict[str, Any] | None = None
    cached_endpoint_state: dict[str, Any] | None = None
    cached_root_state: dict[str, Any] | None = None
    if topology is not None:
        try:
            cached_endpoint = copy.deepcopy(topology["endpoint"])
            cached_root = copy.deepcopy(topology["root"])
            cached_endpoint_state = copy.deepcopy(topology["endpointState"])
            cached_root_state = copy.deepcopy(topology["rootState"])
            pciexbar = int(topology["q35Pciexbar"])
            endpoint_identity = (
                int(cached_endpoint["bus"]),
                int(cached_endpoint["device"]),
                int(cached_endpoint["function"]),
            )
            root_identity = (
                int(cached_root["bus"]),
                int(cached_root["device"]),
                int(cached_root["function"]),
            )
            if endpoint_identity != bdf_tuple(endpoint_bdf):
                raise ValueError(
                    "cached endpoint identity does not match the requested BDF"
                )
            if root_identity != bdf_tuple(root_bdf):
                raise ValueError(
                    "cached root identity does not match the requested BDF"
                )
            if int(cached_endpoint["pcieType"]) != qemu_aer.PCI_EXP_TYPE_ENDPOINT:
                raise ValueError("cached endpoint PCIe type is not Endpoint")
            if int(cached_root["pcieType"]) != qemu_aer.PCI_EXP_TYPE_ROOT_PORT:
                raise ValueError("cached root PCIe type is not Root Port")
            for label, device in (
                ("endpoint", cached_endpoint),
                ("root", cached_root),
            ):
                pcie_offset = int(device["pcieCapabilityOffset"])
                aer_offset = int(device["aerCapabilityOffset"])
                aer_header = int(device["aerHeader"])
                if (
                    pcie_offset < 0x40
                    or pcie_offset >= 0x100
                    or pcie_offset % 4
                ):
                    raise ValueError(
                        f"cached {label} PCIe capability offset is invalid"
                    )
                if (
                    aer_offset < 0x100
                    or aer_offset > 0xFFC
                    or aer_offset % 4
                ):
                    raise ValueError(
                        f"cached {label} AER capability offset is invalid"
                    )
                if aer_header & 0xFFFF != qemu_aer.PCI_EXT_CAP_ID_ERR:
                    raise ValueError(
                        f"cached {label} AER header is not AER"
                    )
            # Validate every immutable field used to reconstruct the full
            # evidence shape before QEMU can become runnable.
            int(cached_endpoint_state["uncorrectableErrorMask"])
            int(cached_root_state["correctableErrorMask"])
            int(cached_root_state["primaryBus"])
            int(cached_root_state["secondaryBus"])
            int(cached_root_state["subordinateBus"])
        except (KeyError, TypeError, ValueError) as error:
            raise BlockedEnvironment(
                f"cached outer-QEMU topology is not reusable: {error}"
            ) from error
        expected_pciexbar = qemu_aer.MCFG_BASE | qemu_aer.Q35_PCIEXBAR_ENABLE
        if pciexbar != expected_pciexbar:
            raise BlockedEnvironment(
                "cached Q35 ECAM base does not match the read-only lab "
                f"accessor: observed=0x{pciexbar:08x}, "
                f"expected=0x{expected_pciexbar:08x}"
            )

    client = qemu_aer.QTestClient(socket_path)
    try:
        if topology is not None:
            assert cached_endpoint is not None
            assert cached_root is not None
            assert cached_endpoint_state is not None
            assert cached_root_state is not None
            eb = int(cached_endpoint["bus"])
            ed = int(cached_endpoint["device"])
            ef = int(cached_endpoint["function"])
            epcie = int(cached_endpoint["pcieCapabilityOffset"])
            eaer = int(cached_endpoint["aerCapabilityOffset"])
            rb = int(cached_root["bus"])
            rd = int(cached_root["device"])
            rf = int(cached_root["function"])
            rpcie = int(cached_root["pcieCapabilityOffset"])
            raer = int(cached_root["aerCapabilityOffset"])
            endpoint_start = min(
                epcie + qemu_aer.PCI_EXP_DEVCTL,
                eaer + qemu_aer.PCI_ERR_UNCOR_STATUS,
            )
            endpoint_end = max(
                epcie + qemu_aer.PCI_EXP_DEVSTA + 2,
                eaer + qemu_aer.PCI_ERR_UNCOR_STATUS + 4,
                eaer + qemu_aer.PCI_ERR_COR_STATUS + 4,
                eaer + qemu_aer.PCI_ERR_COR_MASK + 4,
            )
            root_start = min(
                qemu_aer.PCI_BRIDGE_CONTROL,
                rpcie + qemu_aer.PCI_EXP_DEVCTL,
                raer + qemu_aer.PCI_ERR_UNCOR_STATUS,
            )
            root_end = max(
                qemu_aer.PCI_BRIDGE_CONTROL + 2,
                rpcie + qemu_aer.PCI_EXP_DEVSTA + 2,
                raer + qemu_aer.PCI_ERR_UNCOR_STATUS + 4,
                raer + qemu_aer.PCI_ERR_COR_STATUS + 4,
                raer + qemu_aer.PCI_ERR_ROOT_COMMAND + 4,
                raer + qemu_aer.PCI_ERR_ROOT_STATUS + 4,
                raer + qemu_aer.PCI_ERR_ROOT_ERR_SRC + 4,
            )
            endpoint_block, root_block = qemu_aer.qtest_read_blocks(
                client,
                (
                    (
                        qemu_aer.ecam_address(
                            eb,
                            ed,
                            ef,
                            endpoint_start,
                        ),
                        endpoint_end - endpoint_start,
                    ),
                    (
                        qemu_aer.ecam_address(
                            rb,
                            rd,
                            rf,
                            root_start,
                        ),
                        root_end - root_start,
                    ),
                ),
            )

            def block_value(
                block: bytes,
                start: int,
                offset: int,
                width: int,
            ) -> int:
                relative = offset - start
                raw = block[relative : relative + width]
                if len(raw) != width:
                    raise RuntimeError(
                        "cached-topology block read omitted a dynamic field"
                    )
                return int.from_bytes(raw, byteorder="little")

            endpoint_state = {
                "deviceControl": block_value(
                    endpoint_block,
                    endpoint_start,
                    epcie + qemu_aer.PCI_EXP_DEVCTL,
                    2,
                ),
                "deviceStatus": block_value(
                    endpoint_block,
                    endpoint_start,
                    epcie + qemu_aer.PCI_EXP_DEVSTA,
                    2,
                ),
                "uncorrectableErrorStatus": block_value(
                    endpoint_block,
                    endpoint_start,
                    eaer + qemu_aer.PCI_ERR_UNCOR_STATUS,
                    4,
                ),
                "correctableErrorStatus": block_value(
                    endpoint_block,
                    endpoint_start,
                    eaer + qemu_aer.PCI_ERR_COR_STATUS,
                    4,
                ),
                "correctableErrorMask": block_value(
                    endpoint_block,
                    endpoint_start,
                    eaer + qemu_aer.PCI_ERR_COR_MASK,
                    4,
                ),
                "aerHeader": int(cached_endpoint["aerHeader"]),
                "uncorrectableErrorMask": int(
                    cached_endpoint_state["uncorrectableErrorMask"]
                ),
            }
            root_state = {
                "bridgeControl": block_value(
                    root_block,
                    root_start,
                    qemu_aer.PCI_BRIDGE_CONTROL,
                    2,
                ),
                "deviceControl": block_value(
                    root_block,
                    root_start,
                    rpcie + qemu_aer.PCI_EXP_DEVCTL,
                    2,
                ),
                "deviceStatus": block_value(
                    root_block,
                    root_start,
                    rpcie + qemu_aer.PCI_EXP_DEVSTA,
                    2,
                ),
                "uncorrectableErrorStatus": block_value(
                    root_block,
                    root_start,
                    raer + qemu_aer.PCI_ERR_UNCOR_STATUS,
                    4,
                ),
                "correctableErrorStatus": block_value(
                    root_block,
                    root_start,
                    raer + qemu_aer.PCI_ERR_COR_STATUS,
                    4,
                ),
                "rootErrorCommand": block_value(
                    root_block,
                    root_start,
                    raer + qemu_aer.PCI_ERR_ROOT_COMMAND,
                    4,
                ),
                "rootErrorStatus": block_value(
                    root_block,
                    root_start,
                    raer + qemu_aer.PCI_ERR_ROOT_STATUS,
                    4,
                ),
                "errorSourceIdentification": block_value(
                    root_block,
                    root_start,
                    raer + qemu_aer.PCI_ERR_ROOT_ERR_SRC,
                    4,
                ),
                "aerHeader": int(cached_root["aerHeader"]),
                "correctableErrorMask": int(
                    cached_root_state["correctableErrorMask"]
                ),
                "primaryBus": int(cached_root_state["primaryBus"]),
                "secondaryBus": int(cached_root_state["secondaryBus"]),
                "subordinateBus": int(
                    cached_root_state["subordinateBus"]
                ),
            }
            return {
                "q35Pciexbar": pciexbar,
                "endpoint": cached_endpoint,
                "endpointState": endpoint_state,
                "root": cached_root,
                "rootState": root_state,
            }

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


def gate_tuple_from_snapshot(snapshot: dict[str, Any], mask: int) -> GateTuple:
    endpoint = snapshot["endpointState"]
    root = snapshot["rootState"]
    return GateTuple(
        endpoint_cere=bool(
            int(endpoint["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
        endpoint_masked=bool(int(endpoint["correctableErrorMask"]) & mask),
        root_cor_enabled=bool(
            int(root["rootErrorCommand"]) & qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
        ),
    )


def root_path_from_snapshot(snapshot: dict[str, Any]) -> RootPathState:
    root = snapshot["rootState"]
    return RootPathState(
        bridge_serr=bool(
            int(root["bridgeControl"]) & qemu_aer.PCI_BRIDGE_CTL_SERR
        ),
        root_cere=bool(
            int(root["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
    )


def gate_readback(snapshot: dict[str, Any], mask: int) -> dict[str, Any]:
    endpoint = snapshot["endpointState"]
    root = snapshot["rootState"]
    return {
        "tuple": gate_tuple_from_snapshot(snapshot, mask).as_dict(),
        "raw": {
            "endpointDeviceControl": int(endpoint["deviceControl"]),
            "endpointCorrectableMask": int(endpoint["correctableErrorMask"]),
            "rootErrorCommand": int(root["rootErrorCommand"]),
        },
        "rootPath": root_path_from_snapshot(snapshot).as_dict(),
    }


def outer_snapshot_safety_faults(snapshot: dict[str, Any]) -> list[str]:
    """Return every independently readable non-Correctable safety fault.

    A QTest read can succeed while a later field is absent or malformed.
    Safety authority is monotonic: one known non-zero UES/Device Status/Root
    Error Status value must survive that partial shape instead of being hidden
    by a ``KeyError`` from an unrelated field.
    """

    endpoint_raw = snapshot.get("endpointState")
    root_raw = snapshot.get("rootState")
    endpoint = endpoint_raw if isinstance(endpoint_raw, dict) else {}
    root = root_raw if isinstance(root_raw, dict) else {}

    def parsed(container: dict[str, Any], key: str) -> int | None:
        try:
            value = container[key]
            if isinstance(value, bool):
                return None
            return int(value)
        except (KeyError, TypeError, ValueError):
            return None

    faults: list[str] = []
    endpoint_ues = parsed(endpoint, "uncorrectableErrorStatus")
    if endpoint_ues:
        faults.append(
            "endpoint UES="
            f"0x{endpoint_ues:08x}"
        )
    endpoint_device_status = parsed(endpoint, "deviceStatus")
    if endpoint_device_status is not None:
        endpoint_non_ced = endpoint_device_status & (
            qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK ^ qemu_aer.PCI_EXP_DEVSTA_CED
        )
        if endpoint_non_ced:
            faults.append(
                "endpoint DeviceStatus non-CED="
                f"0x{endpoint_non_ced:04x}"
            )
    root_ues = parsed(root, "uncorrectableErrorStatus")
    if root_ues:
        faults.append(
            f"root UES=0x{root_ues:08x}"
        )
    root_device_status = parsed(root, "deviceStatus")
    if root_device_status is not None:
        root_device_errors = root_device_status & (
            qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK ^ qemu_aer.PCI_EXP_DEVSTA_CED
        )
        if root_device_errors:
            faults.append(
                f"root DeviceStatus error=0x{root_device_errors:04x}"
            )
    root_error_status = parsed(root, "rootErrorStatus")
    if root_error_status is not None:
        root_uncorrectable = (
            root_error_status & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK
        )
        if root_uncorrectable:
            faults.append(
                f"root uncorrectable reception=0x{root_uncorrectable:08x}"
            )
    return faults


def outer_snapshot_correctable_noise(snapshot: dict[str, Any]) -> list[str]:
    """Return pre-existing Correctable surfaces that would confound a case."""

    endpoint = snapshot["endpointState"]
    root = snapshot["rootState"]
    noise: list[str] = []
    values = (
        ("endpoint CES", int(endpoint["correctableErrorStatus"])),
        (
            "endpoint DeviceStatus.CED",
            int(endpoint["deviceStatus"]) & qemu_aer.PCI_EXP_DEVSTA_CED,
        ),
        ("root CES", int(root["correctableErrorStatus"])),
        (
            "root DeviceStatus.CED",
            int(root["deviceStatus"]) & qemu_aer.PCI_EXP_DEVSTA_CED,
        ),
        ("Root Error Status low 0x7f", int(root["rootErrorStatus"]) & 0x7F),
    )
    for label, value in values:
        if value:
            noise.append(f"{label}=0x{value:x}")
    return noise


def transition_qemu(
    monitor: Path,
    command: str,
    expected_status: str,
) -> dict[str, str]:
    output = hmp_command(monitor, command)
    status = hmp_command(monitor, "info status")
    if expected_status.lower() not in status.lower():
        raise SafetyViolation(
            f"QEMU {command!r} did not reach {expected_status!r}: {status!r}"
        )
    return {
        "command": command,
        "output": output,
        "status": status,
        "observedAt": utc_now(),
    }


def qemu_runtime_state(monitor: Path) -> str:
    """Return the observable outer-QEMU state without contacting ESXi."""

    try:
        status = hmp_command(monitor, "info status").lower()
    except Exception:
        return "unknown"
    if "vm status: paused" in status:
        return "paused"
    if "vm status: running" in status:
        return "running"
    return "unknown"


def write_gate_tuple(
    client: qemu_aer.QTestClient,
    topology: dict[str, Any],
    requested: GateTuple,
    mask: int,
    *,
    clear_correctable: bool,
    root_path: RootPathState | None = None,
) -> None:
    endpoint = topology["endpoint"]
    root = topology["root"]
    eb, ed, ef = endpoint["bus"], endpoint["device"], endpoint["function"]
    rb, rd, rf = root["bus"], root["device"], root["function"]
    epcie = endpoint["pcieCapabilityOffset"]
    eaer = endpoint["aerCapabilityOffset"]
    rpcie = root["pcieCapabilityOffset"]
    raer = root["aerCapabilityOffset"]

    # Block Correctable messages while the bit-specific mask and Root Command
    # are staged.  No Uncorrectable enable, mask, or severity bit is exposed.
    endpoint_control = qemu_aer.config_read16(
        client, eb, ed, ef, epcie + qemu_aer.PCI_EXP_DEVCTL
    )
    qemu_aer.config_write16(
        client,
        eb,
        ed,
        ef,
        epcie + qemu_aer.PCI_EXP_DEVCTL,
        endpoint_control & ~qemu_aer.PCI_EXP_DEVCTL_CERE,
    )

    correctable_mask = qemu_aer.config_read32(
        client, eb, ed, ef, eaer + qemu_aer.PCI_ERR_COR_MASK
    )
    desired_mask = (
        correctable_mask | mask
        if requested.endpoint_masked
        else correctable_mask & ~mask
    )
    qemu_aer.config_write32(
        client,
        eb,
        ed,
        ef,
        eaer + qemu_aer.PCI_ERR_COR_MASK,
        desired_mask,
    )

    root_command = qemu_aer.config_read32(
        client, rb, rd, rf, raer + qemu_aer.PCI_ERR_ROOT_COMMAND
    )
    desired_root_command = (
        root_command | qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
        if requested.root_cor_enabled
        else root_command & ~qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
    )
    qemu_aer.config_write32(
        client,
        rb,
        rd,
        rf,
        raer + qemu_aer.PCI_ERR_ROOT_COMMAND,
        desired_root_command,
    )

    if root_path is not None:
        bridge_control = qemu_aer.config_read16(
            client, rb, rd, rf, qemu_aer.PCI_BRIDGE_CONTROL
        )
        desired_bridge_control = (
            bridge_control | qemu_aer.PCI_BRIDGE_CTL_SERR
            if root_path.bridge_serr
            else bridge_control & ~qemu_aer.PCI_BRIDGE_CTL_SERR
        )
        qemu_aer.config_write16(
            client,
            rb,
            rd,
            rf,
            qemu_aer.PCI_BRIDGE_CONTROL,
            desired_bridge_control,
        )
        root_device_control = qemu_aer.config_read16(
            client, rb, rd, rf, rpcie + qemu_aer.PCI_EXP_DEVCTL
        )
        desired_root_device_control = (
            root_device_control | qemu_aer.PCI_EXP_DEVCTL_CERE
            if root_path.root_cere
            else root_device_control & ~qemu_aer.PCI_EXP_DEVCTL_CERE
        )
        qemu_aer.config_write16(
            client,
            rb,
            rd,
            rf,
            rpcie + qemu_aer.PCI_EXP_DEVCTL,
            desired_root_device_control,
        )

    if clear_correctable:
        qemu_aer.config_write16(
            client,
            eb,
            ed,
            ef,
            epcie + qemu_aer.PCI_EXP_DEVSTA,
            qemu_aer.PCI_EXP_DEVSTA_CED,
        )
        qemu_aer.config_write32(
            client,
            eb,
            ed,
            ef,
            eaer + qemu_aer.PCI_ERR_COR_STATUS,
            0xFFFFFFFF,
        )
        qemu_aer.config_write16(
            client,
            rb,
            rd,
            rf,
            rpcie + qemu_aer.PCI_EXP_DEVSTA,
            qemu_aer.PCI_EXP_DEVSTA_CED,
        )
        qemu_aer.config_write32(
            client,
            rb,
            rd,
            rf,
            raer + qemu_aer.PCI_ERR_COR_STATUS,
            0xFFFFFFFF,
        )
        qemu_aer.config_write32(
            client,
            rb,
            rd,
            rf,
            raer + qemu_aer.PCI_ERR_ROOT_STATUS,
            (
                qemu_aer.PCI_ERR_ROOT_COR_RCV
                | qemu_aer.PCI_ERR_ROOT_MULTI_COR_RCV
            ),
        )

    final_endpoint_control = qemu_aer.config_read16(
        client, eb, ed, ef, epcie + qemu_aer.PCI_EXP_DEVCTL
    )
    if requested.endpoint_cere:
        final_endpoint_control |= qemu_aer.PCI_EXP_DEVCTL_CERE
    else:
        final_endpoint_control &= ~qemu_aer.PCI_EXP_DEVCTL_CERE
    qemu_aer.config_write16(
        client,
        eb,
        ed,
        ef,
        epcie + qemu_aer.PCI_EXP_DEVCTL,
        final_endpoint_control,
    )


def gate_non_target_checks(
    before: dict[str, Any],
    after: dict[str, Any],
    mask: int,
) -> dict[str, bool]:
    before_endpoint = before["endpointState"]
    after_endpoint = after["endpointState"]
    before_root = before["rootState"]
    after_root = after["rootState"]
    return {
        "endpointDeviceControlNonCereUnchanged": not bool(
            (
                int(before_endpoint["deviceControl"])
                ^ int(after_endpoint["deviceControl"])
            )
            & ~qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
        "endpointCorrectableMaskNonTargetUnchanged": not bool(
            (
                int(before_endpoint["correctableErrorMask"])
                ^ int(after_endpoint["correctableErrorMask"])
            )
            & ~mask
        ),
        "rootErrorCommandNonCorUnchanged": not bool(
            (
                int(before_root["rootErrorCommand"])
                ^ int(after_root["rootErrorCommand"])
            )
            & ~qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
        ),
        "rootBridgeControlNonSerrUnchanged": not bool(
            (
                int(before_root["bridgeControl"])
                ^ int(after_root["bridgeControl"])
            )
            & ~qemu_aer.PCI_BRIDGE_CTL_SERR
        ),
        "rootDeviceControlNonCereUnchanged": not bool(
            (
                int(before_root["deviceControl"])
                ^ int(after_root["deviceControl"])
            )
            & ~qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
    }


def sample_gate_timeline(
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    delays: Iterable[float] = GATE_STABILITY_DELAYS,
    *,
    started_at: float | None = None,
    stop_on_safety_fault: bool = True,
) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    started = time.monotonic() if started_at is None else started_at
    for target_delay in delays:
        remaining = float(target_delay) - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        actual_elapsed = time.monotonic() - started
        snapshot = outer_qemu_aer_snapshot(
            socket_path, endpoint_bdf, root_bdf
        )
        safety_faults = outer_snapshot_safety_faults(snapshot)
        samples.append(
            {
                "delaySeconds": target_delay,
                "targetDelaySeconds": target_delay,
                "actualElapsedSeconds": actual_elapsed,
                "capturedAt": utc_now(),
                "readback": gate_readback(snapshot, mask),
                "safetyFaults": safety_faults,
                "snapshot": snapshot,
            }
        )
        if safety_faults and stop_on_safety_fault:
            break
    return samples


def sample_gate_timeline_continuous(
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    delays: Iterable[float],
    *,
    started_at: float,
    maximum_poll_interval: float,
    target_poll_interval: float,
    stop_on_safety_fault: bool = True,
    safety_boundary: str = "ATTRIBUTION_WINDOW",
    topology: dict[str, Any] | None = None,
    _partial_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Continuously sample a runnable QEMU until every target delay is covered.

    ``started_at`` must be captured immediately before the corresponding
    ``cont`` attempt.  This makes monitor transition latency part of the first
    measured safety-poll gap instead of silently starting the clock after QEMU
    is already runnable.

    The helper returns fault evidence rather than raising so callers can always
    issue an idempotent fail-stop and retain the complete sampler record.
    """

    target_delays = tuple(float(value) for value in delays)
    if (
        not target_delays
        or target_delays[0] < 0
        or any(
            later <= earlier
            for earlier, later in zip(target_delays, target_delays[1:])
        )
    ):
        raise ValueError(
            "continuous gate timeline delays must be non-negative and "
            "strictly increasing"
        )
    if (
        maximum_poll_interval <= 0
        or target_poll_interval <= 0
        or target_poll_interval > maximum_poll_interval
    ):
        raise ValueError(
            "continuous gate safety poll intervals are outside the valid "
            "envelope"
        )
    if safety_boundary not in {
        "PRE_INJECTION",
        "ATTRIBUTION_WINDOW",
        "POST_CLEANUP",
    }:
        raise ValueError(
            f"invalid continuous safety boundary: {safety_boundary}"
        )

    samples: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    poll_faults: list[dict[str, Any]] = []
    safety_events: list[dict[str, Any]] = []
    record = _partial_record if isinstance(_partial_record, dict) else {}
    record.update(
        {
            "safetyWindowKind": "CONTINUOUS_TIMELINE",
            "safetyBoundary": safety_boundary,
            "targetDelaysSeconds": list(target_delays),
            "targetCount": len(target_delays),
            "maximumPollIntervalSeconds": maximum_poll_interval,
            "targetPollIntervalSeconds": target_poll_interval,
            "snapshotMode": (
                "PINNED_TOPOLOGY_BLOCK_BATCH"
                if topology is not None
                else "FULL_DISCOVERY"
            ),
            "maximumObservedPollGapSeconds": 0.0,
            "maximumObservedReadDurationSeconds": 0.0,
            "sampleCount": 0,
            "samples": samples,
            "timeline": timeline,
            "completedTargetCount": 0,
            "complete": False,
            "pollFaults": poll_faults,
            "safetyEvents": safety_events,
            "finishedAt": None,
        }
    )
    maximum_observed_gap = 0.0
    maximum_observed_read_duration = 0.0
    prior_sample_started: float | None = None
    next_poll_at = started_at
    target_index = 0

    while target_index < len(target_delays):
        try:
            remaining = next_poll_at - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            sample_started = time.monotonic()
        except BaseException as error:
            poll_faults.append(
                {
                    "type": type(error).__name__,
                    "message": str(error),
                    "phase": "safety-poll-scheduler",
                }
            )
            break
        gap = (
            sample_started - prior_sample_started
            if prior_sample_started is not None
            else sample_started - started_at
        )
        maximum_observed_gap = max(maximum_observed_gap, gap)
        record["maximumObservedPollGapSeconds"] = maximum_observed_gap
        gap_fault: dict[str, Any] | None = None
        if gap > maximum_poll_interval:
            gap_fault = {
                "type": "SafetyPollGapExceeded",
                "message": (
                    "Correctable-only safety polling exceeded "
                    f"{maximum_poll_interval:.6f}s: observed {gap:.6f}s"
                ),
                "observedSeconds": gap,
                "maximumSeconds": maximum_poll_interval,
            }

        try:
            snapshot = outer_qemu_aer_snapshot(
                socket_path,
                endpoint_bdf,
                root_bdf,
                **(
                    {"topology": topology}
                    if topology is not None
                    else {}
                ),
            )
        except BaseException as error:
            if gap_fault is not None:
                poll_faults.append(gap_fault)
            poll_faults.append(
                {
                    "type": type(error).__name__,
                    "message": str(error),
                    "phase": "qtest-safety-read",
                    "sampleStartGapSeconds": gap,
                }
            )
            break

        # The caller can attach ``record`` to its lease before QEMU becomes
        # runnable.  Commit the raw read to that shared object as the very
        # first post-read action, before timing, timestamps, copies or parsers.
        # A later BaseException therefore cannot erase an observed unsafe
        # five-register surface.
        sample: dict[str, Any] = {
            "sampleIndex": len(samples),
            "actualElapsedSeconds": None,
            "sampleStartGapSeconds": gap,
            "sampleDurationSeconds": None,
            "capturedAt": None,
            "readback": None,
            "safetyFaults": [],
            "snapshot": snapshot,
            "partial": True,
        }
        samples.append(sample)
        record["sampleCount"] = len(samples)
        try:
            sample_finished = time.monotonic()
            sample_duration = sample_finished - sample_started
            maximum_observed_read_duration = max(
                maximum_observed_read_duration,
                sample_duration,
            )
            record["maximumObservedReadDurationSeconds"] = (
                maximum_observed_read_duration
            )
            actual_elapsed = sample_finished - started_at
            sample["sampleDurationSeconds"] = sample_duration
            sample["actualElapsedSeconds"] = actual_elapsed
        except BaseException as error:
            safety_faults = _partial_numeric_safety_faults(snapshot)
            sample["safetyFaults"] = safety_faults
            if gap_fault is not None:
                poll_faults.append(gap_fault)
            poll_faults.append(
                {
                    "type": type(error).__name__,
                    "message": str(error),
                    "phase": "qtest-safety-timing",
                    "sampleStartGapSeconds": gap,
                    "snapshot": snapshot,
                    "safetyFaults": safety_faults,
                }
            )
            break
        try:
            safety_faults = _partial_numeric_safety_faults(snapshot)
            sample["safetyFaults"] = safety_faults
            sample["capturedAt"] = utc_now()
            readback = gate_readback(snapshot, mask)
        except BaseException as error:
            safety_faults = _partial_numeric_safety_faults(snapshot)
            sample["safetyFaults"] = safety_faults
            if gap_fault is not None:
                poll_faults.append(gap_fault)
            poll_faults.append(
                {
                    "type": type(error).__name__,
                    "message": str(error),
                    "phase": "qtest-safety-parse",
                    "sampleStartGapSeconds": gap,
                    "sampleDurationSeconds": sample_duration,
                    "actualElapsedSeconds": actual_elapsed,
                    "snapshot": snapshot,
                    "safetyFaults": safety_faults,
                }
            )
            break
        sample["readback"] = readback
        sample["partial"] = False

        # Safety evidence is derived before a timing miss is classified.  If
        # both happen in one read, the caller can therefore preserve the
        # safety verdict instead of downgrading it to fixture-invalid.
        if gap_fault is not None:
            poll_faults.append(gap_fault)
        if sample_duration > maximum_poll_interval:
            poll_faults.append(
                {
                    "type": "SafetyPollReadDurationExceeded",
                    "message": (
                        "one Correctable-only safety read exceeded "
                        f"{maximum_poll_interval:.6f}s: observed "
                        f"{sample_duration:.6f}s"
                    ),
                    "observedSeconds": sample_duration,
                    "maximumSeconds": maximum_poll_interval,
                }
            )

        while (
            target_index < len(target_delays)
            and actual_elapsed >= target_delays[target_index]
        ):
            target_delay = target_delays[target_index]
            timeline.append(
                {
                    "delaySeconds": target_delay,
                    "targetDelaySeconds": target_delay,
                    "actualElapsedSeconds": actual_elapsed,
                    "sampleIndex": sample["sampleIndex"],
                    "capturedAt": sample["capturedAt"],
                    "readback": sample["readback"],
                    "safetyFaults": safety_faults,
                    "snapshot": snapshot,
                }
            )
            target_index += 1
            record["completedTargetCount"] = target_index

        if (
            (safety_faults and stop_on_safety_fault)
            or poll_faults
        ):
            break
        prior_sample_started = sample_started
        next_poll_at += target_poll_interval

    safety_events.clear()
    for item in samples:
        item_faults = list(
            item.get("safetyFaults")
            or _partial_numeric_safety_faults(item.get("snapshot"))
        )
        if item_faults:
            item["safetyFaults"] = item_faults
            safety_events.append(
                {
                    "sampleIndex": item.get("sampleIndex"),
                    "actualElapsedSeconds": item.get(
                        "actualElapsedSeconds"
                    ),
                    "faults": item_faults,
                    "snapshot": item.get("snapshot"),
                }
            )
    safety_events.extend(
        {
            "sampleIndex": None,
            "actualElapsedSeconds": item.get("actualElapsedSeconds"),
            "faults": list(item["safetyFaults"]),
            "snapshot": item.get("snapshot"),
            "phase": item.get("phase"),
        }
        for item in poll_faults
        if (
            isinstance(item, dict)
            and isinstance(item.get("safetyFaults"), list)
            and item["safetyFaults"]
        )
    )
    record.update(
        {
            "maximumObservedPollGapSeconds": maximum_observed_gap,
            "maximumObservedReadDurationSeconds": (
                maximum_observed_read_duration
            ),
            "sampleCount": len(samples),
            "completedTargetCount": target_index,
            "complete": (
                target_index == len(target_delays)
                and not poll_faults
                and not safety_events
            ),
        }
    )
    try:
        record["finishedAt"] = utc_now()
    except BaseException as error:
        poll_faults.append(
            {
                "type": type(error).__name__,
                "message": str(error),
                "phase": "safety-poll-finalization",
            }
        )
        record["complete"] = False
    return record


def close_continuous_safety_poll(
    poll: dict[str, Any],
    *,
    started_at: float,
    mode: str,
    stop_confirmed_at: float | None,
) -> None:
    """Bind the last sample to the runnable-window closure decision."""

    maximum = poll.get("maximumPollIntervalSeconds")
    maximum = (
        float(maximum)
        if isinstance(maximum, (int, float))
        and not isinstance(maximum, bool)
        else None
    )
    samples = poll.get("samples")
    samples = samples if isinstance(samples, list) else []
    last_elapsed = None
    if samples and isinstance(samples[-1], dict):
        raw_elapsed = samples[-1].get("actualElapsedSeconds")
        if isinstance(raw_elapsed, (int, float)) and not isinstance(
            raw_elapsed,
            bool,
        ):
            last_elapsed = float(raw_elapsed)
    stop_elapsed = (
        stop_confirmed_at - started_at
        if stop_confirmed_at is not None
        else None
    )
    tail_gap = (
        stop_elapsed - last_elapsed
        if stop_elapsed is not None and last_elapsed is not None
        else None
    )
    closure = {
        "mode": mode,
        "stopConfirmed": stop_confirmed_at is not None,
        "stopConfirmedElapsedSeconds": stop_elapsed,
        "lastSampleFinishedElapsedSeconds": last_elapsed,
        "tailGapSeconds": tail_gap,
    }
    poll["closure"] = closure
    if mode == "STOP_UNCONFIRMED":
        poll["complete"] = False
    if (
        tail_gap is not None
        and maximum is not None
        and tail_gap > maximum
    ):
        poll.setdefault("pollFaults", []).append(
            {
                "type": "SafetyPollTailGapExceeded",
                "message": (
                    "last safety sample to paused ACK exceeded "
                    f"{maximum:.6f}s: observed {tail_gap:.6f}s"
                ),
                "observedSeconds": tail_gap,
                "maximumSeconds": maximum,
            }
        )
        poll["complete"] = False


def _record_gate_tail_control_fault(
    poll: dict[str, Any],
    error: BaseException,
    *,
    phase: str,
) -> None:
    """Persist a control fault without trusting the existing poll shape."""

    raw_faults = poll.get("pollFaults")
    if isinstance(raw_faults, list):
        poll_faults = raw_faults
    else:
        poll_faults = []
        poll["pollFaults"] = poll_faults
    poll_faults.append(
        {
            "type": type(error).__name__,
            "message": str(error),
            "phase": phase,
        }
    )
    poll["complete"] = False


def _shutdown_gate_tail_executor(
    executor: concurrent.futures.ThreadPoolExecutor,
    poll: dict[str, Any],
) -> None:
    """Boundedly retry executor shutdown after an interrupt during join."""

    for attempt in (1, 2):
        try:
            executor.shutdown(wait=True, cancel_futures=True)
            return
        except BaseException as shutdown_error:
            _record_gate_tail_control_fault(
                poll,
                shutdown_error,
                phase=(
                    "safety-poll-tail-executor-shutdown"
                    f"-attempt-{attempt}"
                ),
            )


def _sync_stop_after_gate_tail_bootstrap_fault(
    monitor: Path,
    poll: dict[str, Any],
    error: BaseException,
    *,
    phase: str,
    executor: concurrent.futures.ThreadPoolExecutor | None = None,
) -> tuple[dict[str, Any], float]:
    """Fail-stop when tail sampling cannot be bootstrapped.

    The continuous sampler can legitimately return no sample when its first
    QTest read fails.  Likewise, thread creation can fail before the asynchronous
    HMP stop is submitted.  Neither condition may leave the already-resumed
    QEMU running merely because there is no tail sample to extend.
    """

    _record_gate_tail_control_fault(poll, error, phase=phase)
    if executor is not None:
        _shutdown_gate_tail_executor(executor, poll)
    try:
        transition = transition_qemu(monitor, "stop", "paused")
        stop_confirmed_at = time.monotonic()
    except BaseException as stop_error:
        _record_gate_tail_control_fault(
            poll,
            stop_error,
            phase="safety-poll-tail-fallback-stop",
        )
        raise
    try:
        poll["finishedAt"] = utc_now()
    except BaseException as finalization_error:
        _record_gate_tail_control_fault(
            poll,
            finalization_error,
            phase="safety-poll-tail-fallback-finalization",
        )
    return transition, stop_confirmed_at


def _transition_qemu_stop_while_sampling_gate_tail(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    poll: dict[str, Any],
    *,
    started_at: float,
    topology: dict[str, Any],
) -> tuple[dict[str, Any], float]:
    """Keep the numeric poll live until the stop/status transaction returns.

    Reaching the final target delay does not close the runnable interval.  HMP
    ``stop`` and its subsequent ``info status`` readback can take longer than
    one safety-poll deadline, so execute that transaction on one worker while
    the calling thread continues the pinned-topology QTest reads.  The returned
    timestamp is captured only after the worker has produced the paused ACK.
    """

    maximum_raw = poll.get("maximumPollIntervalSeconds")
    target_raw = poll.get("targetPollIntervalSeconds")
    if (
        not isinstance(maximum_raw, (int, float))
        or isinstance(maximum_raw, bool)
        or float(maximum_raw) <= 0
        or not isinstance(target_raw, (int, float))
        or isinstance(target_raw, bool)
        or float(target_raw) <= 0
        or float(target_raw) > float(maximum_raw)
    ):
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            TypeError("continuous gate poll timing envelope is malformed"),
            phase="safety-poll-tail-precondition",
        )
    maximum = float(maximum_raw)
    target = float(target_raw)
    samples = poll.get("samples")
    poll_faults = poll.get("pollFaults")
    safety_events = poll.get("safetyEvents")
    if (
        not isinstance(samples, list)
        or not samples
        or not isinstance(poll_faults, list)
        or not isinstance(safety_events, list)
    ):
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            TypeError("continuous gate poll has no appendable raw surface"),
            phase="safety-poll-tail-precondition",
        )

    terminal = samples[-1]
    if not isinstance(terminal, dict):
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            TypeError("continuous gate poll terminal sample is malformed"),
            phase="safety-poll-tail-precondition",
        )
    terminal_elapsed = terminal.get("actualElapsedSeconds")
    terminal_duration = terminal.get("sampleDurationSeconds")
    if (
        not isinstance(terminal_elapsed, (int, float))
        or isinstance(terminal_elapsed, bool)
        or not isinstance(terminal_duration, (int, float))
        or isinstance(terminal_duration, bool)
    ):
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            TypeError("continuous gate poll terminal timing is malformed"),
            phase="safety-poll-tail-precondition",
        )
    prior_sample_started = (
        started_at + float(terminal_elapsed) - float(terminal_duration)
    )
    next_poll_at = prior_sample_started + target
    try:
        maximum_observed_gap = float(
            poll.get("maximumObservedPollGapSeconds", 0.0)
        )
        maximum_observed_read_duration = float(
            poll.get("maximumObservedReadDurationSeconds", 0.0)
        )
    except (TypeError, ValueError) as error:
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            error,
            phase="safety-poll-tail-precondition",
        )

    executor: concurrent.futures.ThreadPoolExecutor | None = None
    try:
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="esxi-aer-gate-stop",
        )
        stop_future = executor.submit(
            transition_qemu,
            monitor,
            "stop",
            "paused",
        )
    except BaseException as error:
        return _sync_stop_after_gate_tail_bootstrap_fault(
            monitor,
            poll,
            error,
            phase="safety-poll-tail-executor-bootstrap",
            executor=executor,
        )
    assert executor is not None
    tail_faulted = False
    transition: dict[str, Any] | None = None
    stop_confirmed_at: float | None = None
    stop_error: BaseException | None = None
    try:
        while not stop_future.done() and not tail_faulted:
            try:
                remaining = next_poll_at - time.monotonic()
                if remaining > 0:
                    done, _pending = concurrent.futures.wait(
                        (stop_future,),
                        timeout=remaining,
                    )
                    if done:
                        break
                if stop_future.done():
                    break
                sample_started = time.monotonic()
            except BaseException as error:
                poll_faults.append(
                    {
                        "type": type(error).__name__,
                        "message": str(error),
                        "phase": "safety-poll-tail-scheduler",
                    }
                )
                tail_faulted = True
                break

            gap = sample_started - prior_sample_started
            maximum_observed_gap = max(maximum_observed_gap, gap)
            poll["maximumObservedPollGapSeconds"] = maximum_observed_gap
            gap_fault: dict[str, Any] | None = None
            if gap > maximum:
                gap_fault = {
                    "type": "SafetyPollGapExceeded",
                    "message": (
                        "Correctable-only safety polling exceeded "
                        f"{maximum:.6f}s during paused-ACK wait: "
                        f"observed {gap:.6f}s"
                    ),
                    "observedSeconds": gap,
                    "maximumSeconds": maximum,
                }

            try:
                snapshot = outer_qemu_aer_snapshot(
                    socket_path,
                    endpoint_bdf,
                    root_bdf,
                    topology=topology,
                )
            except BaseException as error:
                if gap_fault is not None:
                    poll_faults.append(gap_fault)
                poll_faults.append(
                    {
                        "type": type(error).__name__,
                        "message": str(error),
                        "phase": "qtest-safety-tail-read",
                        "sampleStartGapSeconds": gap,
                    }
                )
                tail_faulted = True
                break

            sample: dict[str, Any] = {
                "sampleIndex": len(samples),
                "actualElapsedSeconds": None,
                "sampleStartGapSeconds": gap,
                "sampleDurationSeconds": None,
                "capturedAt": None,
                "readback": None,
                "safetyFaults": [],
                "snapshot": snapshot,
                "partial": True,
            }
            samples.append(sample)
            poll["sampleCount"] = len(samples)
            try:
                sample_finished = time.monotonic()
                sample_duration = sample_finished - sample_started
                maximum_observed_read_duration = max(
                    maximum_observed_read_duration,
                    sample_duration,
                )
                poll["maximumObservedReadDurationSeconds"] = (
                    maximum_observed_read_duration
                )
                actual_elapsed = sample_finished - started_at
                sample["sampleDurationSeconds"] = sample_duration
                sample["actualElapsedSeconds"] = actual_elapsed
            except BaseException as error:
                safety_faults = _partial_numeric_safety_faults(snapshot)
                sample["safetyFaults"] = safety_faults
                if gap_fault is not None:
                    poll_faults.append(gap_fault)
                poll_faults.append(
                    {
                        "type": type(error).__name__,
                        "message": str(error),
                        "phase": "qtest-safety-tail-timing",
                        "sampleStartGapSeconds": gap,
                        "snapshot": snapshot,
                        "safetyFaults": safety_faults,
                    }
                )
                tail_faulted = True
                break

            try:
                safety_faults = _partial_numeric_safety_faults(snapshot)
                sample["safetyFaults"] = safety_faults
                sample["capturedAt"] = utc_now()
                sample["readback"] = gate_readback(snapshot, mask)
                sample["partial"] = False
            except BaseException as error:
                safety_faults = _partial_numeric_safety_faults(snapshot)
                sample["safetyFaults"] = safety_faults
                if gap_fault is not None:
                    poll_faults.append(gap_fault)
                poll_faults.append(
                    {
                        "type": type(error).__name__,
                        "message": str(error),
                        "phase": "qtest-safety-tail-parse",
                        "sampleStartGapSeconds": gap,
                        "sampleDurationSeconds": sample_duration,
                        "actualElapsedSeconds": actual_elapsed,
                        "snapshot": snapshot,
                        "safetyFaults": safety_faults,
                    }
                )
                tail_faulted = True
                break

            if gap_fault is not None:
                poll_faults.append(gap_fault)
                tail_faulted = True
            if sample_duration > maximum:
                poll_faults.append(
                    {
                        "type": "SafetyPollReadDurationExceeded",
                        "message": (
                            "one Correctable-only safety read exceeded "
                            f"{maximum:.6f}s during paused-ACK wait: "
                            f"observed {sample_duration:.6f}s"
                        ),
                        "observedSeconds": sample_duration,
                        "maximumSeconds": maximum,
                    }
                )
                tail_faulted = True
            if safety_faults:
                tail_faulted = True
            prior_sample_started = sample_started
            next_poll_at = sample_started + target

        try:
            transition = stop_future.result()
            stop_confirmed_at = time.monotonic()
        except BaseException as error:
            stop_error = error
    finally:
        _shutdown_gate_tail_executor(executor, poll)

    safety_events.clear()
    for item in samples:
        if not isinstance(item, dict):
            continue
        item_faults = list(
            item.get("safetyFaults")
            or _partial_numeric_safety_faults(item.get("snapshot"))
        )
        if item_faults:
            item["safetyFaults"] = item_faults
            safety_events.append(
                {
                    "sampleIndex": item.get("sampleIndex"),
                    "actualElapsedSeconds": item.get(
                        "actualElapsedSeconds"
                    ),
                    "faults": item_faults,
                    "snapshot": item.get("snapshot"),
                }
            )
    safety_events.extend(
        {
            "sampleIndex": None,
            "actualElapsedSeconds": item.get("actualElapsedSeconds"),
            "faults": list(item["safetyFaults"]),
            "snapshot": item.get("snapshot"),
            "phase": item.get("phase"),
        }
        for item in poll_faults
        if (
            isinstance(item, dict)
            and isinstance(item.get("safetyFaults"), list)
            and item["safetyFaults"]
        )
    )
    target_count = poll.get("targetCount")
    completed_target_count = poll.get("completedTargetCount")
    poll.update(
        {
            "maximumObservedPollGapSeconds": maximum_observed_gap,
            "maximumObservedReadDurationSeconds": (
                maximum_observed_read_duration
            ),
            "sampleCount": len(samples),
            "complete": bool(
                isinstance(target_count, int)
                and not isinstance(target_count, bool)
                and isinstance(completed_target_count, int)
                and not isinstance(completed_target_count, bool)
                and completed_target_count == target_count
                and not poll_faults
                and not safety_events
            ),
        }
    )
    try:
        poll["finishedAt"] = utc_now()
    except BaseException as error:
        poll_faults.append(
            {
                "type": type(error).__name__,
                "message": str(error),
                "phase": "safety-poll-tail-finalization",
            }
        )
        poll["complete"] = False
    if stop_error is not None:
        raise stop_error
    if transition is None or stop_confirmed_at is None:
        raise RuntimeError("paused ACK transition result was not retained")
    return transition, stop_confirmed_at


def _partial_numeric_safety_faults(value: Any) -> list[str]:
    """Recover known numeric safety faults from an arbitrary partial record."""

    faults: list[str] = []
    seen: set[int] = set()

    def parsed(container: dict[str, Any], key: str) -> int | None:
        value = container.get(key)
        if isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def snapshot_faults(snapshot: dict[str, Any]) -> list[str]:
        """Read the five fail-stop registers without using a summary parser.

        This intentionally duplicates the tiny closed safety surface.  A
        control interruption or bug in ``outer_snapshot_safety_faults`` must
        not erase a raw UES/Device Status/Root Error Status value that was
        already captured.
        """

        endpoint_raw = snapshot.get("endpointState")
        root_raw = snapshot.get("rootState")
        endpoint = endpoint_raw if isinstance(endpoint_raw, dict) else {}
        root = root_raw if isinstance(root_raw, dict) else {}
        local: list[str] = []
        endpoint_ues = parsed(endpoint, "uncorrectableErrorStatus")
        if endpoint_ues:
            local.append(f"endpoint UES=0x{endpoint_ues:08x}")
        endpoint_status = parsed(endpoint, "deviceStatus")
        if endpoint_status is not None:
            non_ced = endpoint_status & (
                qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                ^ qemu_aer.PCI_EXP_DEVSTA_CED
            )
            if non_ced:
                local.append(
                    f"endpoint DeviceStatus non-CED=0x{non_ced:04x}"
                )
        root_ues = parsed(root, "uncorrectableErrorStatus")
        if root_ues:
            local.append(f"root UES=0x{root_ues:08x}")
        root_status = parsed(root, "deviceStatus")
        if root_status is not None:
            root_errors = root_status & (
                qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                ^ qemu_aer.PCI_EXP_DEVSTA_CED
            )
            if root_errors:
                local.append(
                    f"root DeviceStatus error=0x{root_errors:04x}"
                )
        root_error_status = parsed(root, "rootErrorStatus")
        if root_error_status is not None:
            root_uncorrectable = (
                root_error_status & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK
            )
            if root_uncorrectable:
                local.append(
                    "root uncorrectable reception="
                    f"0x{root_uncorrectable:08x}"
                )
        return local

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            identity = id(item)
            if identity in seen:
                return
            seen.add(identity)
            if "endpointState" in item or "rootState" in item:
                faults.extend(snapshot_faults(item))
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            identity = id(item)
            if identity in seen:
                return
            seen.add(identity)
            for child in item:
                visit(child)

    visit(value)
    return list(dict.fromkeys(faults))


def _close_partial_gate_poll(
    record: dict[str, Any],
    evidence_sink: dict[str, Any],
    *,
    stop_confirmed_at: float | None,
) -> None:
    timeline = record.get("timeline")
    if not isinstance(timeline, dict):
        return
    poll = timeline.get("resumedSafetyPoll")
    started_at = evidence_sink.get("resumeStartedAt")
    if (
        not isinstance(poll, dict)
        or not isinstance(started_at, (int, float))
        or isinstance(started_at, bool)
    ):
        return
    try:
        close_continuous_safety_poll(
            poll,
            started_at=float(started_at),
            mode=(
                "PAUSED_ACK"
                if stop_confirmed_at is not None
                else "STOP_UNCONFIRMED"
            ),
            stop_confirmed_at=stop_confirmed_at,
        )
    except BaseException as error:
        record["safetyPollClosureFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }


def _record_resumed_gate_effective(
    record: dict[str, Any],
    samples: list[dict[str, Any]],
    poll_faults: list[dict[str, Any]],
) -> None:
    """Record current versus last-confirmed readback without hiding partials.

    The continuous sampler deliberately commits a raw snapshot before its
    semantic ``gate_readback``.  A parser/control interruption therefore leaves
    a legitimate terminal sample with ``partial=True`` and ``readback=None``.
    That is not proof of the current effective tuple, but neither is it a
    malformed sampler result.  Keep current effectiveness unconfirmed, retain
    the latest older confirmed readback separately, and require an exact
    producer fault binding so arbitrary malformed samples still fail closed.
    """

    def usable_readback(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and isinstance(value.get("tuple"), dict)
            and isinstance(value.get("raw"), dict)
            and isinstance(value.get("rootPath"), dict)
        )

    paused = record.get("timeline", {}).get("pausedApplied", {})
    paused_readback = (
        paused.get("readback") if isinstance(paused, dict) else None
    )
    if not usable_readback(paused_readback):
        raise TypeError("paused gate readback is missing or malformed")

    terminal_readback: dict[str, Any] | None = None
    effective_source = "NO_RESUMED_SAMPLE"
    if samples:
        terminal = samples[-1]
        if not isinstance(terminal, dict):
            raise TypeError("terminal resumed sample is not an object")
        if "readback" not in terminal:
            raise KeyError("readback")
        candidate = terminal.get("readback")
        if usable_readback(candidate):
            if terminal.get("partial") is not False:
                raise TypeError(
                    "terminal resumed sample readback is not explicitly "
                    "complete"
                )
            terminal_readback = candidate
            effective_source = "RESUMED_TERMINAL_SAMPLE"
        else:
            snapshot = terminal.get("snapshot")
            bound_partial_fault = any(
                isinstance(fault, dict)
                and fault.get("phase")
                in {"qtest-safety-parse", "qtest-safety-timing"}
                and fault.get("snapshot") is snapshot
                for fault in poll_faults
            )
            if (
                candidate is not None
                or terminal.get("partial") is not True
                or not isinstance(snapshot, dict)
                or not bound_partial_fault
            ):
                raise TypeError(
                    "terminal resumed readback is missing without a bound "
                    "partial-sampler fault"
                )
            effective_source = "UNCONFIRMED_PARTIAL_SAMPLE"

    last_confirmed: dict[str, Any] | None = None
    last_confirmed_source = "PAUSED_APPLIED_FALLBACK"
    for index in range(len(samples) - 1, -1, -1):
        sample = samples[index]
        if not isinstance(sample, dict):
            raise TypeError("resumed sample is not an object")
        candidate = sample.get("readback")
        if candidate is None:
            continue
        if not usable_readback(candidate):
            raise TypeError("resumed gate readback is malformed")
        if sample.get("partial") is not False:
            raise TypeError(
                "last-confirmed resumed readback is not explicitly complete"
            )
        last_confirmed = candidate
        last_confirmed_source = f"RESUMED_SAMPLE_{index}"
        break
    if last_confirmed is None:
        last_confirmed = paused_readback

    record["effective"] = copy.deepcopy(terminal_readback)
    record["effectiveSource"] = effective_source
    record["lastConfirmedEffective"] = copy.deepcopy(last_confirmed)
    record["lastConfirmedEffectiveSource"] = last_confirmed_source
    root_path = record.setdefault("rootPathLease", {})
    if not isinstance(root_path, dict):
        raise TypeError("rootPathLease is not an object")
    root_path["effective"] = (
        copy.deepcopy(terminal_readback["rootPath"])
        if terminal_readback is not None
        else None
    )
    root_path["effectiveSource"] = effective_source
    root_path["lastConfirmedEffective"] = copy.deepcopy(
        last_confirmed["rootPath"]
    )
    root_path["lastConfirmedEffectiveSource"] = last_confirmed_source


def _apply_gate_lease_impl(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    requested: GateTuple,
    *,
    enable_root_path: bool,
    timeline_delays: Iterable[float] = GATE_STABILITY_DELAYS,
    maximum_safety_poll_interval: float | None = None,
    safety_poll_target_interval: float | None = None,
    hold_paused_after_sampling: bool = False,
    _partial_evidence_sink: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lease: dict[str, Any] = {
        "safetyBoundary": "PRE_INJECTION",
        "safetyWindowKind": "GATE_LEASE_APPLY",
        "requested": requested.as_dict(),
        "rootPathLease": {
            "managed": enable_root_path,
            "requested": (
                RootPathState(True, True).as_dict()
                if enable_root_path
                else None
            ),
        },
        "startedAt": utc_now(),
        "timeline": {},
        "outcome": "APPLYING",
    }
    if _partial_evidence_sink is not None:
        _partial_evidence_sink["record"] = lease
    paused = False
    writes_started = False
    resume_allowed = False
    original: dict[str, Any] | None = None
    resume_started_at: float | None = None
    try:
        lease["timeline"]["pause"] = transition_qemu(monitor, "stop", "paused")
        paused = True
        original = outer_qemu_aer_snapshot(
            socket_path, endpoint_bdf, root_bdf
        )
        # Persist the complete numeric read before parsing any safety or gate
        # predicate.  A failed RHS assignment in the caller must never erase
        # an observed UES/DeviceStatus/RootErrorStatus value.
        lease["original"] = {
            "capturedAt": None,
            "readback": None,
            "snapshot": original,
        }
        lease["original"]["capturedAt"] = utc_now()
        faults = _partial_numeric_safety_faults(original)
        lease["original"]["safetyFaults"] = faults
        if faults:
            raise SafetyViolation(
                "unsafe state before gate application: " + "; ".join(faults)
            )
        correctable_noise = outer_snapshot_correctable_noise(original)
        if correctable_noise:
            raise InconclusiveObservation(
                "Correctable background state appeared between baseline clear "
                "and gate application: " + "; ".join(correctable_noise)
            )
        lease["original"]["readback"] = gate_readback(original, mask)
        original_root_path = root_path_from_snapshot(original)
        lease["rootPathLease"]["original"] = original_root_path.as_dict()
        requested_root_path = (
            RootPathState(True, True)
            if enable_root_path
            else original_root_path
        )
        client = qemu_aer.QTestClient(socket_path)
        try:
            writes_started = True
            resume_allowed = False
            write_gate_tuple(
                client,
                original,
                requested,
                mask,
                clear_correctable=True,
                root_path=requested_root_path if enable_root_path else None,
            )
        finally:
            client.close()
        paused_applied = outer_qemu_aer_snapshot(
            socket_path, endpoint_bdf, root_bdf
        )
        paused_record: dict[str, Any] = {
            "capturedAt": None,
            "readback": None,
            "checks": None,
            "safetyFaults": [],
            "snapshot": paused_applied,
            "partial": True,
        }
        lease["timeline"]["pausedApplied"] = paused_record
        paused_record["safetyFaults"] = _partial_numeric_safety_faults(
            paused_applied
        )
        paused_checks = gate_non_target_checks(original, paused_applied, mask)
        paused_checks["requestedTupleReadBack"] = (
            gate_tuple_from_snapshot(paused_applied, mask) == requested
        )
        paused_checks["requestedRootPathReadBack"] = (
            root_path_from_snapshot(paused_applied) == requested_root_path
        )
        paused_faults = _partial_numeric_safety_faults(paused_applied)
        paused_checks["noUncorrectableSideEffect"] = not paused_faults
        paused_record.update(
            {
                "capturedAt": utc_now(),
                "readback": gate_readback(paused_applied, mask),
                "checks": paused_checks,
                "safetyFaults": paused_faults,
                "partial": False,
            }
        )
        resume_allowed = all(paused_checks.values())
    except BaseException as error:
        if writes_started and original is not None:
            try:
                client = qemu_aer.QTestClient(socket_path)
                try:
                    write_gate_tuple(
                        client,
                        original,
                        gate_tuple_from_snapshot(original, mask),
                        mask,
                        clear_correctable=False,
                        root_path=(
                            root_path_from_snapshot(original)
                            if enable_root_path
                            else None
                        ),
                    )
                finally:
                    client.close()
                rolled_back = outer_qemu_aer_snapshot(
                    socket_path, endpoint_bdf, root_bdf
                )
                rollback_record: dict[str, Any] = {
                    "capturedAt": None,
                    "readback": None,
                    "checks": None,
                    "safetyFaults": [],
                    "snapshot": rolled_back,
                    "partial": True,
                }
                lease["partialApplyRollback"] = rollback_record
                rollback_record["safetyFaults"] = (
                    _partial_numeric_safety_faults(rolled_back)
                )
                rollback_checks = gate_non_target_checks(
                    original, rolled_back, mask
                )
                rollback_checks["originalTupleReadBack"] = (
                    gate_tuple_from_snapshot(rolled_back, mask)
                    == gate_tuple_from_snapshot(original, mask)
                )
                rollback_checks["originalRootPathReadBack"] = (
                    root_path_from_snapshot(rolled_back)
                    == root_path_from_snapshot(original)
                )
                rollback_record.update(
                    {
                        "capturedAt": utc_now(),
                        "readback": gate_readback(rolled_back, mask),
                        "checks": rollback_checks,
                        "safetyFaults": (
                            _partial_numeric_safety_faults(rolled_back)
                        ),
                        "partial": False,
                    }
                )
                if lease["partialApplyRollback"]["safetyFaults"]:
                    raise SafetyViolation(
                        "gate apply rollback exposed Uncorrectable evidence: "
                        + "; ".join(
                            lease["partialApplyRollback"]["safetyFaults"]
                        )
                    )
                if not all(rollback_checks.values()):
                    raise InconclusiveObservation(
                        "gate apply failed and paused rollback did not read back"
                    )
            except BaseException as restore_error:
                lease["outcome"] = "ROLLBACK_FAILED"
                lease["applyFault"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
                lease["rollbackFault"] = {
                    "type": type(restore_error).__name__,
                    "message": str(restore_error),
                }
                lease["finishedAt"] = utc_now()
                raise GateLeaseApplyFailure(
                    "gate apply failed and paused rollback also failed: "
                    f"{type(error).__name__}: {error}; "
                    f"{type(restore_error).__name__}: {restore_error}",
                    lease,
                    safety=(
                        isinstance(error, SafetyViolation)
                        or isinstance(restore_error, SafetyViolation)
                    ),
                ) from restore_error
            lease["outcome"] = "ROLLED_BACK_AFTER_APPLY_FAILURE"
            lease["applyFault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            lease["finishedAt"] = utc_now()
            raise GateLeaseApplyFailure(
                "gate apply failed after writes; paused rollback read back",
                lease,
                safety=isinstance(error, SafetyViolation),
            ) from error
        lease["outcome"] = (
            "PRE_WRITE_SAFETY_FAULT_HELD_PAUSED"
            if isinstance(error, SafetyViolation)
            else "PRE_WRITE_APPLY_FAILED_HELD_PAUSED"
        )
        lease["applyFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        lease["qemuHeldPaused"] = paused
        lease["finishedAt"] = utc_now()
        raise GateLeaseApplyFailure(
            "gate apply failed before writes; partial numeric evidence was "
            "retained and QEMU was left paused",
            lease,
            safety=isinstance(error, SafetyViolation),
        ) from error
    finally:
        if paused:
            if resume_allowed:
                try:
                    resume_started_at = time.monotonic()
                    if _partial_evidence_sink is not None:
                        _partial_evidence_sink[
                            "resumeStartedAt"
                        ] = resume_started_at
                    lease["timeline"]["resume"] = transition_qemu(
                        monitor, "cont", "running"
                    )
                except BaseException as resume_error:
                    lease["outcome"] = "RESUME_FAILED_AFTER_APPLY"
                    lease["resumeFault"] = {
                        "type": type(resume_error).__name__,
                        "message": str(resume_error),
                    }
                    try:
                        lease["timeline"]["resumeFailureHold"] = (
                            transition_qemu(
                                monitor,
                                "stop",
                                "paused",
                            )
                        )
                        lease["qemuHeldPaused"] = True
                    except BaseException as hold_error:
                        lease["resumeFailureHoldFault"] = {
                            "type": type(hold_error).__name__,
                            "message": str(hold_error),
                        }
                    lease["finishedAt"] = utc_now()
                    if writes_started and original is not None:
                        raise GateLeaseApplyFailure(
                            "QEMU could not resume after gate application",
                            lease,
                            safety=False,
                        ) from resume_error
                    raise
            else:
                lease["timeline"]["heldPaused"] = {
                    "reason": (
                        "gate mutation did not pass paused readback and "
                        "safety checks"
                    ),
                    "observedAt": utc_now(),
                }

    if not resume_allowed:
        paused_checks = lease["timeline"]["pausedApplied"]["checks"]
        if not paused_checks["noUncorrectableSideEffect"]:
            lease["outcome"] = "SAFETY_FAULT_DURING_APPLY"
        elif not paused_checks["requestedRootPathReadBack"]:
            lease["outcome"] = "ROOT_PATH_BLOCKED"
        else:
            lease["outcome"] = "HARDWIRED_OR_PAUSED_READBACK_MISMATCH"
        lease["effective"] = lease["timeline"]["pausedApplied"]["readback"]
        lease["rootPathLease"]["effective"] = lease["effective"]["rootPath"]
        lease["rootPathLease"]["stable"] = False
        lease["finishedAt"] = utc_now()
        return lease

    if maximum_safety_poll_interval is None:
        samples = sample_gate_timeline(
            socket_path,
            endpoint_bdf,
            root_bdf,
            mask,
            delays=timeline_delays,
        )
        safety_poll = None
    else:
        if safety_poll_target_interval is None:
            raise ValueError(
                "continuous gate sampling requires a target poll interval"
            )
        if resume_started_at is None:
            raise AssertionError("gate resume start timestamp was not captured")
        try:
            safety_poll = {}
            lease["timeline"]["resumedSafetyPoll"] = safety_poll
            safety_poll = sample_gate_timeline_continuous(
                socket_path,
                endpoint_bdf,
                root_bdf,
                mask,
                timeline_delays,
                started_at=resume_started_at,
                maximum_poll_interval=maximum_safety_poll_interval,
                target_poll_interval=safety_poll_target_interval,
                safety_boundary="PRE_INJECTION",
                topology=paused_applied,
                _partial_record=safety_poll,
            )
        except BaseException as sampler_error:
            lease["postResumeSamplerFault"] = {
                "type": type(sampler_error).__name__,
                "message": str(sampler_error),
            }
            try:
                lease["timeline"]["samplerFailureHold"] = transition_qemu(
                    monitor,
                    "stop",
                    "paused",
                )
                lease["qemuHeldPaused"] = True
                lease["outcome"] = "POST_RESUME_SAMPLER_FAILED_HELD_PAUSED"
            except BaseException as hold_error:
                lease["samplerFailureHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
                lease["outcome"] = (
                    "POST_RESUME_SAMPLER_AND_HOLD_UNCONFIRMED"
                )
            lease["finishedAt"] = utc_now()
            raise GateLeaseApplyFailure(
                "gate apply post-resume sampler failed; fail-stop was "
                "attempted",
                lease,
                safety=False,
            ) from sampler_error
        lease["timeline"]["resumedSafetyPoll"] = safety_poll
        lease["timeline"]["resumedTargetSamples"] = safety_poll["timeline"]
        samples = safety_poll["samples"]
    lease["timeline"]["resumedSamples"] = samples
    paused_checks = lease["timeline"]["pausedApplied"]["checks"]
    if safety_poll is not None:
        resumed_faults = [
            {
                "delaySeconds": item.get("actualElapsedSeconds"),
                "faults": list(item.get("faults") or []),
                "snapshot": copy.deepcopy(item.get("snapshot")),
                "phase": item.get("phase"),
            }
            for item in safety_poll.get("safetyEvents", [])
            if isinstance(item, dict) and item.get("faults")
        ]
    else:
        resumed_faults = [
            {
                "delaySeconds": item.get(
                    "delaySeconds",
                    item.get("actualElapsedSeconds"),
                ),
                "faults": list(
                    item.get("safetyFaults")
                    or _partial_numeric_safety_faults(item["snapshot"])
                ),
                "snapshot": copy.deepcopy(item.get("snapshot")),
            }
            for item in samples
            if (
                item.get("safetyFaults")
                or _partial_numeric_safety_faults(item["snapshot"])
            )
        ]
    lease["resumedSafetyFaults"] = resumed_faults
    poll_faults = (
        list(safety_poll.get("pollFaults") or [])
        if safety_poll is not None
        else []
    )
    if not samples:
        missing_sample = {
            "type": "MissingSafetySample",
            "message": "no resumed QTest safety sample was retained",
        }
        if not poll_faults:
            poll_faults.append(missing_sample)
            if safety_poll is not None:
                safety_poll.setdefault("pollFaults", []).append(
                    missing_sample
                )
                safety_poll["complete"] = False
    _record_resumed_gate_effective(lease, samples, poll_faults)
    if resumed_faults or poll_faults or hold_paused_after_sampling:
        try:
            hold_label = (
                "safetyHold"
                if resumed_faults
                else (
                    "pollDeadlineHold"
                    if poll_faults
                    else "postSamplingHold"
                )
            )
            if safety_poll is not None and resume_started_at is not None:
                (
                    lease["timeline"][hold_label],
                    stop_confirmed_at,
                ) = _transition_qemu_stop_while_sampling_gate_tail(
                    monitor,
                    socket_path,
                    endpoint_bdf,
                    root_bdf,
                    mask,
                    safety_poll,
                    started_at=resume_started_at,
                    topology=paused_applied,
                )
            else:
                lease["timeline"][hold_label] = transition_qemu(
                    monitor, "stop", "paused"
                )
                stop_confirmed_at = time.monotonic()
            lease["qemuHeldPaused"] = True
            if safety_poll is not None and resume_started_at is not None:
                close_continuous_safety_poll(
                    safety_poll,
                    started_at=resume_started_at,
                    mode="PAUSED_ACK",
                    stop_confirmed_at=stop_confirmed_at,
                )
        except BaseException as hold_error:
            if safety_poll is not None and resume_started_at is not None:
                close_continuous_safety_poll(
                    safety_poll,
                    started_at=resume_started_at,
                    mode="STOP_UNCONFIRMED",
                    stop_confirmed_at=None,
                )
            if resumed_faults:
                lease["outcome"] = (
                    "SAFETY_FAULT_AND_HOLD_UNCONFIRMED"
                )
            elif poll_faults:
                lease["outcome"] = (
                    "SAFETY_POLL_INCOMPLETE_AND_HOLD_UNCONFIRMED"
                )
            else:
                lease["outcome"] = "POST_SAMPLING_HOLD_UNCONFIRMED"
            lease["safetyHoldFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            lease["finishedAt"] = utc_now()
            raise GateLeaseApplyFailure(
                "gate apply sampling could not close with QEMU confirmed "
                "paused",
                lease,
                safety=bool(resumed_faults),
            ) from hold_error
    elif safety_poll is not None and resume_started_at is not None:
        close_continuous_safety_poll(
            safety_poll,
            started_at=resume_started_at,
            mode="RUNNING_AFTER_TARGET_COVERAGE",
            stop_confirmed_at=None,
        )
    poll_faults = (
        list(safety_poll.get("pollFaults") or [])
        if safety_poll is not None
        else []
    )
    if safety_poll is not None:
        resumed_faults = [
            {
                "delaySeconds": item.get("actualElapsedSeconds"),
                "faults": list(item.get("faults") or []),
                "snapshot": copy.deepcopy(item.get("snapshot")),
                "phase": item.get("phase"),
            }
            for item in safety_poll.get("safetyEvents", [])
            if isinstance(item, dict) and item.get("faults")
        ]
        lease["resumedSafetyFaults"] = resumed_faults
        _record_resumed_gate_effective(lease, samples, poll_faults)
    if resumed_faults or not paused_checks["noUncorrectableSideEffect"]:
        lease["outcome"] = "SAFETY_FAULT_AFTER_APPLY"
        lease["rootPathLease"]["stable"] = False
    elif poll_faults or not samples:
        lease["outcome"] = "SAFETY_POLL_INCOMPLETE_AFTER_APPLY"
        lease["safetyPollFaults"] = poll_faults or [
            {
                "type": "MissingSafetySample",
                "message": "no resumed QTest safety sample was retained",
            }
        ]
        lease["rootPathLease"]["stable"] = False
    else:
        resumed_match = all(
            gate_tuple_from_snapshot(item["snapshot"], mask) == requested
            for item in samples
        )
        root_path_match = all(
            root_path_from_snapshot(item["snapshot"])
            == (
                RootPathState(True, True)
                if enable_root_path
                else root_path_from_snapshot(original)
            )
            for item in samples
        )
        if (
            not paused_checks["requestedRootPathReadBack"]
            or not root_path_match
        ):
            lease["outcome"] = "ROOT_PATH_BLOCKED"
        elif not all(paused_checks.values()):
            lease["outcome"] = "HARDWIRED_OR_PAUSED_READBACK_MISMATCH"
        elif not resumed_match:
            lease["outcome"] = "OVERRIDDEN_OR_UNSTABLE_AFTER_RESUME"
        else:
            lease["outcome"] = "EFFECTIVE"
        lease["rootPathLease"]["stable"] = root_path_match
    lease["finishedAt"] = utc_now()
    return lease


def apply_gate_lease(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    requested: GateTuple,
    *,
    enable_root_path: bool,
    timeline_delays: Iterable[float] = GATE_STABILITY_DELAYS,
    maximum_safety_poll_interval: float | None = None,
    safety_poll_target_interval: float | None = None,
    hold_paused_after_sampling: bool = False,
) -> dict[str, Any]:
    """Apply a lease with a final fail-stop boundary around all postprocessing."""

    evidence_sink: dict[str, Any] = {}
    try:
        return _apply_gate_lease_impl(
            monitor,
            socket_path,
            endpoint_bdf,
            root_bdf,
            mask,
            requested,
            enable_root_path=enable_root_path,
            timeline_delays=timeline_delays,
            maximum_safety_poll_interval=maximum_safety_poll_interval,
            safety_poll_target_interval=safety_poll_target_interval,
            hold_paused_after_sampling=hold_paused_after_sampling,
            _partial_evidence_sink=evidence_sink,
        )
    except GateLeaseApplyFailure:
        raise
    except BaseException as error:
        lease = evidence_sink.get("record")
        if not isinstance(lease, dict):
            lease = {
                "safetyBoundary": "PRE_INJECTION",
                "safetyWindowKind": "GATE_LEASE_APPLY",
                "startedAt": utc_now(),
                "timeline": {},
                "outcome": "APPLY_UNHANDLED_FAILURE",
            }
        lease["postProcessingFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        stop_confirmed_at: float | None = None
        try:
            timeline = lease.setdefault("timeline", {})
            if not isinstance(timeline, dict):
                timeline = {}
                lease["timeline"] = timeline
            timeline["unhandledFailureHold"] = transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            stop_confirmed_at = time.monotonic()
            lease["qemuHeldPaused"] = True
            lease["outcome"] = "APPLY_FAILURE_HELD_PAUSED"
        except BaseException as hold_error:
            lease["unhandledFailureHoldFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            lease["outcome"] = "APPLY_FAILURE_AND_HOLD_UNCONFIRMED"
        _close_partial_gate_poll(
            lease,
            evidence_sink,
            stop_confirmed_at=stop_confirmed_at,
        )
        numeric_safety_faults = _partial_numeric_safety_faults(lease)
        lease["numericSafetyFaults"] = numeric_safety_faults
        lease["finishedAt"] = utc_now()
        raise GateLeaseApplyFailure(
            "gate apply failed outside its normal transaction boundary; "
            "partial evidence was retained and an idempotent fail-stop was "
            "attempted",
            lease,
            safety=bool(numeric_safety_faults),
        ) from error


def _restore_gate_lease_impl(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    lease: dict[str, Any],
    *,
    safe_stop: bool,
    timeline_delays: Iterable[float] = (0.0, 0.1),
    maximum_safety_poll_interval: float | None = None,
    safety_poll_target_interval: float | None = None,
    hold_paused_after_sampling: bool = False,
    _partial_evidence_sink: dict[str, Any] | None = None,
) -> dict[str, Any]:
    original_snapshot = lease["original"]["snapshot"]
    root_path_managed = bool(lease["rootPathLease"]["managed"])
    original_root_path = root_path_from_snapshot(original_snapshot)
    requested = (
        GateTuple(False, True, False)
        if safe_stop
        else gate_tuple_from_snapshot(original_snapshot, mask)
    )
    result: dict[str, Any] = {
        "safetyBoundary": "POST_CLEANUP",
        "safetyWindowKind": "GATE_LEASE_RESTORE",
        "mode": "SAFE_STOP" if safe_stop else "RESTORE_ORIGINAL",
        "requested": requested.as_dict(),
        "rootPathLease": {
            "managed": root_path_managed,
            "requested": (
                original_root_path.as_dict() if root_path_managed else None
            ),
            "original": original_root_path.as_dict(),
        },
        "startedAt": utc_now(),
        "timeline": {},
        "outcome": "RESTORING",
    }
    if _partial_evidence_sink is not None:
        _partial_evidence_sink["record"] = result
    paused = False
    resume_allowed = False
    resume_started_at: float | None = None
    try:
        result["timeline"]["pause"] = transition_qemu(
            monitor, "stop", "paused"
        )
        paused = True
        before = outer_qemu_aer_snapshot(
            socket_path, endpoint_bdf, root_bdf
        )
        before_record: dict[str, Any] = {
            "capturedAt": None,
            "readback": None,
            "safetyFaults": [],
            "snapshot": before,
            "partial": True,
        }
        result["timeline"]["before"] = before_record
        before_record["safetyFaults"] = _partial_numeric_safety_faults(before)
        if before_record["safetyFaults"]:
            raise SafetyViolation(
                "unsafe state before gate restore: "
                + "; ".join(before_record["safetyFaults"])
            )
        before_record["capturedAt"] = utc_now()
        before_record["readback"] = gate_readback(before, mask)
        before_record["partial"] = False
        client = qemu_aer.QTestClient(socket_path)
        try:
            write_gate_tuple(
                client,
                before,
                requested,
                mask,
                clear_correctable=not safe_stop,
                root_path=original_root_path if root_path_managed else None,
            )
        finally:
            client.close()
        paused_restored = outer_qemu_aer_snapshot(
            socket_path, endpoint_bdf, root_bdf
        )
        paused_record: dict[str, Any] = {
            "capturedAt": None,
            "readback": None,
            "checks": None,
            "safetyFaults": [],
            "snapshot": paused_restored,
            "partial": True,
        }
        result["timeline"]["pausedApplied"] = paused_record
        paused_record["safetyFaults"] = _partial_numeric_safety_faults(
            paused_restored
        )
        paused_record["capturedAt"] = utc_now()
        checks = gate_non_target_checks(before, paused_restored, mask)
        checks["requestedTupleReadBack"] = (
            gate_tuple_from_snapshot(paused_restored, mask) == requested
        )
        checks["requestedRootPathReadBack"] = (
            root_path_from_snapshot(paused_restored) == original_root_path
        )
        restore_safety_faults = _partial_numeric_safety_faults(paused_restored)
        if not safe_stop:
            checks["noUncorrectableEvidenceAtRestore"] = not restore_safety_faults
        if not safe_stop:
            checks.update(
                {
                    "endpointCorrectableStatusCleared": (
                        int(
                            paused_restored["endpointState"][
                                "correctableErrorStatus"
                            ]
                        )
                        == 0
                    ),
                    "rootCorrectableStatusCleared": (
                        int(
                            paused_restored["rootState"][
                                "correctableErrorStatus"
                            ]
                        )
                        == 0
                    ),
                    "rootCorrectableReceptionCleared": not bool(
                        int(paused_restored["rootState"]["rootErrorStatus"])
                        & (
                            qemu_aer.PCI_ERR_ROOT_COR_RCV
                            | qemu_aer.PCI_ERR_ROOT_MULTI_COR_RCV
                        )
                    ),
                }
            )
        paused_record.update(
            {
                "readback": gate_readback(paused_restored, mask),
                "checks": checks,
                "safetyFaults": restore_safety_faults,
                "partial": False,
            }
        )
        resume_allowed = not safe_stop and all(checks.values())
    except BaseException as error:
        numeric_safety_faults = _partial_numeric_safety_faults(result)
        result["restoreFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        result["numericSafetyFaults"] = numeric_safety_faults
        result["outcome"] = "RESTORE_TRANSACTION_FAILED_HELD_PAUSED"
        result["qemuHeldPaused"] = paused
        result["finishedAt"] = utc_now()
        raise GateLeaseRestoreFailure(
            "gate restore paused transaction failed; partial numeric "
            "evidence was retained and QEMU was left paused",
            result,
            safety=bool(numeric_safety_faults),
        ) from error
    finally:
        if paused:
            if safe_stop or not resume_allowed:
                result["timeline"]["heldPaused"] = {
                    "reason": (
                        "FAIL_SAFETY or incomplete restore preserves evidence "
                        "and prevents further device activity until review"
                    ),
                    "observedAt": utc_now(),
                }
            else:
                resume_started_at = time.monotonic()
                if _partial_evidence_sink is not None:
                    _partial_evidence_sink[
                        "resumeStartedAt"
                    ] = resume_started_at
                try:
                    result["timeline"]["resume"] = transition_qemu(
                        monitor, "cont", "running"
                    )
                except BaseException as resume_error:
                    result["resumeFault"] = {
                        "type": type(resume_error).__name__,
                        "message": str(resume_error),
                    }
                    try:
                        result["timeline"]["resumeFailureHold"] = (
                            transition_qemu(
                                monitor,
                                "stop",
                                "paused",
                            )
                        )
                        result["qemuHeldPaused"] = True
                    except BaseException as hold_error:
                        result["resumeFailureHoldFault"] = {
                            "type": type(hold_error).__name__,
                            "message": str(hold_error),
                        }
                    result["outcome"] = "RESUME_FAILED_DURING_RESTORE"
                    result["finishedAt"] = utc_now()
                    raise GateLeaseRestoreFailure(
                        "QEMU restore resume could not be confirmed; an "
                        "idempotent fail-stop was attempted",
                        result,
                        safety=False,
                    ) from resume_error

    paused_checks = result["timeline"]["pausedApplied"]["checks"]
    if safe_stop:
        effective = result["timeline"]["pausedApplied"]["readback"]
        result["rootPathLease"]["effective"] = effective["rootPath"]
        result["rootPathLease"]["stable"] = (
            root_path_from_snapshot(
                result["timeline"]["pausedApplied"]["snapshot"]
            )
            == original_root_path
        )
        result["outcome"] = (
            "SAFE_STOP_HELD_PAUSED"
            if all(paused_checks.values())
            else "SAFE_STOP_INCOMPLETE_HELD_PAUSED"
        )
        result["effective"] = effective
        result["finishedAt"] = utc_now()
        return result
    if not resume_allowed:
        effective = result["timeline"]["pausedApplied"]["readback"]
        result["rootPathLease"]["effective"] = effective["rootPath"]
        result["rootPathLease"]["stable"] = (
            root_path_from_snapshot(
                result["timeline"]["pausedApplied"]["snapshot"]
            )
            == original_root_path
        )
        result["outcome"] = "RESTORE_INCOMPLETE_HELD_PAUSED"
        result["effective"] = effective
        result["finishedAt"] = utc_now()
        return result

    if maximum_safety_poll_interval is None:
        samples = sample_gate_timeline(
            socket_path,
            endpoint_bdf,
            root_bdf,
            mask,
            delays=timeline_delays,
        )
        safety_poll = None
    else:
        if safety_poll_target_interval is None:
            raise ValueError(
                "continuous gate restore sampling requires a target interval"
            )
        if resume_started_at is None:
            raise AssertionError("gate restore resume timestamp was not captured")
        try:
            safety_poll = {}
            result["timeline"]["resumedSafetyPoll"] = safety_poll
            safety_poll = sample_gate_timeline_continuous(
                socket_path,
                endpoint_bdf,
                root_bdf,
                mask,
                timeline_delays,
                started_at=resume_started_at,
                maximum_poll_interval=maximum_safety_poll_interval,
                target_poll_interval=safety_poll_target_interval,
                safety_boundary="POST_CLEANUP",
                topology=paused_restored,
                _partial_record=safety_poll,
            )
        except BaseException as sampler_error:
            result["postResumeSamplerFault"] = {
                "type": type(sampler_error).__name__,
                "message": str(sampler_error),
            }
            try:
                result["timeline"]["samplerFailureHold"] = transition_qemu(
                    monitor,
                    "stop",
                    "paused",
                )
                result["qemuHeldPaused"] = True
                result["outcome"] = (
                    "RESTORE_POST_RESUME_SAMPLER_FAILED_HELD_PAUSED"
                )
            except BaseException as hold_error:
                result["samplerFailureHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
                result["outcome"] = (
                    "RESTORE_POST_RESUME_SAMPLER_AND_HOLD_UNCONFIRMED"
                )
            result["finishedAt"] = utc_now()
            raise GateLeaseRestoreFailure(
                "gate restore post-resume sampler failed; fail-stop was "
                "attempted",
                result,
                safety=False,
            ) from sampler_error
        result["timeline"]["resumedSafetyPoll"] = safety_poll
        result["timeline"]["resumedTargetSamples"] = safety_poll["timeline"]
        samples = safety_poll["samples"]
    result["timeline"]["resumedSamples"] = samples
    if safety_poll is not None:
        resumed_safety_faults = [
            {
                "delaySeconds": item.get("actualElapsedSeconds"),
                "faults": list(item.get("faults") or []),
                "snapshot": copy.deepcopy(item.get("snapshot")),
                "phase": item.get("phase"),
            }
            for item in safety_poll.get("safetyEvents", [])
            if isinstance(item, dict) and item.get("faults")
        ]
    else:
        resumed_safety_faults = [
            {
                "delaySeconds": item.get(
                    "delaySeconds",
                    item.get("actualElapsedSeconds"),
                ),
                "faults": list(item.get("safetyFaults") or []),
                "snapshot": copy.deepcopy(item.get("snapshot")),
            }
            for item in samples
            if item.get("safetyFaults")
        ]
    result["resumedSafetyFaults"] = resumed_safety_faults
    poll_faults = (
        list(safety_poll.get("pollFaults") or [])
        if safety_poll is not None
        else []
    )
    if not samples:
        missing_sample = {
            "type": "MissingSafetySample",
            "message": "no resumed restore QTest safety sample was retained",
        }
        if not poll_faults:
            poll_faults.append(missing_sample)
            if safety_poll is not None:
                safety_poll.setdefault("pollFaults", []).append(
                    missing_sample
                )
                safety_poll["complete"] = False
    _record_resumed_gate_effective(result, samples, poll_faults)
    if resumed_safety_faults or poll_faults or hold_paused_after_sampling:
        hold_label = (
            "safetyHold"
            if resumed_safety_faults
            else (
                "pollDeadlineHold"
                if poll_faults
                else "postSamplingHold"
            )
        )
        try:
            if safety_poll is not None and resume_started_at is not None:
                (
                    result["timeline"][hold_label],
                    stop_confirmed_at,
                ) = _transition_qemu_stop_while_sampling_gate_tail(
                    monitor,
                    socket_path,
                    endpoint_bdf,
                    root_bdf,
                    mask,
                    safety_poll,
                    started_at=resume_started_at,
                    topology=paused_restored,
                )
            else:
                result["timeline"][hold_label] = transition_qemu(
                    monitor, "stop", "paused"
                )
                stop_confirmed_at = time.monotonic()
            result["qemuHeldPaused"] = True
            if safety_poll is not None and resume_started_at is not None:
                close_continuous_safety_poll(
                    safety_poll,
                    started_at=resume_started_at,
                    mode="PAUSED_ACK",
                    stop_confirmed_at=stop_confirmed_at,
                )
        except BaseException as hold_error:
            if safety_poll is not None and resume_started_at is not None:
                close_continuous_safety_poll(
                    safety_poll,
                    started_at=resume_started_at,
                    mode="STOP_UNCONFIRMED",
                    stop_confirmed_at=None,
                )
            result["safetyHoldFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            result["outcome"] = "RESTORE_FAIL_STOP_UNCONFIRMED"
            result["finishedAt"] = utc_now()
            raise GateLeaseRestoreFailure(
                "gate restore evidence required fail-stop, but paused "
                "readback could not be confirmed",
                result,
                safety=bool(resumed_safety_faults),
            ) from hold_error
    elif safety_poll is not None and resume_started_at is not None:
        close_continuous_safety_poll(
            safety_poll,
            started_at=resume_started_at,
            mode="RUNNING_AFTER_TARGET_COVERAGE",
            stop_confirmed_at=None,
        )
    poll_faults = (
        list(safety_poll.get("pollFaults") or [])
        if safety_poll is not None
        else []
    )
    if safety_poll is not None:
        resumed_safety_faults = [
            {
                "delaySeconds": item.get("actualElapsedSeconds"),
                "faults": list(item.get("faults") or []),
                "snapshot": copy.deepcopy(item.get("snapshot")),
                "phase": item.get("phase"),
            }
            for item in safety_poll.get("safetyEvents", [])
            if isinstance(item, dict) and item.get("faults")
        ]
        result["resumedSafetyFaults"] = resumed_safety_faults
        _record_resumed_gate_effective(result, samples, poll_faults)
    if resumed_safety_faults:
        result["outcome"] = "RESTORE_SAFETY_FAULT_HELD_PAUSED"
        result["rootPathLease"]["stable"] = False
        result["finishedAt"] = utc_now()
        return result
    if poll_faults or not samples:
        result["outcome"] = "RESTORE_SAFETY_POLL_INCOMPLETE_HELD_PAUSED"
        result["safetyPollFaults"] = poll_faults or [
            {
                "type": "MissingSafetySample",
                "message": "no resumed restore QTest safety sample was retained",
            }
        ]
        result["rootPathLease"]["stable"] = False
        result["finishedAt"] = utc_now()
        return result
    stable = all(
        gate_tuple_from_snapshot(item["snapshot"], mask) == requested
        for item in samples
    )
    root_path_stable = all(
        root_path_from_snapshot(item["snapshot"]) == original_root_path
        for item in samples
    )
    result["rootPathLease"]["stable"] = root_path_stable
    if all(paused_checks.values()) and stable and root_path_stable:
        result["outcome"] = "RESTORED"
    else:
        result["outcome"] = "RESTORE_INCOMPLETE"
    result["finishedAt"] = utc_now()
    return result


def restore_gate_lease(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    mask: int,
    lease: dict[str, Any],
    *,
    safe_stop: bool,
    timeline_delays: Iterable[float] = (0.0, 0.1),
    maximum_safety_poll_interval: float | None = None,
    safety_poll_target_interval: float | None = None,
    hold_paused_after_sampling: bool = False,
) -> dict[str, Any]:
    """Restore a lease with fail-stop and typed partial evidence on any fault."""

    evidence_sink: dict[str, Any] = {}
    try:
        return _restore_gate_lease_impl(
            monitor,
            socket_path,
            endpoint_bdf,
            root_bdf,
            mask,
            lease,
            safe_stop=safe_stop,
            timeline_delays=timeline_delays,
            maximum_safety_poll_interval=maximum_safety_poll_interval,
            safety_poll_target_interval=safety_poll_target_interval,
            hold_paused_after_sampling=hold_paused_after_sampling,
            _partial_evidence_sink=evidence_sink,
        )
    except GateLeaseRestoreFailure:
        raise
    except BaseException as error:
        result = evidence_sink.get("record")
        if not isinstance(result, dict):
            result = {
                "safetyBoundary": "POST_CLEANUP",
                "safetyWindowKind": "GATE_LEASE_RESTORE",
                "startedAt": utc_now(),
                "timeline": {},
                "outcome": "RESTORE_UNHANDLED_FAILURE",
            }
        result["postProcessingFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        stop_confirmed_at: float | None = None
        try:
            timeline = result.setdefault("timeline", {})
            if not isinstance(timeline, dict):
                timeline = {}
                result["timeline"] = timeline
            timeline["unhandledFailureHold"] = transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            stop_confirmed_at = time.monotonic()
            result["qemuHeldPaused"] = True
            result["outcome"] = "RESTORE_FAILURE_HELD_PAUSED"
        except BaseException as hold_error:
            result["unhandledFailureHoldFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            result["outcome"] = "RESTORE_FAILURE_AND_HOLD_UNCONFIRMED"
        _close_partial_gate_poll(
            result,
            evidence_sink,
            stop_confirmed_at=stop_confirmed_at,
        )
        numeric_safety_faults = _partial_numeric_safety_faults(result)
        result["numericSafetyFaults"] = numeric_safety_faults
        result["finishedAt"] = utc_now()
        raise GateLeaseRestoreFailure(
            "gate restore failed outside its normal transaction boundary; "
            "partial evidence was retained and an idempotent fail-stop was "
            "attempted",
            result,
            safety=bool(numeric_safety_faults),
        ) from error


def evaluate_frozen_transport(
    requested: GateTuple,
    mask: int,
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_endpoint = before["endpointState"]
    after_endpoint = after["endpointState"]
    before_root = before["rootState"]
    after_root = after["rootState"]
    before_root_status = int(before_root["rootErrorStatus"])
    after_root_status = int(after_root["rootErrorStatus"])
    root_received = bool(
        after_root_status & qemu_aer.PCI_ERR_ROOT_COR_RCV
    )
    source_matches = (
        int(after_root["errorSourceIdentification"]) & 0xFFFF
    ) == int(before["endpoint"]["requesterId"])
    root_path_open = bool(
        int(before_root["bridgeControl"]) & qemu_aer.PCI_BRIDGE_CTL_SERR
    ) and bool(
        int(before_root["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
    )
    expects_root_reception = requested.endpoint_cere and not (
        requested.endpoint_masked
    )
    checks: dict[str, bool] = {
        "effectiveTupleMatchesRequest": (
            gate_tuple_from_snapshot(before, mask) == requested
        ),
        "effectiveTupleStableAfter": (
            gate_tuple_from_snapshot(after, mask) == requested
        ),
        "requestedBitClearBefore": not bool(
            int(before_endpoint["correctableErrorStatus"]) & mask
        ),
        "requestedBitRecordedAfter": bool(
            int(after_endpoint["correctableErrorStatus"]) & mask
        ),
        "rootStatusMessageNumberStable": (
            before_root_status & 0xFFFFFF80
        )
        == (after_root_status & 0xFFFFFF80),
        "rootAuxiliaryPathOpen": root_path_open,
        "noUncorrectableSideEffect": not outer_snapshot_safety_faults(after),
    }
    if expects_root_reception:
        checks.update(
            {
                "rootCorrectableReceptionObserved": root_received,
                "correctableSourceMatches": root_received and source_matches,
                "rootMultipleCorrectableClear": not bool(
                    after_root_status
                    & qemu_aer.PCI_ERR_ROOT_MULTI_COR_RCV
                ),
            }
        )
        conclusion = (
            "FROZEN_FABRIC_RECEPTION_OBSERVED"
            if all(checks.values())
            else "FROZEN_FABRIC_RECEPTION_MISMATCH"
        )
    else:
        checks["rootCorrectableReceptionBlocked"] = not root_received
        conclusion = (
            "FROZEN_ENDPOINT_GATE_BLOCKED_ROOT_RECEPTION"
            if all(checks.values())
            else "FROZEN_ENDPOINT_GATE_MISMATCH"
        )
    return {
        "scope": (
            "QEMU fabric deposition while ESXi execution is frozen; "
            "not evidence of VMware service or interrupt handling"
        ),
        "requested": requested.as_dict(),
        "beforeGate": gate_readback(before, mask),
        "afterGate": gate_readback(after, mask),
        "rootStatusLowBefore": before_root_status & 0x7F,
        "rootStatusLowAfter": after_root_status & 0x7F,
        "rootSourceMeaningful": root_received,
        "checks": checks,
        "conclusion": conclusion,
        "verdict": "PASS" if all(checks.values()) else "FAIL",
    }


def clear_outer_qemu_aer_baseline(
    monitor: Path,
    socket_path: Path,
    endpoint_bdf: str,
    root_bdf: str,
    policy: str,
    *,
    leave_paused: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "safetyBoundary": "PRE_INJECTION",
        "policy": policy,
        "startedAt": utc_now(),
        "clean": False,
        "qemuHeldPaused": False,
    }
    paused = False
    # Resume is a clean-commit action, never the default.  Any parse failure,
    # partial W1C write, control interruption, or inconclusive readback keeps
    # the outer QEMU paused.
    resume_allowed = False
    pending_error: BaseException | None = None
    try:
        stop_output = hmp_command(monitor, "stop")
        paused = True
        result["hmpStop"] = stop_output
        status_output = hmp_command(monitor, "info status")
        result["hmpStatusAfterStop"] = status_output
        if "paused" not in status_output.lower():
            raise InconclusiveObservation(
                f"QEMU did not confirm paused state before QTest writes: {status_output!r}"
            )
        before = outer_qemu_aer_snapshot(socket_path, endpoint_bdf, root_bdf)
        result["before"] = before
        safety_faults = outer_snapshot_safety_faults(before)
        result["beforeSafetyFaults"] = safety_faults
        if safety_faults:
            resume_allowed = False
            raise SafetyViolation(
                "refusing to clear a baseline containing Uncorrectable evidence: "
                + "; ".join(safety_faults)
            )
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
            qemu_aer.config_write16(
                client,
                eb,
                ed,
                ef,
                epcie + qemu_aer.PCI_EXP_DEVSTA,
                qemu_aer.PCI_EXP_DEVSTA_CED,
            )
            qemu_aer.config_write32(client, eb, ed, ef, eaer + 0x10, 0xFFFFFFFF)
            qemu_aer.config_write16(
                client,
                rb,
                rd,
                rf,
                rpcie + qemu_aer.PCI_EXP_DEVSTA,
                qemu_aer.PCI_EXP_DEVSTA_CED,
            )
            qemu_aer.config_write32(client, rb, rd, rf, raer + 0x10, 0xFFFFFFFF)
            qemu_aer.config_write32(
                client,
                rb,
                rd,
                rf,
                raer + qemu_aer.PCI_ERR_ROOT_STATUS,
                (
                    qemu_aer.PCI_ERR_ROOT_COR_RCV
                    | qemu_aer.PCI_ERR_ROOT_MULTI_COR_RCV
                ),
            )
        finally:
            client.close()
        after = outer_qemu_aer_snapshot(socket_path, endpoint_bdf, root_bdf)
        result["after"] = after
        after_safety_faults = outer_snapshot_safety_faults(after)
        result["afterSafetyFaults"] = after_safety_faults
        if after_safety_faults:
            resume_allowed = False
            raise SafetyViolation(
                "Correctable baseline clear exposed Uncorrectable evidence: "
                + "; ".join(after_safety_faults)
            )
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
            "rootErrorStatusClean": not bool(
                after["rootState"]["rootErrorStatus"] & 0x7F
            ),
            "rootErrorSourceIgnoredWithoutReception": not bool(
                after["rootState"]["rootErrorStatus"] & 0x7F
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
                "rootErrorSourceIgnoredWithoutReception",
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
        result.update(
            {
                "checks": checks,
                "stickyDeviceStatusAccepted": (
                    policy == "status-routing"
                    and not checks["endpointDeviceStatusClean"]
                ),
                "clean": clean,
            }
        )
        resume_allowed = True
    except BaseException as error:
        pending_error = error
        result["fault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        if paused:
            if resume_allowed and not leave_paused:
                try:
                    result["hmpContinue"] = hmp_command(monitor, "cont")
                    result["qemuHeldPaused"] = False
                except BaseException as resume_error:
                    result["resumeFault"] = {
                        "type": type(resume_error).__name__,
                        "message": str(resume_error),
                    }
                    try:
                        result["resumeFailureHold"] = transition_qemu(
                            monitor,
                            "stop",
                            "paused",
                        )
                        result["qemuHeldPaused"] = True
                    except BaseException as hold_error:
                        result["resumeFailureHoldFault"] = {
                            "type": type(hold_error).__name__,
                            "message": str(hold_error),
                        }
                    if pending_error is None:
                        pending_error = resume_error
            else:
                result["qemuHeldPaused"] = True
        try:
            result["finishedAt"] = utc_now()
        except BaseException as finalization_error:
            result["finishedAt"] = None
            result["finalizationFault"] = {
                "type": type(finalization_error).__name__,
                "message": str(finalization_error),
            }
            if pending_error is None:
                pending_error = finalization_error
    if pending_error is not None:
        numeric_safety_faults = _partial_numeric_safety_faults(result)
        result["numericSafetyFaults"] = numeric_safety_faults
        raise BaselineClearFailure(
            "baseline clear failed; partial numeric evidence was retained",
            result,
            safety=bool(numeric_safety_faults),
        ) from pending_error
    return result


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
    """Return guest kernel AER event lines, excluding sysfs counter labels."""

    event = re.compile(
        r"PCIe Bus Error|severity=(?:Corrected|Uncorrected|Fatal)",
        re.IGNORECASE,
    )
    return [line for line in text.splitlines() if event.search(line)]


def guest_aer_counter_totals(text: str, phase: str) -> dict[str, int]:
    """Parse the aggregate Linux AER sysfs counters printed for one phase."""

    block = guest_phase_block(text, phase)
    if block is None:
        return {}
    totals: dict[str, int] = {}
    for name, value in re.findall(
        r"^TOTAL_ERR_(COR|FATAL|NONFATAL)\s+([0-9]+)$",
        block,
        re.MULTILINE,
    ):
        totals[name.lower()] = int(value)
    return totals


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
        r"\bAER\b|PCIe Bus Error|severity=(?:Corrected|Uncorrected|Fatal)"
        r"|Receiver Error|Bad TLP|Bad DLLP"
        r"|Replay (?:Timer Timeout|Number Rollover)",
        re.IGNORECASE,
    )
    result = []
    for line in lines:
        lower = line.lower()
        if not pattern.search(line):
            continue
        if "pci-aer-matrix" in lower:
            continue
        # ESXi audits the SCP/log-collection commands in syslog.  Their paths
        # deliberately contain "aer-correctable"; these are transport records,
        # not PCI error events.
        if "sshd-session" in lower and "running command" in lower:
            continue
        result.append(line)
    return result


@dataclass
class ApiSession:
    host_address: str
    user: str
    password: str
    http_connection_timeout: int | None = None

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
            last_connect_error: Exception | None = None
            for attempt in range(3):
                try:
                    self.service_instance = SmartConnect(
                        host=self.host_address,
                        user=self.user,
                        pwd=self.password,
                        sslContext=context,
                        httpConnectionTimeout=self.http_connection_timeout,
                    )
                    break
                except Exception as connect_error:
                    last_connect_error = connect_error
                    if attempt == 2:
                        raise
                    time.sleep(2)
            else:  # pragma: no cover - defensive; the final attempt raises.
                assert last_connect_error is not None
                raise last_connect_error
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

    def close(self, *, remote_logout: bool = True) -> None:
        if remote_logout:
            Disconnect(self.service_instance)
            return
        stub = getattr(self.service_instance, "_stub", None)
        drop_connections = getattr(stub, "DropConnections", None)
        if callable(drop_connections):
            drop_connections()

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


def _active_user_probe_worker(
    sender: Any,
    host: str,
    user: str,
    password: str,
    bdf: str,
    http_timeout_seconds: int,
) -> None:
    """Collect owner evidence in a disposable process and API session."""

    api: ApiSession | None = None
    payload: dict[str, Any]
    try:
        api = ApiSession(
            host,
            user,
            password,
            http_connection_timeout=http_timeout_seconds,
        )
        payload = {
            "ok": True,
            "users": api.active_passthrough_users(bdf),
            "capturedAt": utc_now(),
        }
    except Exception as error:
        payload = {
            "ok": False,
            "error": {
                "type": type(error).__name__,
                "message": str(error),
            },
            "capturedAt": utc_now(),
        }
    if api is not None:
        # The parent enforces the hard deadline.  A responsive endpoint gets
        # a normal logout before success is reported; a stalled logout is
        # terminated with this disposable process.
        try:
            api.close(remote_logout=True)
        except Exception:
            pass
    try:
        sender.send(payload)
    except (BrokenPipeError, EOFError, OSError):
        pass
    finally:
        sender.close()


@dataclass
class ActiveUserProbeProcess:
    process: Any
    receiver: Any
    started_at: str
    started_monotonic: float
    closed: bool = False

    def _stop(self, *, graceful: bool) -> None:
        if self.closed:
            return
        still_alive = False
        try:
            if graceful and self.process.is_alive():
                self.process.join(OWNER_PROBE_TERMINATE_GRACE_SECONDS)
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(OWNER_PROBE_TERMINATE_GRACE_SECONDS)
            if self.process.is_alive():
                kill = getattr(self.process, "kill", None)
                if callable(kill):
                    kill()
                    self.process.join(OWNER_PROBE_TERMINATE_GRACE_SECONDS)
            still_alive = self.process.is_alive()
        finally:
            try:
                self.receiver.close()
            finally:
                if not still_alive:
                    try:
                        self.process.close()
                    except ValueError:
                        pass
                self.closed = True
        if still_alive:
            raise RuntimeError(
                "independent active-user API probe could not be terminated"
            )

    def cancel(self) -> None:
        self._stop(graceful=False)

    def result(self, hard_timeout_seconds: float) -> dict[str, Any]:
        remaining = hard_timeout_seconds - (
            time.monotonic() - self.started_monotonic
        )
        payload_received = False
        try:
            if remaining <= 0 or not self.receiver.poll(remaining):
                raise TimeoutError(
                    "independent active-user API probe exceeded "
                    f"{hard_timeout_seconds:.1f}s hard deadline"
                )
            try:
                payload = self.receiver.recv()
                payload_received = True
            except EOFError as error:
                raise RuntimeError(
                    "independent active-user API probe exited without a result"
                ) from error
            if not isinstance(payload, dict) or payload.get("ok") is not True:
                detail = (
                    payload.get("error")
                    if isinstance(payload, dict)
                    else {"type": "InvalidPayload", "message": repr(payload)}
                )
                raise RuntimeError(
                    "independent active-user API probe failed: "
                    + json.dumps(detail, sort_keys=True)
                )
            return payload
        finally:
            self._stop(graceful=payload_received)


def start_active_user_probe(
    host: str,
    user: str,
    password: str,
    bdf: str,
) -> ActiveUserProbeProcess:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_active_user_probe_worker,
        args=(
            sender,
            host,
            user,
            password,
            bdf,
            OWNER_PROBE_HTTP_TIMEOUT_SECONDS,
        ),
        name="aer-owner-sample",
        daemon=True,
    )
    started_at = utc_now()
    started_monotonic = time.monotonic()
    try:
        process.start()
    except Exception:
        receiver.close()
        sender.close()
        raise
    sender.close()
    return ActiveUserProbeProcess(
        process=process,
        receiver=receiver,
        started_at=started_at,
        started_monotonic=started_monotonic,
    )


def isolated_active_passthrough_users(
    api: ApiSession,
    bdf: str,
) -> dict[str, Any]:
    """Collect pyVmomi owner evidence outside the sampler's Python GIL."""

    probe = start_active_user_probe(
        api.host_address,
        api.user,
        api.password,
        bdf,
    )
    try:
        return probe.result(OWNER_PROBE_HARD_TIMEOUT_SECONDS)
    finally:
        if not probe.closed:
            probe.cancel()


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
    window_seconds: int | None = None
    window_open_observed_monotonic: float | None = None

    def start(
        self,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        def require_not_cancelled() -> None:
            if cancel is not None and cancel.is_set():
                raise InconclusiveObservation(
                    "active DirectPath VM startup was cancelled by the "
                    "outer Correctable-only safety monitor"
                )

        require_not_cancelled()
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
        require_not_cancelled()
        registration = self.ssh.run(f"vim-cmd solo/registervm {quoted_vmx}")
        candidates = [line.strip() for line in registration.stdout.splitlines()]
        candidates = [line for line in candidates if re.fullmatch(r"\d+", line)]
        if not candidates:
            raise BlockedEnvironment(
                f"could not parse VMID from register output: {registration.stdout!r}"
            )
        self.vmid = candidates[-1]
        require_not_cancelled()
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
            require_not_cancelled()
            state = self.ssh.run(
                f"vim-cmd vmsvc/power.getstate {self.vmid}",
                check=False,
                timeout=30,
            )
            last_power_state = state.stdout + state.stderr
            if state.returncode == 0 and "Powered on" in state.stdout:
                break
            if cancel is not None:
                cancel.wait(2)
            else:
                time.sleep(2)
        else:
            raise BlockedEnvironment(
                "active DirectPath VM did not reach powered-on state: "
                f"{last_power_state.strip()}"
            )

        serial_path = f"{self.remote_dir}/{self.serial_name}"
        deadline = time.monotonic() + self.marker_timeout
        while time.monotonic() < deadline:
            require_not_cancelled()
            probe = self.ssh.run(
                f"grep -F '=== AER injection window open ===' "
                f"{shlex.quote(serial_path)} 2>/dev/null",
                check=False,
                timeout=30,
            )
            if probe.returncode == 0 and "injection window open" in probe.stdout:
                self.window_open_observed_monotonic = time.monotonic()
                break
            if cancel is not None:
                cancel.wait(2)
            else:
                time.sleep(2)
        else:
            raise BlockedEnvironment(
                "active DirectPath guest did not open the AER injection window"
            )

        window_deadline = time.monotonic() + 5
        while time.monotonic() < window_deadline:
            require_not_cancelled()
            window_probe = self.ssh.run(
                f"grep -E 'AER-WINDOW seconds=[0-9]+' "
                f"{shlex.quote(serial_path)} 2>/dev/null | tail -1",
                check=False,
                timeout=30,
            )
            match = re.search(
                r"AER-WINDOW seconds=([0-9]+)", window_probe.stdout
            )
            if match:
                self.window_seconds = int(match.group(1))
                break
            if cancel is not None:
                cancel.wait(0.2)
            else:
                time.sleep(0.2)
        if self.window_seconds is None:
            raise BlockedEnvironment(
                "guest did not publish a parseable AER window duration"
            )

        require_not_cancelled()
        active_user_probe = isolated_active_passthrough_users(
            self.api,
            self.bdf,
        )
        require_not_cancelled()
        users = active_user_probe["users"]
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
            "activeUserProbe": {
                "mode": "ISOLATED_PROCESS",
                "capturedAt": active_user_probe.get("capturedAt"),
            },
            "windowSeconds": self.window_seconds,
        }

    def require_window_remaining(self, minimum_seconds: float) -> dict[str, float]:
        if (
            self.window_seconds is None
            or self.window_open_observed_monotonic is None
        ):
            raise InconclusiveObservation(
                "active guest AER window timing is unavailable"
            )
        elapsed = time.monotonic() - self.window_open_observed_monotonic
        remaining = float(self.window_seconds) - elapsed
        result = {
            "windowSeconds": float(self.window_seconds),
            "elapsedSinceOpenObserved": elapsed,
            "remainingSeconds": remaining,
            "requiredRemainingSeconds": minimum_seconds,
        }
        if remaining < minimum_seconds:
            raise InconclusiveObservation(
                "active guest AER window is too close to automatic poweroff: "
                + json.dumps(result, sort_keys=True)
            )
        return result

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

    def cleanup(
        self,
        cancel: threading.Event | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"startedAt": utc_now(), "actions": []}
        def cancelled() -> bool:
            value = cancel is not None and cancel.is_set()
            if value:
                result["cancelledBySafetyMonitor"] = True
            return value

        if self.remote_dir:
            for remote_name, local_name in (
                (self.serial_name, "guest-serial-final.log"),
                ("vmware.log", "vmware.log"),
                (f"{self.case_id}.vmx", "effective.vmx"),
            ):
                if cancelled():
                    break
                if remote_name:
                    copied = self.transfer.from_esxi(
                        f"{self.remote_dir}/{remote_name}",
                        self.case_dir / local_name,
                        required=False,
                    )
                    result["actions"].append(
                        {"copy": remote_name, "destination": local_name, "success": copied}
                    )
        if self.vmid and not cancelled():
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
            if not cancelled():
                unregister = self.ssh.run(
                    f"vim-cmd vmsvc/unregister {self.vmid}", check=False
                )
                result["actions"].append(
                    {"unregisterReturnCode": unregister.returncode}
                )
        try:
            deadline = time.monotonic() + 30
            remaining: list[dict[str, Any]] = []
            probes: list[dict[str, Any]] = []
            while time.monotonic() < deadline and not cancelled():
                payload = isolated_active_passthrough_users(
                    self.api,
                    self.bdf,
                )
                remaining = payload["users"]
                probes.append(
                    {
                        "mode": "ISOLATED_PROCESS",
                        "capturedAt": payload.get("capturedAt"),
                    }
                )
                if not remaining:
                    break
                if cancel is not None:
                    cancel.wait(1)
                else:
                    time.sleep(1)
            result["remainingActiveUsers"] = remaining
            result["activeUserProbes"] = probes
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
    gate_tuple: GateTuple | None = None,
    frozen_transport: dict[str, Any] | None = None,
    post_resume_active_users: list[dict[str, Any]] | None = None,
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
    if gate_tuple is not None:
        observations["immediatePostResumeActivePassthroughUsers"] = (
            post_resume_active_users
        )
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
            if gate_tuple is not None:
                post_resume_errors = (
                    post_resume_active_users is None
                    or any(
                        isinstance(item, dict)
                        and item.get("inspectionError")
                        for item in (post_resume_active_users or [])
                    )
                )
                post_resume_keys = {
                    (item.get("vm"), item.get("vmMoId"), item.get("deviceKey"))
                    for item in (post_resume_active_users or [])
                    if isinstance(item, dict)
                    and not item.get("inspectionError")
                }
                checks["activeVmUseStableThroughInjection"] = (
                    no_inspection_errors
                    and not post_resume_errors
                    and len(active_user_keys[0]) == 1
                    and active_user_keys[0] == post_resume_keys
                )
            else:
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
                    all(
                        keys == active_user_keys[0] or not keys
                        for keys in active_user_keys[1:]
                    )
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
    post_resume_host_bit_observed = bool(
        (int(injection_ces) | int(after_ces)) & mask
    )
    if gate_tuple is None:
        checks["requestedBitObserved"] = post_resume_host_bit_observed
    else:
        observations["host"][
            "requestedBitObservedPostResume"
        ] = post_resume_host_bit_observed
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
            if oracle == "esxi803" and gate_tuple is None:
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
            post_resume_outer_bit_observed = bool(
                (
                    int(outer_endpoint[1]["correctableErrorStatus"])
                    | int(outer_endpoint[2]["correctableErrorStatus"])
                )
                & mask
            )
            if gate_tuple is None:
                checks["outerRequestedBitObserved"] = (
                    post_resume_outer_bit_observed
                )
            else:
                observations[
                    "outerRequestedBitObservedPostResume"
                ] = post_resume_outer_bit_observed
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
            checks["outerRootDeviceStatusCorrectableOnly"] = all(
                not (
                    int(item["deviceStatus"])
                    & (
                        qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                        ^ qemu_aer.PCI_EXP_DEVSTA_CED
                    )
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
                    "outerRootDeviceStatusCorrectableOnly",
                    "outerRootHasNoUncorrectableReception",
                )
            )
            first_endpoint = outer_endpoint[0]
            first_root = outer_root[0]
            root_received = any(
                int(item["rootErrorStatus"]) & qemu_aer.PCI_ERR_ROOT_COR_RCV
                for item in outer_root[1:]
            )
            source_matches = any(
                bool(int(item["rootErrorStatus"]) & qemu_aer.PCI_ERR_ROOT_COR_RCV)
                and (
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
            if oracle == "esxi803" and gate_tuple is None:
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
            "aerCounterTotals": {
                "before": guest_aer_counter_totals(
                    guest_text, "before-injection"
                ),
                "after": guest_aer_counter_totals(
                    guest_text, "after-injection"
                ),
            },
        }
        before_counters = observations["guest"]["aerCounterTotals"]["before"]
        after_counters = observations["guest"]["aerCounterTotals"]["after"]
        observations["guest"]["aerCounterDelta"] = {
            name: after_counters[name] - before_counters[name]
            for name in sorted(before_counters.keys() & after_counters.keys())
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
        if oracle == "esxi803" and gate_tuple is None:
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
        elif oracle == "esxi803":
            observations["guest"]["controlledPostResumeProfile"] = {
                "requestedBitClearBefore": (
                    guest_before["correctableStatus"] is not None
                    and not bool(int(guest_before["correctableStatus"]) & mask)
                ),
                "requestedBitObservedAfter": (
                    guest_after["correctableStatus"] is not None
                    and bool(int(guest_after["correctableStatus"]) & mask)
                ),
                "aerHeaderHidden": (
                    guest_before["aerHeader"] == 0
                    and guest_after["aerHeader"] == 0
                ),
                "aerCapabilityDiscoverable": (
                    guest_before["aerHeader"] not in (None, 0)
                    and guest_after["aerHeader"] not in (None, 0)
                ),
                "nativeAerEventObserved": bool(
                    observations["guest"]["aerEventLines"]
                ),
                "nativeAerCounterDelta": observations["guest"][
                    "aerCounterDelta"
                ],
            }

    if gate_tuple is not None:
        observations["controlledGate"] = {
            "requested": gate_tuple.as_dict(),
            "frozenTransport": frozen_transport,
            "rootCommandInterpretation": (
                "R controls Root Error Command Correctable reporting/service; "
                "frozen ERR_COR deposition is evaluated from E and M, independently of R"
            ),
        }
        checks["controlledFrozenTransportComplete"] = isinstance(
            frozen_transport, dict
        )
        checks["controlledFrozenTransportMatchesGate"] = bool(
            isinstance(frozen_transport, dict)
            and frozen_transport.get("verdict") == "PASS"
        )

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
    gate_tuple: GateTuple | None,
    ssh: EsxiSsh,
    transfer: EsxiScp,
    api: ApiSession,
    output_dir: Path,
) -> dict[str, Any]:
    gate_suffix = f"-g{gate_tuple.label}" if gate_tuple is not None else ""
    case_id = validate_safe_id(
        f"{args.owner_state.lower()}-{bit_name}{gate_suffix}", "case id"
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
        "requestedGate": gate_tuple.as_dict() if gate_tuple is not None else None,
        "claimScope": (
            "QEMU_FROZEN_FABRIC_AND_ESXI_POST_RESUME_BLACKBOX"
            if gate_tuple is not None
            else "ENDPOINT_STATUS_PROJECTION_AND_BOUNDED_OBSERVATION"
        ),
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
    gate_lease: dict[str, Any] | None = None
    frozen_transport: dict[str, Any] | None = None
    post_resume_active_users: list[dict[str, Any]] | None = None
    safety_latched = False
    monitor = Path(args.qemu_monitor)
    qtest_socket = Path(args.qtest_socket) if args.qtest_socket else None
    try:
        initial_users = api.active_passthrough_users(args.esxi_bdf)
        if initial_users:
            raise BlockedEnvironment(
                f"target BDF already has powered-on VM users: {initial_users}"
            )
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
                qtest_socket,
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
                    qtest_socket,
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

        if gate_tuple is not None:
            if qtest_socket is None:
                raise BlockedEnvironment("--gate-tuples requires --qtest-socket")
            try:
                gate_lease = apply_gate_lease(
                    monitor,
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                    mask,
                    gate_tuple,
                    enable_root_path=args.enable_root_path,
                )
            except GateLeaseApplyFailure as error:
                gate_lease = error.lease
                record["gateLease"] = {"apply": gate_lease}
                save_json(case_dir / "gate-lease-apply.json", gate_lease)
                if error.safety:
                    safety_latched = True
                    raise SafetyViolation(str(error)) from error
                raise InconclusiveObservation(str(error)) from error
            record["gateLease"] = {"apply": gate_lease}
            save_json(case_dir / "gate-lease-apply.json", gate_lease)
            record["effectiveGate"] = gate_lease.get("effective")
            save_json(case_dir / "case.json", record)
            if gate_lease["outcome"] in (
                "SAFETY_FAULT_DURING_APPLY",
                "SAFETY_FAULT_AFTER_APPLY",
            ):
                safety_latched = True
                raise SafetyViolation(
                    "Uncorrectable evidence appeared while applying the gate lease"
                )
            if gate_lease["outcome"] != "EFFECTIVE":
                raise InconclusiveObservation(
                    "requested gate tuple is not writable and stable: "
                    f"{gate_lease['outcome']}"
                )

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
            qtest_socket,
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
            value = before_root_aer.get("uncorrectableStatus")
            if value is None or int(value) != 0:
                baseline_faults.append(
                    f"ESXi root uncorrectableStatus={value!r}"
                )
            value = before_root_aer.get("rootErrorStatus")
            if value is None or int(value) & 0x7F:
                baseline_faults.append(
                    f"ESXi root rootErrorStatusLow={value!r}"
                )
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
                if int(root_state["rootErrorStatus"]) & 0x7F:
                    baseline_faults.append(
                        "outer Root Error Status low 0x7f is non-zero"
                    )
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
                qtest_socket,
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
            record["activeVmWindowBeforeInjection"] = (
                active_vm.require_window_remaining(15.0)
            )

        if gate_tuple is not None:
            assert qtest_socket is not None
            frozen_flow: dict[str, Any] = {
                "scope": "freeze-inject-observe-release",
                "startedAt": utc_now(),
            }
            record["freezeInjectObserveRelease"] = frozen_flow
            injection_paused = False
            post_resume_faults: list[dict[str, Any]] = []
            post_resume_sampling_error: str | None = None
            post_resume_gate_mismatch: dict[str, bool] | None = None
            try:
                frozen_flow["pause"] = transition_qemu(
                    monitor, "stop", "paused"
                )
                injection_paused = True
                frozen_before = outer_qemu_aer_snapshot(
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                )
                save_json(
                    case_dir / "frozen-transport-before.json",
                    frozen_before,
                )
                frozen_flow["before"] = {
                    "capturedAt": utc_now(),
                    "readback": gate_readback(frozen_before, mask),
                    "snapshot": "frozen-transport-before.json",
                }
                frozen_faults = outer_snapshot_safety_faults(frozen_before)
                if frozen_faults:
                    safety_latched = True
                    raise SafetyViolation(
                        "unsafe frozen pre-injection state: "
                        + "; ".join(frozen_faults)
                    )
                if gate_tuple_from_snapshot(frozen_before, mask) != gate_tuple:
                    raise InconclusiveObservation(
                        "effective gate tuple changed before frozen injection"
                    )
                frozen_root_path = root_path_from_snapshot(frozen_before)
                if not frozen_root_path.open:
                    frozen_flow["gateBlock"] = {
                        "outcome": "ROOT_PATH_BLOCKED",
                        "rootPath": frozen_root_path.as_dict(),
                        "injectionSuppressed": True,
                    }
                    raise InconclusiveObservation(
                        "ROOT_PATH_BLOCKED: BridgeCtl.SERR and Root "
                        "DeviceCtl.CERE are not both effective"
                    )
                if (
                    int(
                        frozen_before["endpointState"][
                            "correctableErrorStatus"
                        ]
                    )
                    & mask
                ):
                    raise InconclusiveObservation(
                        "requested Correctable bit became dirty before injection"
                    )
                if int(frozen_before["rootState"]["rootErrorStatus"]) & 0x7F:
                    raise InconclusiveObservation(
                        "Root Error Status low 0x7f became dirty before injection"
                    )

                record["injectionAttempted"] = True
                record["injection"] = {
                    "startedAt": utc_now(),
                    "command": command,
                    "safetyClass": "CORRECTABLE_ALLOW_LIST_ONLY",
                    "executionState": "QEMU_PAUSED_ESXI_FROZEN",
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
                frozen_after = outer_qemu_aer_snapshot(
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                )
                save_json(
                    case_dir / "frozen-transport-after.json",
                    frozen_after,
                )
                frozen_transport = evaluate_frozen_transport(
                    gate_tuple,
                    mask,
                    frozen_before,
                    frozen_after,
                )
                frozen_transport["snapshotFiles"] = {
                    "before": "frozen-transport-before.json",
                    "after": "frozen-transport-after.json",
                }
                frozen_flow["observation"] = frozen_transport
                record["injection"].update(
                    {
                        "finishedAt": utc_now(),
                        "accepted": injection_accepted,
                        "output": "injection-hmp.txt",
                        "immediateQtestSnapshot": (
                            "frozen-transport-after.json"
                        ),
                    }
                )
                post_faults = outer_snapshot_safety_faults(frozen_after)
                if post_faults:
                    safety_latched = True
                    raise SafetyViolation(
                        "Correctable injection produced Uncorrectable evidence: "
                        + "; ".join(post_faults)
                    )
            finally:
                if injection_paused:
                    if safety_latched:
                        frozen_flow["heldPaused"] = {
                            "reason": (
                                "Correctable-only safety invariant failed; "
                                "gate restore must complete before resume"
                            ),
                            "observedAt": utc_now(),
                        }
                    else:
                        frozen_flow["resume"] = transition_qemu(
                            monitor, "cont", "running"
                        )
                    if record["injectionAttempted"] and not safety_latched:
                        active_user_probe: ActiveUserProbeProcess | None = None
                        active_user_probe_start_error: str | None = None
                        try:
                            post_resume_started = time.monotonic()
                            if active_vm is not None:
                                try:
                                    active_user_probe = start_active_user_probe(
                                        api.host_address,
                                        api.user,
                                        api.password,
                                        args.esxi_bdf,
                                    )
                                    frozen_flow["postResumeActiveUserProbe"] = {
                                        "mode": (
                                            "INDEPENDENT_PROCESS_AND_API_SESSION"
                                        ),
                                        "startedAt": active_user_probe.started_at,
                                        "httpConnectionTimeoutSeconds": (
                                            OWNER_PROBE_HTTP_TIMEOUT_SECONDS
                                        ),
                                        "hardTimeoutSeconds": (
                                            OWNER_PROBE_HARD_TIMEOUT_SECONDS
                                        ),
                                    }
                                except Exception as probe_start_error:
                                    active_user_probe_start_error = (
                                        f"{type(probe_start_error).__name__}: "
                                        f"{probe_start_error}"
                                    )
                                    frozen_flow[
                                        "postResumeActiveUserProbe"
                                    ] = {
                                        "mode": (
                                            "INDEPENDENT_PROCESS_AND_API_SESSION"
                                        ),
                                        "startError": (
                                            active_user_probe_start_error
                                        ),
                                    }
                            post_resume_samples = sample_gate_timeline(
                                qtest_socket,
                                args.outer_endpoint_bdf,
                                args.outer_root_bdf,
                                mask,
                                delays=(0.0, 0.05, 0.25, 1.0),
                                started_at=post_resume_started,
                            )
                            post_resume_faults = [
                                {
                                    "delaySeconds": item["delaySeconds"],
                                    "actualElapsedSeconds": item[
                                        "actualElapsedSeconds"
                                    ],
                                    "faults": item["safetyFaults"],
                                }
                                for item in post_resume_samples
                                if item["safetyFaults"]
                            ]
                            frozen_flow["postResumeSafetyFaults"] = (
                                post_resume_faults
                            )
                            if post_resume_faults:
                                safety_latched = True
                                try:
                                    frozen_flow[
                                        "postResumeSafetyHold"
                                    ] = transition_qemu(
                                        monitor, "stop", "paused"
                                    )
                                except Exception as hold_error:
                                    frozen_flow[
                                        "postResumeSafetyHoldFault"
                                    ] = (
                                        f"{type(hold_error).__name__}: "
                                        f"{hold_error}"
                                    )
                                if active_user_probe is not None:
                                    active_user_probe.cancel()
                                    active_user_probe = None
                            elif active_vm is not None:
                                if active_user_probe_start_error is not None:
                                    raise RuntimeError(
                                        "independent active-user API probe "
                                        "could not start: "
                                        + active_user_probe_start_error
                                    )
                                assert active_user_probe is not None
                                active_user_payload = active_user_probe.result(
                                    OWNER_PROBE_HARD_TIMEOUT_SECONDS
                                )
                                active_user_probe = None
                                post_resume_active_users = (
                                    active_user_payload["users"]
                                )
                                record[
                                    "immediatePostResumeActivePassthroughUsers"
                                ] = post_resume_active_users
                                frozen_flow[
                                    "postResumeActiveUserProbe"
                                ].update(
                                    {
                                        "capturedAt": active_user_payload[
                                            "capturedAt"
                                        ],
                                        "outcome": "COMPLETED",
                                    }
                                )
                            save_json(
                                case_dir / "post-resume-qtest-timeline.json",
                                post_resume_samples,
                            )
                            frozen_flow["postResumeQtestTimeline"] = {
                                "snapshot": "post-resume-qtest-timeline.json",
                                "samples": [
                                    {
                                        "delaySeconds": item["delaySeconds"],
                                        "actualElapsedSeconds": item[
                                            "actualElapsedSeconds"
                                        ],
                                        "capturedAt": item["capturedAt"],
                                        "readback": item["readback"],
                                    }
                                    for item in post_resume_samples
                                ],
                            }
                            tuple_stable = all(
                                gate_tuple_from_snapshot(
                                    item["snapshot"], mask
                                )
                                == gate_tuple
                                for item in post_resume_samples
                            )
                            root_path_stable = all(
                                root_path_from_snapshot(
                                    item["snapshot"]
                                ).open
                                for item in post_resume_samples
                            )
                            frozen_flow["postResumeGateChecks"] = {
                                "requestedTupleStable": tuple_stable,
                                "rootAuxiliaryPathRemainsOpen": root_path_stable,
                            }
                            if not tuple_stable or not root_path_stable:
                                post_resume_gate_mismatch = {
                                    "requestedTupleStable": tuple_stable,
                                    "rootAuxiliaryPathRemainsOpen": (
                                        root_path_stable
                                    ),
                                }
                        except Exception as sample_error:
                            post_resume_sampling_error = (
                                f"{type(sample_error).__name__}: {sample_error}"
                            )
                            frozen_flow["postResumeSamplingError"] = (
                                post_resume_sampling_error
                            )
                        finally:
                            if active_user_probe is not None:
                                active_user_probe.cancel()
                frozen_flow["finishedAt"] = utc_now()
                save_json(case_dir / "case.json", record)
            if post_resume_faults:
                safety_latched = True
                raise SafetyViolation(
                    "Uncorrectable evidence appeared after ESXi resumed: "
                    + json.dumps(post_resume_faults, sort_keys=True)
                )
            if post_resume_sampling_error is not None:
                raise InconclusiveObservation(
                    "post-resume QTest timeline could not be captured: "
                    + post_resume_sampling_error
                )
            if post_resume_gate_mismatch is not None:
                raise InconclusiveObservation(
                    "ESXi rewrote the controlled gate or auxiliary root path "
                    "during the post-resume sampling window: "
                    + json.dumps(post_resume_gate_mismatch, sort_keys=True)
                )
        else:
            record["injectionAttempted"] = True
            record["injection"] = {
                "startedAt": utc_now(),
                "command": command,
                "safetyClass": "CORRECTABLE_ALLOW_LIST_ONLY",
                "executionState": "QEMU_RUNNING_LEGACY_MODE",
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
            if qtest_socket is not None:
                immediate = outer_qemu_aer_snapshot(
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                )
                save_json(
                    case_dir / "immediate-qtest-after-injection.json",
                    immediate,
                )
                record["injection"]["immediateQtestSnapshot"] = (
                    "immediate-qtest-after-injection.json"
                )
                immediate_faults = outer_snapshot_safety_faults(immediate)
                if immediate_faults:
                    safety_latched = True
                    raise SafetyViolation(
                        "Correctable injection produced Uncorrectable evidence: "
                        + "; ".join(immediate_faults)
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
            qtest_socket,
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
            qtest_socket,
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
            gate_tuple=gate_tuple,
            frozen_transport=frozen_transport,
            post_resume_active_users=post_resume_active_users,
        )
        record["verdict"] = verdict
        if verdict == "FAIL_SAFETY":
            safety_latched = True
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
        safety_latched = True
        record["verdict"] = "FAIL_SAFETY"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    except Exception as error:
        record["verdict"] = "INCONCLUSIVE" if record["injectionAttempted"] else "BLOCKED_ENV"
        record["fault"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if gate_lease is not None and qtest_socket is not None:
            restore_safe = safety_latched or record["verdict"] == "FAIL_SAFETY"
            expected_restore = (
                "SAFE_STOP_HELD_PAUSED" if restore_safe else "RESTORED"
            )
            try:
                restore = restore_gate_lease(
                    monitor,
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                    mask,
                    gate_lease,
                    safe_stop=restore_safe,
                )
                record.setdefault("gateLease", {})["restore"] = restore
                save_json(case_dir / "gate-lease-restore.json", restore)
                if restore["outcome"] != expected_restore:
                    raise SafetyViolation(
                        "gate lease restore did not reach "
                        f"{expected_restore}: {restore['outcome']}"
                    )
            except Exception as restore_error:
                record["restoreFault"] = {
                    "type": type(restore_error).__name__,
                    "message": str(restore_error),
                }
                record["verdict"] = "FAIL_SAFETY"
                if not restore_safe:
                    try:
                        safe_restore = restore_gate_lease(
                            monitor,
                            qtest_socket,
                            args.outer_endpoint_bdf,
                            args.outer_root_bdf,
                            mask,
                            gate_lease,
                            safe_stop=True,
                        )
                        record.setdefault("gateLease", {})[
                            "safeStopFallback"
                        ] = safe_restore
                        save_json(
                            case_dir / "gate-lease-safe-stop.json",
                            safe_restore,
                        )
                        if (
                            safe_restore["outcome"]
                            != "SAFE_STOP_HELD_PAUSED"
                        ):
                            record["restoreFault"][
                                "safeStopFallback"
                            ] = safe_restore["outcome"]
                    except Exception as safe_error:
                        record["restoreFault"]["safeStopFallback"] = (
                            f"{type(safe_error).__name__}: {safe_error}"
                        )
        final_qemu_state = qemu_runtime_state(monitor)
        record["qemuStateBeforeCleanup"] = final_qemu_state
        if (
            final_qemu_state != "running"
            and record["verdict"] != "FAIL_SAFETY"
            and (record["injectionAttempted"] or gate_lease is not None)
        ):
            record["verdict"] = "FAIL_SAFETY"
            record["qemuStateFault"] = (
                "outer QEMU was not confirmed running after controlled "
                "mutation and restore"
            )
        if active_vm is not None:
            if final_qemu_state != "running":
                record["cleanup"] = {
                    "deferred": True,
                    "reason": (
                        "outer QEMU is not confirmed running "
                        f"(state={final_qemu_state}); do not attempt "
                        "SSH/SCP/API cleanup against a possibly frozen ESXi"
                    ),
                    "requiredAction": (
                        "inspect safety evidence, recover or quarantine the "
                        "lab, then remove the runner-created VM"
                    ),
                }
            else:
                try:
                    record["cleanup"] = active_vm.cleanup()
                    if record["cleanup"].get("remainingActiveUsers"):
                        record["verdict"] = (
                            "FAIL"
                            if record["injectionAttempted"]
                            else "BLOCKED_ENV"
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
    assert [gate.label for gate in parse_gate_tuples("000,101,111")] == [
        "000",
        "101",
        "111",
    ]
    for invalid_gates in ("", "00", "000,", "000,000", "012"):
        try:
            parse_gate_tuples(invalid_gates)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"invalid gate tuple list was accepted: {invalid_gates!r}"
            )
    command = build_injection_command("test_fn1", 0x1)
    assert command == "pcie_aer_inject_error -c test_fn1 0x00000001"
    try:
        build_injection_command("test_fn1", 0x00100000)
    except ValueError:
        pass
    else:
        raise AssertionError("uncorrectable mask reached the command builder")

    def synthetic_outer(
        gate: GateTuple,
        *,
        injected: bool,
        override_cere: bool | None = None,
    ) -> dict[str, Any]:
        requester_id = 0x0101
        endpoint_cere = (
            gate.endpoint_cere
            if override_cere is None
            else override_cere
        )
        routed = (
            injected
            and gate.endpoint_cere
            and not gate.endpoint_masked
        )
        return {
            "endpoint": {"requesterId": requester_id},
            "endpointState": {
                "deviceControl": (
                    qemu_aer.PCI_EXP_DEVCTL_CERE if endpoint_cere else 0
                ),
                "deviceStatus": (
                    qemu_aer.PCI_EXP_DEVSTA_CED if injected else 0
                ),
                "correctableErrorStatus": 0x1 if injected else 0,
                "correctableErrorMask": (
                    0x1 if gate.endpoint_masked else 0
                ),
                "uncorrectableErrorStatus": 0,
            },
            "rootState": {
                "bridgeControl": qemu_aer.PCI_BRIDGE_CTL_SERR,
                "deviceControl": qemu_aer.PCI_EXP_DEVCTL_CERE,
                "deviceStatus": 0,
                "correctableErrorStatus": 0,
                "uncorrectableErrorStatus": 0,
                "rootErrorCommand": (
                    qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
                    if gate.root_cor_enabled
                    else 0
                ),
                "rootErrorStatus": (
                    qemu_aer.PCI_ERR_ROOT_COR_RCV if routed else 0
                ),
                "errorSourceIdentification": requester_id if routed else 0,
            },
        }

    unsafe_prewrite = synthetic_outer(
        GateTuple(True, False, False),
        injected=False,
    )
    unsafe_prewrite["endpointState"]["uncorrectableErrorStatus"] = 0x1
    transition_commands: list[str] = []
    saved_transition_qemu = globals()["transition_qemu"]
    saved_outer_snapshot = globals()["outer_qemu_aer_snapshot"]

    def fake_transition_qemu(
        _monitor: Path,
        command: str,
        expected: str,
    ) -> dict[str, str]:
        transition_commands.append(command)
        return {"command": command, "expected": expected}

    try:
        globals()["transition_qemu"] = fake_transition_qemu
        globals()["outer_qemu_aer_snapshot"] = (
            lambda _socket, _endpoint, _root: unsafe_prewrite
        )
        try:
            apply_gate_lease(
                Path("selftest-monitor"),
                Path("selftest-qtest"),
                "0000:01:00.1",
                "0000:00:08.0",
                0x1,
                GateTuple(True, False, False),
                enable_root_path=True,
            )
        except GateLeaseApplyFailure as error:
            assert error.safety
            assert (
                error.lease["outcome"]
                == "PRE_WRITE_SAFETY_FAULT_HELD_PAUSED"
            )
            assert (
                error.lease["original"]["snapshot"]["endpointState"][
                    "uncorrectableErrorStatus"
                ]
                == 0x1
            )
        else:
            raise AssertionError(
                "unsafe pre-write baseline did not fail gate application"
            )
    finally:
        globals()["transition_qemu"] = saved_transition_qemu
        globals()["outer_qemu_aer_snapshot"] = saved_outer_snapshot
    assert transition_commands == ["stop"], transition_commands

    for gate in parse_gate_tuples(
        "000,001,010,011,100,101,110,111"
    ):
        frozen = evaluate_frozen_transport(
            gate,
            0x1,
            synthetic_outer(gate, injected=False),
            synthetic_outer(gate, injected=True),
        )
        assert frozen["verdict"] == "PASS", (gate.label, frozen)
    overridden = evaluate_frozen_transport(
        GateTuple(True, False, False),
        0x1,
        synthetic_outer(GateTuple(True, False, False), injected=False),
        synthetic_outer(
            GateTuple(True, False, False),
            injected=True,
            override_cere=False,
        ),
    )
    assert overridden["verdict"] == "FAIL"
    assert not overridden["checks"]["effectiveTupleStableAfter"]

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
    assert guest_aer_event_lines(
        "aer_dev_correctable:\nTOTAL_ERR_COR 0\n"
    ) == []
    assert guest_aer_event_lines(
        "pcieport 0000:00:01.0: PCIe Bus Error: severity=Corrected\n"
    )
    counter_guest = guest.replace(
        "=== AER injection window open ===",
        "aer_dev_correctable:\nTOTAL_ERR_COR 0\n"
        "aer_dev_fatal:\nTOTAL_ERR_FATAL 0\n"
        "aer_dev_nonfatal:\nTOTAL_ERR_NONFATAL 0\n"
        "=== AER injection window open ===",
    ).replace(
        "=== AER guest probe done ===",
        "aer_dev_correctable:\nTOTAL_ERR_COR 0\n"
        "aer_dev_fatal:\nTOTAL_ERR_FATAL 0\n"
        "aer_dev_nonfatal:\nTOTAL_ERR_NONFATAL 0\n"
        "=== AER guest probe done ===",
    )
    assert guest_aer_counter_totals(counter_guest, "before-injection") == {
        "cor": 0,
        "fatal": 0,
        "nonfatal": 0,
    }
    assert guest_aer_counter_totals(counter_guest, "after-injection") == {
        "cor": 0,
        "fatal": 0,
        "nonfatal": 0,
    }
    assert aer_log_lines(
        [
            "sshd-session: User root running command 'scp -f "
            "/vmfs/volumes/pci-mmio-local/aer-correctable/guest.log'",
            "CpuSched: J6AsyncReplayManager changed by grep -6",
            "PCI-AER-MATRIX injection-complete",
        ]
    ) == []
    assert aer_log_lines(
        [
            "pcieport 0000:00:01.0: PCIe Bus Error: severity=Corrected",
            "AER: Corrected error received",
            "Replay Timer Timeout",
        ]
    ) == [
        "pcieport 0000:00:01.0: PCIe Bus Error: severity=Corrected",
        "AER: Corrected error received",
        "Replay Timer Timeout",
    ]
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
        "--gate-tuples",
        help=(
            "strict comma-separated E/M/R tuples (000-111): Endpoint CERE, "
            "selected Endpoint Correctable Mask bit, Root Command COR_EN"
        ),
    )
    parser.add_argument(
        "--enable-root-path",
        action="store_true",
        help=(
            "with --gate-tuples, lease Root BridgeCtl.SERR=1 and Root "
            "DeviceCtl.CERE=1 as an explicit auxiliary path separate from R"
        ),
    )
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
        gate_tuples = parse_gate_tuples(args.gate_tuples)
        if gate_tuples and not args.qtest_socket:
            raise ValueError("--gate-tuples requires --qtest-socket")
        if gate_tuples and not args.qtest_clean_baseline:
            raise ValueError(
                "--gate-tuples requires --qtest-clean-baseline so every "
                "controlled case starts from verified clean status surfaces"
            )
        if gate_tuples and not args.enable_root_path:
            raise ValueError(
                "--gate-tuples requires --enable-root-path so E/M negative "
                "controls cannot be confounded by a closed upstream path"
            )
        if gate_tuples and args.qtest_baseline_policy != "strict":
            raise ValueError(
                "--gate-tuples requires --qtest-baseline-policy strict"
            )
        if args.enable_root_path and not gate_tuples:
            raise ValueError("--enable-root-path requires --gate-tuples")
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

    gate_plan: list[GateTuple | None] = gate_tuples or [None]
    case_plan = [
        (bit_name, mask, gate_tuple)
        for bit_name, mask in bits
        for gate_tuple in gate_plan
    ]
    planned_case_ids = [
        (
            f"{args.owner_state.lower()}-{bit_name}"
            + (
                f"-g{gate_tuple.label}"
                if gate_tuple is not None
                else ""
            )
        )
        for bit_name, _, gate_tuple in case_plan
    ]
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
            "gateTuples": [gate.as_dict() for gate in gate_tuples],
            "enableRootPath": args.enable_root_path,
            "outerEndpointBdf": args.outer_endpoint_bdf,
            "outerRootBdf": args.outer_root_bdf,
            "oracle": args.oracle,
            "plannedCaseIds": planned_case_ids,
        },
        "cases": {},
        "verdict": "BLOCKED_ENV",
    }
    save_json(output_dir / "result.json", run_result)

    password: str | None = None
    api: ApiSession | None = None
    plan_completed = False
    run_fault = False
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
        for case_index, (bit_name, mask, gate_tuple) in enumerate(case_plan):
            case = run_case(
                args=args,
                run_id=run_id,
                bit_name=bit_name,
                mask=mask,
                gate_tuple=gate_tuple,
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
                    "remainingCasesSkipped": planned_case_ids[case_index + 1 :],
                }
                break
        else:
            plan_completed = True
    except Exception as error:
        run_fault = True
        run_result["verdict"] = "BLOCKED_ENV"
        run_result["fault"] = {"type": type(error).__name__, "message": str(error)}
        run_result["incompletePlan"] = {
            "completedCaseIds": list(run_result["cases"]),
            "remainingCaseIds": [
                case_id
                for case_id in planned_case_ids
                if case_id not in run_result["cases"]
            ],
        }
    finally:
        final_qemu_state = qemu_runtime_state(Path(args.qemu_monitor))
        run_result["finalQemuState"] = final_qemu_state
        if api is not None:
            try:
                api.close(remote_logout=final_qemu_state == "running")
                run_result["apiCloseMode"] = (
                    "REMOTE_LOGOUT"
                    if final_qemu_state == "running"
                    else "LOCAL_DROP_ONLY"
                )
            except Exception as close_error:
                run_result["apiCloseFault"] = {
                    "type": type(close_error).__name__,
                    "message": str(close_error),
                }
        run_result["finishedAt"] = utc_now()
        if run_result["cases"] and (
            plan_completed or "safetyStop" in run_result
        ):
            run_result["verdict"] = aggregate_verdict(run_result["cases"].values())
        elif run_fault:
            run_result["verdict"] = "BLOCKED_ENV"
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
