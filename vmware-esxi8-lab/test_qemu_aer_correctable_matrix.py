#!/usr/bin/env python3
"""Exercise stock QEMU PCIe AER Correctable injection gates without a guest.

The runner uses only the stock ``pcie_aer_inject_error`` HMP command and
QTest PCI configuration accesses.  Every bit/gate tuple starts a fresh QEMU
process, so no status, mask, or source-id state can leak between cases.

This is a register/message-routing test.  It does not corrupt a real TLP or
DLLP and must not be treated as physical-link or device-recovery evidence.

The endpoint is ``virtio-net-pci,aer=on`` because stock QEMU exposes writable
Device Control error-enable bits for that model.  Stock ``e1000e`` exposes an
AER capability but leaves CERE read-only zero, so it cannot exercise the
CERE-enabled routing gates required by this matrix.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MCFG_BASE = 0xB0000000
PCI_CONFIG_ADDRESS = 0xCF8
PCI_CONFIG_DATA = 0xCFC
Q35_PCIEXBAR_OFFSET = 0x60
Q35_PCIEXBAR_ENABLE = 0x1

ROOT_BUS = 0
ROOT_DEVICE = 2
ROOT_FUNCTION = 0
ENDPOINT_BUS = 1
ENDPOINT_DEVICE = 0
ENDPOINT_FUNCTION = 0

PCI_STATUS_CAP_LIST = 0x0010
PCI_CAPABILITY_LIST = 0x34
PCI_CAP_ID_EXP = 0x10
PCI_EXT_CAP_ID_ERR = 0x0001

PCI_PRIMARY_BUS = 0x18
PCI_BRIDGE_CONTROL = 0x3E
PCI_BRIDGE_CTL_SERR = 0x0002

PCI_EXP_FLAGS = 0x02
PCI_EXP_FLAGS_TYPE = 0x00F0
PCI_EXP_TYPE_ENDPOINT = 0x0
PCI_EXP_TYPE_ROOT_PORT = 0x4
PCI_EXP_DEVCTL = 0x08
PCI_EXP_DEVSTA = 0x0A
PCI_EXP_DEVCTL_CERE = 0x0001
PCI_EXP_DEVSTA_CED = 0x0001
PCI_EXP_DEVSTA_ERROR_MASK = 0x000F

PCI_ERR_UNCOR_STATUS = 0x04
PCI_ERR_COR_STATUS = 0x10
PCI_ERR_COR_MASK = 0x14
PCI_ERR_ROOT_COMMAND = 0x2C
PCI_ERR_ROOT_STATUS = 0x30
PCI_ERR_ROOT_ERR_SRC = 0x34
PCI_ERR_ROOT_CMD_COR_EN = 0x00000001
PCI_ERR_ROOT_COR_RCV = 0x00000001
PCI_ERR_ROOT_MULTI_COR_RCV = 0x00000002
PCI_ERR_ROOT_UNCOR_RCV = 0x00000004
PCI_ERR_ROOT_MULTI_UNCOR_RCV = 0x00000008
PCI_ERR_ROOT_FIRST_FATAL = 0x00000010
PCI_ERR_ROOT_NONFATAL_RCV = 0x00000020
PCI_ERR_ROOT_FATAL_RCV = 0x00000040
PCI_ERR_ROOT_COR_MASK = PCI_ERR_ROOT_COR_RCV | PCI_ERR_ROOT_MULTI_COR_RCV
PCI_ERR_ROOT_UNCOR_MASK = (
    PCI_ERR_ROOT_UNCOR_RCV
    | PCI_ERR_ROOT_MULTI_UNCOR_RCV
    | PCI_ERR_ROOT_FIRST_FATAL
    | PCI_ERR_ROOT_NONFATAL_RCV
    | PCI_ERR_ROOT_FATAL_RCV
)
PCI_ERR_ROOT_STATUS_W1C = 0x0000007F


CORRECTABLE_BITS: dict[str, int] = {
    "RCVR": 0x00000001,
    "BAD_TLP": 0x00000040,
    "BAD_DLLP": 0x00000080,
    "REP_ROLL": 0x00000100,
    "REP_TIMER": 0x00001000,
    "ADV_NONFATAL": 0x00002000,
    "INTERNAL": 0x00004000,
    "HL_OVERFLOW": 0x00008000,
}

ORACLE_NOT_RECORDED = "INJECTION_NOT_RECORDED"
ORACLE_CERE_BLOCKED = "RECORDED_CERE_BLOCKED"
ORACLE_MASKED = "RECORDED_MASKED"
ORACLE_CERE_AND_MASK_BLOCKED = "RECORDED_CERE_AND_MASK_BLOCKED"
ORACLE_ROUTED_ROOT_CMD_DISABLED = "ROUTED_ROOT_COMMAND_DISABLED"
ORACLE_ROUTED_ROOT_CMD_ENABLED = "ROUTED_ROOT_COMMAND_ENABLED"


@dataclass(frozen=True)
class Gate:
    name: str
    endpoint_cere: bool
    mask_bit: bool
    root_cor_enable: bool
    expected_oracle: str


GATES: dict[str, Gate] = {
    "g000": Gate(
        name="g000",
        endpoint_cere=False,
        mask_bit=False,
        root_cor_enable=False,
        expected_oracle=ORACLE_CERE_BLOCKED,
    ),
    "g001": Gate(
        name="g001",
        endpoint_cere=False,
        mask_bit=False,
        root_cor_enable=True,
        expected_oracle=ORACLE_CERE_BLOCKED,
    ),
    "g010": Gate(
        name="g010",
        endpoint_cere=False,
        mask_bit=True,
        root_cor_enable=False,
        expected_oracle=ORACLE_CERE_AND_MASK_BLOCKED,
    ),
    "g011": Gate(
        name="g011",
        endpoint_cere=False,
        mask_bit=True,
        root_cor_enable=True,
        expected_oracle=ORACLE_CERE_AND_MASK_BLOCKED,
    ),
    "g100": Gate(
        name="g100",
        endpoint_cere=True,
        mask_bit=False,
        root_cor_enable=False,
        expected_oracle=ORACLE_ROUTED_ROOT_CMD_DISABLED,
    ),
    "g101": Gate(
        name="g101",
        endpoint_cere=True,
        mask_bit=False,
        root_cor_enable=True,
        expected_oracle=ORACLE_ROUTED_ROOT_CMD_ENABLED,
    ),
    "g110": Gate(
        name="g110",
        endpoint_cere=True,
        mask_bit=True,
        root_cor_enable=False,
        expected_oracle=ORACLE_MASKED,
    ),
    "g111": Gate(
        name="g111",
        endpoint_cere=True,
        mask_bit=True,
        root_cor_enable=True,
        expected_oracle=ORACLE_MASKED,
    ),
}

GATE_ALIASES: dict[str, str] = {
    "cere-blocked": "g000",
    "routed-root-command-disabled": "g100",
    "masked-at-endpoint": "g110",
}


class QTestClient:
    def __init__(self, path: Path):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(3)
        self.connection.connect(str(path))

    def close(self) -> None:
        self.connection.close()

    def command(self, command: str) -> str:
        self.connection.sendall(command.encode("ascii") + b"\n")
        response = b""
        while b"\n" not in response:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise ConnectionError("QTest socket closed before a response")
            response += chunk
        return response.decode("ascii", errors="replace").strip()


def qtest(client: QTestClient, command: str) -> int | None:
    response = client.command(command)
    if not response.startswith("OK"):
        raise RuntimeError(f"QTest command failed: {command!r}: {response!r}")
    match = re.search(r"0x[0-9a-fA-F]+|\b\d+\b", response[2:])
    return int(match.group(0), 0) if match else None


def wait_socket(path: Path, process: subprocess.Popen[str], timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(
                f"QEMU exited with {process.returncode} before creating {path}"
            )
        time.sleep(0.02)
    raise TimeoutError(f"QEMU did not create {path} within {timeout}s")


def recv_until(
    connection: socket.socket,
    marker: bytes,
    *,
    allow_eof: bool = False,
) -> bytes:
    response = b""
    while marker not in response:
        try:
            chunk = connection.recv(65536)
        except socket.timeout:
            if allow_eof and response:
                break
            raise
        if not chunk:
            if allow_eof:
                break
            raise ConnectionError(f"HMP socket closed before marker {marker!r}")
        response += chunk
    return response


def hmp_command(path: Path, command: str, *, expect_prompt: bool = True) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(path))
        banner = recv_until(monitor, b"(qemu)")
        monitor.sendall(command.encode("ascii") + b"\n")
        output = recv_until(
            monitor,
            b"(qemu)",
            allow_eof=not expect_prompt,
        )
    return (banner + output).decode("utf-8", errors="replace")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path: Path, value: Any) -> str:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    digest = sha256_file(path)
    path.with_name(path.name + ".sha256").write_text(
        f"{digest}  {path.name}\n",
        encoding="ascii",
    )
    return digest


def pio_read32(client: QTestClient, port: int) -> int:
    value = qtest(client, f"inl 0x{port:x}")
    if value is None:
        raise RuntimeError("QTest inl returned no value")
    return value


def pio_write32(client: QTestClient, port: int, value: int) -> None:
    qtest(client, f"outl 0x{port:x} 0x{value:08x}")


def legacy_config_address(
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    return (
        0x80000000
        | (bus << 16)
        | (device << 11)
        | (function << 8)
        | (offset & 0xFC)
    )


def legacy_config_read32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    pio_write32(
        client,
        PCI_CONFIG_ADDRESS,
        legacy_config_address(bus, device, function, offset),
    )
    return pio_read32(client, PCI_CONFIG_DATA)


def legacy_config_write32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    pio_write32(
        client,
        PCI_CONFIG_ADDRESS,
        legacy_config_address(bus, device, function, offset),
    )
    pio_write32(client, PCI_CONFIG_DATA, value)


def enable_q35_ecam(client: QTestClient) -> dict[str, int]:
    before = legacy_config_read32(client, 0, 0, 0, Q35_PCIEXBAR_OFFSET)
    expected = MCFG_BASE | Q35_PCIEXBAR_ENABLE
    legacy_config_write32(client, 0, 0, 0, Q35_PCIEXBAR_OFFSET, expected)
    after = legacy_config_read32(client, 0, 0, 0, Q35_PCIEXBAR_OFFSET)
    if after != expected:
        raise RuntimeError(
            "failed to enable Q35 ECAM: "
            f"before=0x{before:08x}, after=0x{after:08x}"
        )
    return {"before": before, "after": after}


def configure_root_port_bus(client: QTestClient) -> dict[str, int]:
    before = legacy_config_read32(
        client, ROOT_BUS, ROOT_DEVICE, ROOT_FUNCTION, PCI_PRIMARY_BUS
    )
    after_requested = (before & 0xFF000000) | 0x00010100
    legacy_config_write32(
        client,
        ROOT_BUS,
        ROOT_DEVICE,
        ROOT_FUNCTION,
        PCI_PRIMARY_BUS,
        after_requested,
    )
    after = legacy_config_read32(
        client, ROOT_BUS, ROOT_DEVICE, ROOT_FUNCTION, PCI_PRIMARY_BUS
    )
    if after & 0x00FFFFFF != 0x00010100:
        raise RuntimeError(
            "failed to configure root-port bus numbers: "
            f"before=0x{before:08x}, after=0x{after:08x}"
        )
    return {"before": before, "after": after}


def ecam_address(
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    return (
        MCFG_BASE
        + (bus << 20)
        + (device << 15)
        + (function << 12)
        + offset
    )


def config_read(
    client: QTestClient,
    width: int,
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    command = {1: "readb", 2: "readw", 4: "readl"}[width]
    value = qtest(
        client,
        f"{command} 0x{ecam_address(bus, device, function, offset):x}",
    )
    if value is None:
        raise RuntimeError(f"QTest {command} returned no value")
    return value


def config_write(
    client: QTestClient,
    width: int,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    command = {1: "writeb", 2: "writew", 4: "writel"}[width]
    digits = width * 2
    qtest(
        client,
        f"{command} 0x{ecam_address(bus, device, function, offset):x} "
        f"0x{value:0{digits}x}",
    )


def config_read8(
    client: QTestClient, bus: int, device: int, function: int, offset: int
) -> int:
    return config_read(client, 1, bus, device, function, offset)


def config_read16(
    client: QTestClient, bus: int, device: int, function: int, offset: int
) -> int:
    return config_read(client, 2, bus, device, function, offset)


def config_read32(
    client: QTestClient, bus: int, device: int, function: int, offset: int
) -> int:
    return config_read(client, 4, bus, device, function, offset)


def config_write16(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    config_write(client, 2, bus, device, function, offset, value)


def config_write32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    config_write(client, 4, bus, device, function, offset, value)


def find_standard_capability(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    capability_id: int,
) -> int | None:
    status = config_read16(client, bus, device, function, 0x06)
    if not status & PCI_STATUS_CAP_LIST:
        return None
    pointer = config_read8(
        client, bus, device, function, PCI_CAPABILITY_LIST
    ) & 0xFC
    visited: set[int] = set()
    while pointer and pointer not in visited:
        visited.add(pointer)
        if config_read8(client, bus, device, function, pointer) == capability_id:
            return pointer
        pointer = config_read8(client, bus, device, function, pointer + 1) & 0xFC
    return None


def find_extended_capability(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    capability_id: int,
) -> int | None:
    pointer = 0x100
    visited: set[int] = set()
    while pointer and pointer not in visited:
        visited.add(pointer)
        header = config_read32(client, bus, device, function, pointer)
        if header in (0, 0xFFFFFFFF):
            return None
        if header & 0xFFFF == capability_id:
            return pointer
        pointer = (header >> 20) & 0xFFC
    return None


def discover_device(
    client: QTestClient,
    *,
    bus: int,
    device: int,
    function: int,
    expected_type: int,
) -> dict[str, int]:
    vendor = config_read16(client, bus, device, function, 0x00)
    device_id = config_read16(client, bus, device, function, 0x02)
    if vendor == 0xFFFF:
        raise RuntimeError(
            f"PCI device absent at {bus:02x}:{device:02x}.{function}"
        )
    pcie = find_standard_capability(
        client, bus, device, function, PCI_CAP_ID_EXP
    )
    aer = find_extended_capability(
        client, bus, device, function, PCI_EXT_CAP_ID_ERR
    )
    if pcie is None or aer is None:
        raise RuntimeError(
            f"missing PCIe/AER capability at {bus:02x}:{device:02x}.{function}: "
            f"pcie={pcie}, aer={aer}"
        )
    flags = config_read16(client, bus, device, function, pcie + PCI_EXP_FLAGS)
    observed_type = (flags & PCI_EXP_FLAGS_TYPE) >> 4
    if observed_type != expected_type:
        raise RuntimeError(
            f"unexpected PCIe type at {bus:02x}:{device:02x}.{function}: "
            f"expected {expected_type}, got {observed_type}"
        )
    aer_header = config_read32(client, bus, device, function, aer)
    if aer_header & 0xFFFF != PCI_EXT_CAP_ID_ERR:
        raise RuntimeError(
            f"AER offset validation failed at 0x{aer:x}: "
            f"header=0x{aer_header:08x}"
        )
    return {
        "bus": bus,
        "device": device,
        "function": function,
        "requesterId": (bus << 8) | (device << 3) | function,
        "vendorId": vendor,
        "deviceId": device_id,
        "pcieCapabilityOffset": pcie,
        "aerCapabilityOffset": aer,
        "aerHeader": aer_header,
        "pcieType": observed_type,
    }


def endpoint_snapshot(
    client: QTestClient,
    endpoint: dict[str, int],
) -> dict[str, int]:
    b, d, f = endpoint["bus"], endpoint["device"], endpoint["function"]
    pcie, aer = endpoint["pcieCapabilityOffset"], endpoint["aerCapabilityOffset"]
    return {
        "deviceControl": config_read16(client, b, d, f, pcie + PCI_EXP_DEVCTL),
        "deviceStatus": config_read16(client, b, d, f, pcie + PCI_EXP_DEVSTA),
        "uncorrectableErrorStatus": config_read32(
            client, b, d, f, aer + PCI_ERR_UNCOR_STATUS
        ),
        "correctableErrorStatus": config_read32(
            client, b, d, f, aer + PCI_ERR_COR_STATUS
        ),
        "correctableErrorMask": config_read32(
            client, b, d, f, aer + PCI_ERR_COR_MASK
        ),
    }


def root_snapshot(
    client: QTestClient,
    root: dict[str, int],
) -> dict[str, int]:
    b, d, f = root["bus"], root["device"], root["function"]
    pcie, aer = root["pcieCapabilityOffset"], root["aerCapabilityOffset"]
    return {
        "bridgeControl": config_read16(
            client, b, d, f, PCI_BRIDGE_CONTROL
        ),
        "deviceControl": config_read16(client, b, d, f, pcie + PCI_EXP_DEVCTL),
        "deviceStatus": config_read16(client, b, d, f, pcie + PCI_EXP_DEVSTA),
        "uncorrectableErrorStatus": config_read32(
            client, b, d, f, aer + PCI_ERR_UNCOR_STATUS
        ),
        "correctableErrorStatus": config_read32(
            client, b, d, f, aer + PCI_ERR_COR_STATUS
        ),
        "rootErrorCommand": config_read32(
            client, b, d, f, aer + PCI_ERR_ROOT_COMMAND
        ),
        "rootErrorStatus": config_read32(
            client, b, d, f, aer + PCI_ERR_ROOT_STATUS
        ),
        "errorSourceIdentification": config_read32(
            client, b, d, f, aer + PCI_ERR_ROOT_ERR_SRC
        ),
    }


def clear_and_configure_case(
    client: QTestClient,
    endpoint: dict[str, int],
    root: dict[str, int],
    bit: int,
    gate: Gate,
) -> None:
    eb, ed, ef = endpoint["bus"], endpoint["device"], endpoint["function"]
    epcie = endpoint["pcieCapabilityOffset"]
    eaer = endpoint["aerCapabilityOffset"]
    rb, rd, rf = root["bus"], root["device"], root["function"]
    rpcie = root["pcieCapabilityOffset"]
    raer = root["aerCapabilityOffset"]

    config_write16(
        client, eb, ed, ef, epcie + PCI_EXP_DEVSTA, PCI_EXP_DEVSTA_ERROR_MASK
    )
    config_write32(client, eb, ed, ef, eaer + PCI_ERR_UNCOR_STATUS, 0xFFFFFFFF)
    config_write32(client, eb, ed, ef, eaer + PCI_ERR_COR_STATUS, 0xFFFFFFFF)
    config_write16(
        client, rb, rd, rf, rpcie + PCI_EXP_DEVSTA, PCI_EXP_DEVSTA_ERROR_MASK
    )
    config_write32(client, rb, rd, rf, raer + PCI_ERR_UNCOR_STATUS, 0xFFFFFFFF)
    config_write32(client, rb, rd, rf, raer + PCI_ERR_COR_STATUS, 0xFFFFFFFF)
    config_write32(client, rb, rd, rf, raer + PCI_ERR_ROOT_STATUS,
                   PCI_ERR_ROOT_STATUS_W1C)

    endpoint_control = config_read16(
        client, eb, ed, ef, epcie + PCI_EXP_DEVCTL
    )
    if gate.endpoint_cere:
        endpoint_control |= PCI_EXP_DEVCTL_CERE
    else:
        endpoint_control &= ~PCI_EXP_DEVCTL_CERE
    config_write16(client, eb, ed, ef, epcie + PCI_EXP_DEVCTL,
                   endpoint_control)

    correctable_mask = config_read32(
        client, eb, ed, ef, eaer + PCI_ERR_COR_MASK
    )
    if gate.mask_bit:
        correctable_mask |= bit
    else:
        correctable_mask &= ~bit
    config_write32(client, eb, ed, ef, eaer + PCI_ERR_COR_MASK,
                   correctable_mask)

    bridge_control = config_read16(client, rb, rd, rf, PCI_BRIDGE_CONTROL)
    config_write16(client, rb, rd, rf, PCI_BRIDGE_CONTROL,
                   bridge_control | PCI_BRIDGE_CTL_SERR)
    root_control = config_read16(client, rb, rd, rf, rpcie + PCI_EXP_DEVCTL)
    config_write16(client, rb, rd, rf, rpcie + PCI_EXP_DEVCTL,
                   root_control | PCI_EXP_DEVCTL_CERE)
    root_command = config_read32(
        client, rb, rd, rf, raer + PCI_ERR_ROOT_COMMAND
    )
    if gate.root_cor_enable:
        root_command |= PCI_ERR_ROOT_CMD_COR_EN
    else:
        root_command &= ~PCI_ERR_ROOT_CMD_COR_EN
    config_write32(client, rb, rd, rf, raer + PCI_ERR_ROOT_COMMAND,
                   root_command)


def classify_oracle(
    *,
    bit: int,
    endpoint_requester_id: int,
    after_endpoint: dict[str, int],
    after_root: dict[str, int],
) -> str:
    recorded = bool(
        after_endpoint["deviceStatus"] & PCI_EXP_DEVSTA_CED
        and after_endpoint["correctableErrorStatus"] & bit
    )
    if not recorded:
        return ORACLE_NOT_RECORDED
    routed = bool(after_root["rootErrorStatus"] & PCI_ERR_ROOT_COR_RCV)
    source_matches = (
        after_root["errorSourceIdentification"] & 0xFFFF
    ) == endpoint_requester_id
    if routed and source_matches:
        if after_root["rootErrorCommand"] & PCI_ERR_ROOT_CMD_COR_EN:
            return ORACLE_ROUTED_ROOT_CMD_ENABLED
        return ORACLE_ROUTED_ROOT_CMD_DISABLED
    masked = bool(after_endpoint["correctableErrorMask"] & bit)
    cere_enabled = bool(
        after_endpoint["deviceControl"] & PCI_EXP_DEVCTL_CERE
    )
    if masked and not cere_enabled:
        return ORACLE_CERE_AND_MASK_BLOCKED
    if masked:
        return ORACLE_MASKED
    if not cere_enabled:
        return ORACLE_CERE_BLOCKED
    return ORACLE_NOT_RECORDED


def evaluate_case(
    *,
    bit: int,
    gate: Gate,
    endpoint_requester_id: int,
    before_endpoint: dict[str, int],
    before_root: dict[str, int],
    after_endpoint: dict[str, int],
    after_root: dict[str, int],
    hmp_raw: str,
) -> tuple[str, dict[str, bool]]:
    oracle = classify_oracle(
        bit=bit,
        endpoint_requester_id=endpoint_requester_id,
        after_endpoint=after_endpoint,
        after_root=after_root,
    )
    checks = {
        "cleanEndpointCesBaseline": before_endpoint["correctableErrorStatus"] == 0,
        "cleanEndpointUesBaseline": before_endpoint["uncorrectableErrorStatus"] == 0,
        "cleanEndpointDeviceStatusBaseline": not bool(
            before_endpoint["deviceStatus"] & PCI_EXP_DEVSTA_ERROR_MASK
        ),
        "cleanRootCesBaseline": before_root["correctableErrorStatus"] == 0,
        "cleanRootUesBaseline": before_root["uncorrectableErrorStatus"] == 0,
        "cleanRootDeviceStatusBaseline": not bool(
            before_root["deviceStatus"] & PCI_EXP_DEVSTA_ERROR_MASK
        ),
        "cleanRootStatusBaseline": before_root["rootErrorStatus"] == 0,
        "cleanRootSourceBaseline": before_root["errorSourceIdentification"] == 0,
        "rootBridgeSerrEnabled": bool(
            before_root["bridgeControl"] & PCI_BRIDGE_CTL_SERR
        ),
        "rootCereEnabled": bool(
            before_root["deviceControl"] & PCI_EXP_DEVCTL_CERE
        ),
        "rootCorrectableCommandMatchesGate": bool(
            before_root["rootErrorCommand"] & PCI_ERR_ROOT_CMD_COR_EN
        ) == gate.root_cor_enable,
        "endpointCereMatchesGate": bool(
            before_endpoint["deviceControl"] & PCI_EXP_DEVCTL_CERE
        ) == gate.endpoint_cere,
        "endpointMaskMatchesGate": bool(
            before_endpoint["correctableErrorMask"] & bit
        ) == gate.mask_bit,
        "hmpAccepted": "OK id: ep" in hmp_raw,
        "endpointCedSet": bool(
            after_endpoint["deviceStatus"] & PCI_EXP_DEVSTA_CED
        ),
        "endpointDeviceStatusCorrectableOnly": (
            after_endpoint["deviceStatus"] & PCI_EXP_DEVSTA_ERROR_MASK
        ) == PCI_EXP_DEVSTA_CED,
        "endpointUesRemainsZero": after_endpoint["uncorrectableErrorStatus"] == 0,
        "exactCesBitSet": after_endpoint["correctableErrorStatus"] == bit,
        "rootDeviceStatusHasNoError": not bool(
            after_root["deviceStatus"] & PCI_EXP_DEVSTA_ERROR_MASK
        ),
        "rootUesRemainsZero": after_root["uncorrectableErrorStatus"] == 0,
        "rootCesRemainsZero": after_root["correctableErrorStatus"] == 0,
        "rootHasNoUncorrectableReception": not bool(
            after_root["rootErrorStatus"] & PCI_ERR_ROOT_UNCOR_MASK
        ),
        "uncorrectableSourceRemainsZero": not bool(
            after_root["errorSourceIdentification"] & 0xFFFF0000
        ),
        "oracleMatchesGate": oracle == gate.expected_oracle,
    }
    if gate.expected_oracle in (
        ORACLE_ROUTED_ROOT_CMD_DISABLED,
        ORACLE_ROUTED_ROOT_CMD_ENABLED,
    ):
        checks.update(
            {
                "rootCorrectableReceived": bool(
                    after_root["rootErrorStatus"] & PCI_ERR_ROOT_COR_RCV
                ),
                "rootCorrectableStatusExact": (
                    after_root["rootErrorStatus"] & PCI_ERR_ROOT_STATUS_W1C
                ) == PCI_ERR_ROOT_COR_RCV,
                "rootMultipleCorrectableClear": not bool(
                    after_root["rootErrorStatus"] & PCI_ERR_ROOT_MULTI_COR_RCV
                ),
                "rootCorrectableSourceMatches": (
                    after_root["errorSourceIdentification"] & 0xFFFF
                ) == endpoint_requester_id,
                "rootCommandStillMatchesGate": bool(
                    after_root["rootErrorCommand"] & PCI_ERR_ROOT_CMD_COR_EN
                ) == gate.root_cor_enable,
            }
        )
    else:
        checks.update(
            {
                "rootCorrectableNotReceived": not bool(
                    after_root["rootErrorStatus"] & PCI_ERR_ROOT_COR_MASK
                ),
                "rootStatusRemainsZero": after_root["rootErrorStatus"] == 0,
                "rootSourceUnchanged": after_root[
                    "errorSourceIdentification"
                ] == before_root["errorSourceIdentification"],
            }
        )
    return oracle, checks


def terminate_process(process: subprocess.Popen[str], monitor_path: Path) -> None:
    if process.poll() is not None:
        return
    try:
        hmp_command(monitor_path, "quit", expect_prompt=False)
        process.wait(timeout=5)
    except Exception:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_case(
    *,
    qemu: Path,
    output_dir: Path,
    bit_name: str,
    gate: Gate,
    timeout: int,
) -> dict[str, Any]:
    bit = CORRECTABLE_BITS[bit_name]
    case_id = f"{bit_name.lower()}__{gate.name}"
    case_dir = output_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    hmp_path = case_dir / "hmp.txt"
    stderr_path = case_dir / "qemu-stderr.txt"
    case_result_path = case_dir / "result.json"
    result: dict[str, Any] = {
        "caseId": case_id,
        "bitName": bit_name,
        "bit": bit,
        "gate": gate.name,
        "gateTuple": {
            "endpointCere": gate.endpoint_cere,
            "correctableMaskBit": gate.mask_bit,
            "rootCorrectableCommand": gate.root_cor_enable,
        },
        "expectedOracleState": gate.expected_oracle,
        "verdict": "RUNNING",
    }

    with tempfile.TemporaryDirectory(prefix=f"qemu-aer-{case_id}-") as temporary:
        temporary_path = Path(temporary)
        qtest_path = temporary_path / "qtest.sock"
        monitor_path = temporary_path / "monitor.sock"
        command = [
            str(qemu),
            "-nodefaults",
            "-machine",
            "q35,accel=qtest",
            "-display",
            "none",
            "-S",
            "-nic",
            "none",
            "-device",
            "pcie-root-port,id=rp,bus=pcie.0,addr=0x02.0,chassis=2,slot=2",
            "-device",
            (
                "virtio-net-pci,id=ep,bus=rp,addr=0x00.0,"
                "disable-legacy=on,aer=on"
            ),
            "-qtest",
            f"unix:{qtest_path},server=on,wait=off",
            "-monitor",
            f"unix:{monitor_path},server,nowait",
        ]
        result["command"] = command
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        client: QTestClient | None = None
        try:
            wait_socket(qtest_path, process, timeout)
            wait_socket(monitor_path, process, timeout)
            client = QTestClient(qtest_path)
            result["q35Pciexbar"] = enable_q35_ecam(client)
            result["rootPortBusNumbers"] = configure_root_port_bus(client)
            root = discover_device(
                client,
                bus=ROOT_BUS,
                device=ROOT_DEVICE,
                function=ROOT_FUNCTION,
                expected_type=PCI_EXP_TYPE_ROOT_PORT,
            )
            endpoint = discover_device(
                client,
                bus=ENDPOINT_BUS,
                device=ENDPOINT_DEVICE,
                function=ENDPOINT_FUNCTION,
                expected_type=PCI_EXP_TYPE_ENDPOINT,
            )
            result["rootPort"] = root
            result["endpoint"] = endpoint

            clear_and_configure_case(client, endpoint, root, bit, gate)
            before_endpoint = endpoint_snapshot(client, endpoint)
            before_root = root_snapshot(client, root)
            result["before"] = {
                "endpoint": before_endpoint,
                "rootPort": before_root,
            }

            hmp_raw = hmp_command(
                monitor_path,
                f"pcie_aer_inject_error ep {bit_name}",
            )
            hmp_path.write_text(hmp_raw, encoding="utf-8")

            after_endpoint = endpoint_snapshot(client, endpoint)
            after_root = root_snapshot(client, root)
            result["after"] = {
                "endpoint": after_endpoint,
                "rootPort": after_root,
            }
            oracle, checks = evaluate_case(
                bit=bit,
                gate=gate,
                endpoint_requester_id=endpoint["requesterId"],
                before_endpoint=before_endpoint,
                before_root=before_root,
                after_endpoint=after_endpoint,
                after_root=after_root,
                hmp_raw=hmp_raw,
            )
            result["oracleState"] = oracle
            result["checks"] = checks
            result["verdict"] = "PASS" if all(checks.values()) else "FAIL"
        except Exception as error:
            result["verdict"] = "BLOCKED"
            result["fault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
        finally:
            if client is not None:
                client.close()
            terminate_process(process, monitor_path)
            stdout, stderr = process.communicate(timeout=5)
            result["qemuExitCode"] = process.returncode
            result["qemuStdout"] = stdout
            stderr_path.write_text(stderr, encoding="utf-8")
            if not hmp_path.exists():
                hmp_path.write_text("", encoding="utf-8")

    result["artifacts"] = {
        "hmp": {
            "path": str(hmp_path.relative_to(output_dir)),
            "sha256": sha256_file(hmp_path),
        },
        "qemuStderr": {
            "path": str(stderr_path.relative_to(output_dir)),
            "sha256": sha256_file(stderr_path),
        },
    }
    case_digest = save_json(case_result_path, result)
    result["artifacts"]["caseResult"] = {
        "path": str(case_result_path.relative_to(output_dir)),
        "sha256": case_digest,
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a no-guest stock-QEMU HMP+QTest matrix for all supported "
            "PCIe AER Correctable single-bit injections."
        )
    )
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64",
        help="QEMU 11 binary containing the stock PCIe AER HMP path",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--bit",
        action="append",
        choices=tuple(CORRECTABLE_BITS),
        help="run only this bit; repeat for multiple bits (default: all eight)",
    )
    parser.add_argument(
        "--gate",
        action="append",
        choices=tuple(GATES) + tuple(GATE_ALIASES),
        help=(
            "run only this gEMR tuple; repeat for multiple gates (default: all "
            "eight). Legacy aliases cere-blocked, masked-at-endpoint, and "
            "routed-root-command-disabled remain accepted"
        ),
    )
    parser.add_argument("--socket-timeout", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    qemu = Path(args.qemu).resolve()
    if not qemu.is_file():
        raise FileNotFoundError(qemu)
    output_dir = Path(args.output).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    version = subprocess.run(
        [str(qemu), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()[0]
    if not re.search(r"QEMU emulator version 11(?:\.|\b)", version):
        raise RuntimeError(f"expected QEMU 11, got: {version}")

    bit_names = args.bit or list(CORRECTABLE_BITS)
    requested_gate_names = args.gate or list(GATES)
    gate_names = [GATE_ALIASES.get(name, name) for name in requested_gate_names]
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "case": "QEMU-11-stock-AER-Correctable-single-bit-gate-matrix",
        "scope": (
            "No-guest HMP+QTest register and message-routing behavior only; "
            "no physical PCIe fault or recovery claim"
        ),
        "topology": {
            "machine": "q35,accel=qtest",
            "rootPort": "pcie-root-port,id=rp",
            "endpoint": "virtio-net-pci,id=ep,disable-legacy=on,aer=on",
            "endpointSelectionReason": (
                "stock QEMU makes the endpoint DeviceCtl error-enable bits "
                "writable for this model; e1000e leaves CERE read-only zero"
            ),
        },
        "qemu": {
            "path": str(qemu),
            "version": version,
            "sha256": sha256_file(qemu),
        },
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "requestedBits": bit_names,
        "requestedGates": gate_names,
        "oracleStates": [
            ORACLE_NOT_RECORDED,
            ORACLE_CERE_BLOCKED,
            ORACLE_MASKED,
            ORACLE_CERE_AND_MASK_BLOCKED,
            ORACLE_ROUTED_ROOT_CMD_DISABLED,
            ORACLE_ROUTED_ROOT_CMD_ENABLED,
        ],
        "cases": [],
        "verdict": "RUNNING",
    }
    save_json(output_dir / "result.json", result)

    for bit_name in bit_names:
        for gate_name in gate_names:
            case_result = run_case(
                qemu=qemu,
                output_dir=output_dir,
                bit_name=bit_name,
                gate=GATES[gate_name],
                timeout=args.socket_timeout,
            )
            result["cases"].append(case_result)
            save_json(output_dir / "result.json", result)

    verdicts = [case["verdict"] for case in result["cases"]]
    if verdicts and all(verdict == "PASS" for verdict in verdicts):
        result["verdict"] = "PASS"
    elif any(verdict == "BLOCKED" for verdict in verdicts):
        result["verdict"] = "BLOCKED"
    else:
        result["verdict"] = "FAIL"
    result_digest = save_json(output_dir / "result.json", result)
    print(json.dumps({
        "verdict": result["verdict"],
        "caseCount": len(result["cases"]),
        "result": str(output_dir / "result.json"),
        "sha256": result_digest,
    }, indent=2))
    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
