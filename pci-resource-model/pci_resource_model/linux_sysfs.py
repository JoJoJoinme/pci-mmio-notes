from __future__ import annotations

import os
import platform
import re
from dataclasses import replace
from pathlib import Path
from typing import Iterable

from .model import (
    AcsState,
    Bar,
    BarSpace,
    DeviceInventory,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
)


BDF_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
IORESOURCE_IO = 0x00000100
IORESOURCE_MEM = 0x00000200
IORESOURCE_PREFETCH = 0x00002000
IORESOURCE_MEM_64 = 0x00100000
PCI_HEADER_TYPE = 0x0E
PCI_BASE_ADDRESS_0 = 0x10
PCI_BASE_ADDRESS_SPACE_IO = 0x01
PCI_BASE_ADDRESS_MEM_TYPE_MASK = 0x06
PCI_BASE_ADDRESS_MEM_TYPE_1M = 0x02
PCI_BASE_ADDRESS_MEM_TYPE_64 = 0x04
PCI_EXT_CAP_ID_ACS = 0x000D


def _read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except (FileNotFoundError, PermissionError, OSError):
        return default


def _read_hex(path: Path, default: int = 0) -> int:
    text = _read_text(path)
    return int(text, 0) if text else default


def _read_config(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(4096)
    except (FileNotFoundError, PermissionError, OSError):
        return b""


def _le16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _le32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def parse_acs_state(config: bytes) -> AcsState | None:
    if len(config) < 0x104:
        return None
    offset = 0x100
    visited: set[int] = set()
    while offset and offset not in visited and offset + 4 <= len(config):
        visited.add(offset)
        header = _le32(config, offset)
        if header in (0, 0xFFFFFFFF):
            return None
        capability_id = header & 0xFFFF
        if capability_id == PCI_EXT_CAP_ID_ACS and offset + 8 <= len(config):
            return AcsState(
                capability=_le16(config, offset + 4),
                control=_le16(config, offset + 6),
                offset=offset,
            )
        next_offset = (header >> 20) & 0xFFF
        if next_offset < 0x100 or next_offset % 4:
            return None
        offset = next_offset
    return None


def parse_resource_lines(
    text: str,
    *,
    bdf: str,
    header_type: int,
    config: bytes = b"",
) -> tuple[Bar, ...]:
    slot_count = 6 if header_type == 0 else 2 if header_type == 1 else 0
    entries: list[tuple[int, int, int]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        entries.append(tuple(int(field, 0) for field in fields[:3]))

    bars: list[Bar] = []
    index = 0
    while index < min(slot_count, len(entries)):
        start, end, flags = entries[index]
        raw = (
            _le32(config, PCI_BASE_ADDRESS_0 + index * 4)
            if len(config) >= PCI_BASE_ADDRESS_0 + (index + 1) * 4
            else 0
        )
        if not flags and start == 0 and end == 0:
            index += 1
            continue
        if end < start:
            index += 1
            continue
        size = end - start + 1
        is_io = bool(flags & IORESOURCE_IO) or bool(raw & PCI_BASE_ADDRESS_SPACE_IO)
        if is_io:
            bars.append(
                Bar(
                    bdf=bdf,
                    index=index,
                    size=size,
                    space=BarSpace.IO,
                    address=start,
                    source="linux-sysfs-resource",
                )
            )
            index += 1
            continue

        if not (flags & IORESOURCE_MEM) and not config:
            index += 1
            continue
        memory_type = raw & PCI_BASE_ADDRESS_MEM_TYPE_MASK
        is_64 = bool(flags & IORESOURCE_MEM_64) or (
            memory_type == PCI_BASE_ADDRESS_MEM_TYPE_64
        )
        bars.append(
            Bar(
                bdf=bdf,
                index=index,
                size=size,
                space=BarSpace.MEMORY,
                address=start,
                is_64=is_64,
                prefetchable=bool(flags & IORESOURCE_PREFETCH),
                below_1m=memory_type == PCI_BASE_ADDRESS_MEM_TYPE_1M,
                source="linux-sysfs-resource",
            )
        )
        index += 2 if is_64 else 1
    return tuple(bars)


def _iommu_group(device_path: Path) -> tuple[str, ...]:
    link = device_path / "iommu_group"
    if not link.exists():
        return ()
    try:
        group_path = link.resolve(strict=True)
    except (FileNotFoundError, OSError):
        return ()
    members = group_path / "devices"
    if not members.is_dir():
        return ()
    return tuple(
        sorted(
            path.name.lower()
            for path in members.iterdir()
            if BDF_PATTERN.match(path.name)
        )
    )


def _parent_bdf(device_path: Path, bdf: str) -> str | None:
    try:
        components = [part.lower() for part in device_path.resolve().parts]
    except OSError:
        return None
    matches = [part for part in components if BDF_PATTERN.match(part)]
    if matches and matches[-1] == bdf.lower():
        matches.pop()
    return matches[-1] if matches else None


def _driver_name(device_path: Path) -> str | None:
    link = device_path / "driver"
    if not link.exists():
        return None
    try:
        return link.resolve(strict=True).name
    except (FileNotFoundError, OSError):
        return None


def _reset_methods(device_path: Path) -> tuple[str, ...]:
    methods = _read_text(device_path / "reset_method")
    if methods:
        return tuple(
            dict.fromkeys(token.strip("[]").lower() for token in methods.split())
        )
    if (device_path / "reset").exists():
        return ("unknown",)
    return ()


def _function_role(device_path: Path, header_type: int) -> FunctionRole:
    if header_type == 1:
        return FunctionRole.FABRIC
    pci_bus = device_path / "pci_bus"
    try:
        spawns_bus = pci_bus.is_dir() and any(pci_bus.iterdir())
    except OSError:
        spawns_bus = False
    if spawns_bus:
        return FunctionRole.FABRIC
    if (device_path / "physfn").exists():
        return FunctionRole.VIRTUAL_FUNCTION
    if header_type == 0:
        return FunctionRole.ENDPOINT
    return FunctionRole.UNKNOWN


def _scan_device(
    device_path: Path,
    *,
    acs_override_active: bool,
) -> DeviceInventory:
    bdf = device_path.name.lower()
    config = _read_config(device_path / "config")
    header_type = (
        config[PCI_HEADER_TYPE] & 0x7F if len(config) > PCI_HEADER_TYPE else 0x7F
    )
    role = _function_role(device_path, header_type)
    group = _iommu_group(device_path)
    if group and acs_override_active:
        provenance = IsolationProvenance.ACS_OVERRIDE
        physical_domain: tuple[str, ...] = ()
    elif group:
        provenance = IsolationProvenance.KERNEL_GROUP
        physical_domain = group
    else:
        provenance = IsolationProvenance.MISSING
        physical_domain = ()

    return DeviceInventory(
        bdf=bdf,
        vendor_id=_read_hex(device_path / "vendor"),
        device_id=_read_hex(device_path / "device"),
        class_code=_read_hex(device_path / "class"),
        header_type=header_type,
        function_role=role,
        bars=parse_resource_lines(
            _read_text(device_path / "resource"),
            bdf=bdf,
            header_type=header_type,
            config=config,
        ),
        iommu_group=group,
        physical_isolation_domain=physical_domain,
        reset_methods=_reset_methods(device_path),
        isolation_provenance=provenance,
        platform_reserved=role == FunctionRole.FABRIC,
        driver=_driver_name(device_path),
        parent=_parent_bdf(device_path, bdf),
        acs=parse_acs_state(config),
        metadata={
            "configBytesReadable": len(config),
            "sysfsPath": str(device_path),
        },
    )


def _slot_key(bdf: str) -> str:
    return bdf.rsplit(".", 1)[0]


def _add_domains(devices: dict[str, DeviceInventory]) -> dict[str, DeviceInventory]:
    slots: dict[str, list[str]] = {}
    children: dict[str | None, list[str]] = {}
    for bdf, device in devices.items():
        slots.setdefault(_slot_key(bdf), []).append(bdf)
        children.setdefault(device.parent, []).append(bdf)

    result: dict[str, DeviceInventory] = {}
    function_methods = {"device_specific", "acpi", "flr", "af_flr", "pm"}
    bus_methods = {"bus", "cxl_bus", "bridge", "slot", "hot"}
    for bdf, device in devices.items():
        aliases = tuple(sorted(slots.get(_slot_key(bdf), ())))
        methods = set(device.reset_methods)
        dependencies: tuple[str, ...] = ()
        if methods & function_methods:
            reset_domain = (bdf,)
            source = "sysfs-function-reset"
        elif methods & bus_methods and device.parent:
            reset_domain = tuple(sorted(children.get(device.parent, ())))
            dependencies = (device.parent,)
            source = "sysfs-parent-topology-estimate"
        else:
            reset_domain = ()
            source = "unknown"
        result[bdf] = replace(
            device,
            multifunction_aliases=aliases,
            reset_domain=reset_domain,
            reset_domain_source=source,
            platform_dependencies=dependencies,
        )
    return result


def _bool_file(path: Path) -> bool:
    return _read_text(path).lower() in {"1", "y", "yes", "true"}


def scan_linux_sysfs(
    *,
    sysfs_root: Path = Path("/sys/bus/pci/devices"),
    proc_cmdline: Path = Path("/proc/cmdline"),
    interrupt_remapping: bool | None = None,
    selected_bdfs: Iterable[str] | None = None,
) -> HostInventory:
    """Build a read-only Linux PCI inventory from kernel-probed sysfs data."""

    cmdline = _read_text(proc_cmdline)
    acs_override_active = "pcie_acs_override=" in cmdline
    requested = (
        None if selected_bdfs is None else {bdf.lower() for bdf in selected_bdfs}
    )
    paths = [
        path for path in sorted(sysfs_root.iterdir()) if BDF_PATTERN.match(path.name)
    ]
    # Scan all devices first so reset and multifunction domains are complete.
    all_devices = {
        path.name.lower(): _scan_device(path, acs_override_active=acs_override_active)
        for path in paths
    }
    all_devices = _add_domains(all_devices)
    devices = (
        all_devices
        if requested is None
        else {bdf: device for bdf, device in all_devices.items() if bdf in requested}
    )
    iommu_present = any(device.iommu_group for device in all_devices.values())
    no_iommu_mode = _bool_file(
        Path("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
    )
    return HostInventory(
        iommu_present=iommu_present,
        interrupt_remapping=interrupt_remapping,
        no_iommu_mode=no_iommu_mode,
        acs_override_active=acs_override_active,
        devices=devices,
        source="linux-sysfs-read-only",
        metadata={
            "kernelRelease": platform.release(),
            "kernelCommandLine": cmdline,
            "sysfsRoot": str(sysfs_root),
            "uid": os.geteuid() if hasattr(os, "geteuid") else None,
            "scannedDeviceCount": len(all_devices),
            "returnedDeviceCount": len(devices),
            "physicalDomainRule": (
                "unknown-when-acs-override-active"
                if acs_override_active
                else "stock-kernel-iommu-group"
            ),
        },
    )
