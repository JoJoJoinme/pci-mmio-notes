from __future__ import annotations

import hashlib
import json
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
    DmaIsolationMode,
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
PCI_STATUS = 0x06
PCI_STATUS_CAP_LIST = 0x10
PCI_CAPABILITY_LIST = 0x34
PCI_CAP_ID_EXP = 0x10
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


def _read_optional_bool(path: Path) -> bool | None:
    text = _read_text(path).lower()
    if text in {"1", "y", "yes", "true"}:
        return True
    if text in {"0", "n", "no", "false"}:
        return False
    return None


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


def parse_pcie_type(config: bytes) -> int | None:
    """Return the PCIe Device/Port Type from the standard capability list."""

    if len(config) <= PCI_CAPABILITY_LIST or not (
        _le16(config, PCI_STATUS) & PCI_STATUS_CAP_LIST
    ):
        return None
    offset = config[PCI_CAPABILITY_LIST] & ~0x3
    visited: set[int] = set()
    while offset and offset not in visited and offset + 2 <= len(config):
        if offset < 0x40:
            return None
        visited.add(offset)
        capability_id = config[offset]
        if capability_id == PCI_CAP_ID_EXP and offset + 4 <= len(config):
            return (_le16(config, offset + 2) >> 4) & 0xF
        offset = config[offset + 1] & ~0x3
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


def _iommu_group_id(device_path: Path) -> str | None:
    link = device_path / "iommu_group"
    if not link.exists():
        return None
    try:
        return link.resolve(strict=True).name
    except (FileNotFoundError, OSError):
        return None


def _dma_isolation(
    device_path: Path,
    group: tuple[str, ...],
    *,
    vfio_root: Path = Path("/dev/vfio"),
    unsafe_noiommu_mode_enabled: bool = False,
) -> tuple[DmaIsolationMode, str]:
    """Distinguish a hardware-IOMMU group from VFIO's synthetic noiommu group."""

    group_id = _iommu_group_id(device_path)
    if not group or group_id is None:
        return DmaIsolationMode.UNKNOWN, "missing-iommu-group"
    if (vfio_root / f"noiommu-{group_id}").exists():
        return DmaIsolationMode.NO_IOMMU, "vfio-noiommu-devnode"
    if unsafe_noiommu_mode_enabled and _driver_name(device_path) == "vfio-pci":
        has_group_node = (vfio_root / group_id).exists()
        vfio_cdev_dir = device_path / "vfio-dev"
        try:
            has_cdev = vfio_cdev_dir.is_dir() and any(vfio_cdev_dir.iterdir())
        except OSError:
            has_cdev = False
        if not has_group_node and not has_cdev:
            return DmaIsolationMode.UNKNOWN, "ambiguous-vfio-group"
    return DmaIsolationMode.IOMMU, "linux-iommu-group"


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
    unsafe_noiommu_mode_enabled: bool,
    vfio_root: Path,
) -> DeviceInventory:
    bdf = device_path.name.lower()
    config = _read_config(device_path / "config")
    header_type = (
        config[PCI_HEADER_TYPE] & 0x7F if len(config) > PCI_HEADER_TYPE else 0x7F
    )
    role = _function_role(device_path, header_type)
    group = _iommu_group(device_path)
    dma_isolation_mode, dma_isolation_source = _dma_isolation(
        device_path,
        group,
        vfio_root=vfio_root,
        unsafe_noiommu_mode_enabled=unsafe_noiommu_mode_enabled,
    )
    native_isolation = _read_optional_bool(device_path / "acs_native_isolation")
    effective_isolation = _read_optional_bool(device_path / "acs_effective_isolation")
    override_source = _read_text(device_path / "acs_override_source", "unknown")
    if group and acs_override_active:
        provenance = IsolationProvenance.ACS_OVERRIDE
        physical_domain: tuple[str, ...] = ()
        physical_domain_source = "unknown"
    elif group:
        provenance = IsolationProvenance.KERNEL_GROUP
        physical_domain = group
        physical_domain_source = "stock-kernel-iommu-group"
    else:
        provenance = IsolationProvenance.MISSING
        physical_domain = ()
        physical_domain_source = "unknown"

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
        physical_isolation_domain_source=physical_domain_source,
        reset_methods=_reset_methods(device_path),
        isolation_provenance=provenance,
        dma_isolation_mode=dma_isolation_mode,
        dma_isolation_source=dma_isolation_source,
        platform_reserved=role == FunctionRole.FABRIC,
        driver=_driver_name(device_path),
        parent=_parent_bdf(device_path, bdf),
        acs=parse_acs_state(config),
        acs_native_isolation=native_isolation,
        acs_effective_isolation=effective_isolation,
        acs_override_source=override_source,
        metadata={
            "configBytesReadable": len(config),
            "pcieType": parse_pcie_type(config),
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
            multifunction_source="linux-slot-scan",
            reset_domain=reset_domain,
            reset_domain_source=source,
            platform_dependencies=dependencies,
            platform_dependency_source=(
                "vfio-reset-parent" if dependencies else "unknown"
            ),
        )
    return result


def add_conservative_assignment_groups(
    devices: dict[str, DeviceInventory],
) -> dict[str, DeviceInventory]:
    """Join every known ownership/lease dependency into a safe default group."""

    roots = {bdf: bdf for bdf in devices}

    def find(bdf: str) -> str:
        while roots[bdf] != bdf:
            roots[bdf] = roots[roots[bdf]]
            bdf = roots[bdf]
        return bdf

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            roots[right_root] = left_root

    for bdf, device in devices.items():
        closures = (
            device.iommu_group,
            device.physical_isolation_domain,
            device.reset_domain,
            device.multifunction_aliases,
            device.platform_dependencies,
        )
        for closure in closures:
            for member in closure:
                if member in devices:
                    union(bdf, member)

    components: dict[str, list[str]] = {}
    for bdf in devices:
        components.setdefault(find(bdf), []).append(bdf)

    result: dict[str, DeviceInventory] = {}
    for members in components.values():
        ordered = tuple(sorted(members))
        group_id = "conservative:" + ",".join(ordered)
        for bdf in ordered:
            device = devices[bdf]
            result[bdf] = replace(
                device,
                owner_activation_group=group_id,
                exclusive_attach_group=group_id,
                metadata={
                    **device.metadata,
                    "assignmentGroupSource": (
                        "iommu+physical+reset+multifunction+platform-closure"
                    ),
                },
            )
    return result


def _ancestor_chain(devices: dict[str, DeviceInventory], bdf: str) -> tuple[str, ...]:
    chain: list[str] = []
    seen: set[str] = set()
    current: str | None = bdf
    while current and current in devices and current not in seen:
        seen.add(current)
        chain.append(current)
        current = devices[current].parent
    return tuple(chain)


def _anchor_key(
    devices: dict[str, DeviceInventory],
    bdf: str,
    chain: tuple[str, ...],
) -> str:
    nonisolating = [
        member for member in chain if devices[member].acs_native_isolation is False
    ]
    if not nonisolating:
        return f"native:{bdf}"

    anchor_bdf = nonisolating[-1]
    anchor = devices[anchor_bdf]
    if anchor.function_role != FunctionRole.FABRIC:
        if len(anchor.multifunction_aliases) > 1:
            return f"slot:{_slot_key(anchor_bdf)}"
        if anchor.metadata.get("pcieType") is None and anchor.parent is None:
            return f"legacy-bus:{anchor_bdf.rsplit(':', 1)[0]}"
    return f"node:{anchor_bdf}"


def reconstruct_physical_isolation_domains(
    devices: dict[str, DeviceInventory],
    *,
    acs_override_active: bool,
) -> dict[str, DeviceInventory]:
    """Rebuild a conservative pre-override isolation domain from kernel facts.

    The patched IOMMU group remains the operational VFIO group.  This shadow
    domain joins every function below the highest non-isolating native ACS
    node, then closes over operational groups and multifunction aliases.
    Missing or internally inconsistent kernel provenance leaves the domain
    unknown instead of guessing from raw capability bits.
    """

    if not acs_override_active:
        return devices

    roots = {bdf: bdf for bdf in devices}

    def find(bdf: str) -> str:
        while roots[bdf] != bdf:
            roots[bdf] = roots[roots[bdf]]
            bdf = roots[bdf]
        return bdf

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            roots[right_root] = left_root

    chains = {bdf: _ancestor_chain(devices, bdf) for bdf in devices}
    complete: dict[str, bool] = {}
    override_paths: dict[str, tuple[str, ...]] = {}
    anchors: dict[str, list[str]] = {}
    accepted_sources = {"none", "id", "downstream", "multifunction"}

    for bdf, chain in chains.items():
        valid = bool(chain)
        path: list[str] = []
        for member in chain:
            device = devices[member]
            source = device.acs_override_source
            if (
                device.acs_native_isolation is None
                or device.acs_effective_isolation is None
                or source not in accepted_sources
            ):
                valid = False
                continue
            if source != "none":
                if device.acs_native_isolation or not device.acs_effective_isolation:
                    valid = False
                else:
                    path.append(member)
            elif device.acs_effective_isolation != device.acs_native_isolation:
                valid = False
        complete[bdf] = valid
        override_paths[bdf] = tuple(path)
        if valid:
            anchors.setdefault(_anchor_key(devices, bdf, chain), []).append(bdf)

    if not all(complete.values()):
        return {
            bdf: replace(
                device,
                physical_isolation_domain=(),
                physical_isolation_domain_source="unknown",
                isolation_provenance=IsolationProvenance.ACS_OVERRIDE,
                metadata={
                    **device.metadata,
                    "acsOverridePath": list(override_paths.get(bdf, ())),
                },
            )
            for bdf, device in devices.items()
        }

    for members in anchors.values():
        for member in members[1:]:
            union(members[0], member)
    for bdf, device in devices.items():
        for peer in device.iommu_group + device.multifunction_aliases:
            if peer in devices:
                union(bdf, peer)

    components: dict[str, set[str]] = {}
    for bdf in devices:
        components.setdefault(find(bdf), set()).add(bdf)

    result: dict[str, DeviceInventory] = {}
    for bdf, device in devices.items():
        component = components[find(bdf)]
        component_complete = all(complete.get(member, False) for member in component)
        component_override_path = tuple(
            sorted(
                {
                    path_member
                    for member in component
                    for path_member in override_paths.get(member, ())
                }
            )
        )
        metadata = dict(device.metadata)
        metadata["acsOverridePath"] = list(override_paths.get(bdf, ()))
        if component_complete:
            domain = tuple(sorted(component))
            if component_override_path:
                source = "kernel-acs-provenance-topology-conservative"
                provenance = IsolationProvenance.ACS_OVERRIDE
            else:
                source = "kernel-no-override-iommu-group"
                provenance = IsolationProvenance.KERNEL_GROUP
        else:
            domain = ()
            source = "unknown"
            provenance = IsolationProvenance.ACS_OVERRIDE
        result[bdf] = replace(
            device,
            physical_isolation_domain=domain,
            physical_isolation_domain_source=source,
            isolation_provenance=provenance,
            metadata=metadata,
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
    vfio_root: Path = Path("/dev/vfio"),
    machine_id_path: Path = Path("/etc/machine-id"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    inventory_epoch: int | None = None,
) -> HostInventory:
    """Build a read-only Linux PCI inventory from kernel-probed sysfs data."""

    cmdline = _read_text(proc_cmdline)
    acs_override_active = "pcie_acs_override=" in cmdline
    no_iommu_mode = _bool_file(
        Path("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
    )
    requested = (
        None if selected_bdfs is None else {bdf.lower() for bdf in selected_bdfs}
    )
    paths = [
        path for path in sorted(sysfs_root.iterdir()) if BDF_PATTERN.match(path.name)
    ]
    # Scan all devices first so reset and multifunction domains are complete.
    all_devices = {
        path.name.lower(): _scan_device(
            path,
            acs_override_active=acs_override_active,
            unsafe_noiommu_mode_enabled=no_iommu_mode,
            vfio_root=vfio_root,
        )
        for path in paths
    }
    all_devices = _add_domains(all_devices)
    all_devices = reconstruct_physical_isolation_domains(
        all_devices,
        acs_override_active=acs_override_active,
    )
    all_devices = add_conservative_assignment_groups(all_devices)
    devices = (
        all_devices
        if requested is None
        else {bdf: device for bdf, device in all_devices.items() if bdf in requested}
    )
    iommu_present = any(
        device.dma_isolation_mode == DmaIsolationMode.IOMMU
        for device in all_devices.values()
    )
    acs_provenance_interface_complete = all(
        device.acs_native_isolation is not None
        and device.acs_effective_isolation is not None
        and device.acs_override_source != "unknown"
        for device in all_devices.values()
    )
    if acs_override_active:
        physical_domain_rule = (
            "kernel-acs-provenance-topology-conservative"
            if acs_provenance_interface_complete
            else "unknown-missing-kernel-acs-provenance"
        )
    else:
        physical_domain_rule = "stock-kernel-iommu-group"
    topology_preimage = [
        {
            "bdf": bdf,
            "parent": device.parent,
            "iommuGroup": list(device.iommu_group),
            "physicalIsolationDomain": list(device.physical_isolation_domain),
            "multifunctionAliases": list(device.multifunction_aliases),
            "platformDependencies": list(device.platform_dependencies),
            "resetDomain": list(device.reset_domain),
        }
        for bdf, device in sorted(all_devices.items())
    ]
    topology_hash = hashlib.sha256(
        json.dumps(
            topology_preimage,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return HostInventory(
        iommu_present=iommu_present,
        interrupt_remapping=interrupt_remapping,
        no_iommu_mode=no_iommu_mode,
        acs_override_active=acs_override_active,
        devices=devices,
        source="linux-sysfs-read-only",
        host_id=_read_text(machine_id_path, "unknown"),
        kernel_boot_id=_read_text(boot_id_path, "unknown"),
        inventory_epoch=inventory_epoch,
        topology_hash=topology_hash,
        metadata={
            "kernelRelease": platform.release(),
            "kernelCommandLine": cmdline,
            "sysfsRoot": str(sysfs_root),
            "uid": os.geteuid() if hasattr(os, "geteuid") else None,
            "scannedDeviceCount": len(all_devices),
            "returnedDeviceCount": len(devices),
            "acsProvenanceInterfaceComplete": acs_provenance_interface_complete,
            "physicalDomainRule": physical_domain_rule,
        },
    )
