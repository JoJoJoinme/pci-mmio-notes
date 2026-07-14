from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Protocol, runtime_checkable

from .model import Bar, BarSpace


PCI_COMMAND = 0x04
PCI_COMMAND_IO = 0x0001
PCI_COMMAND_MEMORY = 0x0002
PCI_COMMAND_MASTER = 0x0004
PCI_HEADER_TYPE = 0x0E
PCI_HEADER_TYPE_MASK = 0x7F
PCI_HEADER_TYPE_NORMAL = 0x00
PCI_HEADER_TYPE_BRIDGE = 0x01
PCI_BASE_ADDRESS_0 = 0x10
PCI_BASE_ADDRESS_SPACE_IO = 0x01
PCI_BASE_ADDRESS_IO_MASK = 0xFFFFFFFC
PCI_BASE_ADDRESS_MEM_MASK = 0xFFFFFFF0
PCI_BASE_ADDRESS_MEM_TYPE_MASK = 0x06
PCI_BASE_ADDRESS_MEM_TYPE_32 = 0x00
PCI_BASE_ADDRESS_MEM_TYPE_1M = 0x02
PCI_BASE_ADDRESS_MEM_TYPE_64 = 0x04
PCI_BASE_ADDRESS_MEM_TYPE_RESERVED = 0x06
PCI_BASE_ADDRESS_MEM_PREFETCH = 0x08
BDF_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


@runtime_checkable
class ConfigSpace(Protocol):
    """Minimal config-space interface required by the sizing transaction."""

    def read(self, offset: int, width: int) -> int: ...

    def write(self, offset: int, width: int, value: int) -> None: ...


class ProbeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LinuxSysfsConfigSpace:
    """Exact-offset backend for a Linux PCI config sysfs file."""

    def __init__(self, config_path: Path, *, writable: bool = False) -> None:
        self.config_path = config_path
        self.writable = writable
        self._fd: int | None = None
        self._offset_lock = Lock()

    def __enter__(self) -> LinuxSysfsConfigSpace:
        flags = os.O_RDWR if self.writable else os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        self._fd = os.open(self.config_path, flags)
        return self

    def __exit__(self, *_error: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _require_open(self) -> int:
        if self._fd is None:
            raise RuntimeError("config-space backend is not open")
        return self._fd

    def read(self, offset: int, width: int) -> int:
        fd = self._require_open()
        pread = getattr(os, "pread", None)
        if pread is not None:
            data = pread(fd, width, offset)
        else:
            with self._offset_lock:
                os.lseek(fd, offset, os.SEEK_SET)
                data = os.read(fd, width)
        if len(data) != width:
            raise OSError(
                f"short PCI config read at {offset:#x}: {len(data)} of {width} bytes"
            )
        return int.from_bytes(data, "little")

    def write(self, offset: int, width: int, value: int) -> None:
        if not self.writable:
            raise PermissionError("config-space backend was opened read-only")
        data = value.to_bytes(width, "little")
        fd = self._require_open()
        pwrite = getattr(os, "pwrite", None)
        if pwrite is not None:
            written = pwrite(fd, data, offset)
        else:
            with self._offset_lock:
                os.lseek(fd, offset, os.SEEK_SET)
                written = os.write(fd, data)
        if written != width:
            raise OSError(
                f"short PCI config write at {offset:#x}: {written} of {width} bytes"
            )


@dataclass(frozen=True)
class BarProbeResult:
    bdf: str
    header_type: int
    slot_count: int
    command_before: int
    bars: tuple[Bar, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "bdf": self.bdf,
            "headerType": self.header_type,
            "slotCount": self.slot_count,
            "commandBefore": self.command_before,
            "bars": [bar.to_dict() for bar in self.bars],
        }


def _pci_size(base: int, probe_mask: int, address_mask: int) -> int:
    """Mirror Linux pci_size(): return the lowest significant decode bit."""

    significant = address_mask & probe_mask
    if not significant:
        return 0
    size = significant & -significant
    if base == probe_mask and ((base | (size - 1)) & address_mask) != address_mask:
        return 0
    return size


def _all_ones(value: int, width: int) -> bool:
    return value == (1 << (width * 8)) - 1


def _read(accessor: ConfigSpace, offset: int, width: int) -> int:
    value = accessor.read(offset, width)
    maximum = (1 << (width * 8)) - 1
    if not 0 <= value <= maximum:
        raise ProbeError(
            "CONFIG_READ_WIDTH_VIOLATION",
            f"config read at {offset:#x} returned {value:#x} for width {width}",
        )
    return value


def probe_standard_bars(
    accessor: ConfigSpace,
    bdf: str,
    *,
    include_io: bool = False,
) -> BarProbeResult:
    """Size standard Type-0/Type-1 BARs with a reversible write-all-ones probe.

    The caller must already own and quiesce the function.  This routine disables
    I/O decode, memory decode, and bus mastering for the transaction, restores
    every BAR dword, then restores PCI_COMMAND even when probing fails.

    The function intentionally accepts an abstract backend.  Production code
    can bind it to a hypervisor's config accessor; tests can use an emulator.
    The Linux inventory path in this repository does not call this function on
    live hardware and instead consumes the kernel-probed sysfs resource table.
    """

    header_type = _read(accessor, PCI_HEADER_TYPE, 1) & PCI_HEADER_TYPE_MASK
    if header_type == PCI_HEADER_TYPE_NORMAL:
        slot_count = 6
    elif header_type == PCI_HEADER_TYPE_BRIDGE:
        slot_count = 2
    else:
        raise ProbeError(
            "UNSUPPORTED_HEADER_TYPE",
            f"{bdf}: standard BAR probing does not support header type {header_type:#x}",
        )

    offsets = [PCI_BASE_ADDRESS_0 + index * 4 for index in range(slot_count)]
    original = [_read(accessor, offset, 4) for offset in offsets]
    command_before = _read(accessor, PCI_COMMAND, 2)
    command_quiesced = command_before & ~(
        PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER
    )
    restore_errors: list[str] = []
    bars: list[Bar] = []

    try:
        accessor.write(PCI_COMMAND, 2, command_quiesced)
        index = 0
        while index < slot_count:
            offset = offsets[index]
            raw_low = original[index]

            # A failed config read has no reliable type information.
            if _all_ones(raw_low, 4):
                index += 1
                continue

            is_io = bool(raw_low & PCI_BASE_ADDRESS_SPACE_IO)
            if is_io:
                accessor.write(offset, 4, 0xFFFFFFFF)
                probe_low = _read(accessor, offset, 4)
                accessor.write(offset, 4, raw_low)
                if _all_ones(probe_low, 4):
                    index += 1
                    continue
                base = raw_low & PCI_BASE_ADDRESS_IO_MASK
                mask = probe_low & PCI_BASE_ADDRESS_IO_MASK
                size = _pci_size(base, mask, PCI_BASE_ADDRESS_IO_MASK)
                if size and include_io:
                    bars.append(
                        Bar(
                            bdf=bdf,
                            index=index,
                            size=size,
                            space=BarSpace.IO,
                            address=base,
                            source="config-write-all-ones",
                        )
                    )
                index += 1
                continue

            memory_type = raw_low & PCI_BASE_ADDRESS_MEM_TYPE_MASK
            if memory_type == PCI_BASE_ADDRESS_MEM_TYPE_RESERVED:
                raise ProbeError(
                    "UNSUPPORTED_MEMORY_BAR_TYPE",
                    f"{bdf}: BAR{index} uses reserved memory type encoding 0x6",
                )
            is_64 = memory_type == PCI_BASE_ADDRESS_MEM_TYPE_64
            below_1m = memory_type == PCI_BASE_ADDRESS_MEM_TYPE_1M
            if is_64 and index + 1 >= slot_count:
                raise ProbeError(
                    "TRUNCATED_64BIT_BAR",
                    f"{bdf}: BAR{index} advertises 64-bit width without an upper slot",
                )

            if is_64:
                high_offset = offsets[index + 1]
                raw_high = original[index + 1]
                accessor.write(offset, 4, 0xFFFFFFFF)
                accessor.write(high_offset, 4, 0xFFFFFFFF)
                probe_low = _read(accessor, offset, 4)
                probe_high = _read(accessor, high_offset, 4)
                accessor.write(high_offset, 4, raw_high)
                accessor.write(offset, 4, raw_low)

                if _all_ones(probe_low, 4) and _all_ones(probe_high, 4):
                    index += 2
                    continue
                base = (raw_high << 32) | (raw_low & PCI_BASE_ADDRESS_MEM_MASK)
                mask = (probe_high << 32) | (probe_low & PCI_BASE_ADDRESS_MEM_MASK)
                address_mask = 0xFFFFFFFFFFFFFFFF & ~0xF
                size = _pci_size(base, mask, address_mask)
                consumed = 2
            else:
                accessor.write(offset, 4, 0xFFFFFFFF)
                probe_low = _read(accessor, offset, 4)
                accessor.write(offset, 4, raw_low)
                if _all_ones(probe_low, 4):
                    index += 1
                    continue
                base = raw_low & PCI_BASE_ADDRESS_MEM_MASK
                mask = probe_low & PCI_BASE_ADDRESS_MEM_MASK
                size = _pci_size(base, mask, PCI_BASE_ADDRESS_MEM_MASK)
                consumed = 1

            if size:
                bar = Bar(
                    bdf=bdf,
                    index=index,
                    size=size,
                    space=BarSpace.MEMORY,
                    address=base,
                    is_64=is_64,
                    prefetchable=bool(raw_low & PCI_BASE_ADDRESS_MEM_PREFETCH),
                    below_1m=below_1m,
                    source="config-write-all-ones",
                )
                errors = bar.validation_errors()
                if errors:
                    raise ProbeError(
                        "INVALID_BAR_SHAPE",
                        f"{bar.key}: {', '.join(errors)}",
                    )
                bars.append(bar)
            index += consumed
    finally:
        # Restore all slots, not only the last one touched.  Continue restoration
        # after an individual write failure so PCI_COMMAND still gets restored.
        for offset, value in zip(reversed(offsets), reversed(original)):
            try:
                accessor.write(offset, 4, value)
            except BaseException as error:
                restore_errors.append(f"BAR@{offset:#x}: {error}")
        try:
            accessor.write(PCI_COMMAND, 2, command_before)
        except BaseException as error:
            restore_errors.append(f"COMMAND: {error}")
        if restore_errors:
            raise ProbeError(
                "CONFIG_RESTORE_FAILED",
                f"{bdf}: " + "; ".join(restore_errors),
            )

    return BarProbeResult(
        bdf=bdf.lower(),
        header_type=header_type,
        slot_count=slot_count,
        command_before=command_before,
        bars=tuple(bars),
    )


def probe_unbound_linux_device(
    bdf: str,
    *,
    sysfs_root: Path = Path("/sys/bus/pci/devices"),
    acknowledge_live_writes: bool = False,
    include_io: bool = False,
) -> BarProbeResult:
    """Run the sizing transaction on an explicitly acknowledged unbound device.

    This helper is intentionally absent from the CLI.  A production host
    service must additionally serialize ownership against driver binding and
    VM assignment.  The checks here prevent casual use on a bound function but
    cannot replace that external lease/lock.
    """

    if not acknowledge_live_writes:
        raise ProbeError(
            "LIVE_WRITE_NOT_ACKNOWLEDGED",
            "live BAR sizing requires acknowledge_live_writes=True",
        )
    if not BDF_PATTERN.match(bdf):
        raise ProbeError("INVALID_BDF", f"invalid PCI BDF: {bdf!r}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ProbeError("ROOT_REQUIRED", "live sysfs config writes require root")

    device_path = sysfs_root / bdf.lower()
    config_path = device_path / "config"
    driver_path = device_path / "driver"
    if not config_path.is_file():
        raise ProbeError("DEVICE_NOT_FOUND", f"missing {config_path}")
    if driver_path.exists() or driver_path.is_symlink():
        raise ProbeError(
            "DEVICE_STILL_BOUND",
            f"{bdf} must be unbound before live BAR sizing",
        )

    with LinuxSysfsConfigSpace(config_path, writable=True) as accessor:
        # Recheck after open to narrow the bind/probe race.  The caller still
        # needs an external device lease for complete serialization.
        if driver_path.exists() or driver_path.is_symlink():
            raise ProbeError(
                "DEVICE_BIND_RACE",
                f"{bdf} became bound while opening config space",
            )
        return probe_standard_bars(
            accessor,
            bdf,
            include_io=include_io,
        )
