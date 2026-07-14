from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .model import AddressRange, Bar, BarSpace, is_power_of_two


MIB = 1 << 20
GIB = 1 << 30
FOUR_GIB = 1 << 32


def align_up(value: int, alignment: int) -> int:
    if not is_power_of_two(alignment):
        raise ValueError(f"alignment must be a power of two: {alignment:#x}")
    return (value + alignment - 1) & -alignment


def align_down(value: int, alignment: int) -> int:
    if not is_power_of_two(alignment):
        raise ValueError(f"alignment must be a power of two: {alignment:#x}")
    return value & -alignment


def next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


def _normalize(ranges: Iterable[AddressRange]) -> list[AddressRange]:
    ordered = sorted(ranges)
    merged: list[AddressRange] = []
    for current in ordered:
        if not merged or current.start > merged[-1].end:
            merged.append(current)
            continue
        previous = merged[-1]
        merged[-1] = AddressRange(previous.start, max(previous.end, current.end))
    return merged


class AddressPool:
    def __init__(
        self,
        windows: Iterable[AddressRange],
        reserved: Iterable[AddressRange] = (),
    ) -> None:
        self.free = _normalize(windows)
        for blocked in _normalize(reserved):
            self.reserve(blocked)
        self.initial_free = tuple(self.free)

    def reserve(self, blocked: AddressRange) -> None:
        replacement: list[AddressRange] = []
        for interval in self.free:
            if not interval.overlaps(blocked):
                replacement.append(interval)
                continue
            if interval.start < blocked.start:
                replacement.append(
                    AddressRange(interval.start, min(interval.end, blocked.start))
                )
            if blocked.end < interval.end:
                replacement.append(
                    AddressRange(max(interval.start, blocked.end), interval.end)
                )
        self.free = replacement

    def allocate(
        self,
        size: int,
        alignment: int,
        *,
        top_down: bool = False,
        maximum_end: int | None = None,
    ) -> int | None:
        candidates = (
            range(len(self.free) - 1, -1, -1) if top_down else range(len(self.free))
        )
        for index in candidates:
            interval = self.free[index]
            effective_end = (
                interval.end if maximum_end is None else min(interval.end, maximum_end)
            )
            if effective_end <= interval.start:
                continue
            if top_down:
                address = align_down(effective_end - size, alignment)
            else:
                address = align_up(interval.start, alignment)
            if address < interval.start or address + size > effective_end:
                continue
            self._consume(index, AddressRange(address, address + size))
            return address
        return None

    def _consume(self, index: int, used: AddressRange) -> None:
        interval = self.free[index]
        replacement: list[AddressRange] = []
        if interval.start < used.start:
            replacement.append(AddressRange(interval.start, used.start))
        if used.end < interval.end:
            replacement.append(AddressRange(used.end, interval.end))
        self.free[index : index + 1] = replacement

    @property
    def available_bytes(self) -> int:
        return sum(interval.size for interval in self.free)

    def largest_aligned_fit(self, alignment: int) -> int:
        largest = 0
        for interval in self.free:
            start = align_up(interval.start, alignment)
            if start < interval.end:
                largest = max(largest, interval.end - start)
        return largest


@dataclass(frozen=True)
class AllocationPolicy:
    prefer_64bit_high: bool = False
    force_64bit_high: bool = False
    top_down_high: bool = False
    high_aperture_granularity: int = MIB
    power_of_two_high_aperture: bool = True

    def __post_init__(self) -> None:
        if not is_power_of_two(self.high_aperture_granularity):
            raise ValueError("high_aperture_granularity must be a power of two")


@dataclass(frozen=True)
class BarAllocation:
    bar: Bar
    address: int
    pool: str

    @property
    def end(self) -> int:
        return self.address + self.bar.size

    def to_dict(self) -> dict[str, Any]:
        return {
            "bar": self.bar.key,
            "address": self.address,
            "end": self.end,
            "size": self.bar.size,
            "pool": self.pool,
            "is64": self.bar.is_64,
            "prefetchable": self.bar.prefetchable,
        }


@dataclass(frozen=True)
class AllocationIssue:
    code: str
    message: str
    bar: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "bar": self.bar,
            "details": self.details,
        }


@dataclass(frozen=True)
class AllocationResult:
    success: bool
    allocations: tuple[BarAllocation, ...]
    issues: tuple[AllocationIssue, ...]
    low_free: tuple[AddressRange, ...]
    high_free: tuple[AddressRange, ...]
    high_aperture_bytes: int
    high_aperture_alignment: int

    def qemu_arguments(
        self,
        *,
        firmware: str = "ovmf",
        host_bridge: str = "q35-pcihost",
    ) -> list[str]:
        if not self.success:
            return []
        size = self.high_aperture_bytes
        arguments: list[str] = []
        if firmware.lower() == "ovmf":
            size_mb = (size + MIB - 1) // MIB
            arguments.extend(
                [
                    "-fw_cfg",
                    f"name=opt/ovmf/X-PciMmio64Mb,string={size_mb}",
                ]
            )
        elif firmware.lower() != "seabios":
            raise ValueError(f"unsupported firmware: {firmware!r}")
        arguments.extend(
            [
                "-global",
                f"{host_bridge}.pci-hole64-size={format_qemu_size(size)}",
            ]
        )
        return arguments

    def to_dict(
        self,
        *,
        firmware: str = "ovmf",
        host_bridge: str = "q35-pcihost",
    ) -> dict[str, Any]:
        return {
            "success": self.success,
            "allocations": [item.to_dict() for item in self.allocations],
            "issues": [issue.to_dict() for issue in self.issues],
            "lowFree": [interval.to_dict() for interval in self.low_free],
            "highFree": [interval.to_dict() for interval in self.high_free],
            "highApertureBytes": self.high_aperture_bytes,
            "highApertureAlignment": self.high_aperture_alignment,
            "qemuArguments": self.qemu_arguments(
                firmware=firmware, host_bridge=host_bridge
            ),
        }


def format_qemu_size(size: int) -> str:
    if size == 0:
        return "0"
    if size % GIB == 0:
        return f"{size // GIB}G"
    if size % MIB == 0:
        return f"{size // MIB}M"
    return str(size)


def _bar_order(bar: Bar) -> tuple[int, str]:
    return (-bar.alignment, bar.key)


def _failure(
    issue: AllocationIssue,
    low_pool: AddressPool,
    high_pool: AddressPool,
) -> AllocationResult:
    return AllocationResult(
        success=False,
        allocations=(),
        issues=(issue,),
        low_free=low_pool.initial_free,
        high_free=high_pool.initial_free,
        high_aperture_bytes=0,
        high_aperture_alignment=0,
    )


def plan_mmio(
    bars: Sequence[Bar],
    *,
    low_windows: Sequence[AddressRange],
    high_windows: Sequence[AddressRange] = (),
    reserved: Sequence[AddressRange] = (),
    policy: AllocationPolicy | None = None,
) -> AllocationResult:
    """Transactionally place memory BARs into below/above-4G apertures.

    BAR addresses from the host inventory are deliberately ignored; only the
    probed size and width constrain guest placement.  On failure the returned
    allocation set is empty, so callers never observe a partially committed VM
    layout.
    """

    policy = policy or AllocationPolicy()
    low_pool = AddressPool(low_windows, reserved)
    high_pool = AddressPool(high_windows, reserved)
    invalid_low = [window for window in low_windows if window.end > FOUR_GIB]
    if invalid_low:
        return _failure(
            AllocationIssue(
                "INVALID_MMIO32_WINDOW",
                "below-4G windows must end at or before 0x100000000",
                details={"windows": [window.to_dict() for window in invalid_low]},
            ),
            low_pool,
            high_pool,
        )
    invalid_high = [window for window in high_windows if window.start < FOUR_GIB]
    if invalid_high:
        return _failure(
            AllocationIssue(
                "INVALID_MMIO64_WINDOW",
                "above-4G windows must start at or after 0x100000000",
                details={"windows": [window.to_dict() for window in invalid_high]},
            ),
            low_pool,
            high_pool,
        )
    memory_bars = [bar for bar in bars if bar.space == BarSpace.MEMORY]
    seen: set[str] = set()

    for bar in memory_bars:
        if bar.key in seen:
            return _failure(
                AllocationIssue(
                    "DUPLICATE_BAR",
                    f"duplicate request for {bar.key}",
                    bar.key,
                ),
                low_pool,
                high_pool,
            )
        seen.add(bar.key)
        errors = bar.validation_errors()
        if errors:
            return _failure(
                AllocationIssue(
                    "INVALID_BAR",
                    f"{bar.key} failed validation: {', '.join(errors)}",
                    bar.key,
                    {"validationErrors": list(errors)},
                ),
                low_pool,
                high_pool,
            )

    fixed_low = sorted(
        (bar for bar in memory_bars if not bar.is_64 or bar.below_1m),
        key=_bar_order,
    )
    flexible = sorted(
        (bar for bar in memory_bars if bar.is_64 and not bar.below_1m),
        key=_bar_order,
    )
    placed: list[BarAllocation] = []

    for bar in fixed_low:
        maximum_end = 1 << 20 if bar.below_1m else FOUR_GIB
        address = low_pool.allocate(
            bar.size,
            bar.alignment,
            maximum_end=maximum_end,
        )
        if address is None:
            return _failure(
                AllocationIssue(
                    "MMIO32_EXHAUSTED",
                    f"no below-4G range can place {bar.key} ({bar.size:#x} bytes)",
                    bar.key,
                    {
                        "availableBytes": low_pool.available_bytes,
                        "largestAlignedFit": low_pool.largest_aligned_fit(
                            bar.alignment
                        ),
                        "maximumEnd": maximum_end,
                    },
                ),
                low_pool,
                high_pool,
            )
        placed.append(BarAllocation(bar, address, "mmio32"))

    for bar in flexible:
        address: int | None = None
        pool_name = ""
        try_high_first = policy.prefer_64bit_high or policy.force_64bit_high
        if try_high_first:
            address = high_pool.allocate(
                bar.size,
                bar.alignment,
                top_down=policy.top_down_high,
            )
            if address is not None:
                pool_name = "mmio64"
        if address is None and not policy.force_64bit_high:
            address = low_pool.allocate(
                bar.size,
                bar.alignment,
                maximum_end=FOUR_GIB,
            )
            if address is not None:
                pool_name = "mmio32"
        if address is None and not try_high_first:
            address = high_pool.allocate(
                bar.size,
                bar.alignment,
                top_down=policy.top_down_high,
            )
            if address is not None:
                pool_name = "mmio64"
        if address is None:
            return _failure(
                AllocationIssue(
                    "MMIO64_EXHAUSTED",
                    f"no guest MMIO range can place {bar.key} ({bar.size:#x} bytes)",
                    bar.key,
                    {
                        "lowAvailableBytes": low_pool.available_bytes,
                        "highAvailableBytes": high_pool.available_bytes,
                        "largestHighAlignedFit": high_pool.largest_aligned_fit(
                            bar.alignment
                        ),
                    },
                ),
                low_pool,
                high_pool,
            )
        placed.append(BarAllocation(bar, address, pool_name))

    high_allocations = [item for item in placed if item.pool == "mmio64"]
    if high_allocations:
        used_start = min(item.address for item in high_allocations)
        used_end = max(item.end for item in high_allocations)
        used_span = AddressRange(used_start, used_end)
        containing_windows = [
            window
            for window in _normalize(high_windows)
            if window.contains(used_start, used_end - used_start)
        ]
        blocked_span = [block for block in reserved if block.overlaps(used_span)]
        if not containing_windows or blocked_span:
            return _failure(
                AllocationIssue(
                    "MMIO64_APERTURE_NONCONTIGUOUS",
                    "high BARs cannot be represented by one contiguous root aperture",
                    details={
                        "usedSpan": used_span.to_dict(),
                        "blockingRanges": [block.to_dict() for block in blocked_span],
                    },
                ),
                low_pool,
                high_pool,
            )
        high_alignment = max(item.bar.alignment for item in high_allocations)
        aperture = align_up(
            used_end - used_start,
            policy.high_aperture_granularity,
        )
        aperture = max(aperture, high_alignment)
        if policy.power_of_two_high_aperture:
            aperture = next_power_of_two(aperture)
        if all(window.size < aperture for window in containing_windows):
            return _failure(
                AllocationIssue(
                    "MMIO64_APERTURE_EXCEEDS_WINDOW",
                    "rounded high aperture is larger than its root window",
                    details={
                        "requiredBytes": aperture,
                        "windows": [window.to_dict() for window in containing_windows],
                    },
                ),
                low_pool,
                high_pool,
            )
    else:
        high_alignment = 0
        aperture = 0

    return AllocationResult(
        success=True,
        allocations=tuple(sorted(placed, key=lambda item: item.bar.key)),
        issues=(),
        low_free=tuple(low_pool.free),
        high_free=tuple(high_pool.free),
        high_aperture_bytes=aperture,
        high_aperture_alignment=high_alignment,
    )
