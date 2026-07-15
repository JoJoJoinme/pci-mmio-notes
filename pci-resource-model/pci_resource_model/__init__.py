"""PCI BAR allocation and passthrough capability reference model."""

from .allocator import (
    AllocationPolicy,
    AllocationResult,
    QemuHole64Window,
    plan_mmio,
    project_qemu_hole64_window,
)
from .bar_probe import (
    ConfigSpace,
    LinuxSysfsConfigSpace,
    ProbeError,
    probe_standard_bars,
    probe_unbound_linux_device,
)
from .capability import CapabilityPolicy, CapabilityResult, evaluate_passthrough
from .model import (
    AddressRange,
    Bar,
    BarSpace,
    DeviceInventory,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
)

__all__ = [
    "AddressRange",
    "AllocationPolicy",
    "AllocationResult",
    "Bar",
    "BarSpace",
    "CapabilityPolicy",
    "CapabilityResult",
    "ConfigSpace",
    "DeviceInventory",
    "FunctionRole",
    "HostInventory",
    "IsolationProvenance",
    "LinuxSysfsConfigSpace",
    "ProbeError",
    "QemuHole64Window",
    "evaluate_passthrough",
    "plan_mmio",
    "project_qemu_hole64_window",
    "probe_standard_bars",
    "probe_unbound_linux_device",
]
