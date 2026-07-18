"""PCI BAR allocation and passthrough capability reference model."""

from .activation import (
    ActivationDisposition,
    ActivationMember,
    ActivationPlan,
    ActivationReason,
    ActivationRequestMode,
    DeviceOwner,
    QuiesceState,
    plan_activation,
)
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
    DmaIsolationMode,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
)

__all__ = [
    "AddressRange",
    "ActivationDisposition",
    "ActivationMember",
    "ActivationPlan",
    "ActivationReason",
    "ActivationRequestMode",
    "AllocationPolicy",
    "AllocationResult",
    "Bar",
    "BarSpace",
    "CapabilityPolicy",
    "CapabilityResult",
    "ConfigSpace",
    "DeviceInventory",
    "DeviceOwner",
    "DmaIsolationMode",
    "FunctionRole",
    "HostInventory",
    "IsolationProvenance",
    "LinuxSysfsConfigSpace",
    "ProbeError",
    "QemuHole64Window",
    "QuiesceState",
    "evaluate_passthrough",
    "plan_activation",
    "plan_mmio",
    "project_qemu_hole64_window",
    "probe_standard_bars",
    "probe_unbound_linux_device",
]
