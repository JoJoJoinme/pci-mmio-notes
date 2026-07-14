from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .allocator import AllocationPolicy, AllocationResult, plan_mmio
from .model import (
    AddressRange,
    DeviceInventory,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
    unique_sorted,
)


FUNCTION_RESET_ORDER = (
    "device_specific",
    "acpi",
    "flr",
    "af_flr",
    "pm",
)
BUS_RESET_METHODS = ("bus", "cxl_bus", "bridge", "slot", "hot")
TRUSTED_ISOLATION = {
    IsolationProvenance.NATIVE_ACS,
    IsolationProvenance.NATURAL_TOPOLOGY,
    IsolationProvenance.KERNEL_GROUP,
}
TRUSTED_PHYSICAL_DOMAIN_SOURCES = {
    "stock-kernel-iommu-group",
    "kernel-no-override-iommu-group",
    "kernel-acs-provenance-topology-conservative",
    "qualification-snapshot",
    "manual-audited",
}
OVERRIDE_INDEPENDENT_SOURCES = {
    "kernel-no-override-iommu-group",
    "qualification-snapshot",
    "manual-audited",
}


@dataclass(frozen=True)
class CapabilityPolicy:
    require_interrupt_remapping: bool = True
    allow_acs_override: bool = True
    allow_bus_reset: bool = True
    allow_estimated_reset_domain: bool = False
    allow_host_driver_rebind: bool = True
    trust_domain: str = "untrusted-vm"


@dataclass(frozen=True)
class CapabilityReason:
    code: str
    stage: str
    message: str
    devices: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "message": self.message,
            "devices": list(self.devices),
            "details": self.details,
        }


@dataclass(frozen=True)
class CapabilityResult:
    target: str
    payload_devices: tuple[str, ...]
    eligible: bool
    available: bool
    attachable: bool
    verdict: str
    required_lease: tuple[str, ...]
    reset_methods: dict[str, str]
    reasons: tuple[CapabilityReason, ...]
    warnings: tuple[CapabilityReason, ...]
    allocation: AllocationResult | None

    def to_dict(
        self,
        *,
        firmware: str = "ovmf",
        host_bridge: str = "q35-pcihost",
    ) -> dict[str, Any]:
        return {
            "target": self.target,
            "payloadDevices": list(self.payload_devices),
            "passthroughCapable": self.eligible,
            "eligible": self.eligible,
            "available": self.available,
            "attachable": self.attachable,
            "verdict": self.verdict,
            "requiredLease": list(self.required_lease),
            "selectedResetMethods": dict(sorted(self.reset_methods.items())),
            "reasons": [reason.to_dict() for reason in self.reasons],
            "warnings": [warning.to_dict() for warning in self.warnings],
            "allocation": (
                None
                if self.allocation is None
                else self.allocation.to_dict(firmware=firmware, host_bridge=host_bridge)
            ),
        }


def _reason(
    code: str,
    stage: str,
    message: str,
    devices: Iterable[str] = (),
    **details: Any,
) -> CapabilityReason:
    return CapabilityReason(
        code=code,
        stage=stage,
        message=message,
        devices=unique_sorted(devices),
        details=details,
    )


def _select_reset(
    device: DeviceInventory,
    policy: CapabilityPolicy,
) -> tuple[str | None, CapabilityReason | None]:
    methods = tuple(method.lower() for method in device.reset_methods)
    for method in FUNCTION_RESET_ORDER:
        if method in methods:
            return method, None
    for method in BUS_RESET_METHODS:
        if method not in methods:
            continue
        if not policy.allow_bus_reset:
            return None, _reason(
                "BUS_RESET_NOT_ALLOWED",
                "eligible",
                f"{device.bdf} only has a shared reset path disabled by policy",
                (device.bdf,),
                resetMethod=method,
            )
        if not device.reset_domain:
            return None, _reason(
                "RESET_DOMAIN_UNKNOWN",
                "eligible",
                f"{device.bdf} advertises {method} reset without an affected set",
                (device.bdf,),
            )
        if (
            device.reset_domain_source in {"unknown", "sysfs-parent-topology-estimate"}
            and not policy.allow_estimated_reset_domain
        ):
            return None, _reason(
                "RESET_DOMAIN_UNVERIFIED",
                "eligible",
                f"{device.bdf} shared reset affected set is only an estimate",
                device.reset_domain,
                resetDomainSource=device.reset_domain_source,
            )
        return method, None
    return None, _reason(
        "NO_ACCEPTED_RESET",
        "eligible",
        f"{device.bdf} has no accepted function or shared reset path",
        (device.bdf,),
        resetMethods=list(methods),
    )


def _dependency_closure(
    host: HostInventory,
    seeds: Iterable[str],
) -> tuple[str, ...]:
    pending = list(unique_sorted(seeds))
    closure: set[str] = set()
    while pending:
        bdf = pending.pop()
        if bdf in closure:
            continue
        closure.add(bdf)
        device = host.devices.get(bdf)
        if device is None:
            continue
        dependencies = (
            device.iommu_group
            + device.physical_isolation_domain
            + device.reset_domain
            + device.multifunction_aliases
            + device.platform_dependencies
        )
        pending.extend(dep for dep in dependencies if dep not in closure)
    return tuple(sorted(closure))


def _check_isolation(
    host: HostInventory,
    device: DeviceInventory,
    policy: CapabilityPolicy,
) -> tuple[CapabilityReason | None, CapabilityReason | None]:
    provenance = device.isolation_provenance
    if (
        host.acs_override_active
        and provenance == IsolationProvenance.KERNEL_GROUP
        and device.physical_isolation_domain_source not in OVERRIDE_INDEPENDENT_SOURCES
    ):
        provenance = IsolationProvenance.ACS_OVERRIDE

    if provenance in TRUSTED_ISOLATION:
        if not device.iommu_group:
            return (
                _reason(
                    "IOMMU_GROUP_MISSING",
                    "eligible",
                    f"{device.bdf} has no kernel IOMMU group",
                    (device.bdf,),
                ),
                None,
            )
        return None, None

    if provenance == IsolationProvenance.ACS_OVERRIDE:
        if not policy.allow_acs_override:
            return (
                _reason(
                    "ACS_OVERRIDE_NOT_ALLOWED",
                    "eligible",
                    f"{device.bdf} isolation depends on an ACS override",
                    (device.bdf,),
                    trustDomain=policy.trust_domain,
                ),
                None,
            )
        if not device.physical_isolation_domain:
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_UNKNOWN",
                    "eligible",
                    f"{device.bdf} needs an override-independent physical domain",
                    (device.bdf,),
                ),
                None,
            )
        if device.bdf not in device.physical_isolation_domain:
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_INVALID",
                    "eligible",
                    f"{device.bdf} is absent from its physical isolation domain",
                    device.physical_isolation_domain,
                    physicalDomainSource=device.physical_isolation_domain_source,
                ),
                None,
            )
        if (
            device.physical_isolation_domain_source
            not in TRUSTED_PHYSICAL_DOMAIN_SOURCES
        ):
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_UNTRUSTED",
                    "eligible",
                    f"{device.bdf} physical isolation domain has no trusted provenance",
                    device.physical_isolation_domain,
                    physicalDomainSource=device.physical_isolation_domain_source,
                ),
                None,
            )
        return (
            None,
            _reason(
                "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN",
                "eligible",
                f"{device.bdf} is conditional on leasing its complete physical domain",
                device.physical_isolation_domain,
                trustDomain=policy.trust_domain,
                physicalDomainSource=device.physical_isolation_domain_source,
            ),
        )

    code = (
        "ACS_OR_TOPOLOGY_ISOLATION_MISSING"
        if provenance == IsolationProvenance.MISSING
        else "ISOLATION_PROVENANCE_UNKNOWN"
    )
    return (
        _reason(
            code,
            "eligible",
            f"{device.bdf} lacks a trustworthy DMA isolation provenance",
            (device.bdf,),
            isolationProvenance=provenance.value,
        ),
        None,
    )


def evaluate_passthrough(
    host: HostInventory,
    target_bdf: str,
    *,
    low_windows: Sequence[AddressRange],
    high_windows: Sequence[AddressRange] = (),
    reserved: Sequence[AddressRange] = (),
    payload_devices: Sequence[str] | None = None,
    lease_owner: str = "candidate-vm",
    policy: CapabilityPolicy | None = None,
    allocation_policy: AllocationPolicy | None = None,
) -> CapabilityResult:
    """Evaluate static eligibility, current availability, and VM attachability."""

    policy = policy or CapabilityPolicy()
    target = target_bdf.lower()
    payload = unique_sorted((target,) + tuple(payload_devices or ()))
    reasons: list[CapabilityReason] = []
    warnings: list[CapabilityReason] = []
    selected_resets: dict[str, str] = {}

    missing_payload = [bdf for bdf in payload if bdf not in host.devices]
    if missing_payload:
        reasons.append(
            _reason(
                "DEVICE_NOT_IN_INVENTORY",
                "eligible",
                "one or more payload devices are absent from inventory",
                missing_payload,
            )
        )

    if host.no_iommu_mode:
        reasons.append(
            _reason(
                "VFIO_NOIOMMU_UNSAFE",
                "eligible",
                "host reports VFIO no-IOMMU mode",
                payload,
            )
        )
    elif not host.iommu_present:
        reasons.append(
            _reason(
                "HOST_IOMMU_MISSING",
                "eligible",
                "host IOMMU is not available",
                payload,
            )
        )

    if policy.require_interrupt_remapping:
        if host.interrupt_remapping is False:
            reasons.append(
                _reason(
                    "INTERRUPT_REMAP_MISSING",
                    "eligible",
                    "interrupt remapping is disabled",
                    payload,
                )
            )
        elif host.interrupt_remapping is None:
            reasons.append(
                _reason(
                    "INTERRUPT_REMAP_UNKNOWN",
                    "eligible",
                    "interrupt remapping state is unknown",
                    payload,
                )
            )

    for bdf in payload:
        device = host.devices.get(bdf)
        if device is None:
            continue
        if device.header_type != 0 or device.function_role == FunctionRole.FABRIC:
            reasons.append(
                _reason(
                    "STRUCTURAL_FABRIC_NODE",
                    "eligible",
                    f"{bdf} is a Type-1 or topology-bearing fabric function",
                    (bdf,),
                    headerType=device.header_type,
                    functionRole=device.function_role.value,
                )
            )
        elif device.function_role not in {
            FunctionRole.ENDPOINT,
            FunctionRole.VIRTUAL_FUNCTION,
        }:
            reasons.append(
                _reason(
                    "FUNCTION_ROLE_NOT_ASSIGNABLE",
                    "eligible",
                    f"{bdf} is not classified as an assignable payload",
                    (bdf,),
                    functionRole=device.function_role.value,
                )
            )
        if device.platform_reserved:
            reasons.append(
                _reason(
                    "PLATFORM_RESERVED",
                    "eligible",
                    f"{bdf} is retained by the host platform",
                    (bdf,),
                )
            )
        if device.errata_denied:
            reasons.append(
                _reason(
                    "DEVICE_ERRATA_DENY",
                    "eligible",
                    f"{bdf} matches an audited device erratum deny entry",
                    (bdf,),
                    vendorId=device.vendor_id,
                    deviceId=device.device_id,
                )
            )

        isolation_error, isolation_warning = _check_isolation(host, device, policy)
        if isolation_error:
            reasons.append(isolation_error)
        if isolation_warning:
            warnings.append(isolation_warning)

        reset_method, reset_error = _select_reset(device, policy)
        if reset_error:
            reasons.append(reset_error)
        elif reset_method:
            selected_resets[bdf] = reset_method

    eligibility_reasons = [reason for reason in reasons if reason.stage == "eligible"]
    eligible = not eligibility_reasons
    required_lease = _dependency_closure(host, payload)

    if eligible:
        unknown_dependencies = [
            bdf for bdf in required_lease if bdf not in host.devices
        ]
        if unknown_dependencies:
            reasons.append(
                _reason(
                    "DEPENDENCY_NOT_IN_INVENTORY",
                    "available",
                    "the complete lease domain is not present in inventory",
                    unknown_dependencies,
                )
            )
        busy = {
            bdf: owner
            for bdf in required_lease
            if (owner := host.leases.get(bdf)) not in (None, "", "free", lease_owner)
        }
        if busy:
            reasons.append(
                _reason(
                    "DEPENDENCY_BUSY",
                    "available",
                    "one or more dependency functions are leased by another owner",
                    busy,
                    owners=busy,
                )
            )

        for bdf in payload:
            device = host.devices[bdf]
            if device.driver and device.driver != "vfio-pci":
                if policy.allow_host_driver_rebind:
                    warnings.append(
                        _reason(
                            "HOST_DRIVER_REBIND_REQUIRED",
                            "available",
                            f"{bdf} must be detached from {device.driver}",
                            (bdf,),
                            driver=device.driver,
                        )
                    )
                else:
                    reasons.append(
                        _reason(
                            "HOST_DRIVER_BOUND",
                            "available",
                            f"{bdf} is still bound to {device.driver}",
                            (bdf,),
                            driver=device.driver,
                        )
                    )

    available = eligible and not any(reason.stage == "available" for reason in reasons)
    allocation: AllocationResult | None = None

    if available:
        rmrr_devices = [bdf for bdf in payload if host.devices[bdf].rmrr_conflict]
        if rmrr_devices:
            reasons.append(
                _reason(
                    "RMRR_CONFLICT",
                    "attachable",
                    "reserved DMA region conflicts with the guest memory layout",
                    rmrr_devices,
                )
            )
        else:
            bars = tuple(bar for bdf in payload for bar in host.devices[bdf].bars)
            allocation = plan_mmio(
                bars,
                low_windows=low_windows,
                high_windows=high_windows,
                reserved=reserved,
                policy=allocation_policy,
            )
            if not allocation.success:
                issue = allocation.issues[0]
                reasons.append(
                    _reason(
                        issue.code,
                        "attachable",
                        issue.message,
                        payload,
                        bar=issue.bar,
                        **issue.details,
                    )
                )

    attachable = available and not any(
        reason.stage == "attachable" for reason in reasons
    )
    if attachable and any(
        warning.code == "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN"
        for warning in warnings
    ):
        verdict = "conditional"
    elif attachable:
        verdict = "true"
    else:
        verdict = "false"

    return CapabilityResult(
        target=target,
        payload_devices=payload,
        eligible=eligible,
        available=available,
        attachable=attachable,
        verdict=verdict,
        required_lease=required_lease,
        reset_methods=selected_resets,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
        allocation=allocation,
    )
