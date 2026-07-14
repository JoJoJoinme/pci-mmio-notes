from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class BarSpace(StringEnum):
    MEMORY = "memory"
    IO = "io"


class FunctionRole(StringEnum):
    ENDPOINT = "endpoint"
    VIRTUAL_FUNCTION = "virtual-function"
    FABRIC = "fabric"
    PLATFORM = "platform"
    UNKNOWN = "unknown"


class IsolationProvenance(StringEnum):
    NATIVE_ACS = "native-acs"
    NATURAL_TOPOLOGY = "natural-topology"
    KERNEL_GROUP = "kernel-group"
    ACS_OVERRIDE = "acs-override"
    MISSING = "missing"
    UNKNOWN = "unknown"


def parse_int(value: int | str | None, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return int(value, 0)


def unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value.lower() for value in values if value}))


def is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


@dataclass(frozen=True, order=True)
class AddressRange:
    """A half-open address interval: start <= address < end."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError(f"invalid address range [{self.start:#x}, {self.end:#x})")

    @property
    def size(self) -> int:
        return self.end - self.start

    def overlaps(self, other: AddressRange) -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, start: int, size: int) -> bool:
        return start >= self.start and start + size <= self.end

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AddressRange:
        return cls(parse_int(value["start"]), parse_int(value["end"]))

    @classmethod
    def parse(cls, value: str) -> AddressRange:
        try:
            start_text, end_text = value.split(":", 1)
        except ValueError as error:
            raise ValueError(
                f"range must use START:END with an exclusive END: {value!r}"
            ) from error
        return cls(parse_int(start_text), parse_int(end_text))


@dataclass(frozen=True)
class Bar:
    bdf: str
    index: int
    size: int
    space: BarSpace = BarSpace.MEMORY
    address: int | None = None
    is_64: bool = False
    prefetchable: bool = False
    below_1m: bool = False
    source: str = "unknown"

    @property
    def key(self) -> str:
        return f"{self.bdf.lower()}/BAR{self.index}"

    @property
    def alignment(self) -> int:
        return self.size

    def validation_errors(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not 0 <= self.index <= 5:
            errors.append("BAR_INDEX_OUT_OF_RANGE")
        if not is_power_of_two(self.size):
            errors.append("BAR_SIZE_NOT_POWER_OF_TWO")
        minimum = 4 if self.space == BarSpace.IO else 16
        if self.size < minimum:
            errors.append("BAR_SIZE_TOO_SMALL")
        if not self.is_64 and self.size > 1 << 32:
            errors.append("BAR32_SIZE_EXCEEDS_4G")
        if self.size > 1 << 64:
            errors.append("BAR_SIZE_EXCEEDS_64BIT_ADDRESS_SPACE")
        if self.address not in (None, 0) and self.address % self.alignment:
            errors.append("BAR_ADDRESS_MISALIGNED")
        if self.below_1m and self.size > 1 << 20:
            errors.append("BAR_BELOW_1M_SIZE_EXCEEDS_LIMIT")
        return tuple(errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bdf": self.bdf.lower(),
            "index": self.index,
            "size": self.size,
            "space": self.space.value,
            "address": self.address,
            "is64": self.is_64,
            "prefetchable": self.prefetchable,
            "below1M": self.below_1m,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Bar:
        return cls(
            bdf=str(value["bdf"]).lower(),
            index=parse_int(value["index"]),
            size=parse_int(value["size"]),
            space=BarSpace(value.get("space", BarSpace.MEMORY.value)),
            address=(
                None
                if value.get("address") is None
                else parse_int(value.get("address"))
            ),
            is_64=bool(value.get("is64", False)),
            prefetchable=bool(value.get("prefetchable", False)),
            below_1m=bool(value.get("below1M", False)),
            source=str(value.get("source", "json")),
        )


@dataclass(frozen=True)
class AcsState:
    capability: int
    control: int
    offset: int

    @property
    def redirect_enabled(self) -> bool:
        # P2P Request Redirect, Completion Redirect, and Upstream Forwarding.
        required = 0x04 | 0x08 | 0x10
        return (
            self.capability & required == required
            and self.control & required == required
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "control": self.control,
            "offset": self.offset,
            "redirectEnabled": self.redirect_enabled,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AcsState:
        return cls(
            capability=parse_int(value["capability"]),
            control=parse_int(value["control"]),
            offset=parse_int(value["offset"]),
        )


@dataclass(frozen=True)
class DeviceInventory:
    bdf: str
    vendor_id: int
    device_id: int
    class_code: int
    header_type: int
    function_role: FunctionRole
    bars: tuple[Bar, ...] = ()
    iommu_group: tuple[str, ...] = ()
    physical_isolation_domain: tuple[str, ...] = ()
    physical_isolation_domain_source: str = "unknown"
    reset_methods: tuple[str, ...] = ()
    reset_domain: tuple[str, ...] = ()
    reset_domain_source: str = "unknown"
    multifunction_aliases: tuple[str, ...] = ()
    platform_dependencies: tuple[str, ...] = ()
    isolation_provenance: IsolationProvenance = IsolationProvenance.UNKNOWN
    platform_reserved: bool = False
    errata_denied: bool = False
    rmrr_conflict: bool = False
    driver: str | None = None
    parent: str | None = None
    acs: AcsState | None = None
    acs_native_isolation: bool | None = None
    acs_effective_isolation: bool | None = None
    acs_override_source: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "bdf", self.bdf.lower())
        object.__setattr__(self, "header_type", self.header_type & 0x7F)
        for field_name in (
            "iommu_group",
            "physical_isolation_domain",
            "reset_domain",
            "multifunction_aliases",
            "platform_dependencies",
        ):
            object.__setattr__(
                self, field_name, unique_sorted(getattr(self, field_name))
            )
        object.__setattr__(
            self,
            "reset_methods",
            tuple(dict.fromkeys(method.lower() for method in self.reset_methods)),
        )
        object.__setattr__(
            self,
            "physical_isolation_domain_source",
            self.physical_isolation_domain_source.lower(),
        )
        object.__setattr__(
            self, "acs_override_source", self.acs_override_source.lower()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bdf": self.bdf,
            "vendorId": self.vendor_id,
            "deviceId": self.device_id,
            "classCode": self.class_code,
            "headerType": self.header_type,
            "functionRole": self.function_role.value,
            "bars": [bar.to_dict() for bar in self.bars],
            "kernelIommuGroup": list(self.iommu_group),
            "physicalIsolationDomain": list(self.physical_isolation_domain),
            "physicalIsolationDomainSource": self.physical_isolation_domain_source,
            "resetMethods": list(self.reset_methods),
            "resetDomain": list(self.reset_domain),
            "resetDomainSource": self.reset_domain_source,
            "multifunctionAliases": list(self.multifunction_aliases),
            "platformDependencies": list(self.platform_dependencies),
            "isolationProvenance": self.isolation_provenance.value,
            "platformReserved": self.platform_reserved,
            "errataDenied": self.errata_denied,
            "rmrrConflict": self.rmrr_conflict,
            "driver": self.driver,
            "parent": self.parent,
            "acs": None if self.acs is None else self.acs.to_dict(),
            "acsNativeIsolation": self.acs_native_isolation,
            "acsEffectiveIsolation": self.acs_effective_isolation,
            "acsOverrideSource": self.acs_override_source,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeviceInventory:
        return cls(
            bdf=str(value["bdf"]),
            vendor_id=parse_int(value.get("vendorId")),
            device_id=parse_int(value.get("deviceId")),
            class_code=parse_int(value.get("classCode")),
            header_type=parse_int(value.get("headerType")),
            function_role=FunctionRole(
                value.get("functionRole", FunctionRole.UNKNOWN.value)
            ),
            bars=tuple(Bar.from_dict(bar) for bar in value.get("bars", ())),
            iommu_group=tuple(value.get("kernelIommuGroup", ())),
            physical_isolation_domain=tuple(value.get("physicalIsolationDomain", ())),
            physical_isolation_domain_source=str(
                value.get("physicalIsolationDomainSource", "unknown")
            ),
            reset_methods=tuple(value.get("resetMethods", ())),
            reset_domain=tuple(value.get("resetDomain", ())),
            reset_domain_source=str(value.get("resetDomainSource", "json")),
            multifunction_aliases=tuple(value.get("multifunctionAliases", ())),
            platform_dependencies=tuple(value.get("platformDependencies", ())),
            isolation_provenance=IsolationProvenance(
                value.get("isolationProvenance", IsolationProvenance.UNKNOWN.value)
            ),
            platform_reserved=bool(value.get("platformReserved", False)),
            errata_denied=bool(value.get("errataDenied", False)),
            rmrr_conflict=bool(value.get("rmrrConflict", False)),
            driver=value.get("driver"),
            parent=value.get("parent"),
            acs=(
                None if value.get("acs") is None else AcsState.from_dict(value["acs"])
            ),
            acs_native_isolation=value.get("acsNativeIsolation"),
            acs_effective_isolation=value.get("acsEffectiveIsolation"),
            acs_override_source=str(value.get("acsOverrideSource", "unknown")),
            metadata=dict(value.get("metadata", {})),
        )


@dataclass(frozen=True)
class HostInventory:
    iommu_present: bool
    interrupt_remapping: bool | None
    no_iommu_mode: bool
    acs_override_active: bool
    devices: Mapping[str, DeviceInventory]
    leases: Mapping[str, str] = field(default_factory=dict)
    source: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_devices = {
            bdf.lower(): device for bdf, device in self.devices.items()
        }
        normalized_leases = {bdf.lower(): owner for bdf, owner in self.leases.items()}
        object.__setattr__(self, "devices", normalized_devices)
        object.__setattr__(self, "leases", normalized_leases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "host": {
                "iommuPresent": self.iommu_present,
                "interruptRemapping": self.interrupt_remapping,
                "noIommuMode": self.no_iommu_mode,
                "acsOverrideActive": self.acs_override_active,
                "source": self.source,
                "metadata": dict(self.metadata),
            },
            "leases": dict(sorted(self.leases.items())),
            "devices": [self.devices[bdf].to_dict() for bdf in sorted(self.devices)],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> HostInventory:
        if parse_int(value.get("schemaVersion"), 1) != 1:
            raise ValueError("unsupported inventory schemaVersion")
        host = value.get("host", {})
        raw_devices = value.get("devices", ())
        if isinstance(raw_devices, Mapping):
            devices = {
                str(bdf).lower(): DeviceInventory.from_dict(device)
                for bdf, device in raw_devices.items()
            }
        else:
            parsed = [DeviceInventory.from_dict(device) for device in raw_devices]
            devices = {device.bdf: device for device in parsed}
        return cls(
            iommu_present=bool(host.get("iommuPresent", False)),
            interrupt_remapping=host.get("interruptRemapping"),
            no_iommu_mode=bool(host.get("noIommuMode", False)),
            acs_override_active=bool(host.get("acsOverrideActive", False)),
            devices=devices,
            leases=dict(value.get("leases", {})),
            source=str(host.get("source", "json")),
            metadata=dict(host.get("metadata", {})),
        )
