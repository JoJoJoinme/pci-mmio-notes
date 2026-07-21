from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
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


class DmaIsolationMode(StringEnum):
    """How DMA from this function is constrained on the host."""

    IOMMU = "iommu"
    NO_IOMMU = "no-iommu"
    UNKNOWN = "unknown"


class MemberAction(StringEnum):
    """Owner-independent action required for a dependency bundle member."""

    NONE = "none"
    LOCK_ONLY = "lock-only"
    VFIO_HOLD_IN_SAME_IOAS = "vfio-hold-in-same-ioas"
    ASSIGN_TO_GUEST = "assign-to-guest"
    QUIESCE_HOST = "quiesce-host"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FactEvidence:
    """Provenance envelope for one published capability fact.

    ``subject_hash`` binds the fact to its canonical semantic subject.  The
    ``evidence_hash`` identifies the signed/retained evidence object that
    published it; signature verification remains a provider responsibility.
    Reset contracts additionally carry the snapshot epoch and topology hash
    against which their affected set was discovered.
    """

    source: str
    rule_id: str
    subject_hash: str
    evidence_hash: str
    inventory_epoch: int | None = None
    topology_hash: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", self.source.lower())
        object.__setattr__(self, "subject_hash", self.subject_hash.lower())
        object.__setattr__(self, "evidence_hash", self.evidence_hash.lower())
        if self.topology_hash is not None:
            object.__setattr__(self, "topology_hash", self.topology_hash.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ruleId": self.rule_id,
            "subjectHash": self.subject_hash,
            "evidenceHash": self.evidence_hash,
            "inventoryEpoch": self.inventory_epoch,
            "topologyHash": self.topology_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FactEvidence:
        return cls(
            source=str(value.get("source", "unknown")),
            rule_id=str(value.get("ruleId", "")),
            subject_hash=str(value.get("subjectHash", "")),
            evidence_hash=str(value.get("evidenceHash", "")),
            inventory_epoch=(
                None
                if value.get("inventoryEpoch") is None
                else parse_int(value.get("inventoryEpoch"))
            ),
            topology_hash=(
                None
                if value.get("topologyHash") is None
                else str(value.get("topologyHash"))
            ),
        )


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
    owner_activation_group: str | None = None
    exclusive_attach_group: str | None = None
    isolation_provenance: IsolationProvenance = IsolationProvenance.UNKNOWN
    dma_isolation_mode: DmaIsolationMode = DmaIsolationMode.UNKNOWN
    dma_isolation_source: str = "unknown"
    host_reservation: str | None = None
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
    # Appended fields preserve the positional constructor order of schema v1.
    dependency_action: MemberAction = MemberAction.UNKNOWN
    qualified_actions: tuple[MemberAction, ...] = ()
    dependency_action_fact: FactEvidence | None = None
    qualification_fact: FactEvidence | None = None
    reset_contract_fact: FactEvidence | None = None
    multifunction_source: str = "unknown"
    platform_dependency_source: str = "unknown"
    device_generation: int = 0

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
            "dependency_action",
            MemberAction(self.dependency_action),
        )
        object.__setattr__(
            self,
            "qualified_actions",
            tuple(
                sorted(
                    {MemberAction(action) for action in self.qualified_actions},
                    key=lambda action: action.value,
                )
            ),
        )
        object.__setattr__(
            self,
            "physical_isolation_domain_source",
            self.physical_isolation_domain_source.lower(),
        )
        object.__setattr__(self, "reset_domain_source", self.reset_domain_source.lower())
        object.__setattr__(self, "multifunction_source", self.multifunction_source.lower())
        object.__setattr__(
            self,
            "platform_dependency_source",
            self.platform_dependency_source.lower(),
        )
        object.__setattr__(
            self, "acs_override_source", self.acs_override_source.lower()
        )
        object.__setattr__(
            self, "dma_isolation_source", self.dma_isolation_source.lower()
        )
        for field_name in ("owner_activation_group", "exclusive_attach_group"):
            value = getattr(self, field_name)
            if value:
                object.__setattr__(self, field_name, value.lower())

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
            "dependencyAction": self.dependency_action.value,
            "qualifiedActions": [action.value for action in self.qualified_actions],
            "dependencyActionFact": (
                None
                if self.dependency_action_fact is None
                else self.dependency_action_fact.to_dict()
            ),
            "qualificationFact": (
                None
                if self.qualification_fact is None
                else self.qualification_fact.to_dict()
            ),
            "resetContractFact": (
                None
                if self.reset_contract_fact is None
                else self.reset_contract_fact.to_dict()
            ),
            "multifunctionSource": self.multifunction_source,
            "platformDependencySource": self.platform_dependency_source,
            "deviceGeneration": self.device_generation,
            "ownerActivationGroup": self.owner_activation_group,
            "exclusiveAttachGroup": self.exclusive_attach_group,
            "isolationProvenance": self.isolation_provenance.value,
            "dmaIsolationMode": self.dma_isolation_mode.value,
            "dmaIsolationSource": self.dma_isolation_source,
            "hostReservation": self.host_reservation,
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
            dependency_action=MemberAction(
                value.get("dependencyAction", MemberAction.UNKNOWN.value)
            ),
            qualified_actions=tuple(
                MemberAction(action) for action in value.get("qualifiedActions", ())
            ),
            dependency_action_fact=(
                None
                if value.get("dependencyActionFact") is None
                else FactEvidence.from_dict(value["dependencyActionFact"])
            ),
            qualification_fact=(
                None
                if value.get("qualificationFact") is None
                else FactEvidence.from_dict(value["qualificationFact"])
            ),
            reset_contract_fact=(
                None
                if value.get("resetContractFact") is None
                else FactEvidence.from_dict(value["resetContractFact"])
            ),
            multifunction_source=str(value.get("multifunctionSource", "unknown")),
            platform_dependency_source=str(
                value.get("platformDependencySource", "unknown")
            ),
            device_generation=parse_int(value.get("deviceGeneration"), 0),
            owner_activation_group=value.get("ownerActivationGroup"),
            exclusive_attach_group=value.get("exclusiveAttachGroup"),
            isolation_provenance=IsolationProvenance(
                value.get("isolationProvenance", IsolationProvenance.UNKNOWN.value)
            ),
            dma_isolation_mode=DmaIsolationMode(
                value.get("dmaIsolationMode", DmaIsolationMode.UNKNOWN.value)
            ),
            dma_isolation_source=str(value.get("dmaIsolationSource", "unknown")),
            host_reservation=value.get("hostReservation"),
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
    # Schema-v2 immutable snapshot identity.  Appended for Python API compatibility.
    schema_version: int = 2
    host_id: str = "unknown"
    kernel_boot_id: str = "unknown"
    inventory_epoch: int | None = None
    topology_hash: str = "unknown"

    def __post_init__(self) -> None:
        if self.schema_version != 2:
            raise ValueError(f"unsupported inventory schemaVersion: {self.schema_version}")
        normalized_devices: dict[str, DeviceInventory] = {}
        for raw_bdf, device in self.devices.items():
            bdf = str(raw_bdf).lower()
            if bdf != device.bdf:
                raise ValueError(
                    "inventory device key does not match embedded bdf: "
                    f"{raw_bdf!r} != {device.bdf!r}"
                )
            if bdf in normalized_devices:
                raise ValueError(f"duplicate inventory device bdf: {bdf}")
            normalized_devices[bdf] = device
        normalized_leases = {bdf.lower(): owner for bdf, owner in self.leases.items()}
        object.__setattr__(self, "devices", MappingProxyType(normalized_devices))
        object.__setattr__(self, "leases", MappingProxyType(normalized_leases))
        object.__setattr__(self, "topology_hash", self.topology_hash.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "host": {
                "iommuPresent": self.iommu_present,
                "interruptRemapping": self.interrupt_remapping,
                "unsafeNoIommuModeEnabled": self.no_iommu_mode,
                "acsOverrideActive": self.acs_override_active,
                "source": self.source,
                "hostId": self.host_id,
                "kernelBootId": self.kernel_boot_id,
                "inventoryEpoch": self.inventory_epoch,
                "topologyHash": self.topology_hash,
                "metadata": dict(self.metadata),
            },
            "leases": dict(sorted(self.leases.items())),
            "devices": [self.devices[bdf].to_dict() for bdf in sorted(self.devices)],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> HostInventory:
        schema_version = parse_int(value.get("schemaVersion"), 1)
        if schema_version != 2:
            raise ValueError(
                "inventory schemaVersion 1 predates capability fact provenance; "
                "explicitly migrate it to schemaVersion 2"
                if schema_version == 1
                else f"unsupported inventory schemaVersion: {schema_version}"
            )
        host = value.get("host", {})
        raw_devices = value.get("devices", ())
        if isinstance(raw_devices, Mapping):
            devices = {
                str(bdf): DeviceInventory.from_dict(device)
                for bdf, device in raw_devices.items()
            }
        else:
            parsed = [DeviceInventory.from_dict(device) for device in raw_devices]
            devices = {}
            for device in parsed:
                if device.bdf in devices:
                    raise ValueError(f"duplicate inventory device bdf: {device.bdf}")
                devices[device.bdf] = device
        return cls(
            iommu_present=bool(host.get("iommuPresent", False)),
            interrupt_remapping=host.get("interruptRemapping"),
            no_iommu_mode=bool(
                host.get(
                    "unsafeNoIommuModeEnabled",
                    host.get("noIommuMode", False),
                )
            ),
            acs_override_active=bool(host.get("acsOverrideActive", False)),
            devices=devices,
            leases=dict(value.get("leases", {})),
            source=str(host.get("source", "json")),
            metadata=dict(host.get("metadata", {})),
            schema_version=schema_version,
            host_id=str(host.get("hostId", "unknown")),
            kernel_boot_id=str(host.get("kernelBootId", "unknown")),
            inventory_epoch=(
                None
                if host.get("inventoryEpoch") is None
                else parse_int(host.get("inventoryEpoch"))
            ),
            topology_hash=str(host.get("topologyHash", "unknown")),
        )
