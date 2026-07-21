"""Durable component authority for immutable host inventory snapshots.

The SQLite database is the authority: epoch allocation, the current pointer,
canonical payload and authentication tag commit in one transaction.  JSON
exports are evidence/cache artifacts only.  ``ComponentHmacAuthenticator`` is
deliberately labelled ``COMPONENT_AUTHENTICITY_ONLY``; it demonstrates the
publisher/verifier contract but is not a production trust root, key-rotation
service, TPM rollback anchor, or multi-host consensus authority.

In particular, authentication does not detect an earlier, otherwise valid
database state replayed in place under the same trusted key (including a
block-level rollback or deletion of the newest valid rows).  Detecting that
time rollback requires an external monotonic anchor.

An active :class:`SnapshotLaunchAuthorization` holds ``BEGIN IMMEDIATE`` until
the caller leaves its context.  This prevents a concurrent publication from
changing the authoritative current snapshot between final validation and the
QEMU spawn boundary.  The intended lock order is snapshot -> lease -> launch
envelope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Sequence

from . import vfio_provider as vfio
from .model import FactEvidence, HostInventory


SCHEMA_VERSION = 1
SNAPSHOT_KIND = "qman-authoritative-host-snapshot-v1"
SNAPSHOT_TRUST_BOUNDARY = "COMPONENT_AUTHENTICITY_ONLY"
FULL_HOST_SCOPE = "FULL_HOST"
AUTHENTICATION_ALGORITHM = "HMAC-SHA256"
CAPTURE_PROVIDER_BOUNDARY = "COMPONENT_CAPTURE_PROVIDER"

_SQLITE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS snapshots (
        inventory_epoch INTEGER PRIMARY KEY,
        snapshot_hash TEXT NOT NULL UNIQUE,
        topology_hash TEXT NOT NULL,
        kernel_boot_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        envelope_json TEXT NOT NULL
    );
"""
_SQLITE_OBJECTS = {
    ("index", "sqlite_autoindex_metadata_1", "metadata"),
    ("index", "sqlite_autoindex_snapshots_1", "snapshots"),
    ("table", "metadata", "metadata"),
    ("table", "snapshots", "snapshots"),
}
_SQLITE_TABLE_COLUMNS = {
    "metadata": (
        (0, "key", "TEXT", 0, None, 1, 0),
        (1, "value", "TEXT", 1, None, 0, 0),
    ),
    "snapshots": (
        (0, "inventory_epoch", "INTEGER", 0, None, 1, 0),
        (1, "snapshot_hash", "TEXT", 1, None, 0, 0),
        (2, "topology_hash", "TEXT", 1, None, 0, 0),
        (3, "kernel_boot_id", "TEXT", 1, None, 0, 0),
        (4, "key_id", "TEXT", 1, None, 0, 0),
        (5, "captured_at", "TEXT", 1, None, 0, 0),
        (6, "envelope_json", "TEXT", 1, None, 0, 0),
    ),
}
_SQLITE_INDEXES = {
    "metadata": {
        "sqlite_autoindex_metadata_1": (1, "pk", 0, ("key",)),
    },
    "snapshots": {
        "sqlite_autoindex_snapshots_1": (1, "u", 0, ("snapshot_hash",)),
    },
}

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TEXT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")

_HOST_SAFETY_METADATA_KEYS = (
    "acsProvenanceInterfaceComplete",
    "kernelCommandLine",
    "kernelRelease",
    "physicalDomainRule",
    "returnedDeviceCount",
    "scannedDeviceCount",
    "sysfsRoot",
    "uid",
)
_DEVICE_SAFETY_METADATA_KEYS = (
    "acsOverridePath",
    "pcieType",
)


class SnapshotReason(str, Enum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    STORE_NOT_DURABLE = "STORE_NOT_DURABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    STORE_IDENTITY_MISMATCH = "STORE_IDENTITY_MISMATCH"
    HOST_SCOPE_MISMATCH = "HOST_SCOPE_MISMATCH"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    AUTHENTICATOR_SCOPE_MISMATCH = "AUTHENTICATOR_SCOPE_MISMATCH"
    CAPTURE_NOT_FULL_HOST = "CAPTURE_NOT_FULL_HOST"
    CAPTURE_IDENTITY_INCOMPLETE = "CAPTURE_IDENTITY_INCOMPLETE"
    CAPTURE_UNSTABLE = "CAPTURE_UNSTABLE"
    CAPTURE_PROVIDER_MISMATCH = "CAPTURE_PROVIDER_MISMATCH"
    CAPTURE_PROVIDER_UNAVAILABLE = "CAPTURE_PROVIDER_UNAVAILABLE"
    PUBLISH_CONFLICT = "PUBLISH_CONFLICT"
    EPOCH_EXHAUSTED = "EPOCH_EXHAUSTED"
    SNAPSHOT_NOT_FOUND = "SNAPSHOT_NOT_FOUND"
    SNAPSHOT_HASH_MISMATCH = "SNAPSHOT_HASH_MISMATCH"
    SNAPSHOT_SIGNATURE_INVALID = "SNAPSHOT_SIGNATURE_INVALID"
    SNAPSHOT_STALE = "SNAPSHOT_STALE"
    BOOT_ID_CHANGED = "BOOT_ID_CHANGED"
    TOPOLOGY_CHANGED = "TOPOLOGY_CHANGED"
    LAUNCH_FACTS_CHANGED = "LAUNCH_FACTS_CHANGED"
    INCOMPLETE_IOMMU_GROUP = "INCOMPLETE_IOMMU_GROUP"
    AUTHORIZATION_INACTIVE = "AUTHORIZATION_INACTIVE"
    AUTHORIZATION_ACTIVE = "AUTHORIZATION_ACTIVE"
    STORE_TRANSACTION_ACTIVE = "STORE_TRANSACTION_ACTIVE"


class LiveCapturePhase(str, Enum):
    PRE_OPEN = "PRE_OPEN"
    POST_OPEN = "POST_OPEN"
    PRE_SPAWN = "PRE_SPAWN"


class SnapshotError(RuntimeError):
    def __init__(
        self,
        reason: SnapshotReason,
        detail: str = "",
        *,
        phase: LiveCapturePhase | None = None,
    ) -> None:
        self.reason = reason
        self.detail = detail
        self.phase = phase
        message = reason.value if not detail else f"{reason.value}: {detail}"
        super().__init__(message)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "clock must return aware UTC time")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_id(field_name: str, value: object) -> str:
    if not isinstance(value, str) or _TEXT_ID_RE.fullmatch(value) is None:
        raise SnapshotError(
            SnapshotReason.INVALID_ARGUMENT,
            f"{field_name} is not a canonical identifier",
        )
    return value


def _required_hash(field_name: str, value: object) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value.lower()) is None:
        raise SnapshotError(
            SnapshotReason.INVALID_ARGUMENT,
            f"{field_name} is not a lowercase SHA-256 digest",
        )
    return value.lower()


def _strict_json_loads(value: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise SnapshotError(
                    SnapshotReason.SNAPSHOT_HASH_MISMATCH,
                    f"duplicate JSON key {key!r}",
                )
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=reject_duplicates)
    except SnapshotError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SnapshotError(
            SnapshotReason.SNAPSHOT_HASH_MISMATCH,
            f"invalid canonical snapshot JSON: {error}",
        ) from error


class ComponentHmacAuthenticator:
    """Separate-domain HMAC authenticator for component verification only."""

    algorithm = AUTHENTICATION_ALGORITHM
    trust_boundary = SNAPSHOT_TRUST_BOUNDARY

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        normalized: dict[str, bytes] = {}
        if not isinstance(keys, Mapping) or not keys:
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "at least one key is required")
        for key_id, secret in keys.items():
            if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
                raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "invalid key_id")
            if not isinstance(secret, bytes) or len(secret) < 32:
                raise SnapshotError(
                    SnapshotReason.INVALID_ARGUMENT,
                    f"key {key_id!r} must contain at least 256 bits",
                )
            normalized[key_id] = bytes(secret)
        self._keys = MappingProxyType(normalized)

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def trust_root_digest(self, key_id: str) -> str:
        secret = self._key(key_id)
        return _sha256(b"qman.snapshot.component-hmac-key.v1\x00" + secret)

    def sign(self, key_id: str, payload: bytes) -> str:
        return hmac.new(self._key(key_id), payload, hashlib.sha256).hexdigest()

    def verify(self, key_id: str, payload: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or _HASH_RE.fullmatch(signature) is None:
            return False
        try:
            expected = self.sign(key_id, payload)
        except SnapshotError:
            return False
        return hmac.compare_digest(expected, signature)

    def _key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except (KeyError, TypeError) as error:
            raise SnapshotError(
                SnapshotReason.AUTHENTICATOR_SCOPE_MISMATCH,
                f"unknown snapshot key {key_id!r}",
            ) from error


@dataclass(frozen=True)
class LaunchDeviceFacts:
    bdf: str
    identity: vfio.PciIdentity
    iommu_group: str
    group_members: tuple[str, ...]
    device_generation: int = 0

    def __post_init__(self) -> None:
        bdf = self.bdf.lower() if isinstance(self.bdf, str) else ""
        if vfio.BDF_RE.fullmatch(bdf) is None:
            raise SnapshotError(SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE, "invalid launch BDF")
        if not isinstance(self.identity, vfio.PciIdentity):
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} exact PCI identity is missing",
            )
        widths = (
            (self.identity.vendor_id, 0xFFFF),
            (self.identity.device_id, 0xFFFF),
            (self.identity.subsystem_vendor_id, 0xFFFF),
            (self.identity.subsystem_device_id, 0xFFFF),
            (self.identity.class_code, 0xFFFFFF),
            (self.identity.revision, 0xFF),
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= maximum
            for value, maximum in widths
        ):
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} exact PCI identity is invalid",
            )
        if not isinstance(self.iommu_group, str) or vfio.GROUP_RE.fullmatch(
            self.iommu_group
        ) is None:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} IOMMU group ID is invalid",
            )
        members = tuple(member.lower() for member in self.group_members)
        if (
            not members
            or members != tuple(sorted(set(members)))
            or bdf not in members
            or any(vfio.BDF_RE.fullmatch(member) is None for member in members)
        ):
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} IOMMU group members are incomplete",
            )
        if (
            isinstance(self.device_generation, bool)
            or not isinstance(self.device_generation, int)
            or not 0 <= self.device_generation <= (1 << 63) - 1
        ):
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} device generation is invalid",
            )
        object.__setattr__(self, "bdf", bdf)
        object.__setattr__(self, "group_members", members)

    @property
    def identity_hash(self) -> str:
        return vfio.compute_identity_hash(self.bdf, self.identity)

    @property
    def group_hash(self) -> str:
        return vfio.compute_group_hash(self.bdf, self.iommu_group, self.group_members)

    def to_json(self) -> dict[str, Any]:
        return {
            "bdf": self.bdf,
            "deviceGeneration": self.device_generation,
            "groupHash": self.group_hash,
            "groupMembers": list(self.group_members),
            "identity": self.identity.to_json(),
            "identityHash": self.identity_hash,
            "iommuGroup": self.iommu_group,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "LaunchDeviceFacts":
        if not isinstance(value, Mapping):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "launch fact is not an object")
        identity_value = value.get("identity")
        if not isinstance(identity_value, Mapping):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "launch identity is absent")
        try:
            identity = vfio.PciIdentity(
                vendor_id=int(str(identity_value["vendorId"]), 0),
                device_id=int(str(identity_value["deviceId"]), 0),
                subsystem_vendor_id=int(str(identity_value["subsystemVendorId"]), 0),
                subsystem_device_id=int(str(identity_value["subsystemDeviceId"]), 0),
                class_code=int(str(identity_value["classCode"]), 0),
                revision=int(str(identity_value["revision"]), 0),
            )
            fact = cls(
                bdf=str(value["bdf"]),
                identity=identity,
                iommu_group=str(value["iommuGroup"]),
                group_members=tuple(value["groupMembers"]),
                device_generation=int(value.get("deviceGeneration", 0)),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SnapshotError(
                SnapshotReason.SNAPSHOT_HASH_MISMATCH,
                f"invalid launch fact: {error}",
            ) from error
        if not hmac.compare_digest(fact.identity_hash, str(value.get("identityHash", ""))):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "identity hash mismatch")
        if not hmac.compare_digest(fact.group_hash, str(value.get("groupHash", ""))):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "group hash mismatch")
        return fact


@dataclass(frozen=True)
class SnapshotCapture:
    inventory: HostInventory
    launch_facts: Mapping[str, LaunchDeviceFacts]
    scope: str = FULL_HOST_SCOPE

    def __post_init__(self) -> None:
        if not isinstance(self.inventory, HostInventory):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "inventory must be HostInventory")
        if self.scope != FULL_HOST_SCOPE:
            raise SnapshotError(SnapshotReason.CAPTURE_NOT_FULL_HOST, "capture scope is not FULL_HOST")
        normalized: dict[str, LaunchDeviceFacts] = {}
        if not isinstance(self.launch_facts, Mapping):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "launch_facts must be a mapping")
        for raw_bdf, fact in self.launch_facts.items():
            if not isinstance(fact, LaunchDeviceFacts):
                raise SnapshotError(
                    SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                    f"launch fact {raw_bdf!r} has an invalid type",
                )
            bdf = str(raw_bdf).lower()
            if bdf != fact.bdf or bdf not in self.inventory.devices or bdf in normalized:
                raise SnapshotError(
                    SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                    f"launch fact key {raw_bdf!r} is not an exact inventory member",
                )
            normalized[bdf] = fact
        object.__setattr__(self, "launch_facts", MappingProxyType(normalized))

    def to_json(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory.to_dict(),
            "launchFacts": {
                bdf: self.launch_facts[bdf].to_json() for bdf in sorted(self.launch_facts)
            },
            "scope": self.scope,
        }


def _validate_raw_capture(capture: SnapshotCapture, *, local_host_id: str) -> None:
    if not isinstance(capture, SnapshotCapture):
        raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "capture_fn returned an invalid object")
    inventory = capture.inventory
    if inventory.host_id != local_host_id:
        raise SnapshotError(
            SnapshotReason.HOST_SCOPE_MISMATCH,
            f"capture={inventory.host_id!r}, store={local_host_id!r}",
        )
    if inventory.kernel_boot_id in {"", "unknown"}:
        raise SnapshotError(SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE, "kernel boot ID is unknown")
    if inventory.inventory_epoch is not None:
        raise SnapshotError(
            SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
            "raw capture must not choose inventoryEpoch",
        )
    metadata = inventory.metadata
    scanned = metadata.get("scannedDeviceCount")
    returned = metadata.get("returnedDeviceCount")
    if (
        isinstance(scanned, bool)
        or not isinstance(scanned, int)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or scanned != returned
        or returned != len(inventory.devices)
    ):
        raise SnapshotError(
            SnapshotReason.CAPTURE_NOT_FULL_HOST,
            "scanned/returned inventory counts do not prove a full-host capture",
        )
    _validate_launch_fact_consistency(capture)


def _validate_launch_fact_consistency(capture: SnapshotCapture) -> None:
    """Cross-bind launch facts to the decision inventory for the same BDF."""

    for bdf, fact in capture.launch_facts.items():
        device = capture.inventory.devices[bdf]
        mismatches: list[str] = []
        if fact.identity.vendor_id != device.vendor_id:
            mismatches.append("vendorId")
        if fact.identity.device_id != device.device_id:
            mismatches.append("deviceId")
        if fact.identity.class_code != device.class_code:
            mismatches.append("classCode")
        if fact.group_members != device.iommu_group:
            mismatches.append("groupMembers")
        if fact.device_generation != device.device_generation:
            mismatches.append("deviceGeneration")
        if mismatches:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"{bdf} launch facts disagree with inventory: {','.join(mismatches)}",
            )


def _fact_evidence_preimage(value: FactEvidence | None) -> dict[str, Any] | None:
    if value is None:
        return None
    # These are provider-issued input coordinates, not this snapshot's output
    # epoch/hash.  They must remain in the preimage so a stale reset,
    # qualification, or dependency fact cannot survive live revalidation.
    # Reuse the model's complete canonical representation rather than keeping
    # a second field allowlist here: a future decision-fact field must not be
    # silently omitted from the signed topology preimage.
    return value.to_dict()


def _safety_metadata_preimage(
    metadata: Mapping[str, Any], keys: Sequence[str]
) -> dict[str, Any]:
    # Arbitrary collector/debug metadata is intentionally excluded.  These
    # allowlisted values establish how the safety topology was collected or
    # are direct inputs to isolation/qualification decisions.
    return {key: metadata.get(key) for key in keys}


def _full_topology_preimage(capture: SnapshotCapture) -> dict[str, Any]:
    devices: list[dict[str, Any]] = []
    for bdf, device in sorted(capture.inventory.devices.items()):
        launch = capture.launch_facts.get(bdf)
        devices.append(
            {
                "acs": None if device.acs is None else device.acs.to_dict(),
                "acsEffectiveIsolation": device.acs_effective_isolation,
                "acsNativeIsolation": device.acs_native_isolation,
                "acsOverrideSource": device.acs_override_source,
                "barRequirements": [
                    {
                        "address": bar.address,
                        "below1m": bar.below_1m,
                        "bdf": bar.bdf.lower(),
                        "index": bar.index,
                        "is64": bar.is_64,
                        "prefetchable": bar.prefetchable,
                        "size": bar.size,
                        "source": bar.source,
                        "space": bar.space.value,
                    }
                    for bar in device.bars
                ],
                "bdf": bdf,
                "classCode": device.class_code,
                "dependencyAction": device.dependency_action.value,
                "dependencyActionFact": _fact_evidence_preimage(
                    device.dependency_action_fact
                ),
                "decisionMetadata": _safety_metadata_preimage(
                    device.metadata, _DEVICE_SAFETY_METADATA_KEYS
                ),
                "deviceId": device.device_id,
                "deviceGeneration": device.device_generation,
                "dmaIsolationMode": device.dma_isolation_mode.value,
                "dmaIsolationSource": device.dma_isolation_source,
                "driver": device.driver,
                "errataDenied": device.errata_denied,
                "exclusiveAttachGroup": device.exclusive_attach_group,
                "functionRole": device.function_role.value,
                "headerType": device.header_type,
                "hostReservation": device.host_reservation,
                "isolationProvenance": device.isolation_provenance.value,
                "kernelIommuGroup": list(device.iommu_group),
                "launchFacts": None if launch is None else launch.to_json(),
                "multifunctionAliases": list(device.multifunction_aliases),
                "multifunctionSource": device.multifunction_source,
                "ownerActivationGroup": device.owner_activation_group,
                "parent": device.parent,
                "physicalIsolationDomain": list(device.physical_isolation_domain),
                "physicalIsolationDomainSource": device.physical_isolation_domain_source,
                "platformDependencies": list(device.platform_dependencies),
                "platformDependencySource": device.platform_dependency_source,
                "platformReserved": device.platform_reserved,
                "qualificationFact": _fact_evidence_preimage(
                    device.qualification_fact
                ),
                "qualifiedActions": [
                    action.value for action in device.qualified_actions
                ],
                "resetDomain": list(device.reset_domain),
                "resetDomainSource": device.reset_domain_source,
                "resetContractFact": _fact_evidence_preimage(
                    device.reset_contract_fact
                ),
                "resetMethods": list(device.reset_methods),
                "rmrrConflict": device.rmrr_conflict,
                "vendorId": device.vendor_id,
            }
        )
    return {
        "hostSafetyFacts": {
            "acsOverrideActive": capture.inventory.acs_override_active,
            "captureProvenance": _safety_metadata_preimage(
                capture.inventory.metadata, _HOST_SAFETY_METADATA_KEYS
            ),
            "interruptRemapping": capture.inventory.interrupt_remapping,
            "iommuPresent": capture.inventory.iommu_present,
            "source": capture.inventory.source,
            "unsafeNoIommuModeEnabled": capture.inventory.no_iommu_mode,
        },
        "kind": "qman-full-host-safety-topology-v1",
        "devices": devices,
    }


def compute_full_topology_hash(capture: SnapshotCapture) -> str:
    return _sha256(_canonical_json_bytes(_full_topology_preimage(capture)))


def capture_linux_full_snapshot(
    *,
    sysfs_root: Path = Path("/sys/bus/pci/devices"),
    proc_cmdline: Path = Path("/proc/cmdline"),
    interrupt_remapping: bool | None = None,
    vfio_root: Path = Path("/dev/vfio"),
    machine_id_path: Path = Path("/etc/machine-id"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
) -> SnapshotCapture:
    """Capture a full scanner inventory plus exact launch identity/group facts.

    Devices without an operational IOMMU group remain in the full inventory but
    intentionally receive no ``LaunchDeviceFacts`` and therefore cannot obtain
    a launch authorization.  This function is still a component collector: a
    product publisher must add a real topology-generation source and durable
    device-generation provider rather than treating the double scan as a kernel
    atomic-snapshot ABI.
    """

    from .linux_sysfs import scan_linux_sysfs

    inventory = scan_linux_sysfs(
        sysfs_root=sysfs_root,
        proc_cmdline=proc_cmdline,
        interrupt_remapping=interrupt_remapping,
        selected_bdfs=None,
        vfio_root=vfio_root,
        machine_id_path=machine_id_path,
        boot_id_path=boot_id_path,
        inventory_epoch=None,
    )
    facts: dict[str, LaunchDeviceFacts] = {}

    def required_hex(path: Path, bdf: str) -> int:
        try:
            text = path.read_text(encoding="ascii").strip()
            return int(text, 0)
        except (OSError, UnicodeError, ValueError) as error:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"cannot read exact identity for {bdf}: {path.name}",
            ) from error

    for bdf in sorted(inventory.devices):
        link = sysfs_root / bdf
        try:
            device_path = link.resolve(strict=True)
        except OSError as error:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"cannot resolve {bdf}",
            ) from error
        if device_path.name.lower() != bdf:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"sysfs target changed for {bdf}",
            )
        group_link = device_path / "iommu_group"
        try:
            group_path = group_link.resolve(strict=True)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"cannot resolve IOMMU group for {bdf}",
            ) from error
        group_id = group_path.name
        if vfio.GROUP_RE.fullmatch(group_id) is None:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"invalid IOMMU group ID for {bdf}",
            )
        try:
            members = tuple(
                sorted(entry.name.lower() for entry in (group_path / "devices").iterdir())
            )
        except OSError as error:
            raise SnapshotError(
                SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                f"cannot read IOMMU group members for {bdf}",
            ) from error
        if any(member not in inventory.devices for member in members):
            raise SnapshotError(
                SnapshotReason.CAPTURE_NOT_FULL_HOST,
                f"IOMMU group for {bdf} references a device outside inventory",
            )
        facts[bdf] = LaunchDeviceFacts(
            bdf=bdf,
            identity=vfio.PciIdentity(
                vendor_id=required_hex(device_path / "vendor", bdf),
                device_id=required_hex(device_path / "device", bdf),
                subsystem_vendor_id=required_hex(
                    device_path / "subsystem_vendor", bdf
                ),
                subsystem_device_id=required_hex(
                    device_path / "subsystem_device", bdf
                ),
                class_code=required_hex(device_path / "class", bdf),
                revision=required_hex(device_path / "revision", bdf),
            ),
            iommu_group=group_id,
            group_members=members,
            # A product generation provider is deliberately not invented here.
            device_generation=0,
        )
    return SnapshotCapture(inventory=inventory, launch_facts=facts)


def _capture_stability_bytes(capture: SnapshotCapture) -> bytes:
    return _canonical_json_bytes(capture.to_json())


@dataclass(frozen=True)
class SignedSnapshotEnvelope:
    authority_id: str
    store_instance_id: str
    key_id: str
    trust_root_digest: str
    host_id: str
    kernel_boot_id: str
    inventory_epoch: int
    captured_at: str
    topology_hash: str
    snapshot_hash: str
    capture: SnapshotCapture
    signature: str
    schema_version: int = SCHEMA_VERSION
    kind: str = SNAPSHOT_KIND
    algorithm: str = AUTHENTICATION_ALGORITHM
    trust_boundary: str = SNAPSHOT_TRUST_BOUNDARY

    def unsigned_json(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "authorityId": self.authority_id,
            "capture": self.capture.to_json(),
            "capturedAt": self.captured_at,
            "hostId": self.host_id,
            "inventoryEpoch": self.inventory_epoch,
            "kernelBootId": self.kernel_boot_id,
            "keyId": self.key_id,
            "kind": self.kind,
            "schemaVersion": self.schema_version,
            "storeInstanceId": self.store_instance_id,
            "topologyHash": self.topology_hash,
            "trustBoundary": self.trust_boundary,
            "trustRootDigest": self.trust_root_digest,
        }

    def to_json(self) -> dict[str, Any]:
        return {
            **self.unsigned_json(),
            "signature": self.signature,
            "snapshotHash": self.snapshot_hash,
        }


@dataclass(frozen=True)
class SnapshotRecord:
    envelope: SignedSnapshotEnvelope

    @property
    def inventory_epoch(self) -> int:
        return self.envelope.inventory_epoch

    @property
    def snapshot_hash(self) -> str:
        return self.envelope.snapshot_hash

    @property
    def topology_hash(self) -> str:
        return self.envelope.topology_hash

    @property
    def inventory(self) -> HostInventory:
        # Reparse a defensive copy so mutations of nested metadata never alter
        # the authenticated in-memory record.
        return HostInventory.from_dict(self.envelope.capture.inventory.to_dict())


@dataclass
class _AuthorizationGuard:
    active: bool = True


_AUTHORIZATION_PROVENANCE = object()
_CAPTURE_PROVIDER_PROVENANCE = object()


@dataclass(frozen=True, init=False)
class _CaptureProviderCapability:
    """Process-local capability sealing the publisher's exact capture callable.

    This is deliberately not serialized into SQLite.  Reopening the store in a
    new process therefore requires a fresh publication before launch can be
    authorized; accepting a launch-side replacement callback would turn a
    cached capture into false live evidence.

    The publisher callable (like ``current_boot_id``) is itself inside this
    component's authority boundary.  Exact capability identity prevents a
    launch caller from substituting another callback; it does not turn a
    mutable or test-injected publisher into a production trust root.
    """

    binding_hash: str
    snapshot_hash: str
    _capture_fn: Callable[[], SnapshotCapture] = field(repr=False, compare=False)
    _provenance: object = field(repr=False, compare=False)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("capture provider capabilities are issued only by the store")

    def capture(self) -> SnapshotCapture:
        if (
            type(self) is not _CaptureProviderCapability
            or getattr(self, "_provenance", None) is not _CAPTURE_PROVIDER_PROVENANCE
            or not callable(getattr(self, "_capture_fn", None))
        ):
            raise SnapshotError(SnapshotReason.CAPTURE_PROVIDER_UNAVAILABLE)
        return self._capture_fn()

    def matches(self, capture_fn: object) -> bool:
        return capture_fn is self._capture_fn


def _new_capture_provider_capability(
    capture_fn: Callable[[], SnapshotCapture],
    *,
    authority_id: str,
    host_id: str,
    snapshot_hash: str,
    store_instance_id: str,
) -> _CaptureProviderCapability:
    nonce = uuid.uuid4().hex
    binding_hash = _sha256(
        _canonical_json_bytes(
            {
                "authorityId": authority_id,
                "capabilityNonce": nonce,
                "domain": "qman.snapshot.capture-provider-capability.v1",
                "hostId": host_id,
                "snapshotHash": snapshot_hash,
                "storeInstanceId": store_instance_id,
            }
        )
    )
    capability = object.__new__(_CaptureProviderCapability)
    object.__setattr__(capability, "binding_hash", binding_hash)
    object.__setattr__(capability, "snapshot_hash", snapshot_hash)
    object.__setattr__(capability, "_capture_fn", capture_fn)
    object.__setattr__(capability, "_provenance", _CAPTURE_PROVIDER_PROVENANCE)
    return capability


@dataclass(frozen=True, init=False)
class SnapshotLaunchAuthorization:
    host_id: str
    kernel_boot_id: str
    inventory_epoch: int
    topology_hash: str
    snapshot_hash: str
    authority_id: str
    store_instance_id: str
    key_id: str
    capture_provider_boundary: str
    capture_provider_binding_hash: str
    binding_hash: str
    authorized_bdfs: tuple[str, ...]
    launch_facts: Mapping[str, LaunchDeviceFacts]
    _store: "AuthoritativeSnapshotStore" = field(repr=False, compare=False)
    _guard: _AuthorizationGuard = field(repr=False, compare=False)
    _capture_provider: _CaptureProviderCapability = field(repr=False, compare=False)
    _provenance: object = field(repr=False, compare=False)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("SnapshotLaunchAuthorization is issued only by AuthoritativeSnapshotStore")

    @property
    def is_active(self) -> bool:
        return (
            type(self) is SnapshotLaunchAuthorization
            and getattr(self, "_provenance", None) is _AUTHORIZATION_PROVENANCE
            and isinstance(getattr(self, "_guard", None), _AuthorizationGuard)
            and type(getattr(self, "_capture_provider", None))
            is _CaptureProviderCapability
            and self._guard.active
        )

    def require_current(self) -> None:
        if not self.is_active:
            raise SnapshotError(SnapshotReason.AUTHORIZATION_INACTIVE)
        self._store._require_active_authorization(self)

    def _require_bound_capture_provider(self, capture_fn: object | None = None) -> None:
        """Reject a launch-side callback that is not the publishing capability.

        ``capture_fn`` exists only as a transition witness for callers using
        the old opener signature.  Live validation itself never invokes it.
        """

        self.require_current()
        provider = self._capture_provider
        if capture_fn is not None and not provider.matches(capture_fn):
            raise SnapshotError(
                SnapshotReason.CAPTURE_PROVIDER_MISMATCH,
                "launch caller cannot replace the snapshot publisher's capture provider",
            )

    def revalidate_live(self, phase: LiveCapturePhase) -> None:
        self.require_current()
        if not isinstance(phase, LiveCapturePhase):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "invalid live capture phase")
        try:
            capture = self._capture_provider.capture()
            _validate_raw_capture(capture, local_host_id=self.host_id)
        except SnapshotError as error:
            if error.phase is None:
                error.phase = phase
            raise
        if capture.inventory.kernel_boot_id != self.kernel_boot_id:
            raise SnapshotError(
                SnapshotReason.BOOT_ID_CHANGED,
                "live kernel boot ID differs from authorized snapshot",
                phase=phase,
            )
        live_topology = compute_full_topology_hash(capture)
        if not hmac.compare_digest(live_topology, self.topology_hash):
            raise SnapshotError(
                SnapshotReason.TOPOLOGY_CHANGED,
                "live full-host safety topology differs from authorized snapshot",
                phase=phase,
            )
        for bdf in self.authorized_bdfs:
            observed = capture.launch_facts.get(bdf)
            expected = self.launch_facts[bdf]
            if observed is None or observed.to_json() != expected.to_json():
                raise SnapshotError(
                    SnapshotReason.LAUNCH_FACTS_CHANGED,
                    f"live launch facts changed for {bdf}",
                    phase=phase,
                )
        self.require_current()

    def __copy__(self) -> "SnapshotLaunchAuthorization":
        raise TypeError("snapshot authorization capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> "SnapshotLaunchAuthorization":
        del memo
        raise TypeError("snapshot authorization capabilities cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("snapshot authorization capabilities cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("snapshot authorization capabilities cannot be pickled")


def validate_launch_authorization(value: object) -> SnapshotLaunchAuthorization:
    if type(value) is not SnapshotLaunchAuthorization:
        raise SnapshotError(SnapshotReason.AUTHORIZATION_INACTIVE, "exact authorization type required")
    value.require_current()
    return value


class AuthoritativeSnapshotStore:
    """Host-local SQLite snapshot authority with a sealed launch read guard."""

    def __init__(
        self,
        path: str | Path,
        *,
        local_host_id: str,
        trusted_authority_id: str,
        authenticator: ComponentHmacAuthenticator,
        current_boot_id: Callable[[], str] | None = None,
        allow_unverified_filesystem_for_lab: bool = False,
        timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        raw_path = str(path)
        if raw_path == ":memory:" or raw_path.startswith("file:"):
            raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, "filesystem DB required")
        candidate = Path(path)
        if not candidate.is_absolute():
            raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, "database path must be absolute")
        if candidate.is_symlink():
            raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, "database path must not be symlink")
        self.path = candidate.resolve()
        if not self.path.parent.is_dir() or self.path.parent.is_symlink():
            raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, "database parent is unavailable")
        if self.path.exists() and not stat.S_ISREG(self.path.stat().st_mode):
            raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, "database is not a regular file")
        self.local_host_id = _required_id("local_host_id", local_host_id)
        self.trusted_authority_id = _required_id(
            "trusted_authority_id", trusted_authority_id
        )
        if type(authenticator) is not ComponentHmacAuthenticator:
            raise SnapshotError(
                SnapshotReason.AUTHENTICATOR_SCOPE_MISMATCH,
                "exact ComponentHmacAuthenticator required for this component store",
            )
        self.authenticator = authenticator
        self._current_boot_id = current_boot_id or self._read_current_boot_id
        self._clock = clock or _utc_now
        self._fault_hook = fault_hook
        self._timeout_seconds = timeout_seconds
        self._lock = threading.RLock()
        self._transaction_state_lock = threading.Lock()
        self._transaction_owner: int | None = None
        self._transaction_kind: str | None = None
        self._active_authorization: SnapshotLaunchAuthorization | None = None
        self._current_capture_provider: _CaptureProviderCapability | None = None
        self.persistence_boundary = self._verify_filesystem_provenance(
            self.path, allow_unverified_filesystem_for_lab
        )
        try:
            self._connection = sqlite3.connect(
                self.path,
                timeout=timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            mode = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, f"journal_mode={mode}")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute(
                "PRAGMA busy_timeout=%d" % max(0, int(timeout_seconds * 1000))
            )
            self._initialize_schema()
        except SnapshotError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.Error as error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, str(error)) from error

    @staticmethod
    def _read_current_boot_id() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError:
            return "unknown"

    @staticmethod
    def _linux_filesystem_magic(path: Path) -> int:
        import ctypes

        buffer = ctypes.create_string_buffer(512)
        libc = ctypes.CDLL(None, use_errno=True)
        statfs = libc.statfs
        statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        statfs.restype = ctypes.c_int
        if statfs(os.fsencode(path), ctypes.byref(buffer)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(path))
        bits = ctypes.sizeof(ctypes.c_long) * 8
        return int(ctypes.c_long.from_buffer(buffer).value) & ((1 << bits) - 1)

    @classmethod
    def _verify_filesystem_provenance(cls, path: Path, allow_lab: bool) -> str:
        verified = False
        detail = "unknown platform filesystem"
        if sys.platform.startswith("linux"):
            try:
                magic = cls._linux_filesystem_magic(path.parent)
            except OSError as error:
                detail = f"statfs failed: {error}"
            else:
                local_magics = {
                    0xEF53,
                    0x58465342,
                    0x9123683E,
                    0xF2F52010,
                    0x2FC12FC1,
                    0x5346544E,
                }
                unsafe_magics = {
                    0x01021994,
                    0x858458F6,
                    0x01021997,
                    0x65735546,
                    0x6969,
                    0xFF534D42,
                    0xFE534D42,
                    0x794C7630,
                }
                verified = magic in local_magics
                detail = (
                    f"filesystem magic 0x{magic:x} is unsafe/non-local"
                    if magic in unsafe_magics
                    else f"filesystem magic 0x{magic:x} is not allowlisted"
                )
        elif os.name == "nt":
            try:
                import ctypes

                drive_type = ctypes.windll.kernel32.GetDriveTypeW(path.anchor)
                verified = drive_type == 3 and not str(path).startswith("\\\\")
                detail = f"Windows drive type {drive_type} is not fixed-local"
            except (AttributeError, OSError) as error:
                detail = f"Windows drive provenance failed: {error}"
        if verified:
            return "LOCAL_FILESYSTEM_COMPONENT_PERSISTENCE_ONLY"
        if allow_lab is True:
            return "LAB_UNVERIFIED_FILESYSTEM_COMPONENT_PERSISTENCE_ONLY"
        raise SnapshotError(SnapshotReason.STORE_NOT_DURABLE, detail)

    def _claim_transaction(self, kind: str) -> None:
        owner = threading.get_ident()
        with self._transaction_state_lock:
            if self._transaction_kind is not None:
                reason = (
                    SnapshotReason.AUTHORIZATION_ACTIVE
                    if self._transaction_kind == "LAUNCH_AUTHORIZATION"
                    else SnapshotReason.STORE_TRANSACTION_ACTIVE
                )
                raise SnapshotError(
                    reason,
                    f"{self._transaction_kind} owned by thread {self._transaction_owner}",
                )
            self._transaction_owner = owner
            self._transaction_kind = kind

    def _release_transaction(self, kind: str) -> None:
        with self._transaction_state_lock:
            if (
                self._transaction_kind != kind
                or self._transaction_owner != threading.get_ident()
            ):
                raise RuntimeError("snapshot store transaction ownership invariant violated")
            self._transaction_owner = None
            self._transaction_kind = None

    @contextmanager
    def _transaction_ownership(self, kind: str) -> Iterator[None]:
        self._claim_transaction(kind)
        try:
            yield
        finally:
            self._release_transaction(kind)

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _initialize_schema(self) -> None:
        with self._transaction_ownership("SCHEMA_INIT"), self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                for statement in _SQLITE_SCHEMA.split(";"):
                    if statement.strip():
                        self._connection.execute(statement)
                self._validate_sqlite_schema()
                info = self.path.stat()
                expected = {
                    "schema_version",
                    "local_host_id",
                    "trusted_authority_id",
                    "store_instance_id",
                    "database_path",
                    "database_device",
                    "database_inode",
                    "authenticator_algorithm",
                    "authenticator_trust_boundary",
                    "authenticator_key_ids",
                }
                rows = self._connection.execute("SELECT key,value FROM metadata").fetchall()
                metadata = {str(row["key"]): str(row["value"]) for row in rows}
                if not metadata:
                    store_instance = str(uuid.uuid4())
                    metadata = {
                        "schema_version": str(SCHEMA_VERSION),
                        "local_host_id": self.local_host_id,
                        "trusted_authority_id": self.trusted_authority_id,
                        "store_instance_id": store_instance,
                        "database_path": str(self.path),
                        "database_device": str(info.st_dev),
                        "database_inode": str(info.st_ino),
                        "authenticator_algorithm": self.authenticator.algorithm,
                        "authenticator_trust_boundary": self.authenticator.trust_boundary,
                        "authenticator_key_ids": json.dumps(self.authenticator.key_ids),
                    }
                    self._connection.executemany(
                        "INSERT INTO metadata(key,value) VALUES(?,?)", metadata.items()
                    )
                    self._fault("SCHEMA_BEFORE_COMMIT")
                elif set(metadata) != expected:
                    raise SnapshotError(
                        SnapshotReason.STORE_UNAVAILABLE,
                        "metadata key set differs from fixed schema",
                    )
                self._validate_metadata(metadata, info)
                self._connection.execute("COMMIT")
                self.store_instance_id = metadata["store_instance_id"]
                self._database_identity = (info.st_dev, info.st_ino)
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _validate_sqlite_schema(self) -> None:
        """Reject persistent or TEMP objects that can alter authority semantics."""

        objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in self._connection.execute(
                "SELECT type,name,tbl_name FROM sqlite_master"
            ).fetchall()
        }
        if objects != _SQLITE_OBJECTS:
            raise SnapshotError(
                SnapshotReason.STORE_UNAVAILABLE,
                "SQLite authority object set differs from fixed schema",
            )
        temporary = self._connection.execute(
            "SELECT type,name FROM sqlite_temp_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        if temporary:
            raise SnapshotError(
                SnapshotReason.STORE_UNAVAILABLE,
                "SQLite TEMP schema must contain no user objects",
            )
        for table, expected in _SQLITE_TABLE_COLUMNS.items():
            observed = tuple(
                tuple(row)
                for row in self._connection.execute(
                    f"PRAGMA table_xinfo({table})"
                ).fetchall()
            )
            if observed != expected:
                raise SnapshotError(
                    SnapshotReason.STORE_UNAVAILABLE,
                    f"SQLite table shape changed for {table}",
                )
        for table, expected_indexes in _SQLITE_INDEXES.items():
            observed_rows = self._connection.execute(
                f"PRAGMA index_list({table})"
            ).fetchall()
            observed_indexes = {
                str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
                for row in observed_rows
            }
            expected_summary = {
                name: values[:3] for name, values in expected_indexes.items()
            }
            if observed_indexes != expected_summary:
                raise SnapshotError(
                    SnapshotReason.STORE_UNAVAILABLE,
                    f"SQLite index set changed for {table}",
                )
            for index_name, (*_, expected_columns) in expected_indexes.items():
                observed_columns = tuple(
                    str(row[2])
                    for row in self._connection.execute(
                        f"PRAGMA index_info('{index_name}')"
                    ).fetchall()
                )
                if observed_columns != expected_columns:
                    raise SnapshotError(
                        SnapshotReason.STORE_UNAVAILABLE,
                        f"SQLite index target changed for {index_name}",
                    )

    def _validate_metadata(self, metadata: Mapping[str, str], info: os.stat_result) -> None:
        if metadata.get("schema_version") != str(SCHEMA_VERSION):
            raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, "schema version mismatch")
        if metadata.get("local_host_id") != self.local_host_id:
            raise SnapshotError(SnapshotReason.HOST_SCOPE_MISMATCH)
        if metadata.get("trusted_authority_id") != self.trusted_authority_id:
            raise SnapshotError(SnapshotReason.AUTHORITY_SCOPE_MISMATCH)
        if metadata.get("database_path") != str(self.path):
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, "database path changed")
        if metadata.get("database_device") != str(info.st_dev) or metadata.get(
            "database_inode"
        ) != str(info.st_ino):
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, "database inode changed")
        if metadata.get("authenticator_algorithm") != self.authenticator.algorithm:
            raise SnapshotError(SnapshotReason.AUTHENTICATOR_SCOPE_MISMATCH)
        if metadata.get("authenticator_trust_boundary") != self.authenticator.trust_boundary:
            raise SnapshotError(SnapshotReason.AUTHENTICATOR_SCOPE_MISMATCH)
        if metadata.get("authenticator_key_ids") != json.dumps(self.authenticator.key_ids):
            raise SnapshotError(SnapshotReason.AUTHENTICATOR_SCOPE_MISMATCH, "key set changed")
        try:
            parsed = uuid.UUID(str(metadata.get("store_instance_id")))
        except (TypeError, ValueError, AttributeError) as error:
            raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, "invalid store UUID") from error
        if parsed.version != 4 or str(parsed) != metadata.get("store_instance_id"):
            raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, "store UUID is not UUIDv4")

    def _require_live_store(self) -> None:
        try:
            link = self.path.lstat()
            info = self.path.stat()
        except OSError as error:
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, str(error)) from error
        if stat.S_ISLNK(link.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, "database type changed")
        if (info.st_dev, info.st_ino) != self._database_identity:
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, "database was replaced")
        self._validate_sqlite_schema()
        rows = self._connection.execute("SELECT key,value FROM metadata").fetchall()
        metadata = {str(row["key"]): str(row["value"]) for row in rows}
        self._validate_metadata(metadata, info)
        if metadata["store_instance_id"] != self.store_instance_id:
            raise SnapshotError(SnapshotReason.STORE_IDENTITY_MISMATCH, "store UUID changed")

    def close(self) -> None:
        self._claim_transaction("CLOSE")
        try:
            with self._lock:
                self._connection.close()
        finally:
            self._release_transaction("CLOSE")

    def __enter__(self) -> "AuthoritativeSnapshotStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.close()
        return False

    def capture_and_publish(
        self,
        capture_fn: Callable[[], SnapshotCapture],
        *,
        key_id: str,
        expected_current_hash: str | None,
    ) -> SnapshotRecord:
        if not callable(capture_fn):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "capture_fn must be callable")
        first = capture_fn()
        second = capture_fn()
        _validate_raw_capture(first, local_host_id=self.local_host_id)
        _validate_raw_capture(second, local_host_id=self.local_host_id)
        if not hmac.compare_digest(
            _capture_stability_bytes(first), _capture_stability_bytes(second)
        ):
            raise SnapshotError(
                SnapshotReason.CAPTURE_UNSTABLE,
                "the two complete capture passes differ",
            )
        current_boot = self._current_boot_id()
        if second.inventory.kernel_boot_id != current_boot:
            raise SnapshotError(
                SnapshotReason.BOOT_ID_CHANGED,
                "capture boot ID differs from the publisher's current kernel boot",
            )
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "invalid key_id")
        self.authenticator.trust_root_digest(key_id)
        if expected_current_hash is not None:
            expected_current_hash = _required_hash(
                "expected_current_hash", expected_current_hash
            )

        with self._transaction_ownership("PUBLISH"), self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._require_live_store()
                latest = self._connection.execute(
                    "SELECT inventory_epoch,snapshot_hash FROM snapshots "
                    "ORDER BY inventory_epoch DESC LIMIT 1"
                ).fetchone()
                current_hash = None if latest is None else str(latest["snapshot_hash"])
                if current_hash != expected_current_hash:
                    raise SnapshotError(
                        SnapshotReason.PUBLISH_CONFLICT,
                        f"expected={expected_current_hash!r}, current={current_hash!r}",
                    )
                epoch = 1 if latest is None else int(latest["inventory_epoch"]) + 1
                if epoch > (1 << 63) - 1:
                    raise SnapshotError(SnapshotReason.EPOCH_EXHAUSTED)
                topology_hash = compute_full_topology_hash(second)
                published_inventory = replace(
                    second.inventory,
                    inventory_epoch=epoch,
                    topology_hash=topology_hash,
                )
                published_capture = SnapshotCapture(
                    inventory=published_inventory,
                    launch_facts=second.launch_facts,
                )
                captured_at = _timestamp(self._clock())
                unsigned = {
                    "algorithm": self.authenticator.algorithm,
                    "authorityId": self.trusted_authority_id,
                    "capture": published_capture.to_json(),
                    "capturedAt": captured_at,
                    "hostId": self.local_host_id,
                    "inventoryEpoch": epoch,
                    "kernelBootId": second.inventory.kernel_boot_id,
                    "keyId": key_id,
                    "kind": SNAPSHOT_KIND,
                    "schemaVersion": SCHEMA_VERSION,
                    "storeInstanceId": self.store_instance_id,
                    "topologyHash": topology_hash,
                    "trustBoundary": self.authenticator.trust_boundary,
                    "trustRootDigest": self.authenticator.trust_root_digest(key_id),
                }
                unsigned_bytes = _canonical_json_bytes(unsigned)
                snapshot_hash = _sha256(unsigned_bytes)
                capture_provider = _new_capture_provider_capability(
                    capture_fn,
                    authority_id=self.trusted_authority_id,
                    host_id=self.local_host_id,
                    snapshot_hash=snapshot_hash,
                    store_instance_id=self.store_instance_id,
                )
                signature = self.authenticator.sign(key_id, unsigned_bytes)
                envelope = SignedSnapshotEnvelope(
                    authority_id=self.trusted_authority_id,
                    store_instance_id=self.store_instance_id,
                    key_id=key_id,
                    trust_root_digest=self.authenticator.trust_root_digest(key_id),
                    host_id=self.local_host_id,
                    kernel_boot_id=second.inventory.kernel_boot_id,
                    inventory_epoch=epoch,
                    captured_at=captured_at,
                    topology_hash=topology_hash,
                    snapshot_hash=snapshot_hash,
                    capture=published_capture,
                    signature=signature,
                )
                envelope_json = _canonical_json_bytes(envelope.to_json()).decode("ascii")
                self._connection.execute(
                    "INSERT INTO snapshots(inventory_epoch,snapshot_hash,topology_hash,"
                    "kernel_boot_id,key_id,captured_at,envelope_json) VALUES(?,?,?,?,?,?,?)",
                    (
                        epoch,
                        snapshot_hash,
                        topology_hash,
                        second.inventory.kernel_boot_id,
                        key_id,
                        captured_at,
                        envelope_json,
                    ),
                )
                self._fault("PUBLISH_AFTER_INSERT")
                self._connection.execute("COMMIT")
                self._current_capture_provider = capture_provider
                return SnapshotRecord(envelope)
            except SnapshotError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except sqlite3.Error as error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise SnapshotError(SnapshotReason.STORE_UNAVAILABLE, str(error)) from error
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _decode_row(self, row: sqlite3.Row) -> SnapshotRecord:
        raw = _strict_json_loads(str(row["envelope_json"]))
        if not isinstance(raw, Mapping):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "envelope is not object")
        expected_keys = {
            "algorithm",
            "authorityId",
            "capture",
            "capturedAt",
            "hostId",
            "inventoryEpoch",
            "kernelBootId",
            "keyId",
            "kind",
            "schemaVersion",
            "signature",
            "snapshotHash",
            "storeInstanceId",
            "topologyHash",
            "trustBoundary",
            "trustRootDigest",
        }
        if set(raw) != expected_keys:
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "envelope fields changed")
        capture_value = raw["capture"]
        if not isinstance(capture_value, Mapping):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "capture is not object")
        if set(capture_value) != {"inventory", "launchFacts", "scope"}:
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "capture fields changed")
        try:
            inventory = HostInventory.from_dict(capture_value["inventory"])
            raw_facts = capture_value["launchFacts"]
            if not isinstance(raw_facts, Mapping):
                raise TypeError("launchFacts is not an object")
            facts = {
                str(bdf): LaunchDeviceFacts.from_json(value)
                for bdf, value in raw_facts.items()
            }
            capture = SnapshotCapture(
                inventory=inventory,
                launch_facts=facts,
                scope=str(capture_value["scope"]),
            )
            _validate_launch_fact_consistency(capture)
            epoch = int(raw["inventoryEpoch"])
        except (KeyError, TypeError, ValueError, SnapshotError) as error:
            if isinstance(error, SnapshotError):
                raise
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, str(error)) from error
        unsigned = {key: value for key, value in raw.items() if key not in {"signature", "snapshotHash"}}
        unsigned_bytes = _canonical_json_bytes(unsigned)
        snapshot_hash = _sha256(unsigned_bytes)
        if not hmac.compare_digest(snapshot_hash, str(raw["snapshotHash"])):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "unsigned body hash mismatch")
        if not self.authenticator.verify(
            str(raw["keyId"]), unsigned_bytes, str(raw["signature"])
        ):
            raise SnapshotError(SnapshotReason.SNAPSHOT_SIGNATURE_INVALID)
        if str(raw["trustRootDigest"]) != self.authenticator.trust_root_digest(
            str(raw["keyId"])
        ):
            raise SnapshotError(SnapshotReason.SNAPSHOT_SIGNATURE_INVALID, "trust root mismatch")
        topology_hash = compute_full_topology_hash(
            SnapshotCapture(
                inventory=replace(inventory, inventory_epoch=None),
                launch_facts=facts,
            )
        )
        if not hmac.compare_digest(topology_hash, str(raw["topologyHash"])):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "topology hash mismatch")
        if (
            raw["schemaVersion"] != SCHEMA_VERSION
            or raw["kind"] != SNAPSHOT_KIND
            or raw["algorithm"] != self.authenticator.algorithm
            or raw["trustBoundary"] != self.authenticator.trust_boundary
            or raw["authorityId"] != self.trusted_authority_id
            or raw["storeInstanceId"] != self.store_instance_id
            or raw["hostId"] != self.local_host_id
            or inventory.host_id != self.local_host_id
            or inventory.kernel_boot_id != raw["kernelBootId"]
            or inventory.inventory_epoch != epoch
            or inventory.topology_hash != raw["topologyHash"]
            or epoch != int(row["inventory_epoch"])
            or snapshot_hash != str(row["snapshot_hash"])
            or topology_hash != str(row["topology_hash"])
            or raw["kernelBootId"] != str(row["kernel_boot_id"])
            or raw["keyId"] != str(row["key_id"])
            or raw["capturedAt"] != str(row["captured_at"])
        ):
            raise SnapshotError(SnapshotReason.SNAPSHOT_HASH_MISMATCH, "row/envelope mismatch")
        envelope = SignedSnapshotEnvelope(
            authority_id=str(raw["authorityId"]),
            store_instance_id=str(raw["storeInstanceId"]),
            key_id=str(raw["keyId"]),
            trust_root_digest=str(raw["trustRootDigest"]),
            host_id=str(raw["hostId"]),
            kernel_boot_id=str(raw["kernelBootId"]),
            inventory_epoch=epoch,
            captured_at=str(raw["capturedAt"]),
            topology_hash=topology_hash,
            snapshot_hash=snapshot_hash,
            capture=capture,
            signature=str(raw["signature"]),
        )
        return SnapshotRecord(envelope)

    def _current_in_transaction(self, *, minimum_epoch: int = 0) -> SnapshotRecord:
        self._require_live_store()
        row = self._connection.execute(
            "SELECT * FROM snapshots ORDER BY inventory_epoch DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise SnapshotError(SnapshotReason.SNAPSHOT_NOT_FOUND)
        record = self._decode_row(row)
        if record.inventory_epoch < minimum_epoch:
            raise SnapshotError(
                SnapshotReason.SNAPSHOT_STALE,
                f"current epoch {record.inventory_epoch} is below required {minimum_epoch}",
            )
        current_boot = self._current_boot_id()
        if current_boot != record.envelope.kernel_boot_id:
            raise SnapshotError(
                SnapshotReason.BOOT_ID_CHANGED,
                f"current={current_boot!r}, snapshot={record.envelope.kernel_boot_id!r}",
            )
        return record

    def current(self, *, minimum_epoch: int = 0) -> SnapshotRecord:
        if (
            isinstance(minimum_epoch, bool)
            or not isinstance(minimum_epoch, int)
            or not 0 <= minimum_epoch <= (1 << 63) - 1
        ):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "invalid minimum_epoch")
        with self._transaction_ownership("READ"), self._lock:
            try:
                self._connection.execute("BEGIN")
                record = self._current_in_transaction(minimum_epoch=minimum_epoch)
                self._connection.execute("ROLLBACK")
                return record
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _authorization_hash(
        record: SnapshotRecord,
        requested: tuple[str, ...],
        facts: Mapping[str, LaunchDeviceFacts],
        capture_provider: _CaptureProviderCapability,
    ) -> str:
        return _sha256(
            _canonical_json_bytes(
                {
                    "authorityId": record.envelope.authority_id,
                    "authorizedBdfs": list(requested),
                    "captureProviderBindingHash": capture_provider.binding_hash,
                    "captureProviderBoundary": CAPTURE_PROVIDER_BOUNDARY,
                    "domain": "qman.snapshot.launch-authorization.v1",
                    "hostId": record.envelope.host_id,
                    "inventoryEpoch": record.inventory_epoch,
                    "kernelBootId": record.envelope.kernel_boot_id,
                    "keyId": record.envelope.key_id,
                    "launchFacts": {bdf: facts[bdf].to_json() for bdf in requested},
                    "snapshotHash": record.snapshot_hash,
                    "storeInstanceId": record.envelope.store_instance_id,
                    "topologyHash": record.topology_hash,
                }
            )
        )

    @contextmanager
    def authorize_launch(
        self,
        expected_snapshot_hash: str,
        requested_bdfs: Sequence[str],
    ) -> Iterator[SnapshotLaunchAuthorization]:
        expected = _required_hash("expected_snapshot_hash", expected_snapshot_hash)
        if (
            not isinstance(requested_bdfs, Sequence)
            or isinstance(requested_bdfs, (str, bytes))
            or not requested_bdfs
        ):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "requested_bdfs is empty")
        requested = tuple(sorted(str(bdf).lower() for bdf in requested_bdfs))
        if len(requested) != len(set(requested)) or any(
            vfio.BDF_RE.fullmatch(bdf) is None for bdf in requested
        ):
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "requested BDFs are invalid")
        kind = "LAUNCH_AUTHORIZATION"
        self._claim_transaction(kind)
        authorization: SnapshotLaunchAuthorization | None = None
        try:
            with self._lock:
                self._connection.execute("BEGIN IMMEDIATE")
                record = self._current_in_transaction()
                if not hmac.compare_digest(record.snapshot_hash, expected):
                    raise SnapshotError(SnapshotReason.SNAPSHOT_STALE, "expected snapshot is not current")
                capture_provider = self._current_capture_provider
                if (
                    type(capture_provider) is not _CaptureProviderCapability
                    or not hmac.compare_digest(
                        capture_provider.snapshot_hash,
                        record.snapshot_hash,
                    )
                ):
                    raise SnapshotError(
                        SnapshotReason.CAPTURE_PROVIDER_UNAVAILABLE,
                        "the current snapshot has no live publisher capability in this process",
                    )
                facts: dict[str, LaunchDeviceFacts] = {}
                for bdf in requested:
                    fact = record.envelope.capture.launch_facts.get(bdf)
                    if fact is None:
                        raise SnapshotError(
                            SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                            f"snapshot has no launch facts for {bdf}",
                        )
                    facts[bdf] = fact
                requested_set = frozenset(requested)
                for bdf, fact in facts.items():
                    if frozenset(fact.group_members) != requested_set.intersection(
                        fact.group_members
                    ):
                        missing = sorted(set(fact.group_members) - requested_set)
                        raise SnapshotError(
                            SnapshotReason.INCOMPLETE_IOMMU_GROUP,
                            f"{bdf} missing group members {missing}",
                        )
                    for member in fact.group_members:
                        peer = facts.get(member)
                        if (
                            peer is None
                            or peer.iommu_group != fact.iommu_group
                            or peer.group_members != fact.group_members
                        ):
                            raise SnapshotError(
                                SnapshotReason.INCOMPLETE_IOMMU_GROUP,
                                f"{bdf} group facts are not mutually complete",
                            )
                binding_hash = self._authorization_hash(
                    record,
                    requested,
                    facts,
                    capture_provider,
                )
                guard = _AuthorizationGuard()
                authorization = object.__new__(SnapshotLaunchAuthorization)
                values: dict[str, Any] = {
                    "host_id": record.envelope.host_id,
                    "kernel_boot_id": record.envelope.kernel_boot_id,
                    "inventory_epoch": record.inventory_epoch,
                    "topology_hash": record.topology_hash,
                    "snapshot_hash": record.snapshot_hash,
                    "authority_id": record.envelope.authority_id,
                    "store_instance_id": record.envelope.store_instance_id,
                    "key_id": record.envelope.key_id,
                    "capture_provider_boundary": CAPTURE_PROVIDER_BOUNDARY,
                    "capture_provider_binding_hash": capture_provider.binding_hash,
                    "binding_hash": binding_hash,
                    "authorized_bdfs": requested,
                    "launch_facts": MappingProxyType(facts),
                    "_store": self,
                    "_guard": guard,
                    "_capture_provider": capture_provider,
                    "_provenance": _AUTHORIZATION_PROVENANCE,
                }
                for name, value in values.items():
                    object.__setattr__(authorization, name, value)
                self._active_authorization = authorization
            yield authorization
        except BaseException:
            raise
        finally:
            with self._lock:
                if authorization is not None:
                    authorization._guard.active = False
                self._active_authorization = None
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
            self._release_transaction(kind)

    def _require_active_authorization(
        self, authorization: SnapshotLaunchAuthorization
    ) -> None:
        with self._lock:
            if (
                self._transaction_kind != "LAUNCH_AUTHORIZATION"
                or self._transaction_owner != threading.get_ident()
                or self._active_authorization is not authorization
                or not self._connection.in_transaction
            ):
                raise SnapshotError(SnapshotReason.AUTHORIZATION_INACTIVE)
            self._require_live_store()
            row = self._connection.execute(
                "SELECT * FROM snapshots ORDER BY inventory_epoch DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise SnapshotError(SnapshotReason.SNAPSHOT_NOT_FOUND)
            record = self._decode_row(row)
            current_boot = self._current_boot_id()
            if current_boot != record.envelope.kernel_boot_id:
                raise SnapshotError(
                    SnapshotReason.BOOT_ID_CHANGED,
                    f"current={current_boot!r}, snapshot={record.envelope.kernel_boot_id!r}",
                )
            facts = {bdf: authorization.launch_facts[bdf] for bdf in authorization.authorized_bdfs}
            capture_provider = self._current_capture_provider
            if (
                type(capture_provider) is not _CaptureProviderCapability
                or authorization._capture_provider is not capture_provider
                or not hmac.compare_digest(
                    capture_provider.snapshot_hash,
                    record.snapshot_hash,
                )
                or not hmac.compare_digest(
                    authorization.capture_provider_binding_hash,
                    capture_provider.binding_hash,
                )
            ):
                raise SnapshotError(
                    SnapshotReason.AUTHORIZATION_INACTIVE,
                    "capture provider capability changed",
                )
            expected_binding = self._authorization_hash(
                record,
                authorization.authorized_bdfs,
                facts,
                capture_provider,
            )
            if (
                record.snapshot_hash != authorization.snapshot_hash
                or record.inventory_epoch != authorization.inventory_epoch
                or authorization.capture_provider_boundary
                != CAPTURE_PROVIDER_BOUNDARY
                or not hmac.compare_digest(expected_binding, authorization.binding_hash)
            ):
                raise SnapshotError(SnapshotReason.AUTHORIZATION_INACTIVE, "authorization binding changed")

    def export_current(self, path: str | Path) -> SnapshotRecord:
        """Atomically export a verified cache/evidence copy; never an authority."""

        target = Path(path)
        if not target.is_absolute() or not target.parent.is_dir() or target.is_symlink():
            raise SnapshotError(SnapshotReason.INVALID_ARGUMENT, "export path is invalid")
        record = self.current()
        payload = json.dumps(record.envelope.to_json(), indent=2, sort_keys=True) + "\n"
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        fd: int | None = None
        try:
            fd = os.open(temporary, flags, 0o600)
            data = payload.encode("utf-8")
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temporary, target)
            if os.name != "nt":
                directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except BaseException:
            if fd is not None:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
        return record
