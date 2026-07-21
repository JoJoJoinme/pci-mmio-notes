"""Immutable, fd-only stock-QEMU launch contract for PCI passthrough.

The module renders data; it never opens VFIO devices, creates sockets, or
starts a process.  Callers must acquire and retain the supplied file
descriptors, then call :func:`validate_before_spawn` immediately before using
the returned :class:`SpawnSpec` with their process launcher.

P2 boundary: the QEMU hash covers the executable ELF file, not its dynamic
loader, shared-library, firmware/ROM closure.  A narrow path TOCTOU also remains
between final validation and ``exec``; the trusted coordinator must execute
immediately from read-only deployment paths.  In addition, today's raw opener
returns one result per device and cannot productively share one IOMMUFD file
description across multiple cdevs in the same IOMMU group.  Such bundles must
remain unsupported until an upstream group-aware opener exists; this renderer
does not turn test-only bindings into a production-positive claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Callable, Sequence


HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
GROUP_RE = re.compile(r"^[0-9]+$")
SAFE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
Q35_MACHINE_RE = re.compile(r"^(?:q35|pc-q35-[0-9]+(?:\.[0-9]+)*)$")
QMP_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

MIN_MEMORY_MIB = 256
MAX_MEMORY_MIB = 1_048_576
MIN_VCPU_COUNT = 1
MAX_VCPU_COUNT = 1_024
MIN_INHERITED_FD = 3
MAX_QMP_SOCKET_BYTES = 107


class Reason:
    """Stable machine-facing rejection codes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_QEMU_PATH = "INVALID_QEMU_PATH"
    QEMU_BINARY_IDENTITY_MISMATCH = "QEMU_BINARY_IDENTITY_MISMATCH"
    QEMU_BINARY_HASH_MISMATCH = "QEMU_BINARY_HASH_MISMATCH"
    INVALID_LEASE_BINDING = "INVALID_LEASE_BINDING"
    INVALID_LEASE_AUTHORIZATION = "INVALID_LEASE_AUTHORIZATION"
    INVALID_LEASE_RECORD = "INVALID_LEASE_RECORD"
    LEASE_AUTHORIZATION_INACTIVE = "LEASE_AUTHORIZATION_INACTIVE"
    LEASE_DEVICE_SCOPE_MISMATCH = "LEASE_DEVICE_SCOPE_MISMATCH"
    INVALID_PROFILE = "INVALID_PROFILE"
    INVALID_QMP_SOCKET = "INVALID_QMP_SOCKET"
    QMP_RUNTIME_IDENTITY_MISMATCH = "QMP_RUNTIME_IDENTITY_MISMATCH"
    QMP_SOCKET_ALREADY_EXISTS = "QMP_SOCKET_ALREADY_EXISTS"
    INVALID_DEVICE_BINDING = "INVALID_DEVICE_BINDING"
    FD_ROLE_CONFLICT = "FD_ROLE_CONFLICT"
    FD_IDENTITY_MISMATCH = "FD_IDENTITY_MISMATCH"
    FORBIDDEN_RENDERED_ARGUMENT = "FORBIDDEN_RENDERED_ARGUMENT"
    INVALID_PROVIDER_ADMISSION = "INVALID_PROVIDER_ADMISSION"
    NON_CANONICAL_SPAWN_SPEC = "NON_CANONICAL_SPAWN_SPEC"
    UNSUPPORTED_SPAWN_PLATFORM = "UNSUPPORTED_SPAWN_PLATFORM"


class LaunchContractError(ValueError):
    """Fail-closed contract violation with a stable reason code."""

    def __init__(self, reason_code: str, *, detail: str | None = None) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(reason_code if detail is None else f"{reason_code}: {detail}")


def _reject(reason_code: str, detail: str) -> None:
    raise LaunchContractError(reason_code, detail=detail)


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_plain_int(
    value: object,
    *,
    minimum: int,
    maximum: int | None,
    reason_code: str,
    field: str,
) -> int:
    if not _is_plain_int(value):
        _reject(reason_code, f"{field} must be an integer")
    assert isinstance(value, int)
    if value < minimum or (maximum is not None and value > maximum):
        _reject(reason_code, f"{field} is outside the supported bounds")
    return value


def _require_hash(value: object, *, reason_code: str, field: str) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        _reject(reason_code, f"{field} must be canonical sha256:<lowercase-hex>")
    return value


def _normalize_external_hash(value: object, *, field: str) -> str:
    """Normalize the existing VFIO provider's raw lowercase SHA-256 format."""

    if not isinstance(value, str) or RAW_HASH_RE.fullmatch(value) is None:
        _reject(Reason.INVALID_PROVIDER_ADMISSION, f"{field} is not lowercase SHA-256")
    return f"sha256:{value}"


def _require_safe_id(value: object, *, reason_code: str, field: str) -> str:
    if not isinstance(value, str) or SAFE_ID_RE.fullmatch(value) is None:
        _reject(reason_code, f"{field} is not a canonical safe identifier")
    return value


def _require_text(value: object, *, reason_code: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x20 for character in value)
    ):
        _reject(reason_code, f"{field} must be bounded non-empty text")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _canonical_absolute_path(
    value: object,
    *,
    reason_code: str,
    field: str,
) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _reject(reason_code, f"{field} must be a path")
    path = Path(value)
    if not path.is_absolute():
        _reject(reason_code, f"{field} must be absolute")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        _reject(reason_code, f"{field} cannot be resolved: {error}")
    if path != resolved:
        _reject(reason_code, f"{field} must already be canonical")
    return path


@dataclass(frozen=True)
class BinaryStatToken:
    """Stable identity fields used to detect executable replacement."""

    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int

    def __post_init__(self) -> None:
        for field, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("mode", self.mode),
            ("size", self.size),
            ("mtime_ns", self.mtime_ns),
        ):
            _require_plain_int(
                value,
                minimum=0,
                maximum=None,
                reason_code=Reason.INVALID_QEMU_PATH,
                field=field,
            )
        if not stat.S_ISREG(self.mode):
            _reject(Reason.INVALID_QEMU_PATH, "QEMU must be a regular file")

    @classmethod
    def from_stat(cls, value: os.stat_result) -> BinaryStatToken:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
        )

    def to_json(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "mtimeNs": self.mtime_ns,
            "size": self.size,
        }


@dataclass(frozen=True)
class DirectoryStatToken:
    """Identity and privacy proof for the backend-only QMP directory."""

    device: int
    inode: int
    mode: int
    owner_uid: int

    def __post_init__(self) -> None:
        for field, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("mode", self.mode),
            ("owner_uid", self.owner_uid),
        ):
            _require_plain_int(
                value,
                minimum=0,
                maximum=None,
                reason_code=Reason.INVALID_QMP_SOCKET,
                field=field,
            )
        if not stat.S_ISDIR(self.mode):
            _reject(Reason.INVALID_QMP_SOCKET, "QMP runtime path must be a directory")
        if stat.S_IMODE(self.mode) != 0o700:
            _reject(Reason.INVALID_QMP_SOCKET, "QMP runtime directory mode must be 0700")

    @classmethod
    def from_stat(cls, value: os.stat_result) -> DirectoryStatToken:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            owner_uid=getattr(value, "st_uid", 0),
        )

    def to_json(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "ownerUid": self.owner_uid,
        }


@dataclass(frozen=True)
class FdStatToken:
    """Immutable fstat identity for an inherited character-device fd."""

    device: int
    inode: int
    rdev: int
    mode: int

    def __post_init__(self) -> None:
        for field, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("rdev", self.rdev),
            ("mode", self.mode),
        ):
            _require_plain_int(
                value,
                minimum=0,
                maximum=None,
                reason_code=Reason.INVALID_DEVICE_BINDING,
                field=field,
            )
        if not stat.S_ISCHR(self.mode):
            _reject(Reason.INVALID_DEVICE_BINDING, "inherited VFIO fds must be character devices")

    @classmethod
    def from_stat(cls, value: os.stat_result) -> FdStatToken:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            rdev=value.st_rdev,
            mode=value.st_mode,
        )

    def to_json(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "rdev": self.rdev,
        }


@dataclass(frozen=True)
class QemuBinaryIdentity:
    path: Path
    sha256: str
    stat: BinaryStatToken

    def __post_init__(self) -> None:
        path = _canonical_absolute_path(
            self.path,
            reason_code=Reason.INVALID_QEMU_PATH,
            field="qemu.path",
        )
        if not isinstance(self.stat, BinaryStatToken):
            _reject(Reason.INVALID_QEMU_PATH, "qemu.stat must be a BinaryStatToken")
        object.__setattr__(self, "path", path)
        _require_hash(self.sha256, reason_code=Reason.INVALID_QEMU_PATH, field="qemu.sha256")

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "stat": self.stat.to_json(),
        }


_VERIFIED_LEASE_PROVENANCE = object()


@dataclass(frozen=True, init=False)
class LeaseBinding:
    transaction_id: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    authority_id: str
    bundle_members_hash: str
    members: tuple[str, ...]
    inventory_epoch: int
    device_generations: tuple[tuple[str, int], ...]
    vm_generation: int
    lease_revision: int
    policy_hash: str
    decision_hash: str
    state: str
    authorization_binding_hash: str
    store_instance_id: str
    _authorization: object = dataclass_field(repr=False, compare=False)
    _verified_provenance: object = dataclass_field(repr=False, compare=False)

    @classmethod
    def _from_verified(
        cls,
        *,
        transaction_id: str,
        host_id: str,
        vm_id: str,
        run_id: str,
        bundle_id: str,
        authority_id: str,
        bundle_members_hash: str,
        members: tuple[str, ...],
        inventory_epoch: int,
        device_generations: tuple[tuple[str, int], ...],
        vm_generation: int,
        lease_revision: int,
        policy_hash: str,
        decision_hash: str,
        authorization_binding_hash: str,
        store_instance_id: str,
        authorization: object,
        state: str = "PREPARING",
    ) -> LeaseBinding:
        instance = object.__new__(cls)
        values = {
            "transaction_id": transaction_id,
            "host_id": host_id,
            "vm_id": vm_id,
            "run_id": run_id,
            "bundle_id": bundle_id,
            "authority_id": authority_id,
            "bundle_members_hash": bundle_members_hash,
            "members": members,
            "inventory_epoch": inventory_epoch,
            "device_generations": device_generations,
            "vm_generation": vm_generation,
            "lease_revision": lease_revision,
            "policy_hash": policy_hash,
            "decision_hash": decision_hash,
            "state": state,
            "authorization_binding_hash": authorization_binding_hash,
            "store_instance_id": store_instance_id,
            "_authorization": authorization,
            "_verified_provenance": _VERIFIED_LEASE_PROVENANCE,
        }
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        instance.__post_init__()
        return instance

    def __post_init__(self) -> None:
        if self._verified_provenance is not _VERIFIED_LEASE_PROVENANCE:
            _reject(Reason.INVALID_LEASE_BINDING, "lease lacks verified authorization provenance")
        from . import static_lease

        if type(self._authorization) is not static_lease.LeaseLaunchAuthorization:
            _reject(
                Reason.INVALID_LEASE_AUTHORIZATION,
                "exact LeaseLaunchAuthorization capability is required",
            )
        for field_name in (
            "transaction_id",
            "vm_id",
            "run_id",
            "bundle_id",
            "authority_id",
        ):
            _require_text(
                getattr(self, field_name),
                reason_code=Reason.INVALID_LEASE_BINDING,
                field=field_name,
            )
        if (
            not isinstance(self.host_id, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", self.host_id) is None
        ):
            _reject(Reason.INVALID_LEASE_BINDING, "host_id is not canonical")
        _require_hash(
            self.bundle_members_hash,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="bundle_members_hash",
        )
        if (
            not isinstance(self.members, tuple)
            or not self.members
            or self.members != tuple(sorted(set(self.members)))
            or any(BDF_RE.fullmatch(member) is None for member in self.members)
        ):
            _reject(Reason.INVALID_LEASE_BINDING, "members are not canonical PCI BDFs")
        if (
            not isinstance(self.device_generations, tuple)
            or tuple(bdf for bdf, _generation in self.device_generations) != self.members
        ):
            _reject(
                Reason.INVALID_LEASE_BINDING,
                "device generations must exactly cover canonical members",
            )
        for bdf, generation in self.device_generations:
            if BDF_RE.fullmatch(bdf) is None:
                _reject(Reason.INVALID_LEASE_BINDING, "invalid device generation BDF")
            _require_plain_int(
                generation,
                minimum=0,
                maximum=None,
                reason_code=Reason.INVALID_LEASE_BINDING,
                field=f"device_generations[{bdf}]",
            )
        _require_plain_int(
            self.inventory_epoch,
            minimum=0,
            maximum=None,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="inventory_epoch",
        )
        _require_plain_int(
            self.vm_generation,
            minimum=1,
            maximum=None,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="vm_generation",
        )
        _require_plain_int(
            self.lease_revision,
            minimum=0,
            maximum=None,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="lease_revision",
        )
        _require_hash(
            self.policy_hash,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="policy_hash",
        )
        _require_hash(
            self.decision_hash,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="decision_hash",
        )
        _require_hash(
            self.authorization_binding_hash,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="authorization_binding_hash",
        )
        _require_text(
            self.store_instance_id,
            reason_code=Reason.INVALID_LEASE_BINDING,
            field="store_instance_id",
        )
        if self.state != "PREPARING":
            _reject(Reason.INVALID_LEASE_BINDING, "launch requires a PREPARING lease")
        record = self._authorization.record
        if (
            record.transaction_id != self.transaction_id
            or record.host_id != self.host_id
            or record.vm_id != self.vm_id
            or record.run_id != self.run_id
            or record.bundle_id != self.bundle_id
            or record.authority_id != self.authority_id
            or record.bundle_members_hash != self.bundle_members_hash
            or tuple(record.members) != self.members
            or record.inventory_epoch != self.inventory_epoch
            or tuple(sorted(record.device_generations.items())) != self.device_generations
            or record.vm_generation != self.vm_generation
            or record.revision != self.lease_revision
            or record.policy_hash != self.policy_hash
            or record.decision_hash != self.decision_hash
            or record.state.value != self.state
            or self._authorization.store_instance_id != self.store_instance_id
            or self._authorization.binding_hash != self.authorization_binding_hash
        ):
            _reject(
                Reason.INVALID_LEASE_AUTHORIZATION,
                "lease binding differs from authorization record",
            )
        self.require_active()

    def require_active(self) -> None:
        from . import static_lease

        if type(self._authorization) is not static_lease.LeaseLaunchAuthorization:
            _reject(Reason.INVALID_LEASE_AUTHORIZATION, "authorization type changed")
        try:
            self._authorization.require_active()
        except static_lease.LeaseStoreError as error:
            _reject(Reason.LEASE_AUTHORIZATION_INACTIVE, f"launch authorization: {error}")
        expected_hash = _launch_authorization_hash(
            self._authorization.record,
            self._authorization.store_instance_id,
        )
        if (
            not hmac.compare_digest(expected_hash, self._authorization.binding_hash)
            or not hmac.compare_digest(expected_hash, self.authorization_binding_hash)
            or self._authorization.store_instance_id != self.store_instance_id
        ):
            _reject(
                Reason.INVALID_LEASE_AUTHORIZATION,
                "authorization binding hash or store identity changed",
            )

    @property
    def binding_hash(self) -> str:
        return _digest(self.to_json())

    def to_json(self) -> dict[str, Any]:
        return {
            "authorizationBindingHash": self.authorization_binding_hash,
            "authorityId": self.authority_id,
            "bundleId": self.bundle_id,
            "bundleMembersHash": self.bundle_members_hash,
            "decisionHash": self.decision_hash,
            "deviceGenerations": dict(self.device_generations),
            "hostId": self.host_id,
            "inventoryEpoch": self.inventory_epoch,
            "leaseRevision": self.lease_revision,
            "members": list(self.members),
            "policyHash": self.policy_hash,
            "runId": self.run_id,
            "state": self.state,
            "storeInstanceId": self.store_instance_id,
            "transactionId": self.transaction_id,
            "vmId": self.vm_id,
            "vmGeneration": self.vm_generation,
        }


def _launch_authorization_hash(record: object, store_instance_id: str) -> str:
    return _digest(
        {
            "authorityId": record.authority_id,
            "bundleId": record.bundle_id,
            "bundleMembersHash": record.bundle_members_hash,
            "decisionHash": record.decision_hash,
            "deviceGenerations": dict(sorted(record.device_generations.items())),
            "domain": "qman.static-lease.launch-authorization.v1",
            "hostId": record.host_id,
            "inventoryEpoch": record.inventory_epoch,
            "members": list(record.members),
            "policyHash": record.policy_hash,
            "revision": record.revision,
            "runId": record.run_id,
            "state": record.state.value,
            "storeInstanceId": store_instance_id,
            "transactionId": record.transaction_id,
            "vmGeneration": record.vm_generation,
            "vmId": record.vm_id,
        }
    )


def lease_binding_from_launch_authorization(authorization: object) -> LeaseBinding:
    """Bind one active, exact store-issued launch authorization capability."""

    from . import static_lease

    if type(authorization) is not static_lease.LeaseLaunchAuthorization:
        _reject(
            Reason.INVALID_LEASE_AUTHORIZATION,
            "exact LeaseLaunchAuthorization is required",
        )
    try:
        authorization.require_active()
    except static_lease.LeaseStoreError as error:
        _reject(Reason.LEASE_AUTHORIZATION_INACTIVE, f"launch authorization: {error}")
    record = authorization.record
    if type(record) is not static_lease.LeaseRecord:
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, "authorization record type is invalid")
    if record.state is not static_lease.LeaseState.PREPARING:
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, "lease record must be PREPARING")
    members = tuple(record.members)
    try:
        device_generations = tuple(sorted(record.device_generations.items()))
    except AttributeError:
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, "device_generations must be a mapping")
    try:
        expected_bundle_hash = static_lease.StaticLeaseStore.compute_bundle_members_hash(
            record.host_id,
            record.bundle_id,
            members,
        )
    except static_lease.LeaseStoreError as error:
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, f"invalid lease record: {error}")
    if not hmac.compare_digest(expected_bundle_hash, record.bundle_members_hash):
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, "bundle members hash is invalid")
    expected_authorization_hash = _launch_authorization_hash(
        record,
        authorization.store_instance_id,
    )
    if not hmac.compare_digest(expected_authorization_hash, authorization.binding_hash):
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, "authorization binding hash is invalid")
    try:
        binding = LeaseBinding._from_verified(
            transaction_id=record.transaction_id,
            host_id=record.host_id,
            vm_id=record.vm_id,
            run_id=record.run_id,
            bundle_id=record.bundle_id,
            authority_id=record.authority_id,
            bundle_members_hash=record.bundle_members_hash,
            members=members,
            inventory_epoch=record.inventory_epoch,
            device_generations=device_generations,
            vm_generation=record.vm_generation,
            lease_revision=record.revision,
            policy_hash=record.policy_hash,
            decision_hash=record.decision_hash,
            authorization_binding_hash=authorization.binding_hash,
            store_instance_id=authorization.store_instance_id,
            authorization=authorization,
            state=record.state.value,
        )
    except LaunchContractError as error:
        _reject(Reason.INVALID_LEASE_AUTHORIZATION, f"invalid authorization: {error}")
    binding.require_active()
    return binding


@dataclass(frozen=True)
class MachineProfile:
    profile_id: str
    machine_type: str
    memory_mib: int
    vcpu_count: int

    def __post_init__(self) -> None:
        _require_safe_id(
            self.profile_id,
            reason_code=Reason.INVALID_PROFILE,
            field="profile_id",
        )
        if not isinstance(self.machine_type, str) or Q35_MACHINE_RE.fullmatch(
            self.machine_type
        ) is None:
            _reject(Reason.INVALID_PROFILE, "machine_type must be q35 or a versioned pc-q35")
        _require_plain_int(
            self.memory_mib,
            minimum=MIN_MEMORY_MIB,
            maximum=MAX_MEMORY_MIB,
            reason_code=Reason.INVALID_PROFILE,
            field="memory_mib",
        )
        _require_plain_int(
            self.vcpu_count,
            minimum=MIN_VCPU_COUNT,
            maximum=MAX_VCPU_COUNT,
            reason_code=Reason.INVALID_PROFILE,
            field="vcpu_count",
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "machineType": self.machine_type,
            "memoryMiB": self.memory_mib,
            "profileId": self.profile_id,
            "vcpuCount": self.vcpu_count,
        }


@dataclass(frozen=True)
class QmpSocketBinding:
    runtime_directory: Path
    runtime_stat: DirectoryStatToken
    socket_path: Path
    nonce: str

    def __post_init__(self) -> None:
        runtime_directory = _canonical_absolute_path(
            self.runtime_directory,
            reason_code=Reason.INVALID_QMP_SOCKET,
            field="runtime_directory",
        )
        socket_path = _canonical_absolute_path(
            self.socket_path,
            reason_code=Reason.INVALID_QMP_SOCKET,
            field="socket_path",
        )
        if not isinstance(self.runtime_stat, DirectoryStatToken):
            _reject(Reason.INVALID_QMP_SOCKET, "runtime_stat must be a DirectoryStatToken")
        if not isinstance(self.nonce, str) or QMP_NONCE_RE.fullmatch(self.nonce) is None:
            _reject(Reason.INVALID_QMP_SOCKET, "nonce must be 128 bits of lowercase hex")
        expected_name = f"backend-{self.nonce}.qmp"
        if socket_path.parent != runtime_directory or socket_path.name != expected_name:
            _reject(
                Reason.INVALID_QMP_SOCKET,
                "socket must be the nonce-bound direct child of runtime_directory",
            )
        socket_text = str(socket_path)
        if "," in socket_text or any(ord(character) < 0x20 for character in socket_text):
            _reject(
                Reason.INVALID_QMP_SOCKET,
                "socket path contains a QEMU option-parser delimiter/control character",
            )
        try:
            socket_length = len(os.fsencode(socket_path))
        except UnicodeEncodeError as error:
            _reject(Reason.INVALID_QMP_SOCKET, f"socket path is not encodable: {error}")
        if socket_length > MAX_QMP_SOCKET_BYTES:
            _reject(Reason.INVALID_QMP_SOCKET, "socket path exceeds AF_UNIX sun_path limit")
        object.__setattr__(self, "runtime_directory", runtime_directory)
        object.__setattr__(self, "socket_path", socket_path)

    def to_json(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "runtimeDirectory": str(self.runtime_directory),
            "runtimeStat": self.runtime_stat.to_json(),
            "socketPath": str(self.socket_path),
        }


@dataclass(frozen=True)
class GuestSlot:
    index: int
    root_port_address: int

    def __post_init__(self) -> None:
        _require_plain_int(
            self.index,
            minimum=0,
            maximum=29,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="guest_slot.index",
        )
        _require_plain_int(
            self.root_port_address,
            minimum=2,
            maximum=30,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="guest_slot.root_port_address",
        )

    @property
    def endpoint_id(self) -> str:
        return f"dp{self.index}"

    @property
    def root_port_id(self) -> str:
        return f"rp-dp{self.index}"

    def to_json(self) -> dict[str, int]:
        return {
            "index": self.index,
            "rootPortAddress": self.root_port_address,
        }


@dataclass(frozen=True)
class ProviderAdmission:
    """Immutable correlation with one raw ``VfioLaunchResult`` admission."""

    snapshot_epoch: int
    topology_hash: str
    fd_binding_hash: str
    iommu_group: str
    group_members: tuple[str, ...]
    lease_binding_hash: str
    handoff_mode: str = "PYTHON_SUBPROCESS_PASS_FDS"

    def __post_init__(self) -> None:
        _require_plain_int(
            self.snapshot_epoch,
            minimum=0,
            maximum=(1 << 64) - 1,
            reason_code=Reason.INVALID_PROVIDER_ADMISSION,
            field="snapshot_epoch",
        )
        _require_hash(
            self.topology_hash,
            reason_code=Reason.INVALID_PROVIDER_ADMISSION,
            field="topology_hash",
        )
        _require_hash(
            self.fd_binding_hash,
            reason_code=Reason.INVALID_PROVIDER_ADMISSION,
            field="fd_binding_hash",
        )
        _require_hash(
            self.lease_binding_hash,
            reason_code=Reason.INVALID_PROVIDER_ADMISSION,
            field="lease_binding_hash",
        )
        if not isinstance(self.iommu_group, str) or GROUP_RE.fullmatch(
            self.iommu_group
        ) is None:
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "IOMMU group ID is not canonical")
        if (
            not isinstance(self.group_members, tuple)
            or not self.group_members
            or self.group_members != tuple(sorted(set(self.group_members)))
            or any(BDF_RE.fullmatch(member) is None for member in self.group_members)
        ):
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "group members are not canonical")
        if self.handoff_mode != "PYTHON_SUBPROCESS_PASS_FDS":
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "provider handoff mode is unsupported")

    def to_json(self) -> dict[str, Any]:
        return {
            "fdBindingHash": self.fd_binding_hash,
            "handoffMode": self.handoff_mode,
            "groupMembers": list(self.group_members),
            "iommuGroup": self.iommu_group,
            "leaseBindingHash": self.lease_binding_hash,
            "snapshotEpoch": self.snapshot_epoch,
            "topologyHash": self.topology_hash,
        }


_VERIFIED_DEVICE_PROVENANCE = object()


@dataclass(frozen=True, init=False)
class DeviceFdBinding:
    """Low-level immutable binding used by the renderer.

    Production coordinators should create this value exclusively through
    :func:`device_binding_from_vfio_launch_result`.  Direct construction is a
    deliberate in-process trust seam for deserialization and deterministic
    tests; it does not by itself prove provider admission provenance.
    """

    bdf: str
    guest_slot: GuestSlot
    cdev_fd: int
    cdev_stat: FdStatToken
    iommufd_fd: int
    iommufd_stat: FdStatToken
    identity_hash: str
    group_hash: str
    provider_admission: ProviderAdmission
    _verified_provenance: object = dataclass_field(repr=False, compare=False)

    @classmethod
    def _from_verified(
        cls,
        *,
        bdf: str,
        guest_slot: GuestSlot,
        cdev_fd: int,
        cdev_stat: FdStatToken,
        iommufd_fd: int,
        iommufd_stat: FdStatToken,
        identity_hash: str,
        group_hash: str,
        provider_admission: ProviderAdmission,
    ) -> DeviceFdBinding:
        instance = object.__new__(cls)
        values = {
            "bdf": bdf,
            "guest_slot": guest_slot,
            "cdev_fd": cdev_fd,
            "cdev_stat": cdev_stat,
            "iommufd_fd": iommufd_fd,
            "iommufd_stat": iommufd_stat,
            "identity_hash": identity_hash,
            "group_hash": group_hash,
            "provider_admission": provider_admission,
            "_verified_provenance": _VERIFIED_DEVICE_PROVENANCE,
        }
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        instance.__post_init__()
        return instance

    def __post_init__(self) -> None:
        if self._verified_provenance is not _VERIFIED_DEVICE_PROVENANCE:
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "device lacks verified provenance")
        if not isinstance(self.bdf, str) or BDF_RE.fullmatch(self.bdf) is None:
            _reject(Reason.INVALID_DEVICE_BINDING, "bdf must be canonical lowercase domain BDF")
        if not isinstance(self.guest_slot, GuestSlot):
            _reject(Reason.INVALID_DEVICE_BINDING, "guest_slot must be a GuestSlot")
        _require_plain_int(
            self.cdev_fd,
            minimum=MIN_INHERITED_FD,
            maximum=None,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="cdev_fd",
        )
        _require_plain_int(
            self.iommufd_fd,
            minimum=MIN_INHERITED_FD,
            maximum=None,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="iommufd_fd",
        )
        if not isinstance(self.cdev_stat, FdStatToken) or not isinstance(
            self.iommufd_stat, FdStatToken
        ):
            _reject(Reason.INVALID_DEVICE_BINDING, "fd stat values must be FdStatToken")
        if self.cdev_fd == self.iommufd_fd:
            _reject(Reason.FD_ROLE_CONFLICT, "one fd cannot be both cdev and iommufd")
        _require_hash(
            self.identity_hash,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="identity_hash",
        )
        _require_hash(
            self.group_hash,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="group_hash",
        )
        if not isinstance(self.provider_admission, ProviderAdmission):
            _reject(
                Reason.INVALID_PROVIDER_ADMISSION,
                "provider_admission must be a typed immutable admission",
            )
        if self.bdf not in self.provider_admission.group_members:
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "device BDF is absent from group members")

    def to_json(self) -> dict[str, Any]:
        return {
            "bdf": self.bdf,
            "cdevFd": self.cdev_fd,
            "cdevStat": self.cdev_stat.to_json(),
            "groupHash": self.group_hash,
            "guestSlot": self.guest_slot.to_json(),
            "identityHash": self.identity_hash,
            "iommufdFd": self.iommufd_fd,
            "iommufdStat": self.iommufd_stat.to_json(),
            "providerAdmission": self.provider_admission.to_json(),
        }


@dataclass(frozen=True)
class DirectPathLaunchPlan:
    qemu: QemuBinaryIdentity
    lease: LeaseBinding
    profile: MachineProfile
    qmp: QmpSocketBinding
    devices: Sequence[DeviceFdBinding]

    def __post_init__(self) -> None:
        for field, expected_type in (
            ("qemu", QemuBinaryIdentity),
            ("lease", LeaseBinding),
            ("profile", MachineProfile),
            ("qmp", QmpSocketBinding),
        ):
            if not isinstance(getattr(self, field), expected_type):
                _reject(Reason.INVALID_ARGUMENT, f"{field} has the wrong type")
        if getattr(self.lease, "_verified_provenance", None) is not _VERIFIED_LEASE_PROVENANCE:
            _reject(Reason.INVALID_LEASE_BINDING, "lease provenance is not verified")
        self.lease.require_active()
        if isinstance(self.devices, (str, bytes)):
            _reject(Reason.INVALID_DEVICE_BINDING, "devices must be a sequence of bindings")
        try:
            devices = tuple(self.devices)
        except TypeError:
            _reject(Reason.INVALID_DEVICE_BINDING, "devices must be an iterable of bindings")
        if not devices:
            _reject(Reason.INVALID_DEVICE_BINDING, "at least one device is required")
        if any(not isinstance(device, DeviceFdBinding) for device in devices):
            _reject(Reason.INVALID_DEVICE_BINDING, "devices contain a non-binding value")
        if any(
            getattr(device, "_verified_provenance", None) is not _VERIFIED_DEVICE_PROVENANCE
            for device in devices
        ):
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "device provenance is not verified")
        devices = tuple(sorted(devices, key=lambda item: (item.guest_slot.index, item.bdf)))
        _validate_device_set(devices)
        lease_members = frozenset(self.lease.members)
        for device in devices:
            if device._verified_provenance is not _VERIFIED_DEVICE_PROVENANCE:
                _reject(Reason.INVALID_PROVIDER_ADMISSION, "device provenance is not verified")
            admission = device.provider_admission
            if not set(admission.group_members).issubset(lease_members):
                _reject(
                    Reason.LEASE_DEVICE_SCOPE_MISMATCH,
                    "device or dependency group member is outside the lease",
                )
            if admission.snapshot_epoch != self.lease.inventory_epoch:
                _reject(
                    Reason.LEASE_DEVICE_SCOPE_MISMATCH,
                    "provider inventory epoch differs from the lease",
                )
            if not hmac.compare_digest(admission.lease_binding_hash, self.lease.binding_hash):
                _reject(
                    Reason.LEASE_DEVICE_SCOPE_MISMATCH,
                    "device admission belongs to a different lease",
                )
        object.__setattr__(self, "devices", devices)

    def to_json(self) -> dict[str, Any]:
        return {
            "devices": [device.to_json() for device in self.devices],
            "lease": self.lease.to_json(),
            "profile": self.profile.to_json(),
            "qemu": self.qemu.to_json(),
            "qmp": self.qmp.to_json(),
        }


def _validate_device_set(devices: tuple[DeviceFdBinding, ...]) -> None:
    bdfs: set[str] = set()
    slot_indexes: set[int] = set()
    root_addresses: set[int] = set()
    cdev_fds: set[int] = set()
    iommufd_tokens: dict[int, FdStatToken] = {}
    iommufd_fds: set[int] = set()
    provider_epochs: set[int] = set()
    provider_topologies: set[str] = set()
    provider_binding_hashes: set[str] = set()
    fd_identities: dict[tuple[int, int, int], tuple[int, str]] = {}
    group_contracts: dict[str, tuple[tuple[str, ...], int, FdStatToken]] = {}
    member_groups: dict[str, str] = {}

    for device in devices:
        if device.bdf in bdfs:
            _reject(Reason.INVALID_DEVICE_BINDING, "duplicate BDF")
        if device.guest_slot.index in slot_indexes:
            _reject(Reason.INVALID_DEVICE_BINDING, "duplicate guest slot index")
        if device.guest_slot.root_port_address in root_addresses:
            _reject(Reason.INVALID_DEVICE_BINDING, "duplicate root-port address")
        if device.cdev_fd in cdev_fds:
            _reject(Reason.FD_ROLE_CONFLICT, "cdev fd is assigned more than once")
        if device.cdev_fd in iommufd_fds or device.iommufd_fd in cdev_fds:
            _reject(Reason.FD_ROLE_CONFLICT, "fd is assigned both cdev and iommufd roles")
        prior_token = iommufd_tokens.get(device.iommufd_fd)
        if prior_token is not None and prior_token != device.iommufd_stat:
            _reject(Reason.FD_ROLE_CONFLICT, "shared iommufd has conflicting stat tokens")
        if device.provider_admission.fd_binding_hash in provider_binding_hashes:
            _reject(Reason.INVALID_PROVIDER_ADMISSION, "provider fd binding was reused")
        group_id = device.provider_admission.iommu_group
        group_members = device.provider_admission.group_members
        prior_group = group_contracts.get(group_id)
        if prior_group is not None:
            prior_members, prior_fd, prior_stat = prior_group
            if group_members != prior_members:
                _reject(
                    Reason.INVALID_PROVIDER_ADMISSION,
                    "one IOMMU group ID has conflicting complete member sets",
                )
            if device.iommufd_fd != prior_fd or device.iommufd_stat != prior_stat:
                _reject(
                    Reason.FD_ROLE_CONFLICT,
                    "one IOMMU group must share one IOMMUFD file description",
                )
        for member in group_members:
            prior_group_id = member_groups.get(member)
            if prior_group_id is not None and prior_group_id != group_id:
                _reject(
                    Reason.INVALID_PROVIDER_ADMISSION,
                    "one PCI member appears under different IOMMU group IDs",
                )
        for fd, token, role in (
            (device.cdev_fd, device.cdev_stat, "cdev"),
            (device.iommufd_fd, device.iommufd_stat, "iommufd"),
        ):
            identity = (token.device, token.inode, token.rdev)
            prior_identity = fd_identities.get(identity)
            if (
                prior_identity is not None
                and prior_identity[0] != fd
                and not (role == prior_identity[1] == "iommufd")
            ):
                _reject(
                    Reason.FD_ROLE_CONFLICT,
                    f"{role} fd aliases inode/devt already bound as {prior_identity[1]}",
                )
            fd_identities[identity] = (fd, role)
        bdfs.add(device.bdf)
        slot_indexes.add(device.guest_slot.index)
        root_addresses.add(device.guest_slot.root_port_address)
        cdev_fds.add(device.cdev_fd)
        iommufd_fds.add(device.iommufd_fd)
        iommufd_tokens[device.iommufd_fd] = device.iommufd_stat
        provider_epochs.add(device.provider_admission.snapshot_epoch)
        provider_topologies.add(device.provider_admission.topology_hash)
        provider_binding_hashes.add(device.provider_admission.fd_binding_hash)
        group_contracts.setdefault(
            group_id,
            (group_members, device.iommufd_fd, device.iommufd_stat),
        )
        for member in group_members:
            member_groups[member] = group_id
    if len(provider_epochs) != 1 or len(provider_topologies) != 1:
        _reject(
            Reason.INVALID_PROVIDER_ADMISSION,
            "all device admissions must share one inventory snapshot",
        )


@dataclass(frozen=True)
class FdExpectation:
    fd: int
    roles: tuple[str, ...]
    stat: FdStatToken

    def __post_init__(self) -> None:
        _require_plain_int(
            self.fd,
            minimum=MIN_INHERITED_FD,
            maximum=None,
            reason_code=Reason.INVALID_DEVICE_BINDING,
            field="fd",
        )
        if not self.roles or tuple(sorted(set(self.roles))) != self.roles:
            _reject(Reason.INVALID_DEVICE_BINDING, "fd roles must be a sorted unique tuple")
        if not isinstance(self.stat, FdStatToken):
            _reject(Reason.INVALID_DEVICE_BINDING, "fd stat must be FdStatToken")

    def to_json(self) -> dict[str, Any]:
        return {"fd": self.fd, "roles": list(self.roles), "stat": self.stat.to_json()}


@dataclass(frozen=True)
class SpawnSpec:
    """Canonical process data for an exact trusted ``Popen`` call.

    After :func:`validate_before_spawn`, the coordinator must immediately call
    ``subprocess.Popen(**spec.popen_kwargs())`` without adding or replacing any
    keyword.  In particular, the empty environment prevents ``LD_*``,
    ``PYTHON*`` and ``QEMU_*`` injection inherited from the coordinator.
    """

    plan: DirectPathLaunchPlan
    argv: tuple[str, ...]
    pass_fds: tuple[int, ...]
    fd_expectations: tuple[FdExpectation, ...]
    qemu_identity: QemuBinaryIdentity
    qmp_binding: QmpSocketBinding
    qemu_binary_hash: str
    fd_binding_hash: str
    argv_hash: str
    plan_hash: str
    shell: bool = False
    close_fds: bool = True
    spawn_platform: str = "posix"
    environment: tuple[tuple[str, str], ...] = ()
    trusted_cwd: str = "/"

    def __post_init__(self) -> None:
        _validate_spawn_spec_canonical(self)

    def popen_kwargs(self) -> dict[str, Any]:
        _validate_spawn_spec_canonical(self)
        self.plan.lease.require_active()
        return {
            "args": self.argv,
            "close_fds": self.close_fds,
            "cwd": self.trusted_cwd,
            "env": dict(self.environment),
            "pass_fds": self.pass_fds,
            "shell": self.shell,
        }


StatPath = Callable[[Path], os.stat_result]
Fstat = Callable[[int], os.stat_result]
FileHasher = Callable[[Path], str]


def capture_qemu_binary_identity(
    path: str | os.PathLike[str],
    *,
    stat_path: StatPath = os.stat,
    lstat_path: StatPath = os.lstat,
    file_hasher: FileHasher = _hash_file,
) -> QemuBinaryIdentity:
    """Capture a non-symlink executable's content and stat identity."""

    canonical = _canonical_absolute_path(
        path,
        reason_code=Reason.INVALID_QEMU_PATH,
        field="qemu.path",
    )
    try:
        link_stat = lstat_path(canonical)
        target_stat = stat_path(canonical)
    except OSError as error:
        _reject(Reason.INVALID_QEMU_PATH, f"cannot stat QEMU executable: {error}")
    if stat.S_ISLNK(link_stat.st_mode):
        _reject(Reason.INVALID_QEMU_PATH, "QEMU executable must not be a symbolic link")
    token = BinaryStatToken.from_stat(target_stat)
    if not os.access(canonical, os.X_OK):
        _reject(Reason.INVALID_QEMU_PATH, "QEMU file is not executable by the caller")
    if (link_stat.st_dev, link_stat.st_ino) != (target_stat.st_dev, target_stat.st_ino):
        _reject(Reason.INVALID_QEMU_PATH, "lstat/stat identity mismatch")
    try:
        sha256 = file_hasher(canonical)
    except OSError as error:
        _reject(Reason.INVALID_QEMU_PATH, f"cannot hash QEMU executable: {error}")
    _require_hash(sha256, reason_code=Reason.INVALID_QEMU_PATH, field="qemu.sha256")
    try:
        after_stat = BinaryStatToken.from_stat(stat_path(canonical))
    except OSError as error:
        _reject(Reason.INVALID_QEMU_PATH, f"cannot restat QEMU executable: {error}")
    if after_stat != token:
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, "executable changed while hashing")
    return QemuBinaryIdentity(path=canonical, sha256=sha256, stat=token)


def capture_fd_stat(fd: int, *, fstat: Fstat = os.fstat) -> FdStatToken:
    """Capture the immutable identity token for an already-open provider fd."""

    _require_plain_int(
        fd,
        minimum=MIN_INHERITED_FD,
        maximum=None,
        reason_code=Reason.INVALID_DEVICE_BINDING,
        field="fd",
    )
    try:
        return FdStatToken.from_stat(fstat(fd))
    except OSError as error:
        _reject(Reason.FD_IDENTITY_MISMATCH, f"cannot fstat fd {fd}: {error}")


def _verify_binary(
    expected: QemuBinaryIdentity,
    *,
    stat_path: StatPath,
    lstat_path: StatPath,
    file_hasher: FileHasher,
) -> None:
    try:
        observed_link = lstat_path(expected.path)
        observed = BinaryStatToken.from_stat(stat_path(expected.path))
    except (OSError, LaunchContractError) as error:
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, f"cannot verify executable: {error}")
    if stat.S_ISLNK(observed_link.st_mode):
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, "executable became a symlink")
    if (observed_link.st_dev, observed_link.st_ino) != (observed.device, observed.inode):
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, "lstat/stat identity mismatch")
    if observed != expected.stat:
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, "executable stat identity changed")
    if not os.access(expected.path, os.X_OK):
        _reject(Reason.QEMU_BINARY_IDENTITY_MISMATCH, "executable permission was revoked")
    try:
        observed_hash = file_hasher(expected.path)
    except OSError as error:
        _reject(Reason.QEMU_BINARY_HASH_MISMATCH, f"cannot hash executable: {error}")
    if not isinstance(observed_hash, str) or not hmac.compare_digest(
        observed_hash, expected.sha256
    ):
        _reject(Reason.QEMU_BINARY_HASH_MISMATCH, "executable content hash changed")


def _verify_qmp_runtime(
    binding: QmpSocketBinding,
    *,
    stat_path: StatPath,
    lstat_path: StatPath,
) -> None:
    try:
        observed = DirectoryStatToken.from_stat(stat_path(binding.runtime_directory))
    except (OSError, LaunchContractError) as error:
        _reject(Reason.QMP_RUNTIME_IDENTITY_MISMATCH, f"cannot verify QMP directory: {error}")
    if observed != binding.runtime_stat:
        _reject(Reason.QMP_RUNTIME_IDENTITY_MISMATCH, "QMP runtime directory changed")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and observed.owner_uid != getuid():
        _reject(Reason.QMP_RUNTIME_IDENTITY_MISMATCH, "QMP runtime directory owner is not caller")
    try:
        lstat_path(binding.socket_path)
    except FileNotFoundError:
        return
    except OSError as error:
        _reject(Reason.INVALID_QMP_SOCKET, f"cannot prove QMP socket absence: {error}")
    _reject(Reason.QMP_SOCKET_ALREADY_EXISTS, "QMP socket path must not exist before launch")


def device_binding_from_vfio_launch_result(
    result: object,
    guest_slot: GuestSlot,
    lease: LeaseBinding,
    *,
    fstat: Fstat = os.fstat,
) -> DeviceFdBinding:
    """Snapshot and verify one admitted raw VFIO result for rendering.

    This adapter is the supported bridge from ``vfio_launch_handles``.  It
    rejects closed results, inconsistent request/metadata, wrong node roles,
    and fds whose kernel identity no longer matches the provider metadata.
    """

    from . import vfio_launch_handles as handles

    if not handles.is_production_launch_result(result) or not result.handles_usable:
        _reject(
            Reason.INVALID_PROVIDER_ADMISSION,
            "live production-provenance VfioLaunchResult is required",
        )
    if not isinstance(guest_slot, GuestSlot):
        _reject(Reason.INVALID_DEVICE_BINDING, "guest_slot must be a GuestSlot")
    if (
        not isinstance(lease, LeaseBinding)
        or lease._verified_provenance is not _VERIFIED_LEASE_PROVENANCE
    ):
        _reject(Reason.INVALID_LEASE_BINDING, "verified lease binding is required")
    metadata = result.metadata
    request = result.request
    if (
        metadata.bdf != request.bdf
        or metadata.snapshot_epoch != request.snapshot_epoch
        or metadata.topology_hash != request.topology_hash
        or metadata.identity_hash != request.expected_identity_hash
        or metadata.group_hash != request.expected_group_hash
        or metadata.handoff_mode != handles.HANDOFF_MODE
        or metadata.snapshot_binding != handles.SNAPSHOT_BINDING
        or metadata.cdev.role != "vfio-cdev"
        or metadata.iommufd.role != "iommufd"
    ):
        _reject(Reason.INVALID_PROVIDER_ADMISSION, "provider request and metadata disagree")
    if metadata.snapshot_epoch != lease.inventory_epoch or not set(
        metadata.group_members
    ).issubset(lease.members):
        _reject(
            Reason.LEASE_DEVICE_SCOPE_MISMATCH,
            "provider result is outside the lease inventory/member scope",
        )

    identity_hash = handles.vfio.compute_identity_hash(metadata.bdf, metadata.identity)
    group_hash = handles.vfio.compute_group_hash(
        metadata.bdf,
        metadata.iommu_group,
        metadata.group_members,
    )
    verification_state = handles.vfio.DeviceState(
        bdf=metadata.bdf,
        identity=metadata.identity,
        driver="vfio-pci",
        iommu_group=metadata.iommu_group,
        group_members=metadata.group_members,
        noiommu_node_present=False,
        group_node=Path("/dev/vfio") / metadata.iommu_group,
        cdev_node=metadata.cdev.path,
        cdev_device_number=(
            metadata.cdev.character_device_major,
            metadata.cdev.character_device_minor,
        ),
    )
    fd_binding_hash = handles.compute_fd_binding_hash(
        request=request,
        state=verification_state,
        identity_hash=identity_hash,
        group_hash=group_hash,
        cdev=metadata.cdev,
        iommufd=metadata.iommufd,
    )
    if (
        not hmac.compare_digest(identity_hash, metadata.identity_hash)
        or not hmac.compare_digest(group_hash, metadata.group_hash)
        or not hmac.compare_digest(fd_binding_hash, metadata.fd_binding_hash)
    ):
        _reject(Reason.INVALID_PROVIDER_ADMISSION, "provider metadata hash is invalid")

    cdev_stat = capture_fd_stat(result.device_fd, fstat=fstat)
    iommufd_stat = capture_fd_stat(result.iommufd_fd, fstat=fstat)
    for token, opened, role in (
        (cdev_stat, metadata.cdev, "vfio-cdev"),
        (iommufd_stat, metadata.iommufd, "iommufd"),
    ):
        try:
            observed_devt = (os.major(token.rdev), os.minor(token.rdev))
        except (AttributeError, OSError, ValueError) as error:
            _reject(Reason.INVALID_PROVIDER_ADMISSION, f"cannot decode {role} devt: {error}")
        expected_devt = (opened.character_device_major, opened.character_device_minor)
        if (
            token.device != opened.filesystem_device
            or token.inode != opened.inode
            or observed_devt != expected_devt
            or opened.cloexec is not True
        ):
            _reject(Reason.FD_IDENTITY_MISMATCH, f"{role} fd disagrees with provider metadata")

    return DeviceFdBinding._from_verified(
        bdf=metadata.bdf,
        guest_slot=guest_slot,
        cdev_fd=result.device_fd,
        cdev_stat=cdev_stat,
        iommufd_fd=result.iommufd_fd,
        iommufd_stat=iommufd_stat,
        identity_hash=_normalize_external_hash(metadata.identity_hash, field="identity_hash"),
        group_hash=_normalize_external_hash(metadata.group_hash, field="group_hash"),
        provider_admission=ProviderAdmission(
            snapshot_epoch=metadata.snapshot_epoch,
            topology_hash=_normalize_external_hash(metadata.topology_hash, field="topology_hash"),
            fd_binding_hash=_normalize_external_hash(
                metadata.fd_binding_hash,
                field="fd_binding_hash",
            ),
            iommu_group=metadata.iommu_group,
            group_members=tuple(metadata.group_members),
            lease_binding_hash=lease.binding_hash,
            handoff_mode=metadata.handoff_mode,
        ),
    )


def _fd_expectations(devices: Sequence[DeviceFdBinding]) -> tuple[FdExpectation, ...]:
    by_fd: dict[int, tuple[FdStatToken, set[str]]] = {}
    for device in devices:
        for fd, token, role in (
            (device.cdev_fd, device.cdev_stat, f"cdev:{device.bdf}"),
            (device.iommufd_fd, device.iommufd_stat, "iommufd"),
        ):
            prior = by_fd.get(fd)
            if prior is None:
                by_fd[fd] = (token, {role})
            elif prior[0] != token:
                _reject(Reason.FD_ROLE_CONFLICT, f"fd {fd} has conflicting identity tokens")
            else:
                prior[1].add(role)
    return tuple(
        FdExpectation(fd=fd, roles=tuple(sorted(roles)), stat=token)
        for fd, (token, roles) in sorted(by_fd.items())
    )


def _verify_fds(expectations: Sequence[FdExpectation], *, fstat: Fstat) -> None:
    for expectation in expectations:
        try:
            observed = FdStatToken.from_stat(fstat(expectation.fd))
        except (OSError, LaunchContractError) as error:
            _reject(
                Reason.FD_IDENTITY_MISMATCH,
                f"fd {expectation.fd} cannot be verified: {error}",
            )
        if observed != expectation.stat:
            _reject(Reason.FD_IDENTITY_MISMATCH, f"fd {expectation.fd} was substituted")


def _render_argv(plan: DirectPathLaunchPlan) -> tuple[str, ...]:
    argv = [
        str(plan.qemu.path),
        "-machine",
        plan.profile.machine_type,
        "-accel",
        "kvm",
        "-S",
        "-nodefaults",
        "-display",
        "none",
        "-serial",
        "none",
        "-m",
        str(plan.profile.memory_mib),
        "-smp",
        str(plan.profile.vcpu_count),
        "-monitor",
        "none",
        "-qmp",
        f"unix:{plan.qmp.socket_path},server=on,wait=off",
    ]

    iommufd_ids = {
        fd: f"iommufd{index}"
        for index, fd in enumerate(sorted({device.iommufd_fd for device in plan.devices}))
    }
    for fd, object_id in iommufd_ids.items():
        argv.extend(("-object", f"iommufd,id={object_id},fd={fd}"))

    for device in plan.devices:
        slot = device.guest_slot
        argv.extend(
            (
                "-device",
                (
                    f"pcie-root-port,id={slot.root_port_id},bus=pcie.0,"
                    f"addr={slot.root_port_address:02x}.0,chassis={slot.index + 1},"
                    f"slot={slot.root_port_address},hotplug=off,"
                    "x-do-not-expose-native-hotplug-cap=on"
                ),
                "-device",
                (
                    f"vfio-pci,id={slot.endpoint_id},fd={device.cdev_fd},"
                    f"iommufd={iommufd_ids[device.iommufd_fd]},bus={slot.root_port_id},"
                    "addr=00.0,rombar=0"
                ),
            )
        )
    return tuple(argv)


def _reject_forbidden_arguments(argv: Sequence[str]) -> None:
    forbidden = ("host=", "sysfsdev=", "noiommu", "legacy", "getfd", "add-fd")
    for argument in argv[1:]:
        lowered = argument.lower()
        if any(marker in lowered for marker in forbidden):
            _reject(Reason.FORBIDDEN_RENDERED_ARGUMENT, f"forbidden argument: {argument}")


@dataclass(frozen=True)
class _CanonicalSpawnFields:
    argv: tuple[str, ...]
    pass_fds: tuple[int, ...]
    fd_expectations: tuple[FdExpectation, ...]
    qemu_binary_hash: str
    fd_binding_hash: str
    argv_hash: str
    plan_hash: str
    environment: tuple[tuple[str, str], ...]
    trusted_cwd: str


def _canonical_spawn_fields(plan: DirectPathLaunchPlan) -> _CanonicalSpawnFields:
    if not isinstance(plan, DirectPathLaunchPlan):
        _reject(Reason.NON_CANONICAL_SPAWN_SPEC, "canonical launch plan is missing")
    expectations = _fd_expectations(plan.devices)
    argv = _render_argv(plan)
    _reject_forbidden_arguments(argv)
    pass_fds = tuple(expectation.fd for expectation in expectations)
    fd_binding_hash = _digest(
        {
            "devices": [device.to_json() for device in plan.devices],
            "expectations": [item.to_json() for item in expectations],
        }
    )
    argv_hash = _digest({"argv": list(argv)})
    plan_hash = _digest(
        {
            "argv": list(argv),
            "argvHash": argv_hash,
            "closeFds": True,
            "environment": [],
            "fdBindingHash": fd_binding_hash,
            "lease": plan.lease.to_json(),
            "passFds": list(pass_fds),
            "profile": plan.profile.to_json(),
            "qemu": plan.qemu.to_json(),
            "qmp": plan.qmp.to_json(),
            "shell": False,
            "spawnPlatform": "posix",
            "trustedCwd": "/",
        }
    )
    return _CanonicalSpawnFields(
        argv=argv,
        pass_fds=pass_fds,
        fd_expectations=expectations,
        qemu_binary_hash=plan.qemu.sha256,
        fd_binding_hash=fd_binding_hash,
        argv_hash=argv_hash,
        plan_hash=plan_hash,
        environment=(),
        trusted_cwd="/",
    )


def _validate_spawn_spec_canonical(spec: SpawnSpec) -> None:
    if not isinstance(spec.plan, DirectPathLaunchPlan):
        _reject(Reason.NON_CANONICAL_SPAWN_SPEC, "spec plan has the wrong type")
    canonical = _canonical_spawn_fields(spec.plan)
    if (
        not isinstance(spec.argv, tuple)
        or spec.argv != canonical.argv
        or not isinstance(spec.pass_fds, tuple)
        or spec.pass_fds != canonical.pass_fds
        or not isinstance(spec.fd_expectations, tuple)
        or spec.fd_expectations != canonical.fd_expectations
        or spec.qemu_identity != spec.plan.qemu
        or spec.qmp_binding != spec.plan.qmp
        or spec.qemu_binary_hash != canonical.qemu_binary_hash
        or spec.fd_binding_hash != canonical.fd_binding_hash
        or spec.argv_hash != canonical.argv_hash
        or spec.plan_hash != canonical.plan_hash
        or spec.shell is not False
        or spec.close_fds is not True
        or spec.spawn_platform != "posix"
        or spec.environment != canonical.environment
        or spec.trusted_cwd != canonical.trusted_cwd
    ):
        _reject(
            Reason.NON_CANONICAL_SPAWN_SPEC,
            "spawn fields do not exactly match canonical plan rendering",
        )


def render_launch(
    plan: DirectPathLaunchPlan,
    *,
    fstat: Fstat = os.fstat,
    stat_path: StatPath = os.stat,
    lstat_path: StatPath = os.lstat,
    file_hasher: FileHasher = _hash_file,
) -> SpawnSpec:
    """Validate all identities and deterministically render one spawn spec."""

    if not isinstance(plan, DirectPathLaunchPlan):
        _reject(Reason.INVALID_ARGUMENT, "plan must be a DirectPathLaunchPlan")
    plan.lease.require_active()
    _verify_binary(
        plan.qemu,
        stat_path=stat_path,
        lstat_path=lstat_path,
        file_hasher=file_hasher,
    )
    _verify_qmp_runtime(plan.qmp, stat_path=stat_path, lstat_path=lstat_path)
    canonical = _canonical_spawn_fields(plan)
    _verify_fds(canonical.fd_expectations, fstat=fstat)
    return SpawnSpec(
        plan=plan,
        argv=canonical.argv,
        pass_fds=canonical.pass_fds,
        fd_expectations=canonical.fd_expectations,
        qemu_identity=plan.qemu,
        qmp_binding=plan.qmp,
        qemu_binary_hash=canonical.qemu_binary_hash,
        fd_binding_hash=canonical.fd_binding_hash,
        argv_hash=canonical.argv_hash,
        plan_hash=canonical.plan_hash,
        environment=canonical.environment,
        trusted_cwd=canonical.trusted_cwd,
    )


def validate_before_spawn(
    spec: SpawnSpec,
    *,
    fstat: Fstat = os.fstat,
    stat_path: StatPath = os.stat,
    lstat_path: StatPath = os.lstat,
    file_hasher: FileHasher = _hash_file,
    platform_name: str = os.name,
) -> SpawnSpec:
    """Revalidate executable, socket absence, and fds immediately before spawn."""

    if not isinstance(spec, SpawnSpec):
        _reject(Reason.INVALID_ARGUMENT, "spec must be a SpawnSpec")
    spec.plan.lease.require_active()
    _validate_spawn_spec_canonical(spec)
    if platform_name != "posix":
        _reject(
            Reason.UNSUPPORTED_SPAWN_PLATFORM,
            "subprocess pass_fds handoff is POSIX-only",
        )
    _verify_binary(
        spec.qemu_identity,
        stat_path=stat_path,
        lstat_path=lstat_path,
        file_hasher=file_hasher,
    )
    _verify_qmp_runtime(
        spec.qmp_binding,
        stat_path=stat_path,
        lstat_path=lstat_path,
    )
    _verify_fds(spec.fd_expectations, fstat=fstat)
    return spec


__all__ = [
    "BinaryStatToken",
    "DeviceFdBinding",
    "DirectPathLaunchPlan",
    "DirectoryStatToken",
    "FdExpectation",
    "FdStatToken",
    "GuestSlot",
    "LaunchContractError",
    "LeaseBinding",
    "MachineProfile",
    "ProviderAdmission",
    "QemuBinaryIdentity",
    "QmpSocketBinding",
    "Reason",
    "SpawnSpec",
    "capture_fd_stat",
    "capture_qemu_binary_identity",
    "device_binding_from_vfio_launch_result",
    "lease_binding_from_launch_authorization",
    "render_launch",
    "validate_before_spawn",
]
