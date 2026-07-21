"""Authoritative, fail-closed VFIO provider acquisition.

This module deliberately has no package-local imports so that the file can be
copied into a Linux guest and executed as a standalone probe.  A successful
API call returns an open :class:`VfioProviderSession`; the caller must retain
that session for as long as QEMU may use its file descriptors and then close
it.  The standalone CLI proves acquisition and cleanup in one process.

The preferred path is a VFIO cdev bound to IOMMUFD and attached to a newly
allocated IOAS.  The legacy group/container path is disabled unless the caller
explicitly opts into the lab-only fallback.  A ``noiommu-N`` node is always a
negative proof and is never accepted by either path.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
import platform
import re
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only by non-POSIX test hosts
    fcntl = None  # type: ignore[assignment]


BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
VFIO_CDEV_RE = re.compile(r"^vfio[0-9]+$")
GROUP_RE = re.compile(r"^[0-9]+$")
SUPPORTED_IOCTL_ABI_MACHINES = frozenset({"amd64", "arm64", "aarch64", "x86_64"})

# Linux UAPI constants.  The VFIO and IOMMUFD ABIs intentionally define these
# requests with _IO(), so their numeric value does not encode a struct size.
VFIO_TYPE = ord(";")
VFIO_BASE = 100


def _io(ioctl_type: int, number: int) -> int:
    return (ioctl_type << 8) | number


VFIO_GET_API_VERSION = _io(VFIO_TYPE, VFIO_BASE + 0)
VFIO_CHECK_EXTENSION = _io(VFIO_TYPE, VFIO_BASE + 1)
VFIO_SET_IOMMU = _io(VFIO_TYPE, VFIO_BASE + 2)
VFIO_GROUP_GET_STATUS = _io(VFIO_TYPE, VFIO_BASE + 3)
VFIO_GROUP_SET_CONTAINER = _io(VFIO_TYPE, VFIO_BASE + 4)
VFIO_GROUP_UNSET_CONTAINER = _io(VFIO_TYPE, VFIO_BASE + 5)
VFIO_GROUP_GET_DEVICE_FD = _io(VFIO_TYPE, VFIO_BASE + 6)
VFIO_DEVICE_BIND_IOMMUFD = _io(VFIO_TYPE, VFIO_BASE + 18)
VFIO_DEVICE_ATTACH_IOMMUFD_PT = _io(VFIO_TYPE, VFIO_BASE + 19)
VFIO_DEVICE_DETACH_IOMMUFD_PT = _io(VFIO_TYPE, VFIO_BASE + 20)

IOMMUFD_CMD_DESTROY = 0x80
IOMMUFD_CMD_IOAS_ALLOC = 0x81
IOMMU_DESTROY = _io(ord(";"), IOMMUFD_CMD_DESTROY)
IOMMU_IOAS_ALLOC = _io(ord(";"), IOMMUFD_CMD_IOAS_ALLOC)

VFIO_API_VERSION = 0
VFIO_TYPE1_IOMMU = 1
VFIO_TYPE1V2_IOMMU = 3
VFIO_NOIOMMU_IOMMU = 8
VFIO_GROUP_FLAGS_VIABLE = 1 << 0


class Reason:
    """Stable machine-facing rejection codes."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_BDF = "INVALID_BDF"
    INVALID_SNAPSHOT_EPOCH = "INVALID_SNAPSHOT_EPOCH"
    INVALID_TOPOLOGY_HASH = "INVALID_TOPOLOGY_HASH"
    INVALID_EXPECTED_IDENTITY_HASH = "INVALID_EXPECTED_IDENTITY_HASH"
    INVALID_EXPECTED_GROUP_HASH = "INVALID_EXPECTED_GROUP_HASH"
    UNSUPPORTED_IOCTL_ABI = "UNSUPPORTED_IOCTL_ABI"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    DEVICE_IDENTITY_UNKNOWN = "DEVICE_IDENTITY_UNKNOWN"
    DEVICE_IDENTITY_STALE = "DEVICE_IDENTITY_STALE"
    DEVICE_NOT_VFIO_BOUND = "DEVICE_NOT_VFIO_BOUND"
    DEVICE_OWNER_STALE = "DEVICE_OWNER_STALE"
    IOMMU_GROUP_UNKNOWN = "IOMMU_GROUP_UNKNOWN"
    IOMMU_GROUP_STALE = "IOMMU_GROUP_STALE"
    DEVICE_NO_IOMMU_DMA_ISOLATION = "DEVICE_NO_IOMMU_DMA_ISOLATION"
    VFIO_CDEV_UNAVAILABLE = "VFIO_CDEV_UNAVAILABLE"
    VFIO_NODE_UNKNOWN = "VFIO_NODE_UNKNOWN"
    VFIO_NODE_MISMATCH = "VFIO_NODE_MISMATCH"
    IOMMUFD_OPEN_FAILED = "IOMMUFD_OPEN_FAILED"
    VFIO_CDEV_OPEN_FAILED = "VFIO_CDEV_OPEN_FAILED"
    IOMMUFD_IOAS_ALLOC_FAILED = "IOMMUFD_IOAS_ALLOC_FAILED"
    VFIO_DEVICE_BIND_IOMMUFD_FAILED = "VFIO_DEVICE_BIND_IOMMUFD_FAILED"
    VFIO_DEVICE_ATTACH_IOAS_FAILED = "VFIO_DEVICE_ATTACH_IOAS_FAILED"
    LEGACY_LAB_ONLY_DISABLED = "LEGACY_LAB_ONLY_DISABLED"
    VFIO_CONTAINER_OPEN_FAILED = "VFIO_CONTAINER_OPEN_FAILED"
    VFIO_GROUP_OPEN_FAILED = "VFIO_GROUP_OPEN_FAILED"
    VFIO_API_VERSION_MISMATCH = "VFIO_API_VERSION_MISMATCH"
    VFIO_GROUP_STATUS_FAILED = "VFIO_GROUP_STATUS_FAILED"
    VFIO_GROUP_NOT_VIABLE = "VFIO_GROUP_NOT_VIABLE"
    VFIO_GROUP_SET_CONTAINER_FAILED = "VFIO_GROUP_SET_CONTAINER_FAILED"
    VFIO_TYPE1_UNSUPPORTED = "VFIO_TYPE1_UNSUPPORTED"
    VFIO_SET_IOMMU_FAILED = "VFIO_SET_IOMMU_FAILED"
    VFIO_GET_DEVICE_FD_FAILED = "VFIO_GET_DEVICE_FD_FAILED"
    PROVIDER_STATE_UNKNOWN = "PROVIDER_STATE_UNKNOWN"
    PROVIDER_CLEANUP_FAILED = "PROVIDER_CLEANUP_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ProviderError(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        *,
        bdf: str | None = None,
        stage: str | None = None,
        os_errno: int | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.bdf = bdf
        self.stage = stage
        self.os_errno = os_errno
        super().__init__(reason_code)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schemaVersion": 1,
            "status": "error",
            "reasonCode": self.reason_code,
        }
        if self.bdf is not None:
            result["bdf"] = self.bdf
        if self.stage is not None:
            result["stage"] = self.stage
        if self.os_errno is not None:
            result["errno"] = self.os_errno
        return result


@dataclass(frozen=True)
class PciIdentity:
    vendor_id: int
    device_id: int
    subsystem_vendor_id: int
    subsystem_device_id: int
    class_code: int
    revision: int

    def to_json(self) -> dict[str, str]:
        return {
            "vendorId": f"0x{self.vendor_id:04x}",
            "deviceId": f"0x{self.device_id:04x}",
            "subsystemVendorId": f"0x{self.subsystem_vendor_id:04x}",
            "subsystemDeviceId": f"0x{self.subsystem_device_id:04x}",
            "classCode": f"0x{self.class_code:06x}",
            "revision": f"0x{self.revision:02x}",
        }


@dataclass(frozen=True)
class DeviceState:
    bdf: str
    identity: PciIdentity
    driver: str
    iommu_group: str
    group_members: tuple[str, ...]
    noiommu_node_present: bool
    group_node: Path
    cdev_node: Path | None
    cdev_device_number: tuple[int, int] | None


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_identity_preimage(bdf: str, identity: PciIdentity) -> bytes:
    """Return the versioned bytes hashed by the inventory publisher/provider."""

    return _canonical_json_bytes(
        {
            "bdf": bdf.lower(),
            "classCode": identity.class_code,
            "deviceId": identity.device_id,
            "kind": "qman-vfio-identity-v1",
            "revision": identity.revision,
            "subsystemDeviceId": identity.subsystem_device_id,
            "subsystemVendorId": identity.subsystem_vendor_id,
            "vendorId": identity.vendor_id,
        }
    )


def compute_identity_hash(bdf: str, identity: PciIdentity) -> str:
    return hashlib.sha256(canonical_identity_preimage(bdf, identity)).hexdigest()


def canonical_group_preimage(
    bdf: str, iommu_group: str, group_members: Sequence[str]
) -> bytes:
    """Return the versioned bytes binding a BDF to its complete IOMMU group."""

    return _canonical_json_bytes(
        {
            "bdf": bdf.lower(),
            "groupId": iommu_group,
            "kind": "qman-vfio-iommu-group-v1",
            "members": sorted(member.lower() for member in group_members),
        }
    )


def compute_group_hash(
    bdf: str, iommu_group: str, group_members: Sequence[str]
) -> str:
    return hashlib.sha256(
        canonical_group_preimage(bdf, iommu_group, group_members)
    ).hexdigest()


class StateReader(Protocol):
    def capture(self, bdf: str) -> DeviceState: ...


class KernelOps(Protocol):
    def open_node(
        self,
        path: Path,
        *,
        failure_reason: str,
        expected_device_number: tuple[int, int] | None = None,
        bdf: str,
    ) -> int: ...

    def ioctl(
        self,
        fd: int,
        request: int,
        argument: int | bytes | bytearray = 0,
        *,
        mutate: bool = False,
    ) -> int: ...

    def close(self, fd: int) -> None: ...


def _read_required_hex(path: Path, reason: str, bdf: str) -> int:
    try:
        text = path.read_text(encoding="ascii").strip()
        if not text:
            raise ValueError("empty")
        return int(text, 0)
    except (OSError, UnicodeError, ValueError) as error:
        raise ProviderError(reason, bdf=bdf, stage=path.name) from error


def _path_exists_authoritatively(path: Path, bdf: str) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ProviderError(
            Reason.PROVIDER_STATE_UNKNOWN,
            bdf=bdf,
            stage="stat-provider-node",
            os_errno=error.errno,
        ) from error


class LinuxSysfsStateReader:
    """Capture the exact target identity, group and VFIO node from Linux."""

    def __init__(
        self,
        *,
        sysfs_root: Path = Path("/sys/bus/pci/devices"),
        vfio_root: Path = Path("/dev/vfio"),
    ) -> None:
        self.sysfs_root = sysfs_root
        self.vfio_root = vfio_root

    def capture(self, bdf: str) -> DeviceState:
        link = self.sysfs_root / bdf
        try:
            device = link.resolve(strict=True)
        except FileNotFoundError as error:
            raise ProviderError(Reason.DEVICE_NOT_FOUND, bdf=bdf) from error
        except OSError as error:
            raise ProviderError(
                Reason.PROVIDER_STATE_UNKNOWN,
                bdf=bdf,
                stage="resolve-device",
                os_errno=error.errno,
            ) from error
        if device.name.lower() != bdf:
            raise ProviderError(
                Reason.DEVICE_IDENTITY_UNKNOWN,
                bdf=bdf,
                stage="device-sysfs-target",
            )

        identity = PciIdentity(
            vendor_id=_read_required_hex(device / "vendor", Reason.DEVICE_IDENTITY_UNKNOWN, bdf),
            device_id=_read_required_hex(device / "device", Reason.DEVICE_IDENTITY_UNKNOWN, bdf),
            subsystem_vendor_id=_read_required_hex(
                device / "subsystem_vendor", Reason.DEVICE_IDENTITY_UNKNOWN, bdf
            ),
            subsystem_device_id=_read_required_hex(
                device / "subsystem_device", Reason.DEVICE_IDENTITY_UNKNOWN, bdf
            ),
            class_code=_read_required_hex(device / "class", Reason.DEVICE_IDENTITY_UNKNOWN, bdf),
            revision=_read_required_hex(device / "revision", Reason.DEVICE_IDENTITY_UNKNOWN, bdf),
        )

        driver_link = device / "driver"
        try:
            driver = driver_link.resolve(strict=True).name
        except FileNotFoundError as error:
            raise ProviderError(Reason.DEVICE_NOT_VFIO_BOUND, bdf=bdf) from error
        except OSError as error:
            raise ProviderError(
                Reason.PROVIDER_STATE_UNKNOWN,
                bdf=bdf,
                stage="resolve-driver",
                os_errno=error.errno,
            ) from error
        if driver != "vfio-pci":
            raise ProviderError(Reason.DEVICE_NOT_VFIO_BOUND, bdf=bdf)

        group_link = device / "iommu_group"
        try:
            group_path = group_link.resolve(strict=True)
        except FileNotFoundError as error:
            raise ProviderError(Reason.IOMMU_GROUP_UNKNOWN, bdf=bdf) from error
        except OSError as error:
            raise ProviderError(
                Reason.IOMMU_GROUP_UNKNOWN,
                bdf=bdf,
                stage="resolve-iommu-group",
                os_errno=error.errno,
            ) from error
        group_id = group_path.name
        if not GROUP_RE.fullmatch(group_id):
            raise ProviderError(Reason.IOMMU_GROUP_UNKNOWN, bdf=bdf)

        try:
            entries = tuple((group_path / "devices").iterdir())
        except OSError as error:
            raise ProviderError(
                Reason.IOMMU_GROUP_UNKNOWN,
                bdf=bdf,
                stage="read-iommu-group-members",
                os_errno=error.errno,
            ) from error
        members = tuple(sorted(entry.name.lower() for entry in entries))
        if (
            not members
            or bdf not in members
            or any(not BDF_RE.fullmatch(member) for member in members)
        ):
            raise ProviderError(Reason.IOMMU_GROUP_UNKNOWN, bdf=bdf)

        noiommu = _path_exists_authoritatively(
            self.vfio_root / f"noiommu-{group_id}", bdf
        )
        group_node = self.vfio_root / group_id

        cdev_dir = device / "vfio-dev"
        if noiommu:
            # Some kernels expose a vfio-dev/vfioN sysfs entry for a no-IOMMU
            # device without creating the corresponding cdev.  The explicit
            # noiommu-N node is already authoritative negative evidence; do
            # not let incomplete cdev metadata obscure that stable rejection.
            cdev_entries = ()
        else:
            try:
                cdev_entries = tuple(cdev_dir.iterdir())
            except FileNotFoundError:
                cdev_entries = ()
            except OSError as error:
                raise ProviderError(
                    Reason.VFIO_NODE_UNKNOWN,
                    bdf=bdf,
                    stage="read-vfio-cdev",
                    os_errno=error.errno,
                ) from error
        cdev_names = tuple(
            sorted(entry.name for entry in cdev_entries if VFIO_CDEV_RE.fullmatch(entry.name))
        )
        if len(cdev_names) > 1 or (cdev_entries and len(cdev_names) != len(cdev_entries)):
            raise ProviderError(Reason.VFIO_NODE_UNKNOWN, bdf=bdf)

        cdev_node: Path | None = None
        cdev_device_number: tuple[int, int] | None = None
        if cdev_names:
            cdev_name = cdev_names[0]
            dev_text_path = cdev_dir / cdev_name / "dev"
            try:
                major_text, minor_text = dev_text_path.read_text(
                    encoding="ascii"
                ).strip().split(":", 1)
                cdev_device_number = (int(major_text), int(minor_text))
            except (OSError, UnicodeError, ValueError) as error:
                raise ProviderError(Reason.VFIO_NODE_UNKNOWN, bdf=bdf) from error
            cdev_node = self.vfio_root / "devices" / cdev_name

        return DeviceState(
            bdf=bdf,
            identity=identity,
            driver=driver,
            iommu_group=group_id,
            group_members=members,
            noiommu_node_present=noiommu,
            group_node=group_node,
            cdev_node=cdev_node,
            cdev_device_number=cdev_device_number,
        )


class PosixVfioKernel:
    def open_node(
        self,
        path: Path,
        *,
        failure_reason: str,
        expected_device_number: tuple[int, int] | None = None,
        bdf: str,
    ) -> int:
        try:
            before = path.lstat()
        except OSError as error:
            raise ProviderError(
                failure_reason,
                bdf=bdf,
                stage="stat-device-node",
                os_errno=error.errno,
            ) from error
        if not stat.S_ISCHR(before.st_mode):
            raise ProviderError(Reason.VFIO_NODE_MISMATCH, bdf=bdf)
        if expected_device_number is not None and (
            os.major(before.st_rdev), os.minor(before.st_rdev)
        ) != expected_device_number:
            raise ProviderError(Reason.VFIO_NODE_MISMATCH, bdf=bdf)

        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as error:
            raise ProviderError(
                failure_reason,
                bdf=bdf,
                stage="open-device-node",
                os_errno=error.errno,
            ) from error
        try:
            after = os.fstat(fd)
            if (
                not stat.S_ISCHR(after.st_mode)
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_rdev != after.st_rdev
            ):
                raise ProviderError(Reason.VFIO_NODE_MISMATCH, bdf=bdf)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def ioctl(
        self,
        fd: int,
        request: int,
        argument: int | bytes | bytearray = 0,
        *,
        mutate: bool = False,
    ) -> int:
        if fcntl is None:
            raise OSError(errno.ENOSYS, "VFIO ioctl is available only on POSIX")
        result = fcntl.ioctl(fd, request, argument, mutate)
        if not isinstance(result, int):
            raise OSError(errno.EPROTO, "ioctl did not return an integer")
        return result

    def close(self, fd: int) -> None:
        os.close(fd)


def _ioctl(
    kernel: KernelOps,
    fd: int,
    request: int,
    argument: int | bytes | bytearray,
    *,
    mutate: bool,
    reason: str,
    bdf: str,
    stage: str,
) -> int:
    try:
        return kernel.ioctl(fd, request, argument, mutate=mutate)
    except OSError as error:
        raise ProviderError(
            reason, bdf=bdf, stage=stage, os_errno=error.errno
        ) from error


def _cleanup_cdev(
    kernel: KernelOps,
    *,
    bdf: str,
    device_fd: int | None,
    iommufd_fd: int | None,
    ioas_id: int | None,
    attached: bool,
) -> None:
    failed = False
    if device_fd is not None and attached:
        detach = bytearray(struct.pack("=III", 12, 0, 0))
        try:
            kernel.ioctl(
                device_fd, VFIO_DEVICE_DETACH_IOMMUFD_PT, detach, mutate=True
            )
        except OSError:
            failed = True
    if iommufd_fd is not None and ioas_id is not None:
        destroy = bytearray(struct.pack("=II", 8, ioas_id))
        try:
            kernel.ioctl(iommufd_fd, IOMMU_DESTROY, destroy, mutate=True)
        except OSError:
            failed = True
    for fd in (device_fd, iommufd_fd):
        if fd is None:
            continue
        try:
            kernel.close(fd)
        except OSError:
            failed = True
    if failed:
        raise ProviderError(
            Reason.PROVIDER_CLEANUP_FAILED, bdf=bdf, stage="cdev-cleanup"
        )


def _cleanup_legacy(
    kernel: KernelOps,
    *,
    bdf: str,
    device_fd: int | None,
    group_fd: int | None,
    container_fd: int | None,
    container_set: bool,
) -> None:
    failed = False
    if device_fd is not None:
        try:
            kernel.close(device_fd)
        except OSError:
            failed = True
    if group_fd is not None and container_set:
        try:
            kernel.ioctl(group_fd, VFIO_GROUP_UNSET_CONTAINER, 0, mutate=False)
        except OSError:
            failed = True
    for fd in (group_fd, container_fd):
        if fd is None:
            continue
        try:
            kernel.close(fd)
        except OSError:
            failed = True
    if failed:
        raise ProviderError(
            Reason.PROVIDER_CLEANUP_FAILED, bdf=bdf, stage="legacy-cleanup"
        )


@dataclass
class VfioProviderSession:
    proof: dict[str, Any]
    device_fd: int
    _kernel: KernelOps
    _bdf: str
    iommufd_fd: int | None = None
    ioas_id: int | None = None
    group_fd: int | None = None
    container_fd: int | None = None
    _attached: bool = False
    _container_set: bool = False
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.proof["lifecycle"] = "CLOSING"
        self.proof["handlesUsable"] = False
        device_fd = self.device_fd
        self.device_fd = -1
        try:
            if self.iommufd_fd is not None:
                iommufd_fd = self.iommufd_fd
                self.iommufd_fd = None
                _cleanup_cdev(
                    self._kernel,
                    bdf=self._bdf,
                    device_fd=device_fd,
                    iommufd_fd=iommufd_fd,
                    ioas_id=self.ioas_id,
                    attached=self._attached,
                )
            else:
                group_fd = self.group_fd
                container_fd = self.container_fd
                self.group_fd = None
                self.container_fd = None
                _cleanup_legacy(
                    self._kernel,
                    bdf=self._bdf,
                    device_fd=device_fd,
                    group_fd=group_fd,
                    container_fd=container_fd,
                    container_set=self._container_set,
                )
        except ProviderError:
            self.proof["lifecycle"] = "CLOSED_WITH_CLEANUP_ERROR"
            raise
        else:
            self.proof["lifecycle"] = "CLOSED"

    def __enter__(self) -> "VfioProviderSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            self.close()
        except ProviderError:
            if exc is None:
                raise
        return False


def _proof_base(
    state: DeviceState,
    *,
    snapshot_epoch: int,
    topology_hash: str,
    provider: str,
    vfio_node: Path,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "bdf": state.bdf,
        "snapshotEpoch": snapshot_epoch,
        "topologyHash": topology_hash,
        "callerCorrelation": {
            "snapshotEpoch": snapshot_epoch,
            "topologyHash": topology_hash,
        },
        "provider": provider,
        "identity": state.identity.to_json(),
        "identityHash": compute_identity_hash(state.bdf, state.identity),
        "iommuGroup": state.iommu_group,
        "groupMembers": list(state.group_members),
        "groupHash": compute_group_hash(
            state.bdf, state.iommu_group, state.group_members
        ),
        "vfioNode": str(vfio_node),
        "verifiedClaims": ["pciIdentity", "iommuGroup", "vfioDmaProvider"],
        "snapshotBinding": "CALLER_CORRELATION_ONLY",
        "lifecycle": "LIVE_SESSION",
        "handlesUsable": True,
    }


def _validate_recheck(before: DeviceState, after: DeviceState) -> None:
    bdf = before.bdf
    if after.bdf != bdf or after.identity != before.identity:
        raise ProviderError(Reason.DEVICE_IDENTITY_STALE, bdf=bdf)
    if after.driver != before.driver:
        raise ProviderError(Reason.DEVICE_OWNER_STALE, bdf=bdf)
    if (
        after.iommu_group != before.iommu_group
        or after.group_members != before.group_members
    ):
        raise ProviderError(Reason.IOMMU_GROUP_STALE, bdf=bdf)
    if after.noiommu_node_present:
        raise ProviderError(Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=bdf)
    if (
        after.group_node != before.group_node
        or after.cdev_node != before.cdev_node
        or after.cdev_device_number != before.cdev_device_number
    ):
        raise ProviderError(Reason.VFIO_NODE_MISMATCH, bdf=bdf)


def _valid_int(value: object, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum


def _validate_captured_state(state: DeviceState, bdf: str, vfio_root: Path) -> None:
    """Do not trust even an injected state reader to weaken provider gates."""

    if state.bdf != bdf:
        raise ProviderError(Reason.DEVICE_IDENTITY_UNKNOWN, bdf=bdf)
    identity = state.identity
    if not all(
        (
            _valid_int(identity.vendor_id, 0xFFFF),
            _valid_int(identity.device_id, 0xFFFF),
            _valid_int(identity.subsystem_vendor_id, 0xFFFF),
            _valid_int(identity.subsystem_device_id, 0xFFFF),
            _valid_int(identity.class_code, 0xFFFFFF),
            _valid_int(identity.revision, 0xFF),
        )
    ):
        raise ProviderError(Reason.DEVICE_IDENTITY_UNKNOWN, bdf=bdf)
    if state.driver != "vfio-pci":
        raise ProviderError(Reason.DEVICE_NOT_VFIO_BOUND, bdf=bdf)
    if (
        not GROUP_RE.fullmatch(state.iommu_group)
        or not state.group_members
        or bdf not in state.group_members
        or state.group_members != tuple(sorted(set(state.group_members)))
        or any(not BDF_RE.fullmatch(member) for member in state.group_members)
    ):
        raise ProviderError(Reason.IOMMU_GROUP_UNKNOWN, bdf=bdf)
    if state.group_node != vfio_root / state.iommu_group:
        raise ProviderError(Reason.VFIO_NODE_MISMATCH, bdf=bdf)
    if state.cdev_node is None:
        if state.cdev_device_number is not None:
            raise ProviderError(Reason.VFIO_NODE_UNKNOWN, bdf=bdf)
        return
    if (
        state.cdev_device_number is None
        or not all(_valid_int(part, (1 << 32) - 1) for part in state.cdev_device_number)
        or not VFIO_CDEV_RE.fullmatch(state.cdev_node.name)
        or state.cdev_node != vfio_root / "devices" / state.cdev_node.name
    ):
        raise ProviderError(Reason.VFIO_NODE_UNKNOWN, bdf=bdf)


def _acquire_cdev(
    state_reader: StateReader,
    kernel: KernelOps,
    state: DeviceState,
    *,
    snapshot_epoch: int,
    topology_hash: str,
    iommufd_path: Path,
) -> VfioProviderSession:
    assert state.cdev_node is not None
    bdf = state.bdf
    iommufd_fd: int | None = None
    device_fd: int | None = None
    ioas_id: int | None = None
    attached = False
    try:
        iommufd_fd = kernel.open_node(
            iommufd_path,
            failure_reason=Reason.IOMMUFD_OPEN_FAILED,
            bdf=bdf,
        )
        ioas = bytearray(struct.pack("=III", 12, 0, 0))
        _ioctl(
            kernel,
            iommufd_fd,
            IOMMU_IOAS_ALLOC,
            ioas,
            mutate=True,
            reason=Reason.IOMMUFD_IOAS_ALLOC_FAILED,
            bdf=bdf,
            stage="allocate-ioas",
        )
        _, _, ioas_id = struct.unpack("=III", ioas)
        if ioas_id == 0:
            raise ProviderError(
                Reason.IOMMUFD_IOAS_ALLOC_FAILED, bdf=bdf, stage="zero-ioas-id"
            )

        device_fd = kernel.open_node(
            state.cdev_node,
            failure_reason=Reason.VFIO_CDEV_OPEN_FAILED,
            expected_device_number=state.cdev_device_number,
            bdf=bdf,
        )
        bind = bytearray(struct.pack("=IIiIQ", 24, 0, iommufd_fd, 0, 0))
        _ioctl(
            kernel,
            device_fd,
            VFIO_DEVICE_BIND_IOMMUFD,
            bind,
            mutate=True,
            reason=Reason.VFIO_DEVICE_BIND_IOMMUFD_FAILED,
            bdf=bdf,
            stage="bind-iommufd",
        )
        _, _, _, device_id, _ = struct.unpack("=IIiIQ", bind)
        if device_id == 0:
            raise ProviderError(
                Reason.VFIO_DEVICE_BIND_IOMMUFD_FAILED,
                bdf=bdf,
                stage="zero-device-id",
            )

        attach = bytearray(struct.pack("=IIII", 16, 0, ioas_id, 0))
        _ioctl(
            kernel,
            device_fd,
            VFIO_DEVICE_ATTACH_IOMMUFD_PT,
            attach,
            mutate=True,
            reason=Reason.VFIO_DEVICE_ATTACH_IOAS_FAILED,
            bdf=bdf,
            stage="attach-ioas",
        )
        _, _, hwpt_id, _ = struct.unpack("=IIII", attach)
        if hwpt_id == 0:
            raise ProviderError(
                Reason.VFIO_DEVICE_ATTACH_IOAS_FAILED,
                bdf=bdf,
                stage="zero-hwpt-id",
            )
        attached = True

        after = state_reader.capture(bdf)
        _validate_recheck(state, after)
        proof = _proof_base(
            state,
            snapshot_epoch=snapshot_epoch,
            topology_hash=topology_hash,
            provider="vfio-cdev-iommufd",
            vfio_node=state.cdev_node,
        )
        proof.update({"ioasId": ioas_id, "hwptId": hwpt_id, "deviceId": device_id})
        return VfioProviderSession(
            proof=proof,
            device_fd=device_fd,
            iommufd_fd=iommufd_fd,
            ioas_id=ioas_id,
            _kernel=kernel,
            _bdf=bdf,
            _attached=True,
        )
    except BaseException:
        try:
            _cleanup_cdev(
                kernel,
                bdf=bdf,
                device_fd=device_fd,
                iommufd_fd=iommufd_fd,
                ioas_id=ioas_id,
                attached=attached,
            )
        except ProviderError as cleanup_error:
            raise cleanup_error
        raise


def _acquire_legacy(
    state_reader: StateReader,
    kernel: KernelOps,
    state: DeviceState,
    *,
    snapshot_epoch: int,
    topology_hash: str,
    vfio_root: Path,
) -> VfioProviderSession:
    bdf = state.bdf
    group_fd: int | None = None
    container_fd: int | None = None
    device_fd: int | None = None
    container_set = False
    try:
        group_fd = kernel.open_node(
            state.group_node,
            failure_reason=Reason.VFIO_GROUP_OPEN_FAILED,
            bdf=bdf,
        )
        status_buffer = bytearray(struct.pack("=II", 8, 0))
        _ioctl(
            kernel,
            group_fd,
            VFIO_GROUP_GET_STATUS,
            status_buffer,
            mutate=True,
            reason=Reason.VFIO_GROUP_STATUS_FAILED,
            bdf=bdf,
            stage="group-status",
        )
        _, flags = struct.unpack("=II", status_buffer)
        if not flags & VFIO_GROUP_FLAGS_VIABLE:
            raise ProviderError(Reason.VFIO_GROUP_NOT_VIABLE, bdf=bdf)

        container_fd = kernel.open_node(
            vfio_root / "vfio",
            failure_reason=Reason.VFIO_CONTAINER_OPEN_FAILED,
            bdf=bdf,
        )
        api_version = _ioctl(
            kernel,
            container_fd,
            VFIO_GET_API_VERSION,
            0,
            mutate=False,
            reason=Reason.VFIO_API_VERSION_MISMATCH,
            bdf=bdf,
            stage="get-api-version",
        )
        if api_version != VFIO_API_VERSION:
            raise ProviderError(Reason.VFIO_API_VERSION_MISMATCH, bdf=bdf)

        container_argument = bytearray(struct.pack("=i", container_fd))
        _ioctl(
            kernel,
            group_fd,
            VFIO_GROUP_SET_CONTAINER,
            container_argument,
            mutate=True,
            reason=Reason.VFIO_GROUP_SET_CONTAINER_FAILED,
            bdf=bdf,
            stage="set-container",
        )
        container_set = True

        selected_type: int | None = None
        for candidate in (VFIO_TYPE1V2_IOMMU, VFIO_TYPE1_IOMMU):
            supported = _ioctl(
                kernel,
                container_fd,
                VFIO_CHECK_EXTENSION,
                candidate,
                mutate=False,
                reason=Reason.VFIO_TYPE1_UNSUPPORTED,
                bdf=bdf,
                stage="check-type1-extension",
            )
            if supported > 0:
                selected_type = candidate
                break
        if selected_type not in (VFIO_TYPE1V2_IOMMU, VFIO_TYPE1_IOMMU):
            raise ProviderError(Reason.VFIO_TYPE1_UNSUPPORTED, bdf=bdf)
        _ioctl(
            kernel,
            container_fd,
            VFIO_SET_IOMMU,
            selected_type,
            mutate=False,
            reason=Reason.VFIO_SET_IOMMU_FAILED,
            bdf=bdf,
            stage="set-type1-iommu",
        )

        name = bytearray(bdf.encode("ascii") + b"\0")
        device_fd = _ioctl(
            kernel,
            group_fd,
            VFIO_GROUP_GET_DEVICE_FD,
            name,
            mutate=True,
            reason=Reason.VFIO_GET_DEVICE_FD_FAILED,
            bdf=bdf,
            stage="get-device-fd",
        )
        if device_fd < 0:
            raise ProviderError(Reason.VFIO_GET_DEVICE_FD_FAILED, bdf=bdf)

        after = state_reader.capture(bdf)
        _validate_recheck(state, after)
        provider = (
            "vfio-legacy-type1v2"
            if selected_type == VFIO_TYPE1V2_IOMMU
            else "vfio-legacy-type1"
        )
        proof = _proof_base(
            state,
            snapshot_epoch=snapshot_epoch,
            topology_hash=topology_hash,
            provider=provider,
            vfio_node=state.group_node,
        )
        proof["iommuType"] = "TYPE1v2" if selected_type == VFIO_TYPE1V2_IOMMU else "TYPE1"
        proof["labOnly"] = True
        return VfioProviderSession(
            proof=proof,
            device_fd=device_fd,
            group_fd=group_fd,
            container_fd=container_fd,
            _kernel=kernel,
            _bdf=bdf,
            _container_set=True,
        )
    except BaseException:
        try:
            _cleanup_legacy(
                kernel,
                bdf=bdf,
                device_fd=device_fd,
                group_fd=group_fd,
                container_fd=container_fd,
                container_set=container_set,
            )
        except ProviderError as cleanup_error:
            raise cleanup_error
        raise


def open_vfio_provider(
    bdf: str,
    *,
    snapshot_epoch: int,
    topology_hash: str,
    expected_identity_hash: str,
    expected_group_hash: str,
    allow_legacy_lab: bool = False,
    sysfs_root: Path | str = Path("/sys/bus/pci/devices"),
    vfio_root: Path | str = Path("/dev/vfio"),
    iommufd: Path | str = Path("/dev/iommu"),
    state_reader: StateReader | None = None,
    kernel: KernelOps | None = None,
) -> VfioProviderSession:
    """Open and authoritatively prove the target's DMA provider.

    The returned session owns live file descriptors.  Closing it detaches and
    destroys the acquired context in reverse order and always attempts to close
    every descriptor, even when an explicit teardown ioctl fails.
    """

    if not isinstance(bdf, str):
        raise ProviderError(Reason.INVALID_BDF)
    normalized_bdf = bdf.lower()
    if not BDF_RE.fullmatch(normalized_bdf):
        raise ProviderError(Reason.INVALID_BDF, bdf=normalized_bdf)
    if (
        isinstance(snapshot_epoch, bool)
        or not isinstance(snapshot_epoch, int)
        or snapshot_epoch < 0
        or snapshot_epoch > (1 << 64) - 1
    ):
        raise ProviderError(Reason.INVALID_SNAPSHOT_EPOCH, bdf=normalized_bdf)
    if not isinstance(topology_hash, str):
        raise ProviderError(Reason.INVALID_TOPOLOGY_HASH, bdf=normalized_bdf)
    normalized_hash = topology_hash.lower()
    if not HASH_RE.fullmatch(normalized_hash):
        raise ProviderError(Reason.INVALID_TOPOLOGY_HASH, bdf=normalized_bdf)
    if not isinstance(expected_identity_hash, str) or not HASH_RE.fullmatch(
        expected_identity_hash.lower()
    ):
        raise ProviderError(
            Reason.INVALID_EXPECTED_IDENTITY_HASH, bdf=normalized_bdf
        )
    if not isinstance(expected_group_hash, str) or not HASH_RE.fullmatch(
        expected_group_hash.lower()
    ):
        raise ProviderError(Reason.INVALID_EXPECTED_GROUP_HASH, bdf=normalized_bdf)
    if not isinstance(allow_legacy_lab, bool):
        raise ProviderError(Reason.INVALID_ARGUMENT, bdf=normalized_bdf)
    if platform.machine().lower() not in SUPPORTED_IOCTL_ABI_MACHINES:
        raise ProviderError(Reason.UNSUPPORTED_IOCTL_ABI, bdf=normalized_bdf)

    vfio_root_path = Path(vfio_root)
    reader = state_reader or LinuxSysfsStateReader(
        sysfs_root=Path(sysfs_root), vfio_root=vfio_root_path
    )
    kernel_ops = kernel or PosixVfioKernel()
    state = reader.capture(normalized_bdf)
    _validate_captured_state(state, normalized_bdf, vfio_root_path)
    if not hmac.compare_digest(
        compute_identity_hash(normalized_bdf, state.identity),
        expected_identity_hash.lower(),
    ):
        raise ProviderError(Reason.DEVICE_IDENTITY_STALE, bdf=normalized_bdf)
    if not hmac.compare_digest(
        compute_group_hash(
            normalized_bdf, state.iommu_group, state.group_members
        ),
        expected_group_hash.lower(),
    ):
        raise ProviderError(Reason.IOMMU_GROUP_STALE, bdf=normalized_bdf)
    if state.noiommu_node_present:
        raise ProviderError(
            Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=normalized_bdf
        )
    if state.cdev_node is not None:
        return _acquire_cdev(
            reader,
            kernel_ops,
            state,
            snapshot_epoch=snapshot_epoch,
            topology_hash=normalized_hash,
            iommufd_path=Path(iommufd),
        )
    if not allow_legacy_lab:
        raise ProviderError(Reason.LEGACY_LAB_ONLY_DISABLED, bdf=normalized_bdf)
    return _acquire_legacy(
        reader,
        kernel_ops,
        state,
        snapshot_epoch=snapshot_epoch,
        topology_hash=normalized_hash,
        vfio_root=vfio_root_path,
    )


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ProviderError(Reason.INVALID_ARGUMENT, stage="argument-parse")


def _build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        description="Authoritative VFIO provider probe", add_help=False
    )
    parser.add_argument("--bdf", required=True)
    parser.add_argument("--snapshot-epoch", required=True, type=int)
    parser.add_argument("--topology-hash", required=True)
    parser.add_argument("--expected-identity-hash", required=True)
    parser.add_argument("--expected-group-hash", required=True)
    parser.add_argument("--allow-legacy-lab", action="store_true")
    parser.add_argument("--sysfs-root", default="/sys/bus/pci/devices")
    parser.add_argument("--vfio-root", default="/dev/vfio")
    parser.add_argument("--iommufd", default="/dev/iommu")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    bdf: str | None = None
    try:
        args = _build_parser().parse_args(argv)
        bdf = args.bdf.lower()
        session = open_vfio_provider(
            bdf,
            snapshot_epoch=args.snapshot_epoch,
            topology_hash=args.topology_hash,
            expected_identity_hash=args.expected_identity_hash,
            expected_group_hash=args.expected_group_hash,
            allow_legacy_lab=args.allow_legacy_lab,
            sysfs_root=args.sysfs_root,
            vfio_root=args.vfio_root,
            iommufd=args.iommufd,
        )
        proof = dict(session.proof)
        session.close()
        proof["lifecycle"] = "ACQUIRED_AND_CLOSED"
        proof["handlesUsable"] = False
        print(
            json.dumps(
                {"schemaVersion": 1, "status": "ok", "proof": proof},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except ProviderError as error:
        if error.bdf is None and bdf is not None:
            error.bdf = bdf
        print(json.dumps(error.to_json(), sort_keys=True, separators=(",", ":")))
        return 2
    except BaseException:
        error = ProviderError(Reason.INTERNAL_ERROR, bdf=bdf)
        print(json.dumps(error.to_json(), sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    sys.exit(main())
