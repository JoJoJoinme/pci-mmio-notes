"""Fail-closed raw VFIO cdev and IOMMUFD handles for stock-QEMU handoff.

This module opens two character-device file descriptors and nothing more.  It
does not issue VFIO/IOMMU ioctls, bind a device to IOMMUFD, allocate an IOAS, or
attach an IOAS.  Those operations remain stock QEMU's responsibility after an
explicit ``subprocess`` ``pass_fds`` handoff.

The inventory/state vocabulary and identity/group hashes are shared with
``vfio_provider``.  Unlike ``open_vfio_provider``, this opener intentionally
creates a fresh, unbound pair of raw descriptors rather than a live provider
session that would have to be torn down before QEMU could use it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from . import vfio_provider as vfio

try:
    import fcntl
except ImportError:  # pragma: no cover - real opener is POSIX-only
    fcntl = None  # type: ignore[assignment]


SYSFS_ROOT = Path("/sys/bus/pci/devices")
VFIO_ROOT = Path("/dev/vfio")
IOMMUFD_PATH = Path("/dev/iommu")
HANDOFF_MODE = "PYTHON_SUBPROCESS_PASS_FDS"
SNAPSHOT_BINDING = "CALLER_CORRELATION_ONLY"

# Keep the production reader identity pinned even if a test/lab replaces the
# public module attribute.  This is a provenance guard against accidentally
# treating an injected seam as a product admission result; it is not intended
# to defend against arbitrary code execution inside this Python process.
_PRODUCTION_STATE_READER_TYPE = vfio.LinuxSysfsStateReader


class _OmittedDependency:
    __slots__ = ()


_DEPENDENCY_OMITTED = _OmittedDependency()
_RESULT_FACTORY_SEAL = object()
_PRODUCTION_PROVENANCE = object()
_TEST_LAB_PROVENANCE = object()


@dataclass(frozen=True)
class VfioLaunchRequest:
    """Caller-correlated inventory facts required before opening anything."""

    bdf: str
    snapshot_epoch: int
    topology_hash: str
    expected_identity_hash: str
    expected_group_hash: str


@dataclass(frozen=True)
class OpenHandleMetadata:
    """Immutable identity of one opened character-device inode."""

    role: str
    path: Path
    inode: int
    filesystem_device: int
    character_device_major: int
    character_device_minor: int
    cloexec: bool

    def canonical(self) -> dict[str, Any]:
        return {
            "characterDevice": {
                "major": self.character_device_major,
                "minor": self.character_device_minor,
            },
            "cloexec": self.cloexec,
            "filesystemDevice": self.filesystem_device,
            "inode": self.inode,
            "path": str(self.path),
            "role": self.role,
        }


@dataclass(frozen=True)
class OpenedNode:
    """Trusted kernel-adapter result used by the orchestration layer."""

    fd: int
    metadata: OpenHandleMetadata


class LaunchKernelOps(Protocol):
    def open_char_node(
        self,
        path: Path,
        *,
        role: str,
        failure_reason: str,
        expected_device_number: tuple[int, int] | None,
        bdf: str,
    ) -> OpenedNode: ...

    def close(self, fd: int) -> None: ...


@dataclass(frozen=True)
class VfioLaunchMetadata:
    """Immutable facts bound into ``fd_binding_hash`` (never raw fd numbers)."""

    bdf: str
    snapshot_epoch: int
    topology_hash: str
    identity: vfio.PciIdentity
    identity_hash: str
    iommu_group: str
    group_members: tuple[str, ...]
    group_hash: str
    cdev: OpenHandleMetadata
    iommufd: OpenHandleMetadata
    fd_binding_hash: str
    snapshot_binding: str = SNAPSHOT_BINDING
    handoff_mode: str = HANDOFF_MODE

    def to_json(self) -> dict[str, Any]:
        return {
            "bdf": self.bdf,
            "cdev": self.cdev.canonical(),
            "fdBindingHash": self.fd_binding_hash,
            "groupHash": self.group_hash,
            "groupMembers": list(self.group_members),
            "handoffMode": self.handoff_mode,
            "identity": self.identity.to_json(),
            "identityHash": self.identity_hash,
            "iommuGroup": self.iommu_group,
            "iommufd": self.iommufd.canonical(),
            "schemaVersion": 1,
            "snapshotBinding": self.snapshot_binding,
            "snapshotEpoch": self.snapshot_epoch,
            "topologyHash": self.topology_hash,
        }


@dataclass
class _CloseState:
    closed: bool = False
    cleanup_failed: bool = False


@dataclass(frozen=True, init=False)
class VfioLaunchResult:
    """Own a fresh raw cdev/IOMMUFD pair until explicit QEMU handoff.

    Instances are returned only by :func:`open_vfio_launch_handles`.  The
    private construction seal closes the former public data-object bypass; it
    is deliberately not described as a security boundary against hostile code
    already executing in this module's process.
    """

    request: VfioLaunchRequest
    device_fd: int
    iommufd_fd: int
    metadata: VfioLaunchMetadata
    _kernel: LaunchKernelOps = field(repr=False, compare=False)
    _close_state: _CloseState = field(repr=False, compare=False)
    _provenance: object = field(repr=False, compare=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError(
            "VfioLaunchResult instances are created only by open_vfio_launch_handles"
        )

    @property
    def production_provenance(self) -> bool:
        """Whether this came from the exact, fully-default production path.

        Supplying either dependency (including an exact built-in instance),
        explicitly passing ``None``, subclassing, or replacing a constructor
        keeps the result in the TEST/LAB provenance class.
        """

        return (
            type(self) is VfioLaunchResult
            and getattr(self, "_provenance", None) is _PRODUCTION_PROVENANCE
        )

    @property
    def closed(self) -> bool:
        state = getattr(self, "_close_state", None)
        return not isinstance(state, _CloseState) or state.closed

    @property
    def cleanup_failed(self) -> bool:
        state = getattr(self, "_close_state", None)
        return isinstance(state, _CloseState) and state.cleanup_failed

    @property
    def handles_usable(self) -> bool:
        state = getattr(self, "_close_state", None)
        return (
            type(self) is VfioLaunchResult
            and isinstance(state, _CloseState)
            and getattr(self, "_provenance", None)
            in (_PRODUCTION_PROVENANCE, _TEST_LAB_PROVENANCE)
            and not state.closed
        )

    @property
    def pass_fds(self) -> tuple[int, int]:
        """Descriptors for an explicit ``subprocess.Popen(pass_fds=...)`` call.

        Both descriptors deliberately retain ``FD_CLOEXEC`` in this process.
        ``pass_fds`` is the narrow, auditable mechanism that makes exactly this
        pair survive the child exec; unrelated child processes do not inherit
        them accidentally.
        """

        if not self.handles_usable:
            metadata = getattr(self, "metadata", None)
            raise vfio.ProviderError(
                vfio.Reason.INVALID_ARGUMENT,
                bdf=getattr(metadata, "bdf", None),
                stage="pass-closed-launch-handles",
            )
        return (self.device_fd, self.iommufd_fd)

    def __copy__(self) -> "VfioLaunchResult":
        raise TypeError("VfioLaunchResult capability objects cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> "VfioLaunchResult":
        del memo
        raise TypeError("VfioLaunchResult capability objects cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("VfioLaunchResult capability objects cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("VfioLaunchResult capability objects cannot be pickled")

    def __getstate__(self) -> Any:
        raise TypeError("VfioLaunchResult capability objects cannot be pickled")

    def __setstate__(self, state: Any) -> None:
        del state
        raise TypeError("VfioLaunchResult capability objects cannot be unpickled")

    def close(self) -> None:
        """Close in reverse-open order, attempting both descriptors once."""

        if self._close_state.closed:
            return
        self._close_state.closed = True
        failures: list[BaseException] = []
        for fd in (self.device_fd, self.iommufd_fd):
            try:
                self._kernel.close(fd)
            except BaseException as error:
                failures.append(error)
        if failures:
            self._close_state.cleanup_failed = True
            first = failures[0]
            raise vfio.ProviderError(
                vfio.Reason.PROVIDER_CLEANUP_FAILED,
                bdf=self.metadata.bdf,
                stage="launch-handle-close",
                os_errno=first.errno if isinstance(first, OSError) else None,
            ) from first

    def __enter__(self) -> "VfioLaunchResult":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.close()
        return False


def is_production_launch_result(value: object) -> bool:
    """Return the narrow product-admission provenance decision.

    Consumers must use this exact-type check rather than trusting an
    overridable property on a subclass.  Handle liveness remains a separate
    requirement via :attr:`VfioLaunchResult.handles_usable`.
    """

    return (
        type(value) is VfioLaunchResult
        and getattr(value, "_provenance", None) is _PRODUCTION_PROVENANCE
    )


class PosixLaunchKernel:
    """Open one fixed character node with lstat/open/fstat substitution checks."""

    def open_char_node(
        self,
        path: Path,
        *,
        role: str,
        failure_reason: str,
        expected_device_number: tuple[int, int] | None,
        bdf: str,
    ) -> OpenedNode:
        if os.name != "posix" or fcntl is None:
            raise vfio.ProviderError(
                vfio.Reason.INVALID_ARGUMENT,
                bdf=bdf,
                stage="posix-character-node-required",
            )
        try:
            before = path.lstat()
        except OSError as error:
            raise vfio.ProviderError(
                failure_reason,
                bdf=bdf,
                stage="lstat-launch-node",
                os_errno=error.errno,
            ) from error
        self._validate_character_stat(before, expected_device_number, bdf)

        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd: int | None = None
        try:
            fd = os.open(path, flags)
            after = os.fstat(fd)
            self._validate_character_stat(after, expected_device_number, bdf)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_rdev != after.st_rdev
            ):
                raise vfio.ProviderError(
                    vfio.Reason.VFIO_NODE_MISMATCH,
                    bdf=bdf,
                    stage="launch-node-substitution",
                )

            descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            if not descriptor_flags & fcntl.FD_CLOEXEC:
                fcntl.fcntl(fd, fcntl.F_SETFD, descriptor_flags | fcntl.FD_CLOEXEC)
            if not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
                raise vfio.ProviderError(
                    vfio.Reason.VFIO_NODE_MISMATCH,
                    bdf=bdf,
                    stage="fd-cloexec-not-set",
                )
            return OpenedNode(
                fd=fd,
                metadata=OpenHandleMetadata(
                    role=role,
                    path=path,
                    inode=after.st_ino,
                    filesystem_device=after.st_dev,
                    character_device_major=os.major(after.st_rdev),
                    character_device_minor=os.minor(after.st_rdev),
                    cloexec=True,
                ),
            )
        except vfio.ProviderError:
            if fd is not None:
                self._close_after_failed_open(fd, bdf)
            raise
        except OSError as error:
            if fd is not None:
                self._close_after_failed_open(fd, bdf)
            raise vfio.ProviderError(
                failure_reason,
                bdf=bdf,
                stage="open-launch-node",
                os_errno=error.errno,
            ) from error

    @staticmethod
    def _validate_character_stat(
        value: os.stat_result,
        expected_device_number: tuple[int, int] | None,
        bdf: str,
    ) -> None:
        if not stat.S_ISCHR(value.st_mode):
            raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)
        actual = (os.major(value.st_rdev), os.minor(value.st_rdev))
        if expected_device_number is not None and actual != expected_device_number:
            raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)

    @staticmethod
    def _close_after_failed_open(fd: int, bdf: str) -> None:
        try:
            os.close(fd)
        except OSError as error:
            raise vfio.ProviderError(
                vfio.Reason.PROVIDER_CLEANUP_FAILED,
                bdf=bdf,
                stage="failed-launch-open-cleanup",
                os_errno=error.errno,
            ) from error

    @staticmethod
    def close(fd: int) -> None:
        os.close(fd)


_PRODUCTION_LAUNCH_KERNEL_TYPE = PosixLaunchKernel


def _new_launch_result(
    *,
    request: VfioLaunchRequest,
    device_fd: int,
    iommufd_fd: int,
    metadata: VfioLaunchMetadata,
    kernel: LaunchKernelOps,
    production: bool,
    _seal: object,
) -> VfioLaunchResult:
    if _seal is not _RESULT_FACTORY_SEAL:
        raise RuntimeError("invalid VfioLaunchResult factory seal")
    result = object.__new__(VfioLaunchResult)
    object.__setattr__(result, "request", request)
    object.__setattr__(result, "device_fd", device_fd)
    object.__setattr__(result, "iommufd_fd", iommufd_fd)
    object.__setattr__(result, "metadata", metadata)
    object.__setattr__(result, "_kernel", kernel)
    object.__setattr__(result, "_close_state", _CloseState())
    object.__setattr__(
        result,
        "_provenance",
        _PRODUCTION_PROVENANCE if production else _TEST_LAB_PROVENANCE,
    )
    return result


def _canonical_json_bytes(value: MappingValue) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


MappingValue = dict[str, Any]


def canonical_fd_binding_preimage(
    *,
    request: VfioLaunchRequest,
    state: vfio.DeviceState,
    identity_hash: str,
    group_hash: str,
    cdev: OpenHandleMetadata,
    iommufd: OpenHandleMetadata,
) -> bytes:
    """Bind caller facts to opened inodes/devts without trusting fd integers."""

    return _canonical_json_bytes(
        {
            "bdf": request.bdf,
            "cdev": cdev.canonical(),
            "groupHash": group_hash,
            "groupMembers": list(state.group_members),
            "handoffMode": HANDOFF_MODE,
            "identityHash": identity_hash,
            "iommuGroup": state.iommu_group,
            "iommufd": iommufd.canonical(),
            "kind": "qman-vfio-launch-fd-binding-v1",
            "snapshotEpoch": request.snapshot_epoch,
            "topologyHash": request.topology_hash,
        }
    )


def compute_fd_binding_hash(
    *,
    request: VfioLaunchRequest,
    state: vfio.DeviceState,
    identity_hash: str,
    group_hash: str,
    cdev: OpenHandleMetadata,
    iommufd: OpenHandleMetadata,
) -> str:
    return hashlib.sha256(
        canonical_fd_binding_preimage(
            request=request,
            state=state,
            identity_hash=identity_hash,
            group_hash=group_hash,
            cdev=cdev,
            iommufd=iommufd,
        )
    ).hexdigest()


def _normalize_request(request: VfioLaunchRequest) -> VfioLaunchRequest:
    if not isinstance(request, VfioLaunchRequest):
        raise vfio.ProviderError(vfio.Reason.INVALID_ARGUMENT)
    if not isinstance(request.bdf, str):
        raise vfio.ProviderError(vfio.Reason.INVALID_BDF)
    bdf = request.bdf.lower()
    if not vfio.BDF_RE.fullmatch(bdf):
        raise vfio.ProviderError(vfio.Reason.INVALID_BDF, bdf=bdf)
    if (
        isinstance(request.snapshot_epoch, bool)
        or not isinstance(request.snapshot_epoch, int)
        or not 0 <= request.snapshot_epoch <= (1 << 64) - 1
    ):
        raise vfio.ProviderError(vfio.Reason.INVALID_SNAPSHOT_EPOCH, bdf=bdf)
    if not isinstance(request.topology_hash, str) or not vfio.HASH_RE.fullmatch(
        request.topology_hash.lower()
    ):
        raise vfio.ProviderError(vfio.Reason.INVALID_TOPOLOGY_HASH, bdf=bdf)
    if not isinstance(
        request.expected_identity_hash, str
    ) or not vfio.HASH_RE.fullmatch(request.expected_identity_hash.lower()):
        raise vfio.ProviderError(vfio.Reason.INVALID_EXPECTED_IDENTITY_HASH, bdf=bdf)
    if not isinstance(request.expected_group_hash, str) or not vfio.HASH_RE.fullmatch(
        request.expected_group_hash.lower()
    ):
        raise vfio.ProviderError(vfio.Reason.INVALID_EXPECTED_GROUP_HASH, bdf=bdf)
    return VfioLaunchRequest(
        bdf=bdf,
        snapshot_epoch=request.snapshot_epoch,
        topology_hash=request.topology_hash.lower(),
        expected_identity_hash=request.expected_identity_hash.lower(),
        expected_group_hash=request.expected_group_hash.lower(),
    )


def _valid_int(value: object, maximum: int) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum
    )


def _validate_state(state: vfio.DeviceState, bdf: str) -> None:
    """Apply the provider's fail-closed state shape to even injected readers."""

    if not isinstance(state, vfio.DeviceState) or state.bdf != bdf:
        raise vfio.ProviderError(vfio.Reason.DEVICE_IDENTITY_UNKNOWN, bdf=bdf)
    identity = state.identity
    if not isinstance(identity, vfio.PciIdentity) or not all(
        (
            _valid_int(identity.vendor_id, 0xFFFF),
            _valid_int(identity.device_id, 0xFFFF),
            _valid_int(identity.subsystem_vendor_id, 0xFFFF),
            _valid_int(identity.subsystem_device_id, 0xFFFF),
            _valid_int(identity.class_code, 0xFFFFFF),
            _valid_int(identity.revision, 0xFF),
        )
    ):
        raise vfio.ProviderError(vfio.Reason.DEVICE_IDENTITY_UNKNOWN, bdf=bdf)
    if state.driver != "vfio-pci":
        raise vfio.ProviderError(vfio.Reason.DEVICE_NOT_VFIO_BOUND, bdf=bdf)
    if (
        not isinstance(state.iommu_group, str)
        or not vfio.GROUP_RE.fullmatch(state.iommu_group)
        or not state.group_members
        or bdf not in state.group_members
        or state.group_members != tuple(sorted(set(state.group_members)))
        or any(not vfio.BDF_RE.fullmatch(member) for member in state.group_members)
    ):
        raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_UNKNOWN, bdf=bdf)
    if state.group_node != VFIO_ROOT / state.iommu_group:
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)
    if state.cdev_node is None:
        if state.cdev_device_number is not None:
            raise vfio.ProviderError(vfio.Reason.VFIO_NODE_UNKNOWN, bdf=bdf)
        return
    if (
        state.cdev_device_number is None
        or not all(_valid_int(part, (1 << 32) - 1) for part in state.cdev_device_number)
        or not vfio.VFIO_CDEV_RE.fullmatch(state.cdev_node.name)
        or state.cdev_node != VFIO_ROOT / "devices" / state.cdev_node.name
    ):
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_UNKNOWN, bdf=bdf)


def _validate_recheck(before: vfio.DeviceState, after: vfio.DeviceState) -> None:
    bdf = before.bdf
    if after.bdf != bdf or after.identity != before.identity:
        raise vfio.ProviderError(vfio.Reason.DEVICE_IDENTITY_STALE, bdf=bdf)
    if after.driver != before.driver:
        raise vfio.ProviderError(vfio.Reason.DEVICE_OWNER_STALE, bdf=bdf)
    if (
        after.iommu_group != before.iommu_group
        or after.group_members != before.group_members
    ):
        raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_STALE, bdf=bdf)
    if after.noiommu_node_present:
        raise vfio.ProviderError(vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=bdf)
    if (
        after.group_node != before.group_node
        or after.cdev_node != before.cdev_node
        or after.cdev_device_number != before.cdev_device_number
    ):
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)


def _validate_opened_node(
    opened: OpenedNode,
    *,
    role: str,
    path: Path,
    expected_device_number: tuple[int, int] | None,
    bdf: str,
) -> None:
    if (
        not isinstance(opened, OpenedNode)
        or not isinstance(opened.fd, int)
        or isinstance(opened.fd, bool)
        or opened.fd < 0
    ):
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)
    metadata = opened.metadata
    if (
        not isinstance(metadata, OpenHandleMetadata)
        or metadata.role != role
        or metadata.path != path
        or not _valid_int(metadata.inode, (1 << 64) - 1)
        or not _valid_int(metadata.filesystem_device, (1 << 64) - 1)
        or not _valid_int(metadata.character_device_major, (1 << 32) - 1)
        or not _valid_int(metadata.character_device_minor, (1 << 32) - 1)
        or metadata.cloexec is not True
    ):
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)
    if (
        expected_device_number is not None
        and (
            metadata.character_device_major,
            metadata.character_device_minor,
        )
        != expected_device_number
    ):
        raise vfio.ProviderError(vfio.Reason.VFIO_NODE_MISMATCH, bdf=bdf)


def _close_partial(
    kernel: LaunchKernelOps,
    opened: list[object],
    *,
    bdf: str,
) -> None:
    failures: list[BaseException] = []
    closed: set[int] = set()
    for item in reversed(opened):
        try:
            fd = getattr(item, "fd")
        except BaseException:
            # A TEST/LAB kernel seam may return a malformed object.  Skip that
            # object, but continue closing every earlier validated handle.
            continue
        if not isinstance(fd, int) or isinstance(fd, bool) or fd < 0:
            continue
        if fd in closed:
            continue
        closed.add(fd)
        try:
            kernel.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        first = failures[0]
        raise vfio.ProviderError(
            vfio.Reason.PROVIDER_CLEANUP_FAILED,
            bdf=bdf,
            stage="partial-launch-open-cleanup",
            os_errno=first.errno if isinstance(first, OSError) else None,
        ) from first


def open_vfio_launch_handles(
    request: VfioLaunchRequest,
    *,
    state_reader: vfio.StateReader | None | _OmittedDependency = _DEPENDENCY_OMITTED,
    kernel: LaunchKernelOps | None | _OmittedDependency = _DEPENDENCY_OMITTED,
) -> VfioLaunchResult:
    """Open a fresh cdev/IOMMUFD pair without binding either descriptor.

    Success proves only that exact character-device inodes were opened while
    the target still matched caller-provided identity/group facts.  It does not
    prove that QEMU subsequently bound the cdev to IOMMUFD or attached an IOAS.
    """

    normalized = _normalize_request(request)
    reader_was_omitted = state_reader is _DEPENDENCY_OMITTED
    kernel_was_omitted = kernel is _DEPENDENCY_OMITTED
    if reader_was_omitted or state_reader is None:
        reader = vfio.LinuxSysfsStateReader(sysfs_root=SYSFS_ROOT, vfio_root=VFIO_ROOT)
    else:
        reader = state_reader
    if kernel_was_omitted or kernel is None:
        kernel_ops = PosixLaunchKernel()
    else:
        kernel_ops = kernel
    production = (
        reader_was_omitted
        and kernel_was_omitted
        and type(reader) is _PRODUCTION_STATE_READER_TYPE
        and type(kernel_ops) is _PRODUCTION_LAUNCH_KERNEL_TYPE
    )
    before = reader.capture(normalized.bdf)
    _validate_state(before, normalized.bdf)
    identity_hash = vfio.compute_identity_hash(normalized.bdf, before.identity)
    group_hash = vfio.compute_group_hash(
        normalized.bdf, before.iommu_group, before.group_members
    )
    if not hmac.compare_digest(identity_hash, normalized.expected_identity_hash):
        raise vfio.ProviderError(vfio.Reason.DEVICE_IDENTITY_STALE, bdf=normalized.bdf)
    if not hmac.compare_digest(group_hash, normalized.expected_group_hash):
        raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_STALE, bdf=normalized.bdf)
    if before.noiommu_node_present:
        raise vfio.ProviderError(
            vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=normalized.bdf
        )
    if before.cdev_node is None:
        raise vfio.ProviderError(vfio.Reason.VFIO_CDEV_UNAVAILABLE, bdf=normalized.bdf)
    assert before.cdev_device_number is not None

    opened: list[object] = []
    try:
        iommu_handle = kernel_ops.open_char_node(
            IOMMUFD_PATH,
            role="iommufd",
            failure_reason=vfio.Reason.IOMMUFD_OPEN_FAILED,
            expected_device_number=None,
            bdf=normalized.bdf,
        )
        opened.append(iommu_handle)
        _validate_opened_node(
            iommu_handle,
            role="iommufd",
            path=IOMMUFD_PATH,
            expected_device_number=None,
            bdf=normalized.bdf,
        )
        cdev_handle = kernel_ops.open_char_node(
            before.cdev_node,
            role="vfio-cdev",
            failure_reason=vfio.Reason.VFIO_CDEV_OPEN_FAILED,
            expected_device_number=before.cdev_device_number,
            bdf=normalized.bdf,
        )
        opened.append(cdev_handle)
        _validate_opened_node(
            cdev_handle,
            role="vfio-cdev",
            path=before.cdev_node,
            expected_device_number=before.cdev_device_number,
            bdf=normalized.bdf,
        )
        if iommu_handle.fd == cdev_handle.fd:
            raise vfio.ProviderError(
                vfio.Reason.VFIO_NODE_MISMATCH,
                bdf=normalized.bdf,
                stage="duplicate-launch-fd",
            )

        after = reader.capture(normalized.bdf)
        _validate_recheck(before, after)
        _validate_state(after, normalized.bdf)
        binding_hash = compute_fd_binding_hash(
            request=normalized,
            state=after,
            identity_hash=identity_hash,
            group_hash=group_hash,
            cdev=cdev_handle.metadata,
            iommufd=iommu_handle.metadata,
        )
        metadata = VfioLaunchMetadata(
            bdf=normalized.bdf,
            snapshot_epoch=normalized.snapshot_epoch,
            topology_hash=normalized.topology_hash,
            identity=after.identity,
            identity_hash=identity_hash,
            iommu_group=after.iommu_group,
            group_members=after.group_members,
            group_hash=group_hash,
            cdev=cdev_handle.metadata,
            iommufd=iommu_handle.metadata,
            fd_binding_hash=binding_hash,
        )
        return _new_launch_result(
            request=normalized,
            device_fd=cdev_handle.fd,
            iommufd_fd=iommu_handle.fd,
            metadata=metadata,
            kernel=kernel_ops,
            production=production,
            _seal=_RESULT_FACTORY_SEAL,
        )
    except BaseException as primary:
        try:
            _close_partial(kernel_ops, opened, bdf=normalized.bdf)
        except vfio.ProviderError as cleanup_error:
            raise cleanup_error from primary
        raise
