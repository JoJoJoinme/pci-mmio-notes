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
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from . import vfio_provider as vfio

try:
    import fcntl
except ImportError:  # pragma: no cover - real opener is POSIX-only
    fcntl = None  # type: ignore[assignment]


SYSFS_ROOT = Path("/sys/bus/pci/devices")
VFIO_ROOT = Path("/dev/vfio")
IOMMUFD_PATH = Path("/dev/iommu")
HANDOFF_MODE = "PYTHON_SUBPROCESS_PASS_FDS"
CALLER_SNAPSHOT_BINDING = "CALLER_CORRELATION_ONLY"
AUTHORITATIVE_SNAPSHOT_BINDING = "AUTHORITATIVE_COMPONENT_SNAPSHOT_V1"
# Backward-compatible name for the legacy caller-correlation contract.  New
# product-facing code must explicitly require AUTHORITATIVE_SNAPSHOT_BINDING.
SNAPSHOT_BINDING = CALLER_SNAPSHOT_BINDING

# Keep the production reader identity pinned even if a test/lab replaces the
# public module attribute.  This is a provenance guard against accidentally
# treating an injected seam as a product admission result; it is not intended
# to defend against arbitrary code execution inside this Python process.
_PRODUCTION_STATE_READER_TYPE = vfio.LinuxSysfsStateReader


class _OmittedDependency:
    __slots__ = ()


_DEPENDENCY_OMITTED = _OmittedDependency()
_RESULT_FACTORY_SEAL = object()
_BUNDLE_FACTORY_SEAL = object()
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
    snapshot_hash: str | None = None
    snapshot_authority_id: str | None = None
    snapshot_store_instance_id: str | None = None
    snapshot_key_id: str | None = None
    snapshot_boot_id: str | None = None
    snapshot_authorization_hash: str | None = None

    def to_json(self) -> dict[str, Any]:
        result = {
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
        if self.snapshot_binding == AUTHORITATIVE_SNAPSHOT_BINDING:
            result["publisherSnapshot"] = {
                "authorityId": self.snapshot_authority_id,
                "authorizationHash": self.snapshot_authorization_hash,
                "bootId": self.snapshot_boot_id,
                "keyId": self.snapshot_key_id,
                "snapshotHash": self.snapshot_hash,
                "storeInstanceId": self.snapshot_store_instance_id,
            }
        return result


@dataclass
class _CloseState:
    close_plan: tuple[int, ...]
    bdf: str
    stage: str
    closed: bool = False
    cleanup_failed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


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
    _snapshot_authorization: object | None = field(repr=False, compare=False)

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

        This flag covers only raw launch-handle construction.  It does not
        promote the publisher's ``COMPONENT_CAPTURE_PROVIDER`` or component
        HMAC into a production inventory trust root.
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
        """Close the complete ownership unit exactly once in reverse-open order."""

        _close_owned_handles(self._kernel, self._close_state)

    def require_snapshot_authorization_current(self) -> None:
        """Recheck the sealed publisher capability retained through spawn."""

        from .authoritative_snapshot import validate_launch_authorization

        if self.metadata.snapshot_binding != AUTHORITATIVE_SNAPSHOT_BINDING:
            raise vfio.ProviderError(
                vfio.Reason.INVALID_ARGUMENT,
                bdf=self.metadata.bdf,
                stage="authoritative-snapshot-required",
            )
        validate_launch_authorization(self._snapshot_authorization)

    def revalidate_snapshot_live(self, phase: object) -> None:
        """Re-capture the full host at an explicit launch-side-effect boundary."""

        from .authoritative_snapshot import (
            LiveCapturePhase,
            SnapshotError,
            SnapshotReason,
            validate_launch_authorization,
        )

        authorization = validate_launch_authorization(self._snapshot_authorization)
        if not isinstance(phase, LiveCapturePhase):
            raise SnapshotError(
                SnapshotReason.INVALID_ARGUMENT,
                "authoritative launch result lacks a valid live-capture contract",
            )
        authorization.revalidate_live(phase)

    def __enter__(self) -> "VfioLaunchResult":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.close()
        return False


@dataclass(frozen=True, init=False)
class VfioLaunchBundle:
    """Atomic ownership unit for one or more cdevs sharing one IOMMUFD.

    Every child is an exact :class:`VfioLaunchResult`, but all children share a
    single close state.  Closing the bundle or any child invalidates every child
    and closes all cdevs followed by the one shared IOMMUFD descriptor.
    """

    results: tuple[VfioLaunchResult, ...]
    _kernel: LaunchKernelOps = field(repr=False, compare=False)
    _close_state: _CloseState = field(repr=False, compare=False)
    _provenance: object = field(repr=False, compare=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError(
            "VfioLaunchBundle instances are created only by open_vfio_launch_bundle"
        )

    @property
    def production_provenance(self) -> bool:
        return (
            type(self) is VfioLaunchBundle
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
        results = getattr(self, "results", None)
        return (
            type(self) is VfioLaunchBundle
            and isinstance(state, _CloseState)
            and isinstance(results, tuple)
            and bool(results)
            and getattr(self, "_provenance", None)
            in (_PRODUCTION_PROVENANCE, _TEST_LAB_PROVENANCE)
            and not state.closed
            and all(result.handles_usable for result in results)
        )

    @property
    def pass_fds(self) -> tuple[int, ...]:
        if not self.handles_usable:
            raise vfio.ProviderError(
                vfio.Reason.INVALID_ARGUMENT,
                bdf=getattr(getattr(self, "_close_state", None), "bdf", None),
                stage="pass-closed-launch-bundle",
            )
        iommufd_fd = self.results[0].iommufd_fd
        return tuple(result.device_fd for result in self.results) + (iommufd_fd,)

    def __copy__(self) -> "VfioLaunchBundle":
        raise TypeError("VfioLaunchBundle capability objects cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> "VfioLaunchBundle":
        del memo
        raise TypeError("VfioLaunchBundle capability objects cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("VfioLaunchBundle capability objects cannot be pickled")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("VfioLaunchBundle capability objects cannot be pickled")

    def __getstate__(self) -> Any:
        raise TypeError("VfioLaunchBundle capability objects cannot be pickled")

    def __setstate__(self, state: Any) -> None:
        del state
        raise TypeError("VfioLaunchBundle capability objects cannot be unpickled")

    def close(self) -> None:
        _close_owned_handles(self._kernel, self._close_state)

    def __enter__(self) -> "VfioLaunchBundle":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.close()
        return False


def _close_owned_handles(kernel: LaunchKernelOps, state: _CloseState) -> None:
    with state.lock:
        if state.closed:
            return
        state.closed = True
        failures: list[BaseException] = []
        for fd in state.close_plan:
            try:
                kernel.close(fd)
            except BaseException as error:
                failures.append(error)
        if failures:
            state.cleanup_failed = True
            first = failures[0]
            raise vfio.ProviderError(
                vfio.Reason.PROVIDER_CLEANUP_FAILED,
                bdf=state.bdf,
                stage=state.stage,
                os_errno=first.errno if isinstance(first, OSError) else None,
            ) from first


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


def is_production_launch_bundle(value: object) -> bool:
    """Return the exact product-admission provenance for an atomic bundle."""

    results = getattr(value, "results", None)
    return (
        type(value) is VfioLaunchBundle
        and getattr(value, "_provenance", None) is _PRODUCTION_PROVENANCE
        and isinstance(results, tuple)
        and bool(results)
        and all(is_production_launch_result(result) for result in results)
    )


def is_authoritative_snapshot_launch_result(value: object) -> bool:
    """Return true only for a live default-opener result bound to a snapshot guard."""

    if not is_production_launch_result(value) or not value.handles_usable:
        return False
    if value.metadata.snapshot_binding != AUTHORITATIVE_SNAPSHOT_BINDING:
        return False
    try:
        value.require_snapshot_authorization_current()
    except BaseException:
        return False
    return True


def is_authoritative_snapshot_launch_bundle(value: object) -> bool:
    results = getattr(value, "results", None)
    return (
        is_production_launch_bundle(value)
        and isinstance(results, tuple)
        and bool(results)
        and all(is_authoritative_snapshot_launch_result(result) for result in results)
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
    close_state: _CloseState | None = None,
    snapshot_authorization: object | None = None,
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
    object.__setattr__(
        result,
        "_close_state",
        close_state
        or _CloseState(
            close_plan=(device_fd, iommufd_fd),
            bdf=request.bdf,
            stage="launch-handle-close",
        ),
    )
    object.__setattr__(
        result,
        "_provenance",
        _PRODUCTION_PROVENANCE if production else _TEST_LAB_PROVENANCE,
    )
    object.__setattr__(result, "_snapshot_authorization", snapshot_authorization)
    return result


def _new_launch_bundle(
    *,
    results: tuple[VfioLaunchResult, ...],
    kernel: LaunchKernelOps,
    close_state: _CloseState,
    production: bool,
    _seal: object,
) -> VfioLaunchBundle:
    if _seal is not _BUNDLE_FACTORY_SEAL:
        raise RuntimeError("invalid VfioLaunchBundle factory seal")
    bundle = object.__new__(VfioLaunchBundle)
    object.__setattr__(bundle, "results", results)
    object.__setattr__(bundle, "_kernel", kernel)
    object.__setattr__(bundle, "_close_state", close_state)
    object.__setattr__(
        bundle,
        "_provenance",
        _PRODUCTION_PROVENANCE if production else _TEST_LAB_PROVENANCE,
    )
    return bundle


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
    snapshot_authorization: object | None = None,
) -> bytes:
    """Bind caller facts to opened inodes/devts without trusting fd integers."""

    value: dict[str, Any] = {
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
    if snapshot_authorization is not None:
        from .authoritative_snapshot import validate_launch_authorization

        authorization = validate_launch_authorization(snapshot_authorization)
        value.update(
            {
                "kind": "qman-vfio-launch-fd-binding-v2",
                "publisherSnapshot": {
                    "authorityId": authorization.authority_id,
                    "authorizationHash": authorization.binding_hash,
                    "bootId": authorization.kernel_boot_id,
                    "keyId": authorization.key_id,
                    "snapshotHash": authorization.snapshot_hash,
                    "storeInstanceId": authorization.store_instance_id,
                },
                "snapshotBinding": AUTHORITATIVE_SNAPSHOT_BINDING,
            }
        )
    return _canonical_json_bytes(value)


def compute_fd_binding_hash(
    *,
    request: VfioLaunchRequest,
    state: vfio.DeviceState,
    identity_hash: str,
    group_hash: str,
    cdev: OpenHandleMetadata,
    iommufd: OpenHandleMetadata,
    snapshot_authorization: object | None = None,
) -> str:
    return hashlib.sha256(
        canonical_fd_binding_preimage(
            request=request,
            state=state,
            identity_hash=identity_hash,
            group_hash=group_hash,
            cdev=cdev,
            iommufd=iommufd,
            snapshot_authorization=snapshot_authorization,
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


def _validate_complete_bundle_groups(
    states: dict[str, vfio.DeviceState], request_bdfs: frozenset[str]
) -> None:
    groups: dict[str, tuple[str, ...]] = {}
    member_owner: dict[str, str] = {}
    requested_by_group: dict[str, set[str]] = {}
    for bdf, device_state in states.items():
        group = device_state.iommu_group
        members = device_state.group_members
        previous = groups.setdefault(group, members)
        if previous != members:
            raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_STALE, bdf=bdf)
        requested_by_group.setdefault(group, set()).add(bdf)
        for member in members:
            owner = member_owner.setdefault(member, group)
            if owner != group:
                raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_STALE, bdf=bdf)
    for group, members in groups.items():
        if frozenset(members) != frozenset(requested_by_group[group]):
            representative = min(requested_by_group[group])
            raise vfio.ProviderError(
                vfio.Reason.IOMMU_GROUP_STALE,
                bdf=representative,
                stage="incomplete-launch-bundle-iommu-group",
            )
    if frozenset(states) != request_bdfs:
        raise vfio.ProviderError(
            vfio.Reason.IOMMU_GROUP_STALE,
            stage="launch-bundle-state-coverage",
        )


def open_vfio_launch_bundle(
    requests: Sequence[VfioLaunchRequest],
    *,
    state_reader: vfio.StateReader | None | _OmittedDependency = _DEPENDENCY_OMITTED,
    kernel: LaunchKernelOps | None | _OmittedDependency = _DEPENDENCY_OMITTED,
) -> VfioLaunchBundle:
    """Open complete IOMMU-group cdev sets on one shared IOMMUFD.

    All requests must belong to one inventory snapshot.  Every referenced IOMMU
    group must be represented by its complete, exact member set.  The function
    captures all devices before opening anything, opens exactly one IOMMUFD and
    one cdev per BDF, then rechecks the complete set.  Any failure closes every
    opened descriptor in reverse order and returns no partial capability.
    """

    if (
        not isinstance(requests, Sequence)
        or isinstance(requests, (str, bytes))
        or not requests
    ):
        raise vfio.ProviderError(
            vfio.Reason.INVALID_ARGUMENT, stage="launch-bundle-requests"
        )
    normalized = tuple(
        sorted(
            (_normalize_request(item) for item in requests),
            key=lambda item: item.bdf,
        )
    )
    request_bdfs = frozenset(item.bdf for item in normalized)
    if len(request_bdfs) != len(normalized):
        raise vfio.ProviderError(
            vfio.Reason.INVALID_ARGUMENT, stage="duplicate-launch-bundle-bdf"
        )
    if len({item.snapshot_epoch for item in normalized}) != 1:
        raise vfio.ProviderError(
            vfio.Reason.INVALID_SNAPSHOT_EPOCH,
            stage="mixed-launch-bundle-snapshot",
        )
    if len({item.topology_hash for item in normalized}) != 1:
        raise vfio.ProviderError(
            vfio.Reason.INVALID_TOPOLOGY_HASH,
            stage="mixed-launch-bundle-topology",
        )

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

    before_states: dict[str, vfio.DeviceState] = {}
    identity_hashes: dict[str, str] = {}
    group_hashes: dict[str, str] = {}
    by_bdf = {item.bdf: item for item in normalized}
    for item in normalized:
        observed = reader.capture(item.bdf)
        _validate_state(observed, item.bdf)
        identity_hash = vfio.compute_identity_hash(item.bdf, observed.identity)
        group_hash = vfio.compute_group_hash(
            item.bdf, observed.iommu_group, observed.group_members
        )
        if not hmac.compare_digest(identity_hash, item.expected_identity_hash):
            raise vfio.ProviderError(
                vfio.Reason.DEVICE_IDENTITY_STALE, bdf=item.bdf
            )
        if not hmac.compare_digest(group_hash, item.expected_group_hash):
            raise vfio.ProviderError(vfio.Reason.IOMMU_GROUP_STALE, bdf=item.bdf)
        if observed.noiommu_node_present:
            raise vfio.ProviderError(
                vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=item.bdf
            )
        if observed.cdev_node is None:
            raise vfio.ProviderError(
                vfio.Reason.VFIO_CDEV_UNAVAILABLE, bdf=item.bdf
            )
        before_states[item.bdf] = observed
        identity_hashes[item.bdf] = identity_hash
        group_hashes[item.bdf] = group_hash
    _validate_complete_bundle_groups(before_states, request_bdfs)

    opened: list[object] = []
    first_bdf = normalized[0].bdf
    try:
        iommu_handle = kernel_ops.open_char_node(
            IOMMUFD_PATH,
            role="iommufd",
            failure_reason=vfio.Reason.IOMMUFD_OPEN_FAILED,
            expected_device_number=None,
            bdf=first_bdf,
        )
        opened.append(iommu_handle)
        _validate_opened_node(
            iommu_handle,
            role="iommufd",
            path=IOMMUFD_PATH,
            expected_device_number=None,
            bdf=first_bdf,
        )
        used_fds = {iommu_handle.fd}
        cdev_handles: dict[str, OpenedNode] = {}
        for item in normalized:
            before = before_states[item.bdf]
            assert before.cdev_node is not None
            assert before.cdev_device_number is not None
            cdev_handle = kernel_ops.open_char_node(
                before.cdev_node,
                role="vfio-cdev",
                failure_reason=vfio.Reason.VFIO_CDEV_OPEN_FAILED,
                expected_device_number=before.cdev_device_number,
                bdf=item.bdf,
            )
            opened.append(cdev_handle)
            _validate_opened_node(
                cdev_handle,
                role="vfio-cdev",
                path=before.cdev_node,
                expected_device_number=before.cdev_device_number,
                bdf=item.bdf,
            )
            if cdev_handle.fd in used_fds:
                raise vfio.ProviderError(
                    vfio.Reason.VFIO_NODE_MISMATCH,
                    bdf=item.bdf,
                    stage="duplicate-launch-bundle-fd",
                )
            used_fds.add(cdev_handle.fd)
            cdev_handles[item.bdf] = cdev_handle

        after_states: dict[str, vfio.DeviceState] = {}
        for item in normalized:
            after = reader.capture(item.bdf)
            _validate_recheck(before_states[item.bdf], after)
            _validate_state(after, item.bdf)
            after_states[item.bdf] = after
        _validate_complete_bundle_groups(after_states, request_bdfs)

        close_state = _CloseState(
            close_plan=tuple(
                [cdev_handles[item.bdf].fd for item in reversed(normalized)]
                + [iommu_handle.fd]
            ),
            bdf=first_bdf,
            stage="launch-bundle-close",
        )
        results: list[VfioLaunchResult] = []
        for item in normalized:
            after = after_states[item.bdf]
            cdev_handle = cdev_handles[item.bdf]
            metadata = VfioLaunchMetadata(
                bdf=item.bdf,
                snapshot_epoch=item.snapshot_epoch,
                topology_hash=item.topology_hash,
                identity=after.identity,
                identity_hash=identity_hashes[item.bdf],
                iommu_group=after.iommu_group,
                group_members=after.group_members,
                group_hash=group_hashes[item.bdf],
                cdev=cdev_handle.metadata,
                iommufd=iommu_handle.metadata,
                fd_binding_hash=compute_fd_binding_hash(
                    request=by_bdf[item.bdf],
                    state=after,
                    identity_hash=identity_hashes[item.bdf],
                    group_hash=group_hashes[item.bdf],
                    cdev=cdev_handle.metadata,
                    iommufd=iommu_handle.metadata,
                ),
            )
            results.append(
                _new_launch_result(
                    request=by_bdf[item.bdf],
                    device_fd=cdev_handle.fd,
                    iommufd_fd=iommu_handle.fd,
                    metadata=metadata,
                    kernel=kernel_ops,
                    production=production,
                    close_state=close_state,
                    _seal=_RESULT_FACTORY_SEAL,
                )
            )
        return _new_launch_bundle(
            results=tuple(results),
            kernel=kernel_ops,
            close_state=close_state,
            production=production,
            _seal=_BUNDLE_FACTORY_SEAL,
        )
    except BaseException as primary:
        try:
            _close_partial(kernel_ops, opened, bdf=first_bdf)
        except vfio.ProviderError as cleanup_error:
            raise cleanup_error from primary
        raise


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


def _verification_state_from_metadata(metadata: VfioLaunchMetadata) -> vfio.DeviceState:
    """Reconstruct only the already-observed fields used by the binding hash."""

    return vfio.DeviceState(
        bdf=metadata.bdf,
        identity=metadata.identity,
        driver="vfio-pci",
        iommu_group=metadata.iommu_group,
        group_members=metadata.group_members,
        noiommu_node_present=False,
        group_node=VFIO_ROOT / metadata.iommu_group,
        cdev_node=metadata.cdev.path,
        cdev_device_number=(
            metadata.cdev.character_device_major,
            metadata.cdev.character_device_minor,
        ),
    )


def open_authorized_vfio_launch_bundle(
    authorization: object,
    capture_fn: Callable[[], Any] | None = None,
    *,
    state_reader: vfio.StateReader | None | _OmittedDependency = _DEPENDENCY_OMITTED,
    kernel: LaunchKernelOps | None | _OmittedDependency = _DEPENDENCY_OMITTED,
) -> VfioLaunchBundle:
    """Open one complete group set derived only from a sealed publisher capability.

    The caller does not supply BDF identity, group, epoch, or topology hashes.
    Those values are derived from the active store authorization, then the full
    host is re-captured immediately before and after the raw character-device
    opens.  The returned capability remains valid only while the authorization
    context is active and retains the sealed publisher authorization for the
    pre-spawn recheck.

    ``capture_fn`` is a compatibility witness for the former API only.  If
    supplied, it must be the exact callable sealed by ``capture_and_publish``;
    validation always invokes the provider capability carried by the
    authorization.  New callers should omit it.
    """

    from .authoritative_snapshot import (
        LiveCapturePhase,
        SnapshotError,
        SnapshotReason,
        validate_launch_authorization,
    )

    verified = validate_launch_authorization(authorization)
    verified._require_bound_capture_provider(capture_fn)
    verified.revalidate_live(LiveCapturePhase.PRE_OPEN)
    requests = tuple(
        VfioLaunchRequest(
            bdf=bdf,
            snapshot_epoch=verified.inventory_epoch,
            topology_hash=verified.topology_hash,
            expected_identity_hash=verified.launch_facts[bdf].identity_hash,
            expected_group_hash=verified.launch_facts[bdf].group_hash,
        )
        for bdf in verified.authorized_bdfs
    )

    dependencies: dict[str, object] = {}
    if state_reader is not _DEPENDENCY_OMITTED:
        dependencies["state_reader"] = state_reader
    if kernel is not _DEPENDENCY_OMITTED:
        dependencies["kernel"] = kernel
    bundle = open_vfio_launch_bundle(requests, **dependencies)
    try:
        verified.revalidate_live(LiveCapturePhase.POST_OPEN)
        by_bdf = {result.metadata.bdf: result for result in bundle.results}
        if set(by_bdf) != set(verified.authorized_bdfs):
            raise SnapshotError(
                SnapshotReason.LAUNCH_FACTS_CHANGED,
                "raw launch result coverage differs from snapshot authorization",
                phase=LiveCapturePhase.POST_OPEN,
            )

        upgraded: list[VfioLaunchResult] = []
        for bdf in verified.authorized_bdfs:
            legacy = by_bdf[bdf]
            fact = verified.launch_facts[bdf]
            metadata = legacy.metadata
            if (
                metadata.identity != fact.identity
                or metadata.iommu_group != fact.iommu_group
                or metadata.group_members != fact.group_members
                or not hmac.compare_digest(metadata.identity_hash, fact.identity_hash)
                or not hmac.compare_digest(metadata.group_hash, fact.group_hash)
            ):
                raise SnapshotError(
                    SnapshotReason.LAUNCH_FACTS_CHANGED,
                    f"opened VFIO facts differ from publisher facts for {bdf}",
                    phase=LiveCapturePhase.POST_OPEN,
                )
            binding_hash = compute_fd_binding_hash(
                request=legacy.request,
                state=_verification_state_from_metadata(metadata),
                identity_hash=metadata.identity_hash,
                group_hash=metadata.group_hash,
                cdev=metadata.cdev,
                iommufd=metadata.iommufd,
                snapshot_authorization=verified,
            )
            authoritative_metadata = replace(
                metadata,
                fd_binding_hash=binding_hash,
                snapshot_binding=AUTHORITATIVE_SNAPSHOT_BINDING,
                snapshot_hash=verified.snapshot_hash,
                snapshot_authority_id=verified.authority_id,
                snapshot_store_instance_id=verified.store_instance_id,
                snapshot_key_id=verified.key_id,
                snapshot_boot_id=verified.kernel_boot_id,
                snapshot_authorization_hash=verified.binding_hash,
            )
            upgraded.append(
                _new_launch_result(
                    request=legacy.request,
                    device_fd=legacy.device_fd,
                    iommufd_fd=legacy.iommufd_fd,
                    metadata=authoritative_metadata,
                    kernel=bundle._kernel,
                    production=bundle.production_provenance,
                    close_state=bundle._close_state,
                    snapshot_authorization=verified,
                    _seal=_RESULT_FACTORY_SEAL,
                )
            )
        return _new_launch_bundle(
            results=tuple(upgraded),
            kernel=bundle._kernel,
            close_state=bundle._close_state,
            production=bundle.production_provenance,
            _seal=_BUNDLE_FACTORY_SEAL,
        )
    except BaseException as primary:
        try:
            bundle.close()
        except vfio.ProviderError as cleanup_error:
            raise cleanup_error from primary
        raise


def open_authorized_vfio_launch_handles(
    authorization: object,
    capture_fn: Callable[[], Any] | None = None,
    *,
    state_reader: vfio.StateReader | None | _OmittedDependency = _DEPENDENCY_OMITTED,
    kernel: LaunchKernelOps | None | _OmittedDependency = _DEPENDENCY_OMITTED,
) -> VfioLaunchResult:
    """Singleton convenience wrapper; complete multi-function groups use the bundle API."""

    from .authoritative_snapshot import (
        SnapshotError,
        SnapshotReason,
        validate_launch_authorization,
    )

    verified = validate_launch_authorization(authorization)
    if len(verified.authorized_bdfs) != 1:
        raise SnapshotError(
            SnapshotReason.INCOMPLETE_IOMMU_GROUP,
            "singleton opener requires an authorization containing exactly one BDF",
        )
    dependencies: dict[str, object] = {}
    if state_reader is not _DEPENDENCY_OMITTED:
        dependencies["state_reader"] = state_reader
    if kernel is not _DEPENDENCY_OMITTED:
        dependencies["kernel"] = kernel
    bundle = open_authorized_vfio_launch_bundle(
        verified,
        capture_fn,
        **dependencies,
    )
    return bundle.results[0]
