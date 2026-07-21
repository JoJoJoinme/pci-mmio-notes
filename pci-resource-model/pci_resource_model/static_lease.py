"""Fail-closed, host-local durable lease state for Static DirectPath.

This module deliberately stops at the persistence and transaction boundary.  It
does not bind a driver, reset a device, open VFIO, or start QEMU.  Callers must
persist PREPARING before performing those side effects and may release member
claims only after cleanup has been independently verified.  ``cleanup_verified``
is therefore an upper-layer evidence assertion, not evidence produced or
authenticated by this store; product integration must restrict that caller.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence


_BDF = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class LeaseState(str, Enum):
    RESERVED = "RESERVED"
    PREPARING = "PREPARING"
    ATTACHED = "ATTACHED"
    RELEASING = "RELEASING"
    RELEASED = "RELEASED"
    QUARANTINED = "QUARANTINED"


class ReconcileObservation(str, Enum):
    """Authoritative observations accepted by crash reconciliation.

    Process absence is intentionally not represented: it cannot prove that DMA,
    IRQ, reset, kernel ownership, or device identity are clean.
    """

    ACTIVE_OWNER_VERIFIED = "ACTIVE_OWNER_VERIFIED"
    CLEANUP_VERIFIED = "CLEANUP_VERIFIED"
    UNSAFE_OR_UNKNOWN = "UNSAFE_OR_UNKNOWN"


class Reason(str, Enum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_REQUEST = "INVALID_REQUEST"
    STORE_NOT_DURABLE = "STORE_NOT_DURABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    HOST_SCOPE_MISMATCH = "HOST_SCOPE_MISMATCH"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    VM_GENERATION_MISMATCH = "VM_GENERATION_MISMATCH"
    VM_GENERATION_SUPERSEDED = "VM_GENERATION_SUPERSEDED"
    DEVICE_GENERATION_UNKNOWN = "DEVICE_GENERATION_UNKNOWN"
    DEVICE_GENERATION_MISMATCH = "DEVICE_GENERATION_MISMATCH"
    DEVICE_GENERATION_SNAPSHOT_MISMATCH = "DEVICE_GENERATION_SNAPSHOT_MISMATCH"
    DEVICE_GENERATION_PUBLISH_CONFLICT = "DEVICE_GENERATION_PUBLISH_CONFLICT"
    DEVICE_GENERATION_PUBLISH_BUSY = "DEVICE_GENERATION_PUBLISH_BUSY"
    DEVICE_GENERATION_REGRESSION = "DEVICE_GENERATION_REGRESSION"
    BUNDLE_BUSY = "BUNDLE_BUSY"
    BUNDLE_UNKNOWN = "BUNDLE_UNKNOWN"
    BUNDLE_MEMBERS_MISMATCH = "BUNDLE_MEMBERS_MISMATCH"
    BUNDLE_SNAPSHOT_MISMATCH = "BUNDLE_SNAPSHOT_MISMATCH"
    BUNDLE_PUBLISH_CONFLICT = "BUNDLE_PUBLISH_CONFLICT"
    BUNDLE_PUBLISH_BUSY = "BUNDLE_PUBLISH_BUSY"
    RUN_ID_BUSY = "RUN_ID_BUSY"
    VM_TRANSACTION_BUSY = "VM_TRANSACTION_BUSY"
    MEMBER_BUSY = "MEMBER_BUSY"
    TRANSACTION_NOT_FOUND = "TRANSACTION_NOT_FOUND"
    TRANSACTION_GENERATION_MISMATCH = "TRANSACTION_GENERATION_MISMATCH"
    LEASE_REVISION_MISMATCH = "LEASE_REVISION_MISMATCH"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    CLEANUP_EVIDENCE_REQUIRED = "CLEANUP_EVIDENCE_REQUIRED"
    RECONCILE_OBSERVATION_INVALID = "RECONCILE_OBSERVATION_INVALID"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class LeaseStoreError(RuntimeError):
    def __init__(self, reason: Reason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason.value if not detail else f"{reason.value}: {detail}")


@dataclass(frozen=True)
class BeginRequest:
    idempotency_key: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    expected_bundle_hash: str
    members: Sequence[str]
    inventory_epoch: int
    expected_vm_generation: int
    expected_device_generations: Mapping[str, int]
    decision_hash: str
    policy_hash: str


@dataclass(frozen=True)
class LeaseRecord:
    transaction_id: str
    idempotency_key: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    authority_id: str
    bundle_members_hash: str
    members: tuple[str, ...]
    inventory_epoch: int
    device_generations: Mapping[str, int]
    decision_hash: str
    policy_hash: str
    vm_generation: int
    state: LeaseState
    revision: int
    reason_code: str | None
    reason_detail: str | None
    cleanup_request_hash: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class JournalEntry:
    sequence: int
    transaction_id: str
    event: str
    state: LeaseState
    revision: int
    detail: Mapping[str, object]
    created_at: str


@dataclass(frozen=True)
class _NormalizedBegin:
    idempotency_key: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    expected_bundle_hash: str
    members: tuple[str, ...]
    inventory_epoch: int
    expected_vm_generation: int
    expected_device_generations: dict[str, int]
    decision_hash: str
    policy_hash: str

    def canonical(self) -> dict[str, object]:
        return {
            "bundleId": self.bundle_id,
            "expectedBundleHash": self.expected_bundle_hash,
            "decisionHash": self.decision_hash,
            "deviceGenerations": dict(sorted(self.expected_device_generations.items())),
            "expectedVmGeneration": self.expected_vm_generation,
            "hostId": self.host_id,
            "inventoryEpoch": self.inventory_epoch,
            "members": list(self.members),
            "policyHash": self.policy_hash,
            "runId": self.run_id,
            "vmId": self.vm_id,
        }


class StaticLeaseStore:
    """SQLite-backed single-host lease/CAS component.

    A database file is mandatory.  SQLite ``:memory:`` and URI memory databases
    are rejected so a passing component test cannot accidentally prove only
    volatile state.  The filesystem provenance gate proves only host-local
    component persistence; WAL/FULL does not prove end-to-end power-loss safety.
    """

    SCHEMA_VERSION = 3

    def __init__(
        self,
        path: str | Path,
        *,
        local_host_id: str,
        trusted_authority_id: str,
        allow_unverified_filesystem_for_lab: bool = False,
        timeout_seconds: float = 5.0,
        transaction_id_factory: Callable[[], str] | None = None,
        clock: Callable[[], datetime] | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        raw_path = str(path)
        if raw_path == ":memory:" or raw_path.startswith("file:"):
            raise LeaseStoreError(Reason.STORE_NOT_DURABLE, "a filesystem database is required")
        raw_file = Path(path)
        if not raw_file.is_absolute():
            raise LeaseStoreError(Reason.STORE_NOT_DURABLE, "database path must be absolute")
        if raw_file.is_symlink():
            raise LeaseStoreError(Reason.STORE_NOT_DURABLE, "database path must not be a symlink")
        self.path = raw_file.resolve()
        if not self.path.parent.is_dir() or self.path.parent.is_symlink():
            raise LeaseStoreError(Reason.STORE_UNAVAILABLE, "database parent directory does not exist")
        if self.path.exists() and not stat.S_ISREG(self.path.stat().st_mode):
            raise LeaseStoreError(Reason.STORE_NOT_DURABLE, "database path is not a regular file")
        self.local_host_id = self._canonical_host_id(local_host_id)
        self.trusted_authority_id = self._required_text(
            "trusted_authority_id", trusted_authority_id
        )
        self.persistence_boundary = self._verify_filesystem_provenance(
            self.path, allow_unverified_filesystem_for_lab
        )
        self._transaction_id_factory = transaction_id_factory or (lambda: str(uuid.uuid4()))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(
                self.path,
                timeout=timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys=ON")
            mode = self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise LeaseStoreError(Reason.STORE_NOT_DURABLE, f"journal_mode={mode}")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA busy_timeout=%d" % max(0, int(timeout_seconds * 1000)))
            self._initialize_schema()
        except LeaseStoreError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.Error as error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise LeaseStoreError(Reason.STORE_UNAVAILABLE, str(error)) from error

    @staticmethod
    def _linux_filesystem_magic(path: Path) -> int:
        # Linux struct statfs is architecture-specific, but f_type is always the
        # first native long.  A generously sized output buffer avoids mirroring
        # the remaining ABI fields merely to read that discriminator.
        import ctypes

        buffer = ctypes.create_string_buffer(512)
        libc = ctypes.CDLL(None, use_errno=True)
        statfs = libc.statfs
        statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        statfs.restype = ctypes.c_int
        if statfs(os.fsencode(path), ctypes.byref(buffer)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(path))
        return int(ctypes.c_long.from_buffer(buffer).value) & ((1 << (ctypes.sizeof(ctypes.c_long) * 8)) - 1)

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
                # Conservative allowlist of local, block-backed or host-local
                # filesystems.  This is a provenance check, not a power-loss
                # durability claim about the underlying hardware/controller.
                local_magics = {
                    0xEF53,  # ext2/3/4
                    0x58465342,  # xfs
                    0x9123683E,  # btrfs
                    0xF2F52010,  # f2fs
                    0x2FC12FC1,  # zfs
                    0x5346544E,  # ntfs
                }
                unsafe_magics = {
                    0x01021994,  # tmpfs
                    0x858458F6,  # ramfs
                    0x01021997,  # 9p/v9fs (including WSL DrvFS mounts)
                    0x65735546,  # fuse
                    0x6969,  # nfs
                    0xFF534D42,  # cifs
                    0xFE534D42,  # smb2
                    0x794C7630,  # overlayfs/container ephemeral layer
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

                anchor = path.anchor
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(anchor)
                # DRIVE_FIXED=3.  Remote, RAM-disk, removable and unknown paths
                # are rejected for this component's normal mode.
                verified = drive_type == 3 and not str(path).startswith("\\\\")
                detail = f"Windows drive type {drive_type} is not fixed-local"
            except (AttributeError, OSError) as error:
                detail = f"Windows drive provenance failed: {error}"
        if verified:
            return "LOCAL_FILESYSTEM_COMPONENT_PERSISTENCE_ONLY"
        if allow_lab is True:
            return "LAB_UNVERIFIED_FILESYSTEM_COMPONENT_PERSISTENCE_ONLY"
        raise LeaseStoreError(Reason.STORE_NOT_DURABLE, detail)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "StaticLeaseStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vm_generations (
                host_id TEXT NOT NULL,
                vm_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                PRIMARY KEY (host_id, vm_id)
            );
            CREATE TABLE IF NOT EXISTS device_generations (
                host_id TEXT NOT NULL,
                bdf TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                authority_id TEXT NOT NULL,
                authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 0),
                updated_at TEXT NOT NULL,
                PRIMARY KEY (host_id, bdf)
            );
            CREATE TABLE IF NOT EXISTS bundle_definitions (
                host_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL,
                members_hash TEXT NOT NULL,
                members_json TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                authority_epoch INTEGER NOT NULL CHECK (authority_epoch >= 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (host_id, bundle_id)
            );
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_hash TEXT NOT NULL,
                host_id TEXT NOT NULL,
                vm_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                bundle_members_hash TEXT NOT NULL,
                members_json TEXT NOT NULL,
                inventory_epoch INTEGER NOT NULL CHECK (inventory_epoch >= 0),
                device_generations_json TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                vm_generation INTEGER NOT NULL CHECK (vm_generation > 0),
                state TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK (revision >= 0),
                reason_code TEXT,
                reason_detail TEXT,
                cleanup_request_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS member_claims (
                host_id TEXT NOT NULL,
                bdf TEXT NOT NULL,
                transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
                vm_generation INTEGER NOT NULL,
                PRIMARY KEY (host_id, bdf)
            );
            CREATE TABLE IF NOT EXISTS bundle_claims (
                host_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL,
                members_hash TEXT NOT NULL,
                transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
                vm_generation INTEGER NOT NULL,
                PRIMARY KEY (host_id, bundle_id)
            );
            CREATE TABLE IF NOT EXISTS journal (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
                event TEXT NOT NULL,
                state TEXT NOT NULL,
                revision INTEGER NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS journal_transaction_sequence
                ON journal(transaction_id, sequence);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_transaction_per_run
                ON transactions(host_id, run_id)
                WHERE state != 'RELEASED';
            """
        )
        row = self._connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )
        elif row["value"] != str(self.SCHEMA_VERSION):
            raise LeaseStoreError(
                Reason.STORE_UNAVAILABLE,
                f"unsupported schema version {row['value']}",
            )
        host_row = self._connection.execute(
            "SELECT value FROM metadata WHERE key='local_host_id'"
        ).fetchone()
        if host_row is None:
            self._connection.execute(
                "INSERT INTO metadata(key, value) VALUES('local_host_id', ?)",
                (self.local_host_id,),
            )
        elif host_row["value"] != self.local_host_id:
            raise LeaseStoreError(
                Reason.HOST_SCOPE_MISMATCH,
                f"database={host_row['value']}, requested={self.local_host_id}",
            )
        authority_row = self._connection.execute(
            "SELECT value FROM metadata WHERE key='trusted_authority_id'"
        ).fetchone()
        if authority_row is None:
            self._connection.execute(
                "INSERT INTO metadata(key, value) VALUES('trusted_authority_id', ?)",
                (self.trusted_authority_id,),
            )
        elif authority_row["value"] != self.trusted_authority_id:
            raise LeaseStoreError(
                Reason.AUTHORITY_SCOPE_MISMATCH,
                f"database={authority_row['value']}, requested={self.trusted_authority_id}",
            )

    @contextmanager
    def _write(self) -> Iterator[None]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._connection.execute("COMMIT")
            except LeaseStoreError:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except sqlite3.Error as error:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise LeaseStoreError(Reason.STORE_UNAVAILABLE, str(error)) from error
            except BaseException:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _now(self) -> str:
        return self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def _hash(cls, value: object) -> str:
        return "sha256:" + hashlib.sha256(cls._json(value).encode("ascii")).hexdigest()

    @staticmethod
    def _required_text(name: str, value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, f"{name} must be non-empty text")
        return value.strip()

    @classmethod
    def _canonical_host_id(cls, value: object) -> str:
        host_id = cls._required_text("host_id", value).lower()
        if len(host_id) > 128 or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]*", host_id):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "host_id is not canonical")
        return host_id

    def _require_local_host(self, host_id: str) -> None:
        if host_id != self.local_host_id:
            raise LeaseStoreError(
                Reason.HOST_SCOPE_MISMATCH,
                f"store={self.local_host_id}, request={host_id}",
            )

    def _require_trusted_authority(self, authority_id: str) -> None:
        if authority_id != self.trusted_authority_id:
            raise LeaseStoreError(
                Reason.AUTHORITY_SCOPE_MISMATCH,
                f"store={self.trusted_authority_id}, request={authority_id}",
            )

    @staticmethod
    def _nonnegative(name: str, value: object) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > (1 << 63) - 1
        ):
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT,
                f"{name} must be an unsigned SQLite int64 value",
            )
        return value

    @classmethod
    def _normalize_begin(cls, request: BeginRequest) -> _NormalizedBegin:
        if not isinstance(request, BeginRequest):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "request must be BeginRequest")
        if (
            not isinstance(request.members, Sequence)
            or isinstance(request.members, (str, bytes))
            or not request.members
        ):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be a non-empty sequence")
        raw_members = tuple(str(member).lower() for member in request.members)
        if len(raw_members) != len(set(raw_members)):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be unique")
        members = tuple(sorted(raw_members))
        if not members or any(not _BDF.fullmatch(member) for member in members):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be canonical PCI BDFs")
        if not isinstance(request.expected_device_generations, Mapping):
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT,
                "expected_device_generations must be a mapping",
            )
        normalized_generations: dict[str, int] = {}
        for raw_bdf, generation in request.expected_device_generations.items():
            bdf = str(raw_bdf).lower()
            if not _BDF.fullmatch(bdf):
                raise LeaseStoreError(Reason.INVALID_ARGUMENT, "device generation key is not a PCI BDF")
            if bdf in normalized_generations:
                raise LeaseStoreError(
                    Reason.INVALID_ARGUMENT,
                    "duplicate canonical device generation key",
                )
            normalized_generations[bdf] = cls._nonnegative("device generation", generation)
        if set(normalized_generations) != set(members):
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT,
                "device generations must exactly cover all lease members",
            )
        decision_hash = cls._required_text("decision_hash", request.decision_hash).lower()
        policy_hash = cls._required_text("policy_hash", request.policy_hash).lower()
        expected_bundle_hash = cls._required_text(
            "expected_bundle_hash", request.expected_bundle_hash
        ).lower()
        if (
            not _SHA256.fullmatch(decision_hash)
            or not _SHA256.fullmatch(policy_hash)
            or not _SHA256.fullmatch(expected_bundle_hash)
        ):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "decision and policy hashes must be sha256")
        return _NormalizedBegin(
            idempotency_key=cls._required_text("idempotency_key", request.idempotency_key),
            host_id=cls._canonical_host_id(request.host_id),
            vm_id=cls._required_text("vm_id", request.vm_id),
            run_id=cls._required_text("run_id", request.run_id),
            bundle_id=cls._required_text("bundle_id", request.bundle_id),
            expected_bundle_hash=expected_bundle_hash,
            members=members,
            inventory_epoch=cls._nonnegative("inventory_epoch", request.inventory_epoch),
            expected_vm_generation=cls._nonnegative(
                "expected_vm_generation", request.expected_vm_generation
            ),
            expected_device_generations=normalized_generations,
            decision_hash=decision_hash,
            policy_hash=policy_hash,
        )

    @classmethod
    def _normalize_device_generations(
        cls, generations: Mapping[str, int]
    ) -> dict[str, int]:
        if not isinstance(generations, Mapping) or not generations:
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT, "device generations must be a non-empty mapping"
            )
        normalized: dict[str, int] = {}
        for raw_bdf, generation in generations.items():
            bdf = str(raw_bdf).lower()
            if not _BDF.fullmatch(bdf):
                raise LeaseStoreError(Reason.INVALID_ARGUMENT, "device generation key is not a PCI BDF")
            if bdf in normalized:
                raise LeaseStoreError(Reason.INVALID_ARGUMENT, "duplicate canonical device BDF")
            normalized[bdf] = cls._nonnegative("device generation", generation)
        return normalized

    @classmethod
    def compute_bundle_members_hash(
        cls, host_id: str, bundle_id: str, members: Sequence[str]
    ) -> str:
        host = cls._canonical_host_id(host_id)
        bundle = cls._required_text("bundle_id", bundle_id)
        if (
            not isinstance(members, Sequence)
            or isinstance(members, (str, bytes))
            or not members
        ):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be a non-empty sequence")
        raw_members = tuple(str(member).lower() for member in members)
        if len(raw_members) != len(set(raw_members)):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be unique")
        canonical = tuple(sorted(raw_members))
        if any(not _BDF.fullmatch(member) for member in canonical):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "members must be canonical PCI BDFs")
        return cls._hash(
            {
                "kind": "qman-static-bundle-v1",
                "hostId": host,
                "bundleId": bundle,
                "members": list(canonical),
            }
        )

    def publish_authoritative_bundle(
        self,
        host_id: str,
        bundle_id: str,
        members: Sequence[str],
        *,
        expected_current_hash: str | None,
        authority_id: str,
        authority_epoch: int,
    ) -> str:
        """CAS-publish one complete dependency bundle from an authority.

        Begin requests cannot self-register bundles.  A definition remains after
        lease release, and changing it while claimed is rejected.
        """

        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        bundle = self._required_text("bundle_id", bundle_id)
        authority = self._required_text("authority_id", authority_id)
        self._require_trusted_authority(authority)
        epoch = self._nonnegative("authority_epoch", authority_epoch)
        members_hash = self.compute_bundle_members_hash(host, bundle, members)
        canonical_members = tuple(sorted(set(str(member).lower() for member in members)))
        if expected_current_hash is not None:
            expected_current_hash = self._required_text(
                "expected_current_hash", expected_current_hash
            ).lower()
            if not _SHA256.fullmatch(expected_current_hash):
                raise LeaseStoreError(
                    Reason.INVALID_ARGUMENT, "expected_current_hash must be sha256"
                )
        with self._write():
            current = self._connection.execute(
                """SELECT members_hash,authority_id,authority_epoch
                   FROM bundle_definitions WHERE host_id=? AND bundle_id=?""",
                (host, bundle),
            ).fetchone()
            current_hash = None if current is None else current["members_hash"]
            if current_hash != expected_current_hash:
                raise LeaseStoreError(
                    Reason.BUNDLE_PUBLISH_CONFLICT,
                    f"expected {expected_current_hash}, current {current_hash}",
                )
            if current is not None:
                if current["authority_id"] != authority or epoch < current["authority_epoch"]:
                    raise LeaseStoreError(
                        Reason.BUNDLE_PUBLISH_CONFLICT,
                        "bundle authority changed or epoch regressed",
                    )
                if (
                    members_hash != current_hash
                    and epoch <= current["authority_epoch"]
                ):
                    raise LeaseStoreError(
                        Reason.BUNDLE_PUBLISH_CONFLICT,
                        "bundle members changed without a newer authority epoch",
                    )
                claim = self._connection.execute(
                    "SELECT 1 FROM bundle_claims WHERE host_id=? AND bundle_id=?",
                    (host, bundle),
                ).fetchone()
                if claim is not None and (
                    members_hash != current_hash or epoch != current["authority_epoch"]
                ):
                    raise LeaseStoreError(Reason.BUNDLE_PUBLISH_BUSY, bundle)
            now = self._now()
            self._connection.execute(
                """INSERT INTO bundle_definitions(
                       host_id,bundle_id,members_hash,members_json,authority_id,
                       authority_epoch,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(host_id,bundle_id) DO UPDATE SET
                       members_hash=excluded.members_hash,
                       members_json=excluded.members_json,
                       authority_id=excluded.authority_id,
                       authority_epoch=excluded.authority_epoch,
                       updated_at=excluded.updated_at""",
                (
                    host,
                    bundle,
                    members_hash,
                    self._json(canonical_members),
                    authority,
                    epoch,
                    now,
                    now,
                ),
            )
            self._fault("BUNDLE_DEFINITION_BEFORE_COMMIT")
        return members_hash

    def publish_authoritative_device_generations(
        self,
        host_id: str,
        generations: Mapping[str, int],
        *,
        expected_current: Mapping[str, int | None],
        authority_id: str,
        authority_epoch: int,
    ) -> Mapping[str, int]:
        """Atomically publish current per-device generations from one authority.

        ``expected_current`` is a required CAS precondition and must exactly
        cover ``generations``.  ``None`` means that the device must not already
        exist.  A generation cannot decrease, an authority cannot silently
        change, and an authority epoch cannot move backwards.
        """

        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        authority = self._required_text("authority_id", authority_id)
        self._require_trusted_authority(authority)
        epoch = self._nonnegative("authority_epoch", authority_epoch)
        normalized = self._normalize_device_generations(generations)
        if not isinstance(expected_current, Mapping):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "expected_current must be a mapping")
        expected: dict[str, int | None] = {}
        for raw_bdf, value in expected_current.items():
            bdf = str(raw_bdf).lower()
            if not _BDF.fullmatch(bdf) or bdf in expected:
                raise LeaseStoreError(Reason.INVALID_ARGUMENT, "invalid expected_current BDF")
            expected[bdf] = None if value is None else self._nonnegative("expected generation", value)
        if set(expected) != set(normalized):
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT,
                "expected_current must exactly cover published devices",
            )

        with self._write():
            for bdf, generation in sorted(normalized.items()):
                row = self._connection.execute(
                    """SELECT generation,authority_id,authority_epoch
                       FROM device_generations WHERE host_id=? AND bdf=?""",
                    (host, bdf),
                ).fetchone()
                current = None if row is None else row["generation"]
                if current != expected[bdf]:
                    raise LeaseStoreError(
                        Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
                        f"{bdf}: expected {expected[bdf]}, current {current}",
                    )
                if row is not None:
                    if row["authority_id"] != authority:
                        raise LeaseStoreError(
                            Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
                            f"{bdf}: authority changed",
                        )
                    if epoch < row["authority_epoch"]:
                        raise LeaseStoreError(
                            Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
                            f"{bdf}: authority epoch regressed",
                        )
                    if generation < current:
                        raise LeaseStoreError(
                            Reason.DEVICE_GENERATION_REGRESSION,
                            f"{bdf}: {current}->{generation}",
                        )
                    if generation != current and epoch <= row["authority_epoch"]:
                        raise LeaseStoreError(
                            Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
                            f"{bdf}: generation changed without a newer authority epoch",
                        )
                    claim = self._connection.execute(
                        "SELECT 1 FROM member_claims WHERE host_id=? AND bdf=?",
                        (host, bdf),
                    ).fetchone()
                    if claim is not None and (
                        generation != current or epoch != row["authority_epoch"]
                    ):
                        raise LeaseStoreError(Reason.DEVICE_GENERATION_PUBLISH_BUSY, bdf)
                self._connection.execute(
                    """INSERT INTO device_generations(
                           host_id,bdf,generation,authority_id,authority_epoch,updated_at)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(host_id,bdf) DO UPDATE SET
                           generation=excluded.generation,
                           authority_id=excluded.authority_id,
                           authority_epoch=excluded.authority_epoch,
                           updated_at=excluded.updated_at""",
                    (host, bdf, generation, authority, epoch, self._now()),
                )
            self._fault("DEVICE_GENERATIONS_BEFORE_COMMIT")
        return dict(sorted(normalized.items()))

    @staticmethod
    def _record(row: sqlite3.Row) -> LeaseRecord:
        return LeaseRecord(
            transaction_id=row["transaction_id"],
            idempotency_key=row["idempotency_key"],
            host_id=row["host_id"],
            vm_id=row["vm_id"],
            run_id=row["run_id"],
            bundle_id=row["bundle_id"],
            authority_id=row["authority_id"],
            bundle_members_hash=row["bundle_members_hash"],
            members=tuple(json.loads(row["members_json"])),
            inventory_epoch=row["inventory_epoch"],
            device_generations=json.loads(row["device_generations_json"]),
            decision_hash=row["decision_hash"],
            policy_hash=row["policy_hash"],
            vm_generation=row["vm_generation"],
            state=LeaseState(row["state"]),
            revision=row["revision"],
            reason_code=row["reason_code"],
            reason_detail=row["reason_detail"],
            cleanup_request_hash=row["cleanup_request_hash"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _row_by_id(self, transaction_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM transactions WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        if row is None:
            raise LeaseStoreError(Reason.TRANSACTION_NOT_FOUND, transaction_id)
        return row

    def _require_generation(
        self, row: sqlite3.Row, vm_generation: int, *, require_current: bool = True
    ) -> None:
        if isinstance(vm_generation, bool) or row["vm_generation"] != vm_generation:
            raise LeaseStoreError(
                Reason.TRANSACTION_GENERATION_MISMATCH,
                f"expected {row['vm_generation']}, got {vm_generation}",
            )
        if not require_current:
            return
        current = self._connection.execute(
            "SELECT generation FROM vm_generations WHERE host_id=? AND vm_id=?",
            (row["host_id"], row["vm_id"]),
        ).fetchone()
        if current is None or current["generation"] != row["vm_generation"]:
            current_value = None if current is None else current["generation"]
            raise LeaseStoreError(
                Reason.VM_GENERATION_SUPERSEDED,
                f"transaction {row['vm_generation']}, current {current_value}",
            )

    def _require_transaction_facts(self, row: sqlite3.Row) -> None:
        members = tuple(json.loads(row["members_json"]))
        expected = json.loads(row["device_generations_json"])
        placeholders = ",".join("?" for _ in members)
        current_rows = self._connection.execute(
            f"""SELECT bdf,generation,authority_id,authority_epoch FROM device_generations
                WHERE host_id=? AND bdf IN ({placeholders})""",
            (row["host_id"], *members),
        ).fetchall()
        current = {item["bdf"]: item for item in current_rows}
        unknown = [bdf for bdf in members if bdf not in current]
        if unknown:
            raise LeaseStoreError(Reason.DEVICE_GENERATION_UNKNOWN, ",".join(unknown))
        authority_stale = [
            bdf
            for bdf in members
            if current[bdf]["authority_id"] != row["authority_id"]
            or current[bdf]["authority_id"] != self.trusted_authority_id
        ]
        if authority_stale:
            raise LeaseStoreError(
                Reason.AUTHORITY_SCOPE_MISMATCH, ",".join(authority_stale)
            )
        epoch_stale = [
            bdf for bdf in members if current[bdf]["authority_epoch"] != row["inventory_epoch"]
        ]
        if epoch_stale:
            raise LeaseStoreError(
                Reason.DEVICE_GENERATION_SNAPSHOT_MISMATCH, ",".join(epoch_stale)
            )
        generation_stale = [
            bdf for bdf in members if current[bdf]["generation"] != expected[bdf]
        ]
        if generation_stale:
            raise LeaseStoreError(Reason.DEVICE_GENERATION_MISMATCH, ",".join(generation_stale))
        bundle = self._connection.execute(
            """SELECT members_hash,authority_id,authority_epoch FROM bundle_definitions
               WHERE host_id=? AND bundle_id=?""",
            (row["host_id"], row["bundle_id"]),
        ).fetchone()
        if bundle is None:
            raise LeaseStoreError(Reason.BUNDLE_UNKNOWN, row["bundle_id"])
        if (
            bundle["authority_id"] != row["authority_id"]
            or bundle["authority_id"] != self.trusted_authority_id
        ):
            raise LeaseStoreError(
                Reason.AUTHORITY_SCOPE_MISMATCH, row["bundle_id"]
            )
        if bundle["members_hash"] != row["bundle_members_hash"]:
            raise LeaseStoreError(Reason.BUNDLE_MEMBERS_MISMATCH, row["bundle_id"])
        if bundle["authority_epoch"] != row["inventory_epoch"]:
            raise LeaseStoreError(Reason.BUNDLE_SNAPSHOT_MISMATCH, row["bundle_id"])

    def _journal(
        self,
        transaction_id: str,
        event: str,
        state: LeaseState,
        revision: int,
        detail: Mapping[str, object] | None = None,
    ) -> None:
        self._connection.execute(
            """INSERT INTO journal(transaction_id,event,state,revision,detail_json,created_at)
               VALUES(?,?,?,?,?,?)""",
            (transaction_id, event, state.value, revision, self._json(detail or {}), self._now()),
        )

    def begin(self, request: BeginRequest) -> LeaseRecord:
        normalized = self._normalize_begin(request)
        self._require_local_host(normalized.host_id)
        request_hash = self._hash(normalized.canonical())
        bundle_members_hash = self.compute_bundle_members_hash(
            normalized.host_id, normalized.bundle_id, normalized.members
        )
        if bundle_members_hash != normalized.expected_bundle_hash:
            raise LeaseStoreError(
                Reason.BUNDLE_MEMBERS_MISMATCH,
                "request members do not match expected authoritative bundle hash",
            )
        with self._write():
            existing = self._connection.execute(
                "SELECT * FROM transactions WHERE idempotency_key=?",
                (normalized.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise LeaseStoreError(
                        Reason.IDEMPOTENCY_CONFLICT,
                        "idempotency key was already used for a different request",
                    )
                existing_state = LeaseState(existing["state"])
                self._require_generation(
                    existing,
                    existing["vm_generation"],
                    require_current=existing_state not in {
                        LeaseState.RELEASED,
                        LeaseState.QUARANTINED,
                    },
                )
                if existing_state not in {
                    LeaseState.RELEASED,
                    LeaseState.QUARANTINED,
                }:
                    self._require_transaction_facts(existing)
                return self._record(existing)

            placeholders = ",".join("?" for _ in normalized.members)
            generation_rows = self._connection.execute(
                f"""SELECT bdf,generation,authority_id,authority_epoch FROM device_generations
                    WHERE host_id=? AND bdf IN ({placeholders}) ORDER BY bdf""",
                (normalized.host_id, *normalized.members),
            ).fetchall()
            generation_by_bdf = {row["bdf"]: row for row in generation_rows}
            unknown = [bdf for bdf in normalized.members if bdf not in generation_by_bdf]
            if unknown:
                raise LeaseStoreError(
                    Reason.DEVICE_GENERATION_UNKNOWN,
                    ",".join(unknown),
                )
            mixed_authority = [
                bdf
                for bdf in normalized.members
                if generation_by_bdf[bdf]["authority_id"] != self.trusted_authority_id
            ]
            if mixed_authority:
                raise LeaseStoreError(
                    Reason.AUTHORITY_SCOPE_MISMATCH,
                    ",".join(mixed_authority),
                )
            stale_snapshot = [
                bdf
                for bdf in normalized.members
                if generation_by_bdf[bdf]["authority_epoch"] != normalized.inventory_epoch
            ]
            if stale_snapshot:
                raise LeaseStoreError(
                    Reason.DEVICE_GENERATION_SNAPSHOT_MISMATCH,
                    ",".join(stale_snapshot),
                )
            stale_generation = [
                bdf
                for bdf in normalized.members
                if generation_by_bdf[bdf]["generation"]
                != normalized.expected_device_generations[bdf]
            ]
            if stale_generation:
                raise LeaseStoreError(
                    Reason.DEVICE_GENERATION_MISMATCH,
                    ",".join(stale_generation),
                )

            bundle_definition = self._connection.execute(
                """SELECT members_hash,members_json,authority_id,authority_epoch
                   FROM bundle_definitions
                   WHERE host_id=? AND bundle_id=?""",
                (normalized.host_id, normalized.bundle_id),
            ).fetchone()
            if bundle_definition is None:
                raise LeaseStoreError(Reason.BUNDLE_UNKNOWN, normalized.bundle_id)
            if bundle_definition["authority_id"] != self.trusted_authority_id:
                raise LeaseStoreError(
                    Reason.AUTHORITY_SCOPE_MISMATCH,
                    normalized.bundle_id,
                )
            if bundle_definition["members_hash"] != bundle_members_hash:
                raise LeaseStoreError(
                    Reason.BUNDLE_MEMBERS_MISMATCH,
                    normalized.bundle_id,
                )
            if bundle_definition["authority_epoch"] != normalized.inventory_epoch:
                raise LeaseStoreError(
                    Reason.BUNDLE_SNAPSHOT_MISMATCH,
                    normalized.bundle_id,
                )
            bundle_claim = self._connection.execute(
                """SELECT transaction_id FROM bundle_claims
                   WHERE host_id=? AND bundle_id=?""",
                (normalized.host_id, normalized.bundle_id),
            ).fetchone()
            if bundle_claim is not None:
                raise LeaseStoreError(
                    Reason.BUNDLE_BUSY,
                    normalized.bundle_id,
                )
            active_run = self._connection.execute(
                """SELECT transaction_id FROM transactions
                   WHERE host_id=? AND run_id=? AND state != ?""",
                (normalized.host_id, normalized.run_id, LeaseState.RELEASED.value),
            ).fetchone()
            if active_run is not None:
                raise LeaseStoreError(Reason.RUN_ID_BUSY, normalized.run_id)
            active_vm = self._connection.execute(
                """SELECT transaction_id FROM transactions
                   WHERE host_id=? AND vm_id=? AND state != ?""",
                (normalized.host_id, normalized.vm_id, LeaseState.RELEASED.value),
            ).fetchone()
            if active_vm is not None:
                raise LeaseStoreError(Reason.VM_TRANSACTION_BUSY, normalized.vm_id)

            generation_row = self._connection.execute(
                "SELECT generation FROM vm_generations WHERE host_id=? AND vm_id=?",
                (normalized.host_id, normalized.vm_id),
            ).fetchone()
            current_generation = 0 if generation_row is None else generation_row["generation"]
            if current_generation != normalized.expected_vm_generation:
                raise LeaseStoreError(
                    Reason.VM_GENERATION_MISMATCH,
                    f"expected {normalized.expected_vm_generation}, current {current_generation}",
                )

            conflicts = self._connection.execute(
                f"""SELECT bdf,transaction_id FROM member_claims
                    WHERE host_id=? AND bdf IN ({placeholders}) ORDER BY bdf""",
                (normalized.host_id, *normalized.members),
            ).fetchall()
            if conflicts:
                raise LeaseStoreError(
                    Reason.MEMBER_BUSY,
                    ",".join(row["bdf"] for row in conflicts),
                )

            vm_generation = current_generation + 1
            self._connection.execute(
                """INSERT INTO vm_generations(host_id,vm_id,generation) VALUES(?,?,?)
                   ON CONFLICT(host_id,vm_id) DO UPDATE SET generation=excluded.generation""",
                (normalized.host_id, normalized.vm_id, vm_generation),
            )
            transaction_id = self._required_text(
                "transaction_id", self._transaction_id_factory()
            )
            now = self._now()
            self._connection.execute(
                """INSERT INTO transactions(
                       transaction_id,idempotency_key,request_hash,host_id,vm_id,run_id,bundle_id,
                       authority_id,bundle_members_hash,members_json,inventory_epoch,
                       device_generations_json,
                       decision_hash,policy_hash,
                       vm_generation,state,revision,reason_code,reason_detail,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    transaction_id,
                    normalized.idempotency_key,
                    request_hash,
                    normalized.host_id,
                    normalized.vm_id,
                    normalized.run_id,
                    normalized.bundle_id,
                    self.trusted_authority_id,
                    bundle_members_hash,
                    self._json(normalized.members),
                    normalized.inventory_epoch,
                    self._json(normalized.expected_device_generations),
                    normalized.decision_hash,
                    normalized.policy_hash,
                    vm_generation,
                    LeaseState.RESERVED.value,
                    0,
                    None,
                    None,
                    now,
                    now,
                ),
            )
            self._connection.execute(
                """INSERT INTO bundle_claims(
                       host_id,bundle_id,members_hash,transaction_id,vm_generation)
                   VALUES(?,?,?,?,?)""",
                (
                    normalized.host_id,
                    normalized.bundle_id,
                    bundle_members_hash,
                    transaction_id,
                    vm_generation,
                ),
            )
            for bdf in normalized.members:
                self._connection.execute(
                    "INSERT INTO member_claims(host_id,bdf,transaction_id,vm_generation) VALUES(?,?,?,?)",
                    (normalized.host_id, bdf, transaction_id, vm_generation),
                )
            self._journal(
                transaction_id,
                "BEGIN_RESERVED",
                LeaseState.RESERVED,
                0,
                {"members": list(normalized.members), "vmGeneration": vm_generation},
            )
            self._fault("BEGIN_BEFORE_COMMIT")
            return self._record(self._row_by_id(transaction_id))

    def _transition(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        *,
        allowed: set[LeaseState],
        target: LeaseState,
        event: str,
        reason_code: str | None = None,
        reason_detail: str | None = None,
        release_claims: bool = False,
        require_current_vm: bool = True,
        require_current_facts: bool = False,
        stale_facts_quarantine: bool = False,
    ) -> LeaseRecord:
        with self._write():
            row = self._row_by_id(transaction_id)
            self._require_generation(
                row, vm_generation, require_current=require_current_vm
            )
            state = LeaseState(row["state"])
            if state is LeaseState.QUARANTINED and stale_facts_quarantine:
                return self._record(row)
            if require_current_facts:
                try:
                    self._require_transaction_facts(row)
                except LeaseStoreError as stale:
                    if not stale_facts_quarantine:
                        raise
                    target = LeaseState.QUARANTINED
                    event = "STALE_FACTS_QUARANTINED"
                    reason_code = stale.reason.value
                    reason_detail = stale.detail
                    release_claims = False
            if state is target:
                return self._record(row)
            if state not in allowed:
                raise LeaseStoreError(
                    Reason.INVALID_STATE_TRANSITION,
                    f"{state.value}->{target.value}",
                )
            if isinstance(expected_revision, bool) or row["revision"] != expected_revision:
                raise LeaseStoreError(
                    Reason.LEASE_REVISION_MISMATCH,
                    f"expected {expected_revision}, current {row['revision']}",
                )
            revision = row["revision"] + 1
            self._connection.execute(
                """UPDATE transactions
                   SET state=?,revision=?,reason_code=?,reason_detail=?,updated_at=?
                   WHERE transaction_id=?""",
                (
                    target.value,
                    revision,
                    reason_code,
                    reason_detail,
                    self._now(),
                    transaction_id,
                ),
            )
            if release_claims:
                self._connection.execute(
                    "DELETE FROM member_claims WHERE transaction_id=?", (transaction_id,)
                )
                self._connection.execute(
                    "DELETE FROM bundle_claims WHERE transaction_id=?", (transaction_id,)
                )
            self._journal(
                transaction_id,
                event,
                target,
                revision,
                {"reasonCode": reason_code} if reason_code else {},
            )
            self._fault(f"{event}_BEFORE_COMMIT")
            return self._record(self._row_by_id(transaction_id))

    def _release_with_generation_advance(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        *,
        allowed: set[LeaseState],
        event: str,
        reason_code: str,
        reason_detail: str,
        next_device_generations: Mapping[str, int] | None,
        next_authority_epoch: int | None,
        authority_id: str | None,
    ) -> LeaseRecord:
        if next_device_generations is None:
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT,
                "cleanup release requires next_device_generations",
            )
        next_generations = self._normalize_device_generations(next_device_generations)
        if next_authority_epoch is None:
            raise LeaseStoreError(
                Reason.INVALID_ARGUMENT, "cleanup release requires next_authority_epoch"
            )
        next_epoch = self._nonnegative("next_authority_epoch", next_authority_epoch)
        authority = self._required_text("authority_id", authority_id)
        self._require_trusted_authority(authority)
        code = self._required_text("reason_code", reason_code)
        if not isinstance(reason_detail, str):
            raise LeaseStoreError(Reason.INVALID_ARGUMENT, "reason_detail must be text")
        cleanup_request_hash = self._hash(
            {
                "authorityId": authority,
                "event": event,
                "nextAuthorityEpoch": next_epoch,
                "nextDeviceGenerations": dict(sorted(next_generations.items())),
                "reasonCode": code,
                "reasonDetail": reason_detail,
            }
        )
        with self._write():
            row = self._row_by_id(transaction_id)
            self._require_generation(row, vm_generation, require_current=False)
            if row["authority_id"] != self.trusted_authority_id:
                raise LeaseStoreError(
                    Reason.AUTHORITY_SCOPE_MISMATCH,
                    f"transaction={row['authority_id']}, store={self.trusted_authority_id}",
                )
            state = LeaseState(row["state"])
            if state is LeaseState.RELEASED:
                if row["cleanup_request_hash"] != cleanup_request_hash:
                    raise LeaseStoreError(
                        Reason.IDEMPOTENCY_CONFLICT,
                        "cleanup replay does not match committed release",
                    )
                return self._record(row)
            if state is LeaseState.QUARANTINED:
                if row["cleanup_request_hash"] not in (None, cleanup_request_hash):
                    raise LeaseStoreError(
                        Reason.IDEMPOTENCY_CONFLICT,
                        "cleanup replay does not match quarantined attempt",
                    )
                return self._record(row)
            self._require_generation(row, vm_generation, require_current=True)
            if state not in allowed:
                raise LeaseStoreError(
                    Reason.INVALID_STATE_TRANSITION,
                    f"{state.value}->{LeaseState.RELEASED.value}",
                )
            if isinstance(expected_revision, bool) or row["revision"] != expected_revision:
                raise LeaseStoreError(
                    Reason.LEASE_REVISION_MISMATCH,
                    f"expected {expected_revision}, current {row['revision']}",
                )
            try:
                self._require_transaction_facts(row)
            except LeaseStoreError as stale:
                revision = row["revision"] + 1
                self._connection.execute(
                    """UPDATE transactions SET state=?,revision=?,reason_code=?,
                           reason_detail=?,cleanup_request_hash=?,updated_at=?
                       WHERE transaction_id=?""",
                    (
                        LeaseState.QUARANTINED.value,
                        revision,
                        stale.reason.value,
                        stale.detail,
                        cleanup_request_hash,
                        self._now(),
                        transaction_id,
                    ),
                )
                self._journal(
                    transaction_id,
                    "STALE_FACTS_QUARANTINED",
                    LeaseState.QUARANTINED,
                    revision,
                    {"reasonCode": stale.reason.value},
                )
                return self._record(self._row_by_id(transaction_id))

            members = tuple(json.loads(row["members_json"]))
            if set(next_generations) != set(members):
                raise LeaseStoreError(
                    Reason.INVALID_ARGUMENT,
                    "next_device_generations must exactly cover lease members",
                )
            current_rows = self._connection.execute(
                f"""SELECT bdf,generation,authority_id,authority_epoch
                    FROM device_generations WHERE host_id=? AND bdf IN
                    ({','.join('?' for _ in members)})""",
                (row["host_id"], *members),
            ).fetchall()
            current = {item["bdf"]: item for item in current_rows}
            for bdf in members:
                item = current[bdf]
                if item["authority_id"] != authority:
                    raise LeaseStoreError(
                        Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
                        f"{bdf}: authority mismatch",
                    )
                proposed = next_generations[bdf]
                if state is LeaseState.RESERVED:
                    valid_generation = proposed == item["generation"]
                    valid_epoch = next_epoch == item["authority_epoch"]
                else:
                    valid_generation = proposed > item["generation"]
                    valid_epoch = next_epoch > item["authority_epoch"]
                if not valid_generation or not valid_epoch:
                    raise LeaseStoreError(
                        Reason.DEVICE_GENERATION_REGRESSION,
                        f"{bdf}: current={item['generation']}@{item['authority_epoch']}, "
                        f"next={proposed}@{next_epoch}",
                    )

            now = self._now()
            for bdf in members:
                self._connection.execute(
                    """UPDATE device_generations SET generation=?,authority_epoch=?,updated_at=?
                       WHERE host_id=? AND bdf=?""",
                    (next_generations[bdf], next_epoch, now, row["host_id"], bdf),
                )
            revision = row["revision"] + 1
            self._connection.execute(
                """UPDATE transactions SET state=?,revision=?,reason_code=?,reason_detail=?,
                       cleanup_request_hash=?,updated_at=? WHERE transaction_id=?""",
                (
                    LeaseState.RELEASED.value,
                    revision,
                    code,
                    reason_detail,
                    cleanup_request_hash,
                    now,
                    transaction_id,
                ),
            )
            self._connection.execute(
                "DELETE FROM member_claims WHERE transaction_id=?", (transaction_id,)
            )
            self._connection.execute(
                "DELETE FROM bundle_claims WHERE transaction_id=?", (transaction_id,)
            )
            self._journal(
                transaction_id,
                event,
                LeaseState.RELEASED,
                revision,
                {
                    "nextAuthorityEpoch": next_epoch,
                    "nextDeviceGenerations": dict(sorted(next_generations.items())),
                    "reasonCode": code,
                },
            )
            self._fault(f"{event}_BEFORE_COMMIT")
            return self._record(self._row_by_id(transaction_id))

    def prepare(
        self, transaction_id: str, vm_generation: int, expected_revision: int
    ) -> LeaseRecord:
        return self._transition(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={LeaseState.RESERVED},
            target=LeaseState.PREPARING,
            event="PREPARE_STARTED",
            require_current_facts=True,
        )

    def commit(
        self, transaction_id: str, vm_generation: int, expected_revision: int
    ) -> LeaseRecord:
        return self._transition(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={LeaseState.PREPARING},
            target=LeaseState.ATTACHED,
            event="ATTACH_COMMITTED",
            require_current_facts=True,
        )

    def begin_release(
        self, transaction_id: str, vm_generation: int, expected_revision: int
    ) -> LeaseRecord:
        return self._transition(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={LeaseState.ATTACHED},
            target=LeaseState.RELEASING,
            event="RELEASE_STARTED",
        )

    def quarantine(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        *,
        reason_code: str,
        reason_detail: str = "",
    ) -> LeaseRecord:
        code = self._required_text("reason_code", reason_code)
        return self._transition(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={
                LeaseState.RESERVED,
                LeaseState.PREPARING,
                LeaseState.ATTACHED,
                LeaseState.RELEASING,
            },
            target=LeaseState.QUARANTINED,
            event="QUARANTINED",
            reason_code=code,
            reason_detail=reason_detail,
            require_current_vm=False,
        )

    def rollback(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        *,
        cleanup_verified: bool,
        reason_code: str,
        reason_detail: str = "",
        next_device_generations: Mapping[str, int] | None = None,
        next_authority_epoch: int | None = None,
        authority_id: str | None = None,
    ) -> LeaseRecord:
        if cleanup_verified is not True:
            return self.quarantine(
                transaction_id,
                vm_generation,
                expected_revision,
                reason_code=Reason.CLEANUP_EVIDENCE_REQUIRED.value,
                reason_detail=reason_detail or reason_code,
            )
        return self._release_with_generation_advance(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={LeaseState.RESERVED, LeaseState.PREPARING},
            event="ROLLBACK_CLEAN",
            reason_code=reason_code,
            reason_detail=reason_detail,
            next_device_generations=next_device_generations,
            next_authority_epoch=next_authority_epoch,
            authority_id=authority_id,
        )

    def complete_release(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        *,
        cleanup_verified: bool,
        reason_code: str = "RELEASE_COMPLETE",
        reason_detail: str = "",
        next_device_generations: Mapping[str, int] | None = None,
        next_authority_epoch: int | None = None,
        authority_id: str | None = None,
    ) -> LeaseRecord:
        if cleanup_verified is not True:
            return self.quarantine(
                transaction_id,
                vm_generation,
                expected_revision,
                reason_code=Reason.CLEANUP_EVIDENCE_REQUIRED.value,
                reason_detail=reason_detail or reason_code,
            )
        return self._release_with_generation_advance(
            transaction_id,
            vm_generation,
            expected_revision,
            allowed={LeaseState.RELEASING},
            event="RELEASE_CLEAN",
            reason_code=reason_code,
            reason_detail=reason_detail,
            next_device_generations=next_device_generations,
            next_authority_epoch=next_authority_epoch,
            authority_id=authority_id,
        )

    def reconcile(
        self,
        transaction_id: str,
        vm_generation: int,
        expected_revision: int,
        observation: ReconcileObservation,
        *,
        reason_detail: str = "",
        next_device_generations: Mapping[str, int] | None = None,
        next_authority_epoch: int | None = None,
        authority_id: str | None = None,
    ) -> LeaseRecord:
        if not isinstance(observation, ReconcileObservation):
            raise LeaseStoreError(
                Reason.RECONCILE_OBSERVATION_INVALID,
                "only authoritative typed observations are accepted",
            )
        with self._write():
            row = self._row_by_id(transaction_id)
            self._require_generation(row, vm_generation, require_current=False)
            record = self._record(row)
        if (
            record.state in {LeaseState.RELEASED, LeaseState.QUARANTINED}
            and observation is not ReconcileObservation.CLEANUP_VERIFIED
        ):
            return record
        if observation is ReconcileObservation.ACTIVE_OWNER_VERIFIED:
            if record.state is not LeaseState.ATTACHED:
                return self.quarantine(
                    transaction_id,
                    vm_generation,
                    expected_revision,
                    reason_code=Reason.RECOVERY_REQUIRED.value,
                    reason_detail=reason_detail or "active owner contradicts durable state",
                )
            return self._transition(
                transaction_id,
                vm_generation,
                expected_revision,
                allowed={LeaseState.ATTACHED},
                target=LeaseState.ATTACHED,
                event="ACTIVE_OWNER_RECONCILED",
                require_current_facts=True,
                stale_facts_quarantine=True,
            )
        if observation is ReconcileObservation.CLEANUP_VERIFIED:
            return self._release_with_generation_advance(
                transaction_id,
                vm_generation,
                expected_revision,
                allowed={
                    LeaseState.RESERVED,
                    LeaseState.PREPARING,
                    LeaseState.ATTACHED,
                    LeaseState.RELEASING,
                },
                event="RECONCILE_CLEAN",
                reason_code="RECONCILE_CLEANUP_VERIFIED",
                reason_detail=reason_detail,
                next_device_generations=next_device_generations,
                next_authority_epoch=next_authority_epoch,
                authority_id=authority_id,
            )
        if observation is ReconcileObservation.UNSAFE_OR_UNKNOWN:
            return self.quarantine(
                transaction_id,
                vm_generation,
                expected_revision,
                reason_code=Reason.RECOVERY_REQUIRED.value,
                reason_detail=reason_detail or "cleanup or owner state is not authoritative",
            )
        raise AssertionError("unreachable typed reconciliation observation")

    def get(self, transaction_id: str) -> LeaseRecord:
        transaction_id = self._required_text("transaction_id", transaction_id)
        with self._lock:
            try:
                return self._record(self._row_by_id(transaction_id))
            except sqlite3.Error as error:
                raise LeaseStoreError(Reason.STORE_UNAVAILABLE, str(error)) from error

    def current_vm_generation(self, host_id: str, vm_id: str) -> int:
        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT generation FROM vm_generations WHERE host_id=? AND vm_id=?",
                    (host, self._required_text("vm_id", vm_id)),
                ).fetchone()
                return 0 if row is None else row["generation"]
            except sqlite3.Error as error:
                raise LeaseStoreError(Reason.STORE_UNAVAILABLE, str(error)) from error

    def claimed_members(self, host_id: str) -> Mapping[str, str]:
        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        with self._lock:
            rows = self._connection.execute(
                "SELECT bdf,transaction_id FROM member_claims WHERE host_id=? ORDER BY bdf",
                (host,),
            ).fetchall()
            return {row["bdf"]: row["transaction_id"] for row in rows}

    def current_device_generations(self, host_id: str) -> Mapping[str, int]:
        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        with self._lock:
            rows = self._connection.execute(
                """SELECT bdf,generation FROM device_generations
                   WHERE host_id=? ORDER BY bdf""",
                (host,),
            ).fetchall()
            return {row["bdf"]: row["generation"] for row in rows}

    def claimed_bundles(self, host_id: str) -> Mapping[str, str]:
        host = self._canonical_host_id(host_id)
        self._require_local_host(host)
        with self._lock:
            rows = self._connection.execute(
                """SELECT bundle_id,transaction_id FROM bundle_claims
                   WHERE host_id=? ORDER BY bundle_id""",
                (host,),
            ).fetchall()
            return {row["bundle_id"]: row["transaction_id"] for row in rows}

    def recovery_required(self) -> tuple[LeaseRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM transactions
                   WHERE state != ? ORDER BY created_at,transaction_id""",
                (LeaseState.RELEASED.value,),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def journal(self, transaction_id: str) -> tuple[JournalEntry, ...]:
        self.get(transaction_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM journal WHERE transaction_id=? ORDER BY sequence",
                (transaction_id,),
            ).fetchall()
            return tuple(
                JournalEntry(
                    sequence=row["sequence"],
                    transaction_id=row["transaction_id"],
                    event=row["event"],
                    state=LeaseState(row["state"]),
                    revision=row["revision"],
                    detail=json.loads(row["detail_json"]),
                    created_at=row["created_at"],
                )
                for row in rows
            )
