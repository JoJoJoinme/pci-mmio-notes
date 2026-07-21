"""Fail-closed persistence boundary for a Static DirectPath launch.

The envelope is bound to one concrete, open :class:`StaticLeaseStore`.  Lease
state is read directly from that store; callers cannot advance the envelope by
supplying a Boolean or a self-authored lease fact.  Because the two stores are
still separate SQLite databases, ``COMMIT_INTENT_DURABLE`` is an explicit crash
boundary and recovery always consults the authoritative lease.

QMP and DMA receipts use domain-separated HMAC-SHA256 assertions.  HMAC proves
component-level authenticity only: the verifier and this Python process share
key material, so this module does not claim independent product-observer or DMA
isolation proof.  It also cannot prevent another caller from bypassing this
component and invoking ``StaticLeaseStore.commit`` directly; product service
permissions must close that boundary.

``StaticLeaseStore`` v4 has a persistent ``store_instance_id``.  Both databases
pin their own resolved path and device/inode identity in addition to complete
schema/host/authority metadata.  Copying, moving, restoring, or replacing either
database invalidates the binding even when its logical rows are identical.  This
component therefore supports in-place reopen, not file-copy restore.

The production process verifier is the exact Linux default-path ``/proc``
boot-id plus process-starttime implementation.  It is not a pidfd and cannot
prove the process stays alive after each observation.  Injected callables are an
explicit LAB seam whose provenance is persisted and cannot reopen a production
store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
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
from types import MappingProxyType
from typing import Callable, ClassVar, Iterator, Mapping

from .static_lease import LeaseRecord, LeaseState, LeaseStoreError, StaticLeaseStore


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HMAC_SHA256 = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_CHALLENGE = re.compile(r"^challenge256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_HOST_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,255}$")
_LINUX_PROCESS_TOKEN = re.compile(
    r"^linux-proc-v1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([1-9][0-9]*)$"
)


class EnvelopeState(str, Enum):
    INTENT_PERSISTED = "INTENT_PERSISTED"
    LEASE_PREPARED = "LEASE_PREPARED"
    HANDLES_OPEN = "HANDLES_OPEN"
    QEMU_RUNNING = "QEMU_RUNNING"
    QMP_RECEIPT_VERIFIED = "QMP_RECEIPT_VERIFIED"
    DMA_RECEIPT_VERIFIED = "DMA_RECEIPT_VERIFIED"
    COMMIT_INTENT_DURABLE = "COMMIT_INTENT_DURABLE"
    ATTACHED_CONFIRMED = "ATTACHED_CONFIRMED"
    CLEANING = "CLEANING"
    QUARANTINED = "QUARANTINED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class ReceiptRole(str, Enum):
    QMP = "QMP"
    DMA = "DMA"


class ReceiptOutcome(str, Enum):
    QMP_DEVICE_OBSERVED = "QMP_DEVICE_OBSERVED"
    DMA_ISOLATION_ESTABLISHED = "DMA_ISOLATION_ESTABLISHED"


class RecoveryDisposition(str, Enum):
    CLEANUP_REQUIRED = "CLEANUP_REQUIRED"
    REQUIRE_AUTHORITATIVE_LEASE_RECONCILIATION = (
        "REQUIRE_AUTHORITATIVE_LEASE_RECONCILIATION"
    )
    OWNER_REVALIDATION_REQUIRED = "OWNER_REVALIDATION_REQUIRED"
    MAINTAIN_QUARANTINE = "MAINTAIN_QUARANTINE"


class EnvelopeReason(str, Enum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    STORE_NOT_DURABLE = "STORE_NOT_DURABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    METADATA_INTEGRITY_FAILURE = "METADATA_INTEGRITY_FAILURE"
    HOST_SCOPE_MISMATCH = "HOST_SCOPE_MISMATCH"
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    VERIFIER_CONFIG_MISMATCH = "VERIFIER_CONFIG_MISMATCH"
    LEASE_STORE_INVALID = "LEASE_STORE_INVALID"
    LEASE_STORE_UNAVAILABLE = "LEASE_STORE_UNAVAILABLE"
    LEASE_STORE_BINDING_MISMATCH = "LEASE_STORE_BINDING_MISMATCH"
    LEASE_FACT_MISMATCH = "LEASE_FACT_MISMATCH"
    TRANSACTION_NOT_FOUND = "TRANSACTION_NOT_FOUND"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    REVISION_MISMATCH = "REVISION_MISMATCH"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    REENTRANT_STORE_OPERATION = "REENTRANT_STORE_OPERATION"
    PROCESS_VERIFIER_UNAVAILABLE = "PROCESS_VERIFIER_UNAVAILABLE"
    PROCESS_IDENTITY_STALE = "PROCESS_IDENTITY_STALE"
    RECEIPT_ROLE_MISMATCH = "RECEIPT_ROLE_MISMATCH"
    RECEIPT_OBSERVER_UNKNOWN = "RECEIPT_OBSERVER_UNKNOWN"
    RECEIPT_SIGNATURE_INVALID = "RECEIPT_SIGNATURE_INVALID"
    RECEIPT_BINDING_MISMATCH = "RECEIPT_BINDING_MISMATCH"
    RECEIPT_OUTCOME_NOT_SUCCESS = "RECEIPT_OUTCOME_NOT_SUCCESS"
    RECEIPT_REPLAY = "RECEIPT_REPLAY"
    RECEIPTS_REQUIRED = "RECEIPTS_REQUIRED"


class EnvelopeStoreError(RuntimeError):
    def __init__(self, reason: EnvelopeReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason.value if not detail else f"{reason.value}: {detail}")


@dataclass(frozen=True)
class LaunchIntent:
    transaction_id: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    vm_generation: int
    planned_preparing_revision: int
    decision_hash: str
    policy_hash: str
    qmp_endpoint: str


@dataclass(frozen=True)
class SignedReceipt:
    PROTOCOL: ClassVar[str] = "QMAN_STATIC_LAUNCH_RECEIPT_V1"
    DOMAIN: ClassVar[str] = "qman.static-directpath.launch-observation"

    role: ReceiptRole
    observer_id: str
    envelope_store_id: str
    lease_store_binding_hash: str
    receipt_challenge: str
    transaction_id: str
    host_id: str
    authority_id: str
    lease_revision: int
    vm_generation: int
    decision_hash: str
    policy_hash: str
    launch_plan_hash: str | None
    fd_binding_hash: str
    qemu_pid: int
    qemu_start_token: str
    outcome: ReceiptOutcome
    nonce: str
    signature: str

    def canonical_payload(self) -> Mapping[str, object]:
        return {
            "authorityId": self.authority_id,
            "decisionHash": self.decision_hash,
            "domain": self.DOMAIN,
            "envelopeStoreId": self.envelope_store_id,
            "fdBindingHash": self.fd_binding_hash,
            "hostId": self.host_id,
            "launchPlanHash": self.launch_plan_hash,
            "leaseRevision": self.lease_revision,
            "leaseStoreBindingHash": self.lease_store_binding_hash,
            "nonce": self.nonce,
            "observerId": self.observer_id,
            "outcome": self.outcome.value,
            "policyHash": self.policy_hash,
            "protocol": self.PROTOCOL,
            "qemuPid": self.qemu_pid,
            "qemuStartToken": self.qemu_start_token,
            "receiptChallenge": self.receipt_challenge,
            "role": self.role.value,
            "transactionId": self.transaction_id,
            "vmGeneration": self.vm_generation,
        }

    @classmethod
    def sign(
        cls,
        *,
        key: bytes,
        role: ReceiptRole,
        observer_id: str,
        envelope_store_id: str,
        lease_store_binding_hash: str,
        receipt_challenge: str,
        transaction_id: str,
        host_id: str,
        authority_id: str,
        lease_revision: int,
        vm_generation: int,
        decision_hash: str,
        policy_hash: str,
        launch_plan_hash: str,
        fd_binding_hash: str,
        qemu_pid: int,
        qemu_start_token: str,
        outcome: ReceiptOutcome,
        nonce: str,
    ) -> "SignedReceipt":
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("receipt key must contain at least 32 bytes")
        if not isinstance(role, ReceiptRole) or not isinstance(outcome, ReceiptOutcome):
            raise ValueError("role and outcome must be typed enums")
        normalized = cls(
            role=role,
            observer_id=_value_identifier("observer_id", observer_id),
            envelope_store_id=_value_uuid("envelope_store_id", envelope_store_id),
            lease_store_binding_hash=_value_hash(
                "lease_store_binding_hash", lease_store_binding_hash
            ),
            receipt_challenge=_value_challenge(receipt_challenge),
            transaction_id=_value_identifier("transaction_id", transaction_id),
            host_id=_value_host(host_id),
            authority_id=_value_identifier("authority_id", authority_id),
            lease_revision=_value_uint("lease_revision", lease_revision),
            vm_generation=_value_positive("vm_generation", vm_generation),
            decision_hash=_value_hash("decision_hash", decision_hash),
            policy_hash=_value_hash("policy_hash", policy_hash),
            launch_plan_hash=_value_hash("launch_plan_hash", launch_plan_hash),
            fd_binding_hash=_value_hash("fd_binding_hash", fd_binding_hash),
            qemu_pid=_value_positive("qemu_pid", qemu_pid),
            qemu_start_token=_value_identifier("qemu_start_token", qemu_start_token),
            outcome=outcome,
            nonce=_value_nonce(nonce),
            signature="",
        )
        signature = hmac.new(
            key,
            _json(normalized.canonical_payload()).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return cls(**{**normalized.__dict__, "signature": f"hmac-sha256:{signature}"})


@dataclass(frozen=True)
class EnvelopeRecord:
    transaction_id: str
    host_id: str
    vm_id: str
    run_id: str
    bundle_id: str
    authority_id: str
    lease_idempotency_key: str
    bundle_members_hash: str
    members: tuple[str, ...]
    inventory_epoch: int
    device_generations: Mapping[str, int]
    vm_generation: int
    planned_preparing_revision: int
    decision_hash: str
    policy_hash: str
    launch_plan_hash: str | None
    qmp_endpoint: str
    envelope_store_id: str
    lease_store_binding_hash: str
    receipt_challenge: str
    fd_binding_hash: str | None
    qemu_pid: int | None
    qemu_start_token: str | None
    qmp_observer_id: str | None
    dma_observer_id: str | None
    attached_lease_revision: int | None
    recovery_origin_state: EnvelopeState | None
    state: EnvelopeState
    revision: int
    reason_code: str | None
    reason_detail: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class EnvelopeJournalEntry:
    sequence: int
    transaction_id: str
    event: str
    state: EnvelopeState
    revision: int
    detail: Mapping[str, object]
    created_at: str


@dataclass(frozen=True)
class DurabilityProfile:
    journal_mode: str
    synchronous: int
    persistence_boundary: str


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _value_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    text = value.strip()
    if any(ord(character) < 32 for character in text) or len(text) > 1024:
        raise ValueError(f"{name} contains invalid text")
    return text


def _value_identifier(name: str, value: object) -> str:
    text = _value_text(name, value)
    if not _IDENTIFIER.fullmatch(text):
        raise ValueError(f"{name} is not canonical")
    return text


def _value_host(value: object) -> str:
    host = _value_text("host_id", value).lower()
    if not _HOST_ID.fullmatch(host):
        raise ValueError("host_id is not canonical")
    return host


def _value_hash(name: str, value: object) -> str:
    digest = _value_text(name, value).lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError(f"{name} must be a canonical SHA-256 digest")
    return digest


def _value_uuid(name: str, value: object) -> str:
    text = _value_text(name, value).lower()
    try:
        parsed = uuid.UUID(text)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"{name} must be a canonical UUID") from error
    if parsed.version != 4 or str(parsed) != text:
        raise ValueError(f"{name} must be a canonical UUIDv4")
    return text


def _value_challenge(value: object) -> str:
    challenge = _value_text("receipt_challenge", value).lower()
    if not _CHALLENGE.fullmatch(challenge):
        raise ValueError("receipt_challenge must contain 256 bits")
    return challenge


def _value_uint(name: str, value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > (1 << 63) - 1
    ):
        raise ValueError(f"{name} must be an unsigned SQLite int64 value")
    return value


def _value_positive(name: str, value: object) -> int:
    number = _value_uint(name, value)
    if number == 0:
        raise ValueError(f"{name} must be positive")
    return number


def _value_nonce(value: object) -> str:
    nonce = _value_text("nonce", value)
    if not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be at least 16 canonical characters")
    return nonce


class StaticLaunchEnvelopeStore:
    """Durable, host-local ordering component bound to one lease database."""

    SCHEMA_VERSION = 4
    _PRODUCTION_PROCESS_PROVENANCE = "PRODUCTION_LINUX_PROC_BOOT_ID_STARTTIME_V1"
    _LAB_PROCESS_PROVENANCE = "LAB_INJECTED_CALLABLE_V1"
    _METADATA_KEYS = frozenset(
        {
            "schema_version",
            "local_host_id",
            "trusted_authority_id",
            "observer_config",
            "lease_store_binding_hash",
            "envelope_store_id",
            "envelope_store_resolved_path",
            "envelope_store_st_dev",
            "envelope_store_st_ino",
            "process_identity_verifier_provenance",
        }
    )
    _UPDATE_COLUMNS = frozenset(
        {
            "fd_binding_hash",
            "launch_plan_hash",
            "qemu_pid",
            "qemu_start_token",
            "qmp_observer_id",
            "dma_observer_id",
            "attached_lease_revision",
            "recovery_origin_state",
            "reason_code",
            "reason_detail",
        }
    )

    def __init__(
        self,
        path: str | Path,
        *,
        local_host_id: str,
        trusted_authority_id: str,
        authoritative_lease_store: StaticLeaseStore,
        verifier_keys: Mapping[ReceiptRole | str, Mapping[str, bytes]],
        process_identity_verifier: Callable[[int, str], bool] | None = None,
        process_identity_verifier_id: str | None = None,
        allow_lab_process_identity_verifier: bool = False,
        allow_unverified_filesystem_for_lab: bool = False,
        timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        raw_path = str(path)
        if raw_path == ":memory:" or raw_path.lower().startswith("file:"):
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_NOT_DURABLE, "a filesystem database is required"
            )
        raw_file = Path(path)
        if not raw_file.is_absolute():
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_NOT_DURABLE, "database path must be absolute"
            )
        if raw_file.is_symlink() or raw_file.parent.is_symlink():
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_NOT_DURABLE,
                "database path and parent must not be symlinks",
            )
        self.path = raw_file.resolve()
        if not self.path.parent.is_dir():
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_UNAVAILABLE,
                "database parent directory does not exist",
            )
        if self.path.exists() and not stat.S_ISREG(self.path.stat().st_mode):
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_NOT_DURABLE,
                "database path is not a regular file",
            )
        try:
            self.local_host_id = _value_host(local_host_id)
            self.trusted_authority_id = _value_identifier(
                "trusted_authority_id", trusted_authority_id
            )
            keys, observer_config = self._normalize_verifier_keys(verifier_keys)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error
        if type(authoritative_lease_store) is not StaticLeaseStore:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_INVALID,
                "authoritative_lease_store must be an exact StaticLeaseStore",
            )
        if not isinstance(allow_lab_process_identity_verifier, bool):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT,
                "allow_lab_process_identity_verifier must be bool",
            )
        if process_identity_verifier is None:
            if process_identity_verifier_id is not None:
                raise EnvelopeStoreError(
                    EnvelopeReason.INVALID_ARGUMENT,
                    "built-in process verifier does not accept a caller identity",
                )
            if not sys.platform.startswith("linux"):
                raise EnvelopeStoreError(
                    EnvelopeReason.PROCESS_VERIFIER_UNAVAILABLE,
                    "production verifier requires Linux /proc",
                )
            self._process_identity_verifier = (
                self._builtin_linux_process_identity_verifier
            )
            self.process_identity_verifier_id = self._PRODUCTION_PROCESS_PROVENANCE
            self.process_identity_verifier_provenance = _json(
                {
                    "bootIdPath": "/proc/sys/kernel/random/boot_id",
                    "implementation": self._PRODUCTION_PROCESS_PROVENANCE,
                    "mode": "PRODUCTION",
                    "procRoot": "/proc",
                }
            )
        else:
            if allow_lab_process_identity_verifier is not True:
                raise EnvelopeStoreError(
                    EnvelopeReason.PROCESS_VERIFIER_UNAVAILABLE,
                    "injected process verifier requires explicit LAB opt-in",
                )
            if not callable(process_identity_verifier):
                raise EnvelopeStoreError(
                    EnvelopeReason.INVALID_ARGUMENT,
                    "process_identity_verifier must be callable",
                )
            try:
                verifier_id = _value_identifier(
                    "process_identity_verifier_id", process_identity_verifier_id
                )
            except ValueError as error:
                raise EnvelopeStoreError(
                    EnvelopeReason.INVALID_ARGUMENT, str(error)
                ) from error
            self._process_identity_verifier = process_identity_verifier
            self.process_identity_verifier_id = verifier_id
            self.process_identity_verifier_provenance = _json(
                {
                    "id": verifier_id,
                    "implementation": self._LAB_PROCESS_PROVENANCE,
                    "mode": "LAB",
                }
            )
        self._lease_store = authoritative_lease_store
        self._verifier_keys = keys
        self._observer_config = observer_config
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._transaction_state_lock = threading.Lock()
        self._transaction_owner: int | None = None
        self._transaction_kind: str | None = None
        self.lease_store_binding_hash = self._compute_lease_store_binding_hash()
        if self.path == self._lease_store.path.resolve():
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_INVALID,
                "envelope and authoritative lease require different database files",
            )
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
            self._connection.execute("PRAGMA foreign_keys=ON")
            mode = str(
                self._connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            ).lower()
            if mode != "wal":
                raise EnvelopeStoreError(
                    EnvelopeReason.STORE_NOT_DURABLE, f"journal_mode={mode}"
                )
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute(
                "PRAGMA busy_timeout=%d" % max(0, int(timeout_seconds * 1000))
            )
            if self.path.is_symlink() or not stat.S_ISREG(self.path.stat().st_mode):
                raise EnvelopeStoreError(
                    EnvelopeReason.STORE_NOT_DURABLE,
                    "opened database path is not a regular non-symlink file",
                )
            (
                self._envelope_store_resolved_path,
                self._envelope_store_st_dev,
                self._envelope_store_st_ino,
            ) = self._capture_envelope_store_binding()
            self._initialize_or_validate_schema()
        except BaseException:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise

    @staticmethod
    def capture_linux_process_start_token(pid: int) -> str:
        """Capture Linux boot identity plus ``/proc/<pid>/stat`` starttime.

        This is an exact default-path component observation, not a pidfd and not
        a guarantee that the process remains alive after the read completes.
        """

        try:
            process_id = _value_positive("pid", pid)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error
        if not sys.platform.startswith("linux"):
            raise EnvelopeStoreError(
                EnvelopeReason.PROCESS_VERIFIER_UNAVAILABLE,
                "Linux /proc is required",
            )
        try:
            boot_id = (
                Path("/proc/sys/kernel/random/boot_id")
                .read_text(encoding="ascii")
                .strip()
                .lower()
            )
            if str(uuid.UUID(boot_id)) != boot_id:
                raise ValueError("boot_id is not canonical")
            stat_text = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
            closing_parenthesis = stat_text.rfind(")")
            if closing_parenthesis < 0 or not stat_text.startswith(f"{process_id} ("):
                raise ValueError("/proc stat identity is malformed")
            fields_after_comm = stat_text[closing_parenthesis + 1 :].split()
            if len(fields_after_comm) <= 19:
                raise ValueError("/proc stat lacks process starttime")
            starttime = fields_after_comm[19]
            if (
                not starttime.isascii()
                or not starttime.isdigit()
                or int(starttime) <= 0
            ):
                raise ValueError("/proc starttime is not a positive integer")
        except (OSError, ValueError) as error:
            raise EnvelopeStoreError(
                EnvelopeReason.PROCESS_IDENTITY_STALE, str(error)
            ) from error
        return f"linux-proc-v1:{boot_id}:{starttime}"

    @classmethod
    def _builtin_linux_process_identity_verifier(
        cls, pid: int, start_token: str
    ) -> bool:
        if not isinstance(start_token, str) or not _LINUX_PROCESS_TOKEN.fullmatch(
            start_token
        ):
            return False
        try:
            observed = cls.capture_linux_process_start_token(pid)
        except EnvelopeStoreError:
            return False
        return hmac.compare_digest(observed, start_token)

    @staticmethod
    def _normalize_verifier_keys(
        verifier_keys: Mapping[ReceiptRole | str, Mapping[str, bytes]],
    ) -> tuple[
        Mapping[ReceiptRole, Mapping[str, bytes]],
        Mapping[ReceiptRole, tuple[tuple[str, str], ...]],
    ]:
        if not isinstance(verifier_keys, Mapping):
            raise ValueError("verifier_keys must be a mapping")
        normalized: dict[ReceiptRole, dict[str, bytes]] = {
            ReceiptRole.QMP: {},
            ReceiptRole.DMA: {},
        }
        for raw_role, observer_keys in verifier_keys.items():
            try:
                role = (
                    raw_role
                    if isinstance(raw_role, ReceiptRole)
                    else ReceiptRole(raw_role)
                )
            except (TypeError, ValueError) as error:
                raise ValueError("verifier key role must be QMP or DMA") from error
            if not isinstance(observer_keys, Mapping) or not observer_keys:
                raise ValueError(f"{role.value} verifier map must not be empty")
            for raw_observer, key in observer_keys.items():
                observer = _value_identifier("observer_id", raw_observer)
                if not isinstance(key, bytes) or len(key) < 32:
                    raise ValueError("verifier keys must contain at least 32 bytes")
                normalized[role][observer] = bytes(key)
        if not normalized[ReceiptRole.QMP] or not normalized[ReceiptRole.DMA]:
            raise ValueError("independent QMP and DMA verifier keys are required")
        if set(normalized[ReceiptRole.QMP]) & set(normalized[ReceiptRole.DMA]):
            raise ValueError("QMP and DMA observer identities must be disjoint")
        for qmp_key in normalized[ReceiptRole.QMP].values():
            if any(
                hmac.compare_digest(qmp_key, dma_key)
                for dma_key in normalized[ReceiptRole.DMA].values()
            ):
                raise ValueError("QMP and DMA observers must use different keys")
        key_id_domain = b"qman-static-launch-envelope-verifier-key-id-v1"
        config = MappingProxyType(
            {
                role: tuple(
                    sorted(
                        (
                            observer,
                            "hmac-sha256:"
                            + hmac.new(key, key_id_domain, hashlib.sha256).hexdigest(),
                        )
                        for observer, key in values.items()
                    )
                )
                for role, values in normalized.items()
            }
        )
        keys = MappingProxyType(
            {
                role: MappingProxyType(dict(values))
                for role, values in normalized.items()
            }
        )
        return keys, config

    def _compute_lease_store_binding_hash(self) -> str:
        store = self._lease_store
        try:
            with store._lock:  # exact pinned schema; one coherent identity snapshot
                store._connection.execute("SELECT 1").fetchone()
                if store.path.is_symlink():
                    raise EnvelopeStoreError(
                        EnvelopeReason.LEASE_STORE_INVALID,
                        "authoritative lease path is a symlink",
                    )
                path = store.path.resolve(strict=True)
                if not stat.S_ISREG(path.stat().st_mode):
                    raise EnvelopeStoreError(
                        EnvelopeReason.LEASE_STORE_INVALID,
                        "authoritative lease path is not a regular non-symlink file",
                    )
                database_path = store._connection.execute(
                    "PRAGMA database_list"
                ).fetchone()[2]
                if Path(database_path).resolve(strict=True) != path:
                    raise EnvelopeStoreError(
                        EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                        "lease connection path differs from configured path",
                    )
                rows = store._connection.execute(
                    "SELECT key,value FROM metadata ORDER BY key"
                ).fetchall()
                metadata = {row["key"]: row["value"] for row in rows}
        except EnvelopeStoreError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_UNAVAILABLE, str(error)
            ) from error
        required = {
            "schema_version": str(StaticLeaseStore.SCHEMA_VERSION),
            "local_host_id": self.local_host_id,
            "trusted_authority_id": self.trusted_authority_id,
            "store_instance_id": store.store_instance_id,
        }
        if set(metadata) != set(required) or any(
            metadata.get(key) != value for key, value in required.items()
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                "lease schema/host/authority metadata does not match envelope scope",
            )
        if (
            store.local_host_id != self.local_host_id
            or store.trusted_authority_id != self.trusted_authority_id
            or metadata["store_instance_id"] != store.store_instance_id
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                "lease store object scope does not match persisted metadata",
            )
        identity = path.stat()
        return _digest(
            {
                "localHostId": required["local_host_id"],
                "path": str(path),
                "schemaVersion": required["schema_version"],
                "stDev": identity.st_dev,
                "stIno": identity.st_ino,
                "storeInstanceId": required["store_instance_id"],
                "trustedAuthorityId": required["trusted_authority_id"],
                "metadata": dict(sorted(metadata.items())),
            }
        )

    def _assert_live_lease_store_binding(self) -> None:
        if self._compute_lease_store_binding_hash() != self.lease_store_binding_hash:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                "authoritative lease database was moved, copied, or replaced",
            )

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
        raise EnvelopeStoreError(EnvelopeReason.STORE_NOT_DURABLE, detail)

    def _schema_statements(self) -> tuple[str, ...]:
        states = ",".join(f"'{state.value}'" for state in EnvelopeState)
        return (
            """CREATE TABLE metadata (
                   key TEXT PRIMARY KEY,
                   value TEXT NOT NULL
               )""",
            f"""CREATE TABLE envelopes (
                   transaction_id TEXT PRIMARY KEY,
                   request_hash TEXT NOT NULL,
                   host_id TEXT NOT NULL,
                   vm_id TEXT NOT NULL,
                   run_id TEXT NOT NULL,
                   bundle_id TEXT NOT NULL,
                   authority_id TEXT NOT NULL,
                   lease_idempotency_key TEXT NOT NULL,
                   bundle_members_hash TEXT NOT NULL,
                   members_json TEXT NOT NULL,
                   inventory_epoch INTEGER NOT NULL CHECK (inventory_epoch >= 0),
                   device_generations_json TEXT NOT NULL,
                   vm_generation INTEGER NOT NULL CHECK (vm_generation > 0),
                   planned_preparing_revision INTEGER NOT NULL
                       CHECK (planned_preparing_revision > 0),
                   decision_hash TEXT NOT NULL,
                   policy_hash TEXT NOT NULL,
                   launch_plan_hash TEXT,
                   qmp_endpoint TEXT NOT NULL UNIQUE,
                   receipt_challenge TEXT NOT NULL,
                   fd_binding_hash TEXT,
                   qemu_pid INTEGER,
                   qemu_start_token TEXT,
                   qmp_observer_id TEXT,
                   dma_observer_id TEXT,
                   attached_lease_revision INTEGER,
                   recovery_origin_state TEXT,
                   state TEXT NOT NULL CHECK (state IN ({states})),
                   revision INTEGER NOT NULL CHECK (revision >= 0),
                   last_request_hash TEXT NOT NULL,
                   reason_code TEXT,
                   reason_detail TEXT,
                   created_at TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   UNIQUE(host_id, run_id)
               )""",
            """CREATE TABLE receipts (
                   transaction_id TEXT NOT NULL REFERENCES envelopes(transaction_id),
                   role TEXT NOT NULL CHECK (role IN ('QMP','DMA')),
                   observer_id TEXT NOT NULL,
                   nonce TEXT NOT NULL,
                   outcome TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   payload_hash TEXT NOT NULL,
                   signature TEXT NOT NULL,
                   verified_at TEXT NOT NULL,
                   PRIMARY KEY (transaction_id, role),
                   UNIQUE(observer_id, nonce)
               )""",
            """CREATE TABLE journal (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   transaction_id TEXT NOT NULL REFERENCES envelopes(transaction_id),
                   event TEXT NOT NULL,
                   state TEXT NOT NULL,
                   revision INTEGER NOT NULL,
                   detail_json TEXT NOT NULL,
                   created_at TEXT NOT NULL
               )""",
            """CREATE INDEX journal_transaction_sequence
                   ON journal(transaction_id, sequence)""",
        )

    def _capture_envelope_store_binding(self) -> tuple[str, int, int]:
        """Return the physical identity of the configured envelope database.

        The identity deliberately includes the resolved path as well as the
        filesystem device/inode pair.  A copied database must not inherit the
        authority of the original store merely because it contains the same
        UUID, challenge, rows, and HMAC-verifier configuration.
        """

        try:
            if self.path.is_symlink():
                raise OSError("envelope database path became a symlink")
            resolved = self.path.resolve(strict=True)
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                raise OSError("envelope database path is not a regular file")
        except OSError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_UNAVAILABLE, str(error)
            ) from error
        return str(resolved), int(info.st_dev), int(info.st_ino)

    def _assert_live_envelope_store_binding(self) -> None:
        observed = self._capture_envelope_store_binding()
        expected = (
            self._envelope_store_resolved_path,
            self._envelope_store_st_dev,
            self._envelope_store_st_ino,
        )
        if observed != expected:
            raise EnvelopeStoreError(
                EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                "envelope database resolved path/device/inode binding changed",
            )

    def _configured_metadata(self, envelope_store_id: str) -> dict[str, str]:
        return {
            "schema_version": str(self.SCHEMA_VERSION),
            "local_host_id": self.local_host_id,
            "trusted_authority_id": self.trusted_authority_id,
            "observer_config": _json(
                {
                    role.value: [
                        {"keyConfirmation": key_id, "observerId": observer}
                        for observer, key_id in observers
                    ]
                    for role, observers in self._observer_config.items()
                }
            ),
            "lease_store_binding_hash": self.lease_store_binding_hash,
            "envelope_store_id": envelope_store_id,
            "envelope_store_resolved_path": self._envelope_store_resolved_path,
            "envelope_store_st_dev": str(self._envelope_store_st_dev),
            "envelope_store_st_ino": str(self._envelope_store_st_ino),
            "process_identity_verifier_provenance": (
                self.process_identity_verifier_provenance
            ),
        }

    @staticmethod
    def _canonical_sql(sql: str | None) -> str | None:
        return None if sql is None else " ".join(sql.strip().rstrip(";").split())

    @classmethod
    def _schema_signature(cls, connection: sqlite3.Connection) -> object:
        object_rows = connection.execute(
            """SELECT type,name,sql FROM sqlite_master
               WHERE type IN ('table','index','view','trigger')
                 AND name NOT LIKE 'sqlite_%'
               ORDER BY type,name"""
        ).fetchall()
        objects = tuple(
            (row[0], row[1], cls._canonical_sql(row[2])) for row in object_rows
        )
        tables: list[object] = []
        for object_type, name, _ in objects:
            if object_type != "table":
                continue
            quoted = name.replace('"', '""')
            columns = tuple(
                tuple(row)
                for row in connection.execute(
                    f'PRAGMA table_xinfo("{quoted}")'
                ).fetchall()
            )
            foreign_keys = tuple(
                tuple(row)
                for row in connection.execute(
                    f'PRAGMA foreign_key_list("{quoted}")'
                ).fetchall()
            )
            indexes: list[object] = []
            for index_row in connection.execute(
                f'PRAGMA index_list("{quoted}")'
            ).fetchall():
                index_name = index_row[1]
                quoted_index = index_name.replace('"', '""')
                index_columns = tuple(
                    tuple(row)
                    for row in connection.execute(
                        f'PRAGMA index_xinfo("{quoted_index}")'
                    ).fetchall()
                )
                indexes.append((tuple(index_row), index_columns))
            tables.append((name, columns, foreign_keys, tuple(indexes)))
        return objects, tuple(tables)

    def _expected_schema_signature(self) -> object:
        reference = sqlite3.connect(":memory:")
        try:
            reference.execute("PRAGMA foreign_keys=ON")
            for statement in self._schema_statements():
                reference.execute(statement)
            return self._schema_signature(reference)
        finally:
            reference.close()

    def _require_exact_schema(self) -> None:
        self._require_exact_temporary_schema()
        if (
            self._schema_signature(self._connection)
            != self._expected_schema_signature()
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                "envelope schema DDL or structure differs from the pinned schema",
            )

    def _require_pinned_envelope_metadata(self) -> None:
        self._assert_live_envelope_store_binding()
        rows = self._connection.execute(
            "SELECT key,value FROM metadata ORDER BY key"
        ).fetchall()
        metadata = {row["key"]: row["value"] for row in rows}
        expected = self._configured_metadata(self.envelope_store_id)
        if (
            set(metadata) != self._METADATA_KEYS
            or len(rows) != len(metadata)
            or metadata != expected
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                "envelope identity metadata changed after open",
            )

    def _initialize_or_validate_schema(self) -> None:
        with self._owned_transaction("SCHEMA_INITIALIZE"):
            self._require_exact_temporary_schema()
            objects = self._connection.execute(
                """SELECT type,name FROM sqlite_master
                   WHERE type IN ('table','index','view','trigger')
                     AND name NOT LIKE 'sqlite_%'"""
            ).fetchall()
            if not objects:
                envelope_store_id = str(uuid.uuid4())
                statements = self._schema_statements()
                for statement in statements[:-1]:
                    self._connection.execute(statement)
                self._fault("SCHEMA_AFTER_DDL")
                self._connection.execute(statements[-1])
                self._require_exact_schema()
                metadata = self._configured_metadata(envelope_store_id)
                self._connection.executemany(
                    "INSERT INTO metadata(key,value) VALUES(?,?)",
                    sorted(metadata.items()),
                )
                self._fault("SCHEMA_INITIALIZE_BEFORE_COMMIT")
            else:
                self._require_exact_schema()
                rows = self._connection.execute(
                    "SELECT key,value FROM metadata ORDER BY key"
                ).fetchall()
                metadata = {row["key"]: row["value"] for row in rows}
                if set(metadata) != self._METADATA_KEYS or len(rows) != len(metadata):
                    raise EnvelopeStoreError(
                        EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                        "metadata keys are incomplete, duplicated, or unexpected",
                    )
                try:
                    envelope_store_id = _value_uuid(
                        "envelope_store_id", metadata["envelope_store_id"]
                    )
                except ValueError as error:
                    raise EnvelopeStoreError(
                        EnvelopeReason.METADATA_INTEGRITY_FAILURE, str(error)
                    ) from error
                configured = self._configured_metadata(envelope_store_id)
                if metadata != configured:
                    reason = EnvelopeReason.METADATA_INTEGRITY_FAILURE
                    if metadata["local_host_id"] != self.local_host_id:
                        reason = EnvelopeReason.HOST_SCOPE_MISMATCH
                    elif metadata["trusted_authority_id"] != self.trusted_authority_id:
                        reason = EnvelopeReason.AUTHORITY_SCOPE_MISMATCH
                    elif metadata["observer_config"] != configured["observer_config"]:
                        reason = EnvelopeReason.VERIFIER_CONFIG_MISMATCH
                    elif (
                        metadata["lease_store_binding_hash"]
                        != self.lease_store_binding_hash
                    ):
                        reason = EnvelopeReason.LEASE_STORE_BINDING_MISMATCH
                    raise EnvelopeStoreError(reason, "persisted store binding differs")
        self.envelope_store_id = envelope_store_id

    def _require_exact_temporary_schema(self) -> None:
        temporary_objects = self._connection.execute(
            """SELECT type,name FROM sqlite_temp_master
               WHERE type IN ('table','index','view','trigger')
                 AND name NOT LIKE 'sqlite_%'
               ORDER BY type,name"""
        ).fetchall()
        if temporary_objects:
            raise EnvelopeStoreError(
                EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                "temporary schema objects are forbidden on the authoritative connection",
            )

    def _claim_transaction(self, kind: str) -> None:
        owner = threading.get_ident()
        with self._transaction_state_lock:
            if self._transaction_owner is not None:
                raise EnvelopeStoreError(
                    EnvelopeReason.REENTRANT_STORE_OPERATION,
                    f"active={self._transaction_kind}, requested={kind}",
                )
            self._transaction_owner = owner
            self._transaction_kind = kind

    def _release_transaction(self, kind: str) -> None:
        owner = threading.get_ident()
        with self._transaction_state_lock:
            if self._transaction_owner != owner or self._transaction_kind != kind:
                raise RuntimeError("envelope transaction ownership is inconsistent")
            self._transaction_owner = None
            self._transaction_kind = None

    @contextmanager
    def _owned_transaction(self, kind: str) -> Iterator[None]:
        with self._lock:
            self._claim_transaction(kind)
            try:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    yield
                    self._connection.execute("COMMIT")
                except EnvelopeStoreError:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    raise
                except sqlite3.Error as error:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    raise EnvelopeStoreError(
                        EnvelopeReason.STORE_UNAVAILABLE, str(error)
                    ) from error
                except BaseException:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    raise
            finally:
                self._release_transaction(kind)

    def close(self) -> None:
        with self._lock:
            with self._transaction_state_lock:
                if self._transaction_owner is not None:
                    raise EnvelopeStoreError(
                        EnvelopeReason.REENTRANT_STORE_OPERATION,
                        f"cannot close during {self._transaction_kind}",
                    )
            self._connection.close()

    def __enter__(self) -> "StaticLaunchEnvelopeStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _write(self) -> Iterator[None]:
        """Commit one envelope mutation while the outer lease guard is live.

        Every call site is nested inside ``_authoritative_lease_guard``.  The
        final lease/store/schema checks intentionally run after the staged
        mutation but before ``_owned_transaction`` commits, so a failed final
        check rolls the entire envelope operation back.
        """

        with self._owned_transaction("WRITE"):
            self._require_exact_schema()
            self._require_pinned_envelope_metadata()
            self._assert_live_lease_store_binding()
            yield
            self._assert_live_lease_store_binding()
            self._require_exact_schema()
            self._require_pinned_envelope_metadata()

    def _now(self) -> str:
        return self._clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    @staticmethod
    def _operation_hash(operation: str, detail: Mapping[str, object]) -> str:
        return _digest({"detail": detail, "operation": operation})

    def _record(self, row: sqlite3.Row) -> EnvelopeRecord:
        origin = row["recovery_origin_state"]
        return EnvelopeRecord(
            transaction_id=row["transaction_id"],
            host_id=row["host_id"],
            vm_id=row["vm_id"],
            run_id=row["run_id"],
            bundle_id=row["bundle_id"],
            authority_id=row["authority_id"],
            lease_idempotency_key=row["lease_idempotency_key"],
            bundle_members_hash=row["bundle_members_hash"],
            members=tuple(json.loads(row["members_json"])),
            inventory_epoch=row["inventory_epoch"],
            device_generations=json.loads(row["device_generations_json"]),
            vm_generation=row["vm_generation"],
            planned_preparing_revision=row["planned_preparing_revision"],
            decision_hash=row["decision_hash"],
            policy_hash=row["policy_hash"],
            launch_plan_hash=row["launch_plan_hash"],
            qmp_endpoint=row["qmp_endpoint"],
            envelope_store_id=self.envelope_store_id,
            lease_store_binding_hash=self.lease_store_binding_hash,
            receipt_challenge=row["receipt_challenge"],
            fd_binding_hash=row["fd_binding_hash"],
            qemu_pid=row["qemu_pid"],
            qemu_start_token=row["qemu_start_token"],
            qmp_observer_id=row["qmp_observer_id"],
            dma_observer_id=row["dma_observer_id"],
            attached_lease_revision=row["attached_lease_revision"],
            recovery_origin_state=EnvelopeState(origin) if origin else None,
            state=EnvelopeState(row["state"]),
            revision=row["revision"],
            reason_code=row["reason_code"],
            reason_detail=row["reason_detail"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _row(self, transaction_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM envelopes WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        if row is None:
            raise EnvelopeStoreError(
                EnvelopeReason.TRANSACTION_NOT_FOUND, transaction_id
            )
        return row

    def _journal(
        self,
        transaction_id: str,
        event: str,
        state: EnvelopeState,
        revision: int,
        detail: Mapping[str, object] | None = None,
    ) -> None:
        self._connection.execute(
            """INSERT INTO journal(transaction_id,event,state,revision,detail_json,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                transaction_id,
                event,
                state.value,
                revision,
                _json(detail or {}),
                self._now(),
            ),
        )

    def _transition_locked(
        self,
        row: sqlite3.Row,
        *,
        expected_revision: int,
        allowed: set[EnvelopeState],
        target: EnvelopeState,
        event: str,
        request_hash: str,
        updates: Mapping[str, object] | None = None,
        journal_detail: Mapping[str, object] | None = None,
    ) -> tuple[EnvelopeRecord, bool]:
        state = EnvelopeState(row["state"])
        if state is target and row["revision"] == expected_revision + 1:
            if row["last_request_hash"] != request_hash:
                raise EnvelopeStoreError(
                    EnvelopeReason.IDEMPOTENCY_CONFLICT,
                    f"{event} replay payload differs",
                )
            return self._record(row), True
        if row["revision"] != expected_revision:
            raise EnvelopeStoreError(
                EnvelopeReason.REVISION_MISMATCH,
                f"expected {expected_revision}, current {row['revision']}",
            )
        if state not in allowed:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_STATE_TRANSITION,
                f"{state.value}->{target.value}",
            )
        values = dict(updates or {})
        unknown = set(values) - self._UPDATE_COLUMNS
        if unknown:
            raise AssertionError(f"unsafe internal update columns: {sorted(unknown)}")
        revision = row["revision"] + 1
        assignments = ["state=?", "revision=?", "last_request_hash=?", "updated_at=?"]
        parameters: list[object] = [target.value, revision, request_hash, self._now()]
        for column in sorted(values):
            assignments.append(f"{column}=?")
            parameters.append(values[column])
        parameters.append(row["transaction_id"])
        self._connection.execute(
            f"UPDATE envelopes SET {','.join(assignments)} WHERE transaction_id=?",
            parameters,
        )
        self._journal(row["transaction_id"], event, target, revision, journal_detail)
        self._fault(f"{event}_BEFORE_COMMIT")
        return self._record(self._row(row["transaction_id"])), False

    @staticmethod
    def _lease_snapshot(record: LeaseRecord) -> dict[str, object]:
        return {
            "authorityId": record.authority_id,
            "bundleId": record.bundle_id,
            "bundleMembersHash": record.bundle_members_hash,
            "decisionHash": record.decision_hash,
            "deviceGenerations": dict(sorted(record.device_generations.items())),
            "hostId": record.host_id,
            "idempotencyKey": record.idempotency_key,
            "inventoryEpoch": record.inventory_epoch,
            "members": list(record.members),
            "policyHash": record.policy_hash,
            "runId": record.run_id,
            "transactionId": record.transaction_id,
            "vmGeneration": record.vm_generation,
            "vmId": record.vm_id,
        }

    @contextmanager
    def _authoritative_lease_guard(
        self,
        transaction_id: str,
        vm_generation: int,
        lease_revision: int,
        *,
        expected_state: LeaseState,
        require_current_facts: bool,
        require_claims: bool,
    ) -> Iterator[LeaseRecord]:
        """Acquire the lease snapshot before any envelope transaction."""

        try:
            with self._lease_store.authorize_state_snapshot(
                transaction_id,
                vm_generation,
                lease_revision,
                expected_state=expected_state,
                require_current_facts=require_current_facts,
                require_claims=require_claims,
            ) as record:
                self._assert_live_lease_store_binding()
                self._validate_authoritative_lease(record)
                yield record
        except EnvelopeStoreError:
            raise
        except LeaseStoreError as error:
            reason = (
                EnvelopeReason.LEASE_STORE_UNAVAILABLE
                if error.reason.value
                in {
                    "STORE_UNAVAILABLE",
                    "STORE_TRANSACTION_ACTIVE",
                    "LAUNCH_AUTHORIZATION_ACTIVE",
                }
                else EnvelopeReason.LEASE_FACT_MISMATCH
            )
            raise EnvelopeStoreError(
                reason, f"{error.reason.value}: {error.detail}"
            ) from error
        except sqlite3.Error as error:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_STORE_UNAVAILABLE, str(error)
            ) from error

    def _validate_authoritative_lease(
        self, record: LeaseRecord, envelope_row: sqlite3.Row | None = None
    ) -> None:
        if (
            record.host_id != self.local_host_id
            or record.authority_id != self.trusted_authority_id
            or StaticLeaseStore.compute_bundle_members_hash(
                record.host_id, record.bundle_id, record.members
            )
            != record.bundle_members_hash
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_FACT_MISMATCH,
                "authoritative lease ownership/snapshot facts are inconsistent",
            )
        if envelope_row is None:
            return
        persisted = {
            "authorityId": envelope_row["authority_id"],
            "bundleId": envelope_row["bundle_id"],
            "bundleMembersHash": envelope_row["bundle_members_hash"],
            "decisionHash": envelope_row["decision_hash"],
            "deviceGenerations": json.loads(envelope_row["device_generations_json"]),
            "hostId": envelope_row["host_id"],
            "idempotencyKey": envelope_row["lease_idempotency_key"],
            "inventoryEpoch": envelope_row["inventory_epoch"],
            "members": json.loads(envelope_row["members_json"]),
            "policyHash": envelope_row["policy_hash"],
            "runId": envelope_row["run_id"],
            "transactionId": envelope_row["transaction_id"],
            "vmGeneration": envelope_row["vm_generation"],
            "vmId": envelope_row["vm_id"],
        }
        if self._lease_snapshot(record) != persisted:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_FACT_MISMATCH,
                "authoritative lease no longer matches persisted envelope snapshot",
            )

    def _peek_authoritative_lease(self, transaction_id: str) -> LeaseRecord:
        try:
            with self._lease_store._lock:
                self._assert_live_lease_store_binding()
                return self._lease_store.get(transaction_id)
        except EnvelopeStoreError:
            raise
        except LeaseStoreError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_FACT_MISMATCH,
                f"{error.reason.value}: {error.detail}",
            ) from error

    def _normalize_intent(self, intent: LaunchIntent) -> dict[str, object]:
        if not isinstance(intent, LaunchIntent):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, "intent must be LaunchIntent"
            )
        try:
            endpoint = Path(_value_text("qmp_endpoint", intent.qmp_endpoint))
            if not endpoint.is_absolute():
                raise ValueError("qmp_endpoint must be an absolute filesystem path")
            if endpoint.is_symlink():
                raise ValueError("qmp_endpoint must not be a symlink")
            if endpoint.parent.is_symlink() or not endpoint.parent.is_dir():
                raise ValueError(
                    "qmp_endpoint parent must be an existing non-symlink directory"
                )
            normalized = {
                "transactionId": _value_identifier(
                    "transaction_id", intent.transaction_id
                ),
                "hostId": _value_host(intent.host_id),
                "vmId": _value_identifier("vm_id", intent.vm_id),
                "runId": _value_identifier("run_id", intent.run_id),
                "bundleId": _value_identifier("bundle_id", intent.bundle_id),
                "vmGeneration": _value_positive("vm_generation", intent.vm_generation),
                "plannedPreparingRevision": _value_positive(
                    "planned_preparing_revision", intent.planned_preparing_revision
                ),
                "decisionHash": _value_hash("decision_hash", intent.decision_hash),
                "policyHash": _value_hash("policy_hash", intent.policy_hash),
                "qmpEndpoint": str(endpoint.resolve(strict=False)),
            }
        except (OSError, ValueError) as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error
        if normalized["hostId"] != self.local_host_id:
            raise EnvelopeStoreError(
                EnvelopeReason.HOST_SCOPE_MISMATCH,
                f"store={self.local_host_id}, request={normalized['hostId']}",
            )
        return normalized

    def begin(self, intent: LaunchIntent) -> EnvelopeRecord:
        normalized = self._normalize_intent(intent)
        intent_hash = _digest(normalized)
        transaction_id = str(normalized["transactionId"])
        with self._lease_store._lock:
            self._assert_live_lease_store_binding()
            with self._lock:
                self._require_exact_schema()
                self._require_pinned_envelope_metadata()
                existing = self._connection.execute(
                    "SELECT * FROM envelopes WHERE transaction_id=?",
                    (transaction_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != intent_hash:
                        raise EnvelopeStoreError(
                            EnvelopeReason.IDEMPOTENCY_CONFLICT,
                            "transaction_id was reused for a different intent",
                        )
                    return self._record(existing)
        planned_revision = int(normalized["plannedPreparingRevision"])
        with self._authoritative_lease_guard(
            transaction_id,
            int(normalized["vmGeneration"]),
            planned_revision - 1,
            expected_state=LeaseState.RESERVED,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            expected_intent_facts = {
                "bundleId": lease.bundle_id,
                "decisionHash": lease.decision_hash,
                "hostId": lease.host_id,
                "policyHash": lease.policy_hash,
                "runId": lease.run_id,
                "transactionId": lease.transaction_id,
                "vmGeneration": lease.vm_generation,
                "vmId": lease.vm_id,
            }
            actual_intent_facts = {
                key: normalized[key] for key in expected_intent_facts
            }
            if actual_intent_facts != expected_intent_facts:
                raise EnvelopeStoreError(
                    EnvelopeReason.LEASE_FACT_MISMATCH,
                    "launch intent does not match authoritative RESERVED lease",
                )
            with self._write():
                existing = self._connection.execute(
                    "SELECT * FROM envelopes WHERE transaction_id=?",
                    (transaction_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != intent_hash:
                        raise EnvelopeStoreError(
                            EnvelopeReason.IDEMPOTENCY_CONFLICT,
                            "transaction_id was reused for a different intent",
                        )
                    return self._record(existing)
                challenge = "challenge256:" + secrets.token_hex(32)
                now = self._now()
                try:
                    self._connection.execute(
                        """INSERT INTO envelopes(
                           transaction_id,request_hash,host_id,vm_id,run_id,bundle_id,
                           authority_id,lease_idempotency_key,bundle_members_hash,
                           members_json,inventory_epoch,device_generations_json,
                           vm_generation,planned_preparing_revision,decision_hash,
                           policy_hash,launch_plan_hash,qmp_endpoint,receipt_challenge,
                           state,revision,last_request_hash,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            transaction_id,
                            intent_hash,
                            lease.host_id,
                            lease.vm_id,
                            lease.run_id,
                            lease.bundle_id,
                            lease.authority_id,
                            lease.idempotency_key,
                            lease.bundle_members_hash,
                            _json(list(lease.members)),
                            lease.inventory_epoch,
                            _json(dict(sorted(lease.device_generations.items()))),
                            lease.vm_generation,
                            planned_revision,
                            lease.decision_hash,
                            lease.policy_hash,
                            None,
                            normalized["qmpEndpoint"],
                            challenge,
                            EnvelopeState.INTENT_PERSISTED.value,
                            0,
                            intent_hash,
                            now,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise EnvelopeStoreError(
                        EnvelopeReason.IDEMPOTENCY_CONFLICT,
                        "run_id or QMP endpoint is already bound",
                    ) from error
                self._journal(
                    transaction_id,
                    "INTENT_PERSISTED",
                    EnvelopeState.INTENT_PERSISTED,
                    0,
                    {
                        "leaseRevision": lease.revision,
                        "receiptChallengeHash": _digest(challenge),
                        "requestHash": intent_hash,
                    },
                )
                self._fault("INTENT_PERSISTED_BEFORE_COMMIT")
                return self._record(self._row(transaction_id))

    def mark_lease_prepared(
        self, transaction_id: str, expected_revision: int
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        hint = self.get(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision,
            expected_state=LeaseState.PREPARING,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                detail = {
                    "leaseRevision": lease.revision,
                    "leaseState": lease.state.value,
                }
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={EnvelopeState.INTENT_PERSISTED},
                    target=EnvelopeState.LEASE_PREPARED,
                    event="LEASE_PREPARED",
                    request_hash=self._operation_hash("LEASE_PREPARED", detail),
                    journal_detail=detail,
                )
                return record

    def mark_handles_open(
        self,
        transaction_id: str,
        expected_revision: int,
        *,
        fd_binding_hash: str,
        launch_plan_hash: str,
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        binding = self._hash("fd_binding_hash", fd_binding_hash)
        plan = self._hash("launch_plan_hash", launch_plan_hash)
        detail = {"fdBindingHash": binding, "launchPlanHash": plan}
        hint = self.get(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision,
            expected_state=LeaseState.PREPARING,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={EnvelopeState.LEASE_PREPARED},
                    target=EnvelopeState.HANDLES_OPEN,
                    event="HANDLES_OPEN",
                    request_hash=self._operation_hash("HANDLES_OPEN", detail),
                    updates={"fd_binding_hash": binding, "launch_plan_hash": plan},
                    journal_detail=detail,
                )
                return record

    def _verify_process_identity(self, pid: int, start_token: str) -> None:
        try:
            alive = self._process_identity_verifier(pid, start_token)
        except Exception as error:
            raise EnvelopeStoreError(
                EnvelopeReason.PROCESS_IDENTITY_STALE,
                f"process verifier raised {type(error).__name__}",
            ) from error
        if alive is not True:
            raise EnvelopeStoreError(
                EnvelopeReason.PROCESS_IDENTITY_STALE,
                "QEMU pid/start-token identity is not live",
            )

    def _verify_row_process(self, row: sqlite3.Row) -> None:
        if not isinstance(row["qemu_pid"], int) or not isinstance(
            row["qemu_start_token"], str
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.PROCESS_IDENTITY_STALE,
                "durable QEMU process identity is incomplete",
            )
        self._verify_process_identity(row["qemu_pid"], row["qemu_start_token"])

    def mark_qemu_running(
        self,
        transaction_id: str,
        expected_revision: int,
        *,
        qemu_pid: int,
        qemu_start_token: str,
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        pid = self._positive("qemu_pid", qemu_pid)
        token = self._identifier("qemu_start_token", qemu_start_token)
        detail = {"qemuPid": pid, "qemuStartToken": token}
        hint = self.get(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision,
            expected_state=LeaseState.PREPARING,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                self._verify_process_identity(pid, token)
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                if not isinstance(row["fd_binding_hash"], str) or not isinstance(
                    row["launch_plan_hash"], str
                ):
                    raise EnvelopeStoreError(
                        EnvelopeReason.INVALID_STATE_TRANSITION,
                        "fd and launch-plan bindings must be durable before QEMU",
                    )
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={EnvelopeState.HANDLES_OPEN},
                    target=EnvelopeState.QEMU_RUNNING,
                    event="QEMU_RUNNING",
                    request_hash=self._operation_hash("QEMU_RUNNING", detail),
                    updates={"qemu_pid": pid, "qemu_start_token": token},
                    journal_detail=detail,
                )
                return record

    def _normalize_receipt(self, receipt: SignedReceipt) -> SignedReceipt:
        if not isinstance(receipt, SignedReceipt):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, "receipt must be SignedReceipt"
            )
        if not isinstance(receipt.role, ReceiptRole) or not isinstance(
            receipt.outcome, ReceiptOutcome
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT,
                "receipt role and outcome must be typed",
            )
        try:
            signature = _value_text("signature", receipt.signature).lower()
            if not _HMAC_SHA256.fullmatch(signature):
                raise ValueError("signature must be canonical HMAC-SHA256")
            return SignedReceipt(
                role=receipt.role,
                observer_id=_value_identifier("observer_id", receipt.observer_id),
                envelope_store_id=_value_uuid(
                    "envelope_store_id", receipt.envelope_store_id
                ),
                lease_store_binding_hash=_value_hash(
                    "lease_store_binding_hash", receipt.lease_store_binding_hash
                ),
                receipt_challenge=_value_challenge(receipt.receipt_challenge),
                transaction_id=_value_identifier(
                    "transaction_id", receipt.transaction_id
                ),
                host_id=_value_host(receipt.host_id),
                authority_id=_value_identifier("authority_id", receipt.authority_id),
                lease_revision=_value_uint("lease_revision", receipt.lease_revision),
                vm_generation=_value_positive("vm_generation", receipt.vm_generation),
                decision_hash=_value_hash("decision_hash", receipt.decision_hash),
                policy_hash=_value_hash("policy_hash", receipt.policy_hash),
                launch_plan_hash=_value_hash(
                    "launch_plan_hash", receipt.launch_plan_hash
                ),
                fd_binding_hash=_value_hash("fd_binding_hash", receipt.fd_binding_hash),
                qemu_pid=_value_positive("qemu_pid", receipt.qemu_pid),
                qemu_start_token=_value_identifier(
                    "qemu_start_token", receipt.qemu_start_token
                ),
                outcome=receipt.outcome,
                nonce=_value_nonce(receipt.nonce),
                signature=signature,
            )
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    @staticmethod
    def _success_outcome(role: ReceiptRole) -> ReceiptOutcome:
        return (
            ReceiptOutcome.QMP_DEVICE_OBSERVED
            if role is ReceiptRole.QMP
            else ReceiptOutcome.DMA_ISOLATION_ESTABLISHED
        )

    def _verify_receipt_against_row(
        self, receipt: SignedReceipt, row: sqlite3.Row, expected_role: ReceiptRole
    ) -> None:
        if receipt.role is not expected_role:
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_ROLE_MISMATCH,
                f"expected {expected_role.value}, got {receipt.role.value}",
            )
        key = self._verifier_keys[expected_role].get(receipt.observer_id)
        if key is None:
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_OBSERVER_UNKNOWN, receipt.observer_id
            )
        expected_signature = (
            "hmac-sha256:"
            + hmac.new(
                key,
                _json(receipt.canonical_payload()).encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected_signature, receipt.signature):
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_SIGNATURE_INVALID, receipt.observer_id
            )
        if receipt.outcome is not self._success_outcome(expected_role):
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_OUTCOME_NOT_SUCCESS, receipt.outcome.value
            )
        expected_binding = {
            "authority_id": row["authority_id"],
            "decision_hash": row["decision_hash"],
            "envelope_store_id": self.envelope_store_id,
            "fd_binding_hash": row["fd_binding_hash"],
            "host_id": row["host_id"],
            "launch_plan_hash": row["launch_plan_hash"],
            "lease_revision": row["planned_preparing_revision"],
            "lease_store_binding_hash": self.lease_store_binding_hash,
            "policy_hash": row["policy_hash"],
            "qemu_pid": row["qemu_pid"],
            "qemu_start_token": row["qemu_start_token"],
            "receipt_challenge": row["receipt_challenge"],
            "transaction_id": row["transaction_id"],
            "vm_generation": row["vm_generation"],
        }
        actual_binding = {
            "authority_id": receipt.authority_id,
            "decision_hash": receipt.decision_hash,
            "envelope_store_id": receipt.envelope_store_id,
            "fd_binding_hash": receipt.fd_binding_hash,
            "host_id": receipt.host_id,
            "launch_plan_hash": receipt.launch_plan_hash,
            "lease_revision": receipt.lease_revision,
            "lease_store_binding_hash": receipt.lease_store_binding_hash,
            "policy_hash": receipt.policy_hash,
            "qemu_pid": receipt.qemu_pid,
            "qemu_start_token": receipt.qemu_start_token,
            "receipt_challenge": receipt.receipt_challenge,
            "transaction_id": receipt.transaction_id,
            "vm_generation": receipt.vm_generation,
        }
        if actual_binding != expected_binding:
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                "receipt does not bind this store/lease/plan/fd/process tuple",
            )

    def _mark_receipt(
        self,
        transaction_id: str,
        expected_revision: int,
        receipt: SignedReceipt,
        *,
        expected_role: ReceiptRole,
        allowed: EnvelopeState,
        target: EnvelopeState,
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        normalized = self._normalize_receipt(receipt)
        hint = self.get(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision,
            expected_state=LeaseState.PREPARING,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                self._verify_row_process(row)
                self._verify_receipt_against_row(normalized, row, expected_role)
                payload = normalized.canonical_payload()
                payload_hash = _digest(payload)
                request_hash = self._operation_hash(
                    f"{expected_role.value}_RECEIPT_VERIFIED",
                    {"payloadHash": payload_hash, "signature": normalized.signature},
                )
                state = EnvelopeState(row["state"])
                if state is target and row["revision"] == expected + 1:
                    if row["last_request_hash"] != request_hash:
                        raise EnvelopeStoreError(
                            EnvelopeReason.IDEMPOTENCY_CONFLICT,
                            f"{expected_role.value} receipt replay differs",
                        )
                    return self._record(row)
                if row["revision"] != expected:
                    raise EnvelopeStoreError(
                        EnvelopeReason.REVISION_MISMATCH,
                        f"expected {expected}, current {row['revision']}",
                    )
                if state is not allowed:
                    raise EnvelopeStoreError(
                        EnvelopeReason.INVALID_STATE_TRANSITION,
                        f"{state.value}->{target.value}",
                    )
                nonce_owner = self._connection.execute(
                    "SELECT transaction_id,role FROM receipts WHERE observer_id=? AND nonce=?",
                    (normalized.observer_id, normalized.nonce),
                ).fetchone()
                if nonce_owner is not None:
                    raise EnvelopeStoreError(
                        EnvelopeReason.RECEIPT_REPLAY,
                        f"nonce used by {nonce_owner['transaction_id']}/{nonce_owner['role']}",
                    )
                self._connection.execute(
                    """INSERT INTO receipts(transaction_id,role,observer_id,nonce,outcome,
                           payload_json,payload_hash,signature,verified_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        transaction,
                        expected_role.value,
                        normalized.observer_id,
                        normalized.nonce,
                        normalized.outcome.value,
                        _json(payload),
                        payload_hash,
                        normalized.signature,
                        self._now(),
                    ),
                )
                observer_column = (
                    "qmp_observer_id"
                    if expected_role is ReceiptRole.QMP
                    else "dma_observer_id"
                )
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={allowed},
                    target=target,
                    event=f"{expected_role.value}_RECEIPT_VERIFIED",
                    request_hash=request_hash,
                    updates={observer_column: normalized.observer_id},
                    journal_detail={
                        "observerId": normalized.observer_id,
                        "payloadHash": payload_hash,
                    },
                )
                return record

    def mark_qmp_receipt_verified(
        self,
        transaction_id: str,
        expected_revision: int,
        receipt: SignedReceipt,
    ) -> EnvelopeRecord:
        return self._mark_receipt(
            transaction_id,
            expected_revision,
            receipt,
            expected_role=ReceiptRole.QMP,
            allowed=EnvelopeState.QEMU_RUNNING,
            target=EnvelopeState.QMP_RECEIPT_VERIFIED,
        )

    def mark_dma_receipt_verified(
        self,
        transaction_id: str,
        expected_revision: int,
        receipt: SignedReceipt,
    ) -> EnvelopeRecord:
        return self._mark_receipt(
            transaction_id,
            expected_revision,
            receipt,
            expected_role=ReceiptRole.DMA,
            allowed=EnvelopeState.QMP_RECEIPT_VERIFIED,
            target=EnvelopeState.DMA_RECEIPT_VERIFIED,
        )

    def _receipt_from_row(self, row: sqlite3.Row) -> SignedReceipt:
        try:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("receipt payload is not an object")
            if (
                payload.get("protocol") != SignedReceipt.PROTOCOL
                or payload.get("domain") != SignedReceipt.DOMAIN
            ):
                raise ValueError("receipt protocol/domain mismatch")
            receipt = SignedReceipt(
                role=ReceiptRole(payload["role"]),
                observer_id=payload["observerId"],
                envelope_store_id=payload["envelopeStoreId"],
                lease_store_binding_hash=payload["leaseStoreBindingHash"],
                receipt_challenge=payload["receiptChallenge"],
                transaction_id=payload["transactionId"],
                host_id=payload["hostId"],
                authority_id=payload["authorityId"],
                lease_revision=payload["leaseRevision"],
                vm_generation=payload["vmGeneration"],
                decision_hash=payload["decisionHash"],
                policy_hash=payload["policyHash"],
                launch_plan_hash=payload["launchPlanHash"],
                fd_binding_hash=payload["fdBindingHash"],
                qemu_pid=payload["qemuPid"],
                qemu_start_token=payload["qemuStartToken"],
                outcome=ReceiptOutcome(payload["outcome"]),
                nonce=payload["nonce"],
                signature=row["signature"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                "persisted receipt is malformed",
            ) from error
        normalized = self._normalize_receipt(receipt)
        if (
            row["observer_id"] != normalized.observer_id
            or row["role"] != normalized.role.value
            or row["nonce"] != normalized.nonce
            or row["outcome"] != normalized.outcome.value
            or row["payload_hash"] != _digest(normalized.canonical_payload())
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                "persisted receipt columns disagree with signed payload",
            )
        return normalized

    def mark_commit_intent(
        self, transaction_id: str, expected_revision: int
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        request_hash = self._operation_hash("COMMIT_INTENT_DURABLE", {})
        hint = self.get(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision,
            expected_state=LeaseState.PREPARING,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                self._verify_row_process(row)
                state = EnvelopeState(row["state"])
                if (
                    state is EnvelopeState.COMMIT_INTENT_DURABLE
                    and row["revision"] == expected + 1
                ):
                    if row["last_request_hash"] != request_hash:
                        raise EnvelopeStoreError(
                            EnvelopeReason.IDEMPOTENCY_CONFLICT,
                            "commit intent replay differs",
                        )
                    return self._record(row)
                if row["revision"] != expected:
                    raise EnvelopeStoreError(
                        EnvelopeReason.REVISION_MISMATCH,
                        f"expected {expected}, current {row['revision']}",
                    )
                if state is not EnvelopeState.DMA_RECEIPT_VERIFIED:
                    raise EnvelopeStoreError(
                        EnvelopeReason.INVALID_STATE_TRANSITION,
                        f"{state.value}->{EnvelopeState.COMMIT_INTENT_DURABLE.value}",
                    )
                rows = self._connection.execute(
                    "SELECT * FROM receipts WHERE transaction_id=? ORDER BY role",
                    (transaction,),
                ).fetchall()
                by_role = {receipt_row["role"]: receipt_row for receipt_row in rows}
                if set(by_role) != {ReceiptRole.QMP.value, ReceiptRole.DMA.value}:
                    raise EnvelopeStoreError(
                        EnvelopeReason.RECEIPTS_REQUIRED,
                        "both QMP and DMA receipts are required",
                    )
                verified: dict[ReceiptRole, SignedReceipt] = {}
                for role in ReceiptRole:
                    receipt = self._receipt_from_row(by_role[role.value])
                    self._verify_receipt_against_row(receipt, row, role)
                    verified[role] = receipt
                if (
                    verified[ReceiptRole.QMP].observer_id
                    == verified[ReceiptRole.DMA].observer_id
                ):
                    raise EnvelopeStoreError(
                        EnvelopeReason.RECEIPTS_REQUIRED,
                        "QMP and DMA receipts must come from different observers",
                    )
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={EnvelopeState.DMA_RECEIPT_VERIFIED},
                    target=EnvelopeState.COMMIT_INTENT_DURABLE,
                    event="COMMIT_INTENT_DURABLE",
                    request_hash=request_hash,
                    journal_detail={
                        "dmaObserverId": verified[ReceiptRole.DMA].observer_id,
                        "qmpObserverId": verified[ReceiptRole.QMP].observer_id,
                    },
                )
                return record

    def confirm_attached(
        self, transaction_id: str, expected_revision: int
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        hint = self.get(transaction)
        if (
            hint.state is EnvelopeState.RECOVERY_REQUIRED
            and hint.recovery_origin_state is not EnvelopeState.COMMIT_INTENT_DURABLE
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_STATE_TRANSITION,
                "only COMMIT_INTENT recovery can confirm ATTACHED",
            )
        if hint.state not in {
            EnvelopeState.COMMIT_INTENT_DURABLE,
            EnvelopeState.RECOVERY_REQUIRED,
            EnvelopeState.ATTACHED_CONFIRMED,
        }:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_STATE_TRANSITION,
                f"{hint.state.value}->{EnvelopeState.ATTACHED_CONFIRMED.value}",
            )
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            hint.planned_preparing_revision + 1,
            expected_state=LeaseState.ATTACHED,
            require_current_facts=True,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                state = EnvelopeState(row["state"])
                if (
                    state is EnvelopeState.RECOVERY_REQUIRED
                    and row["recovery_origin_state"]
                    != EnvelopeState.COMMIT_INTENT_DURABLE.value
                ):
                    raise EnvelopeStoreError(
                        EnvelopeReason.INVALID_STATE_TRANSITION,
                        "only COMMIT_INTENT recovery can confirm ATTACHED",
                    )
                if state not in {
                    EnvelopeState.COMMIT_INTENT_DURABLE,
                    EnvelopeState.RECOVERY_REQUIRED,
                    EnvelopeState.ATTACHED_CONFIRMED,
                }:
                    raise EnvelopeStoreError(
                        EnvelopeReason.INVALID_STATE_TRANSITION,
                        f"{state.value}->{EnvelopeState.ATTACHED_CONFIRMED.value}",
                    )
                self._verify_row_process(row)
                detail = {
                    "leaseRevision": lease.revision,
                    "leaseState": lease.state.value,
                }
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={
                        EnvelopeState.COMMIT_INTENT_DURABLE,
                        EnvelopeState.RECOVERY_REQUIRED,
                    },
                    target=EnvelopeState.ATTACHED_CONFIRMED,
                    event="ATTACHED_CONFIRMED",
                    request_hash=self._operation_hash("ATTACHED_CONFIRMED", detail),
                    updates={"attached_lease_revision": lease.revision},
                    journal_detail=detail,
                )
                return record

    _PRECOMMIT_FAILURE_STATES = frozenset(
        {
            EnvelopeState.INTENT_PERSISTED,
            EnvelopeState.LEASE_PREPARED,
            EnvelopeState.HANDLES_OPEN,
            EnvelopeState.QEMU_RUNNING,
            EnvelopeState.QMP_RECEIPT_VERIFIED,
            EnvelopeState.DMA_RECEIPT_VERIFIED,
        }
    )

    def start_cleaning(
        self,
        transaction_id: str,
        expected_revision: int,
        *,
        reason_code: str,
        reason_detail: str = "",
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        code = self._identifier("reason_code", reason_code)
        detail_text = self._text("reason_detail", reason_detail, allow_empty=True)
        detail = {"reasonCode": code, "reasonDetail": detail_text}
        hint = self.get(transaction)
        if hint.state not in self._PRECOMMIT_FAILURE_STATES and (
            hint.state is not EnvelopeState.CLEANING
        ):
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_STATE_TRANSITION,
                f"{hint.state.value}->{EnvelopeState.CLEANING.value}",
            )
        lease_hint = self._peek_authoritative_lease(transaction)
        allowed_lease_states = (
            {LeaseState.RESERVED, LeaseState.PREPARING}
            if hint.state is EnvelopeState.INTENT_PERSISTED
            else {LeaseState.PREPARING}
        )
        if hint.state is EnvelopeState.CLEANING:
            allowed_lease_states.add(LeaseState.QUARANTINED)
        if lease_hint.state not in allowed_lease_states:
            raise EnvelopeStoreError(
                EnvelopeReason.LEASE_FACT_MISMATCH,
                "cleanup requires the matching RESERVED/PREPARING lease, or an "
                "already-QUARANTINED lease on replay",
            )
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            lease_hint.revision,
            expected_state=lease_hint.state,
            require_current_facts=lease_hint.state is not LeaseState.QUARANTINED,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed=set(self._PRECOMMIT_FAILURE_STATES),
                    target=EnvelopeState.CLEANING,
                    event="CLEANING",
                    request_hash=self._operation_hash("CLEANING", detail),
                    updates={"reason_code": code, "reason_detail": detail_text},
                    journal_detail=detail,
                )
                return record

    def confirm_quarantined(
        self, transaction_id: str, expected_revision: int
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        hint = self.get(transaction)
        lease_hint = self._peek_authoritative_lease(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            lease_hint.revision,
            expected_state=LeaseState.QUARANTINED,
            require_current_facts=False,
            require_claims=True,
        ) as lease:
            with self._write():
                row = self._row(transaction)
                self._validate_authoritative_lease(lease, row)
                if lease.revision < row["planned_preparing_revision"]:
                    raise EnvelopeStoreError(
                        EnvelopeReason.LEASE_FACT_MISMATCH,
                        "QUARANTINED lease revision predates planned PREPARING revision",
                    )
                detail = {
                    "leaseRevision": lease.revision,
                    "leaseState": lease.state.value,
                }
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed={EnvelopeState.CLEANING, EnvelopeState.RECOVERY_REQUIRED},
                    target=EnvelopeState.QUARANTINED,
                    event="QUARANTINED_CONFIRMED",
                    request_hash=self._operation_hash("QUARANTINED_CONFIRMED", detail),
                    journal_detail=detail,
                )
                return record

    def mark_recovery_required(
        self,
        transaction_id: str,
        expected_revision: int,
        *,
        reason_code: str,
        reason_detail: str = "",
    ) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        expected = self._expected_revision(expected_revision)
        code = self._identifier("reason_code", reason_code)
        detail_text = self._text("reason_detail", reason_detail, allow_empty=True)
        hint = self.get(transaction)
        lease_hint = self._peek_authoritative_lease(transaction)
        with self._authoritative_lease_guard(
            transaction,
            hint.vm_generation,
            lease_hint.revision,
            expected_state=lease_hint.state,
            require_current_facts=False,
            require_claims=False,
        ):
            with self._write():
                row = self._row(transaction)
                state = EnvelopeState(row["state"])
                origin = (
                    row["recovery_origin_state"]
                    if state is EnvelopeState.RECOVERY_REQUIRED
                    else state.value
                )
                detail = {
                    "originState": origin,
                    "reasonCode": code,
                    "reasonDetail": detail_text,
                }
                allowed = set(EnvelopeState) - {
                    EnvelopeState.QUARANTINED,
                    EnvelopeState.RECOVERY_REQUIRED,
                }
                record, _ = self._transition_locked(
                    row,
                    expected_revision=expected,
                    allowed=allowed,
                    target=EnvelopeState.RECOVERY_REQUIRED,
                    event="RECOVERY_REQUIRED",
                    request_hash=self._operation_hash("RECOVERY_REQUIRED", detail),
                    updates={
                        "reason_code": code,
                        "reason_detail": detail_text,
                        "recovery_origin_state": origin,
                    },
                    journal_detail=detail,
                )
                return record

    @staticmethod
    def _text(name: str, value: object, *, allow_empty: bool = False) -> str:
        if allow_empty and isinstance(value, str) and not value:
            return ""
        try:
            return _value_text(name, value)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    @staticmethod
    def _identifier(name: str, value: object) -> str:
        try:
            return _value_identifier(name, value)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    @staticmethod
    def _hash(name: str, value: object) -> str:
        try:
            return _value_hash(name, value)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    @staticmethod
    def _positive(name: str, value: object) -> int:
        try:
            return _value_positive(name, value)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    @staticmethod
    def _expected_revision(value: object) -> int:
        try:
            return _value_uint("expected_revision", value)
        except ValueError as error:
            raise EnvelopeStoreError(
                EnvelopeReason.INVALID_ARGUMENT, str(error)
            ) from error

    def get(self, transaction_id: str) -> EnvelopeRecord:
        transaction = self._identifier("transaction_id", transaction_id)
        try:
            with self._lease_store._lock:
                self._assert_live_lease_store_binding()
                with self._lock:
                    self._require_exact_schema()
                    self._require_pinned_envelope_metadata()
                    return self._record(self._row(transaction))
        except sqlite3.Error as error:
            raise EnvelopeStoreError(
                EnvelopeReason.STORE_UNAVAILABLE, str(error)
            ) from error

    def journal(self, transaction_id: str) -> tuple[EnvelopeJournalEntry, ...]:
        transaction = self._identifier("transaction_id", transaction_id)
        self.get(transaction)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM journal WHERE transaction_id=? ORDER BY sequence",
                (transaction,),
            ).fetchall()
            return tuple(
                EnvelopeJournalEntry(
                    sequence=row["sequence"],
                    transaction_id=row["transaction_id"],
                    event=row["event"],
                    state=EnvelopeState(row["state"]),
                    revision=row["revision"],
                    detail=json.loads(row["detail_json"]),
                    created_at=row["created_at"],
                )
                for row in rows
            )

    def recovery_disposition(self, transaction_id: str) -> RecoveryDisposition:
        state = self.get(transaction_id).state
        if state in self._PRECOMMIT_FAILURE_STATES or state is EnvelopeState.CLEANING:
            return RecoveryDisposition.CLEANUP_REQUIRED
        if state in {
            EnvelopeState.COMMIT_INTENT_DURABLE,
            EnvelopeState.RECOVERY_REQUIRED,
        }:
            return RecoveryDisposition.REQUIRE_AUTHORITATIVE_LEASE_RECONCILIATION
        if state is EnvelopeState.ATTACHED_CONFIRMED:
            return RecoveryDisposition.OWNER_REVALIDATION_REQUIRED
        if state is EnvelopeState.QUARANTINED:
            return RecoveryDisposition.MAINTAIN_QUARANTINE
        raise AssertionError(f"unhandled state {state.value}")

    def recovery_required(self) -> tuple[EnvelopeRecord, ...]:
        with self._lease_store._lock:
            self._assert_live_lease_store_binding()
            with self._lock:
                self._require_exact_schema()
                self._require_pinned_envelope_metadata()
                rows = self._connection.execute(
                    "SELECT * FROM envelopes ORDER BY created_at,transaction_id"
                ).fetchall()
                return tuple(self._record(row) for row in rows)

    def durability_profile(self) -> DurabilityProfile:
        with self._lock:
            mode = str(
                self._connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            synchronous = int(
                self._connection.execute("PRAGMA synchronous").fetchone()[0]
            )
        return DurabilityProfile(mode, synchronous, self.persistence_boundary)
