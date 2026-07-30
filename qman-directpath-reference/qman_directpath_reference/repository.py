"""Executable SQLite reference transaction for one Static admission.

This module is intentionally a narrow, auditable reference component.  It
does not implement a Qman product repository, a distributed lock service, or
power-loss certification.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hmac
from pathlib import Path
import re
import sqlite3
import threading
from types import MappingProxyType
from typing import Protocol
import uuid

from .sqlite_schema import DDL_STATEMENTS, EXPECTED_METADATA_KEYS, SCHEMA_VERSION
from .static_admission_contracts import (
    EVIDENCE_BOUNDARY,
    CommittedIdempotency,
    CommittedOperationLeaseCapability,
    CommittedResourceVersions,
    CommittedStaticAdmission,
    IdempotencyNaturalKey,
    OperationLeaseMemberGeneration,
    StaticAdmissionCommand,
    canonical_json_bytes,
    derive_idempotency_scope_hash,
    load_canonical_json,
    parse_committed_static_admission,
    parse_static_admission_command,
    sha256_digest,
)


REFERENCE_EVALUATOR_PREMISE = "REFERENCE_EVALUATOR_PREMISE"
REFERENCE_ONLY_BOOTSTRAP = "REFERENCE_ONLY_BOOTSTRAP"

AFTER_AVAILABILITY_ABSENCE_READ = "AFTER_AVAILABILITY_ABSENCE_READ"
AFTER_COMMIT_BEFORE_RETURN = "AFTER_COMMIT_BEFORE_RETURN"
WRITE_FAULT_STAGES = (
    "IDEMPOTENCY_WRITTEN",
    "LEASE_WRITTEN",
    "BINDING_WRITTEN",
    "CLAIMS_WRITTEN",
    "RUN_WRITTEN",
    "AUDIT_WRITTEN",
    "OUTBOX_WRITTEN",
    "AVAILABILITY_ADVANCED",
    "COMMIT_SEQUENCE_ALLOCATED",
    "IDEMPOTENCY_COMPLETED",
    "COMMIT_RECORD_WRITTEN",
    "BEFORE_COMMIT",
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_ARTIFACT_KINDS = ("CATALOG", "INVENTORY", "POLICY", "TRUST")


class ReferenceRepositoryReason(str, Enum):
    """Stable fail-closed reasons exposed by the reference component."""

    INVALID_COMMAND = "INVALID_COMMAND"
    STORE_NOT_DURABLE = "STORE_NOT_DURABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    REFERENCE_PREMISE_MISMATCH = "REFERENCE_PREMISE_MISMATCH"
    BOOTSTRAP_INCOMPLETE = "BOOTSTRAP_INCOMPLETE"
    DEADLINE_EXPIRED = "DEADLINE_EXPIRED"
    IDEMPOTENCY_KEY_REUSED = "IDEMPOTENCY_KEY_REUSED"
    DEPENDENCY_BUSY = "DEPENDENCY_BUSY"
    CURRENT_CHANGED = "CURRENT_CHANGED"
    EVALUATOR_INVALID = "EVALUATOR_INVALID"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"


class ReferenceRepositoryError(RuntimeError):
    """A stable reference-repository rejection."""

    def __init__(
        self,
        reason: ReferenceRepositoryReason,
        detail: str,
    ) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


def _fail(
    reason: ReferenceRepositoryReason,
    detail: str,
) -> ReferenceRepositoryError:
    return ReferenceRepositoryError(reason, detail)


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ValueError(f"{field}: expected a closed identifier")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{field}: expected sha256:<64 lowercase hex>")
    return value


def _require_positive(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 9_007_199_254_740_991
    ):
        raise ValueError(f"{field}: expected a safe positive integer")
    return value


def _timestamp_datetime(value: str, field: str) -> datetime:
    if _TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError(f"{field}: expected exact six-digit UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError(f"{field}: invalid UTC timestamp") from error


def _require_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected timestamp string")
    _timestamp_datetime(value, field)
    return value


def _clock_timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        return _require_timestamp(value, "clock")
    if not isinstance(value, datetime):
        raise TypeError("clock must return datetime or exact UTC timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock datetime must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_unique_ids(values: Sequence[str], field: str) -> tuple[str, ...]:
    normalized = tuple(_require_id(value, field) for value in values)
    ordered = tuple(sorted(normalized, key=canonical_json_bytes))
    if not ordered or ordered != normalized or len(set(ordered)) != len(ordered):
        raise ValueError(f"{field}: expected non-empty unique canonical order")
    return ordered


def _canonical_unique_digests(
    values: Sequence[str],
    field: str,
) -> tuple[str, ...]:
    normalized = tuple(_require_digest(value, field) for value in values)
    ordered = tuple(sorted(normalized, key=canonical_json_bytes))
    if not ordered or ordered != normalized or len(set(ordered)) != len(ordered):
        raise ValueError(f"{field}: expected non-empty unique canonical order")
    return ordered


@dataclass(frozen=True, slots=True)
class ReferenceSelectionPremise:
    """Pinned evaluator input for one VM in the deterministic reference."""

    bundle_id: str
    scope_hash: str
    member_ids: tuple[str, ...]
    evidence_blob_hashes: tuple[str, ...]
    valid_until: str

    def __post_init__(self) -> None:
        _require_digest(self.bundle_id, "bundle_id")
        _require_digest(self.scope_hash, "scope_hash")
        object.__setattr__(
            self,
            "member_ids",
            _canonical_unique_ids(self.member_ids, "member_ids"),
        )
        object.__setattr__(
            self,
            "evidence_blob_hashes",
            _canonical_unique_digests(
                self.evidence_blob_hashes,
                "evidence_blob_hashes",
            ),
        )
        _require_timestamp(self.valid_until, "valid_until")

    def to_wire(self) -> dict[str, object]:
        return {
            "bundleId": self.bundle_id,
            "scopeHash": self.scope_hash,
            "memberIds": list(self.member_ids),
            "evidenceBlobHashes": list(self.evidence_blob_hashes),
            "validUntil": self.valid_until,
        }


@dataclass(frozen=True, slots=True)
class ReferenceEvaluation:
    """Pure evaluator output subsequently verified against current rows."""

    bundle_id: str
    scope_hash: str
    member_generations: tuple[OperationLeaseMemberGeneration, ...]
    evidence_blob_hashes: tuple[str, ...]
    valid_until: str

    def __post_init__(self) -> None:
        _require_digest(self.bundle_id, "evaluation.bundle_id")
        _require_digest(self.scope_hash, "evaluation.scope_hash")
        members = tuple(self.member_generations)
        if not members or any(
            not isinstance(item, OperationLeaseMemberGeneration) for item in members
        ):
            raise ValueError("evaluation.member_generations: invalid members")
        ordered = tuple(
            sorted(
                members,
                key=lambda item: canonical_json_bytes([item.id, item.generation]),
            )
        )
        if members != ordered or len({item.id for item in members}) != len(members):
            raise ValueError(
                "evaluation.member_generations: expected unique canonical order"
            )
        object.__setattr__(self, "member_generations", members)
        object.__setattr__(
            self,
            "evidence_blob_hashes",
            _canonical_unique_digests(
                self.evidence_blob_hashes,
                "evaluation.evidence_blob_hashes",
            ),
        )
        _require_timestamp(self.valid_until, "evaluation.valid_until")


@dataclass(frozen=True, slots=True)
class ReferenceCurrentArtifact:
    kind: str
    authority_id: str
    sequence: int
    artifact_digest: str
    resource_version: int
    valid_until: str
    blob_sha256: str

    def to_wire(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "authorityId": self.authority_id,
            "sequence": self.sequence,
            "artifactDigest": self.artifact_digest,
            "resourceVersion": self.resource_version,
            "validUntil": self.valid_until,
            "blobSha256": self.blob_sha256,
        }


@dataclass(frozen=True, slots=True)
class ReferenceAvailabilityMember:
    device_id: str
    generation: int
    resource_version: int
    evidence_blob_hash: str

    def to_wire(self) -> dict[str, object]:
        return {
            "deviceId": self.device_id,
            "generation": self.generation,
            "resourceVersion": self.resource_version,
            "evidenceBlobHash": self.evidence_blob_hash,
        }


@dataclass(frozen=True, slots=True)
class ReferenceBundle:
    bundle_id: str
    member_ids: tuple[str, ...]

    def to_wire(self) -> dict[str, object]:
        return {
            "bundleId": self.bundle_id,
            "memberIds": list(self.member_ids),
        }


@dataclass(frozen=True, slots=True)
class ReferenceCurrentState:
    """Exact current rows visible to the pure evaluator."""

    controller_generation: int
    controller_authority_lease_id: str
    controller_resource_version: int
    controller_expires_at: str
    controller_blob_sha256: str
    vm_id: str
    request_version: int
    request_hash: str
    request_resource_version: int
    request_blob_sha256: str
    artifacts: tuple[ReferenceCurrentArtifact, ...]
    availability_authority_id: str
    availability_resource_version: int
    members: tuple[ReferenceAvailabilityMember, ...]
    bundles: tuple[ReferenceBundle, ...]
    quarantine_keys: tuple[str, ...]
    claimed_bundle_ids: tuple[str, ...]
    claimed_member_ids: tuple[str, ...]
    active_scope_hashes: tuple[str, ...]
    active_run_ids: tuple[str, ...]
    active_vm_ids: tuple[str, ...]

    def artifact(self, kind: str) -> ReferenceCurrentArtifact:
        for artifact in self.artifacts:
            if artifact.kind == kind:
                return artifact
        raise KeyError(kind)

    def member(self, member_id: str) -> ReferenceAvailabilityMember:
        for member in self.members:
            if member.device_id == member_id:
                return member
        raise KeyError(member_id)

    def bundle_member_ids(self, bundle_id: str) -> tuple[str, ...]:
        for bundle in self.bundles:
            if bundle.bundle_id == bundle_id:
                return bundle.member_ids
        raise KeyError(bundle_id)

    def to_wire(self) -> dict[str, object]:
        return {
            "subjectType": "REFERENCE_CURRENT_STATIC_ADMISSION_STATE",
            "schemaVersion": 1,
            "controller": {
                "controllerGeneration": self.controller_generation,
                "authorityLeaseId": self.controller_authority_lease_id,
                "resourceVersion": self.controller_resource_version,
                "expiresAt": self.controller_expires_at,
                "blobSha256": self.controller_blob_sha256,
            },
            "request": {
                "vmId": self.vm_id,
                "requestVersion": self.request_version,
                "requestHash": self.request_hash,
                "resourceVersion": self.request_resource_version,
                "blobSha256": self.request_blob_sha256,
            },
            "artifacts": [item.to_wire() for item in self.artifacts],
            "availability": {
                "authorityId": self.availability_authority_id,
                "resourceVersion": self.availability_resource_version,
                "members": [item.to_wire() for item in self.members],
                "bundles": [item.to_wire() for item in self.bundles],
                "quarantineKeys": list(self.quarantine_keys),
                "claimedBundleIds": list(self.claimed_bundle_ids),
                "claimedMemberIds": list(self.claimed_member_ids),
                "activeScopeHashes": list(self.active_scope_hashes),
                "activeRunIds": list(self.active_run_ids),
                "activeVmIds": list(self.active_vm_ids),
            },
        }


class ReferenceEvaluatorPremise(Protocol):
    """Constructor-injected pure evaluator boundary."""

    premise_identity: str
    premise_digest: str

    def evaluate(
        self,
        command: StaticAdmissionCommand,
        current: ReferenceCurrentState,
    ) -> ReferenceEvaluation:
        """Select exactly one current bundle and its evidence."""


class DeterministicReferenceEvaluator:
    """Small pinned evaluator suitable for executable reference scenarios."""

    premise_identity = REFERENCE_EVALUATOR_PREMISE

    def __init__(
        self,
        selections_by_vm_id: Mapping[str, ReferenceSelectionPremise],
    ) -> None:
        normalized: dict[str, ReferenceSelectionPremise] = {}
        for vm_id, selection in selections_by_vm_id.items():
            vm_id = _require_id(vm_id, "selections_by_vm_id key")
            if not isinstance(selection, ReferenceSelectionPremise):
                raise TypeError("selection must be ReferenceSelectionPremise")
            normalized[vm_id] = selection
        if not normalized:
            raise ValueError("at least one evaluator selection is required")
        self._selections = MappingProxyType(normalized)
        premise_subject = {
            "subjectType": REFERENCE_EVALUATOR_PREMISE,
            "schemaVersion": 1,
            "selections": [
                {"vmId": vm_id, **normalized[vm_id].to_wire()}
                for vm_id in sorted(normalized, key=canonical_json_bytes)
            ],
        }
        self.premise_digest = sha256_digest(canonical_json_bytes(premise_subject))

    def evaluate(
        self,
        command: StaticAdmissionCommand,
        current: ReferenceCurrentState,
    ) -> ReferenceEvaluation:
        try:
            selection = self._selections[command.vm_id]
            bundle_member_ids = current.bundle_member_ids(selection.bundle_id)
        except KeyError as error:
            raise ValueError("no pinned current bundle for VM") from error
        if bundle_member_ids != selection.member_ids:
            raise ValueError("pinned bundle members do not match current membership")
        members = tuple(
            sorted(
                (
                    OperationLeaseMemberGeneration(
                        id=member_id,
                        generation=current.member(member_id).generation,
                    )
                    for member_id in selection.member_ids
                ),
                key=lambda item: canonical_json_bytes([item.id, item.generation]),
            )
        )
        member_evidence = {
            current.member(member_id).evidence_blob_hash
            for member_id in selection.member_ids
        }
        evidence = tuple(
            sorted(
                set(selection.evidence_blob_hashes) | member_evidence,
                key=canonical_json_bytes,
            )
        )
        return ReferenceEvaluation(
            bundle_id=selection.bundle_id,
            scope_hash=selection.scope_hash,
            member_generations=members,
            evidence_blob_hashes=evidence,
            valid_until=selection.valid_until,
        )


class SqliteReferenceStaticAdmissionRepository:
    """One-file SQLite implementation of the frozen reference transaction."""

    def __init__(
        self,
        database_path: str | Path,
        evaluator: ReferenceEvaluatorPremise,
        *,
        clock: Callable[[], datetime | str] | None = None,
        busy_timeout_ms: int = 5_000,
        fault_hook: Callable[[str], None] | None = None,
        statement_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._database_path = self._validate_database_path(database_path)
        self._evaluator = self._validate_evaluator(evaluator)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._closed = False
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 1
        ):
            raise ValueError("busy_timeout_ms must be a positive integer")
        try:
            self._connection = sqlite3.connect(
                str(self._database_path),
                timeout=busy_timeout_ms / 1_000,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._configure_connection(busy_timeout_ms)
            self._initialize_store()
            if statement_hook is not None:
                self._connection.set_trace_callback(statement_hook)
        except ReferenceRepositoryError:
            self._close_after_failed_init()
            raise
        except sqlite3.Error as error:
            self._close_after_failed_init()
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                f"cannot open configured SQLite store: {error}",
            ) from error

    @staticmethod
    def _validate_database_path(database_path: str | Path) -> Path:
        raw = str(database_path)
        if raw == ":memory:" or raw.lower().startswith("file:"):
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "memory and URI SQLite databases are forbidden",
            )
        path = Path(database_path)
        if not path.is_absolute():
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "database path must be absolute",
            )
        if not path.parent.exists() or not path.parent.is_dir():
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "database parent directory must already exist",
            )
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "database path must name a non-symlink regular file",
            )
        return path

    @staticmethod
    def _validate_evaluator(
        evaluator: ReferenceEvaluatorPremise,
    ) -> ReferenceEvaluatorPremise:
        if getattr(evaluator, "premise_identity", None) != REFERENCE_EVALUATOR_PREMISE:
            raise _fail(
                ReferenceRepositoryReason.REFERENCE_PREMISE_MISMATCH,
                "evaluator premise identity is not REFERENCE_EVALUATOR_PREMISE",
            )
        try:
            _require_digest(
                getattr(evaluator, "premise_digest", None),
                "evaluator.premise_digest",
            )
        except ValueError as error:
            raise _fail(
                ReferenceRepositoryReason.REFERENCE_PREMISE_MISMATCH,
                str(error),
            ) from error
        if not callable(getattr(evaluator, "evaluate", None)):
            raise _fail(
                ReferenceRepositoryReason.REFERENCE_PREMISE_MISMATCH,
                "evaluator does not expose evaluate(command, current)",
            )
        return evaluator

    def _close_after_failed_init(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        connection = self._connection
        connection.execute("PRAGMA foreign_keys = ON")
        journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if str(journal_mode).lower() != "wal":
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "SQLite journal_mode is not WAL",
            )
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "SQLite foreign_keys is not ON",
            )
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise _fail(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                "SQLite synchronous is not FULL",
            )

    def _initialize_store(self) -> None:
        connection = self._connection
        in_transaction = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            in_transaction = True
            metadata_exists = (
                connection.execute(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'table' AND name = 'metadata'
                    """
                ).fetchone()
                is not None
            )
            if not metadata_exists:
                for statement in DDL_STATEMENTS:
                    connection.execute(statement)
                metadata = {
                    "schema_version": str(SCHEMA_VERSION),
                    "evidence_boundary": EVIDENCE_BOUNDARY,
                    "evaluator_premise_identity": REFERENCE_EVALUATOR_PREMISE,
                    "evaluator_premise_digest": self._evaluator.premise_digest,
                    "store_instance_id": f"reference-store-{uuid.uuid4().hex}",
                }
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    sorted(metadata.items()),
                )
                connection.execute(
                    "INSERT INTO commit_clock(singleton, last_sequence) VALUES (1, 0)"
                )
            self._verify_metadata()
            missing = self._missing_tables()
            if missing:
                raise _fail(
                    ReferenceRepositoryReason.STORE_UNAVAILABLE,
                    f"reference schema is incomplete: {missing}",
                )
            connection.execute("COMMIT")
            in_transaction = False
        except Exception:
            if in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _missing_tables(self) -> list[str]:
        expected = {
            "admission_bindings",
            "assignment_runs",
            "audit_events",
            "availability_members",
            "bundle_claims",
            "bundle_members",
            "commit_clock",
            "controller_current",
            "current_artifacts",
            "current_requests",
            "global_availability",
            "idempotency_records",
            "immutable_blobs",
            "member_claims",
            "metadata",
            "operation_lease_bundles",
            "operation_lease_members",
            "operation_leases",
            "outbox_events",
            "quarantines",
            "reference_query_observer",
            "repository_commits",
        }
        actual = {
            row[0]
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        return sorted(expected - actual)

    def _verify_metadata(self) -> None:
        rows = self._connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ).fetchall()
        metadata = {row["key"]: row["value"] for row in rows}
        if set(metadata) != EXPECTED_METADATA_KEYS:
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "reference metadata keys do not match the frozen set",
            )
        if metadata["schema_version"] != str(SCHEMA_VERSION):
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "reference schema version mismatch",
            )
        if metadata["evidence_boundary"] != EVIDENCE_BOUNDARY:
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "reference evidence boundary mismatch",
            )
        if (
            metadata["evaluator_premise_identity"] != REFERENCE_EVALUATOR_PREMISE
            or metadata["evaluator_premise_digest"] != self._evaluator.premise_digest
        ):
            raise _fail(
                ReferenceRepositoryReason.REFERENCE_PREMISE_MISMATCH,
                "store is pinned to a different evaluator premise",
            )
        _require_id(metadata["store_instance_id"], "store_instance_id")

    @property
    def database_path(self) -> Path:
        return self._database_path

    def reference_only_bootstrap_admin(self) -> "ReferenceOnlyBootstrapAdmin":
        """Return the explicitly non-product fixture/admin writer."""

        return ReferenceOnlyBootstrapAdmin(self)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "SqliteReferenceStaticAdmissionRepository":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "repository is closed",
            )

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    @staticmethod
    def _sqlite_reason(error: sqlite3.Error) -> ReferenceRepositoryReason:
        message = str(error).lower()
        if "locked" in message or "busy" in message:
            return ReferenceRepositoryReason.DEPENDENCY_BUSY
        return ReferenceRepositoryReason.STORE_UNAVAILABLE

    def _rollback_quietly(self) -> None:
        try:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def admit_static(
        self,
        command: StaticAdmissionCommand,
    ) -> CommittedStaticAdmission:
        """Commit or exactly replay one already-parsed Static command."""

        if not isinstance(command, StaticAdmissionCommand):
            raise _fail(
                ReferenceRepositoryReason.INVALID_COMMAND,
                "admit_static accepts only an already-parsed StaticAdmissionCommand",
            )
        try:
            command_bytes = command.to_canonical_bytes()
            if parse_static_admission_command(command_bytes) != command:
                raise ValueError("typed command does not round-trip exactly")
            command_hash = command.command_hash
            idempotency_scope_hash = derive_idempotency_scope_hash(command.vm_id)
        except Exception as error:
            raise _fail(
                ReferenceRepositoryReason.INVALID_COMMAND,
                str(error),
            ) from error

        with self._lock:
            self._ensure_open()
            began = False
            committed = False
            try:
                # This is deliberately the first database statement in the
                # admission operation.
                self._connection.execute("BEGIN IMMEDIATE")
                began = True
                self._verify_metadata()
                replay = self._read_idempotent_replay(
                    command,
                    command_bytes,
                    idempotency_scope_hash,
                )
                if replay is not None:
                    self._connection.execute("COMMIT")
                    committed = True
                    self._fault(AFTER_COMMIT_BEFORE_RETURN)
                    return replay

                now = _clock_timestamp(self._clock())
                current = self._read_current_state(command.vm_id)
                self._validate_command_currentness(command, current, now)
                evaluation = self._evaluate(command, current, now)
                self._verify_evaluation(evaluation, current, now)
                self._ensure_dependencies_absent(command, evaluation, current)
                self._fault(AFTER_AVAILABILITY_ABSENCE_READ)

                reread = self._read_current_state(command.vm_id)
                if not hmac.compare_digest(
                    canonical_json_bytes(current.to_wire()),
                    canonical_json_bytes(reread.to_wire()),
                ):
                    raise _fail(
                        ReferenceRepositoryReason.CURRENT_CHANGED,
                        "current rows changed between evaluation and commit",
                    )

                commit_decision_at = _clock_timestamp(self._clock())
                self._validate_commit_horizons(
                    command,
                    reread,
                    evaluation,
                    commit_decision_at,
                )
                result = self._write_admission(
                    command=command,
                    command_bytes=command_bytes,
                    command_hash=command_hash,
                    idempotency_scope_hash=idempotency_scope_hash,
                    current=reread,
                    evaluation=evaluation,
                    committed_at=commit_decision_at,
                )
                self._validate_commit_horizons(
                    command,
                    reread,
                    evaluation,
                    _clock_timestamp(self._clock()),
                )
                self._connection.execute("COMMIT")
                committed = True
                self._fault(AFTER_COMMIT_BEFORE_RETURN)
                return result
            except ReferenceRepositoryError:
                if began and not committed:
                    self._rollback_quietly()
                raise
            except sqlite3.Error as error:
                if began and not committed:
                    self._rollback_quietly()
                raise _fail(
                    self._sqlite_reason(error),
                    f"SQLite admission transaction failed: {error}",
                ) from error
            except Exception:
                if began and not committed:
                    self._rollback_quietly()
                raise

    def _read_idempotent_replay(
        self,
        command: StaticAdmissionCommand,
        command_bytes: bytes,
        idempotency_scope_hash: str,
    ) -> CommittedStaticAdmission | None:
        row = self._connection.execute(
            """
            SELECT command_hash, command_bytes, state, result_hash, result_bytes,
                   resource_version
            FROM idempotency_records
            WHERE operation_id = 'STATIC_ADMISSION'
              AND idempotency_scope_hash = ?
              AND idempotency_key = ?
            """,
            (idempotency_scope_hash, command.idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (
            row["command_hash"] != command.command_hash
            or bytes(row["command_bytes"]) != command_bytes
        ):
            raise _fail(
                ReferenceRepositoryReason.IDEMPOTENCY_KEY_REUSED,
                "natural key is already bound to different exact command bytes",
            )
        if (
            row["state"] != "COMPLETED"
            or row["result_hash"] is None
            or row["result_bytes"] is None
        ):
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "persisted idempotency row is not a completed atomic record",
            )
        result_bytes = bytes(row["result_bytes"])
        result = parse_committed_static_admission(result_bytes)
        if (
            result.result_hash != row["result_hash"]
            or result.command_id != command.command_id
            or result.command_hash != command.command_hash
            or result.vm_id != command.vm_id
            or result.run_id != command.run_id
            or result.idempotency.natural_key.idempotency_key != command.idempotency_key
            or result.idempotency.resource_version != row["resource_version"]
        ):
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "completed idempotency result is not bound to the accepted command",
            )
        return result

    def _verify_blob(self, blob_hash: str) -> None:
        row = self._connection.execute(
            """
            SELECT canonical_bytes
            FROM immutable_blobs
            WHERE blob_sha256 = ?
            """,
            (blob_hash,),
        ).fetchone()
        if row is None:
            raise _fail(
                ReferenceRepositoryReason.EVIDENCE_MISSING,
                f"immutable blob is absent: {blob_hash}",
            )
        raw = bytes(row["canonical_bytes"])
        try:
            load_canonical_json(raw)
        except Exception as error:
            raise _fail(
                ReferenceRepositoryReason.EVIDENCE_MISSING,
                f"immutable blob is not exact canonical JSON: {blob_hash}",
            ) from error
        if not hmac.compare_digest(sha256_digest(raw), blob_hash):
            raise _fail(
                ReferenceRepositoryReason.EVIDENCE_MISSING,
                f"immutable blob digest mismatch: {blob_hash}",
            )

    def _read_current_state(self, vm_id: str) -> ReferenceCurrentState:
        controller = self._connection.execute(
            """
            SELECT controller_generation, authority_lease_id, resource_version,
                   expires_at, blob_sha256
            FROM controller_current
            WHERE singleton = 1
            """
        ).fetchone()
        request = self._connection.execute(
            """
            SELECT request_version, request_hash, resource_version, blob_sha256
            FROM current_requests
            WHERE vm_id = ?
            """,
            (vm_id,),
        ).fetchone()
        availability = self._connection.execute(
            """
            SELECT authority_id, resource_version
            FROM global_availability
            WHERE singleton = 1
            """
        ).fetchone()
        artifact_rows = self._connection.execute(
            """
            SELECT kind, authority_id, sequence, artifact_digest,
                   resource_version, valid_until, blob_sha256
            FROM current_artifacts
            ORDER BY kind
            """
        ).fetchall()
        if (
            controller is None
            or request is None
            or availability is None
            or tuple(row["kind"] for row in artifact_rows) != _ARTIFACT_KINDS
        ):
            raise _fail(
                ReferenceRepositoryReason.BOOTSTRAP_INCOMPLETE,
                "controller/request/artifacts/global availability are incomplete",
            )

        member_rows = self._connection.execute(
            """
            SELECT device_id, generation, resource_version, evidence_blob_hash
            FROM availability_members
            ORDER BY device_id
            """
        ).fetchall()
        bundle_rows = self._connection.execute(
            """
            SELECT bundle_id, device_id
            FROM bundle_members
            ORDER BY bundle_id, device_id
            """
        ).fetchall()
        if not member_rows or not bundle_rows:
            raise _fail(
                ReferenceRepositoryReason.BOOTSTRAP_INCOMPLETE,
                "availability members and bundle membership are required",
            )

        blob_hashes = {
            controller["blob_sha256"],
            request["blob_sha256"],
            *(row["blob_sha256"] for row in artifact_rows),
            *(row["evidence_blob_hash"] for row in member_rows),
        }
        for blob_hash in sorted(blob_hashes):
            self._verify_blob(blob_hash)

        bundles_by_id: dict[str, list[str]] = {}
        for row in bundle_rows:
            bundles_by_id.setdefault(row["bundle_id"], []).append(row["device_id"])
        bundles = tuple(
            ReferenceBundle(bundle_id, tuple(member_ids))
            for bundle_id, member_ids in sorted(bundles_by_id.items())
        )
        artifacts = tuple(
            ReferenceCurrentArtifact(
                kind=row["kind"],
                authority_id=row["authority_id"],
                sequence=row["sequence"],
                artifact_digest=row["artifact_digest"],
                resource_version=row["resource_version"],
                valid_until=row["valid_until"],
                blob_sha256=row["blob_sha256"],
            )
            for row in artifact_rows
        )
        members = tuple(
            ReferenceAvailabilityMember(
                device_id=row["device_id"],
                generation=row["generation"],
                resource_version=row["resource_version"],
                evidence_blob_hash=row["evidence_blob_hash"],
            )
            for row in member_rows
        )

        def first_column(query: str) -> tuple[str, ...]:
            return tuple(row[0] for row in self._connection.execute(query))

        return ReferenceCurrentState(
            controller_generation=controller["controller_generation"],
            controller_authority_lease_id=controller["authority_lease_id"],
            controller_resource_version=controller["resource_version"],
            controller_expires_at=controller["expires_at"],
            controller_blob_sha256=controller["blob_sha256"],
            vm_id=vm_id,
            request_version=request["request_version"],
            request_hash=request["request_hash"],
            request_resource_version=request["resource_version"],
            request_blob_sha256=request["blob_sha256"],
            artifacts=artifacts,
            availability_authority_id=availability["authority_id"],
            availability_resource_version=availability["resource_version"],
            members=members,
            bundles=bundles,
            quarantine_keys=first_column(
                "SELECT conflict_key FROM quarantines ORDER BY conflict_key"
            ),
            claimed_bundle_ids=first_column(
                "SELECT bundle_id FROM bundle_claims ORDER BY bundle_id"
            ),
            claimed_member_ids=first_column(
                "SELECT member_id FROM member_claims ORDER BY member_id"
            ),
            active_scope_hashes=first_column(
                """
                SELECT scope_hash
                FROM operation_leases
                WHERE state = 'ACTIVE'
                ORDER BY scope_hash
                """
            ),
            active_run_ids=first_column(
                """
                SELECT run_id
                FROM operation_leases
                WHERE state = 'ACTIVE'
                ORDER BY run_id
                """
            ),
            active_vm_ids=first_column(
                """
                SELECT vm_id
                FROM assignment_runs
                WHERE state = 'PREPARING'
                ORDER BY vm_id
                """
            ),
        )

    @staticmethod
    def _validate_command_currentness(
        command: StaticAdmissionCommand,
        current: ReferenceCurrentState,
        now: str,
    ) -> None:
        now_dt = _timestamp_datetime(now, "now")
        if now_dt >= _timestamp_datetime(command.deadline, "command.deadline"):
            raise _fail(
                ReferenceRepositoryReason.DEADLINE_EXPIRED,
                "command deadline is not strictly in the future",
            )
        if (
            command.request_reference.request_version != current.request_version
            or command.request_reference.request_hash != current.request_hash
        ):
            raise _fail(
                ReferenceRepositoryReason.CURRENT_CHANGED,
                "command requestReference is not the current persisted request",
            )
        horizons = [
            current.controller_expires_at,
            *(artifact.valid_until for artifact in current.artifacts),
        ]
        if any(
            now_dt >= _timestamp_datetime(value, "current.valid_until")
            for value in horizons
        ):
            raise _fail(
                ReferenceRepositoryReason.CURRENT_CHANGED,
                "one or more current authority/artifact horizons have expired",
            )

    def _evaluate(
        self,
        command: StaticAdmissionCommand,
        current: ReferenceCurrentState,
        now: str,
    ) -> ReferenceEvaluation:
        try:
            evaluation = self._evaluator.evaluate(command, current)
        except Exception as error:
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                f"reference evaluator rejected current state: {error}",
            ) from error
        if not isinstance(evaluation, ReferenceEvaluation):
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                "reference evaluator returned the wrong type",
            )
        if _timestamp_datetime(now, "now") >= _timestamp_datetime(
            evaluation.valid_until,
            "evaluation.valid_until",
        ):
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                "reference evaluator evidence horizon has expired",
            )
        return evaluation

    @classmethod
    def _validate_commit_horizons(
        cls,
        command: StaticAdmissionCommand,
        current: ReferenceCurrentState,
        evaluation: ReferenceEvaluation,
        now: str,
    ) -> None:
        cls._validate_command_currentness(command, current, now)
        if _timestamp_datetime(now, "now") >= _timestamp_datetime(
            evaluation.valid_until,
            "evaluation.valid_until",
        ):
            raise _fail(
                ReferenceRepositoryReason.DEADLINE_EXPIRED,
                "evaluator evidence horizon expired before commit",
            )

    def _verify_evaluation(
        self,
        evaluation: ReferenceEvaluation,
        current: ReferenceCurrentState,
        now: str,
    ) -> None:
        del now
        try:
            bundle_member_ids = current.bundle_member_ids(evaluation.bundle_id)
            expected_members = tuple(
                sorted(
                    (
                        OperationLeaseMemberGeneration(
                            id=member_id,
                            generation=current.member(member_id).generation,
                        )
                        for member_id in bundle_member_ids
                    ),
                    key=lambda item: canonical_json_bytes([item.id, item.generation]),
                )
            )
        except KeyError as error:
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                "evaluator selected a non-current bundle or member",
            ) from error
        if evaluation.member_generations != expected_members:
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                "evaluator member generations are not the exact current bundle",
            )
        required_member_evidence = {
            current.member(member.id).evidence_blob_hash
            for member in evaluation.member_generations
        }
        if not required_member_evidence.issubset(evaluation.evidence_blob_hashes):
            raise _fail(
                ReferenceRepositoryReason.EVALUATOR_INVALID,
                "evaluator omitted evidence for one or more selected members",
            )
        for blob_hash in evaluation.evidence_blob_hashes:
            self._verify_blob(blob_hash)

    @staticmethod
    def _ensure_dependencies_absent(
        command: StaticAdmissionCommand,
        evaluation: ReferenceEvaluation,
        current: ReferenceCurrentState,
    ) -> None:
        member_ids = {item.id for item in evaluation.member_generations}
        conflict_keys = {
            evaluation.scope_hash,
            evaluation.bundle_id,
            *member_ids,
        }
        busy = (
            evaluation.scope_hash in current.active_scope_hashes
            or command.run_id in current.active_run_ids
            or command.vm_id in current.active_vm_ids
            or evaluation.bundle_id in current.claimed_bundle_ids
            or bool(member_ids.intersection(current.claimed_member_ids))
            or bool(conflict_keys.intersection(current.quarantine_keys))
        )
        if busy:
            raise _fail(
                ReferenceRepositoryReason.DEPENDENCY_BUSY,
                "static admission dependency is busy",
            )

    def _write_admission(
        self,
        *,
        command: StaticAdmissionCommand,
        command_bytes: bytes,
        command_hash: str,
        idempotency_scope_hash: str,
        current: ReferenceCurrentState,
        evaluation: ReferenceEvaluation,
        committed_at: str,
    ) -> CommittedStaticAdmission:
        connection = self._connection
        repository_transaction_id = f"reference-tx-{uuid.uuid4().hex}"
        operation_lease_id = f"operation-lease-{uuid.uuid4().hex}"
        bundle_lease_id = f"bundle-lease-{uuid.uuid4().hex}"
        valid_until = min(
            command.deadline,
            current.controller_expires_at,
            evaluation.valid_until,
            *(artifact.valid_until for artifact in current.artifacts),
        )
        availability_after = current.availability_resource_version + 1
        members_wire = [member.to_wire() for member in evaluation.member_generations]
        artifacts_wire = [artifact.to_wire() for artifact in current.artifacts]
        lease_spec_hash = sha256_digest(
            canonical_json_bytes(
                {
                    "subjectType": "REFERENCE_ASSIGNMENT_PREPARE_LEASE_SPEC",
                    "schemaVersion": 1,
                    "scopeHash": evaluation.scope_hash,
                    "runId": command.run_id,
                    "bundleId": evaluation.bundle_id,
                    "memberGenerations": members_wire,
                    "hostEpoch": current.artifact("INVENTORY").sequence,
                    "runGeneration": 1,
                    "holderControllerGeneration": (current.controller_generation),
                    "validUntil": valid_until,
                }
            )
        )
        binding_without_hash = {
            "subjectType": "REFERENCE_STATIC_ADMISSION_BINDING",
            "schemaVersion": 1,
            "operationLeaseId": operation_lease_id,
            "runId": command.run_id,
            "vmId": command.vm_id,
            "commandHash": command_hash,
            "scopeHash": evaluation.scope_hash,
            "bundleId": evaluation.bundle_id,
            "memberGenerations": members_wire,
            "evidenceBlobHashes": list(evaluation.evidence_blob_hashes),
            "controllerAuthorityResourceVersion": (current.controller_resource_version),
            "requestResourceVersion": current.request_resource_version,
            "availabilityAuthorityResourceVersionBefore": (
                current.availability_resource_version
            ),
            "availabilityAuthorityResourceVersionAfter": availability_after,
            "artifacts": artifacts_wire,
            "validUntil": valid_until,
            "bindingHash": None,
        }
        binding_hash = sha256_digest(canonical_json_bytes(binding_without_hash))
        binding_wire = dict(binding_without_hash)
        binding_wire["bindingHash"] = binding_hash
        binding_bytes = canonical_json_bytes(binding_wire)

        connection.execute(
            """
            INSERT INTO idempotency_records(
                operation_id, idempotency_scope_hash, idempotency_key,
                command_id, command_hash, command_bytes, state,
                result_hash, result_bytes, run_id, resource_version
            ) VALUES (
                'STATIC_ADMISSION', ?, ?, ?, ?, ?, 'IN_PROGRESS',
                NULL, NULL, ?, 1
            )
            """,
            (
                idempotency_scope_hash,
                command.idempotency_key,
                command.command_id,
                command_hash,
                command_bytes,
                command.run_id,
            ),
        )
        self._fault("IDEMPOTENCY_WRITTEN")

        connection.execute(
            """
            INSERT INTO operation_leases(
                operation_lease_id, lease_type, state, scope_hash, run_id,
                host_epoch, run_generation, holder_controller_generation,
                resource_version, lease_spec_hash, admission_binding_hash,
                valid_until, created_at
            ) VALUES (
                ?, 'ASSIGNMENT_PREPARE', 'ACTIVE', ?, ?, ?, 1, ?, 1, ?, ?, ?, ?
            )
            """,
            (
                operation_lease_id,
                evaluation.scope_hash,
                command.run_id,
                current.artifact("INVENTORY").sequence,
                current.controller_generation,
                lease_spec_hash,
                binding_hash,
                valid_until,
                committed_at,
            ),
        )
        self._fault("LEASE_WRITTEN")

        connection.execute(
            """
            INSERT INTO admission_bindings(
                binding_hash, operation_lease_id, binding_bytes,
                valid_until, resource_version
            ) VALUES (?, ?, ?, ?, 1)
            """,
            (
                binding_hash,
                operation_lease_id,
                binding_bytes,
                valid_until,
            ),
        )
        self._fault("BINDING_WRITTEN")

        connection.execute(
            """
            INSERT INTO operation_lease_bundles(operation_lease_id, bundle_id)
            VALUES (?, ?)
            """,
            (operation_lease_id, evaluation.bundle_id),
        )
        connection.executemany(
            """
            INSERT INTO operation_lease_members(
                operation_lease_id, member_id, generation
            ) VALUES (?, ?, ?)
            """,
            (
                (operation_lease_id, member.id, member.generation)
                for member in evaluation.member_generations
            ),
        )
        connection.execute(
            """
            INSERT INTO bundle_claims(
                bundle_id, lease_id, operation_lease_id, run_id,
                state, resource_version
            ) VALUES (?, ?, ?, ?, 'RESERVED', 1)
            """,
            (
                evaluation.bundle_id,
                bundle_lease_id,
                operation_lease_id,
                command.run_id,
            ),
        )
        connection.executemany(
            """
            INSERT INTO member_claims(
                member_id, operation_lease_id, run_id, generation
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (
                    member.id,
                    operation_lease_id,
                    command.run_id,
                    member.generation,
                )
                for member in evaluation.member_generations
            ),
        )
        self._fault("CLAIMS_WRITTEN")

        connection.execute(
            """
            INSERT INTO assignment_runs(
                run_id, vm_id, state, operation_lease_id,
                admission_binding_hash, controller_generation,
                resource_version
            ) VALUES (?, ?, 'PREPARING', ?, ?, ?, 1)
            """,
            (
                command.run_id,
                command.vm_id,
                operation_lease_id,
                binding_hash,
                current.controller_generation,
            ),
        )
        self._fault("RUN_WRITTEN")

        audit_event_id = f"audit-{uuid.uuid4().hex}"
        connection.execute(
            """
            INSERT INTO audit_events(
                event_id, repository_transaction_id, run_id,
                aggregate_version, payload_hash, prior_event_hash, created_at
            ) VALUES (?, ?, ?, 1, ?, ?, ?)
            """,
            (
                audit_event_id,
                repository_transaction_id,
                command.run_id,
                binding_hash,
                sha256_digest(b""),
                committed_at,
            ),
        )
        self._fault("AUDIT_WRITTEN")

        outbox_id = f"outbox-{uuid.uuid4().hex}"
        connection.execute(
            """
            INSERT INTO outbox_events(
                outbox_id, repository_transaction_id, run_id,
                aggregate_version, event_type, payload_hash,
                state, resource_version, created_at
            ) VALUES (
                ?, ?, ?, 1, 'STATIC_ADMISSION_COMMITTED', ?,
                'PENDING', 1, ?
            )
            """,
            (
                outbox_id,
                repository_transaction_id,
                command.run_id,
                binding_hash,
                committed_at,
            ),
        )
        self._fault("OUTBOX_WRITTEN")

        cursor = connection.execute(
            """
            UPDATE global_availability
            SET resource_version = ?
            WHERE singleton = 1 AND authority_id = ? AND resource_version = ?
            """,
            (
                availability_after,
                current.availability_authority_id,
                current.availability_resource_version,
            ),
        )
        if cursor.rowcount != 1:
            raise _fail(
                ReferenceRepositoryReason.CURRENT_CHANGED,
                "global availability authority CAS failed",
            )
        self._fault("AVAILABILITY_ADVANCED")

        connection.execute(
            "UPDATE commit_clock SET last_sequence = last_sequence + 1 WHERE singleton = 1"
        )
        commit_sequence = connection.execute(
            "SELECT last_sequence FROM commit_clock WHERE singleton = 1"
        ).fetchone()[0]
        self._fault("COMMIT_SEQUENCE_ALLOCATED")

        capability = CommittedOperationLeaseCapability(
            operation_lease_id=operation_lease_id,
            scope_hash=evaluation.scope_hash,
            run_id_or_intent_id=command.run_id,
            bundle_ids=(evaluation.bundle_id,),
            member_generations=evaluation.member_generations,
            host_epoch=current.artifact("INVENTORY").sequence,
            run_generation_or_null=1,
            holder_controller_generation=current.controller_generation,
            operation_lease_resource_version=1,
            admission_binding_hash_or_null=binding_hash,
        )
        result = CommittedStaticAdmission.create(
            command_id=command.command_id,
            vm_id=command.vm_id,
            run_id=command.run_id,
            command_hash=command_hash,
            operation_lease_capability=capability,
            admission_binding_hash=binding_hash,
            committed_resource_versions=CommittedResourceVersions(
                controller_authority_resource_version=(
                    current.controller_resource_version
                ),
                host_authority_resource_version=(
                    current.artifact("INVENTORY").resource_version
                ),
                request_resource_version=current.request_resource_version,
                policy_authority_resource_version=(
                    current.artifact("POLICY").resource_version
                ),
                availability_authority_resource_version=availability_after,
                assignment_run_resource_version=1,
                bundle_lease_resource_version=1,
                operation_lease_resource_version=1,
            ),
            idempotency=CommittedIdempotency(
                natural_key=IdempotencyNaturalKey(
                    idempotency_scope_hash=idempotency_scope_hash,
                    idempotency_key=command.idempotency_key,
                ),
                resource_version=2,
            ),
            repository_transaction_id=repository_transaction_id,
            commit_sequence=commit_sequence,
            committed_at=committed_at,
        )
        result_bytes = result.to_canonical_bytes()
        cursor = connection.execute(
            """
            UPDATE idempotency_records
            SET state = 'COMPLETED', result_hash = ?, result_bytes = ?,
                resource_version = 2
            WHERE operation_id = 'STATIC_ADMISSION'
              AND idempotency_scope_hash = ?
              AND idempotency_key = ?
              AND state = 'IN_PROGRESS'
              AND resource_version = 1
              AND command_hash = ?
              AND command_bytes = ?
            """,
            (
                result.result_hash,
                result_bytes,
                idempotency_scope_hash,
                command.idempotency_key,
                command_hash,
                command_bytes,
            ),
        )
        if cursor.rowcount != 1:
            raise _fail(
                ReferenceRepositoryReason.CURRENT_CHANGED,
                "idempotency completion CAS failed",
            )
        self._fault("IDEMPOTENCY_COMPLETED")

        connection.execute(
            """
            INSERT INTO repository_commits(
                commit_sequence, repository_transaction_id,
                command_hash, result_hash, committed_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                commit_sequence,
                repository_transaction_id,
                command_hash,
                result.result_hash,
                committed_at,
            ),
        )
        self._fault("COMMIT_RECORD_WRITTEN")
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise _fail(
                ReferenceRepositoryReason.STORE_UNAVAILABLE,
                "foreign-key invariant failed before commit",
            )
        self._fault("BEFORE_COMMIT")
        return result

    def _admin_transaction(self, operation: Callable[[sqlite3.Connection], object]):
        with self._lock:
            self._ensure_open()
            began = False
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                began = True
                self._verify_metadata()
                result = operation(self._connection)
                self._connection.execute("COMMIT")
                return result
            except ReferenceRepositoryError:
                if began:
                    self._rollback_quietly()
                raise
            except sqlite3.Error as error:
                if began:
                    self._rollback_quietly()
                raise _fail(
                    self._sqlite_reason(error),
                    f"SQLite reference-only admin transaction failed: {error}",
                ) from error
            except Exception:
                if began:
                    self._rollback_quietly()
                raise

    def inspect_reference_state(self) -> dict[str, object]:
        """Return read-only diagnostics for tests and evidence inspection."""

        with self._lock:
            self._ensure_open()
            table_names = (
                "admission_bindings",
                "assignment_runs",
                "audit_events",
                "bundle_claims",
                "idempotency_records",
                "member_claims",
                "operation_leases",
                "outbox_events",
                "quarantines",
                "repository_commits",
            )
            counts = {
                table: self._connection.execute(
                    f"SELECT COUNT(*) FROM {table}"  # noqa: S608
                ).fetchone()[0]
                for table in table_names
            }
            metadata = {
                row["key"]: row["value"]
                for row in self._connection.execute(
                    "SELECT key, value FROM metadata ORDER BY key"
                )
            }
            availability = self._connection.execute(
                "SELECT authority_id, resource_version FROM global_availability"
            ).fetchone()
            commits = [
                {
                    "commitSequence": row["commit_sequence"],
                    "repositoryTransactionId": row["repository_transaction_id"],
                    "commandHash": row["command_hash"],
                    "resultHash": row["result_hash"],
                }
                for row in self._connection.execute(
                    """
                    SELECT commit_sequence, repository_transaction_id,
                           command_hash, result_hash
                    FROM repository_commits
                    ORDER BY commit_sequence
                    """
                )
            ]
            leases = [
                {
                    "operationLeaseId": row["operation_lease_id"],
                    "scopeHash": row["scope_hash"],
                    "runId": row["run_id"],
                    "state": row["state"],
                    "admissionBindingHash": row["admission_binding_hash"],
                }
                for row in self._connection.execute(
                    """
                    SELECT operation_lease_id, scope_hash, run_id, state,
                           admission_binding_hash
                    FROM operation_leases
                    ORDER BY operation_lease_id
                    """
                )
            ]
            commit_clock = self._connection.execute(
                "SELECT last_sequence FROM commit_clock WHERE singleton = 1"
            ).fetchone()[0]
            return {
                "evidenceBoundary": EVIDENCE_BOUNDARY,
                "databasePath": str(self._database_path),
                "metadata": metadata,
                "pragmas": {
                    "journalMode": self._connection.execute(
                        "PRAGMA journal_mode"
                    ).fetchone()[0],
                    "synchronous": self._connection.execute(
                        "PRAGMA synchronous"
                    ).fetchone()[0],
                    "foreignKeys": self._connection.execute(
                        "PRAGMA foreign_keys"
                    ).fetchone()[0],
                    "busyTimeoutMs": self._connection.execute(
                        "PRAGMA busy_timeout"
                    ).fetchone()[0],
                },
                "globalAvailability": (
                    None
                    if availability is None
                    else {
                        "authorityId": availability["authority_id"],
                        "resourceVersion": availability["resource_version"],
                    }
                ),
                "counts": counts,
                "commitClock": commit_clock,
                "commits": commits,
                "operationLeases": leases,
            }


class ReferenceOnlyBootstrapAdmin:
    """Explicit fixture/admin API; never a production mutation surface."""

    evidence_boundary = REFERENCE_ONLY_BOOTSTRAP

    def __init__(
        self,
        repository: SqliteReferenceStaticAdmissionRepository,
    ) -> None:
        self._repository = repository

    def put_immutable_blob(
        self,
        schema_ref: str,
        value: object | bytes | bytearray | memoryview,
    ) -> str:
        schema_ref = _require_id(schema_ref, "schema_ref")
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            load_canonical_json(raw)
        else:
            raw = canonical_json_bytes(value)
        blob_hash = sha256_digest(raw)

        def write(connection: sqlite3.Connection) -> str:
            now = _clock_timestamp(self._repository._clock())
            row = connection.execute(
                """
                SELECT schema_ref, canonical_bytes
                FROM immutable_blobs
                WHERE blob_sha256 = ?
                """,
                (blob_hash,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO immutable_blobs(
                        blob_sha256, schema_ref, canonical_bytes, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (blob_hash, schema_ref, raw, now),
                )
            elif (
                row["schema_ref"] != schema_ref or bytes(row["canonical_bytes"]) != raw
            ):
                raise _fail(
                    ReferenceRepositoryReason.STORE_UNAVAILABLE,
                    "immutable blob identity collision",
                )
            return blob_hash

        return self._repository._admin_transaction(write)

    @staticmethod
    def _require_blob(connection: sqlite3.Connection, blob_hash: str) -> None:
        if (
            connection.execute(
                "SELECT 1 FROM immutable_blobs WHERE blob_sha256 = ?",
                (blob_hash,),
            ).fetchone()
            is None
        ):
            raise _fail(
                ReferenceRepositoryReason.EVIDENCE_MISSING,
                f"bootstrap references absent immutable blob: {blob_hash}",
            )

    def set_controller_current(
        self,
        *,
        controller_generation: int,
        authority_lease_id: str,
        resource_version: int,
        expires_at: str,
        blob_sha256: str,
    ) -> None:
        controller_generation = _require_positive(
            controller_generation, "controller_generation"
        )
        authority_lease_id = _require_id(authority_lease_id, "authority_lease_id")
        resource_version = _require_positive(resource_version, "resource_version")
        expires_at = _require_timestamp(expires_at, "expires_at")
        blob_sha256 = _require_digest(blob_sha256, "blob_sha256")

        def write(connection: sqlite3.Connection) -> None:
            self._require_blob(connection, blob_sha256)
            connection.execute(
                """
                INSERT INTO controller_current(
                    singleton, controller_generation, authority_lease_id,
                    resource_version, expires_at, blob_sha256
                ) VALUES (1, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    controller_generation = excluded.controller_generation,
                    authority_lease_id = excluded.authority_lease_id,
                    resource_version = excluded.resource_version,
                    expires_at = excluded.expires_at,
                    blob_sha256 = excluded.blob_sha256
                """,
                (
                    controller_generation,
                    authority_lease_id,
                    resource_version,
                    expires_at,
                    blob_sha256,
                ),
            )

        self._repository._admin_transaction(write)

    def set_current_request(
        self,
        *,
        vm_id: str,
        request_version: int,
        request_hash: str,
        resource_version: int,
        blob_sha256: str,
    ) -> None:
        vm_id = _require_id(vm_id, "vm_id")
        request_version = _require_positive(request_version, "request_version")
        request_hash = _require_digest(request_hash, "request_hash")
        resource_version = _require_positive(resource_version, "resource_version")
        blob_sha256 = _require_digest(blob_sha256, "blob_sha256")

        def write(connection: sqlite3.Connection) -> None:
            self._require_blob(connection, blob_sha256)
            connection.execute(
                """
                INSERT INTO current_requests(
                    vm_id, request_version, request_hash,
                    resource_version, blob_sha256
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(vm_id) DO UPDATE SET
                    request_version = excluded.request_version,
                    request_hash = excluded.request_hash,
                    resource_version = excluded.resource_version,
                    blob_sha256 = excluded.blob_sha256
                """,
                (
                    vm_id,
                    request_version,
                    request_hash,
                    resource_version,
                    blob_sha256,
                ),
            )

        self._repository._admin_transaction(write)

    def set_current_artifact(
        self,
        *,
        kind: str,
        authority_id: str,
        sequence: int,
        artifact_digest: str,
        resource_version: int,
        valid_until: str,
        blob_sha256: str,
    ) -> None:
        if kind not in _ARTIFACT_KINDS:
            raise ValueError(f"kind must be one of {_ARTIFACT_KINDS}")
        authority_id = _require_id(authority_id, "authority_id")
        sequence = _require_positive(sequence, "sequence")
        artifact_digest = _require_digest(artifact_digest, "artifact_digest")
        resource_version = _require_positive(resource_version, "resource_version")
        valid_until = _require_timestamp(valid_until, "valid_until")
        blob_sha256 = _require_digest(blob_sha256, "blob_sha256")

        def write(connection: sqlite3.Connection) -> None:
            self._require_blob(connection, blob_sha256)
            connection.execute(
                """
                INSERT INTO current_artifacts(
                    kind, authority_id, sequence, artifact_digest,
                    resource_version, valid_until, blob_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind) DO UPDATE SET
                    authority_id = excluded.authority_id,
                    sequence = excluded.sequence,
                    artifact_digest = excluded.artifact_digest,
                    resource_version = excluded.resource_version,
                    valid_until = excluded.valid_until,
                    blob_sha256 = excluded.blob_sha256
                """,
                (
                    kind,
                    authority_id,
                    sequence,
                    artifact_digest,
                    resource_version,
                    valid_until,
                    blob_sha256,
                ),
            )

        self._repository._admin_transaction(write)

    def set_global_availability(
        self,
        *,
        authority_id: str,
        resource_version: int,
    ) -> None:
        authority_id = _require_id(authority_id, "authority_id")
        resource_version = _require_positive(resource_version, "resource_version")

        def write(connection: sqlite3.Connection) -> None:
            if connection.execute("SELECT 1 FROM operation_leases LIMIT 1").fetchone():
                raise _fail(
                    ReferenceRepositoryReason.DEPENDENCY_BUSY,
                    "cannot reset global availability after an admission commit",
                )
            connection.execute(
                """
                INSERT INTO global_availability(
                    singleton, authority_id, resource_version
                ) VALUES (1, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    authority_id = excluded.authority_id,
                    resource_version = excluded.resource_version
                """,
                (authority_id, resource_version),
            )

        self._repository._admin_transaction(write)

    @staticmethod
    def _advance_global(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            """
            SELECT authority_id, resource_version
            FROM global_availability
            WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise _fail(
                ReferenceRepositoryReason.BOOTSTRAP_INCOMPLETE,
                "global availability must be bootstrapped first",
            )
        cursor = connection.execute(
            """
            UPDATE global_availability
            SET resource_version = ?
            WHERE singleton = 1 AND authority_id = ? AND resource_version = ?
            """,
            (row["resource_version"] + 1, row["authority_id"], row["resource_version"]),
        )
        if cursor.rowcount != 1:
            raise _fail(
                ReferenceRepositoryReason.CURRENT_CHANGED,
                "reference-only global availability CAS failed",
            )

    def set_availability_member(
        self,
        *,
        device_id: str,
        generation: int,
        resource_version: int,
        evidence_blob_hash: str,
    ) -> None:
        device_id = _require_id(device_id, "device_id")
        generation = _require_positive(generation, "generation")
        resource_version = _require_positive(resource_version, "resource_version")
        evidence_blob_hash = _require_digest(evidence_blob_hash, "evidence_blob_hash")

        def write(connection: sqlite3.Connection) -> None:
            self._require_blob(connection, evidence_blob_hash)
            if connection.execute(
                "SELECT 1 FROM member_claims WHERE member_id = ?",
                (device_id,),
            ).fetchone():
                raise _fail(
                    ReferenceRepositoryReason.DEPENDENCY_BUSY,
                    "static admission dependency is busy",
                )
            connection.execute(
                """
                INSERT INTO availability_members(
                    device_id, generation, resource_version, evidence_blob_hash
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    generation = excluded.generation,
                    resource_version = excluded.resource_version,
                    evidence_blob_hash = excluded.evidence_blob_hash
                """,
                (device_id, generation, resource_version, evidence_blob_hash),
            )
            self._advance_global(connection)

        self._repository._admin_transaction(write)

    def set_bundle_members(
        self,
        *,
        bundle_id: str,
        member_ids: Sequence[str],
    ) -> None:
        bundle_id = _require_digest(bundle_id, "bundle_id")
        normalized_member_ids = _canonical_unique_ids(member_ids, "member_ids")

        def write(connection: sqlite3.Connection) -> None:
            if connection.execute(
                "SELECT 1 FROM bundle_claims WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone():
                raise _fail(
                    ReferenceRepositoryReason.DEPENDENCY_BUSY,
                    "static admission dependency is busy",
                )
            for member_id in normalized_member_ids:
                if (
                    connection.execute(
                        "SELECT 1 FROM availability_members WHERE device_id = ?",
                        (member_id,),
                    ).fetchone()
                    is None
                ):
                    raise _fail(
                        ReferenceRepositoryReason.BOOTSTRAP_INCOMPLETE,
                        f"bundle member is absent: {member_id}",
                    )
            connection.execute(
                "DELETE FROM bundle_members WHERE bundle_id = ?",
                (bundle_id,),
            )
            connection.executemany(
                """
                INSERT INTO bundle_members(bundle_id, device_id)
                VALUES (?, ?)
                """,
                ((bundle_id, member_id) for member_id in normalized_member_ids),
            )
            self._advance_global(connection)

        self._repository._admin_transaction(write)

    def set_quarantine(
        self,
        *,
        conflict_key: str,
        quarantine_digest: str,
        resource_version: int,
    ) -> None:
        if not isinstance(conflict_key, str) or not (
            _ID_RE.fullmatch(conflict_key) or _DIGEST_RE.fullmatch(conflict_key)
        ):
            raise ValueError("conflict_key must be a closed identifier or digest")
        quarantine_digest = _require_digest(quarantine_digest, "quarantine_digest")
        resource_version = _require_positive(resource_version, "resource_version")

        def write(connection: sqlite3.Connection) -> None:
            busy = any(
                connection.execute(query, (conflict_key,)).fetchone() is not None
                for query in (
                    """
                    SELECT 1 FROM operation_leases
                    WHERE state = 'ACTIVE' AND scope_hash = ?
                    """,
                    "SELECT 1 FROM bundle_claims WHERE bundle_id = ?",
                    "SELECT 1 FROM member_claims WHERE member_id = ?",
                )
            )
            if busy:
                raise _fail(
                    ReferenceRepositoryReason.DEPENDENCY_BUSY,
                    "static admission dependency is busy",
                )
            connection.execute(
                """
                INSERT INTO quarantines(
                    conflict_key, quarantine_digest, resource_version
                ) VALUES (?, ?, ?)
                ON CONFLICT(conflict_key) DO UPDATE SET
                    quarantine_digest = excluded.quarantine_digest,
                    resource_version = excluded.resource_version
                """,
                (conflict_key, quarantine_digest, resource_version),
            )
            self._advance_global(connection)

        self._repository._admin_transaction(write)

    def set_reference_query_observer(
        self,
        *,
        observer_instance_id: str,
        restart_generation: int,
        resource_version: int,
        host_id: str,
        host_epoch: int,
        kernel_boot_id: str,
        agent_generation: int,
        journal_epoch: int,
        counter_epoch: int,
        reset_observer_id: str,
        host_journal_sequence: int,
        driver_bind_count: int,
        driver_unbind_count: int,
        device_reset_count: int,
        vfio_exclusive_open_count: int,
        qemu_spawn_count: int,
        observation_digest: str,
    ) -> None:
        """Bootstrap the explicitly non-product C15 observer row.

        The row models evidence that a production query would obtain from a
        host journal and device observers.  It is fixture state only: no
        reference code in this package reads a real driver or host journal.
        """

        observer_instance_id = _require_id(
            observer_instance_id,
            "observer_instance_id",
        )
        restart_generation = _require_positive(
            restart_generation,
            "restart_generation",
        )
        resource_version = _require_positive(
            resource_version,
            "resource_version",
        )
        host_id = _require_id(host_id, "host_id")
        host_epoch = _require_positive(host_epoch, "host_epoch")
        kernel_boot_id = _require_id(kernel_boot_id, "kernel_boot_id")
        agent_generation = _require_positive(
            agent_generation,
            "agent_generation",
        )
        journal_epoch = _require_positive(journal_epoch, "journal_epoch")
        counter_epoch = _require_positive(counter_epoch, "counter_epoch")
        reset_observer_id = _require_id(
            reset_observer_id,
            "reset_observer_id",
        )
        counters = {
            "host_journal_sequence": host_journal_sequence,
            "driver_bind_count": driver_bind_count,
            "driver_unbind_count": driver_unbind_count,
            "device_reset_count": device_reset_count,
            "vfio_exclusive_open_count": vfio_exclusive_open_count,
            "qemu_spawn_count": qemu_spawn_count,
        }
        for field, value in counters.items():
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > 9_007_199_254_740_991
            ):
                raise ValueError(f"{field}: expected a safe non-negative integer")
        observation_digest = _require_digest(
            observation_digest,
            "observation_digest",
        )

        def write(connection: sqlite3.Connection) -> None:
            connection.execute(
                """
                INSERT INTO reference_query_observer(
                    singleton, observer_instance_id, restart_generation,
                    resource_version, host_id, host_epoch, kernel_boot_id,
                    agent_generation, journal_epoch, counter_epoch,
                    reset_observer_id, host_journal_sequence,
                    driver_bind_count, driver_unbind_count,
                    device_reset_count, vfio_exclusive_open_count,
                    qemu_spawn_count, observation_digest
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    observer_instance_id = excluded.observer_instance_id,
                    restart_generation = excluded.restart_generation,
                    resource_version = excluded.resource_version,
                    host_id = excluded.host_id,
                    host_epoch = excluded.host_epoch,
                    kernel_boot_id = excluded.kernel_boot_id,
                    agent_generation = excluded.agent_generation,
                    journal_epoch = excluded.journal_epoch,
                    counter_epoch = excluded.counter_epoch,
                    reset_observer_id = excluded.reset_observer_id,
                    host_journal_sequence = excluded.host_journal_sequence,
                    driver_bind_count = excluded.driver_bind_count,
                    driver_unbind_count = excluded.driver_unbind_count,
                    device_reset_count = excluded.device_reset_count,
                    vfio_exclusive_open_count =
                        excluded.vfio_exclusive_open_count,
                    qemu_spawn_count = excluded.qemu_spawn_count,
                    observation_digest = excluded.observation_digest
                """,
                (
                    observer_instance_id,
                    restart_generation,
                    resource_version,
                    host_id,
                    host_epoch,
                    kernel_boot_id,
                    agent_generation,
                    journal_epoch,
                    counter_epoch,
                    reset_observer_id,
                    host_journal_sequence,
                    driver_bind_count,
                    driver_unbind_count,
                    device_reset_count,
                    vfio_exclusive_open_count,
                    qemu_spawn_count,
                    observation_digest,
                ),
            )

        self._repository._admin_transaction(write)

    def publish_reference_query_observation(
        self,
        *,
        inventory_authority_id: str,
        inventory_sequence: int,
        inventory_digest: str,
        inventory_resource_version: int,
        inventory_valid_until: str,
        inventory_blob_sha256: str,
        observer_instance_id: str,
        restart_generation: int,
        observer_resource_version: int,
        host_id: str,
        host_epoch: int,
        kernel_boot_id: str,
        agent_generation: int,
        journal_epoch: int,
        counter_epoch: int,
        reset_observer_id: str,
        host_journal_sequence: int,
        driver_bind_count: int,
        driver_unbind_count: int,
        device_reset_count: int,
        vfio_exclusive_open_count: int,
        qemu_spawn_count: int,
        observation_digest: str,
    ) -> None:
        """Atomically publish one complete reference query observation.

        This is a deterministic fixture publisher for the WAL snapshot tests.
        It advances the same global availability fence as other
        availability-affecting reference-only mutations.
        """

        inventory_authority_id = _require_id(
            inventory_authority_id,
            "inventory_authority_id",
        )
        inventory_sequence = _require_positive(
            inventory_sequence,
            "inventory_sequence",
        )
        inventory_digest = _require_digest(
            inventory_digest,
            "inventory_digest",
        )
        inventory_resource_version = _require_positive(
            inventory_resource_version,
            "inventory_resource_version",
        )
        inventory_valid_until = _require_timestamp(
            inventory_valid_until,
            "inventory_valid_until",
        )
        inventory_blob_sha256 = _require_digest(
            inventory_blob_sha256,
            "inventory_blob_sha256",
        )
        observer_instance_id = _require_id(
            observer_instance_id,
            "observer_instance_id",
        )
        restart_generation = _require_positive(
            restart_generation,
            "restart_generation",
        )
        observer_resource_version = _require_positive(
            observer_resource_version,
            "observer_resource_version",
        )
        host_id = _require_id(host_id, "host_id")
        host_epoch = _require_positive(host_epoch, "host_epoch")
        kernel_boot_id = _require_id(kernel_boot_id, "kernel_boot_id")
        agent_generation = _require_positive(
            agent_generation,
            "agent_generation",
        )
        journal_epoch = _require_positive(journal_epoch, "journal_epoch")
        counter_epoch = _require_positive(counter_epoch, "counter_epoch")
        reset_observer_id = _require_id(
            reset_observer_id,
            "reset_observer_id",
        )
        counters = {
            "host_journal_sequence": host_journal_sequence,
            "driver_bind_count": driver_bind_count,
            "driver_unbind_count": driver_unbind_count,
            "device_reset_count": device_reset_count,
            "vfio_exclusive_open_count": vfio_exclusive_open_count,
            "qemu_spawn_count": qemu_spawn_count,
        }
        for field, value in counters.items():
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > 9_007_199_254_740_991
            ):
                raise ValueError(f"{field}: expected a safe non-negative integer")
        observation_digest = _require_digest(
            observation_digest,
            "observation_digest",
        )

        def write(connection: sqlite3.Connection) -> None:
            self._require_blob(connection, inventory_blob_sha256)
            if (
                connection.execute(
                    "SELECT 1 FROM reference_query_observer WHERE singleton = 1"
                ).fetchone()
                is None
            ):
                raise _fail(
                    ReferenceRepositoryReason.BOOTSTRAP_INCOMPLETE,
                    "reference query observer must be bootstrapped first",
                )
            connection.execute(
                """
                INSERT INTO current_artifacts(
                    kind, authority_id, sequence, artifact_digest,
                    resource_version, valid_until, blob_sha256
                ) VALUES ('INVENTORY', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind) DO UPDATE SET
                    authority_id = excluded.authority_id,
                    sequence = excluded.sequence,
                    artifact_digest = excluded.artifact_digest,
                    resource_version = excluded.resource_version,
                    valid_until = excluded.valid_until,
                    blob_sha256 = excluded.blob_sha256
                """,
                (
                    inventory_authority_id,
                    inventory_sequence,
                    inventory_digest,
                    inventory_resource_version,
                    inventory_valid_until,
                    inventory_blob_sha256,
                ),
            )
            connection.execute(
                """
                UPDATE reference_query_observer
                SET observer_instance_id = ?,
                    restart_generation = ?,
                    resource_version = ?,
                    host_id = ?,
                    host_epoch = ?,
                    kernel_boot_id = ?,
                    agent_generation = ?,
                    journal_epoch = ?,
                    counter_epoch = ?,
                    reset_observer_id = ?,
                    host_journal_sequence = ?,
                    driver_bind_count = ?,
                    driver_unbind_count = ?,
                    device_reset_count = ?,
                    vfio_exclusive_open_count = ?,
                    qemu_spawn_count = ?,
                    observation_digest = ?
                WHERE singleton = 1
                """,
                (
                    observer_instance_id,
                    restart_generation,
                    observer_resource_version,
                    host_id,
                    host_epoch,
                    kernel_boot_id,
                    agent_generation,
                    journal_epoch,
                    counter_epoch,
                    reset_observer_id,
                    host_journal_sequence,
                    driver_bind_count,
                    driver_unbind_count,
                    device_reset_count,
                    vfio_exclusive_open_count,
                    qemu_spawn_count,
                    observation_digest,
                ),
            )
            self._advance_global(connection)

        self._repository._admin_transaction(write)


__all__ = [
    "AFTER_AVAILABILITY_ABSENCE_READ",
    "AFTER_COMMIT_BEFORE_RETURN",
    "REFERENCE_EVALUATOR_PREMISE",
    "REFERENCE_ONLY_BOOTSTRAP",
    "WRITE_FAULT_STAGES",
    "DeterministicReferenceEvaluator",
    "ReferenceAvailabilityMember",
    "ReferenceBundle",
    "ReferenceCurrentArtifact",
    "ReferenceCurrentState",
    "ReferenceEvaluation",
    "ReferenceEvaluatorPremise",
    "ReferenceOnlyBootstrapAdmin",
    "ReferenceRepositoryError",
    "ReferenceRepositoryReason",
    "ReferenceSelectionPremise",
    "SqliteReferenceStaticAdmissionRepository",
]
