"""Read-only SQLite snapshot evidence for the C15 reference query lane.

This module deliberately stops below the portable query trace contract.  It
proves what the local SQLite connection actually read and how the connection
was configured; it does not manufacture a product host journal, driver
counter, capability decision, or Qman repository transaction.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
import sqlite3
from typing import Any

from .sqlite_schema import SCHEMA_VERSION
from .static_admission_contracts import (
    ContractViolation,
    EVIDENCE_BOUNDARY,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)


REFERENCE_QUERY_EVIDENCE_BOUNDARY = "REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY"
AFTER_QUERY_BEFORE_STATE = "AFTER_QUERY_BEFORE_STATE"
BEFORE_QUERY_READ_COMMIT = "BEFORE_QUERY_READ_COMMIT"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReferenceQueryReason(str, Enum):
    """Stable fail-closed reasons for the reference read adapter."""

    STORE_NOT_READABLE = "STORE_NOT_READABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    STORE_IDENTITY_MISSING = "STORE_IDENTITY_MISSING"
    AVAILABILITY_FENCE_MISSING = "AVAILABILITY_FENCE_MISSING"
    QUERY_OBSERVER_MISSING = "QUERY_OBSERVER_MISSING"
    CURRENT_REQUEST_MISSING = "CURRENT_REQUEST_MISSING"
    CURRENT_INVENTORY_MISSING = "CURRENT_INVENTORY_MISSING"
    READ_ONLY_VIOLATION = "READ_ONLY_VIOLATION"
    SNAPSHOT_DRIFT = "SNAPSHOT_DRIFT"
    ZERO_WRITE_VIOLATION = "ZERO_WRITE_VIOLATION"


class ReferenceQueryError(RuntimeError):
    """One stable reference-query rejection."""

    def __init__(self, reason: ReferenceQueryReason, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


def _fail(reason: ReferenceQueryReason, detail: str) -> ReferenceQueryError:
    return ReferenceQueryError(reason, detail)


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise _fail(
            ReferenceQueryReason.STORE_UNAVAILABLE,
            f"{field}: invalid closed identifier",
        )
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise _fail(
            ReferenceQueryReason.STORE_UNAVAILABLE,
            f"{field}: invalid sha256 digest",
        )
    return value


def _row_wire(row: sqlite3.Row, fields: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    return {wire_name: row[column_name] for column_name, wire_name in fields}


@dataclass(frozen=True, slots=True)
class ReferenceRawQueryRead:
    """Canonical before/after rows from one SQLite read transaction."""

    store_instance_id: str
    vm_id: str
    before_bytes: bytes
    after_bytes: bytes
    total_changes_before: int
    total_changes_after: int

    def __post_init__(self) -> None:
        _require_id(self.store_instance_id, "store_instance_id")
        _require_id(self.vm_id, "vm_id")
        before = load_canonical_json(self.before_bytes)
        after = load_canonical_json(self.after_bytes)
        if before != after:
            raise _fail(
                ReferenceQueryReason.SNAPSHOT_DRIFT,
                "before and after rows differ inside one read transaction",
            )
        if self.total_changes_before != 0 or self.total_changes_after != 0:
            raise _fail(
                ReferenceQueryReason.ZERO_WRITE_VIOLATION,
                "a fresh mode=ro query connection reported SQLite changes",
            )

    @property
    def before(self) -> dict[str, object]:
        value = load_canonical_json(self.before_bytes)
        assert isinstance(value, dict)
        return value

    @property
    def after(self) -> dict[str, object]:
        value = load_canonical_json(self.after_bytes)
        assert isinstance(value, dict)
        return value

    @property
    def state_digest(self) -> str:
        return sha256_digest(self.before_bytes)


class ReferenceSqliteSnapshotReader:
    """Open a fresh absolute-file ``mode=ro`` connection for every query."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        transaction_hook: Callable[[str, sqlite3.Connection], None] | None = None,
        statement_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._database_path = self._validate_database_path(database_path)
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 1
        ):
            raise ValueError("busy_timeout_ms must be a positive integer")
        self._busy_timeout_ms = busy_timeout_ms
        self._transaction_hook = transaction_hook
        self._statement_hook = statement_hook

    @staticmethod
    def _validate_database_path(database_path: str | Path) -> Path:
        raw = str(database_path)
        if raw == ":memory:" or raw.lower().startswith("file:"):
            raise _fail(
                ReferenceQueryReason.STORE_NOT_READABLE,
                "memory and caller-supplied URI databases are forbidden",
            )
        path = Path(database_path)
        if not path.is_absolute():
            raise _fail(
                ReferenceQueryReason.STORE_NOT_READABLE,
                "database path must be absolute",
            )
        if not path.exists() or path.is_symlink() or not path.is_file():
            raise _fail(
                ReferenceQueryReason.STORE_NOT_READABLE,
                "database path must be an existing non-symlink regular file",
            )
        return path.resolve()

    @property
    def database_path(self) -> Path:
        return self._database_path

    def _open(self) -> sqlite3.Connection:
        uri = self._database_path.as_uri() + "?mode=ro"
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self._busy_timeout_ms / 1_000,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA query_only = ON")
            if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise _fail(
                    ReferenceQueryReason.READ_ONLY_VIOLATION,
                    "SQLite query_only is not ON",
                )
            if self._statement_hook is not None:
                connection.set_trace_callback(self._statement_hook)
            return connection
        except ReferenceQueryError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()
            raise _fail(
                ReferenceQueryReason.STORE_UNAVAILABLE,
                f"cannot open mode=ro SQLite connection: {error}",
            ) from error

    def read(self, vm_id: str) -> ReferenceRawQueryRead:
        vm_id = _require_id(vm_id, "vm_id")
        connection = self._open()
        in_transaction = False
        try:
            total_changes_before = connection.total_changes
            connection.execute("BEGIN")
            in_transaction = True
            before = self._read_state(connection, vm_id)
            if self._transaction_hook is not None:
                self._transaction_hook(AFTER_QUERY_BEFORE_STATE, connection)
            after = self._read_state(connection, vm_id)
            total_changes_after = connection.total_changes
            if self._transaction_hook is not None:
                self._transaction_hook(BEFORE_QUERY_READ_COMMIT, connection)
            if total_changes_before != 0 or total_changes_after != 0:
                raise _fail(
                    ReferenceQueryReason.ZERO_WRITE_VIOLATION,
                    "mode=ro query connection reported non-zero total_changes",
                )
            before_bytes = canonical_json_bytes(before)
            after_bytes = canonical_json_bytes(after)
            if before_bytes != after_bytes:
                raise _fail(
                    ReferenceQueryReason.SNAPSHOT_DRIFT,
                    "SQLite read transaction mixed two repository snapshots",
                )
            connection.execute("COMMIT")
            in_transaction = False
            return ReferenceRawQueryRead(
                store_instance_id=str(before["storeInstanceId"]),
                vm_id=vm_id,
                before_bytes=before_bytes,
                after_bytes=after_bytes,
                total_changes_before=total_changes_before,
                total_changes_after=total_changes_after,
            )
        except ReferenceQueryError:
            if in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as error:
            if in_transaction:
                connection.execute("ROLLBACK")
            text = str(error).lower()
            reason = (
                ReferenceQueryReason.READ_ONLY_VIOLATION
                if "readonly" in text or "query_only" in text
                else ReferenceQueryReason.STORE_UNAVAILABLE
            )
            raise _fail(reason, f"SQLite read transaction failed: {error}") from error
        finally:
            connection.close()

    @staticmethod
    def _read_state(
        connection: sqlite3.Connection,
        vm_id: str,
    ) -> dict[str, object]:
        metadata_rows = connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ).fetchall()
        metadata = {row["key"]: row["value"] for row in metadata_rows}
        store_instance_id = metadata.get("store_instance_id")
        if (
            not isinstance(store_instance_id, str)
            or _ID_RE.fullmatch(store_instance_id) is None
        ):
            raise _fail(
                ReferenceQueryReason.STORE_IDENTITY_MISSING,
                "metadata.store_instance_id is absent or invalid",
            )
        if (
            metadata.get("schema_version") != str(SCHEMA_VERSION)
            or metadata.get("evidence_boundary") != EVIDENCE_BOUNDARY
        ):
            raise _fail(
                ReferenceQueryReason.STORE_UNAVAILABLE,
                "reference store schema/evidence metadata mismatch",
            )

        commit_clock_row = connection.execute(
            "SELECT last_sequence FROM commit_clock WHERE singleton = 1"
        ).fetchone()
        if commit_clock_row is None:
            raise _fail(
                ReferenceQueryReason.STORE_UNAVAILABLE,
                "repository commit clock is absent",
            )
        commit_clock = commit_clock_row["last_sequence"]
        if (
            not isinstance(commit_clock, int)
            or isinstance(commit_clock, bool)
            or commit_clock < 0
        ):
            raise _fail(
                ReferenceQueryReason.STORE_UNAVAILABLE,
                "repository commit clock is invalid",
            )

        controller = connection.execute(
            """
            SELECT controller_generation, authority_lease_id, resource_version,
                   expires_at, blob_sha256
            FROM controller_current
            WHERE singleton = 1
            """
        ).fetchone()
        if controller is None:
            raise _fail(
                ReferenceQueryReason.STORE_UNAVAILABLE,
                "controller current row is absent",
            )
        request = connection.execute(
            """
            SELECT vm_id, request_version, request_hash, resource_version,
                   blob_sha256
            FROM current_requests
            WHERE vm_id = ?
            """,
            (vm_id,),
        ).fetchone()
        if request is None:
            raise _fail(
                ReferenceQueryReason.CURRENT_REQUEST_MISSING,
                f"current request is absent for {vm_id}",
            )
        inventory = connection.execute(
            """
            SELECT kind, authority_id, sequence, artifact_digest,
                   resource_version, valid_until, blob_sha256
            FROM current_artifacts
            WHERE kind = 'INVENTORY'
            """
        ).fetchone()
        if inventory is None:
            raise _fail(
                ReferenceQueryReason.CURRENT_INVENTORY_MISSING,
                "current inventory authority row is absent",
            )
        availability = connection.execute(
            """
            SELECT authority_id, resource_version
            FROM global_availability
            WHERE singleton = 1
            """
        ).fetchone()
        if availability is None:
            raise _fail(
                ReferenceQueryReason.AVAILABILITY_FENCE_MISSING,
                "global availability authority row is absent",
            )
        observer = connection.execute(
            """
            SELECT observer_instance_id, restart_generation, resource_version,
                   host_id, host_epoch, kernel_boot_id, agent_generation,
                   journal_epoch, counter_epoch, reset_observer_id,
                   host_journal_sequence, driver_bind_count, driver_unbind_count,
                   device_reset_count, vfio_exclusive_open_count,
                   qemu_spawn_count,
                   observation_digest
            FROM reference_query_observer
            WHERE singleton = 1
            """
        ).fetchone()
        if observer is None:
            raise _fail(
                ReferenceQueryReason.QUERY_OBSERVER_MISSING,
                "reference query observer row is absent",
            )

        repository_head = connection.execute(
            """
            SELECT commit_sequence, repository_transaction_id, command_hash,
                   result_hash, committed_at
            FROM repository_commits
            ORDER BY commit_sequence DESC
            LIMIT 1
            """
        ).fetchone()
        artifacts = connection.execute(
            """
            SELECT kind, authority_id, sequence, artifact_digest,
                   resource_version, valid_until, blob_sha256
            FROM current_artifacts
            ORDER BY kind
            """
        ).fetchall()
        members = connection.execute(
            """
            SELECT device_id, generation, resource_version, evidence_blob_hash
            FROM availability_members
            ORDER BY device_id
            """
        ).fetchall()
        bundle_members = connection.execute(
            """
            SELECT bundle_id, device_id
            FROM bundle_members
            ORDER BY bundle_id, device_id
            """
        ).fetchall()
        quarantines = connection.execute(
            """
            SELECT conflict_key, quarantine_digest, resource_version
            FROM quarantines
            ORDER BY conflict_key
            """
        ).fetchall()
        operation_leases = connection.execute(
            """
            SELECT operation_lease_id, lease_type, state, scope_hash, run_id,
                   host_epoch, run_generation, holder_controller_generation,
                   resource_version, admission_binding_hash, valid_until
            FROM operation_leases
            ORDER BY operation_lease_id
            """
        ).fetchall()
        bundle_claims = connection.execute(
            """
            SELECT bundle_id, lease_id, operation_lease_id, run_id, state,
                   resource_version
            FROM bundle_claims
            ORDER BY bundle_id
            """
        ).fetchall()
        assignment_runs = connection.execute(
            """
            SELECT run_id, vm_id, state, operation_lease_id,
                   admission_binding_hash, controller_generation,
                   resource_version
            FROM assignment_runs
            ORDER BY run_id
            """
        ).fetchall()
        member_claims = connection.execute(
            """
            SELECT member_id, operation_lease_id, run_id, generation
            FROM member_claims
            ORDER BY member_id
            """
        ).fetchall()

        _require_digest(observer["observation_digest"], "observation_digest")
        return {
            "subjectType": "REFERENCE_QUERY_REPOSITORY_STATE",
            "schemaVersion": 1,
            "storeInstanceId": store_instance_id,
            "repositoryCommitClock": commit_clock,
            "repositoryCommitHead": (
                None
                if repository_head is None
                else _row_wire(
                    repository_head,
                    (
                        ("commit_sequence", "commitSequence"),
                        ("repository_transaction_id", "repositoryTransactionId"),
                        ("command_hash", "commandHash"),
                        ("result_hash", "resultHash"),
                        ("committed_at", "committedAt"),
                    ),
                )
            ),
            "controllerCurrent": _row_wire(
                controller,
                (
                    ("controller_generation", "controllerGeneration"),
                    ("authority_lease_id", "authorityLeaseId"),
                    ("resource_version", "resourceVersion"),
                    ("expires_at", "expiresAt"),
                    ("blob_sha256", "blobSha256"),
                ),
            ),
            "requestCurrent": _row_wire(
                request,
                (
                    ("vm_id", "vmId"),
                    ("request_version", "requestVersion"),
                    ("request_hash", "requestHash"),
                    ("resource_version", "resourceVersion"),
                    ("blob_sha256", "blobSha256"),
                ),
            ),
            "inventoryCurrent": _row_wire(
                inventory,
                (
                    ("kind", "kind"),
                    ("authority_id", "authorityId"),
                    ("sequence", "sequence"),
                    ("artifact_digest", "artifactDigest"),
                    ("resource_version", "resourceVersion"),
                    ("valid_until", "validUntil"),
                    ("blob_sha256", "blobSha256"),
                ),
            ),
            "currentArtifacts": [
                _row_wire(
                    row,
                    (
                        ("kind", "kind"),
                        ("authority_id", "authorityId"),
                        ("sequence", "sequence"),
                        ("artifact_digest", "artifactDigest"),
                        ("resource_version", "resourceVersion"),
                        ("valid_until", "validUntil"),
                        ("blob_sha256", "blobSha256"),
                    ),
                )
                for row in artifacts
            ],
            "availabilityAuthority": _row_wire(
                availability,
                (
                    ("authority_id", "authorityId"),
                    ("resource_version", "resourceVersion"),
                ),
            ),
            "availabilityMembers": [
                _row_wire(
                    row,
                    (
                        ("device_id", "deviceId"),
                        ("generation", "generation"),
                        ("resource_version", "resourceVersion"),
                        ("evidence_blob_hash", "evidenceBlobHash"),
                    ),
                )
                for row in members
            ],
            "bundleMembers": [
                _row_wire(
                    row,
                    (
                        ("bundle_id", "bundleId"),
                        ("device_id", "deviceId"),
                    ),
                )
                for row in bundle_members
            ],
            "quarantines": [
                _row_wire(
                    row,
                    (
                        ("conflict_key", "conflictKey"),
                        ("quarantine_digest", "quarantineDigest"),
                        ("resource_version", "resourceVersion"),
                    ),
                )
                for row in quarantines
            ],
            "operationLeases": [
                _row_wire(
                    row,
                    (
                        ("operation_lease_id", "operationLeaseId"),
                        ("lease_type", "leaseType"),
                        ("state", "state"),
                        ("scope_hash", "scopeHash"),
                        ("run_id", "runId"),
                        ("host_epoch", "hostEpoch"),
                        ("run_generation", "runGeneration"),
                        (
                            "holder_controller_generation",
                            "holderControllerGeneration",
                        ),
                        ("resource_version", "resourceVersion"),
                        ("admission_binding_hash", "admissionBindingHash"),
                        ("valid_until", "validUntil"),
                    ),
                )
                for row in operation_leases
            ],
            "bundleClaims": [
                _row_wire(
                    row,
                    (
                        ("bundle_id", "bundleId"),
                        ("lease_id", "leaseId"),
                        ("operation_lease_id", "operationLeaseId"),
                        ("run_id", "runId"),
                        ("state", "state"),
                        ("resource_version", "resourceVersion"),
                    ),
                )
                for row in bundle_claims
            ],
            "assignmentRuns": [
                _row_wire(
                    row,
                    (
                        ("run_id", "runId"),
                        ("vm_id", "vmId"),
                        ("state", "state"),
                        ("operation_lease_id", "operationLeaseId"),
                        ("admission_binding_hash", "admissionBindingHash"),
                        ("controller_generation", "controllerGeneration"),
                        ("resource_version", "resourceVersion"),
                    ),
                )
                for row in assignment_runs
            ],
            "memberClaims": [
                _row_wire(
                    row,
                    (
                        ("member_id", "memberId"),
                        ("operation_lease_id", "operationLeaseId"),
                        ("run_id", "runId"),
                        ("generation", "generation"),
                    ),
                )
                for row in member_claims
            ],
            "observer": _row_wire(
                observer,
                (
                    ("observer_instance_id", "observerInstanceId"),
                    ("restart_generation", "restartGeneration"),
                    ("resource_version", "resourceVersion"),
                    ("host_id", "hostId"),
                    ("host_epoch", "hostEpoch"),
                    ("kernel_boot_id", "kernelBootId"),
                    ("agent_generation", "agentGeneration"),
                    ("journal_epoch", "journalEpoch"),
                    ("counter_epoch", "counterEpoch"),
                    ("reset_observer_id", "resetObserverId"),
                    ("host_journal_sequence", "hostJournalSequence"),
                    ("driver_bind_count", "driverBindCount"),
                    ("driver_unbind_count", "driverUnbindCount"),
                    ("device_reset_count", "deviceResetCount"),
                    ("vfio_exclusive_open_count", "vfioExclusiveOpenCount"),
                    ("qemu_spawn_count", "qemuSpawnCount"),
                    ("observation_digest", "observationDigest"),
                ),
            ),
        }


@dataclass(frozen=True, slots=True)
class ReferenceDeterministicQueryOutput:
    """Exact ``output_OP_QUERY_DIRECTPATH`` canonical bytes."""

    _canonical_bytes: bytes

    @classmethod
    def create(
        cls,
        *,
        capability_status: Mapping[str, object],
        bundle_summaries: Sequence[Mapping[str, object]],
        lease_summaries: Sequence[Mapping[str, object]],
        reasons: Sequence[Mapping[str, object]],
        evidence_refs: Sequence[Mapping[str, object]],
        query_state_hash: str,
    ) -> "ReferenceDeterministicQueryOutput":
        try:
            _require_digest(query_state_hash, "query_state_hash")
        except ReferenceQueryError as error:
            raise ContractViolation(error.detail) from error
        status = dict(capability_status)
        bundles = [dict(item) for item in bundle_summaries]
        leases = [dict(item) for item in lease_summaries]
        reason_values = [dict(item) for item in reasons]
        evidence = [dict(item) for item in evidence_refs]
        capability_decision_hash = sha256_digest(
            b"QMAN-DIRECTPATH/QUERY-CAPABILITY-DECISION/V1"
            + b"\x00"
            + canonical_json_bytes(
                {
                    "capabilityStatus": status,
                    "reasons": reason_values,
                }
            )
        )
        semantic_dependency_hash = sha256_digest(
            b"QMAN-DIRECTPATH/QUERY-SEMANTIC-DEPENDENCIES/V1"
            + b"\x00"
            + canonical_json_bytes(
                {
                    "bundleSummaries": bundles,
                    "leaseSummaries": leases,
                    "evidenceRefs": evidence,
                }
            )
        )
        return cls.from_wire(
            {
                "capabilityStatus": status,
                "bundleSummaries": bundles,
                "leaseSummaries": leases,
                "reasons": reason_values,
                "evidenceRefs": evidence,
                "capabilityDecisionHash": capability_decision_hash,
                "semanticDependencyHash": semantic_dependency_hash,
                "queryStateHash": query_state_hash,
            }
        )

    def to_wire(self) -> dict[str, object]:
        value = load_canonical_json(self._canonical_bytes)
        assert isinstance(value, dict)
        return value

    def to_canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def canonical_bytes_sha256(self) -> str:
        return sha256_digest(self.to_canonical_bytes())

    @property
    def capability_decision_hash(self) -> str:
        return str(self.to_wire()["capabilityDecisionHash"])

    @property
    def semantic_dependency_hash(self) -> str:
        return str(self.to_wire()["semanticDependencyHash"])

    @property
    def query_state_hash(self) -> str:
        return str(self.to_wire()["queryStateHash"])

    @classmethod
    def from_wire(
        cls,
        value: object,
    ) -> "ReferenceDeterministicQueryOutput":
        if not isinstance(value, Mapping):
            raise ContractViolation("query output: expected an object")
        required = {
            "capabilityStatus",
            "bundleSummaries",
            "leaseSummaries",
            "reasons",
            "evidenceRefs",
            "capabilityDecisionHash",
            "semanticDependencyHash",
            "queryStateHash",
        }
        if set(value) != required:
            raise ContractViolation(
                "query output: closed fields mismatch; "
                f"missing={sorted(required - set(value))}, "
                f"extra={sorted(set(value) - required)}"
            )
        for field in (
            "bundleSummaries",
            "leaseSummaries",
            "reasons",
            "evidenceRefs",
        ):
            items = value[field]
            if not isinstance(items, list):
                raise ContractViolation(f"query output.{field}: expected an array")
            expected = sorted(items, key=canonical_json_bytes)
            if items != expected:
                raise ContractViolation(
                    f"query output.{field}: noncanonical array order"
                )
            encoded = [canonical_json_bytes(item) for item in items]
            if len(encoded) != len(set(encoded)):
                raise ContractViolation(f"query output.{field}: duplicate item")
        status = value["capabilityStatus"]
        if not isinstance(status, Mapping):
            raise ContractViolation("query output.capabilityStatus: expected object")
        for field in (
            "capabilityDecisionHash",
            "semanticDependencyHash",
            "queryStateHash",
        ):
            try:
                _require_digest(value[field], f"query output.{field}")
            except ReferenceQueryError as error:
                raise ContractViolation(error.detail) from error
        expected_capability = sha256_digest(
            b"QMAN-DIRECTPATH/QUERY-CAPABILITY-DECISION/V1"
            + b"\x00"
            + canonical_json_bytes(
                {
                    "capabilityStatus": status,
                    "reasons": value["reasons"],
                }
            )
        )
        expected_semantic = sha256_digest(
            b"QMAN-DIRECTPATH/QUERY-SEMANTIC-DEPENDENCIES/V1"
            + b"\x00"
            + canonical_json_bytes(
                {
                    "bundleSummaries": value["bundleSummaries"],
                    "leaseSummaries": value["leaseSummaries"],
                    "evidenceRefs": value["evidenceRefs"],
                }
            )
        )
        if value["capabilityDecisionHash"] != expected_capability:
            raise ContractViolation(
                "query output.capabilityDecisionHash: domain hash mismatch"
            )
        if value["semanticDependencyHash"] != expected_semantic:
            raise ContractViolation(
                "query output.semanticDependencyHash: domain hash mismatch"
            )
        return cls(
            canonical_json_bytes(dict(value)),
        )

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | bytearray | memoryview,
    ) -> "ReferenceDeterministicQueryOutput":
        return cls.from_wire(load_canonical_json(data))


__all__ = [
    "AFTER_QUERY_BEFORE_STATE",
    "BEFORE_QUERY_READ_COMMIT",
    "REFERENCE_QUERY_EVIDENCE_BOUNDARY",
    "ReferenceQueryError",
    "ReferenceQueryReason",
    "ReferenceDeterministicQueryOutput",
    "ReferenceRawQueryRead",
    "ReferenceSqliteSnapshotReader",
]
