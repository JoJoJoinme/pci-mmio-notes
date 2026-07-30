"""Executable SQLite reference store for HostSnapshot publication.

This module intentionally consumes the verified mutation closure produced by
``qman_directpath_core`` instead of reimplementing its verifier.  The SQLite
transaction demonstrates one deterministic component implementation of the
closed mutation set.  It is not a Qman product repository, a signed repository
receipt producer, or crash-durability certification.

V1 intentionally permits one reference-only bootstrap, zero-write
``NO_CHANGE`` evaluations before publication, and at most one terminal
``COMMITTED`` publication whose only later operation is exact replay.
Supporting an arbitrary lifecycle would require retaining and replaying a
stronger verified preimage for every historical commit; this component fails
closed instead of inventing that authority.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hmac
from pathlib import Path
import re
import sqlite3
import threading
from types import MappingProxyType
from typing import Any, Final
import uuid

from qman_directpath_core.publication_mutation import (
    MUTATION_SET_DOMAIN,
    VerifiedHostSnapshotPublicationMutationContext,
    replay_host_snapshot_publication_mutation_closure,
)
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from qman_directpath_core.publication_repository import (
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS,
)

from .publication_sqlite_schema import (
    PUBLICATION_DDL_STATEMENTS,
    PUBLICATION_EXPECTED_COLUMNS,
    PUBLICATION_EXPECTED_METADATA_KEYS,
    PUBLICATION_EXPECTED_TABLES,
    PUBLICATION_EXPECTED_TABLE_SQL,
    PUBLICATION_SQLITE_SCHEMA_IDENTITY,
    PUBLICATION_SQLITE_SCHEMA_VERSION,
    normalize_publication_schema_sql,
)

REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY: Final = (
    "REFERENCE_SQLITE_HOST_SNAPSHOT_PUBLICATION_COMPONENT_ONLY"
)
REFERENCE_ONLY_PUBLICATION_BOOTSTRAP: Final = (
    "REFERENCE_ONLY_HOST_SNAPSHOT_PUBLICATION_BOOTSTRAP"
)
REFERENCE_PUBLICATION_STORE_LIFECYCLE: Final = (
    "REFERENCE_V1_BOOTSTRAP_NO_CHANGE_OR_ONE_TERMINAL_COMMITTED_PUBLICATION"
)
REFERENCE_PUBLICATION_EXECUTION_CONTEXT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/REFERENCE-HOST-SNAPSHOT-PUBLICATION-EXECUTION/V1\x00"
)
AFTER_PUBLICATION_COMMIT_BEFORE_RETURN: Final = "AFTER_PUBLICATION_COMMIT_BEFORE_RETURN"

# Alias the portable repository boundary instead of copying a blocker list that
# could silently drift as that normative component evolves.
REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS: Final = (
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
)

PUBLICATION_WRITE_FAULT_STAGES: Final = (
    "HOST_SNAPSHOT_WRITTEN",
    "DEVICE_RECORDS_WRITTEN",
    "HOST_AUTHORITY_CAS_WRITTEN",
    "AVAILABILITY_AUTHORITY_CAS_WRITTEN",
    "AUDIT_WRITTEN",
    "OUTBOX_WRITTEN",
    "COMMIT_CLOCK_ADVANCED",
    "COMMIT_RECORD_WRITTEN",
    "MATERIALIZATION_CHECKED",
    "FOREIGN_KEY_CHECKED",
    "BEFORE_COMMIT",
)

_TIMESTAMP_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_IDENTIFIER_RE: Final = re.compile(r"^\S(?:.*\S)?$")
_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_AUTHORITY_KINDS: Final = (
    "HOST",
    "AVAILABILITY",
    "CAPABILITY_POLICY",
    "FRESHNESS_POLICY",
)
_FORBIDDEN_COMMIT_COLUMN_TOKENS: Final = (
    "mutation_context_digest",
    "query_digest",
    "nonce",
    "requested_at",
    "receipt_digest",
    "signature",
    "receipt_bytes",
)
_UNSET: Final = object()


class ReferencePublicationRepositoryReason(str, Enum):
    """Stable fail-closed reasons for the publication reference component."""

    INVALID_MUTATION = "INVALID_MUTATION"
    STORE_NOT_DURABLE = "STORE_NOT_DURABLE"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    REPOSITORY_ID_MISMATCH = "REPOSITORY_ID_MISMATCH"
    BOOTSTRAP_REQUIRED = "BOOTSTRAP_REQUIRED"
    STORE_NOT_EMPTY = "STORE_NOT_EMPTY"
    TRANSACTION_ID_COLLISION = "TRANSACTION_ID_COLLISION"
    CURRENT_CHANGED = "CURRENT_CHANGED"
    CLOCK_MISMATCH = "CLOCK_MISMATCH"
    MUTATION_COUNT_MISMATCH = "MUTATION_COUNT_MISMATCH"
    DEPENDENCY_BUSY = "DEPENDENCY_BUSY"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    NO_CHANGE_WRITE = "NO_CHANGE_WRITE"


class ReferencePublicationRepositoryError(RuntimeError):
    """A stable reference-publication repository rejection."""

    def __init__(
        self,
        reason: ReferencePublicationRepositoryReason,
        detail: str,
    ) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}")


def _fail(
    reason: ReferencePublicationRepositoryReason,
    detail: str,
) -> ReferencePublicationRepositoryError:
    return ReferencePublicationRepositoryError(reason, detail)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or _IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise ValueError(f"{field}: expected a non-empty closed identifier")
    return value


def _timestamp_text(value: datetime | str, field: str) -> str:
    if isinstance(value, str):
        if _TIMESTAMP_RE.fullmatch(value) is None:
            raise ValueError(f"{field}: expected exact UTC microsecond timestamp")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as error:
            raise ValueError(f"{field}: invalid UTC timestamp") from error
        return value
    if not isinstance(value, datetime):
        raise TypeError(f"{field}: clock must return datetime or timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field}: clock datetime must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _bytes_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


@dataclass(frozen=True, slots=True)
class _Artifact:
    artifact_bytes: bytes
    artifact_sha256: str
    state: Mapping[str, Any]
    instance_bytes: bytes
    instance_sha256: str


def _artifact(raw: bytes, field: str) -> _Artifact:
    try:
        document = load_canonical_json(raw)
        if not isinstance(document, dict):
            raise ValueError("artifact must be an object")
        if set(document) != {
            "canonicalInstanceBase64",
            "instanceBytesSha256",
            "schemaRef",
            "state",
        }:
            raise ValueError("artifact wrapper fields are not closed")
        state = document["state"]
        if not isinstance(state, dict):
            raise ValueError("artifact state must be an object")
        encoded = document["canonicalInstanceBase64"]
        if not isinstance(encoded, str) or len(encoded) % 4 != 0:
            raise ValueError("artifact state is not exact padded RFC 4648 base64")
        try:
            state_raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("artifact state base64 is invalid") from error
        if (
            not state_raw
            or base64.b64encode(state_raw).decode("ascii") != encoded
            or load_canonical_json(state_raw) != state
            or canonical_json_bytes(state) != state_raw
        ):
            raise ValueError("artifact decoded state differs from exact state bytes")
        instance_sha256 = sha256_digest(state_raw)
        if document["instanceBytesSha256"] != instance_sha256:
            raise ValueError("artifact instance hash differs from exact state bytes")
    except Exception as error:
        raise _fail(
            ReferencePublicationRepositoryReason.INVALID_MUTATION,
            f"{field}: invalid retained artifact: {error}",
        ) from error
    return _Artifact(
        artifact_bytes=raw,
        artifact_sha256=sha256_digest(raw),
        state=_freeze(state),
        instance_bytes=state_raw,
        instance_sha256=instance_sha256,
    )


@dataclass(frozen=True, slots=True)
class _Authority:
    kind: str
    authority_id: str
    resource_version: int
    policy_hash_or_null: str | None
    artifact: _Artifact


def _authority(
    kind: str,
    raw: bytes,
    *,
    field: str,
) -> _Authority:
    artifact = _artifact(raw, field)
    state = artifact.state
    if kind == "HOST":
        authority_id = state["hostId"]
        policy_hash = None
    elif kind == "AVAILABILITY":
        authority_id = state["availabilityAuthorityId"]
        policy_hash = None
    elif kind == "CAPABILITY_POLICY":
        authority_id = state["policyAuthorityId"]
        policy_hash = state["policyDigest"]
    elif kind == "FRESHNESS_POLICY":
        authority_id = state["freshnessPolicyAuthorityId"]
        policy_hash = state["policyDigest"]
    else:  # pragma: no cover - all callers use the frozen tuple
        raise AssertionError(f"unknown authority kind: {kind}")
    try:
        authority_id = _identifier(authority_id, f"{field}.authorityId")
        resource_version = state["resourceVersion"]
        if (
            not isinstance(resource_version, int)
            or isinstance(resource_version, bool)
            or resource_version < 1
        ):
            raise ValueError("resourceVersion must be a positive integer")
        if policy_hash is not None:
            _identifier(policy_hash, f"{field}.policyDigest")
    except (KeyError, TypeError, ValueError) as error:
        raise _fail(
            ReferencePublicationRepositoryReason.INVALID_MUTATION,
            f"{field}: invalid authority state: {error}",
        ) from error
    return _Authority(
        kind=kind,
        authority_id=authority_id,
        resource_version=resource_version,
        policy_hash_or_null=policy_hash,
        artifact=artifact,
    )


@dataclass(frozen=True, slots=True, init=False)
class ReferencePublicationExecution:
    """Factory-only immutable canonical result of one reference execution."""

    repository_id: str
    store_instance_id: str
    transaction_id: str
    command_id: str
    outcome: str
    commit_id_or_null: str | None
    commit_clock_before: int
    commit_clock_after: int
    committed_at_or_null: str | None
    mutation_context_digest: str
    mutation_set_hash_or_null: str | None
    publication_mutation_count: int
    repository_transaction_canonical_sha256: str
    canonical_context: Mapping[str, Any]
    canonical_context_bytes: bytes
    context_digest: str
    product_authorized: bool
    product_evidence_blockers: tuple[str, ...]

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "ReferencePublicationExecution":
        raise TypeError(
            "ReferencePublicationExecution is factory-only; use the repository"
        )

    @classmethod
    def _construct(
        cls,
        **values: Any,
    ) -> "ReferencePublicationExecution":
        instance = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        return instance

    def to_canonical_bytes(self) -> bytes:
        """Return the exact stable in-memory execution context bytes."""

        return self.canonical_context_bytes


def _execution(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
    *,
    store_instance_id: str,
) -> ReferencePublicationExecution:
    transaction = mutation.repository_transaction
    subject = {
        "subjectType": "REFERENCE_HOST_SNAPSHOT_PUBLICATION_EXECUTION",
        "schemaVersion": 1,
        "repositoryId": transaction["repositoryId"],
        "storeInstanceId": store_instance_id,
        "transactionId": transaction["transactionId"],
        "commandId": transaction["commandId"],
        "operationRequestContextDigest": transaction["operationRequestContextDigest"],
        "decisionContextDigest": transaction["decisionContextDigest"],
        "mutationContextDigest": mutation.context_digest,
        "outcome": transaction["outcome"],
        "commitIdOrNull": transaction["commitIdOrNull"],
        "committedAtOrNull": transaction["committedAtOrNull"],
        "commitClockBefore": transaction["commitClockBefore"],
        "commitClockAfter": transaction["commitClockAfter"],
        "repositoryTransactionCanonicalSha256": sha256_digest(
            mutation.repository_transaction_canonical_bytes
        ),
        "mutationsCanonicalSha256": sha256_digest(mutation.mutations_canonical_bytes),
        "mutationSetHashOrNull": mutation.mutation_set_hash_or_null,
        "publicationMutationCount": mutation.publication_mutation_count,
        "deviceRecordSetDigest": mutation.device_record_set_digest,
        "resolvedAuthorityVectorHash": mutation.resolved_authority_vector_hash,
        "commitRecordDigestOrNull": mutation.commit_record_digest_or_null,
        "evidenceBoundary": REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY,
        "productAuthorized": False,
        "productEvidenceBlockers": list(
            REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "contextDigest": None,
    }
    context_digest = sha256_digest(
        REFERENCE_PUBLICATION_EXECUTION_CONTEXT_DOMAIN + canonical_json_bytes(subject)
    )
    subject["contextDigest"] = context_digest
    raw = canonical_json_bytes(subject)
    return ReferencePublicationExecution._construct(
        repository_id=transaction["repositoryId"],
        store_instance_id=store_instance_id,
        transaction_id=transaction["transactionId"],
        command_id=transaction["commandId"],
        outcome=transaction["outcome"],
        commit_id_or_null=transaction["commitIdOrNull"],
        commit_clock_before=transaction["commitClockBefore"],
        commit_clock_after=transaction["commitClockAfter"],
        committed_at_or_null=transaction["committedAtOrNull"],
        mutation_context_digest=mutation.context_digest,
        mutation_set_hash_or_null=mutation.mutation_set_hash_or_null,
        publication_mutation_count=mutation.publication_mutation_count,
        repository_transaction_canonical_sha256=sha256_digest(
            mutation.repository_transaction_canonical_bytes
        ),
        canonical_context=_freeze(subject),
        canonical_context_bytes=raw,
        context_digest=context_digest,
        product_authorized=False,
        product_evidence_blockers=(REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS),
    )


def _replay_mutation(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> VerifiedHostSnapshotPublicationMutationContext:
    if not isinstance(mutation, VerifiedHostSnapshotPublicationMutationContext):
        raise _fail(
            ReferencePublicationRepositoryReason.INVALID_MUTATION,
            ("execute accepts only a VerifiedHostSnapshotPublicationMutationContext"),
        )
    try:
        return replay_host_snapshot_publication_mutation_closure(mutation)
    except Exception as error:
        raise _fail(
            ReferencePublicationRepositoryReason.INVALID_MUTATION,
            f"mutation context replay failed: {error}",
        ) from error


def _before_authorities(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> tuple[_Authority, ...]:
    read_set = mutation.decision.read_set
    return (
        _authority(
            "HOST",
            read_set.host_authority_before_artifact_canonical_bytes,
            field="hostAuthorityBefore",
        ),
        _authority(
            "AVAILABILITY",
            read_set.availability_authority_before_artifact_canonical_bytes,
            field="availabilityAuthorityBefore",
        ),
        _authority(
            "CAPABILITY_POLICY",
            read_set.capability_policy_authority_artifact_canonical_bytes,
            field="capabilityPolicyAuthority",
        ),
        _authority(
            "FRESHNESS_POLICY",
            read_set.freshness_policy_authority_artifact_canonical_bytes,
            field="freshnessPolicyAuthority",
        ),
    )


def _after_authorities(
    mutation: VerifiedHostSnapshotPublicationMutationContext,
) -> tuple[_Authority, ...]:
    if mutation.availability_authority_after_artifact_canonical_bytes_or_null is None:
        raise _fail(
            ReferencePublicationRepositoryReason.INVALID_MUTATION,
            "COMMITTED mutation lacks AvailabilityAuthority after bytes",
        )
    before = _before_authorities(mutation)
    return (
        _authority(
            "HOST",
            mutation.rollback.host_authority_after_artifact_canonical_bytes,
            field="hostAuthorityAfter",
        ),
        _authority(
            "AVAILABILITY",
            mutation.availability_authority_after_artifact_canonical_bytes_or_null,
            field="availabilityAuthorityAfter",
        ),
        before[2],
        before[3],
    )


class SqliteReferenceHostSnapshotPublicationRepository:
    """One-file deterministic HostSnapshot publication reference store."""

    def __init__(
        self,
        database_path: str | Path,
        repository_id: str,
        *,
        clock: Callable[[], datetime | str] | None = None,
        busy_timeout_ms: int = 5_000,
        fault_hook: Callable[[str], None] | None = None,
        statement_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._database_path = self._validate_database_path(database_path)
        try:
            self._repository_id = _identifier(repository_id, "repository_id")
        except ValueError as error:
            raise _fail(
                ReferencePublicationRepositoryReason.REPOSITORY_ID_MISMATCH,
                str(error),
            ) from error
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or busy_timeout_ms < 1
        ):
            raise ValueError("busy_timeout_ms must be a positive integer")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable")
        if statement_hook is not None and not callable(statement_hook):
            raise TypeError("statement_hook must be callable")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._closed = False
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
        except ReferencePublicationRepositoryError:
            self._close_after_failed_init()
            raise
        except sqlite3.Error as error:
            self._close_after_failed_init()
            raise _fail(
                self._sqlite_reason(error),
                f"cannot open publication SQLite store: {error}",
            ) from error
        except Exception:
            self._close_after_failed_init()
            raise

    @staticmethod
    def _validate_database_path(database_path: str | Path) -> Path:
        raw = str(database_path)
        if raw == ":memory:" or raw.lower().startswith("file:"):
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "memory and URI SQLite databases are forbidden",
            )
        path = Path(database_path)
        if not path.is_absolute():
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "database path must be absolute",
            )
        if not path.parent.exists() or not path.parent.is_dir():
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "database parent directory must already exist",
            )
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "database path must name a non-symlink regular file",
            )
        return path

    def _close_after_failed_init(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()

    @staticmethod
    def _sqlite_reason(
        error: sqlite3.Error,
    ) -> ReferencePublicationRepositoryReason:
        if isinstance(error, sqlite3.IntegrityError):
            return ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
        message = str(error).lower()
        if "locked" in message or "busy" in message:
            return ReferencePublicationRepositoryReason.DEPENDENCY_BUSY
        return ReferencePublicationRepositoryReason.STORE_UNAVAILABLE

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        connection = self._connection
        connection.execute("PRAGMA foreign_keys = ON")
        journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA read_uncommitted = OFF")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if str(journal_mode).lower() != "wal":
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "SQLite journal_mode is not WAL",
            )
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "SQLite foreign_keys is not ON",
            )
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "SQLite synchronous is not FULL",
            )
        if connection.execute("PRAGMA read_uncommitted").fetchone()[0] != 0:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "SQLite read_uncommitted is not OFF",
            )
        if connection.execute("PRAGMA busy_timeout").fetchone()[0] < 1:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_DURABLE,
                "SQLite busy_timeout is not positive",
            )

    def _initialize_store(self) -> None:
        connection = self._connection
        began = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            began = True
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
                for statement in PUBLICATION_DDL_STATEMENTS:
                    connection.execute(statement)
                metadata = {
                    "schema_version": str(PUBLICATION_SQLITE_SCHEMA_VERSION),
                    "schema_identity": PUBLICATION_SQLITE_SCHEMA_IDENTITY,
                    "evidence_boundary": REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY,
                    "bootstrap_boundary": REFERENCE_ONLY_PUBLICATION_BOOTSTRAP,
                    "bootstrap_commit_clock": "UNSEEDED",
                    "bootstrap_snapshot_content_hash_or_null": "UNSEEDED",
                    "repository_id": self._repository_id,
                    "store_instance_id": (
                        f"reference-publication-store-{uuid.uuid4().hex}"
                    ),
                }
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    sorted(metadata.items()),
                )
                connection.execute(
                    "INSERT INTO commit_clock(singleton, last_sequence) VALUES (1, 0)"
                )
            self._verify_store_identity()
            self._verify_schema_shape()
            self._verify_repository_chain()
            connection.execute("COMMIT")
            began = False
        except Exception:
            if began and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _verify_schema_shape(self) -> None:
        table_rows = self._connection.execute(
            """
            SELECT name, sql
            FROM sqlite_schema
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()
        actual = {row["name"] for row in table_rows}
        missing = sorted(PUBLICATION_EXPECTED_TABLES - actual)
        unexpected = sorted(
            name
            for name in actual - PUBLICATION_EXPECTED_TABLES
            if not name.startswith("sqlite_")
        )
        if missing or unexpected:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                (
                    "publication schema table set differs; "
                    f"missing={missing}, unexpected={unexpected}"
                ),
            )
        sql_by_table = {
            row["name"]: row["sql"]
            for row in table_rows
            if row["name"] in PUBLICATION_EXPECTED_TABLES
        }
        ddl_drift = {
            table: {
                "expected": expected_sql,
                "actual": (
                    None
                    if sql_by_table.get(table) is None
                    else normalize_publication_schema_sql(sql_by_table[table])
                ),
            }
            for table, expected_sql in PUBLICATION_EXPECTED_TABLE_SQL.items()
            if sql_by_table.get(table) is None
            or normalize_publication_schema_sql(sql_by_table[table]) != expected_sql
        }
        if ddl_drift:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                f"publication frozen table DDL differs: {ddl_drift}",
            )
        forbidden_objects = self._connection.execute(
            """
            SELECT type, name
            FROM sqlite_schema
            WHERE type IN ('trigger', 'view')
               OR (
                    type = 'index'
                    AND name NOT LIKE 'sqlite_autoindex_%'
               )
            ORDER BY type, name
            """
        ).fetchall()
        if forbidden_objects:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                (
                    "publication schema has forbidden trigger/view/explicit "
                    f"index objects: {[(row['type'], row['name']) for row in forbidden_objects]}"
                ),
            )
        columns_by_table = {
            table: {
                row["name"]
                for row in self._connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            for table in PUBLICATION_EXPECTED_TABLES
        }
        column_drift = {
            table: {
                "missing": sorted(expected - columns_by_table[table]),
                "unexpected": sorted(columns_by_table[table] - expected),
            }
            for table, expected in PUBLICATION_EXPECTED_COLUMNS.items()
            if columns_by_table[table] != expected
        }
        if column_drift:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                f"publication schema columns differ: {column_drift}",
            )
        all_columns = {
            column for columns in columns_by_table.values() for column in columns
        }
        forbidden = sorted(
            token for token in _FORBIDDEN_COMMIT_COLUMN_TOKENS if token in all_columns
        )
        if forbidden:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                f"publication commit schema stores forbidden fields: {forbidden}",
            )

    def _verify_store_identity(
        self,
        *,
        allow_bootstrap_transition: bool = False,
    ) -> None:
        rows = self._connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ).fetchall()
        metadata = {row["key"]: row["value"] for row in rows}
        if set(metadata) != PUBLICATION_EXPECTED_METADATA_KEYS:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                "publication metadata keys do not match the frozen set",
            )
        expected = {
            "schema_version": str(PUBLICATION_SQLITE_SCHEMA_VERSION),
            "schema_identity": PUBLICATION_SQLITE_SCHEMA_IDENTITY,
            "evidence_boundary": REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY,
            "bootstrap_boundary": REFERENCE_ONLY_PUBLICATION_BOOTSTRAP,
            "repository_id": self._repository_id,
        }
        for key, value in expected.items():
            if metadata.get(key) != value:
                reason = (
                    ReferencePublicationRepositoryReason.REPOSITORY_ID_MISMATCH
                    if key == "repository_id"
                    else ReferencePublicationRepositoryReason.STORE_UNAVAILABLE
                )
                raise _fail(
                    reason,
                    f"publication metadata {key} mismatch",
                )
        try:
            store_instance_id = _identifier(
                metadata["store_instance_id"],
                "store_instance_id",
            )
            cached_store_instance_id = getattr(
                self,
                "_store_instance_id",
                _UNSET,
            )
            if (
                cached_store_instance_id is not _UNSET
                and cached_store_instance_id != store_instance_id
            ):
                raise ValueError("store_instance_id changed after the store was opened")
            bootstrap_clock = metadata["bootstrap_commit_clock"]
            if bootstrap_clock == "UNSEEDED":
                parsed_clock_or_none = None
            else:
                if (
                    not bootstrap_clock.isascii()
                    or not bootstrap_clock.isdigit()
                    or (len(bootstrap_clock) > 1 and bootstrap_clock[0] == "0")
                ):
                    raise ValueError("bootstrap_commit_clock is not canonical decimal")
                parsed_clock = int(bootstrap_clock)
                if parsed_clock > 9_007_199_254_740_991:
                    raise ValueError(
                        "bootstrap_commit_clock exceeds the safe integer range"
                    )
                parsed_clock_or_none = parsed_clock
            snapshot_marker = metadata["bootstrap_snapshot_content_hash_or_null"]
            if parsed_clock_or_none is None:
                if snapshot_marker != "UNSEEDED":
                    raise ValueError(
                        "unseeded bootstrap clock has a seeded snapshot marker"
                    )
                parsed_snapshot_or_none = None
            else:
                if snapshot_marker == "NULL":
                    parsed_snapshot_or_none = None
                elif _DIGEST_RE.fullmatch(snapshot_marker) is not None:
                    parsed_snapshot_or_none = snapshot_marker
                else:
                    raise ValueError(
                        "bootstrap snapshot marker is not NULL or a digest"
                    )
            cached_clock = getattr(
                self,
                "_bootstrap_commit_clock_or_none",
                _UNSET,
            )
            cached_snapshot = getattr(
                self,
                "_bootstrap_snapshot_content_hash_or_none",
                _UNSET,
            )
            if cached_clock is not _UNSET and (
                cached_clock != parsed_clock_or_none
                or cached_snapshot != parsed_snapshot_or_none
            ):
                if not (
                    allow_bootstrap_transition
                    and cached_clock is None
                    and parsed_clock_or_none is not None
                ):
                    raise ValueError(
                        "bootstrap metadata changed after the store was opened"
                    )
            self._store_instance_id = store_instance_id
            self._bootstrap_commit_clock_or_none = parsed_clock_or_none
            self._bootstrap_snapshot_content_hash_or_none = parsed_snapshot_or_none
        except ValueError as error:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                str(error),
            ) from error

    @property
    def database_path(self) -> Path:
        return self._database_path

    @property
    def repository_id(self) -> str:
        return self._repository_id

    @property
    def store_instance_id(self) -> str:
        with self._lock:
            self._ensure_open()
            return self._store_instance_id

    @property
    def connection_total_changes(self) -> int:
        with self._lock:
            self._ensure_open()
            return self._connection.total_changes

    def reference_only_bootstrap_admin(
        self,
    ) -> "ReferenceOnlyPublicationBootstrapAdmin":
        return ReferenceOnlyPublicationBootstrapAdmin(self)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "SqliteReferenceHostSnapshotPublicationRepository":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
                "publication repository is closed",
            )

    def _rollback_quietly(self) -> None:
        try:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _clock_must_equal(self, expected: object, field: str) -> str:
        try:
            expected_text = _timestamp_text(expected, field)
            actual = _timestamp_text(self._clock(), "clock")
        except (TypeError, ValueError) as error:
            raise _fail(
                ReferencePublicationRepositoryReason.CLOCK_MISMATCH,
                str(error),
            ) from error
        if actual != expected_text:
            raise _fail(
                ReferencePublicationRepositoryReason.CLOCK_MISMATCH,
                f"clock {actual!r} does not equal {field} {expected_text!r}",
            )
        return actual

    def execute_host_snapshot_publication(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> ReferencePublicationExecution:
        """Execute, exactly replay, or read-only validate one mutation closure."""

        mutation = _replay_mutation(mutation)
        transaction = mutation.repository_transaction
        if transaction["repositoryId"] != self._repository_id:
            raise _fail(
                ReferencePublicationRepositoryReason.REPOSITORY_ID_MISMATCH,
                "mutation repositoryId differs from the configured store",
            )
        with self._lock:
            self._ensure_open()
            began = False
            committed = False
            before_total_changes = self._connection.total_changes
            try:
                # Deliberately the first database statement in this operation.
                self._connection.execute("BEGIN IMMEDIATE")
                began = True
                replay_row = self._connection.execute(
                    """
                    SELECT *
                    FROM publication_commits
                    WHERE transaction_id = ?
                    """,
                    (transaction["transactionId"],),
                ).fetchone()
                self._verify_store_identity()
                self._verify_schema_shape()
                durable_commit = self._verify_repository_chain()
                if replay_row is not None:
                    if transaction["outcome"] != "COMMITTED":
                        raise _fail(
                            ReferencePublicationRepositoryReason.TRANSACTION_ID_COLLISION,
                            (
                                "NO_CHANGE transactionId is already bound to "
                                "a durable COMMITTED transaction"
                            ),
                        )
                    self._verify_exact_committed_replay(replay_row, mutation)
                    self._verify_committed_materialization(mutation)
                    self._connection.execute("COMMIT")
                    committed = True
                    if self._connection.total_changes != before_total_changes:
                        raise _fail(
                            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                            "exact replay unexpectedly changed SQLite rows",
                        )
                    return _execution(
                        mutation,
                        store_instance_id=self.store_instance_id,
                    )
                if durable_commit is not None:
                    raise _fail(
                        ReferencePublicationRepositoryReason.TRANSACTION_ID_COLLISION,
                        (
                            "V1 publication store already owns its single "
                            "COMMITTED transactionId"
                        ),
                    )

                self._clock_must_equal(transaction["beganAt"], "beganAt")
                self._verify_bootstrapped()
                self._verify_current_projection(mutation)
                if transaction["outcome"] == "NO_CHANGE":
                    self._verify_no_change(mutation)
                    self._connection.execute("COMMIT")
                    committed = True
                    if self._connection.total_changes != before_total_changes:
                        raise _fail(
                            ReferencePublicationRepositoryReason.NO_CHANGE_WRITE,
                            "NO_CHANGE executed durable DML",
                        )
                    return _execution(
                        mutation,
                        store_instance_id=self.store_instance_id,
                    )
                if transaction["outcome"] != "COMMITTED":
                    raise _fail(
                        ReferencePublicationRepositoryReason.INVALID_MUTATION,
                        f"unsupported transaction outcome {transaction['outcome']!r}",
                    )
                self._write_committed(mutation)
                self._clock_must_equal(
                    transaction["committedAtOrNull"],
                    "committedAt",
                )
                self._fault("BEFORE_COMMIT")
                self._connection.execute("COMMIT")
                committed = True
                result = _execution(
                    mutation,
                    store_instance_id=self.store_instance_id,
                )
                self._fault(AFTER_PUBLICATION_COMMIT_BEFORE_RETURN)
                return result
            except ReferencePublicationRepositoryError:
                if began and not committed:
                    self._rollback_quietly()
                raise
            except sqlite3.IntegrityError as error:
                if began and not committed:
                    self._rollback_quietly()
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"SQLite publication integrity failure: {error}",
                ) from error
            except sqlite3.Error as error:
                if began and not committed:
                    self._rollback_quietly()
                raise _fail(
                    self._sqlite_reason(error),
                    f"SQLite publication transaction failed: {error}",
                ) from error
            except Exception:
                if began and not committed:
                    self._rollback_quietly()
                raise

    def _verify_bootstrapped(self) -> None:
        if self._bootstrap_commit_clock_or_none is None:
            raise _fail(
                ReferencePublicationRepositoryReason.BOOTSTRAP_REQUIRED,
                (
                    "reference store is empty; invoke the explicit "
                    "reference-only bootstrap admin"
                ),
            )
        self._read_exact_authority_rows()

    def _read_exact_authority_rows(self) -> dict[str, sqlite3.Row]:
        rows = self._connection.execute(
            """
            SELECT *
            FROM authority_current
            ORDER BY authority_kind
            """
        ).fetchall()
        kinds = tuple(row["authority_kind"] for row in rows)
        if len(rows) != len(_AUTHORITY_KINDS) or set(kinds) != set(_AUTHORITY_KINDS):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "authority_current must contain exactly the four frozen "
                    f"kinds; actual={kinds}"
                ),
            )
        by_kind = {row["authority_kind"]: row for row in rows}
        for kind in _AUTHORITY_KINDS:
            row = by_kind[kind]
            try:
                expected = _authority(
                    kind,
                    bytes(row["artifact_bytes"]),
                    field=f"storedAuthority.{kind}",
                )
            except (ReferencePublicationRepositoryError, TypeError) as error:
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"{kind} current authority artifact is invalid: {error}",
                ) from error
            if not self._authority_row_matches(row, expected):
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    (
                        f"{kind} current authority row is not self-consistent "
                        "with its retained exact artifact"
                    ),
                )
        return by_kind

    def _verify_repository_chain(self) -> sqlite3.Row | None:
        """Verify the V1 zero-or-one commit chain and global row closure."""

        clock = self._read_commit_clock()
        commit_rows = self._connection.execute(
            """
            SELECT *
            FROM publication_commits
            ORDER BY commit_sequence
            """
        ).fetchall()
        bootstrap_clock = self._bootstrap_commit_clock_or_none
        authority_count = self._connection.execute(
            "SELECT COUNT(*) FROM authority_current"
        ).fetchone()[0]
        if bootstrap_clock is None:
            unseeded_counts = {
                "authority_current": authority_count,
                "host_snapshots": self._connection.execute(
                    "SELECT COUNT(*) FROM host_snapshots"
                ).fetchone()[0],
                "device_records": self._connection.execute(
                    "SELECT COUNT(*) FROM device_records"
                ).fetchone()[0],
                "publication_audit": self._connection.execute(
                    "SELECT COUNT(*) FROM publication_audit"
                ).fetchone()[0],
                "publication_outbox": self._connection.execute(
                    "SELECT COUNT(*) FROM publication_outbox"
                ).fetchone()[0],
                "publication_commits": len(commit_rows),
            }
            if clock != 0 or any(unseeded_counts.values()):
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    (
                        "UNSEEDED publication store has durable rows or a "
                        f"nonzero clock; clock={clock}, counts={unseeded_counts}"
                    ),
                )
            return None

        current_authorities = self._read_exact_authority_rows()
        if len(commit_rows) > 1:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "V1 publication reference store permits at most one "
                    f"COMMITTED row; actual={len(commit_rows)}"
                ),
            )
        if not commit_rows:
            if clock != bootstrap_clock:
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    (
                        "zero-commit store clock must equal its bootstrap "
                        f"clock; clock={clock}, bootstrap={bootstrap_clock}"
                    ),
                )
            self._verify_global_materialized_sets(None)
            return None

        tip = commit_rows[0]
        expected_after = bootstrap_clock + 1
        if (
            tip["commit_sequence"] != expected_after
            or tip["commit_clock_before"] != bootstrap_clock
            or tip["commit_clock_after"] != expected_after
            or clock != expected_after
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "single publication commit must be exactly "
                    f"{bootstrap_clock}->{expected_after} and own the clock tip"
                ),
            )
        self._verify_stored_commit_row(tip)
        self._verify_global_materialized_sets(tip)
        try:
            tip_host = _authority(
                "HOST",
                bytes(tip["host_authority_artifact_bytes"]),
                field="publicationCommitTip.hostAuthorityAfter",
            )
            tip_availability = _authority(
                "AVAILABILITY",
                bytes(tip["availability_authority_artifact_bytes"]),
                field="publicationCommitTip.availabilityAuthorityAfter",
            )
        except (ReferencePublicationRepositoryError, TypeError) as error:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"publication commit tip authority bytes are invalid: {error}",
            ) from error
        for expected in (tip_host, tip_availability):
            if not self._authority_row_matches(
                current_authorities[expected.kind],
                expected,
            ):
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    (
                        f"current {expected.kind} authority differs from "
                        "the retained publication commit tip"
                    ),
                )
        return tip

    def _verify_stored_commit_row(self, row: sqlite3.Row) -> None:
        """Check one durable commit row without relying on a caller context."""

        try:
            transaction_raw = bytes(row["repository_transaction_bytes"])
            if row["repository_transaction_sha256"] != sha256_digest(transaction_raw):
                raise ValueError("repository transaction hash mismatch")
            transaction = load_canonical_json(transaction_raw)
            if not isinstance(transaction, dict):
                raise ValueError("repository transaction is not an object")
            expected_transaction_fields = {
                "transactionId": row["transaction_id"],
                "repositoryId": row["repository_id"],
                "commandId": row["command_id"],
                "outcome": row["outcome"],
                "commitIdOrNull": row["commit_id"],
                "commitClockBefore": row["commit_clock_before"],
                "commitClockAfter": row["commit_clock_after"],
                "committedAtOrNull": row["committed_at"],
            }
            if any(
                transaction.get(key) != value
                for key, value in expected_transaction_fields.items()
            ):
                raise ValueError(
                    "repository transaction indexes differ from exact bytes"
                )
            if (
                row["repository_id"] != self._repository_id
                or row["store_singleton"] != 1
                or row["store_instance_id"] != self._store_instance_id
                or row["outcome"] != "COMMITTED"
            ):
                raise ValueError("commit row repository/outcome is invalid")

            mutations_raw = bytes(row["mutations_bytes"])
            mutations = load_canonical_json(mutations_raw)
            if (
                not isinstance(mutations, list)
                or len(mutations) != row["publication_mutation_count"]
                or row["mutation_set_hash"]
                != sha256_digest(MUTATION_SET_DOMAIN + mutations_raw)
            ):
                raise ValueError("mutation bytes/count/set hash differ")

            artifact_columns = (
                "host_snapshot_artifact",
                "host_authority_artifact",
                "availability_authority_artifact",
                "audit_artifact",
                "outbox_artifact",
                "commit_artifact",
            )
            artifacts = {
                prefix: _artifact(
                    bytes(row[f"{prefix}_bytes"]),
                    f"storedCommit.{prefix}",
                )
                for prefix in artifact_columns
            }
            if any(
                row[f"{prefix}_sha256"] != artifacts[prefix].artifact_sha256
                for prefix in artifact_columns
            ):
                raise ValueError("stored commit artifact hash mismatch")
            if artifacts["availability_authority_artifact"].state[
                "lastMutationDigest"
            ] != row["mutation_set_hash"] or any(
                artifacts[prefix].state["mutationSetHash"] != row["mutation_set_hash"]
                for prefix in (
                    "audit_artifact",
                    "outbox_artifact",
                    "commit_artifact",
                )
            ):
                raise ValueError("stored commit mutation-set projections differ")
            commit_state = artifacts["commit_artifact"].state
            expected_commit_fields = {
                "transactionId": row["transaction_id"],
                "repositoryId": row["repository_id"],
                "commandId": row["command_id"],
                "commitId": row["commit_id"],
                "commitClockBefore": row["commit_clock_before"],
                "commitClockAfter": row["commit_clock_after"],
                "committedAt": row["committed_at"],
                "mutationSetHash": row["mutation_set_hash"],
            }
            if any(
                commit_state.get(key) != value
                for key, value in expected_commit_fields.items()
            ):
                raise ValueError("commit artifact indexes differ from commit row")
        except (
            KeyError,
            ReferencePublicationRepositoryError,
            TypeError,
            ValueError,
        ) as error:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"stored publication commit row is invalid: {error}",
            ) from error

    def _verify_global_materialized_sets(
        self,
        commit_row_or_none: sqlite3.Row | None,
    ) -> None:
        """Close every durable row over bootstrap plus the optional V1 commit."""

        expected_snapshots: dict[str, _Artifact | None] = {}
        bootstrap_snapshot = self._bootstrap_snapshot_content_hash_or_none
        if bootstrap_snapshot is not None:
            expected_snapshots[bootstrap_snapshot] = None

        expected_audit: _Artifact | None = None
        expected_outbox: _Artifact | None = None
        transaction_id_or_none: str | None = None
        committed_hash: str | None = None
        if commit_row_or_none is not None:
            try:
                committed_snapshot = _artifact(
                    bytes(commit_row_or_none["host_snapshot_artifact_bytes"]),
                    "globalClosure.committedHostSnapshot",
                )
                committed_hash = committed_snapshot.state["contentHash"]
                if committed_hash in expected_snapshots:
                    raise ValueError(
                        "committed snapshot duplicates the bootstrap predecessor"
                    )
                if (
                    committed_snapshot.state["previousSnapshotContentHashOrNull"]
                    != bootstrap_snapshot
                ):
                    raise ValueError(
                        "committed snapshot predecessor differs from the "
                        "bootstrap marker"
                    )
                expected_snapshots[committed_hash] = committed_snapshot
                expected_audit = _artifact(
                    bytes(commit_row_or_none["audit_artifact_bytes"]),
                    "globalClosure.audit",
                )
                expected_outbox = _artifact(
                    bytes(commit_row_or_none["outbox_artifact_bytes"]),
                    "globalClosure.outbox",
                )
                transaction_id_or_none = commit_row_or_none["transaction_id"]
            except (
                KeyError,
                ReferencePublicationRepositoryError,
                TypeError,
                ValueError,
            ) as error:
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"global commit materialization preimage is invalid: {error}",
                ) from error

        snapshot_rows = self._connection.execute(
            """
            SELECT *
            FROM host_snapshots
            ORDER BY snapshot_content_hash
            """
        ).fetchall()
        actual_snapshot_hashes = {row["snapshot_content_hash"] for row in snapshot_rows}
        if actual_snapshot_hashes != set(expected_snapshots) or len(
            snapshot_rows
        ) != len(expected_snapshots):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "HostSnapshot rows are not exactly bootstrap predecessor "
                    f"plus optional commit; actual={sorted(actual_snapshot_hashes)}, "
                    f"expected={sorted(expected_snapshots)}"
                ),
            )

        expected_device_keys: set[tuple[str, str]] = set()
        snapshot_states: dict[str, Mapping[str, Any]] = {}
        for row in snapshot_rows:
            snapshot_hash = row["snapshot_content_hash"]
            expected_artifact = expected_snapshots[snapshot_hash]
            try:
                instance_raw = bytes(row["instance_bytes"])
                state = load_canonical_json(instance_raw)
                if not isinstance(state, dict):
                    raise ValueError("snapshot instance is not an object")
                if (
                    row["instance_sha256"] != sha256_digest(instance_raw)
                    or state.get("contentHash") != snapshot_hash
                    or state.get("hostId") != row["host_id"]
                    or state.get("snapshotEpoch") != row["snapshot_epoch"]
                ):
                    raise ValueError("snapshot row indexes/hash differ")
                artifact_raw = (
                    None
                    if row["artifact_bytes"] is None
                    else bytes(row["artifact_bytes"])
                )
                artifact_sha = row["artifact_sha256"]
                if expected_artifact is not None:
                    if (
                        artifact_raw is None
                        or artifact_sha != expected_artifact.artifact_sha256
                        or not _bytes_equal(
                            artifact_raw,
                            expected_artifact.artifact_bytes,
                        )
                        or not _bytes_equal(
                            instance_raw,
                            expected_artifact.instance_bytes,
                        )
                    ):
                        raise ValueError(
                            "committed snapshot differs from retained commit bytes"
                        )
                elif artifact_raw is not None or artifact_sha is not None:
                    raise ValueError(
                        "bootstrap predecessor must retain the exact NULL artifact pair"
                    )
                record_digests = state.get("deviceRecordDigests")
                if (
                    not isinstance(record_digests, list)
                    or len(record_digests) != len(set(record_digests))
                    or any(
                        not isinstance(digest, str)
                        or _DIGEST_RE.fullmatch(digest) is None
                        for digest in record_digests
                    )
                ):
                    raise ValueError(
                        "snapshot deviceRecordDigests is not a unique digest set"
                    )
                snapshot_states[snapshot_hash] = _freeze(state)
                expected_device_keys.update(
                    (snapshot_hash, digest) for digest in record_digests
                )
            except (
                KeyError,
                ReferencePublicationRepositoryError,
                TypeError,
                ValueError,
            ) as error:
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"stored HostSnapshot is invalid: {error}",
                ) from error

        try:
            current_host_row = self._connection.execute(
                """
                SELECT *
                FROM authority_current
                WHERE authority_kind = 'HOST'
                """
            ).fetchone()
            if current_host_row is None:
                raise ValueError("current HostAuthority row is absent")
            current_host = _authority(
                "HOST",
                bytes(current_host_row["artifact_bytes"]),
                field="globalClosure.currentHostAuthority",
            )
            current_host_state = current_host.artifact.state
            if commit_row_or_none is None:
                expected_current_hash = bootstrap_snapshot
            else:
                if committed_hash is None:  # pragma: no cover - set above
                    raise AssertionError("committed snapshot hash is absent")
                expected_current_hash = committed_hash
            if (
                current_host_state["currentSnapshotContentHash"]
                != expected_current_hash
            ):
                raise ValueError(
                    "current HostAuthority pointer differs from the exact "
                    "bootstrap-or-commit tip"
                )
            if expected_current_hash is None:
                if current_host_state["lastSnapshotEpoch"] != 0:
                    raise ValueError(
                        "null current HostAuthority pointer has a nonzero epoch"
                    )
            else:
                current_snapshot_state = snapshot_states[expected_current_hash]
                projection = (
                    ("hostId", "hostId"),
                    ("kernelBootId", "kernelBootId"),
                    ("hostEpoch", "hostEpoch"),
                    ("agentGeneration", "agentGeneration"),
                    ("lastSnapshotEpoch", "snapshotEpoch"),
                    ("resourceVersion", "hostAuthorityResourceVersion"),
                )
                if any(
                    current_host_state[host_field]
                    != current_snapshot_state[snapshot_field]
                    for host_field, snapshot_field in projection
                ):
                    raise ValueError(
                        "current HostAuthority identity/epoch/version differs "
                        "from its pointed HostSnapshot"
                    )
        except (
            KeyError,
            ReferencePublicationRepositoryError,
            TypeError,
            ValueError,
        ) as error:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"current HostAuthority snapshot projection is invalid: {error}",
            ) from error

        device_rows = self._connection.execute(
            """
            SELECT *
            FROM device_records
            ORDER BY snapshot_content_hash, device_record_hash
            """
        ).fetchall()
        actual_device_keys = {
            (row["snapshot_content_hash"], row["device_record_hash"])
            for row in device_rows
        }
        if actual_device_keys != expected_device_keys or len(device_rows) != len(
            expected_device_keys
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "DeviceRecord rows are not the exact complete snapshot "
                    f"membership; actual={sorted(actual_device_keys)}, "
                    f"expected={sorted(expected_device_keys)}"
                ),
            )
        for row in device_rows:
            try:
                raw = bytes(row["canonical_bytes"])
                document = load_canonical_json(raw)
                if not isinstance(document, dict):
                    raise ValueError("DeviceRecord is not an object")
                if (
                    row["canonical_sha256"] != sha256_digest(raw)
                    or document.get("deviceRecordHash") != row["device_record_hash"]
                    or document.get("deviceUid") != row["device_uid"]
                    or document.get("currentBdf") != row["current_bdf"]
                ):
                    raise ValueError("DeviceRecord row indexes/hash differ")
            except (TypeError, ValueError) as error:
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"stored DeviceRecord is invalid: {error}",
                ) from error

        audit_rows = self._connection.execute(
            "SELECT * FROM publication_audit ORDER BY audit_event_id"
        ).fetchall()
        outbox_rows = self._connection.execute(
            "SELECT * FROM publication_outbox ORDER BY outbox_event_id"
        ).fetchall()
        expected_event_count = 0 if commit_row_or_none is None else 1
        if (
            len(audit_rows) != expected_event_count
            or len(outbox_rows) != expected_event_count
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "audit/outbox rows must be exactly one-to-one with the "
                    f"optional commit; audit={len(audit_rows)}, "
                    f"outbox={len(outbox_rows)}, expected={expected_event_count}"
                ),
            )
        if commit_row_or_none is not None:
            assert expected_audit is not None
            assert expected_outbox is not None
            assert transaction_id_or_none is not None
            self._verify_event_materialization(
                table="publication_audit",
                id_column="audit_event_id",
                event_id=expected_audit.state["auditEventId"],
                transaction_id=transaction_id_or_none,
                expected=expected_audit,
            )
            self._verify_event_materialization(
                table="publication_outbox",
                id_column="outbox_event_id",
                event_id=expected_outbox.state["outboxEventId"],
                transaction_id=transaction_id_or_none,
                expected=expected_outbox,
            )
        violations = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"global materialization foreign key check failed: {violations!r}",
            )

    def _read_commit_clock(self) -> int:
        rows = self._connection.execute(
            """
            SELECT singleton, last_sequence
            FROM commit_clock
            ORDER BY singleton
            """
        ).fetchall()
        if (
            len(rows) != 1
            or rows[0]["singleton"] != 1
            or type(rows[0]["last_sequence"]) is not int
            or rows[0]["last_sequence"] < 0
            or rows[0]["last_sequence"] > 9_007_199_254_740_991
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                ("commit_clock must contain exactly one canonical singleton=1 row"),
            )
        return rows[0]["last_sequence"]

    def _verify_current_projection(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        transaction = mutation.repository_transaction
        if self._read_commit_clock() != transaction["commitClockBefore"]:
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                "commit clock differs from commitClockBefore",
            )
        for expected in _before_authorities(mutation):
            row = self._connection.execute(
                """
                SELECT *
                FROM authority_current
                WHERE authority_kind = ?
                """,
                (expected.kind,),
            ).fetchone()
            if row is None or not self._authority_row_matches(row, expected):
                raise _fail(
                    ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                    f"{expected.kind} authority differs from exact read-set bytes",
                )
        self._verify_transaction_cas_indexes(mutation)
        self._verify_predecessor_inventory(mutation)

    @staticmethod
    def _authority_row_matches(row: sqlite3.Row, expected: _Authority) -> bool:
        artifact_bytes = bytes(row["artifact_bytes"])
        instance_bytes = bytes(row["instance_bytes"])
        return (
            row["authority_kind"] == expected.kind
            and row["authority_id"] == expected.authority_id
            and row["resource_version"] == expected.resource_version
            and row["policy_hash_or_null"] == expected.policy_hash_or_null
            and row["artifact_sha256"] == expected.artifact.artifact_sha256
            and row["instance_sha256"] == expected.artifact.instance_sha256
            and sha256_digest(artifact_bytes) == row["artifact_sha256"]
            and sha256_digest(instance_bytes) == row["instance_sha256"]
            and _bytes_equal(artifact_bytes, expected.artifact.artifact_bytes)
            and _bytes_equal(instance_bytes, expected.artifact.instance_bytes)
        )

    @staticmethod
    def _verify_transaction_cas_indexes(
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        transaction = mutation.repository_transaction
        before = {item.kind: item for item in _before_authorities(mutation)}
        expected = {
            "expectedHostAuthorityResourceVersion": before["HOST"].resource_version,
            "expectedAvailabilityAuthorityResourceVersion": before[
                "AVAILABILITY"
            ].resource_version,
            "expectedCapabilityPolicyAuthorityResourceVersion": before[
                "CAPABILITY_POLICY"
            ].resource_version,
            "expectedCapabilityPolicyHash": before[
                "CAPABILITY_POLICY"
            ].policy_hash_or_null,
            "expectedFreshnessPolicyAuthorityResourceVersion": before[
                "FRESHNESS_POLICY"
            ].resource_version,
            "expectedFreshnessPolicyHash": before[
                "FRESHNESS_POLICY"
            ].policy_hash_or_null,
        }
        if any(transaction[key] != value for key, value in expected.items()):
            raise _fail(
                ReferencePublicationRepositoryReason.INVALID_MUTATION,
                "repository transaction CAS indexes differ from read-set bytes",
            )

    def _verify_predecessor_inventory(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        inventory = mutation.decision.read_set.current_inventory_or_null
        host_before = _artifact(
            mutation.decision.read_set.host_authority_before_artifact_canonical_bytes,
            "hostAuthorityBefore",
        ).state
        if inventory is None:
            if host_before["currentSnapshotContentHash"] is not None:
                raise _fail(
                    ReferencePublicationRepositoryReason.INVALID_MUTATION,
                    "absent current inventory has a non-null HostAuthority pointer",
                )
            return
        row = self._connection.execute(
            """
            SELECT *
            FROM host_snapshots
            WHERE snapshot_content_hash = ?
            """,
            (inventory.snapshot_content_hash,),
        ).fetchone()
        if row is None:
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                "predecessor HostSnapshot is absent",
            )
        snapshot_raw = bytes(row["instance_bytes"])
        artifact_raw_or_null = (
            None if row["artifact_bytes"] is None else bytes(row["artifact_bytes"])
        )
        artifact_sha_or_null = row["artifact_sha256"]
        artifact_valid = artifact_raw_or_null is None and artifact_sha_or_null is None
        if artifact_raw_or_null is not None and artifact_sha_or_null is not None:
            try:
                retained_artifact = _artifact(
                    artifact_raw_or_null,
                    "predecessorHostSnapshot",
                )
                artifact_valid = (
                    retained_artifact.artifact_sha256 == artifact_sha_or_null
                    and _bytes_equal(
                        retained_artifact.instance_bytes,
                        snapshot_raw,
                    )
                )
            except ReferencePublicationRepositoryError:
                artifact_valid = False
        if (
            row["host_id"] != inventory.host_id
            or row["snapshot_epoch"] != inventory.snapshot_epoch
            or row["instance_sha256"] != sha256_digest(snapshot_raw)
            or not _bytes_equal(snapshot_raw, inventory.host_snapshot_canonical_bytes)
            or not artifact_valid
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                "predecessor HostSnapshot exact bytes differ",
            )
        rows = self._connection.execute(
            """
            SELECT *
            FROM device_records
            WHERE snapshot_content_hash = ?
            ORDER BY device_record_hash
            """,
            (inventory.snapshot_content_hash,),
        ).fetchall()
        expected_records = {
            record.device_record_hash: record for record in inventory.device_records
        }
        if len(rows) != len(expected_records):
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                "predecessor DeviceRecord complete set differs",
            )
        for record_row in rows:
            record = expected_records.get(record_row["device_record_hash"])
            raw = bytes(record_row["canonical_bytes"])
            if (
                record is None
                or record_row["device_uid"] != record.device_uid
                or record_row["current_bdf"] != record.current_bdf
                or record_row["canonical_sha256"] != sha256_digest(raw)
                or not _bytes_equal(raw, record.canonical_bytes)
            ):
                raise _fail(
                    ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                    "predecessor DeviceRecord exact bytes differ",
                )

    def _verify_no_change(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        transaction = mutation.repository_transaction
        if (
            mutation.publication_mutation_count != 0
            or mutation.mutation_set_hash_or_null is not None
            or mutation.mutations_canonical_bytes != b"[]"
            or transaction["commitIdOrNull"] is not None
            or transaction["committedAtOrNull"] is not None
            or transaction["commitClockAfter"] != transaction["commitClockBefore"]
            or any(
                value is not None
                for value in (
                    mutation.availability_authority_after_artifact_canonical_bytes_or_null,
                    mutation.audit_record_artifact_canonical_bytes_or_null,
                    mutation.outbox_record_artifact_canonical_bytes_or_null,
                    mutation.commit_record_artifact_canonical_bytes_or_null,
                )
            )
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INVALID_MUTATION,
                "NO_CHANGE mutation is not the closed zero-write form",
            )

    @staticmethod
    def _committed_artifacts(
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> tuple[_Artifact, _Artifact, _Artifact, _Artifact, _Artifact, _Artifact]:
        optional = (
            mutation.availability_authority_after_artifact_canonical_bytes_or_null,
            mutation.audit_record_artifact_canonical_bytes_or_null,
            mutation.outbox_record_artifact_canonical_bytes_or_null,
            mutation.commit_record_artifact_canonical_bytes_or_null,
        )
        if any(raw is None for raw in optional):
            raise _fail(
                ReferencePublicationRepositoryReason.INVALID_MUTATION,
                "COMMITTED mutation lacks one or more required artifacts",
            )
        availability_raw, audit_raw, outbox_raw, commit_raw = optional
        assert availability_raw is not None
        assert audit_raw is not None
        assert outbox_raw is not None
        assert commit_raw is not None
        return (
            _artifact(
                mutation.rollback.host_snapshot_after_artifact_canonical_bytes,
                "hostSnapshotAfter",
            ),
            _artifact(
                mutation.rollback.host_authority_after_artifact_canonical_bytes,
                "hostAuthorityAfter",
            ),
            _artifact(availability_raw, "availabilityAuthorityAfter"),
            _artifact(audit_raw, "publicationAudit"),
            _artifact(outbox_raw, "publicationOutbox"),
            _artifact(commit_raw, "repositoryCommit"),
        )

    @staticmethod
    def _verify_logical_mutation_count(
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        device_count = len(mutation.decision.persisted_device_records)
        expected_count = device_count + 6
        counts: dict[str, int] = {}
        for item in mutation.mutations:
            entity = item["entityType"]
            counts[entity] = counts.get(entity, 0) + 1
        expected_counts = {
            "ENTITY-DEVICE-RECORD": device_count,
            "ENTITY-HOST-SNAPSHOT": 1,
            "ENTITY-HOST-AUTHORITY": 1,
            "ENTITY-AVAILABILITY-AUTHORITY": 1,
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT": 1,
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX": 1,
            "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT": 1,
        }
        if (
            mutation.publication_mutation_count != expected_count
            or len(mutation.mutations) != expected_count
            or counts != expected_counts
            or mutation.mutation_set_hash_or_null is None
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.MUTATION_COUNT_MISMATCH,
                "COMMITTED logical mutation set is not exactly N plus six",
            )

    def _write_committed(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        self._verify_logical_mutation_count(mutation)
        transaction = mutation.repository_transaction
        (
            snapshot,
            host_after,
            availability_after,
            audit,
            outbox,
            commit,
        ) = self._committed_artifacts(mutation)
        snapshot_state = snapshot.state
        self._connection.execute(
            """
            INSERT INTO host_snapshots(
                snapshot_content_hash,
                host_id,
                snapshot_epoch,
                artifact_bytes,
                artifact_sha256,
                instance_bytes,
                instance_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_state["contentHash"],
                snapshot_state["hostId"],
                snapshot_state["snapshotEpoch"],
                snapshot.artifact_bytes,
                snapshot.artifact_sha256,
                snapshot.instance_bytes,
                snapshot.instance_sha256,
            ),
        )
        self._fault("HOST_SNAPSHOT_WRITTEN")
        for record in mutation.decision.persisted_device_records:
            self._connection.execute(
                """
                INSERT INTO device_records(
                    snapshot_content_hash,
                    device_record_hash,
                    device_uid,
                    current_bdf,
                    canonical_bytes,
                    canonical_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_state["contentHash"],
                    record.device_record_hash,
                    record.device_uid,
                    record.current_bdf,
                    record.canonical_bytes,
                    sha256_digest(record.canonical_bytes),
                ),
            )
        self._fault("DEVICE_RECORDS_WRITTEN")

        before = {item.kind: item for item in _before_authorities(mutation)}
        after = {item.kind: item for item in _after_authorities(mutation)}
        self._cas_authority(before["HOST"], after["HOST"])
        self._fault("HOST_AUTHORITY_CAS_WRITTEN")
        self._cas_authority(before["AVAILABILITY"], after["AVAILABILITY"])
        self._fault("AVAILABILITY_AUTHORITY_CAS_WRITTEN")
        audit_state = audit.state
        outbox_state = outbox.state
        self._connection.execute(
            """
            INSERT INTO publication_audit(
                audit_event_id,
                transaction_id,
                artifact_bytes,
                artifact_sha256,
                instance_bytes,
                instance_sha256
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                audit_state["auditEventId"],
                transaction["transactionId"],
                audit.artifact_bytes,
                audit.artifact_sha256,
                audit.instance_bytes,
                audit.instance_sha256,
            ),
        )
        self._fault("AUDIT_WRITTEN")
        self._connection.execute(
            """
            INSERT INTO publication_outbox(
                outbox_event_id,
                transaction_id,
                state,
                artifact_bytes,
                artifact_sha256,
                instance_bytes,
                instance_sha256
            ) VALUES (?, ?, 'PENDING', ?, ?, ?, ?)
            """,
            (
                outbox_state["outboxEventId"],
                transaction["transactionId"],
                outbox.artifact_bytes,
                outbox.artifact_sha256,
                outbox.instance_bytes,
                outbox.instance_sha256,
            ),
        )
        self._fault("OUTBOX_WRITTEN")
        cursor = self._connection.execute(
            """
            UPDATE commit_clock
            SET last_sequence = ?
            WHERE singleton = 1 AND last_sequence = ?
            """,
            (
                transaction["commitClockAfter"],
                transaction["commitClockBefore"],
            ),
        )
        if cursor.rowcount != 1:
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                "commit clock CAS failed",
            )
        self._fault("COMMIT_CLOCK_ADVANCED")
        self._insert_commit_row(
            mutation,
            snapshot=snapshot,
            host_after=host_after,
            availability_after=availability_after,
            audit=audit,
            outbox=outbox,
            commit=commit,
        )
        self._fault("COMMIT_RECORD_WRITTEN")
        replay_row = self._connection.execute(
            """
            SELECT *
            FROM publication_commits
            WHERE transaction_id = ?
            """,
            (transaction["transactionId"],),
        ).fetchone()
        if replay_row is None:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                "new publication commit row disappeared before COMMIT",
            )
        self._verify_repository_chain()
        self._verify_exact_committed_replay(replay_row, mutation)
        self._verify_committed_materialization(mutation)
        self._fault("MATERIALIZATION_CHECKED")
        violations = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"foreign key check failed: {violations!r}",
            )
        self._fault("FOREIGN_KEY_CHECKED")

    def _cas_authority(self, before: _Authority, after: _Authority) -> None:
        cursor = self._connection.execute(
            """
            UPDATE authority_current
            SET authority_id = ?,
                resource_version = ?,
                policy_hash_or_null = ?,
                artifact_bytes = ?,
                artifact_sha256 = ?,
                instance_bytes = ?,
                instance_sha256 = ?
            WHERE authority_kind = ?
              AND authority_id = ?
              AND resource_version = ?
              AND policy_hash_or_null IS ?
              AND artifact_sha256 = ?
              AND instance_sha256 = ?
            """,
            (
                after.authority_id,
                after.resource_version,
                after.policy_hash_or_null,
                after.artifact.artifact_bytes,
                after.artifact.artifact_sha256,
                after.artifact.instance_bytes,
                after.artifact.instance_sha256,
                before.kind,
                before.authority_id,
                before.resource_version,
                before.policy_hash_or_null,
                before.artifact.artifact_sha256,
                before.artifact.instance_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise _fail(
                ReferencePublicationRepositoryReason.CURRENT_CHANGED,
                f"{before.kind} authority compare-and-swap failed",
            )

    def _insert_commit_row(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
        *,
        snapshot: _Artifact,
        host_after: _Artifact,
        availability_after: _Artifact,
        audit: _Artifact,
        outbox: _Artifact,
        commit: _Artifact,
    ) -> None:
        transaction = mutation.repository_transaction
        self._connection.execute(
            """
            INSERT INTO publication_commits(
                commit_sequence,
                store_singleton,
                store_instance_id,
                transaction_id,
                repository_id,
                command_id,
                outcome,
                commit_id,
                commit_clock_before,
                commit_clock_after,
                committed_at,
                repository_transaction_bytes,
                repository_transaction_sha256,
                mutations_bytes,
                mutation_set_hash,
                publication_mutation_count,
                host_snapshot_artifact_bytes,
                host_snapshot_artifact_sha256,
                host_authority_artifact_bytes,
                host_authority_artifact_sha256,
                availability_authority_artifact_bytes,
                availability_authority_artifact_sha256,
                audit_artifact_bytes,
                audit_artifact_sha256,
                outbox_artifact_bytes,
                outbox_artifact_sha256,
                commit_artifact_bytes,
                commit_artifact_sha256
            ) VALUES (
                ?, 1, ?, ?, ?, ?, 'COMMITTED', ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                transaction["commitClockAfter"],
                self._store_instance_id,
                transaction["transactionId"],
                transaction["repositoryId"],
                transaction["commandId"],
                transaction["commitIdOrNull"],
                transaction["commitClockBefore"],
                transaction["commitClockAfter"],
                transaction["committedAtOrNull"],
                mutation.repository_transaction_canonical_bytes,
                sha256_digest(mutation.repository_transaction_canonical_bytes),
                mutation.mutations_canonical_bytes,
                mutation.mutation_set_hash_or_null,
                mutation.publication_mutation_count,
                snapshot.artifact_bytes,
                snapshot.artifact_sha256,
                host_after.artifact_bytes,
                host_after.artifact_sha256,
                availability_after.artifact_bytes,
                availability_after.artifact_sha256,
                audit.artifact_bytes,
                audit.artifact_sha256,
                outbox.artifact_bytes,
                outbox.artifact_sha256,
                commit.artifact_bytes,
                commit.artifact_sha256,
            ),
        )

    def _verify_exact_committed_replay(
        self,
        row: sqlite3.Row,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        self._verify_logical_mutation_count(mutation)
        transaction = mutation.repository_transaction
        (
            snapshot,
            host_after,
            availability_after,
            audit,
            outbox,
            commit,
        ) = self._committed_artifacts(mutation)
        expected_scalars = {
            "store_singleton": 1,
            "store_instance_id": self._store_instance_id,
            "transaction_id": transaction["transactionId"],
            "repository_id": transaction["repositoryId"],
            "command_id": transaction["commandId"],
            "outcome": "COMMITTED",
            "commit_id": transaction["commitIdOrNull"],
            "commit_sequence": transaction["commitClockAfter"],
            "commit_clock_before": transaction["commitClockBefore"],
            "commit_clock_after": transaction["commitClockAfter"],
            "committed_at": transaction["committedAtOrNull"],
            "repository_transaction_sha256": sha256_digest(
                mutation.repository_transaction_canonical_bytes
            ),
            "mutation_set_hash": mutation.mutation_set_hash_or_null,
            "publication_mutation_count": mutation.publication_mutation_count,
            "host_snapshot_artifact_sha256": snapshot.artifact_sha256,
            "host_authority_artifact_sha256": host_after.artifact_sha256,
            "availability_authority_artifact_sha256": (
                availability_after.artifact_sha256
            ),
            "audit_artifact_sha256": audit.artifact_sha256,
            "outbox_artifact_sha256": outbox.artifact_sha256,
            "commit_artifact_sha256": commit.artifact_sha256,
        }
        expected_bytes = {
            "repository_transaction_bytes": (
                mutation.repository_transaction_canonical_bytes
            ),
            "mutations_bytes": mutation.mutations_canonical_bytes,
            "host_snapshot_artifact_bytes": snapshot.artifact_bytes,
            "host_authority_artifact_bytes": host_after.artifact_bytes,
            "availability_authority_artifact_bytes": (
                availability_after.artifact_bytes
            ),
            "audit_artifact_bytes": audit.artifact_bytes,
            "outbox_artifact_bytes": outbox.artifact_bytes,
            "commit_artifact_bytes": commit.artifact_bytes,
        }
        mismatch = any(row[key] != value for key, value in expected_scalars.items())
        mismatch = mismatch or any(
            not _bytes_equal(bytes(row[key]), value)
            for key, value in expected_bytes.items()
        )
        mismatch = mismatch or any(
            sha256_digest(bytes(row[key]))
            != row[key.removesuffix("_bytes") + "_sha256"]
            for key in expected_bytes
            if key != "mutations_bytes"
        )
        if mismatch:
            raise _fail(
                ReferencePublicationRepositoryReason.TRANSACTION_ID_COLLISION,
                "transactionId is bound to a different exact publication projection",
            )

    def _verify_committed_materialization(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        """Fail closed if an exact commit row lost any durable materialization."""

        transaction = mutation.repository_transaction
        (
            snapshot,
            _host_after_artifact,
            _availability_after_artifact,
            audit,
            outbox,
            _commit_artifact,
        ) = self._committed_artifacts(mutation)
        snapshot_state = snapshot.state
        snapshot_row = self._connection.execute(
            """
            SELECT *
            FROM host_snapshots
            WHERE snapshot_content_hash = ?
            """,
            (snapshot_state["contentHash"],),
        ).fetchone()
        if (
            snapshot_row is None
            or snapshot_row["host_id"] != snapshot_state["hostId"]
            or snapshot_row["snapshot_epoch"] != snapshot_state["snapshotEpoch"]
            or snapshot_row["artifact_sha256"] != snapshot.artifact_sha256
            or snapshot_row["instance_sha256"] != snapshot.instance_sha256
            or snapshot_row["artifact_bytes"] is None
            or not _bytes_equal(
                bytes(snapshot_row["artifact_bytes"]),
                snapshot.artifact_bytes,
            )
            or not _bytes_equal(
                bytes(snapshot_row["instance_bytes"]),
                snapshot.instance_bytes,
            )
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                "committed HostSnapshot materialization differs from commit bytes",
            )
        device_rows = self._connection.execute(
            """
            SELECT *
            FROM device_records
            WHERE snapshot_content_hash = ?
            ORDER BY device_record_hash
            """,
            (snapshot_state["contentHash"],),
        ).fetchall()
        expected_records = {
            record.device_record_hash: record
            for record in mutation.decision.persisted_device_records
        }
        if len(device_rows) != len(expected_records):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                "committed DeviceRecord complete set is missing or expanded",
            )
        for row in device_rows:
            record = expected_records.get(row["device_record_hash"])
            raw = bytes(row["canonical_bytes"])
            if (
                record is None
                or row["device_uid"] != record.device_uid
                or row["current_bdf"] != record.current_bdf
                or row["canonical_sha256"] != sha256_digest(raw)
                or not _bytes_equal(raw, record.canonical_bytes)
            ):
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    "committed DeviceRecord materialization differs",
                )
        self._verify_event_materialization(
            table="publication_audit",
            id_column="audit_event_id",
            event_id=audit.state["auditEventId"],
            transaction_id=transaction["transactionId"],
            expected=audit,
        )
        self._verify_event_materialization(
            table="publication_outbox",
            id_column="outbox_event_id",
            event_id=outbox.state["outboxEventId"],
            transaction_id=transaction["transactionId"],
            expected=outbox,
        )
        clock = self._read_commit_clock()
        if clock < transaction["commitClockAfter"]:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                "commit clock retreated below the durable replay",
            )
        if clock == transaction["commitClockAfter"]:
            current = {
                row["authority_kind"]: row
                for row in self._connection.execute(
                    """
                    SELECT *
                    FROM authority_current
                    WHERE authority_kind IN (
                        'HOST',
                        'AVAILABILITY',
                        'CAPABILITY_POLICY',
                        'FRESHNESS_POLICY'
                    )
                    """
                ).fetchall()
            }
            after = {item.kind: item for item in _after_authorities(mutation)}
            if any(
                kind not in current
                or not self._authority_row_matches(current[kind], after[kind])
                for kind in _AUTHORITY_KINDS
            ):
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    (
                        "tip replay current four-authority projection "
                        "differ from committed after bytes"
                    ),
                )
        violations = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"durable replay foreign key check failed: {violations!r}",
            )

    def _verify_event_materialization(
        self,
        *,
        table: str,
        id_column: str,
        event_id: str,
        transaction_id: str,
        expected: _Artifact,
    ) -> None:
        row = self._connection.execute(
            f"SELECT * FROM {table} WHERE {id_column} = ?",
            (event_id,),
        ).fetchone()
        if (
            row is None
            or row["transaction_id"] != transaction_id
            or (table == "publication_outbox" and row["state"] != "PENDING")
            or row["artifact_sha256"] != expected.artifact_sha256
            or row["instance_sha256"] != expected.instance_sha256
            or not _bytes_equal(
                bytes(row["artifact_bytes"]),
                expected.artifact_bytes,
            )
            or not _bytes_equal(
                bytes(row["instance_bytes"]),
                expected.instance_bytes,
            )
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                f"{table} durable materialization differs from commit bytes",
            )

    def inspect_reference_publication_state(self) -> Mapping[str, Any]:
        """Return a deeply immutable diagnostic snapshot of reference rows."""

        with self._lock:
            self._ensure_open()
            metadata = {
                row["key"]: row["value"]
                for row in self._connection.execute(
                    "SELECT key, value FROM metadata ORDER BY key"
                ).fetchall()
            }

            def rows(table: str, order_by: str) -> list[dict[str, Any]]:
                return [
                    {key: row[key] for key in row.keys()}
                    for row in self._connection.execute(
                        f"SELECT * FROM {table} ORDER BY {order_by}"
                    ).fetchall()
                ]

            state = {
                "databasePath": str(self._database_path),
                "repositoryId": self._repository_id,
                "storeInstanceId": self._store_instance_id,
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
                    "readUncommitted": self._connection.execute(
                        "PRAGMA read_uncommitted"
                    ).fetchone()[0],
                    "busyTimeout": self._connection.execute(
                        "PRAGMA busy_timeout"
                    ).fetchone()[0],
                },
                "metadata": metadata,
                "commitClock": self._read_commit_clock(),
                "authorityCurrent": rows(
                    "authority_current",
                    "authority_kind",
                ),
                "hostSnapshots": rows(
                    "host_snapshots",
                    "snapshot_content_hash",
                ),
                "deviceRecords": rows(
                    "device_records",
                    "snapshot_content_hash, device_record_hash",
                ),
                "publicationAudit": rows(
                    "publication_audit",
                    "audit_event_id",
                ),
                "publicationOutbox": rows(
                    "publication_outbox",
                    "outbox_event_id",
                ),
                "publicationCommits": rows(
                    "publication_commits",
                    "commit_sequence",
                ),
                "totalChanges": self._connection.total_changes,
            }
            return _freeze(state)


class ReferenceOnlyPublicationBootstrapAdmin:
    """Explicit non-product bootstrap writer for an otherwise empty store."""

    def __init__(
        self,
        repository: SqliteReferenceHostSnapshotPublicationRepository,
    ) -> None:
        if not isinstance(
            repository,
            SqliteReferenceHostSnapshotPublicationRepository,
        ):
            raise TypeError("repository must be a publication reference repository")
        self._repository = repository

    def seed_from_mutation(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        mutation = _replay_mutation(mutation)
        transaction = mutation.repository_transaction
        repository = self._repository
        if transaction["repositoryId"] != repository.repository_id:
            raise _fail(
                ReferencePublicationRepositoryReason.REPOSITORY_ID_MISMATCH,
                "bootstrap mutation repositoryId differs from the store",
            )
        with repository._lock:
            repository._ensure_open()
            began = False
            metadata_transitioned = False
            original_bootstrap_clock = repository._bootstrap_commit_clock_or_none
            original_bootstrap_snapshot = (
                repository._bootstrap_snapshot_content_hash_or_none
            )

            def restore_cached_bootstrap_metadata() -> None:
                if metadata_transitioned:
                    repository._bootstrap_commit_clock_or_none = (
                        original_bootstrap_clock
                    )
                    repository._bootstrap_snapshot_content_hash_or_none = (
                        original_bootstrap_snapshot
                    )

            try:
                # Deliberately the first database statement in bootstrap.
                repository._connection.execute("BEGIN IMMEDIATE")
                began = True
                repository._verify_store_identity()
                repository._verify_schema_shape()
                repository._verify_repository_chain()
                self._require_empty()
                for authority in _before_authorities(mutation):
                    repository._connection.execute(
                        """
                        INSERT INTO authority_current(
                            authority_kind,
                            authority_id,
                            resource_version,
                            policy_hash_or_null,
                            artifact_bytes,
                            artifact_sha256,
                            instance_bytes,
                            instance_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            authority.kind,
                            authority.authority_id,
                            authority.resource_version,
                            authority.policy_hash_or_null,
                            authority.artifact.artifact_bytes,
                            authority.artifact.artifact_sha256,
                            authority.artifact.instance_bytes,
                            authority.artifact.instance_sha256,
                        ),
                    )
                self._seed_predecessor_inventory(mutation)
                cursor = repository._connection.execute(
                    """
                    UPDATE commit_clock
                    SET last_sequence = ?
                    WHERE singleton = 1 AND last_sequence = 0
                    """,
                    (transaction["commitClockBefore"],),
                )
                if cursor.rowcount != 1:
                    raise _fail(
                        ReferencePublicationRepositoryReason.STORE_NOT_EMPTY,
                        "bootstrap commit clock is no longer empty",
                    )
                cursor = repository._connection.execute(
                    """
                    UPDATE metadata
                    SET value = ?
                    WHERE key = 'bootstrap_commit_clock'
                      AND value = 'UNSEEDED'
                    """,
                    (str(transaction["commitClockBefore"]),),
                )
                if cursor.rowcount != 1:
                    raise _fail(
                        ReferencePublicationRepositoryReason.STORE_NOT_EMPTY,
                        "bootstrap clock metadata is already seeded",
                    )
                inventory = mutation.decision.read_set.current_inventory_or_null
                snapshot_marker = (
                    "NULL" if inventory is None else inventory.snapshot_content_hash
                )
                cursor = repository._connection.execute(
                    """
                    UPDATE metadata
                    SET value = ?
                    WHERE key = 'bootstrap_snapshot_content_hash_or_null'
                      AND value = 'UNSEEDED'
                    """,
                    (snapshot_marker,),
                )
                if cursor.rowcount != 1:
                    raise _fail(
                        ReferencePublicationRepositoryReason.STORE_NOT_EMPTY,
                        "bootstrap snapshot metadata is already seeded",
                    )
                repository._verify_store_identity(allow_bootstrap_transition=True)
                metadata_transitioned = True
                repository._verify_schema_shape()
                repository._verify_repository_chain()
                repository._verify_current_projection(mutation)
                self._verify_bootstrap_materialization(mutation)
                violations = repository._connection.execute(
                    "PRAGMA foreign_key_check"
                ).fetchall()
                if violations:
                    raise _fail(
                        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                        f"bootstrap foreign key check failed: {violations!r}",
                    )
                repository._connection.execute("COMMIT")
                began = False
            except ReferencePublicationRepositoryError:
                if began:
                    repository._rollback_quietly()
                restore_cached_bootstrap_metadata()
                raise
            except sqlite3.IntegrityError as error:
                if began:
                    repository._rollback_quietly()
                restore_cached_bootstrap_metadata()
                raise _fail(
                    ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                    f"SQLite bootstrap integrity failure: {error}",
                ) from error
            except sqlite3.Error as error:
                if began:
                    repository._rollback_quietly()
                restore_cached_bootstrap_metadata()
                raise _fail(
                    repository._sqlite_reason(error),
                    f"SQLite publication bootstrap failed: {error}",
                ) from error
            except Exception:
                if began:
                    repository._rollback_quietly()
                restore_cached_bootstrap_metadata()
                raise

    def _require_empty(self) -> None:
        repository = self._repository
        tables = (
            "authority_current",
            "host_snapshots",
            "device_records",
            "publication_audit",
            "publication_outbox",
            "publication_commits",
        )
        counts = {
            table: repository._connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in tables
        }
        if (
            any(counts.values())
            or repository._read_commit_clock() != 0
            or repository._bootstrap_commit_clock_or_none is not None
        ):
            raise _fail(
                ReferencePublicationRepositoryReason.STORE_NOT_EMPTY,
                "reference-only bootstrap requires an empty publication store",
            )

    def _verify_bootstrap_materialization(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        repository = self._repository
        inventory = mutation.decision.read_set.current_inventory_or_null
        expected_snapshot_count = 0 if inventory is None else 1
        expected_device_count = (
            0 if inventory is None else len(inventory.device_records)
        )
        actual = {
            "host_snapshots": repository._connection.execute(
                "SELECT COUNT(*) FROM host_snapshots"
            ).fetchone()[0],
            "device_records": repository._connection.execute(
                "SELECT COUNT(*) FROM device_records"
            ).fetchone()[0],
            "publication_audit": repository._connection.execute(
                "SELECT COUNT(*) FROM publication_audit"
            ).fetchone()[0],
            "publication_outbox": repository._connection.execute(
                "SELECT COUNT(*) FROM publication_outbox"
            ).fetchone()[0],
            "publication_commits": repository._connection.execute(
                "SELECT COUNT(*) FROM publication_commits"
            ).fetchone()[0],
        }
        expected = {
            "host_snapshots": expected_snapshot_count,
            "device_records": expected_device_count,
            "publication_audit": 0,
            "publication_outbox": 0,
            "publication_commits": 0,
        }
        if actual != expected:
            raise _fail(
                ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
                (
                    "bootstrap durable predecessor set differs from the "
                    f"replayed mutation; actual={actual}, expected={expected}"
                ),
            )

    def _seed_predecessor_inventory(
        self,
        mutation: VerifiedHostSnapshotPublicationMutationContext,
    ) -> None:
        inventory = mutation.decision.read_set.current_inventory_or_null
        if inventory is None:
            return
        repository = self._repository
        snapshot_raw = inventory.host_snapshot_canonical_bytes
        snapshot_sha = sha256_digest(snapshot_raw)
        repository._connection.execute(
            """
            INSERT INTO host_snapshots(
                snapshot_content_hash,
                host_id,
                snapshot_epoch,
                artifact_bytes,
                artifact_sha256,
                instance_bytes,
                instance_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inventory.snapshot_content_hash,
                inventory.host_id,
                inventory.snapshot_epoch,
                None,
                None,
                snapshot_raw,
                snapshot_sha,
            ),
        )
        for record in inventory.device_records:
            repository._connection.execute(
                """
                INSERT INTO device_records(
                    snapshot_content_hash,
                    device_record_hash,
                    device_uid,
                    current_bdf,
                    canonical_bytes,
                    canonical_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    inventory.snapshot_content_hash,
                    record.device_record_hash,
                    record.device_uid,
                    record.current_bdf,
                    record.canonical_bytes,
                    sha256_digest(record.canonical_bytes),
                ),
            )


def inspect_reference_publication_state(
    repository: SqliteReferenceHostSnapshotPublicationRepository,
) -> Mapping[str, Any]:
    """Inspect one open store without exposing its writable connection."""

    if not isinstance(
        repository,
        SqliteReferenceHostSnapshotPublicationRepository,
    ):
        raise TypeError("repository must be a publication reference repository")
    return repository.inspect_reference_publication_state()


__all__ = [
    "AFTER_PUBLICATION_COMMIT_BEFORE_RETURN",
    "PUBLICATION_WRITE_FAULT_STAGES",
    "REFERENCE_ONLY_PUBLICATION_BOOTSTRAP",
    "REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY",
    "REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS",
    "REFERENCE_PUBLICATION_STORE_LIFECYCLE",
    "ReferenceOnlyPublicationBootstrapAdmin",
    "ReferencePublicationExecution",
    "ReferencePublicationRepositoryError",
    "ReferencePublicationRepositoryReason",
    "SqliteReferenceHostSnapshotPublicationRepository",
    "inspect_reference_publication_state",
]
