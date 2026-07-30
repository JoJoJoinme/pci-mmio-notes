"""Pinned SQLite schema for the HostSnapshot publication reference store.

The schema is deliberately independent from the Static-admission reference
schema.  It is a component test fixture, not a Qman product migration.
"""

from __future__ import annotations

import re
from types import MappingProxyType


PUBLICATION_SQLITE_SCHEMA_VERSION = 1
PUBLICATION_SQLITE_SCHEMA_IDENTITY = (
    "QMAN_DIRECTPATH_REFERENCE_HOST_SNAPSHOT_PUBLICATION_SQLITE_V1"
)

PUBLICATION_DDL_STATEMENTS = (
    """
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE commit_clock (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
    )
    """,
    """
    CREATE TABLE authority_current (
        authority_kind TEXT PRIMARY KEY CHECK (
            authority_kind IN (
                'HOST',
                'AVAILABILITY',
                'CAPABILITY_POLICY',
                'FRESHNESS_POLICY'
            )
        ),
        authority_id TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        policy_hash_or_null TEXT,
        artifact_bytes BLOB NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        instance_bytes BLOB NOT NULL,
        instance_sha256 TEXT NOT NULL,
        CHECK (
            (
                authority_kind IN ('HOST', 'AVAILABILITY')
                AND policy_hash_or_null IS NULL
            )
            OR
            (
                authority_kind IN (
                    'CAPABILITY_POLICY',
                    'FRESHNESS_POLICY'
                )
                AND policy_hash_or_null IS NOT NULL
            )
        )
    )
    """,
    """
    CREATE TABLE host_snapshots (
        snapshot_content_hash TEXT PRIMARY KEY,
        host_id TEXT NOT NULL,
        snapshot_epoch INTEGER NOT NULL CHECK (snapshot_epoch > 0),
        artifact_bytes BLOB,
        artifact_sha256 TEXT,
        instance_bytes BLOB NOT NULL,
        instance_sha256 TEXT NOT NULL,
        CHECK (
            (artifact_bytes IS NULL AND artifact_sha256 IS NULL)
            OR
            (artifact_bytes IS NOT NULL AND artifact_sha256 IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE device_records (
        snapshot_content_hash TEXT NOT NULL
            REFERENCES host_snapshots(snapshot_content_hash),
        device_record_hash TEXT NOT NULL,
        device_uid TEXT NOT NULL,
        current_bdf TEXT NOT NULL,
        canonical_bytes BLOB NOT NULL,
        canonical_sha256 TEXT NOT NULL,
        PRIMARY KEY (snapshot_content_hash, device_record_hash),
        UNIQUE (snapshot_content_hash, device_uid),
        UNIQUE (snapshot_content_hash, current_bdf)
    )
    """,
    """
    CREATE TABLE publication_audit (
        audit_event_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE,
        artifact_bytes BLOB NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        instance_bytes BLOB NOT NULL,
        instance_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE publication_outbox (
        outbox_event_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK (state = 'PENDING'),
        artifact_bytes BLOB NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        instance_bytes BLOB NOT NULL,
        instance_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE publication_commits (
        commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
        store_singleton INTEGER NOT NULL UNIQUE CHECK (store_singleton = 1),
        store_instance_id TEXT NOT NULL,
        transaction_id TEXT NOT NULL UNIQUE,
        repository_id TEXT NOT NULL,
        command_id TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome = 'COMMITTED'),
        commit_id TEXT NOT NULL UNIQUE,
        commit_clock_before INTEGER NOT NULL CHECK (commit_clock_before >= 0),
        commit_clock_after INTEGER NOT NULL CHECK (
            commit_clock_after = commit_clock_before + 1
        ),
        committed_at TEXT NOT NULL,
        repository_transaction_bytes BLOB NOT NULL,
        repository_transaction_sha256 TEXT NOT NULL,
        mutations_bytes BLOB NOT NULL,
        mutation_set_hash TEXT NOT NULL,
        publication_mutation_count INTEGER NOT NULL
            CHECK (publication_mutation_count >= 7),
        host_snapshot_artifact_bytes BLOB NOT NULL,
        host_snapshot_artifact_sha256 TEXT NOT NULL,
        host_authority_artifact_bytes BLOB NOT NULL,
        host_authority_artifact_sha256 TEXT NOT NULL,
        availability_authority_artifact_bytes BLOB NOT NULL,
        availability_authority_artifact_sha256 TEXT NOT NULL,
        audit_artifact_bytes BLOB NOT NULL,
        audit_artifact_sha256 TEXT NOT NULL,
        outbox_artifact_bytes BLOB NOT NULL,
        outbox_artifact_sha256 TEXT NOT NULL,
        commit_artifact_bytes BLOB NOT NULL,
        commit_artifact_sha256 TEXT NOT NULL
    )
    """,
)

PUBLICATION_EXPECTED_TABLES = frozenset(
    {
        "metadata",
        "commit_clock",
        "authority_current",
        "host_snapshots",
        "device_records",
        "publication_audit",
        "publication_outbox",
        "publication_commits",
    }
)

PUBLICATION_EXPECTED_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "schema_identity",
        "evidence_boundary",
        "bootstrap_boundary",
        "bootstrap_commit_clock",
        "bootstrap_snapshot_content_hash_or_null",
        "repository_id",
        "store_instance_id",
    }
)

PUBLICATION_EXPECTED_COLUMNS = {
    "metadata": frozenset({"key", "value"}),
    "commit_clock": frozenset({"singleton", "last_sequence"}),
    "authority_current": frozenset(
        {
            "authority_kind",
            "authority_id",
            "resource_version",
            "policy_hash_or_null",
            "artifact_bytes",
            "artifact_sha256",
            "instance_bytes",
            "instance_sha256",
        }
    ),
    "host_snapshots": frozenset(
        {
            "snapshot_content_hash",
            "host_id",
            "snapshot_epoch",
            "artifact_bytes",
            "artifact_sha256",
            "instance_bytes",
            "instance_sha256",
        }
    ),
    "device_records": frozenset(
        {
            "snapshot_content_hash",
            "device_record_hash",
            "device_uid",
            "current_bdf",
            "canonical_bytes",
            "canonical_sha256",
        }
    ),
    "publication_audit": frozenset(
        {
            "audit_event_id",
            "transaction_id",
            "artifact_bytes",
            "artifact_sha256",
            "instance_bytes",
            "instance_sha256",
        }
    ),
    "publication_outbox": frozenset(
        {
            "outbox_event_id",
            "transaction_id",
            "state",
            "artifact_bytes",
            "artifact_sha256",
            "instance_bytes",
            "instance_sha256",
        }
    ),
    "publication_commits": frozenset(
        {
            "commit_sequence",
            "store_singleton",
            "store_instance_id",
            "transaction_id",
            "repository_id",
            "command_id",
            "outcome",
            "commit_id",
            "commit_clock_before",
            "commit_clock_after",
            "committed_at",
            "repository_transaction_bytes",
            "repository_transaction_sha256",
            "mutations_bytes",
            "mutation_set_hash",
            "publication_mutation_count",
            "host_snapshot_artifact_bytes",
            "host_snapshot_artifact_sha256",
            "host_authority_artifact_bytes",
            "host_authority_artifact_sha256",
            "availability_authority_artifact_bytes",
            "availability_authority_artifact_sha256",
            "audit_artifact_bytes",
            "audit_artifact_sha256",
            "outbox_artifact_bytes",
            "outbox_artifact_sha256",
            "commit_artifact_bytes",
            "commit_artifact_sha256",
        }
    ),
}

_CREATE_TABLE_NAME_RE = re.compile(
    r"^CREATE\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    flags=re.ASCII,
)
_SQL_WHITESPACE_RE = re.compile(r"\s+")


def normalize_publication_schema_sql(value: str) -> str:
    """Normalize only insignificant SQL whitespace for frozen-DDL comparison."""

    if not isinstance(value, str):
        raise TypeError("SQLite schema SQL must be text")
    normalized = _SQL_WHITESPACE_RE.sub(" ", value.strip())
    if normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    return normalized


def _expected_table_sql() -> MappingProxyType[str, str]:
    expected: dict[str, str] = {}
    for statement in PUBLICATION_DDL_STATEMENTS:
        normalized = normalize_publication_schema_sql(statement)
        match = _CREATE_TABLE_NAME_RE.match(normalized)
        if match is None:
            raise RuntimeError("publication DDL contains a non-CREATE TABLE statement")
        table = match.group(1)
        if table in expected:
            raise RuntimeError(f"duplicate publication DDL table: {table}")
        expected[table] = normalized
    if set(expected) != PUBLICATION_EXPECTED_TABLES:
        raise RuntimeError("publication DDL table set differs from expected tables")
    return MappingProxyType(expected)


PUBLICATION_EXPECTED_TABLE_SQL = _expected_table_sql()


__all__ = [
    "PUBLICATION_DDL_STATEMENTS",
    "PUBLICATION_EXPECTED_COLUMNS",
    "PUBLICATION_EXPECTED_METADATA_KEYS",
    "PUBLICATION_EXPECTED_TABLE_SQL",
    "PUBLICATION_EXPECTED_TABLES",
    "PUBLICATION_SQLITE_SCHEMA_IDENTITY",
    "PUBLICATION_SQLITE_SCHEMA_VERSION",
    "normalize_publication_schema_sql",
]
