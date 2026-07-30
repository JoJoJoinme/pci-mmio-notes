"""Pinned SQLite schema for the reference Static admission component."""

from __future__ import annotations


SCHEMA_VERSION = 1

DDL_STATEMENTS = (
    """
    CREATE TABLE metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE immutable_blobs (
        blob_sha256 TEXT PRIMARY KEY,
        schema_ref TEXT NOT NULL,
        canonical_bytes BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TRIGGER immutable_blobs_no_update
        BEFORE UPDATE ON immutable_blobs
        BEGIN
            SELECT RAISE(ABORT, 'immutable_blobs are append-only');
        END
    """,
    """
    CREATE TRIGGER immutable_blobs_no_delete
        BEFORE DELETE ON immutable_blobs
        BEGIN
            SELECT RAISE(ABORT, 'immutable_blobs are append-only');
        END
    """,
    """
    CREATE TABLE controller_current (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        controller_generation INTEGER NOT NULL CHECK (controller_generation > 0),
        authority_lease_id TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        expires_at TEXT NOT NULL,
        blob_sha256 TEXT NOT NULL REFERENCES immutable_blobs(blob_sha256)
    )
    """,
    """
    CREATE TABLE current_requests (
        vm_id TEXT PRIMARY KEY,
        request_version INTEGER NOT NULL CHECK (request_version > 0),
        request_hash TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        blob_sha256 TEXT NOT NULL REFERENCES immutable_blobs(blob_sha256)
    )
    """,
    """
    CREATE TABLE current_artifacts (
        kind TEXT PRIMARY KEY
            CHECK (kind IN ('POLICY', 'TRUST', 'CATALOG', 'INVENTORY')),
        authority_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence > 0),
        artifact_digest TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        valid_until TEXT NOT NULL,
        blob_sha256 TEXT NOT NULL REFERENCES immutable_blobs(blob_sha256)
    )
    """,
    """
    CREATE TABLE global_availability (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        authority_id TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0)
    )
    """,
    """
    CREATE TABLE availability_members (
        device_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL CHECK (generation > 0),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        evidence_blob_hash TEXT NOT NULL
            REFERENCES immutable_blobs(blob_sha256)
    )
    """,
    """
    CREATE TABLE bundle_members (
        bundle_id TEXT NOT NULL,
        device_id TEXT NOT NULL REFERENCES availability_members(device_id),
        PRIMARY KEY (bundle_id, device_id)
    )
    """,
    """
    CREATE TABLE quarantines (
        conflict_key TEXT PRIMARY KEY,
        quarantine_digest TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0)
    )
    """,
    """
    CREATE TABLE operation_leases (
        operation_lease_id TEXT PRIMARY KEY,
        lease_type TEXT NOT NULL CHECK (lease_type = 'ASSIGNMENT_PREPARE'),
        state TEXT NOT NULL CHECK (state = 'ACTIVE'),
        scope_hash TEXT NOT NULL,
        run_id TEXT NOT NULL,
        host_epoch INTEGER NOT NULL CHECK (host_epoch > 0),
        run_generation INTEGER NOT NULL CHECK (run_generation > 0),
        holder_controller_generation INTEGER NOT NULL
            CHECK (holder_controller_generation > 0),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        lease_spec_hash TEXT NOT NULL,
        admission_binding_hash TEXT NOT NULL UNIQUE,
        valid_until TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (admission_binding_hash)
            REFERENCES admission_bindings(binding_hash)
            DEFERRABLE INITIALLY DEFERRED
    )
    """,
    """
    CREATE UNIQUE INDEX one_active_operation_per_scope
        ON operation_leases(scope_hash)
        WHERE state = 'ACTIVE'
    """,
    """
    CREATE UNIQUE INDEX one_active_operation_per_run
        ON operation_leases(run_id)
        WHERE state = 'ACTIVE'
    """,
    """
    CREATE TABLE admission_bindings (
        binding_hash TEXT PRIMARY KEY,
        operation_lease_id TEXT NOT NULL UNIQUE,
        binding_bytes BLOB NOT NULL,
        valid_until TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        FOREIGN KEY (operation_lease_id)
            REFERENCES operation_leases(operation_lease_id)
            DEFERRABLE INITIALLY DEFERRED
    )
    """,
    """
    CREATE TABLE operation_lease_bundles (
        operation_lease_id TEXT NOT NULL
            REFERENCES operation_leases(operation_lease_id),
        bundle_id TEXT NOT NULL,
        PRIMARY KEY (operation_lease_id, bundle_id)
    )
    """,
    """
    CREATE TABLE operation_lease_members (
        operation_lease_id TEXT NOT NULL
            REFERENCES operation_leases(operation_lease_id),
        member_id TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK (generation > 0),
        PRIMARY KEY (operation_lease_id, member_id)
    )
    """,
    """
    CREATE TABLE bundle_claims (
        bundle_id TEXT PRIMARY KEY,
        lease_id TEXT NOT NULL UNIQUE,
        operation_lease_id TEXT NOT NULL UNIQUE
            REFERENCES operation_leases(operation_lease_id),
        run_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state = 'RESERVED'),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0)
    )
    """,
    """
    CREATE TABLE member_claims (
        member_id TEXT PRIMARY KEY,
        operation_lease_id TEXT NOT NULL
            REFERENCES operation_leases(operation_lease_id),
        run_id TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK (generation > 0)
    )
    """,
    """
    CREATE TABLE assignment_runs (
        run_id TEXT PRIMARY KEY,
        vm_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state = 'PREPARING'),
        operation_lease_id TEXT NOT NULL UNIQUE
            REFERENCES operation_leases(operation_lease_id),
        admission_binding_hash TEXT NOT NULL
            REFERENCES admission_bindings(binding_hash),
        controller_generation INTEGER NOT NULL
            CHECK (controller_generation > 0),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0)
    )
    """,
    """
    CREATE UNIQUE INDEX one_preparing_run_per_vm
        ON assignment_runs(vm_id)
        WHERE state = 'PREPARING'
    """,
    """
    CREATE TABLE idempotency_records (
        operation_id TEXT NOT NULL CHECK (operation_id = 'STATIC_ADMISSION'),
        idempotency_scope_hash TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        command_id TEXT NOT NULL,
        command_hash TEXT NOT NULL,
        command_bytes BLOB NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('IN_PROGRESS', 'COMPLETED')),
        result_hash TEXT,
        result_bytes BLOB,
        run_id TEXT NOT NULL,
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        PRIMARY KEY (
            operation_id,
            idempotency_scope_hash,
            idempotency_key
        ),
        CHECK (
            (state = 'IN_PROGRESS' AND result_hash IS NULL AND result_bytes IS NULL)
            OR
            (state = 'COMPLETED' AND result_hash IS NOT NULL AND result_bytes IS NOT NULL)
        ),
        CHECK (
            (state = 'IN_PROGRESS' AND resource_version = 1)
            OR
            (state = 'COMPLETED' AND resource_version = 2)
        )
    )
    """,
    """
    CREATE TABLE audit_events (
        event_id TEXT PRIMARY KEY,
        repository_transaction_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
        payload_hash TEXT NOT NULL,
        prior_event_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (run_id, aggregate_version)
    )
    """,
    """
    CREATE TABLE outbox_events (
        outbox_id TEXT PRIMARY KEY,
        repository_transaction_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
        event_type TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state = 'PENDING'),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        created_at TEXT NOT NULL,
        UNIQUE (run_id, aggregate_version, event_type)
    )
    """,
    """
    CREATE TABLE commit_clock (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
    )
    """,
    """
    CREATE TABLE repository_commits (
        commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
        repository_transaction_id TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        result_hash TEXT NOT NULL UNIQUE,
        committed_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE reference_query_observer (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        observer_instance_id TEXT NOT NULL,
        restart_generation INTEGER NOT NULL CHECK (restart_generation > 0),
        resource_version INTEGER NOT NULL CHECK (resource_version > 0),
        host_id TEXT NOT NULL,
        host_epoch INTEGER NOT NULL CHECK (host_epoch > 0),
        kernel_boot_id TEXT NOT NULL,
        agent_generation INTEGER NOT NULL CHECK (agent_generation > 0),
        journal_epoch INTEGER NOT NULL CHECK (journal_epoch > 0),
        counter_epoch INTEGER NOT NULL CHECK (counter_epoch > 0),
        reset_observer_id TEXT NOT NULL,
        host_journal_sequence INTEGER NOT NULL CHECK (host_journal_sequence >= 0),
        driver_bind_count INTEGER NOT NULL CHECK (driver_bind_count >= 0),
        driver_unbind_count INTEGER NOT NULL CHECK (driver_unbind_count >= 0),
        device_reset_count INTEGER NOT NULL CHECK (device_reset_count >= 0),
        vfio_exclusive_open_count INTEGER NOT NULL
            CHECK (vfio_exclusive_open_count >= 0),
        qemu_spawn_count INTEGER NOT NULL CHECK (qemu_spawn_count >= 0),
        observation_digest TEXT NOT NULL
    )
    """,
)


EXPECTED_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "evidence_boundary",
        "evaluator_premise_identity",
        "evaluator_premise_digest",
        "store_instance_id",
    }
)


__all__ = [
    "DDL_STATEMENTS",
    "EXPECTED_METADATA_KEYS",
    "SCHEMA_VERSION",
]
