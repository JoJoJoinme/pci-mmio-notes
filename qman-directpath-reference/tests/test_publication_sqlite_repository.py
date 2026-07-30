from __future__ import annotations

import base64
from collections.abc import Iterator, Mapping
from contextlib import closing
import copy
import inspect
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
import time

import pytest


# The reference package has a deliberate one-way production dependency on the
# core package.  Tests additionally reuse the expensive, factory-verified core
# fixture without allowing production code to import core test modules.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = REPOSITORY_ROOT / "qman-directpath-core"
for import_root in (REFERENCE_ROOT, CORE_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from qman_directpath_core.canonical import (  # noqa: E402
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.publication_repository import (  # noqa: E402
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS,
)
from qman_directpath_core.publication_mutation import (  # noqa: E402
    AUDIT_RECORD_DOMAIN,
    OUTBOX_RECORD_DOMAIN,
)
from tests.test_publication_capture import thaw  # noqa: E402
from tests.test_publication_repository import RepositoryFixture  # noqa: E402

import qman_directpath_reference as public_api  # noqa: E402
from qman_directpath_reference.publication_repository import (  # noqa: E402
    AFTER_PUBLICATION_COMMIT_BEFORE_RETURN,
    PUBLICATION_WRITE_FAULT_STAGES,
    REFERENCE_ONLY_PUBLICATION_BOOTSTRAP,
    REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY,
    REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS,
    ReferenceOnlyPublicationBootstrapAdmin,
    ReferencePublicationExecution,
    ReferencePublicationRepositoryError,
    ReferencePublicationRepositoryReason,
    SqliteReferenceHostSnapshotPublicationRepository,
    inspect_reference_publication_state,
)
from publication_sqlite_worker import (  # noqa: E402
    build_deterministic_repository_fixture,
    deterministic_fixture_fingerprint,
)


class InjectedPublicationFault(RuntimeError):
    pass


WORKER = Path(__file__).with_name("publication_sqlite_worker.py")


@pytest.fixture(scope="module")
def committed_fixture() -> RepositoryFixture:
    return RepositoryFixture("SUCCESSOR")


@pytest.fixture(scope="module")
def no_change_fixture() -> RepositoryFixture:
    return RepositoryFixture("NO_CHANGE")


@pytest.fixture(scope="module")
def deterministic_committed_fixture() -> RepositoryFixture:
    return build_deterministic_repository_fixture()


@pytest.fixture(scope="module")
def genesis_fixture() -> RepositoryFixture:
    return RepositoryFixture("GENESIS")


def _repository_id(fixture: RepositoryFixture) -> str:
    return str(thaw(fixture.mutation.repository_transaction)["repositoryId"])


def _fixture_clock(fixture: RepositoryFixture):
    transaction = thaw(fixture.mutation.repository_transaction)
    clock_values = [transaction["beganAt"]]
    if transaction["committedAtOrNull"] is not None:
        clock_values.append(transaction["committedAtOrNull"])
    clock_iterator = iter(clock_values)
    final_clock_value = clock_values[-1]
    return lambda: next(clock_iterator, final_clock_value)


def _open_repository(
    path: Path,
    fixture: RepositoryFixture,
    *,
    fault_hook=None,
    statement_hook=None,
) -> SqliteReferenceHostSnapshotPublicationRepository:
    return SqliteReferenceHostSnapshotPublicationRepository(
        path,
        _repository_id(fixture),
        clock=_fixture_clock(fixture),
        fault_hook=fault_hook,
        statement_hook=statement_hook,
    )


def _make_repository(
    path: Path,
    fixture: RepositoryFixture,
    *,
    fault_hook=None,
    statement_hook=None,
) -> SqliteReferenceHostSnapshotPublicationRepository:
    repository = _open_repository(
        path,
        fixture,
        fault_hook=fault_hook,
        statement_hook=statement_hook,
    )
    repository.reference_only_bootstrap_admin().seed_from_mutation(fixture.mutation)
    return repository


def _spawn_worker(
    root: Path,
    *,
    name: str,
    database_path: Path,
    start_path: Path,
    hard_exit_stage: str | None = None,
    hard_exit_code: int = 79,
) -> tuple[subprocess.Popen[str], Path, Path]:
    ready_path = root / f"{name}.ready"
    output_path = root / f"{name}.output.json"
    payload_path = root / f"{name}.payload.json"
    payload_path.write_text(
        json.dumps(
            {
                "databasePath": str(database_path),
                "startPath": str(start_path),
                "readyPath": str(ready_path),
                "outputPath": str(output_path),
                "hardExitStage": hard_exit_stage,
                "hardExitCode": hard_exit_code,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sys.executable, str(WORKER), str(payload_path)],
        cwd=REFERENCE_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, ready_path, output_path


def _wait_for_worker_ready(
    process: subprocess.Popen[str],
    ready_path: Path,
    *,
    timeout: float = 120,
) -> None:
    deadline = time.monotonic() + timeout
    while not ready_path.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "publication worker exited before ready: "
                f"rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(
                "publication worker timed out before ready: "
                f"stdout={stdout!r}, stderr={stderr!r}"
            )
        time.sleep(0.01)


def _normal_worker_result(
    process: subprocess.Popen[str],
    output_path: Path,
) -> dict[str, object]:
    stdout, stderr = process.communicate(timeout=120)
    assert process.returncode == 0, (
        f"worker rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
    )
    return json.loads(output_path.read_text(encoding="utf-8"))


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _database_snapshot(
    path: Path,
) -> dict[str, tuple[tuple[str, ...], tuple[tuple[object, ...], ...]]]:
    """Return a stable, byte-preserving snapshot of every application table."""

    with closing(sqlite3.connect(path)) as connection:
        table_names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_schema
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        snapshot = {}
        for table_name in table_names:
            quoted = _quote_identifier(table_name)
            columns = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")
            )
            rows = tuple(connection.execute(f"SELECT * FROM {quoted}").fetchall())
            snapshot[table_name] = (
                columns,
                tuple(sorted(rows, key=repr)),
            )
        return snapshot


def _database_schema_snapshot(
    path: Path,
) -> tuple[tuple[object, ...], ...]:
    with closing(sqlite3.connect(path)) as connection:
        return tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_autoindex_%'
                ORDER BY type, name
                """
            ).fetchall()
        )


def _rebuild_authority_table_without_checks(
    path: Path,
    *,
    add_fifth_authority: bool,
) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "ALTER TABLE authority_current RENAME TO authority_current_old"
        )
        connection.execute(
            """
            CREATE TABLE authority_current (
                authority_kind TEXT PRIMARY KEY,
                authority_id TEXT NOT NULL,
                resource_version INTEGER NOT NULL,
                policy_hash_or_null TEXT,
                artifact_bytes BLOB NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                instance_bytes BLOB NOT NULL,
                instance_sha256 TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO authority_current
            SELECT *
            FROM authority_current_old
            """
        )
        connection.execute("DROP TABLE authority_current_old")
        if add_fifth_authority:
            artifact = b'{"corrupt":"fifth-authority"}'
            instance = b'{"corrupt":"fifth-authority-instance"}'
            connection.execute(
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
                ) VALUES ('EVIL', 'evil-authority', 1, NULL, ?, ?, ?, ?)
                """,
                (
                    artifact,
                    sha256_digest(artifact),
                    instance,
                    sha256_digest(instance),
                ),
            )
        connection.commit()


def _retained_artifact_bytes(
    *,
    state: Mapping[str, object],
    schema_ref: str,
) -> tuple[bytes, bytes]:
    instance_bytes = canonical_json_bytes(state)
    artifact = {
        "canonicalInstanceBase64": base64.b64encode(instance_bytes).decode("ascii"),
        "instanceBytesSha256": sha256_digest(instance_bytes),
        "schemaRef": schema_ref,
        "state": state,
    }
    return canonical_json_bytes(artifact), instance_bytes


def _domain_self_digest(
    state: Mapping[str, object],
    *,
    field: str,
    domain: bytes,
) -> str:
    projection = copy.deepcopy(dict(state))
    projection[field] = None
    return sha256_digest(domain + canonical_json_bytes(projection))


def _insert_orphan_materialization(
    path: Path,
    fixture: RepositoryFixture,
    orphan_kind: str,
) -> None:
    mutation = fixture.mutation
    with closing(sqlite3.connect(path)) as connection:
        if orphan_kind == "audit":
            wrapper = thaw(mutation.audit_record_artifact_or_null)
            state = copy.deepcopy(wrapper["state"])
            state["auditEventId"] = "audit:" + ("a" * 64)
            state["transactionId"] = "orphan-audit-transaction"
            state["auditDigest"] = _domain_self_digest(
                state,
                field="auditDigest",
                domain=AUDIT_RECORD_DOMAIN,
            )
            artifact, instance = _retained_artifact_bytes(
                state=state,
                schema_ref=wrapper["schemaRef"],
            )
            connection.execute(
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
                    state["auditEventId"],
                    state["transactionId"],
                    artifact,
                    sha256_digest(artifact),
                    instance,
                    sha256_digest(instance),
                ),
            )
        elif orphan_kind == "outbox":
            wrapper = thaw(mutation.outbox_record_artifact_or_null)
            state = copy.deepcopy(wrapper["state"])
            state["outboxEventId"] = "outbox:" + ("b" * 64)
            state["transactionId"] = "orphan-outbox-transaction"
            state["outboxDigest"] = _domain_self_digest(
                state,
                field="outboxDigest",
                domain=OUTBOX_RECORD_DOMAIN,
            )
            artifact, instance = _retained_artifact_bytes(
                state=state,
                schema_ref=wrapper["schemaRef"],
            )
            connection.execute(
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
                    state["outboxEventId"],
                    state["transactionId"],
                    artifact,
                    sha256_digest(artifact),
                    instance,
                    sha256_digest(instance),
                ),
            )
        elif orphan_kind == "snapshot":
            wrapper = thaw(mutation.rollback.host_snapshot_after_artifact)
            state = copy.deepcopy(wrapper["state"])
            state["contentHash"] = "sha256:" + ("c" * 64)
            state["snapshotEpoch"] += 100
            artifact, instance = _retained_artifact_bytes(
                state=state,
                schema_ref=wrapper["schemaRef"],
            )
            connection.execute(
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
                    state["contentHash"],
                    state["hostId"],
                    state["snapshotEpoch"],
                    artifact,
                    sha256_digest(artifact),
                    instance,
                    sha256_digest(instance),
                ),
            )
        elif orphan_kind == "device":
            snapshot_state = thaw(mutation.rollback.host_snapshot_after_artifact)[
                "state"
            ]
            state = copy.deepcopy(
                thaw(mutation.decision.persisted_device_records[0].document)
            )
            state["deviceRecordHash"] = "sha256:" + ("d" * 64)
            state["deviceUid"] = (
                "urn:qman:directpath:device:v1:"
                "550e8400-e29b-41d4-a716-446655440000:"
                "sha256:" + ("d" * 64)
            )
            state["currentBdf"] = "0000:02:00.0"
            canonical = canonical_json_bytes(state)
            connection.execute(
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
                    state["deviceRecordHash"],
                    state["deviceUid"],
                    state["currentBdf"],
                    canonical,
                    sha256_digest(canonical),
                ),
            )
        else:
            raise AssertionError(f"unknown orphan kind: {orphan_kind}")
        connection.commit()


def _replace_current_authorities_from_fixture(
    path: Path,
    fixture: RepositoryFixture,
) -> None:
    read_set = fixture.mutation.decision.read_set
    rows = (
        (
            "HOST",
            read_set.host_authority_before_artifact_canonical_bytes,
            "hostId",
            None,
        ),
        (
            "AVAILABILITY",
            read_set.availability_authority_before_artifact_canonical_bytes,
            "availabilityAuthorityId",
            None,
        ),
        (
            "CAPABILITY_POLICY",
            read_set.capability_policy_authority_artifact_canonical_bytes,
            "policyAuthorityId",
            "policyDigest",
        ),
        (
            "FRESHNESS_POLICY",
            read_set.freshness_policy_authority_artifact_canonical_bytes,
            "freshnessPolicyAuthorityId",
            "policyDigest",
        ),
    )
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DELETE FROM authority_current")
        for kind, artifact, id_field, policy_field in rows:
            wrapper = json.loads(artifact)
            state = wrapper["state"]
            instance = base64.b64decode(
                wrapper["canonicalInstanceBase64"],
                validate=True,
            )
            assert canonical_json_bytes(state) == instance
            connection.execute(
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
                    kind,
                    state[id_field],
                    state["resourceVersion"],
                    None if policy_field is None else state[policy_field],
                    artifact,
                    sha256_digest(artifact),
                    instance,
                    sha256_digest(instance),
                ),
            )
        connection.commit()


def _attempt_second_commit_row(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute("SELECT * FROM publication_commits").fetchone()
        assert row is not None
        columns = tuple(
            item[1]
            for item in connection.execute("PRAGMA table_info(publication_commits)")
        )
        values = dict(zip(columns, row, strict=True))
        values["commit_sequence"] += 1
        values["transaction_id"] += "-fake-second"
        values["command_id"] += "-fake-second"
        values["commit_id"] += "-fake-second"
        values["commit_clock_before"] += 1
        values["commit_clock_after"] += 1
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"""
            INSERT INTO publication_commits(
                {", ".join(_quote_identifier(column) for column in columns)}
            ) VALUES ({placeholders})
            """,
            tuple(values[column] for column in columns),
        )


def _table_rows(
    snapshot: Mapping[
        str,
        tuple[tuple[str, ...], tuple[tuple[object, ...], ...]],
    ],
    table_name: str,
) -> tuple[dict[str, object], ...]:
    columns, rows = snapshot[table_name]
    return tuple(dict(zip(columns, row, strict=True)) for row in rows)


def _single_row(
    snapshot: Mapping[
        str,
        tuple[tuple[str, ...], tuple[tuple[object, ...], ...]],
    ],
    table_name: str,
) -> dict[str, object]:
    rows = _table_rows(snapshot, table_name)
    assert len(rows) == 1
    return rows[0]


def _assert_exact_blob_present(
    snapshot: Mapping[
        str,
        tuple[tuple[str, ...], tuple[tuple[object, ...], ...]],
    ],
    table_name: str,
    expected: bytes,
) -> None:
    rows = _table_rows(snapshot, table_name)
    assert any(
        type(value) is bytes and value == expected
        for row in rows
        for value in row.values()
    ), f"{table_name} does not contain the expected exact canonical bytes"


def _iter_database_material(
    path: Path,
) -> Iterator[tuple[str, bytes]]:
    """Yield schema/column/value bytes with a label for DAG contamination tests."""

    with closing(sqlite3.connect(path)) as connection:
        for name, sql in connection.execute(
            """
            SELECT name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ):
            if sql is not None:
                yield f"schema:{name}", str(sql).encode("utf-8")
        for table_name in (
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_schema
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        ):
            quoted = _quote_identifier(table_name)
            for column in connection.execute(f"PRAGMA table_info({quoted})"):
                yield f"column:{table_name}", str(column[1]).encode("utf-8")
            for row_index, row in enumerate(
                connection.execute(f"SELECT * FROM {quoted}")
            ):
                for column_index, value in enumerate(row):
                    if type(value) is bytes:
                        encoded = value
                    elif value is None:
                        continue
                    else:
                        encoded = str(value).encode("utf-8")
                    yield (
                        f"value:{table_name}:{row_index}:{column_index}",
                        encoded,
                    )


def _update_authority(
    path: Path,
    *,
    authority_kind: str,
    column: str,
    value: object,
) -> None:
    allowed_columns = {
        "resource_version",
        "policy_hash_or_null",
        "artifact_bytes",
        "artifact_sha256",
    }
    if column not in allowed_columns:
        raise AssertionError(f"test attempted an unsafe column update: {column}")
    with closing(sqlite3.connect(path)) as connection:
        result = connection.execute(
            f"""
            UPDATE authority_current
            SET {_quote_identifier(column)} = ?
            WHERE authority_kind = ?
            """,
            (value, authority_kind),
        )
        assert result.rowcount == 1
        connection.commit()


def _insert_collision(
    path: Path,
    fixture: RepositoryFixture,
    collision_kind: str,
) -> None:
    """Insert a coherent-enough conflicting natural key before execution."""

    mutation = fixture.mutation
    transaction = thaw(mutation.repository_transaction)
    if collision_kind == "snapshot":
        state = thaw(mutation.rollback.host_snapshot_after_artifact)["state"]
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
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
                    state["contentHash"],
                    state["hostId"],
                    state["snapshotEpoch"],
                    b'{"collision":"snapshot"}',
                    sha256_digest(b'{"collision":"snapshot"}'),
                    b'{"collision":"snapshot-instance"}',
                    sha256_digest(b'{"collision":"snapshot-instance"}'),
                ),
            )
            connection.commit()
        return

    if collision_kind == "audit":
        state = thaw(mutation.audit_record_artifact_or_null)["state"]
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
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
                    state["auditEventId"],
                    "collision-audit-transaction",
                    b'{"collision":"audit"}',
                    sha256_digest(b'{"collision":"audit"}'),
                    b'{"collision":"audit-instance"}',
                    sha256_digest(b'{"collision":"audit-instance"}'),
                ),
            )
            connection.commit()
        return

    if collision_kind == "outbox":
        state = thaw(mutation.outbox_record_artifact_or_null)["state"]
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
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
                    state["outboxEventId"],
                    "collision-outbox-transaction",
                    b'{"collision":"outbox"}',
                    sha256_digest(b'{"collision":"outbox"}'),
                    b'{"collision":"outbox-instance"}',
                    sha256_digest(b'{"collision":"outbox-instance"}'),
                ),
            )
            connection.commit()
        return

    if collision_kind == "commit":
        with closing(sqlite3.connect(path)) as connection:
            store_instance_id = connection.execute(
                """
                SELECT value
                FROM metadata
                WHERE key = 'store_instance_id'
                """
            ).fetchone()[0]
            connection.execute(
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
                    ?, 1, ?, ?, ?, ?, 'COMMITTED', ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    transaction["commitClockAfter"],
                    store_instance_id,
                    transaction["transactionId"],
                    transaction["repositoryId"],
                    transaction["commandId"],
                    transaction["commitIdOrNull"],
                    transaction["commitClockBefore"],
                    transaction["commitClockAfter"],
                    transaction["committedAtOrNull"],
                    b'{"collision":"transaction"}',
                    sha256_digest(b'{"collision":"transaction"}'),
                    b"[]",
                    mutation.mutation_set_hash_or_null,
                    mutation.publication_mutation_count,
                    b'{"collision":"snapshot"}',
                    sha256_digest(b'{"collision":"snapshot"}'),
                    b'{"collision":"host-authority"}',
                    sha256_digest(b'{"collision":"host-authority"}'),
                    b'{"collision":"availability"}',
                    sha256_digest(b'{"collision":"availability"}'),
                    b'{"collision":"audit"}',
                    sha256_digest(b'{"collision":"audit"}'),
                    b'{"collision":"outbox"}',
                    sha256_digest(b'{"collision":"outbox"}'),
                    b'{"collision":"commit"}',
                    sha256_digest(b'{"collision":"commit"}'),
                ),
            )
            connection.commit()
        return

    if collision_kind == "device":
        # A candidate DeviceRecord cannot be pre-inserted through the normal
        # FK-enabled API before its candidate HostSnapshot parent exists.  To
        # model on-disk corruption without inventing a non-schema uniqueness
        # rule, inject the exact candidate composite key through an independent
        # FK-disabled connection.  The transaction first materializes the
        # missing parent, then deterministically hits this real PK collision.
        snapshot_state = thaw(mutation.rollback.host_snapshot_after_artifact)["state"]
        record = mutation.decision.persisted_device_records[0]
        corrupt_bytes = b'{"collision":"device"}'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
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
                    corrupt_bytes,
                    sha256_digest(corrupt_bytes),
                ),
            )
            connection.commit()
        return

    raise AssertionError(f"unknown collision kind: {collision_kind}")


def test_committed_execution_persists_exact_n_plus_six_and_replays_zero_write(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    repository = _make_repository(
        tmp_path / "committed.db",
        committed_fixture,
    )
    try:
        mutation = committed_fixture.mutation
        device_records = mutation.decision.persisted_device_records
        baseline = _database_snapshot(repository.database_path)

        execution = repository.execute_host_snapshot_publication(mutation)
        committed_state = _database_snapshot(repository.database_path)

        assert execution.outcome == "COMMITTED"
        assert execution.commit_clock_after == execution.commit_clock_before + 1
        assert execution.publication_mutation_count == len(device_records) + 6
        assert execution.publication_mutation_count == (
            mutation.publication_mutation_count
        )
        assert len(_table_rows(committed_state, "host_snapshots")) == (
            len(_table_rows(baseline, "host_snapshots")) + 1
        )
        assert len(_table_rows(committed_state, "device_records")) == (
            len(_table_rows(baseline, "device_records")) + len(device_records)
        )
        assert len(_table_rows(committed_state, "publication_audit")) == 1
        assert len(_table_rows(committed_state, "publication_outbox")) == 1
        assert len(_table_rows(committed_state, "publication_commits")) == 1
        assert _single_row(committed_state, "commit_clock")["last_sequence"] == (
            execution.commit_clock_after
        )

        _assert_exact_blob_present(
            committed_state,
            "host_snapshots",
            mutation.rollback.host_snapshot_after_artifact_canonical_bytes,
        )
        for record in device_records:
            _assert_exact_blob_present(
                committed_state,
                "device_records",
                record.canonical_bytes,
            )
        _assert_exact_blob_present(
            committed_state,
            "authority_current",
            mutation.rollback.host_authority_after_artifact_canonical_bytes,
        )
        assert (
            mutation.availability_authority_after_artifact_canonical_bytes_or_null
            is not None
        )
        _assert_exact_blob_present(
            committed_state,
            "authority_current",
            mutation.availability_authority_after_artifact_canonical_bytes_or_null,
        )
        assert mutation.audit_record_artifact_canonical_bytes_or_null is not None
        _assert_exact_blob_present(
            committed_state,
            "publication_audit",
            mutation.audit_record_artifact_canonical_bytes_or_null,
        )
        assert mutation.outbox_record_artifact_canonical_bytes_or_null is not None
        _assert_exact_blob_present(
            committed_state,
            "publication_outbox",
            mutation.outbox_record_artifact_canonical_bytes_or_null,
        )
        assert mutation.commit_record_artifact_canonical_bytes_or_null is not None
        _assert_exact_blob_present(
            committed_state,
            "publication_commits",
            mutation.commit_record_artifact_canonical_bytes_or_null,
        )

        total_changes_before_replay = repository.connection_total_changes
        replay = repository.execute_host_snapshot_publication(mutation)
        assert replay.canonical_context_bytes == execution.canonical_context_bytes
        assert replay == execution
        assert repository.connection_total_changes == total_changes_before_replay
        assert _database_snapshot(repository.database_path) == committed_state
    finally:
        repository.close()


def test_no_change_is_exact_zero_dml_and_has_no_commit_audit_or_outbox(
    tmp_path: Path,
    no_change_fixture: RepositoryFixture,
) -> None:
    repository = _make_repository(
        tmp_path / "no-change.db",
        no_change_fixture,
    )
    try:
        before = _database_snapshot(repository.database_path)
        changes_before = repository.connection_total_changes
        clock_before = _single_row(before, "commit_clock")["last_sequence"]

        execution = repository.execute_host_snapshot_publication(
            no_change_fixture.mutation
        )

        after = _database_snapshot(repository.database_path)
        assert execution.outcome == "NO_CHANGE"
        assert execution.commit_id_or_null is None
        assert execution.commit_clock_before == clock_before
        assert execution.commit_clock_after == clock_before
        assert execution.publication_mutation_count == 0
        assert repository.connection_total_changes == changes_before
        assert after == before
        assert _table_rows(after, "publication_commits") == ()
        assert _table_rows(after, "publication_audit") == ()
        assert _table_rows(after, "publication_outbox") == ()
    finally:
        repository.close()


def test_terminal_commit_rejects_same_id_verified_no_change_outcome(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    no_change_fixture: RepositoryFixture,
) -> None:
    committed_transaction = thaw(committed_fixture.mutation.repository_transaction)
    no_change_transaction = thaw(no_change_fixture.mutation.repository_transaction)
    assert (
        no_change_transaction["repositoryId"] == (committed_transaction["repositoryId"])
    )
    assert (
        no_change_transaction["transactionId"]
        == (committed_transaction["transactionId"])
    )
    assert committed_transaction["outcome"] == "COMMITTED"
    assert no_change_transaction["outcome"] == "NO_CHANGE"
    assert no_change_fixture.mutation.context_digest != (
        committed_fixture.mutation.context_digest
    )

    repository = _make_repository(
        tmp_path / "terminal-no-change.db",
        committed_fixture,
    )
    try:
        repository.execute_host_snapshot_publication(committed_fixture.mutation)
        baseline = _database_snapshot(repository.database_path)
        changes_before = repository.connection_total_changes

        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(no_change_fixture.mutation)

        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.TRANSACTION_ID_COLLISION
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(repository.database_path) == baseline
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("authority_kind", "column", "replacement"),
    (
        ("HOST", "resource_version", 10_001),
        ("HOST", "artifact_bytes", b'{"coherent":"host-byte-drift"}'),
        ("AVAILABILITY", "resource_version", 10_002),
        (
            "AVAILABILITY",
            "artifact_bytes",
            b'{"coherent":"availability-byte-drift"}',
        ),
        ("CAPABILITY_POLICY", "resource_version", 10_003),
        (
            "CAPABILITY_POLICY",
            "policy_hash_or_null",
            "sha256:" + ("c" * 64),
        ),
        ("FRESHNESS_POLICY", "resource_version", 10_004),
        (
            "FRESHNESS_POLICY",
            "policy_hash_or_null",
            "sha256:" + ("f" * 64),
        ),
    ),
)
def test_each_four_authority_cas_dimension_fails_closed_without_writes(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    authority_kind: str,
    column: str,
    replacement: object,
) -> None:
    repository = _make_repository(
        tmp_path / f"authority-{authority_kind}-{column}.db",
        committed_fixture,
    )
    try:
        _update_authority(
            repository.database_path,
            authority_kind=authority_kind,
            column=column,
            value=replacement,
        )
        if column == "artifact_bytes":
            _update_authority(
                repository.database_path,
                authority_kind=authority_kind,
                column="artifact_sha256",
                value=sha256_digest(replacement),
            )
        baseline = _database_snapshot(repository.database_path)
        changes_before = repository.connection_total_changes

        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)

        assert raised.value.reason in {
            ReferencePublicationRepositoryReason.CURRENT_CHANGED,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert _database_snapshot(repository.database_path) == baseline
        assert repository.connection_total_changes == changes_before
    finally:
        repository.close()


@pytest.mark.parametrize(
    "collision_kind",
    ("snapshot", "device", "audit", "outbox", "commit"),
)
def test_representative_insert_collisions_fail_closed_and_roll_back(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    collision_kind: str,
) -> None:
    repository = _make_repository(
        tmp_path / f"collision-{collision_kind}.db",
        committed_fixture,
    )
    try:
        _insert_collision(
            repository.database_path,
            committed_fixture,
            collision_kind,
        )
        baseline = _database_snapshot(repository.database_path)

        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)

        assert raised.value.reason in {
            ReferencePublicationRepositoryReason.TRANSACTION_ID_COLLISION,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert _database_snapshot(repository.database_path) == baseline
    finally:
        repository.close()


@pytest.mark.parametrize("fault_stage", PUBLICATION_WRITE_FAULT_STAGES)
def test_every_publication_write_fault_stage_fully_rolls_back(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    fault_stage: str,
) -> None:
    def fault(stage: str) -> None:
        if stage == fault_stage:
            raise InjectedPublicationFault(stage)

    repository = _make_repository(
        tmp_path / f"fault-{fault_stage.lower()}.db",
        committed_fixture,
        fault_hook=fault,
    )
    try:
        baseline = _database_snapshot(repository.database_path)
        with pytest.raises(InjectedPublicationFault, match=fault_stage):
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert _database_snapshot(repository.database_path) == baseline
    finally:
        repository.close()


def test_postcommit_failure_reopens_as_exact_zero_write_replay(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    def fault(stage: str) -> None:
        if stage == AFTER_PUBLICATION_COMMIT_BEFORE_RETURN:
            raise InjectedPublicationFault(stage)

    database_path = tmp_path / "postcommit-failure.db"
    repository = _make_repository(
        database_path,
        committed_fixture,
        fault_hook=fault,
    )
    with pytest.raises(
        InjectedPublicationFault,
        match=AFTER_PUBLICATION_COMMIT_BEFORE_RETURN,
    ):
        repository.execute_host_snapshot_publication(committed_fixture.mutation)
    committed_state = _database_snapshot(database_path)
    assert (
        _single_row(committed_state, "commit_clock")["last_sequence"]
        == (committed_fixture.mutation.repository_transaction["commitClockAfter"])
    )
    assert len(_table_rows(committed_state, "publication_commits")) == 1
    repository.close()

    reopened = SqliteReferenceHostSnapshotPublicationRepository(
        database_path,
        _repository_id(committed_fixture),
    )
    try:
        changes_before = reopened.connection_total_changes
        replay = reopened.execute_host_snapshot_publication(committed_fixture.mutation)
        assert replay.outcome == "COMMITTED"
        assert reopened.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == committed_state
    finally:
        reopened.close()


def test_precommit_process_exit_reopens_at_exact_baseline(
    tmp_path: Path,
    deterministic_committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "precommit-process-exit.db"
    repository = _make_repository(
        database_path,
        deterministic_committed_fixture,
    )
    repository.close()
    baseline = _database_snapshot(database_path)
    start_path = tmp_path / "precommit.start"
    process, ready_path, _ = _spawn_worker(
        tmp_path,
        name="precommit",
        database_path=database_path,
        start_path=start_path,
        hard_exit_stage="BEFORE_COMMIT",
        hard_exit_code=71,
    )
    try:
        _wait_for_worker_ready(process, ready_path)
        start_path.write_text("start", encoding="utf-8")
        stdout, stderr = process.communicate(timeout=120)
        assert process.returncode == 71, (
            f"worker rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)

    assert _database_snapshot(database_path) == baseline
    reopened = _open_repository(
        database_path,
        deterministic_committed_fixture,
    )
    try:
        execution = reopened.execute_host_snapshot_publication(
            deterministic_committed_fixture.mutation
        )
        assert execution.outcome == "COMMITTED"
        assert (
            len(
                _table_rows(
                    _database_snapshot(database_path),
                    "publication_commits",
                )
            )
            == 1
        )
    finally:
        reopened.close()


def test_postcommit_process_exit_reopens_as_exact_zero_write_replay(
    tmp_path: Path,
    deterministic_committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "postcommit-process-exit.db"
    repository = _make_repository(
        database_path,
        deterministic_committed_fixture,
    )
    repository.close()
    start_path = tmp_path / "postcommit.start"
    process, ready_path, _ = _spawn_worker(
        tmp_path,
        name="postcommit",
        database_path=database_path,
        start_path=start_path,
        hard_exit_stage=AFTER_PUBLICATION_COMMIT_BEFORE_RETURN,
        hard_exit_code=72,
    )
    try:
        _wait_for_worker_ready(process, ready_path)
        start_path.write_text("start", encoding="utf-8")
        stdout, stderr = process.communicate(timeout=120)
        assert process.returncode == 72, (
            f"worker rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)

    committed_state = _database_snapshot(database_path)
    assert len(_table_rows(committed_state, "publication_commits")) == 1
    reopened = _open_repository(
        database_path,
        deterministic_committed_fixture,
    )
    try:
        changes_before = reopened.connection_total_changes
        replay = reopened.execute_host_snapshot_publication(
            deterministic_committed_fixture.mutation
        )
        assert replay.outcome == "COMMITTED"
        assert reopened.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == committed_state
    finally:
        reopened.close()


def test_two_processes_same_predecessor_serialize_as_one_write_and_exact_replay(
    tmp_path: Path,
    deterministic_committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "two-processes.db"
    repository = _make_repository(
        database_path,
        deterministic_committed_fixture,
    )
    repository.close()
    start_path = tmp_path / "two-processes.start"
    workers = [
        _spawn_worker(
            tmp_path,
            name=f"concurrent-{index}",
            database_path=database_path,
            start_path=start_path,
        )
        for index in range(2)
    ]
    try:
        for process, ready_path, _ in workers:
            _wait_for_worker_ready(process, ready_path)
        start_path.write_text("start", encoding="utf-8")
        results = [
            _normal_worker_result(process, output_path)
            for process, _, output_path in workers
        ]
    finally:
        for process, _, _ in workers:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)

    assert [result["status"] for result in results] == ["OK", "OK"]
    assert {result["executionBytesBase64"] for result in results} == {
        results[0]["executionBytesBase64"],
    }
    assert sorted(result["totalChangesDelta"] for result in results)[0] == 0
    assert sorted(result["totalChangesDelta"] for result in results)[1] > 0
    expected_fingerprint = deterministic_fixture_fingerprint(
        deterministic_committed_fixture
    )
    assert {
        json.dumps(result["fingerprint"], sort_keys=True) for result in results
    } == {json.dumps(expected_fingerprint, sort_keys=True)}

    final_state = _database_snapshot(database_path)
    assert len(_table_rows(final_state, "publication_commits")) == 1
    assert (
        _single_row(final_state, "commit_clock")["last_sequence"]
        == (
            deterministic_committed_fixture.mutation.repository_transaction[
                "commitClockAfter"
            ]
        )
    )


def test_non_factory_context_fails_before_any_database_statement(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    statements: list[str] = []
    repository = _make_repository(
        tmp_path / "non-factory.db",
        committed_fixture,
        statement_hook=statements.append,
    )
    mutation = committed_fixture.mutation
    original = mutation.context_digest
    statements.clear()
    object.__setattr__(
        mutation,
        "context_digest",
        "sha256:" + ("0" * 64),
    )
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(mutation)
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.INVALID_MUTATION
        )
        assert statements == []
    finally:
        object.__setattr__(mutation, "context_digest", original)
        repository.close()


@pytest.mark.parametrize(
    "tamper_kind",
    ("metadata-value", "metadata-key", "missing-table"),
)
def test_metadata_or_table_shape_tamper_fails_closed_without_further_writes(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    tamper_kind: str,
) -> None:
    repository = _make_repository(
        tmp_path / f"store-shape-{tamper_kind}.db",
        committed_fixture,
    )
    try:
        with closing(sqlite3.connect(repository.database_path)) as connection:
            if tamper_kind == "metadata-value":
                connection.execute(
                    """
                    UPDATE metadata
                    SET value = '999'
                    WHERE key = 'schema_version'
                    """
                )
            elif tamper_kind == "metadata-key":
                connection.execute(
                    "DELETE FROM metadata WHERE key = 'evidence_boundary'"
                )
            else:
                connection.execute("DROP TABLE publication_outbox")
            connection.commit()
        baseline = _database_snapshot(repository.database_path)

        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)

        assert raised.value.reason in {
            ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert _database_snapshot(repository.database_path) == baseline
    finally:
        repository.close()


def test_rebuilt_authority_ddl_and_fifth_authority_block_replay_and_reopen(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "authority-ddl-drift.db"
    repository = _make_repository(database_path, committed_fixture)
    repository.execute_host_snapshot_publication(committed_fixture.mutation)
    _rebuild_authority_table_without_checks(
        database_path,
        add_fifth_authority=True,
    )
    baseline = _database_snapshot(database_path)
    baseline_schema = _database_schema_snapshot(database_path)
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as replay_error:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert replay_error.value.reason is (
            ReferencePublicationRepositoryReason.STORE_UNAVAILABLE
        )
        assert _database_snapshot(database_path) == baseline
        assert _database_schema_snapshot(database_path) == baseline_schema
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason is (
        ReferencePublicationRepositoryReason.STORE_UNAVAILABLE
    )


def test_commit_clock_and_host_tip_without_new_commit_break_exact_replay(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "orphan-tip.db"
    repository = _make_repository(database_path, committed_fixture)
    repository.execute_host_snapshot_publication(committed_fixture.mutation)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("UPDATE commit_clock SET last_sequence = last_sequence + 1")
        connection.execute(
            """
            UPDATE authority_current
            SET resource_version = resource_version + 100
            WHERE authority_kind = 'HOST'
            """
        )
        connection.commit()
    baseline = _database_snapshot(database_path)
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason in {
            ReferencePublicationRepositoryReason.CURRENT_CHANGED,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()


@pytest.mark.parametrize(
    "schema_tamper",
    ("user-trigger", "authority-constraint-drift"),
)
def test_bootstrap_rechecks_frozen_schema_before_any_seed_write(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    schema_tamper: str,
) -> None:
    database_path = tmp_path / f"bootstrap-{schema_tamper}.db"
    repository = _open_repository(database_path, committed_fixture)
    if schema_tamper == "user-trigger":
        with closing(sqlite3.connect(database_path)) as connection:
            connection.execute(
                """
                CREATE TRIGGER forbidden_authority_trigger
                AFTER INSERT ON authority_current
                BEGIN
                    SELECT 1;
                END
                """
            )
            connection.commit()
    else:
        _rebuild_authority_table_without_checks(
            database_path,
            add_fifth_authority=False,
        )
    baseline = _database_snapshot(database_path)
    baseline_schema = _database_schema_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.reference_only_bootstrap_admin().seed_from_mutation(
                committed_fixture.mutation
            )
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.STORE_UNAVAILABLE
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
        assert _database_schema_snapshot(database_path) == baseline_schema
    finally:
        repository.close()


@pytest.mark.parametrize(
    "orphan_kind",
    ("audit", "outbox", "snapshot", "device"),
)
def test_exact_replay_rejects_global_orphan_materialization_without_writes(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    orphan_kind: str,
) -> None:
    database_path = tmp_path / f"orphan-{orphan_kind}.db"
    repository = _make_repository(database_path, committed_fixture)
    repository.execute_host_snapshot_publication(committed_fixture.mutation)
    _insert_orphan_materialization(
        database_path,
        committed_fixture,
        orphan_kind,
    )
    baseline = _database_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()


def test_predecessor_snapshot_rejects_smuggled_nonempty_artifact_wrapper(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "predecessor-wrapper-smuggling.db"
    repository = _make_repository(database_path, committed_fixture)
    with closing(sqlite3.connect(database_path)) as connection:
        row = connection.execute(
            """
            SELECT instance_bytes
            FROM host_snapshots
            WHERE artifact_bytes IS NULL AND artifact_sha256 IS NULL
            """
        ).fetchone()
        assert row is not None
        predecessor_state = json.loads(bytes(row[0]))
        artifact, instance = _retained_artifact_bytes(
            state=predecessor_state,
            schema_ref="forged/predecessor-snapshot-wrapper",
        )
        assert instance == bytes(row[0])
        updated = connection.execute(
            """
            UPDATE host_snapshots
            SET artifact_bytes = ?,
                artifact_sha256 = ?
            WHERE artifact_bytes IS NULL AND artifact_sha256 IS NULL
            """,
            (artifact, sha256_digest(artifact)),
        )
        assert updated.rowcount == 1
        connection.commit()
    baseline = _database_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason is (
        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
    )


def test_factory_verified_genesis_authorities_cannot_replace_bootstrap_baseline(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
    genesis_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "verified-authority-replacement.db"
    repository = _make_repository(database_path, committed_fixture)
    _replace_current_authorities_from_fixture(
        database_path,
        genesis_fixture,
    )
    baseline = _database_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason in {
            ReferencePublicationRepositoryReason.CURRENT_CHANGED,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason is (
        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
    )


def test_second_commit_clock_singleton_is_rejected_even_if_check_is_bypassed(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "second-clock-singleton.db"
    repository = _make_repository(database_path, committed_fixture)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        assert connection.execute("PRAGMA ignore_check_constraints").fetchone()[0] == 1
        connection.execute(
            """
            INSERT INTO commit_clock(singleton, last_sequence)
            VALUES (2, ?)
            """,
            (committed_fixture.mutation.repository_transaction["commitClockBefore"],),
        )
        connection.commit()
    baseline = _database_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason is (
        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
    )


def test_single_commit_v1_unique_singleton_rejects_second_row_without_writes(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "second-commit-row.db"
    repository = _make_repository(database_path, committed_fixture)
    repository.execute_host_snapshot_publication(committed_fixture.mutation)
    baseline = _database_snapshot(database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _attempt_second_commit_row(database_path)
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()


def test_store_instance_id_drift_cannot_change_replay_context_or_reopen(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "store-instance-drift.db"
    repository = _make_repository(database_path, committed_fixture)
    original = repository.execute_host_snapshot_publication(committed_fixture.mutation)
    replacement = "reference-publication-store-" + ("e" * 32)
    assert replacement != original.store_instance_id
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            """
            UPDATE metadata
            SET value = ?
            WHERE key = 'store_instance_id'
            """,
            (replacement,),
        )
        connection.commit()
    baseline = _database_snapshot(database_path)
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as replay_error:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert replay_error.value.reason in {
            ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
        }
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason in {
        ReferencePublicationRepositoryReason.STORE_UNAVAILABLE,
        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION,
    }


def test_commit_mutations_bytes_must_recompute_and_cross_link_mutation_set_hash(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    database_path = tmp_path / "mutations-cross-link.db"
    repository = _make_repository(database_path, committed_fixture)
    repository.execute_host_snapshot_publication(committed_fixture.mutation)
    replacement = canonical_json_bytes(
        [None] * committed_fixture.mutation.publication_mutation_count
    )
    with closing(sqlite3.connect(database_path)) as connection:
        updated = connection.execute(
            """
            UPDATE publication_commits
            SET mutations_bytes = ?
            """,
            (replacement,),
        )
        assert updated.rowcount == 1
        connection.commit()
    baseline = _database_snapshot(database_path)
    changes_before = repository.connection_total_changes
    try:
        with pytest.raises(ReferencePublicationRepositoryError) as raised:
            repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert raised.value.reason is (
            ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
        )
        assert repository.connection_total_changes == changes_before
        assert _database_snapshot(database_path) == baseline
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as reopen_error:
        SqliteReferenceHostSnapshotPublicationRepository(
            database_path,
            _repository_id(committed_fixture),
        )
    assert reopen_error.value.reason is (
        ReferencePublicationRepositoryReason.INTEGRITY_VIOLATION
    )


def test_first_statement_is_begin_immediate_and_path_metadata_api_are_closed(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    statements: list[str] = []
    repository = _make_repository(
        tmp_path / "first-statement.db",
        committed_fixture,
        statement_hook=statements.append,
    )
    try:
        statements.clear()
        repository.execute_host_snapshot_publication(committed_fixture.mutation)
        assert statements
        assert statements[0].strip().upper() == "BEGIN IMMEDIATE"
        assert tuple(
            inspect.signature(
                SqliteReferenceHostSnapshotPublicationRepository.execute_host_snapshot_publication
            ).parameters
        ) == ("self", "mutation")
        with pytest.raises(TypeError):
            repository.execute_host_snapshot_publication(
                committed_fixture.mutation,
                read_set={},
            )

        state = repository.inspect_reference_publication_state()
        assert repository.database_path == tmp_path / "first-statement.db"
        assert repository.repository_id == _repository_id(committed_fixture)
        assert state["metadata"]["repository_id"] == _repository_id(committed_fixture)
        assert state["metadata"]["store_instance_id"] == (repository.store_instance_id)
        assert (
            state["commitClock"]
            == (committed_fixture.mutation.repository_transaction["commitClockAfter"])
        )
        with closing(sqlite3.connect(repository.database_path)) as independent:
            assert independent.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert independent.execute("PRAGMA synchronous").fetchone()[0] == 2
    finally:
        repository.close()

    with pytest.raises(ReferencePublicationRepositoryError) as closed:
        repository.inspect_reference_publication_state()
    assert closed.value.reason is (
        ReferencePublicationRepositoryReason.STORE_UNAVAILABLE
    )

    for value in (":memory:", "file:publication?mode=memory", "relative.db"):
        with pytest.raises(ReferencePublicationRepositoryError) as invalid:
            SqliteReferenceHostSnapshotPublicationRepository(
                value,
                _repository_id(committed_fixture),
            )
        assert invalid.value.reason is (
            ReferencePublicationRepositoryReason.STORE_NOT_DURABLE
        )


def test_store_never_persists_post_commit_query_or_repository_receipt_material(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    repository = _make_repository(
        tmp_path / "dag.db",
        committed_fixture,
    )
    try:
        execution = repository.execute_host_snapshot_publication(
            committed_fixture.mutation
        )
        assert committed_fixture.mutation.context_digest in (
            execution.canonical_context_bytes.decode("utf-8")
        )

        receipt_bytes = canonical_json_bytes(committed_fixture.receipt)
        forbidden_exact_values = {
            committed_fixture.mutation.context_digest.encode("utf-8"),
            committed_fixture.query.query_digest.encode("utf-8"),
            committed_fixture.query.verification_nonce.encode("utf-8"),
            committed_fixture.receipt["requestedAt"].encode("utf-8"),
            committed_fixture.receipt["receiptDigest"].encode("utf-8"),
            committed_fixture.receipt["signature"].encode("utf-8"),
            receipt_bytes,
        }
        forbidden_schema_names = (
            b"mutation_context_digest",
            b"mutationcontextdigest",
            b"context_receipt",
            b"query_digest",
            b"querydigest",
            b"verification_nonce",
            b"verificationnonce",
            b"requested_at",
            b"requestedat",
            b"receipt_digest",
            b"receiptdigest",
            b"receipt_signature",
            b"repository_receipt",
        )

        for label, material in _iter_database_material(repository.database_path):
            lowered = material.lower()
            if label.startswith(("schema:", "column:")):
                for forbidden_name in forbidden_schema_names:
                    assert forbidden_name not in lowered, (
                        f"{label} persisted forbidden post-commit field "
                        f"{forbidden_name!r}"
                    )
            for forbidden_value in forbidden_exact_values:
                assert forbidden_value not in material, (
                    f"{label} persisted post-commit query/receipt material"
                )
    finally:
        repository.close()


def test_execution_is_component_only_and_keeps_exact_product_blockers(
    tmp_path: Path,
    committed_fixture: RepositoryFixture,
) -> None:
    repository = _make_repository(
        tmp_path / "boundary.db",
        committed_fixture,
    )
    try:
        execution = repository.execute_host_snapshot_publication(
            committed_fixture.mutation
        )
        assert execution.product_authorized is False
        assert execution.product_evidence_blockers == (
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
        )
        assert len(execution.product_evidence_blockers) == 12
        assert execution.canonical_context["productAuthorized"] is False
        assert (
            tuple(execution.canonical_context["productEvidenceBlockers"])
            == HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
        )
    finally:
        repository.close()


def test_public_api_exports_are_exact_and_execution_is_factory_only() -> None:
    expected = {
        "AFTER_PUBLICATION_COMMIT_BEFORE_RETURN": (
            AFTER_PUBLICATION_COMMIT_BEFORE_RETURN
        ),
        "PUBLICATION_WRITE_FAULT_STAGES": PUBLICATION_WRITE_FAULT_STAGES,
        "REFERENCE_ONLY_PUBLICATION_BOOTSTRAP": (REFERENCE_ONLY_PUBLICATION_BOOTSTRAP),
        "REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY": (
            REFERENCE_PUBLICATION_EVIDENCE_BOUNDARY
        ),
        "REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS": (
            REFERENCE_PUBLICATION_PRODUCT_EVIDENCE_BLOCKERS
        ),
        "ReferenceOnlyPublicationBootstrapAdmin": (
            ReferenceOnlyPublicationBootstrapAdmin
        ),
        "ReferencePublicationExecution": ReferencePublicationExecution,
        "ReferencePublicationRepositoryError": (ReferencePublicationRepositoryError),
        "ReferencePublicationRepositoryReason": (ReferencePublicationRepositoryReason),
        "SqliteReferenceHostSnapshotPublicationRepository": (
            SqliteReferenceHostSnapshotPublicationRepository
        ),
        "inspect_reference_publication_state": (inspect_reference_publication_state),
    }
    for name, value in expected.items():
        assert getattr(public_api, name) is value
        assert name in public_api.__all__
    with pytest.raises(TypeError):
        ReferencePublicationExecution()
