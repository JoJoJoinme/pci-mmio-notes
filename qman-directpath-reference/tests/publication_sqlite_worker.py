"""Independent-process worker for publication SQLite crash/serialization tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = REPOSITORY_ROOT / "qman-directpath-core"
for import_root in (REFERENCE_ROOT, CORE_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from qman_directpath_core.canonical import sha256_digest  # noqa: E402
from tests.test_publication_capture import thaw  # noqa: E402
from tests.test_publication_repository import RepositoryFixture  # noqa: E402

from qman_directpath_reference.publication_repository import (  # noqa: E402
    ReferencePublicationRepositoryError,
    SqliteReferenceHostSnapshotPublicationRepository,
)


_KEY_SEED = b"qman-directpath/reference-publication-sqlite-worker/v1"


def build_deterministic_repository_fixture() -> RepositoryFixture:
    """Build byte-identical core fixtures independently in parent and workers."""

    counter = 0

    def deterministic_generate() -> Ed25519PrivateKey:
        nonlocal counter
        material = hashlib.sha256(_KEY_SEED + counter.to_bytes(8, "big")).digest()
        counter += 1
        return Ed25519PrivateKey.from_private_bytes(material)

    with patch.object(
        Ed25519PrivateKey,
        "generate",
        side_effect=deterministic_generate,
    ):
        return RepositoryFixture("SUCCESSOR")


def deterministic_fixture_fingerprint(
    fixture: RepositoryFixture,
) -> dict[str, str]:
    mutation = fixture.mutation
    optional = (
        mutation.availability_authority_after_artifact_canonical_bytes_or_null,
        mutation.audit_record_artifact_canonical_bytes_or_null,
        mutation.outbox_record_artifact_canonical_bytes_or_null,
        mutation.commit_record_artifact_canonical_bytes_or_null,
    )
    if any(value is None for value in optional):
        raise AssertionError("deterministic committed fixture lacks artifacts")
    availability, audit, outbox, commit = optional
    assert availability is not None
    assert audit is not None
    assert outbox is not None
    assert commit is not None
    return {
        "mutationContextDigest": mutation.context_digest,
        "repositoryTransactionSha256": sha256_digest(
            mutation.repository_transaction_canonical_bytes
        ),
        "mutationsSha256": sha256_digest(mutation.mutations_canonical_bytes),
        "hostSnapshotSha256": sha256_digest(
            mutation.rollback.host_snapshot_after_artifact_canonical_bytes
        ),
        "hostAuthoritySha256": sha256_digest(
            mutation.rollback.host_authority_after_artifact_canonical_bytes
        ),
        "availabilityAuthoritySha256": sha256_digest(availability),
        "auditSha256": sha256_digest(audit),
        "outboxSha256": sha256_digest(outbox),
        "commitSha256": sha256_digest(commit),
    }


def _wait_for_start(path: Path) -> None:
    deadline = time.monotonic() + 120
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("worker start file was not created")
        time.sleep(0.01)


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    fixture = build_deterministic_repository_fixture()
    transaction = thaw(fixture.mutation.repository_transaction)
    clock_values = iter((transaction["beganAt"], transaction["committedAtOrNull"]))

    def fault(stage: str) -> None:
        if stage == payload.get("hardExitStage"):
            os._exit(int(payload.get("hardExitCode", 79)))

    repository = SqliteReferenceHostSnapshotPublicationRepository(
        Path(payload["databasePath"]),
        transaction["repositoryId"],
        clock=lambda: next(clock_values, transaction["committedAtOrNull"]),
        busy_timeout_ms=int(payload.get("busyTimeoutMs", 20_000)),
        fault_hook=fault,
    )
    ready_path = Path(payload["readyPath"])
    output_path = Path(payload["outputPath"])
    ready_path.write_text("ready", encoding="utf-8")
    _wait_for_start(Path(payload["startPath"]))

    before_changes = repository.connection_total_changes
    try:
        execution = repository.execute_host_snapshot_publication(fixture.mutation)
        result = {
            "status": "OK",
            "outcome": execution.outcome,
            "executionBytesBase64": base64.b64encode(
                execution.canonical_context_bytes
            ).decode("ascii"),
            "totalChangesDelta": (repository.connection_total_changes - before_changes),
            "fingerprint": deterministic_fixture_fingerprint(fixture),
        }
    except ReferencePublicationRepositoryError as error:
        result = {
            "status": "ERROR",
            "reason": error.reason.value,
            "detail": error.detail,
            "fingerprint": deterministic_fixture_fingerprint(fixture),
        }
    finally:
        repository.close()
    output_path.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
