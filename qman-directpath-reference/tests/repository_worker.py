"""Independent-process worker for SQLite reference repository tests."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import time

from qman_directpath_reference import (
    DeterministicReferenceEvaluator,
    ReferenceRepositoryError,
    ReferenceSelectionPremise,
    SqliteReferenceStaticAdmissionRepository,
    StaticAdmissionCommand,
)


def _selection(value: dict[str, object]) -> ReferenceSelectionPremise:
    return ReferenceSelectionPremise(
        bundle_id=str(value["bundleId"]),
        scope_hash=str(value["scopeHash"]),
        member_ids=tuple(value["memberIds"]),
        evidence_blob_hashes=tuple(value["evidenceBlobHashes"]),
        valid_until=str(value["validUntil"]),
    )


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    selections = {
        vm_id: _selection(value) for vm_id, value in payload["selections"].items()
    }
    evaluator = DeterministicReferenceEvaluator(selections)
    ready_path = Path(payload["readyPath"])
    start_path = Path(payload["startPath"])
    output_path = Path(payload["outputPath"])
    reached_path = Path(payload["reachedPath"]) if payload.get("reachedPath") else None
    release_path = Path(payload["releasePath"]) if payload.get("releasePath") else None
    attempted_path = (
        Path(payload["attemptedPath"]) if payload.get("attemptedPath") else None
    )

    def fault(stage: str) -> None:
        if stage == payload.get("hardExitStage"):
            os._exit(int(payload.get("hardExitCode", 79)))
        if stage == payload.get("pauseStage"):
            assert reached_path is not None
            assert release_path is not None
            reached_path.write_text(stage, encoding="utf-8")
            deadline = time.monotonic() + 20
            while not release_path.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("release file was not created")
                time.sleep(0.01)

    repository = SqliteReferenceStaticAdmissionRepository(
        Path(payload["databasePath"]),
        evaluator,
        clock=lambda: payload["clock"],
        busy_timeout_ms=int(payload.get("busyTimeoutMs", 10_000)),
        fault_hook=fault,
    )
    ready_path.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 20
    while not start_path.exists():
        if time.monotonic() >= deadline:
            repository.close()
            raise TimeoutError("start file was not created")
        time.sleep(0.01)

    try:
        if payload["mode"] == "admit":
            command = StaticAdmissionCommand.from_wire(payload["command"])
            result = repository.admit_static(command)
            output = {
                "status": "OK",
                "commitSequence": result.commit_sequence,
                "resultBytes": base64.b64encode(result.to_canonical_bytes()).decode(
                    "ascii"
                ),
                "resultHash": result.result_hash,
            }
        elif payload["mode"] == "quarantine":
            quarantine = payload["quarantine"]
            if attempted_path is not None:
                attempted_path.write_text("attempted", encoding="utf-8")
            repository.reference_only_bootstrap_admin().set_quarantine(
                conflict_key=quarantine["conflictKey"],
                quarantine_digest=quarantine["quarantineDigest"],
                resource_version=quarantine["resourceVersion"],
            )
            output = {"status": "OK"}
        else:
            raise ValueError(f"unknown worker mode: {payload['mode']}")
    except ReferenceRepositoryError as error:
        output = {
            "status": "ERROR",
            "reason": error.reason.value,
            "detail": error.detail,
        }
    finally:
        repository.close()
    output_path.write_text(
        json.dumps(output, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
