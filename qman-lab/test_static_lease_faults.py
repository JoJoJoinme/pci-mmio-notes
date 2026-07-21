#!/usr/bin/env python3
"""Exercise the Qman Static lease component across real process failures.

The SQLite databases used for the run live on a WSL-native filesystem.  The
requested output directory may live on DrvFS because it contains only retained
artifacts, never the live lease store.  Every child imports a byte-for-byte
pinned copy of ``static_lease.py`` and verifies its SHA-256 before touching the
database.

This is a component fault runner.  Bind, reset, VFIO and QEMU phase names below
are explicit simulated event labels; no such external operation is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_SOURCE = (
    REPO_ROOT / "pci-resource-model" / "pci_resource_model" / "static_lease.py"
)

HOST = "qman-wsl-host-a"
AUTHORITY = "qman-inventory-publisher-lab-v1"
EPOCH = 42
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
MEMBERS = ("0000:64:00.0", "0000:65:00.0")
OVERLAP_MEMBERS = ("0000:65:00.0", "0000:66:00.0")
ALL_GENERATIONS = {
    "0000:64:00.0": 7,
    "0000:65:00.0": 8,
    "0000:66:00.0": 9,
}

BEGIN_HARD_EXIT = 91
RELEASE_HARD_EXIT = 92
CHILD_TIMEOUT_SECONDS = 30
WAIT_TIMEOUT_SECONDS = 20


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise AssertionError(detail)


def load_pinned_module(source: Path, expected_sha256: str) -> ModuleType:
    source = source.resolve(strict=True)
    actual_sha256 = sha256_file(source)
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            "pinned Static lease source hash mismatch: "
            f"expected {expected_sha256}, actual {actual_sha256}"
        )
    module_name = f"_qman_static_lease_{actual_sha256[:20]}"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import pinned source: {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def open_store(module: ModuleType, database: Path, **kwargs: Any) -> Any:
    return module.StaticLeaseStore(
        database,
        local_host_id=HOST,
        trusted_authority_id=AUTHORITY,
        **kwargs,
    )


def initialize_authority(
    module: ModuleType,
    database: Path,
    bundles: Mapping[str, Sequence[str]],
) -> str:
    store = open_store(module, database, timeout_seconds=10)
    try:
        boundary = store.persistence_boundary
        store.publish_authoritative_device_generations(
            HOST,
            ALL_GENERATIONS,
            expected_current={bdf: None for bdf in ALL_GENERATIONS},
            authority_id=AUTHORITY,
            authority_epoch=EPOCH,
        )
        for bundle_id, members in bundles.items():
            store.publish_authoritative_bundle(
                HOST,
                bundle_id,
                members,
                expected_current_hash=None,
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            )
        return boundary
    finally:
        store.close()


def make_request(
    module: ModuleType,
    *,
    key: str,
    vm_id: str,
    run_id: str,
    bundle_id: str = "bundle-a",
    members: Sequence[str] = MEMBERS,
) -> Any:
    canonical_members = tuple(members)
    return module.BeginRequest(
        idempotency_key=key,
        host_id=HOST,
        vm_id=vm_id,
        run_id=run_id,
        bundle_id=bundle_id,
        expected_bundle_hash=module.StaticLeaseStore.compute_bundle_members_hash(
            HOST, bundle_id, canonical_members
        ),
        members=canonical_members,
        inventory_epoch=EPOCH,
        expected_vm_generation=0,
        expected_device_generations={
            member: ALL_GENERATIONS[member] for member in canonical_members
        },
        decision_hash=HASH_A,
        policy_hash=HASH_B,
    )


def record_json(record: Any) -> dict[str, Any]:
    return {
        "transactionId": record.transaction_id,
        "idempotencyKey": record.idempotency_key,
        "hostId": record.host_id,
        "vmId": record.vm_id,
        "runId": record.run_id,
        "bundleId": record.bundle_id,
        "authorityId": record.authority_id,
        "bundleMembersHash": record.bundle_members_hash,
        "members": list(record.members),
        "inventoryEpoch": record.inventory_epoch,
        "deviceGenerations": dict(sorted(record.device_generations.items())),
        "decisionHash": record.decision_hash,
        "policyHash": record.policy_hash,
        "vmGeneration": record.vm_generation,
        "state": record.state.value,
        "revision": record.revision,
        "reasonCode": record.reason_code,
        "reasonDetail": record.reason_detail,
        "cleanupRequestHash": record.cleanup_request_hash,
        "createdAt": record.created_at,
        "updatedAt": record.updated_at,
    }


def journal_json(entries: Sequence[Any]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": entry.sequence,
            "transactionId": entry.transaction_id,
            "event": entry.event,
            "state": entry.state.value,
            "revision": entry.revision,
            "detail": dict(entry.detail),
            "createdAt": entry.created_at,
        }
        for entry in entries
    ]


def raw_database_facts(database: Path) -> dict[str, Any]:
    table_names = (
        "metadata",
        "vm_generations",
        "device_generations",
        "bundle_definitions",
        "transactions",
        "member_claims",
        "bundle_claims",
        "journal",
    )
    connection = sqlite3.connect(database)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in table_names
        }
        metadata = dict(
            connection.execute("SELECT key,value FROM metadata ORDER BY key").fetchall()
        )
        return {
            "integrityCheck": integrity,
            "tableCounts": counts,
            "metadata": metadata,
        }
    finally:
        connection.close()


def store_snapshot(
    module: ModuleType,
    database: Path,
    *,
    transaction_id: str | None = None,
    vm_id: str | None = None,
) -> dict[str, Any]:
    store = open_store(module, database, timeout_seconds=10)
    try:
        record = None if transaction_id is None else record_json(store.get(transaction_id))
        journal = (
            []
            if transaction_id is None
            else journal_json(store.journal(transaction_id))
        )
        snapshot = {
            "persistenceBoundary": store.persistence_boundary,
            "trustedAuthorityId": store.trusted_authority_id,
            "record": record,
            "journal": journal,
            "claimedMembers": dict(store.claimed_members(HOST)),
            "claimedBundles": dict(store.claimed_bundles(HOST)),
            "deviceGenerations": dict(store.current_device_generations(HOST)),
            "vmGeneration": (
                None if vm_id is None else store.current_vm_generation(HOST, vm_id)
            ),
            "recoveryRequired": [
                record_json(item) for item in store.recovery_required()
            ],
        }
    finally:
        store.close()
    snapshot["database"] = raw_database_facts(database)
    return snapshot


def checkpoint_and_copy(database: Path, destination: Path) -> dict[str, Any]:
    connection = sqlite3.connect(database)
    try:
        checkpoint = list(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()
    require(integrity == "ok", f"SQLite integrity check failed for {database}: {integrity}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(database, destination)
    return {
        "walCheckpoint": checkpoint,
        "integrityCheck": integrity,
        "retainedSha256": sha256_file(destination),
    }


def child_result_base(mode: str, source_sha256: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "mode": mode,
        "pid": os.getpid(),
        "sourceSha256": source_sha256,
        "trustedAuthorityId": AUTHORITY,
    }


def child_main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--module-source", type=Path, required=True)
    parser.add_argument("--module-sha256", required=True)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args(arguments)
    module = load_pinned_module(args.module_source, args.module_sha256)
    payload = read_json(args.payload)
    mode = payload["mode"]
    database = Path(payload["database"])
    result_path = Path(payload["resultPath"])
    transaction_id = payload["transactionId"]

    if mode == "begin-hard-exit":
        def fault(point: str) -> None:
            if point == "BEGIN_BEFORE_COMMIT":
                os._exit(BEGIN_HARD_EXIT)

        store = open_store(
            module,
            database,
            timeout_seconds=10,
            transaction_id_factory=lambda: transaction_id,
            fault_hook=fault,
        )
        store.begin(
            make_request(
                module,
                key="begin-crash-key",
                vm_id="vm-begin-crash",
                run_id="run-begin-crash",
            )
        )
        raise AssertionError("BEGIN hard-exit fault did not fire")

    if mode == "release-hard-exit":
        def fault(point: str) -> None:
            if point == "RELEASE_CLEAN_BEFORE_COMMIT":
                os._exit(RELEASE_HARD_EXIT)

        store = open_store(module, database, timeout_seconds=10, fault_hook=fault)
        store.complete_release(
            transaction_id,
            payload["vmGeneration"],
            payload["expectedRevision"],
            cleanup_verified=True,
            reason_code="RELEASE_COMPLETE",
            reason_detail="test-only cleanup assertion before injected crash",
            next_device_generations=payload["nextDeviceGenerations"],
            next_authority_epoch=payload["nextAuthorityEpoch"],
            authority_id=AUTHORITY,
        )
        raise AssertionError("release hard-exit fault did not fire")

    if mode == "concurrent-begin":
        deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
        start_path = Path(payload["startPath"])
        while not start_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("concurrent start barrier was not released")
            time.sleep(0.01)
        store = open_store(
            module,
            database,
            timeout_seconds=10,
            transaction_id_factory=lambda: transaction_id,
        )
        result = child_result_base(mode, args.module_sha256)
        try:
            record = store.begin(
                make_request(
                    module,
                    key=payload["idempotencyKey"],
                    vm_id=payload["vmId"],
                    run_id=payload["runId"],
                    bundle_id=payload["bundleId"],
                    members=payload["members"],
                )
            )
            result.update({"status": "OK", "record": record_json(record)})
        except module.LeaseStoreError as error:
            result.update(
                {
                    "status": "DENIED",
                    "reason": error.reason.value,
                    "detail": error.detail,
                }
            )
        finally:
            store.close()
        write_json(result_path, result)
        return 0

    store = open_store(
        module,
        database,
        timeout_seconds=10,
        transaction_id_factory=lambda: transaction_id,
    )
    result = child_result_base(mode, args.module_sha256)
    try:
        reserved = store.begin(
            make_request(
                module,
                key=f"{mode}-key",
                vm_id=f"vm-{mode}",
                run_id=f"run-{mode}",
            )
        )
        preparing = store.prepare(
            reserved.transaction_id, reserved.vm_generation, reserved.revision
        )

        if mode == "s03-clean-rollback":
            released = store.rollback(
                preparing.transaction_id,
                preparing.vm_generation,
                preparing.revision,
                cleanup_verified=True,
                reason_code="BIND_FAILED_ORIGINAL_OWNER_RESTORED",
                reason_detail="simulated bind failure; cleanup proof is a test assertion",
                next_device_generations={MEMBERS[0]: 8, MEMBERS[1]: 9},
                next_authority_epoch=EPOCH + 1,
                authority_id=AUTHORITY,
            )
            result.update(
                {
                    "status": "OK",
                    "record": record_json(released),
                    "phaseInjection": "SIMULATED_BIND_FAILURE_LABEL_ONLY",
                    "cleanupEvidence": "TEST_ASSERTION_ONLY",
                }
            )
        elif mode == "s04-reset-failure":
            quarantined = store.quarantine(
                preparing.transaction_id,
                preparing.vm_generation,
                preparing.revision,
                reason_code="RESET_STATE_VERIFY_FAILED",
                reason_detail="simulated reset verification failure",
            )
            result.update(
                {
                    "status": "OK",
                    "record": record_json(quarantined),
                    "phaseInjection": "SIMULATED_RESET_FAILURE_LABEL_ONLY",
                }
            )
        elif mode == "s05-qemu-start-failure":
            quarantined = store.rollback(
                preparing.transaction_id,
                preparing.vm_generation,
                preparing.revision,
                cleanup_verified=False,
                reason_code="QEMU_START_FAILED",
                reason_detail="simulated QEMU start failure without cleanup evidence",
            )
            result.update(
                {
                    "status": "OK",
                    "record": record_json(quarantined),
                    "phaseInjection": "SIMULATED_QEMU_START_FAILURE_LABEL_ONLY",
                    "cleanupEvidence": "ABSENT_BY_TEST_CONSTRUCTION",
                }
            )
        elif mode == "f00-attached-wait":
            attached = store.commit(
                preparing.transaction_id,
                preparing.vm_generation,
                preparing.revision,
            )
            result.update(
                {
                    "status": "READY",
                    "record": record_json(attached),
                    "phaseInjection": "SIMULATED_QEMU_OWNER_WAIT_LABEL_ONLY",
                }
            )
            write_json(result_path, result)
            while True:
                signal.pause()
        else:
            raise ValueError(f"unsupported child mode: {mode}")
    finally:
        store.close()
    write_json(result_path, result)
    return 0


@dataclass(frozen=True)
class RunContext:
    module: ModuleType
    runner_path: Path
    pinned_source: Path
    source_sha256: str
    native_root: Path
    output_root: Path
    persistence_boundary: str


def case_paths(context: RunContext, case_id: str) -> tuple[Path, Path, Path]:
    native = context.native_root / case_id
    artifact = context.output_root / case_id
    native.mkdir()
    artifact.mkdir()
    return native, artifact, native / "lease.sqlite3"


def payload_path(
    native: Path,
    *,
    mode: str,
    database: Path,
    transaction_id: str,
    extra: Mapping[str, Any] | None = None,
) -> tuple[Path, Path]:
    result = native / "child-result.json"
    payload: dict[str, Any] = {
        "mode": mode,
        "database": str(database),
        "resultPath": str(result),
        "transactionId": transaction_id,
    }
    if extra:
        payload.update(extra)
    path = native / "child-payload.json"
    write_json(path, payload)
    return path, result


def child_command(context: RunContext, payload: Path) -> list[str]:
    return [
        sys.executable,
        str(context.runner_path),
        "--_child",
        "--module-source",
        str(context.pinned_source),
        "--module-sha256",
        context.source_sha256,
        "--payload",
        str(payload),
    ]


def process_json(command: Sequence[str], return_code: int) -> dict[str, Any]:
    return {
        "command": list(command),
        "returnCode": return_code,
        "signal": -return_code if return_code < 0 else None,
    }


def run_child(
    context: RunContext,
    payload: Path,
    artifact: Path,
    *,
    timeout: int = CHILD_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    command = child_command(context, payload)
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    (artifact / "child.stdout").write_text(completed.stdout, encoding="utf-8")
    (artifact / "child.stderr").write_text(completed.stderr, encoding="utf-8")
    return process_json(command, completed.returncode)


def retain_case(
    database: Path,
    artifact: Path,
    result: Mapping[str, Any],
    child_result: Path | None = None,
) -> dict[str, Any]:
    if child_result is not None and child_result.is_file():
        shutil.copy2(child_result, artifact / "child-result.json")
    database_artifact = checkpoint_and_copy(database, artifact / "lease.sqlite3")
    final = dict(result)
    final["databaseArtifact"] = database_artifact
    write_json(artifact / "result.json", final)
    return final


def case_begin_crash(context: RunContext) -> dict[str, Any]:
    case_id = "begin-hard-exit"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    payload, child_result = payload_path(
        native,
        mode="begin-hard-exit",
        database=database,
        transaction_id="tx-begin-hard-exit",
    )
    process = run_child(context, payload, artifact)
    snapshot = store_snapshot(
        context.module, database, vm_id="vm-begin-crash"
    )
    counts = snapshot["database"]["tableCounts"]
    checks = {
        "hardExitObserved": process["returnCode"] == BEGIN_HARD_EXIT,
        "vmGenerationNotAdvanced": snapshot["vmGeneration"] == 0,
        "noTransactionResidue": counts["transactions"] == 0,
        "noJournalResidue": counts["journal"] == 0,
        "noMemberClaimResidue": snapshot["claimedMembers"] == {},
        "noBundleClaimResidue": snapshot["claimedBundles"] == {},
        "noRecoveryRecord": snapshot["recoveryRequired"] == [],
        "sqliteIntegrityOk": snapshot["database"]["integrityCheck"] == "ok",
    }
    require(all(checks.values()), f"begin crash checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process,
            "checks": checks,
            "snapshot": snapshot,
            "fault": "os._exit at BEGIN_BEFORE_COMMIT",
        },
        child_result,
    )


def case_s03(context: RunContext) -> dict[str, Any]:
    case_id = "S03"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    payload, child_result = payload_path(
        native,
        mode="s03-clean-rollback",
        database=database,
        transaction_id="tx-s03",
    )
    process = run_child(context, payload, artifact)
    snapshot = store_snapshot(
        context.module, database, transaction_id="tx-s03", vm_id="vm-s03-clean-rollback"
    )
    record = snapshot["record"]
    checks = {
        "childExitedCleanly": process["returnCode"] == 0,
        "released": record["state"] == "RELEASED",
        "deviceGenerationsAdvancedTogether": {
            member: snapshot["deviceGenerations"][member] for member in MEMBERS
        }
        == {MEMBERS[0]: 8, MEMBERS[1]: 9},
        "claimsReleased": snapshot["claimedMembers"] == {}
        and snapshot["claimedBundles"] == {},
        "journalAtomicSequence": [entry["event"] for entry in snapshot["journal"]]
        == ["BEGIN_RESERVED", "PREPARE_STARTED", "ROLLBACK_CLEAN"],
        "cleanupRequestBound": bool(record["cleanupRequestHash"]),
        "sqliteIntegrityOk": snapshot["database"]["integrityCheck"] == "ok",
    }
    require(all(checks.values()), f"S03 checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process,
            "checks": checks,
            "snapshot": snapshot,
            "phaseInjection": "SIMULATED_BIND_FAILURE_LABEL_ONLY",
            "cleanupEvidence": "TEST_ASSERTION_ONLY",
        },
        child_result,
    )


def case_s04(context: RunContext) -> dict[str, Any]:
    case_id = "S04"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    payload, child_result = payload_path(
        native,
        mode="s04-reset-failure",
        database=database,
        transaction_id="tx-s04",
    )
    process = run_child(context, payload, artifact)
    snapshot = store_snapshot(
        context.module, database, transaction_id="tx-s04", vm_id="vm-s04-reset-failure"
    )
    record = snapshot["record"]
    checks = {
        "childExitedCleanly": process["returnCode"] == 0,
        "wholeBundleQuarantined": record["state"] == "QUARANTINED",
        "reasonStable": record["reasonCode"] == "RESET_STATE_VERIFY_FAILED",
        "memberClaimsRetained": set(snapshot["claimedMembers"]) == set(MEMBERS),
        "bundleClaimRetained": snapshot["claimedBundles"]
        == {"bundle-a": "tx-s04"},
        "deviceGenerationsUnchanged": all(
            snapshot["deviceGenerations"][member] == ALL_GENERATIONS[member]
            for member in MEMBERS
        ),
    }
    require(all(checks.values()), f"S04 checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process,
            "checks": checks,
            "snapshot": snapshot,
            "phaseInjection": "SIMULATED_RESET_FAILURE_LABEL_ONLY",
        },
        child_result,
    )


def case_s05(context: RunContext) -> dict[str, Any]:
    case_id = "S05"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    payload, child_result = payload_path(
        native,
        mode="s05-qemu-start-failure",
        database=database,
        transaction_id="tx-s05",
    )
    process = run_child(context, payload, artifact)
    snapshot = store_snapshot(
        context.module,
        database,
        transaction_id="tx-s05",
        vm_id="vm-s05-qemu-start-failure",
    )
    record = snapshot["record"]
    checks = {
        "childExitedCleanly": process["returnCode"] == 0,
        "quarantined": record["state"] == "QUARANTINED",
        "cleanupEvidenceRequired": record["reasonCode"]
        == "CLEANUP_EVIDENCE_REQUIRED",
        "memberClaimsRetained": set(snapshot["claimedMembers"]) == set(MEMBERS),
        "bundleClaimRetained": snapshot["claimedBundles"]
        == {"bundle-a": "tx-s05"},
    }
    require(all(checks.values()), f"S05 checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process,
            "checks": checks,
            "snapshot": snapshot,
            "phaseInjection": "SIMULATED_QEMU_START_FAILURE_LABEL_ONLY",
            "cleanupEvidence": "ABSENT_BY_TEST_CONSTRUCTION",
        },
        child_result,
    )


def wait_for_file(path: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while not path.is_file():
        if process.poll() is not None:
            raise RuntimeError(
                f"child exited {process.returncode} before readiness: {path}"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for child readiness: {path}")
        time.sleep(0.02)


def case_f00(context: RunContext) -> dict[str, Any]:
    case_id = "F00"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    payload, child_result = payload_path(
        native,
        mode="f00-attached-wait",
        database=database,
        transaction_id="tx-f00",
    )
    command = child_command(context, payload)
    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout = ""
    stderr = ""
    try:
        wait_for_file(child_result, process)
        ready = read_json(child_result)
        require(ready["record"]["state"] == "ATTACHED", "child was not ATTACHED")
        os.kill(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
    (artifact / "child.stdout").write_text(stdout, encoding="utf-8")
    (artifact / "child.stderr").write_text(stderr, encoding="utf-8")
    process_evidence = process_json(command, process.returncode)
    before = store_snapshot(
        context.module, database, transaction_id="tx-f00", vm_id="vm-f00-attached-wait"
    )
    store = open_store(context.module, database, timeout_seconds=10)
    try:
        attached = store.get("tx-f00")
        quarantined = store.reconcile(
            attached.transaction_id,
            attached.vm_generation,
            attached.revision,
            context.module.ReconcileObservation.UNSAFE_OR_UNKNOWN,
            reason_detail=(
                "simulated owner process was SIGKILLed; DMA teardown is unknown"
            ),
        )
        require(quarantined.state.value == "QUARANTINED", "reconcile did not quarantine")
    finally:
        store.close()
    after = store_snapshot(
        context.module, database, transaction_id="tx-f00", vm_id="vm-f00-attached-wait"
    )
    checks = {
        "actualSigkillObserved": process.returncode == -signal.SIGKILL,
        "attachedStateSurvivedCrash": before["record"]["state"] == "ATTACHED",
        "unknownObservationQuarantined": after["record"]["state"] == "QUARANTINED",
        "recoveryReasonStable": after["record"]["reasonCode"] == "RECOVERY_REQUIRED",
        "memberClaimsRetained": set(after["claimedMembers"]) == set(MEMBERS),
        "bundleClaimRetained": after["claimedBundles"] == {"bundle-a": "tx-f00"},
    }
    require(all(checks.values()), f"F00 checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process_evidence,
            "checks": checks,
            "beforeReconcile": before,
            "afterReconcile": after,
            "phaseInjection": "SIMULATED_QEMU_OWNER_PROCESS_SIGKILL",
            "actualQemuProcess": False,
        },
        child_result,
    )


def case_concurrent_overlap(context: RunContext) -> dict[str, Any]:
    case_id = "concurrent-overlap"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(
        context.module,
        database,
        {"bundle-a": MEMBERS, "bundle-b": OVERLAP_MEMBERS},
    )
    start_path = native / "start"
    definitions = (
        {
            "name": "a",
            "transactionId": "tx-race-a",
            "idempotencyKey": "race-a",
            "vmId": "vm-race-a",
            "runId": "run-race-a",
            "bundleId": "bundle-a",
            "members": list(MEMBERS),
        },
        {
            "name": "b",
            "transactionId": "tx-race-b",
            "idempotencyKey": "race-b",
            "vmId": "vm-race-b",
            "runId": "run-race-b",
            "bundleId": "bundle-b",
            "members": list(OVERLAP_MEMBERS),
        },
    )
    children: list[tuple[dict[str, Any], Path, list[str], subprocess.Popen[str]]] = []
    for definition in definitions:
        payload, result_path = payload_path(
            native,
            mode="concurrent-begin",
            database=database,
            transaction_id=definition["transactionId"],
            extra={
                **definition,
                "startPath": str(start_path),
            },
        )
        renamed_payload = native / f"child-payload-{definition['name']}.json"
        os.replace(payload, renamed_payload)
        renamed_result = native / f"child-result-{definition['name']}.json"
        value = read_json(renamed_payload)
        value["resultPath"] = str(renamed_result)
        write_json(renamed_payload, value)
        command = child_command(context, renamed_payload)
        child = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        children.append((definition, renamed_result, command, child))
    write_json(start_path, {"released": True})
    child_evidence = []
    child_values = []
    try:
        for definition, result_path, command, child in children:
            stdout, stderr = child.communicate(timeout=CHILD_TIMEOUT_SECONDS)
            (artifact / f"child-{definition['name']}.stdout").write_text(
                stdout, encoding="utf-8"
            )
            (artifact / f"child-{definition['name']}.stderr").write_text(
                stderr, encoding="utf-8"
            )
            child_evidence.append(process_json(command, child.returncode))
            require(result_path.is_file(), f"missing race child result: {result_path}")
            value = read_json(result_path)
            child_values.append(value)
            shutil.copy2(result_path, artifact / f"child-result-{definition['name']}.json")
    finally:
        for _, _, _, child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    statuses = sorted(
        value["status"] if value["status"] == "OK" else value.get("reason")
        for value in child_values
    )
    snapshot = store_snapshot(context.module, database)
    winner = next(value for value in child_values if value["status"] == "OK")
    checks = {
        "childrenExitedCleanly": all(item["returnCode"] == 0 for item in child_evidence),
        "exactlyOneWinner": statuses == ["MEMBER_BUSY", "OK"],
        "oneTransactionCommitted": snapshot["database"]["tableCounts"]["transactions"] == 1,
        "overlapMemberHasWinnerClaim": snapshot["claimedMembers"].get(MEMBERS[1])
        == winner["record"]["transactionId"],
        "oneBundleClaim": len(snapshot["claimedBundles"]) == 1,
    }
    require(all(checks.values()), f"concurrent overlap checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "processes": child_evidence,
            "childResults": child_values,
            "checks": checks,
            "snapshot": snapshot,
        },
    )


def case_release_crash(context: RunContext) -> dict[str, Any]:
    case_id = "release-hard-exit"
    native, artifact, database = case_paths(context, case_id)
    initialize_authority(context.module, database, {"bundle-a": MEMBERS})
    store = open_store(
        context.module,
        database,
        timeout_seconds=10,
        transaction_id_factory=lambda: "tx-release-hard-exit",
    )
    try:
        reserved = store.begin(
            make_request(
                context.module,
                key="release-hard-exit-key",
                vm_id="vm-release-hard-exit",
                run_id="run-release-hard-exit",
            )
        )
        preparing = store.prepare(
            reserved.transaction_id, reserved.vm_generation, reserved.revision
        )
        attached = store.commit(
            preparing.transaction_id, preparing.vm_generation, preparing.revision
        )
        releasing = store.begin_release(
            attached.transaction_id, attached.vm_generation, attached.revision
        )
    finally:
        store.close()
    before = store_snapshot(
        context.module,
        database,
        transaction_id="tx-release-hard-exit",
        vm_id="vm-release-hard-exit",
    )
    payload, child_result = payload_path(
        native,
        mode="release-hard-exit",
        database=database,
        transaction_id="tx-release-hard-exit",
        extra={
            "vmGeneration": releasing.vm_generation,
            "expectedRevision": releasing.revision,
            "nextDeviceGenerations": {MEMBERS[0]: 8, MEMBERS[1]: 9},
            "nextAuthorityEpoch": EPOCH + 1,
        },
    )
    process = run_child(context, payload, artifact)
    after = store_snapshot(
        context.module,
        database,
        transaction_id="tx-release-hard-exit",
        vm_id="vm-release-hard-exit",
    )
    checks = {
        "hardExitObserved": process["returnCode"] == RELEASE_HARD_EXIT,
        "stateRetained": after["record"]["state"] == "RELEASING",
        "recordUnchanged": before["record"] == after["record"],
        "claimsUnchanged": before["claimedMembers"] == after["claimedMembers"]
        and before["claimedBundles"] == after["claimedBundles"],
        "journalUnchanged": before["journal"] == after["journal"],
        "deviceGenerationsUnchanged": before["deviceGenerations"]
        == after["deviceGenerations"],
        "rawTableCountsUnchanged": before["database"]["tableCounts"]
        == after["database"]["tableCounts"],
    }
    require(all(checks.values()), f"release crash checks failed: {checks}")
    return retain_case(
        database,
        artifact,
        {
            "schemaVersion": 1,
            "caseId": case_id,
            "passed": True,
            "process": process,
            "checks": checks,
            "before": before,
            "after": after,
            "fault": "os._exit at RELEASE_CLEAN_BEFORE_COMMIT",
            "cleanupEvidence": "TEST_ASSERTION_ONLY",
        },
        child_result,
    )


CASE_RUNNERS: tuple[tuple[str, Callable[[RunContext], dict[str, Any]]], ...] = (
    ("begin-hard-exit", case_begin_crash),
    ("S03", case_s03),
    ("S04", case_s04),
    ("S05", case_s05),
    ("F00", case_f00),
    ("concurrent-overlap", case_concurrent_overlap),
    ("release-hard-exit", case_release_crash),
)


def retained_artifact_hashes(output: Path) -> dict[str, str]:
    return {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name not in {"hashes.json", "summary.json"}
    }


def validate_public_args(args: argparse.Namespace) -> None:
    if not sys.platform.startswith("linux") or os.name != "posix":
        raise RuntimeError("this fault runner requires Linux/WSL SIGKILL semantics")
    if not args.source.is_file():
        raise FileNotFoundError(f"Static lease source is not a file: {args.source}")
    if args.output_dir.exists():
        raise FileExistsError(f"output directory must not already exist: {args.output_dir}")
    state_base = args.state_root.resolve()
    state_text = state_base.as_posix()
    if state_text == "/mnt" or state_text.startswith("/mnt/"):
        raise RuntimeError(
            "live SQLite state must be WSL-native; /mnt/... (including /mnt/e) is rejected"
        )


def public_main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run WSL-native subprocess faults against StaticLeaseStore"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--state-root",
        type=Path,
        default=Path.home() / ".qman-static-lease-fault-state",
        help="WSL-native parent for temporary live SQLite databases",
    )
    args = parser.parse_args(arguments)
    args.output_dir = args.output_dir.resolve()
    args.source = args.source.resolve()
    args.state_root = args.state_root.resolve()
    validate_public_args(args)

    args.output_dir.mkdir(parents=True)
    args.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    source_bytes = args.source.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)
    runner_path = Path(__file__).resolve()
    shutil.copy2(args.source, args.output_dir / "embedded-static-lease.py")

    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    persistence_boundary = ""
    native_run_path = ""
    with tempfile.TemporaryDirectory(
        prefix="run-", dir=args.state_root
    ) as temporary:
        native_root = Path(temporary)
        native_run_path = str(native_root)
        pinned_source = native_root / "pinned-static-lease.py"
        pinned_source.write_bytes(source_bytes)
        require(
            sha256_file(pinned_source) == source_sha256,
            "native pinned source copy changed",
        )
        module = load_pinned_module(pinned_source, source_sha256)

        probe_db = native_root / "provenance-probe.sqlite3"
        probe = open_store(module, probe_db)
        persistence_boundary = probe.persistence_boundary
        probe.close()
        for suffix in ("", "-wal", "-shm"):
            probe_file = Path(str(probe_db) + suffix)
            if probe_file.exists():
                probe_file.unlink()

        context = RunContext(
            module=module,
            runner_path=runner_path,
            pinned_source=pinned_source,
            source_sha256=source_sha256,
            native_root=native_root,
            output_root=args.output_dir,
            persistence_boundary=persistence_boundary,
        )
        for case_id, runner in CASE_RUNNERS:
            started = time.monotonic()
            try:
                result = runner(context)
                result["durationSeconds"] = round(time.monotonic() - started, 3)
                write_json(args.output_dir / case_id / "result.json", result)
                results.append(result)
            except BaseException as error:
                failure = {
                    "caseId": case_id,
                    "errorType": type(error).__name__,
                    "detail": str(error),
                    "traceback": traceback.format_exc(),
                }
                failures.append(failure)
                case_output = args.output_dir / case_id
                case_output.mkdir(exist_ok=True)
                write_json(case_output / "failure.json", failure)
                results.append(
                    {
                        "schemaVersion": 1,
                        "caseId": case_id,
                        "passed": False,
                        "error": failure,
                        "durationSeconds": round(time.monotonic() - started, 3),
                    }
                )

    input_hashes = {
        "runner": {"path": str(runner_path), "sha256": sha256_file(runner_path)},
        "staticLeaseSource": {
            "path": str(args.source),
            "sha256": source_sha256,
        },
        "embeddedStaticLeaseSource": {
            "path": str(args.output_dir / "embedded-static-lease.py"),
            "sha256": sha256_file(args.output_dir / "embedded-static-lease.py"),
        },
    }
    hashes = {
        "schemaVersion": 1,
        "algorithm": "sha256",
        "inputs": input_hashes,
        "retainedArtifacts": retained_artifact_hashes(args.output_dir),
    }
    write_json(args.output_dir / "hashes.json", hashes)
    verdict = "pass" if not failures and all(item["passed"] for item in results) else "fail"
    summary = {
        "schemaVersion": 1,
        "id": "QMAN-E3-STATIC-LEASE-FAULT-001",
        "test": "qman-static-lease-subprocess-faults",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subject": "QMAN_COMPONENT",
        "claimScope": "COMPONENT_ONLY",
        "evidenceGrade": "E3",
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "execution": "Linux/WSL native SQLite plus real child processes",
            "temporaryNativeStateRoot": native_run_path,
            "temporaryStateRemovedAfterRun": True,
            "persistenceBoundary": persistence_boundary,
            "liveDatabaseUnderMnt": False,
        },
        "inputs": input_hashes,
        "claims": {
            "sourceBytesPinnedAndHashCheckedInEveryChild": True,
            "liveSQLiteUsesNormalFilesystemProvenanceGate": True,
            "beginHardExitLeavesNoPartialLease": True,
            "cleanRollbackAdvancesAllMemberGenerationsAndReleasesAtomically": True,
            "resetFailureQuarantinesWholeBundle": True,
            "missingCleanupEvidenceQuarantinesWholeBundle": True,
            "actualSigkillOfAttachedSimulatedOwnerRetainsClaims": True,
            "overlappingMultiprocessBeginHasExactlyOneWinner": True,
            "releaseHardExitRetainsPriorStateClaimsJournalAndGenerations": True,
            "actualVfioBindResetOrQemuOperations": False,
        },
        "cases": results,
        "mapping": {
            "techStories": ["TS-F3-02", "TS-F3-05", "TS-F5-03", "TS-F5-04"],
            "casePremisesOnly": ["S03", "S04", "S05", "F00"],
            "caseClosures": [],
            "riskClosures": [],
        },
        "limitations": [
            "This is Qman component evidence for the SQLite lease/FSM boundary only.",
            "Bind, reset, cleanup verification, VFIO and QEMU phases are simulated labels; no external device operation is performed.",
            "The S03 cleanup_verified value is a test assertion, not independently authenticated cleanup evidence.",
            "F00 SIGKILL targets a Python process standing in for an owner, not a QEMU process.",
            "SQLite WAL/FULL and the filesystem provenance gate do not prove end-to-end power-loss durability.",
            "The fixed lab authority is passed through the schema-v3 trusted_authority_id gate; this runner does not prove a product inventory publisher.",
            "It does not close S03, S04, S05, F00 or any product risk.",
        ],
        "failures": failures,
        "hashSummary": {
            "path": str(args.output_dir / "hashes.json"),
            "sha256": sha256_file(args.output_dir / "hashes.json"),
        },
        "verdict": verdict,
    }
    write_json(args.output_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if verdict == "pass" else 1


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--_child":
        try:
            return child_main(sys.argv[2:])
        except BaseException:
            traceback.print_exc()
            return 1
    return public_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
