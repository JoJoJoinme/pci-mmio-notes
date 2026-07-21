#!/usr/bin/env python3
"""WSL-native subprocess faults for ``AuthoritativeSnapshotStore``.

The live SQLite databases are created only on a Linux-native filesystem.  The
requested output directory may be on DrvFS because it retains evidence/cache
artifacts, never authoritative state.  A complete copy of the Python package is
staged on the native filesystem and every child verifies its deterministic
source-tree hash before importing it.

This runner proves a Qman component boundary only.  The HMAC authenticator is
``COMPONENT_AUTHENTICITY_ONLY`` and is intentionally not presented as a
production trust root or external rollback anchor.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping, Sequence


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_MODEL_ROOT = REPO_ROOT / "pci-resource-model"

HOST = "qman-wsl-snapshot-host-a"
AUTHORITY = "qman-snapshot-component-publisher-v1"
KEY_ID = "qman-snapshot-component-key-v1"
KEY = b"qman-snapshot-component-fault-key-v1-0123456789abcdef"
BDF1 = "0000:65:00.0"
BDF2 = "0000:65:00.1"
MEMBERS = (BDF1, BDF2)
FIXED_CLOCK = datetime(2026, 7, 21, 2, 3, 4, tzinfo=timezone.utc)

CRASH_EXIT = 91
CHILD_TIMEOUT_SECONDS = 30
BARRIER_TIMEOUT_SECONDS = 20


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def python_tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*.py") if path.is_file())
    if not files:
        raise RuntimeError(f"no Python source below {root}")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
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


def wait_for_path(path: Path, timeout: float = BARRIER_TIMEOUT_SECONDS) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {path.name}")


@dataclass(frozen=True)
class Api:
    snapshot: ModuleType
    model: ModuleType
    vfio: ModuleType


def load_api(model_root: Path, expected_tree_hash: str) -> Api:
    model_root = model_root.resolve(strict=True)
    actual = python_tree_hash(model_root / "pci_resource_model")
    if actual != expected_tree_hash:
        raise RuntimeError(
            "pinned pci_resource_model tree hash mismatch: "
            f"expected {expected_tree_hash}, actual {actual}"
        )
    root_text = str(model_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return Api(
        snapshot=importlib.import_module(
            "pci_resource_model.authoritative_snapshot"
        ),
        model=importlib.import_module("pci_resource_model.model"),
        vfio=importlib.import_module("pci_resource_model.vfio_provider"),
    )


def pci_identity(api: Api, *, device_id: int = 0x10D3) -> Any:
    return api.vfio.PciIdentity(
        vendor_id=0x8086,
        device_id=device_id,
        subsystem_vendor_id=0x8086,
        subsystem_device_id=0xA01F,
        class_code=0x020000,
        revision=2,
    )


def device(api: Api, bdf: str, *, generation: int) -> Any:
    return api.model.DeviceInventory(
        bdf=bdf,
        vendor_id=0x8086,
        device_id=0x10D3,
        class_code=0x020000,
        header_type=0,
        function_role=api.model.FunctionRole.ENDPOINT,
        iommu_group=MEMBERS,
        physical_isolation_domain=MEMBERS,
        physical_isolation_domain_source="stock-kernel-iommu-group",
        reset_methods=("flr",),
        reset_domain=(bdf,),
        reset_domain_source="sysfs-function-reset",
        multifunction_aliases=MEMBERS,
        multifunction_source="linux-slot-scan",
        owner_activation_group="bundle-a",
        exclusive_attach_group="bundle-a",
        isolation_provenance=api.model.IsolationProvenance.KERNEL_GROUP,
        dma_isolation_mode=api.model.DmaIsolationMode.IOMMU,
        dma_isolation_source="linux-iommu-group",
        driver="vfio-pci",
        acs_native_isolation=True,
        acs_effective_isolation=True,
        acs_override_source="none",
        device_generation=generation,
    )


def make_capture(
    api: Api,
    boot_id: str,
    *,
    first_device_id: int = 0x10D3,
) -> Any:
    inventory = api.model.HostInventory(
        iommu_present=True,
        interrupt_remapping=True,
        no_iommu_mode=False,
        acs_override_active=False,
        devices={
            BDF1: device(api, BDF1, generation=3),
            BDF2: device(api, BDF2, generation=4),
        },
        source="qman-wsl-component-double-capture",
        metadata={
            "scannedDeviceCount": 2,
            "returnedDeviceCount": 2,
        },
        host_id=HOST,
        kernel_boot_id=boot_id,
        inventory_epoch=None,
        topology_hash="0" * 64,
    )
    return api.snapshot.SnapshotCapture(
        inventory=inventory,
        launch_facts={
            BDF1: api.snapshot.LaunchDeviceFacts(
                bdf=BDF1,
                identity=pci_identity(api, device_id=first_device_id),
                iommu_group="7",
                group_members=MEMBERS,
                device_generation=3,
            ),
            BDF2: api.snapshot.LaunchDeviceFacts(
                bdf=BDF2,
                identity=pci_identity(api),
                iommu_group="7",
                group_members=MEMBERS,
                device_generation=4,
            ),
        },
    )


def open_store(
    api: Api,
    database: Path,
    boot_id: str,
    *,
    timeout_seconds: float = 10,
    fault_hook: Callable[[str], None] | None = None,
) -> Any:
    return api.snapshot.AuthoritativeSnapshotStore(
        database.resolve(),
        local_host_id=HOST,
        trusted_authority_id=AUTHORITY,
        authenticator=api.snapshot.ComponentHmacAuthenticator({KEY_ID: KEY}),
        current_boot_id=lambda: boot_id,
        timeout_seconds=timeout_seconds,
        clock=lambda: FIXED_CLOCK,
        fault_hook=fault_hook,
    )


def publish(api: Api, store: Any, boot_id: str, expected: str | None) -> Any:
    capture = make_capture(api, boot_id)
    return store.capture_and_publish(
        lambda: capture,
        key_id=KEY_ID,
        expected_current_hash=expected,
    )


def database_observation(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(database)
    try:
        epochs = [
            int(row[0])
            for row in connection.execute(
                "SELECT inventory_epoch FROM snapshots ORDER BY inventory_epoch"
            ).fetchall()
        ]
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        return {"epochs": epochs, "integrityCheck": integrity}
    finally:
        connection.close()


def child_crash_publish(args: argparse.Namespace, api: Api) -> int:
    def fault(stage: str) -> None:
        if stage == "PUBLISH_AFTER_INSERT":
            os._exit(CRASH_EXIT)

    store = open_store(api, args.database, args.boot_id, fault_hook=fault)
    publish(api, store, args.boot_id, args.expected_hash)
    raise AssertionError("PUBLISH_AFTER_INSERT hard-exit fault did not fire")


def child_race_publish(args: argparse.Namespace, api: Api) -> int:
    store = open_store(api, args.database, args.boot_id, timeout_seconds=20)
    try:
        write_json(args.ready_file, {"ready": True})
        wait_for_path(args.start_file)
        try:
            record = publish(api, store, args.boot_id, args.expected_hash)
            result = {
                "epoch": record.inventory_epoch,
                "outcome": "PUBLISHED",
            }
        except api.snapshot.SnapshotError as error:
            if error.reason is not api.snapshot.SnapshotReason.PUBLISH_CONFLICT:
                raise
            result = {
                "epoch": None,
                "outcome": error.reason.value,
            }
        write_json(args.result_file, result)
        return 0
    finally:
        store.close()


def child_main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("action", choices=("crash-publish", "race-publish"))
    parser.add_argument("--model-root", type=Path, required=True)
    parser.add_argument("--tree-sha256", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--expected-hash", required=True)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--start-file", type=Path)
    parser.add_argument("--result-file", type=Path)
    args = parser.parse_args(arguments)
    api = load_api(args.model_root, args.tree_sha256)
    if args.action == "crash-publish":
        return child_crash_publish(args, api)
    if None in (args.ready_file, args.start_file, args.result_file):
        raise ValueError("race child requires ready/start/result files")
    return child_race_publish(args, api)


@dataclass(frozen=True)
class RunContext:
    api: Api
    runner: Path
    model_root: Path
    tree_sha256: str
    native_root: Path
    output_root: Path
    boot_id: str
    persistence_boundary: str


def child_command(
    context: RunContext,
    action: str,
    database: Path,
    expected_hash: str,
    *extra: str,
) -> list[str]:
    return [
        sys.executable,
        str(context.runner),
        "--_child",
        action,
        "--model-root",
        str(context.model_root),
        "--tree-sha256",
        context.tree_sha256,
        "--database",
        str(database),
        "--boot-id",
        context.boot_id,
        "--expected-hash",
        expected_hash,
        *extra,
    ]


def child_environment(context: RunContext) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(context.model_root)
    return environment


def finish_child(process: subprocess.Popen[str]) -> tuple[int, str]:
    try:
        output, _ = process.communicate(timeout=CHILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate(timeout=5)
        raise TimeoutError(f"child {process.args!r} timed out; output={output}")
    return int(process.returncode), output


def run_publish_hard_exit(context: RunContext) -> dict[str, Any]:
    database = context.native_root / "hard-exit.sqlite3"
    store = open_store(context.api, database, context.boot_id)
    first = publish(context.api, store, context.boot_id, None)
    store.close()

    process = subprocess.Popen(
        child_command(
            context,
            "crash-publish",
            database,
            first.snapshot_hash,
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=child_environment(context),
    )
    return_code, output = finish_child(process)
    require(
        return_code == CRASH_EXIT,
        f"hard-exit child rc={return_code}, output={output}",
    )

    reopened = open_store(context.api, database, context.boot_id)
    try:
        current = reopened.current()
        observation = database_observation(database)
        require(current.snapshot_hash == first.snapshot_hash, "old snapshot hash changed")
        require(current.inventory_epoch == 1, "uncommitted epoch became visible")
        require(observation["epochs"] == [1], "partial snapshot row survived crash")
        require(observation["integrityCheck"] == "ok", "SQLite integrity check failed")
    finally:
        reopened.close()
    return {
        "caseId": "F01_PUBLISH_AFTER_INSERT_HARD_EXIT",
        "passed": True,
        "observed": {
            "childExitCode": return_code,
            "committedEpochsAfterReopen": [1],
            "oldCommittedSnapshotRetained": True,
            "partialEpochVisible": False,
            "sqliteIntegrityCheck": "ok",
        },
    }


def run_concurrent_cas(context: RunContext) -> dict[str, Any]:
    database = context.native_root / "concurrent-cas.sqlite3"
    store = open_store(context.api, database, context.boot_id)
    first = publish(context.api, store, context.boot_id, None)
    store.close()

    barrier = context.native_root / "race-barrier"
    barrier.mkdir()
    start = barrier / "start"
    processes: list[subprocess.Popen[str]] = []
    results: list[Path] = []
    for index in range(2):
        ready = barrier / f"ready-{index}.json"
        result = barrier / f"result-{index}.json"
        results.append(result)
        command = child_command(
            context,
            "race-publish",
            database,
            first.snapshot_hash,
            "--ready-file",
            str(ready),
            "--start-file",
            str(start),
            "--result-file",
            str(result),
        )
        processes.append(
            subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=child_environment(context),
            )
        )
    for index in range(2):
        wait_for_path(barrier / f"ready-{index}.json")
    write_json(start, {"start": True})
    child_outputs = [finish_child(process) for process in processes]
    require(
        all(return_code == 0 for return_code, _output in child_outputs),
        f"race child failed: {child_outputs}",
    )
    outcomes = [read_json(path) for path in results]
    normalized = sorted(item["outcome"] for item in outcomes)
    require(
        normalized == ["PUBLISHED", "PUBLISH_CONFLICT"],
        f"unexpected race outcomes {normalized}",
    )

    reopened = open_store(context.api, database, context.boot_id)
    try:
        current = reopened.current()
        observation = database_observation(database)
        require(current.inventory_epoch == 2, "winner did not publish epoch 2")
        require(observation["epochs"] == [1, 2], "epochs are not strictly monotonic")
        try:
            publish(context.api, reopened, context.boot_id, first.snapshot_hash)
        except context.api.snapshot.SnapshotError as error:
            require(
                error.reason is context.api.snapshot.SnapshotReason.PUBLISH_CONFLICT,
                f"stale CAS returned {error.reason}",
            )
            stale_cas_reason = error.reason.value
        else:
            raise AssertionError("stale CAS unexpectedly published")
        require(reopened.current().inventory_epoch == 2, "stale CAS advanced epoch")
    finally:
        reopened.close()
    return {
        "caseId": "C01_CONCURRENT_CAS_SINGLE_WINNER",
        "passed": True,
        "observed": {
            "attemptCount": 2,
            "committedEpochs": [1, 2],
            "conflictCount": 1,
            "publishWinnerCount": 1,
            "staleCasReason": stale_cas_reason,
            "strictlyMonotonicEpoch": True,
        },
    }


def set_envelope(database: Path, epoch: int, envelope: Mapping[str, Any]) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE snapshots SET envelope_json=? WHERE inventory_epoch=?",
            (json.dumps(envelope, sort_keys=True, separators=(",", ":")), epoch),
        )
        connection.commit()
    finally:
        connection.close()


def current_reason(context: RunContext, database: Path, boot_id: str) -> str:
    store = open_store(context.api, database, boot_id)
    try:
        store.current()
    except context.api.snapshot.SnapshotError as error:
        return error.reason.value
    finally:
        store.close()
    raise AssertionError("tampered snapshot unexpectedly verified")


def run_authenticity_replay_boot(context: RunContext) -> dict[str, Any]:
    database = context.native_root / "negative-gates.sqlite3"
    store = open_store(context.api, database, context.boot_id)
    first = publish(context.api, store, context.boot_id, None)
    second = publish(context.api, store, context.boot_id, first.snapshot_hash)
    store.close()

    connection = sqlite3.connect(database)
    try:
        original_text = str(
            connection.execute(
                "SELECT envelope_json FROM snapshots WHERE inventory_epoch=2"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    original = json.loads(original_text)

    signature_tamper = dict(original)
    signature_tamper["signature"] = "0" * 64
    set_envelope(database, 2, signature_tamper)
    signature_reason = current_reason(context, database, context.boot_id)
    require(
        signature_reason == "SNAPSHOT_SIGNATURE_INVALID",
        f"signature tamper returned {signature_reason}",
    )

    set_envelope(database, 2, original)
    payload_tamper = json.loads(original_text)
    payload_tamper["capture"]["inventory"]["host"][
        "unsafeNoIommuModeEnabled"
    ] = True
    set_envelope(database, 2, payload_tamper)
    payload_reason = current_reason(context, database, context.boot_id)
    require(
        payload_reason == "SNAPSHOT_HASH_MISMATCH",
        f"payload tamper returned {payload_reason}",
    )

    set_envelope(database, 2, original)
    boot_reason = current_reason(context, database, context.boot_id + "-changed")
    require(boot_reason == "BOOT_ID_CHANGED", f"boot drift returned {boot_reason}")

    replay_store = open_store(context.api, database, context.boot_id)
    try:
        try:
            with replay_store.authorize_launch(first.snapshot_hash, MEMBERS):
                raise AssertionError("old snapshot authorization was issued")
        except context.api.snapshot.SnapshotError as error:
            require(
                error.reason is context.api.snapshot.SnapshotReason.SNAPSHOT_STALE,
                f"old snapshot replay returned {error.reason}",
            )
            replay_reason = error.reason.value
        try:
            replay_store.current(minimum_epoch=second.inventory_epoch + 1)
        except context.api.snapshot.SnapshotError as error:
            require(
                error.reason is context.api.snapshot.SnapshotReason.SNAPSHOT_STALE,
                f"minimum epoch gate returned {error.reason}",
            )
            minimum_epoch_reason = error.reason.value
        else:
            raise AssertionError("minimum epoch replay gate accepted stale state")
    finally:
        replay_store.close()
    return {
        "caseId": "N01_AUTHENTICITY_REPLAY_BOOT_GATES",
        "passed": True,
        "observed": {
            "bootDriftReason": boot_reason,
            "minimumEpochReason": minimum_epoch_reason,
            "oldSnapshotAuthorizationReason": replay_reason,
            "payloadTamperReason": payload_reason,
            "signatureTamperReason": signature_reason,
        },
    }


def run_earlier_valid_state_replay(context: RunContext) -> dict[str, Any]:
    """Demonstrate the explicit no-external-anchor rollback boundary."""

    database = context.native_root / "earlier-valid-state-replay.sqlite3"
    store = open_store(context.api, database, context.boot_id)
    first = publish(context.api, store, context.boot_id, None)
    second = publish(context.api, store, context.boot_id, first.snapshot_hash)
    original_store_instance_id = store.store_instance_id
    original_inode = database.stat().st_ino
    store.close()

    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "DELETE FROM snapshots WHERE inventory_epoch=?",
            (second.inventory_epoch,),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = open_store(context.api, database, context.boot_id)
    try:
        accepted = reopened.current()
        require(
            accepted.snapshot_hash == first.snapshot_hash,
            "earlier still-valid state was not accepted as the current snapshot",
        )
        require(database.stat().st_ino == original_inode, "database inode changed")
        require(
            reopened.store_instance_id == original_store_instance_id,
            "store instance identity changed",
        )
    finally:
        reopened.close()

    return {
        "caseId": "L01_EARLIER_VALID_STATE_REPLAY_BOUNDARY",
        "passed": True,
        "observed": {
            "acceptedInventoryEpoch": first.inventory_epoch,
            "deletedNewestInventoryEpoch": second.inventory_epoch,
            "earlierValidStateAccepted": True,
            "externalMonotonicRollbackAnchorPresent": False,
            "sameDatabaseInode": True,
            "sameStoreInstanceId": True,
        },
    }


CASE_RUNNERS: tuple[tuple[str, Callable[[RunContext], dict[str, Any]]], ...] = (
    ("F01", run_publish_hard_exit),
    ("C01", run_concurrent_cas),
    ("N01", run_authenticity_replay_boot),
    ("L01", run_earlier_valid_state_replay),
)


def retained_artifact_hashes(output_root: Path) -> dict[str, str]:
    return {
        path.relative_to(output_root).as_posix(): sha256_file(path)
        for path in sorted(output_root.rglob("*"))
        if path.is_file() and path.name not in {"hashes.json", "summary.json"}
    }


def validate_public_args(args: argparse.Namespace) -> None:
    if not sys.platform.startswith("linux") or os.name != "posix":
        raise RuntimeError("this runner requires Linux/WSL subprocess semantics")
    package = args.model_root / "pci_resource_model"
    if not (package / "authoritative_snapshot.py").is_file():
        raise FileNotFoundError(f"authoritative snapshot source is absent: {package}")
    if args.output_dir.exists():
        raise FileExistsError(f"output directory must not already exist: {args.output_dir}")
    state_text = args.state_root.resolve().as_posix()
    if state_text == "/mnt" or state_text.startswith("/mnt/"):
        raise RuntimeError(
            "live SQLite state must be WSL-native; /mnt/... is rejected"
        )


def public_main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run WSL-native subprocess faults against AuthoritativeSnapshotStore"
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-root", type=Path, default=DEFAULT_MODEL_ROOT)
    parser.add_argument(
        "--state-root",
        type=Path,
        default=Path.home() / ".qman-authoritative-snapshot-fault-state",
        help="Linux-native parent for temporary live SQLite databases",
    )
    args = parser.parse_args(arguments)
    args.output_dir = args.output_dir.resolve()
    args.model_root = args.model_root.resolve()
    args.state_root = args.state_root.resolve()
    validate_public_args(args)

    args.output_dir.mkdir(parents=True)
    args.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner = Path(__file__).resolve()

    results: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    persistence_boundary = ""
    source_tree_sha256 = ""
    pinned_source_sha256 = ""
    with tempfile.TemporaryDirectory(prefix="run-", dir=args.state_root) as temporary:
        native_root = Path(temporary).resolve()
        staged_model_root = native_root / "pinned-model"
        source_tree_before_pin = python_tree_hash(
            args.model_root / "pci_resource_model"
        )
        shutil.copytree(
            args.model_root / "pci_resource_model",
            staged_model_root / "pci_resource_model",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        source_tree_sha256 = python_tree_hash(
            staged_model_root / "pci_resource_model"
        )
        source_tree_after_pin = python_tree_hash(
            args.model_root / "pci_resource_model"
        )
        require(
            source_tree_before_pin == source_tree_sha256 == source_tree_after_pin,
            "model source tree changed while the executable snapshot was pinned",
        )
        pinned_source = (
            staged_model_root
            / "pci_resource_model"
            / "authoritative_snapshot.py"
        )
        pinned_source_sha256 = sha256_file(pinned_source)
        shutil.copy2(
            pinned_source,
            args.output_dir / "embedded-authoritative_snapshot.py",
        )
        api = load_api(staged_model_root, source_tree_sha256)
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
        require(boot_id not in {"", "unknown"}, "kernel boot ID is unavailable")

        probe_path = native_root / "provenance-probe.sqlite3"
        probe = open_store(api, probe_path, boot_id)
        persistence_boundary = probe.persistence_boundary
        probe.close()
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(probe_path) + suffix)
            if candidate.exists():
                candidate.unlink()

        context = RunContext(
            api=api,
            runner=runner,
            model_root=staged_model_root,
            tree_sha256=source_tree_sha256,
            native_root=native_root,
            output_root=args.output_dir,
            boot_id=boot_id,
            persistence_boundary=persistence_boundary,
        )
        for case_id, runner_fn in CASE_RUNNERS:
            try:
                result = runner_fn(context)
                write_json(args.output_dir / case_id / "result.json", result)
                results.append(result)
            except BaseException as error:
                failure = {
                    "caseId": case_id,
                    "detail": str(error),
                    "errorType": type(error).__name__,
                    "traceback": traceback.format_exc(),
                }
                failures.append(failure)
                write_json(args.output_dir / case_id / "failure.json", failure)
                results.append(
                    {
                        "caseId": case_id,
                        "error": {
                            "detail": str(error),
                            "errorType": type(error).__name__,
                        },
                        "passed": False,
                    }
                )

    source_tree_stable = (
        python_tree_hash(args.model_root / "pci_resource_model")
        == source_tree_sha256
    )
    if not source_tree_stable:
        failures.append(
            {
                "caseId": "SOURCE_PIN",
                "detail": "model source tree changed after the executable snapshot was pinned",
                "errorType": "SourceTreeChangedDuringRun",
            }
        )
    inputs = {
        "authoritativeSnapshotSource": {
            "sha256": pinned_source_sha256,
        },
        "pinnedPythonTree": {
            "sha256": source_tree_sha256,
        },
        "runner": {
            "sha256": sha256_file(runner),
        },
    }
    hashes = {
        "algorithm": "sha256",
        "inputs": inputs,
        "retainedArtifacts": retained_artifact_hashes(args.output_dir),
        "schemaVersion": 1,
    }
    write_json(args.output_dir / "hashes.json", hashes)
    verdict = "pass" if not failures and all(item["passed"] for item in results) else "fail"
    passed_cases = {
        str(item.get("caseId")): item.get("passed") is True for item in results
    }
    summary = {
        "caseClosures": [],
        "cases": results,
        "claimScope": "COMPONENT_ONLY",
        "claims": {
            "actualSubprocessHardExitAtPublishAfterInsert": passed_cases.get(
                "F01_PUBLISH_AFTER_INSERT_HARD_EXIT", False
            ),
            "concurrentCasHasExactlyOneWinner": passed_cases.get(
                "C01_CONCURRENT_CAS_SINGLE_WINNER", False
            ),
            "hmacAuthenticityBoundary": "COMPONENT_AUTHENTICITY_ONLY",
            "liveDatabaseUnderMnt": False,
            "monotonicEpochsObserved": (
                [1, 2]
                if passed_cases.get("C01_CONCURRENT_CAS_SINGLE_WINNER", False)
                else []
            ),
            "oldCommittedSnapshotSurvivesHardExit": passed_cases.get(
                "F01_PUBLISH_AFTER_INSERT_HARD_EXIT", False
            ),
            "payloadSignatureReplayAndBootNegativeGates": passed_cases.get(
                "N01_AUTHENTICITY_REPLAY_BOOT_GATES", False
            ),
            "sourceTreePinnedAndCheckedInEveryChild": (
                source_tree_stable and verdict == "pass"
            ),
        },
        "environment": {
            "execution": "Linux/WSL native SQLite plus real child processes",
            "persistenceBoundary": persistence_boundary,
            "platform": platform.system(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "sourceTreeStableThroughCompletion": source_tree_stable,
            "temporaryStateRemovedAfterRun": True,
        },
        "evidenceGrade": "E3",
        "failures": failures,
        "id": "QMAN-E3-AUTHORITATIVE-SNAPSHOT-FAULT-001",
        "inputs": inputs,
        "limitations": [
            "This is Qman component evidence for one host-local SQLite snapshot authority only.",
            "The HMAC signer and verifier share a component key; this is not a production trust root, TPM-backed signer, or multi-host authority.",
            "Without an external monotonic rollback anchor, any replay of an earlier still-valid SQLite state can be accepted, including same-key in-place/block restoration or deletion of the newest rows; inode and store UUID checks do not provide anti-rollback.",
            "SQLite WAL/FULL and the filesystem provenance gate do not prove end-to-end power-loss durability.",
            "The synthetic PCI capture exercises snapshot contracts only; it performs no VFIO bind, reset, DMA, IRQ, or QEMU operation.",
            "No acceptance Case, product Risk, milestone, or release gate is closed by this runner.",
        ],
        "mapping": {
            "casePremisesOnly": [],
            "riskClosures": [],
            "techStories": ["TS-F1-01"],
        },
        "schemaVersion": 1,
        "subject": "QMAN_COMPONENT",
        "test": "qman-authoritative-snapshot-subprocess-faults",
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
            return 2
    try:
        return public_main(sys.argv[1:])
    except BaseException:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
