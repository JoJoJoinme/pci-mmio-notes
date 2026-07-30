from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from qman_directpath_reference import (
    AFTER_AVAILABILITY_ABSENCE_READ,
    AFTER_COMMIT_BEFORE_RETURN,
    EVIDENCE_BOUNDARY,
    WRITE_FAULT_STAGES,
    DeterministicReferenceEvaluator,
    ReferenceEvaluation,
    ReferenceRepositoryError,
    ReferenceRepositoryReason,
    ReferenceSelectionPremise,
    SqliteReferenceStaticAdmissionRepository,
    StaticAdmissionCommand,
    StaticAdmissionRequestReference,
    canonical_json_bytes,
    sha256_digest,
)


NOW = "2026-07-24T12:00:00.000000Z"
DEADLINE = "2026-07-24T13:00:00.000000Z"
EVALUATION_VALID_UNTIL = "2026-07-24T14:00:00.000000Z"
CURRENT_VALID_UNTIL = "2026-07-24T15:00:00.000000Z"
WORKER = Path(__file__).with_name("repository_worker.py")


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def blob_value(label: str) -> dict[str, str]:
    return {"fixture": label}


def blob_hash(label: str) -> str:
    return sha256_digest(canonical_json_bytes(blob_value(label)))


def evaluator_for(
    specs: dict[str, tuple[str, str, tuple[str, ...]]],
) -> DeterministicReferenceEvaluator:
    return DeterministicReferenceEvaluator(
        {
            vm_id: ReferenceSelectionPremise(
                bundle_id=digest(f"bundle:{bundle_label}"),
                scope_hash=digest(f"scope:{scope_label}"),
                member_ids=member_ids,
                evidence_blob_hashes=(blob_hash(f"evaluation:{vm_id}"),),
                valid_until=EVALUATION_VALID_UNTIL,
            )
            for vm_id, (bundle_label, scope_label, member_ids) in specs.items()
        }
    )


def seed_store(
    repository: SqliteReferenceStaticAdmissionRepository,
    specs: dict[str, tuple[str, str, tuple[str, ...]]],
) -> dict[str, StaticAdmissionCommand]:
    admin = repository.reference_only_bootstrap_admin()
    labels = {
        "controller",
        "artifact:CATALOG",
        "artifact:INVENTORY",
        "artifact:POLICY",
        "artifact:TRUST",
        *(f"request:{vm_id}" for vm_id in specs),
        *(f"evaluation:{vm_id}" for vm_id in specs),
        *(
            f"member:{member_id}"
            for _, _, member_ids in specs.values()
            for member_id in member_ids
        ),
    }
    blobs = {
        label: admin.put_immutable_blob("schema:reference-fixture", blob_value(label))
        for label in sorted(labels)
    }
    admin.set_controller_current(
        controller_generation=7,
        authority_lease_id="controller-authority-lease-1",
        resource_version=11,
        expires_at=CURRENT_VALID_UNTIL,
        blob_sha256=blobs["controller"],
    )
    for sequence, kind in enumerate(
        ("CATALOG", "INVENTORY", "POLICY", "TRUST"),
        start=21,
    ):
        admin.set_current_artifact(
            kind=kind,
            authority_id=f"authority-{kind.lower()}",
            sequence=sequence,
            artifact_digest=blobs[f"artifact:{kind}"],
            resource_version=sequence + 100,
            valid_until=CURRENT_VALID_UNTIL,
            blob_sha256=blobs[f"artifact:{kind}"],
        )
    for index, vm_id in enumerate(sorted(specs), start=1):
        admin.set_current_request(
            vm_id=vm_id,
            request_version=index,
            request_hash=blobs[f"request:{vm_id}"],
            resource_version=200 + index,
            blob_sha256=blobs[f"request:{vm_id}"],
        )
    admin.set_global_availability(
        authority_id="availability-authority-1",
        resource_version=300,
    )
    member_ids = sorted(
        {member_id for _, _, members in specs.values() for member_id in members}
    )
    for generation, member_id in enumerate(member_ids, start=31):
        admin.set_availability_member(
            device_id=member_id,
            generation=generation,
            resource_version=400 + generation,
            evidence_blob_hash=blobs[f"member:{member_id}"],
        )
    bundles: dict[str, tuple[str, ...]] = {}
    for bundle_label, _, members in specs.values():
        bundle_id = digest(f"bundle:{bundle_label}")
        previous = bundles.setdefault(bundle_id, members)
        if previous != members:
            raise AssertionError("one fixture bundle has inconsistent membership")
    for bundle_id, members in sorted(bundles.items()):
        admin.set_bundle_members(bundle_id=bundle_id, member_ids=members)

    commands = {}
    for index, vm_id in enumerate(sorted(specs), start=1):
        commands[vm_id] = StaticAdmissionCommand.create(
            command_id=f"command-{vm_id}",
            vm_id=vm_id,
            run_id=f"run-{vm_id}",
            idempotency_key=f"idempotency-{vm_id}",
            actor="controller:reference-test",
            deadline=DEADLINE,
            request_reference=StaticAdmissionRequestReference(
                request_version=index,
                request_hash=blobs[f"request:{vm_id}"],
            ),
        )
    return commands


def selection_payload(
    evaluator: DeterministicReferenceEvaluator,
    specs: dict[str, tuple[str, str, tuple[str, ...]]],
) -> dict[str, object]:
    rebuilt = evaluator_for(specs)
    if rebuilt.premise_digest != evaluator.premise_digest:
        raise AssertionError("worker evaluator premise does not match store")
    return {
        vm_id: ReferenceSelectionPremise(
            bundle_id=digest(f"bundle:{bundle_label}"),
            scope_hash=digest(f"scope:{scope_label}"),
            member_ids=member_ids,
            evidence_blob_hashes=(blob_hash(f"evaluation:{vm_id}"),),
            valid_until=EVALUATION_VALID_UNTIL,
        ).to_wire()
        for vm_id, (bundle_label, scope_label, member_ids) in specs.items()
    }


class InjectedFault(RuntimeError):
    pass


class OmittingMemberEvidenceEvaluator:
    """Malicious premise-compatible evaluator used by one fail-closed test."""

    def __init__(self, delegate: DeterministicReferenceEvaluator) -> None:
        self._delegate = delegate
        self.premise_identity = delegate.premise_identity
        self.premise_digest = delegate.premise_digest

    def evaluate(self, command, current) -> ReferenceEvaluation:
        complete = self._delegate.evaluate(command, current)
        member_evidence = {
            current.member(member.id).evidence_blob_hash
            for member in complete.member_generations
        }
        incomplete = tuple(
            item
            for item in complete.evidence_blob_hashes
            if item not in member_evidence
        )
        return replace(complete, evidence_blob_hashes=incomplete)


class SqliteReferenceRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        self.processes: list[subprocess.Popen[str]] = []
        self.addCleanup(self._terminate_processes)

    def _terminate_processes(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    @staticmethod
    def one_spec() -> dict[str, tuple[str, str, tuple[str, ...]]]:
        return {
            "vm-a": (
                "bundle-a",
                "scope-a",
                ("device-a", "device-b"),
            )
        }

    def make_store(
        self,
        name: str,
        specs: dict[str, tuple[str, str, tuple[str, ...]]] | None = None,
        *,
        evaluator=None,
        fault_hook=None,
        statement_hook=None,
        seed: bool = True,
        clock=lambda: NOW,
    ):
        specs = specs or self.one_spec()
        evaluator = evaluator or evaluator_for(specs)
        repository = SqliteReferenceStaticAdmissionRepository(
            self.root / name,
            evaluator,
            clock=clock,
            fault_hook=fault_hook,
            statement_hook=statement_hook,
        )
        commands = seed_store(repository, specs) if seed else {}
        return repository, evaluator, commands

    def _worker_payload(
        self,
        *,
        name: str,
        database_path: Path,
        evaluator: DeterministicReferenceEvaluator,
        specs: dict[str, tuple[str, str, tuple[str, ...]]],
        mode: str,
        start_path: Path,
        command: StaticAdmissionCommand | None = None,
        hard_exit_stage: str | None = None,
        hard_exit_code: int = 79,
        pause_stage: str | None = None,
        reached_path: Path | None = None,
        release_path: Path | None = None,
        attempted_path: Path | None = None,
        quarantine: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], Path, Path]:
        output_path = self.root / f"{name}.output.json"
        ready_path = self.root / f"{name}.ready"
        payload: dict[str, object] = {
            "databasePath": str(database_path),
            "clock": NOW,
            "selections": selection_payload(evaluator, specs),
            "mode": mode,
            "startPath": str(start_path),
            "readyPath": str(ready_path),
            "outputPath": str(output_path),
            "hardExitStage": hard_exit_stage,
            "hardExitCode": hard_exit_code,
            "pauseStage": pause_stage,
            "reachedPath": None if reached_path is None else str(reached_path),
            "releasePath": None if release_path is None else str(release_path),
            "attemptedPath": (None if attempted_path is None else str(attempted_path)),
        }
        if command is not None:
            payload["command"] = command.to_wire()
        if quarantine is not None:
            payload["quarantine"] = quarantine
        return payload, ready_path, output_path

    def _launch(
        self,
        name: str,
        payload: dict[str, object],
        ready_path: Path,
    ) -> subprocess.Popen[str]:
        payload_path = self.root / f"{name}.payload.json"
        payload_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parents[1])
        environment["PYTHONPATH"] = (
            package_root + os.pathsep + environment.get("PYTHONPATH", "")
        )
        process = subprocess.Popen(
            [sys.executable, str(WORKER), str(payload_path)],
            cwd=package_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(process)
        self._wait_for_file(ready_path, process=process)
        return process

    def _wait_for_file(
        self,
        path: Path,
        *,
        process: subprocess.Popen[str] | None = None,
        timeout: float = 15,
    ) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if process is not None and process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(
                    f"worker exited before {path.name}: "
                    f"rc={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                self.fail(f"timed out waiting for {path}")
            time.sleep(0.01)

    def _normal_worker_result(
        self,
        process: subprocess.Popen[str],
        output_path: Path,
    ) -> dict[str, object]:
        stdout, stderr = process.communicate(timeout=20)
        self.assertEqual(
            0,
            process.returncode,
            f"stdout={stdout!r}, stderr={stderr!r}",
        )
        return json.loads(output_path.read_text(encoding="utf-8"))

    def test_rejects_memory_uri_and_relative_database_paths(self) -> None:
        evaluator = evaluator_for(self.one_spec())
        for path in (":memory:", "file:reference?mode=memory", "relative.db"):
            with (
                self.subTest(path=path),
                self.assertRaises(ReferenceRepositoryError) as caught,
            ):
                SqliteReferenceStaticAdmissionRepository(path, evaluator)
            self.assertEqual(
                ReferenceRepositoryReason.STORE_NOT_DURABLE,
                caught.exception.reason,
            )

    def test_first_admission_statement_is_begin_immediate_and_api_is_closed(
        self,
    ) -> None:
        statements: list[str] = []
        repository, _, commands = self.make_store(
            "first-statement.db",
            statement_hook=statements.append,
        )
        self.addCleanup(repository.close)
        statements.clear()
        repository.admit_static(commands["vm-a"])
        self.assertTrue(statements)
        self.assertEqual("BEGIN IMMEDIATE", statements[0].strip().upper())
        self.assertEqual(
            ("self", "command"),
            tuple(
                inspect.signature(
                    SqliteReferenceStaticAdmissionRepository.admit_static
                ).parameters
            ),
        )
        with self.assertRaises(TypeError):
            repository.admit_static(commands["vm-a"], read_set={})

    def test_commit_replay_is_byte_identical_and_versioned(self) -> None:
        repository, _, commands = self.make_store("replay.db")
        self.addCleanup(repository.close)
        command = commands["vm-a"]
        committed = repository.admit_static(command)
        replay = repository.admit_static(command)
        self.assertEqual(
            committed.to_canonical_bytes(),
            replay.to_canonical_bytes(),
        )
        self.assertEqual(2, committed.idempotency.resource_version)
        state = repository.inspect_reference_state()
        self.assertEqual(EVIDENCE_BOUNDARY, state["evidenceBoundary"])
        self.assertEqual("wal", state["pragmas"]["journalMode"])
        self.assertEqual(2, state["pragmas"]["synchronous"])
        self.assertEqual(1, state["pragmas"]["foreignKeys"])
        self.assertEqual(5_000, state["pragmas"]["busyTimeoutMs"])
        self.assertEqual(
            EVIDENCE_BOUNDARY,
            state["metadata"]["evidence_boundary"],
        )
        self.assertEqual(1, state["counts"]["operation_leases"])
        self.assertEqual(1, state["counts"]["admission_bindings"])
        self.assertEqual(1, state["counts"]["idempotency_records"])
        self.assertEqual(1, state["commitClock"])
        self.assertEqual(
            committed.admission_binding_hash,
            state["operationLeases"][0]["admissionBindingHash"],
        )
        with closing(sqlite3.connect(repository.database_path)) as independent:
            row = independent.execute(
                """
                SELECT state, resource_version, result_bytes
                FROM idempotency_records
                """
            ).fetchone()
            binding_bytes = independent.execute(
                "SELECT binding_bytes FROM admission_bindings"
            ).fetchone()[0]
            integrity = independent.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_key_violations = independent.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
        self.assertEqual(("COMPLETED", 2), row[:2])
        self.assertEqual("ok", integrity)
        self.assertEqual([], foreign_key_violations)
        self.assertEqual(committed.to_canonical_bytes(), row[2])
        binding = json.loads(binding_bytes)
        self.assertEqual(
            "REFERENCE_STATIC_ADMISSION_BINDING",
            binding["subjectType"],
        )
        self.assertEqual(
            binding["availabilityAuthorityResourceVersionBefore"] + 1,
            binding["availabilityAuthorityResourceVersionAfter"],
        )

    def test_same_natural_key_with_different_exact_command_is_rejected(
        self,
    ) -> None:
        repository, _, commands = self.make_store("idempotency-conflict.db")
        self.addCleanup(repository.close)
        command = commands["vm-a"]
        repository.admit_static(command)
        changed = StaticAdmissionCommand.create(
            command_id="different-command",
            vm_id=command.vm_id,
            run_id="different-run",
            idempotency_key=command.idempotency_key,
            actor=command.actor,
            deadline=command.deadline,
            request_reference=command.request_reference,
        )
        with self.assertRaises(ReferenceRepositoryError) as caught:
            repository.admit_static(changed)
        self.assertEqual(
            ReferenceRepositoryReason.IDEMPOTENCY_KEY_REUSED,
            caught.exception.reason,
        )
        self.assertEqual(1, repository.inspect_reference_state()["commitClock"])

    def test_repository_rejects_evaluator_that_omits_selected_member_evidence(
        self,
    ) -> None:
        specs = self.one_spec()
        delegate = evaluator_for(specs)
        malicious = OmittingMemberEvidenceEvaluator(delegate)
        repository, _, commands = self.make_store(
            "omitted-evidence.db",
            specs,
            evaluator=malicious,
        )
        self.addCleanup(repository.close)
        with self.assertRaises(ReferenceRepositoryError) as caught:
            repository.admit_static(commands["vm-a"])
        self.assertEqual(
            ReferenceRepositoryReason.EVALUATOR_INVALID,
            caught.exception.reason,
        )
        self.assertEqual(
            0,
            repository.inspect_reference_state()["counts"]["operation_leases"],
        )

    def test_horizon_crossed_after_evaluation_rolls_back_without_side_effects(
        self,
    ) -> None:
        specs = self.one_spec()
        repository, evaluator, commands = self.make_store("stepping-clock.db", specs)
        baseline = repository.inspect_reference_state()["globalAvailability"][
            "resourceVersion"
        ]
        repository.close()
        values = iter((NOW, CURRENT_VALID_UNTIL))
        repository = SqliteReferenceStaticAdmissionRepository(
            self.root / "stepping-clock.db",
            evaluator,
            clock=lambda: next(values),
        )
        self.addCleanup(repository.close)
        with self.assertRaises(ReferenceRepositoryError) as caught:
            repository.admit_static(commands["vm-a"])
        self.assertEqual(
            ReferenceRepositoryReason.DEADLINE_EXPIRED,
            caught.exception.reason,
        )
        state = repository.inspect_reference_state()
        self.assertEqual(baseline, state["globalAvailability"]["resourceVersion"])
        self.assertEqual(0, state["commitClock"])
        for count in state["counts"].values():
            self.assertEqual(0, count)

    def test_every_atomic_write_fault_stage_rolls_back(self) -> None:
        for index, target in enumerate(WRITE_FAULT_STAGES):
            with self.subTest(stage=target):

                def fault(stage: str, expected=target) -> None:
                    if stage == expected:
                        raise InjectedFault(stage)

                repository, _, commands = self.make_store(
                    f"fault-{index}.db",
                    fault_hook=fault,
                )
                baseline = repository.inspect_reference_state()["globalAvailability"][
                    "resourceVersion"
                ]
                with self.assertRaisesRegex(InjectedFault, target):
                    repository.admit_static(commands["vm-a"])
                state = repository.inspect_reference_state()
                self.assertEqual(
                    baseline,
                    state["globalAvailability"]["resourceVersion"],
                )
                self.assertEqual(0, state["commitClock"])
                for count in state["counts"].values():
                    self.assertEqual(0, count)
                repository.close()

    def test_precommit_process_exit_reopens_without_half_state(self) -> None:
        specs = self.one_spec()
        repository, evaluator, commands = self.make_store("precommit-exit.db", specs)
        database_path = repository.database_path
        baseline = repository.inspect_reference_state()["globalAvailability"][
            "resourceVersion"
        ]
        repository.close()
        start = self.root / "precommit.start"
        payload, ready, _ = self._worker_payload(
            name="precommit",
            database_path=database_path,
            evaluator=evaluator,
            specs=specs,
            mode="admit",
            start_path=start,
            command=commands["vm-a"],
            hard_exit_stage="BEFORE_COMMIT",
            hard_exit_code=71,
        )
        process = self._launch("precommit", payload, ready)
        start.write_text("start", encoding="utf-8")
        process.communicate(timeout=20)
        self.assertEqual(71, process.returncode)

        reopened = SqliteReferenceStaticAdmissionRepository(
            database_path,
            evaluator,
            clock=lambda: NOW,
        )
        self.addCleanup(reopened.close)
        state = reopened.inspect_reference_state()
        self.assertEqual(baseline, state["globalAvailability"]["resourceVersion"])
        self.assertEqual(0, state["commitClock"])
        for count in state["counts"].values():
            self.assertEqual(0, count)
        committed = reopened.admit_static(commands["vm-a"])
        self.assertEqual(1, committed.commit_sequence)

    def test_postcommit_process_exit_retries_exact_stored_result(self) -> None:
        specs = self.one_spec()
        repository, evaluator, commands = self.make_store("postcommit-exit.db", specs)
        database_path = repository.database_path
        repository.close()
        start = self.root / "postcommit.start"
        payload, ready, _ = self._worker_payload(
            name="postcommit",
            database_path=database_path,
            evaluator=evaluator,
            specs=specs,
            mode="admit",
            start_path=start,
            command=commands["vm-a"],
            hard_exit_stage=AFTER_COMMIT_BEFORE_RETURN,
            hard_exit_code=72,
        )
        process = self._launch("postcommit", payload, ready)
        start.write_text("start", encoding="utf-8")
        process.communicate(timeout=20)
        self.assertEqual(72, process.returncode)
        with closing(sqlite3.connect(database_path)) as independent:
            stored_result = independent.execute(
                "SELECT result_bytes FROM idempotency_records"
            ).fetchone()[0]

        reopened = SqliteReferenceStaticAdmissionRepository(
            database_path,
            evaluator,
            clock=lambda: NOW,
        )
        self.addCleanup(reopened.close)
        replay = reopened.admit_static(commands["vm-a"])
        self.assertEqual(stored_result, replay.to_canonical_bytes())
        state = reopened.inspect_reference_state()
        self.assertEqual(1, state["commitClock"])
        self.assertEqual(1, state["counts"]["operation_leases"])
        self.assertEqual(1, state["counts"]["repository_commits"])

    def test_two_processes_overlapping_dependency_yield_one_stable_busy(
        self,
    ) -> None:
        specs = {
            "vm-a": ("shared", "shared", ("device-a", "device-b")),
            "vm-b": ("shared", "shared", ("device-a", "device-b")),
        }
        repository, evaluator, commands = self.make_store("overlap.db", specs)
        database_path = repository.database_path
        repository.close()
        start = self.root / "overlap.start"
        workers = []
        for vm_id in sorted(specs):
            name = f"overlap-{vm_id}"
            payload, ready, output = self._worker_payload(
                name=name,
                database_path=database_path,
                evaluator=evaluator,
                specs=specs,
                mode="admit",
                start_path=start,
                command=commands[vm_id],
            )
            workers.append((self._launch(name, payload, ready), output))
        start.write_text("start", encoding="utf-8")
        results = [
            self._normal_worker_result(process, output) for process, output in workers
        ]
        self.assertEqual(
            ["ERROR", "OK"],
            sorted(item["status"] for item in results),
        )
        error = next(item for item in results if item["status"] == "ERROR")
        self.assertEqual(
            ReferenceRepositoryReason.DEPENDENCY_BUSY.value,
            error["reason"],
        )
        reopened = SqliteReferenceStaticAdmissionRepository(
            database_path,
            evaluator,
            clock=lambda: NOW,
        )
        self.addCleanup(reopened.close)
        self.assertEqual(
            1,
            reopened.inspect_reference_state()["counts"]["operation_leases"],
        )

    def test_two_processes_disjoint_dependencies_both_commit_serially(
        self,
    ) -> None:
        specs = {
            "vm-a": ("bundle-a", "scope-a", ("device-a", "device-b")),
            "vm-b": ("bundle-b", "scope-b", ("device-c", "device-d")),
        }
        repository, evaluator, commands = self.make_store("disjoint.db", specs)
        database_path = repository.database_path
        repository.close()
        start = self.root / "disjoint.start"
        workers = []
        for vm_id in sorted(specs):
            name = f"disjoint-{vm_id}"
            payload, ready, output = self._worker_payload(
                name=name,
                database_path=database_path,
                evaluator=evaluator,
                specs=specs,
                mode="admit",
                start_path=start,
                command=commands[vm_id],
            )
            workers.append((self._launch(name, payload, ready), output))
        start.write_text("start", encoding="utf-8")
        results = [
            self._normal_worker_result(process, output) for process, output in workers
        ]
        self.assertEqual({"OK"}, {item["status"] for item in results})
        self.assertEqual({1, 2}, {item["commitSequence"] for item in results})
        reopened = SqliteReferenceStaticAdmissionRepository(
            database_path,
            evaluator,
            clock=lambda: NOW,
        )
        self.addCleanup(reopened.close)
        state = reopened.inspect_reference_state()
        self.assertEqual(2, state["counts"]["operation_leases"])
        self.assertEqual(2, state["commitClock"])

    def test_absence_phantom_writer_uses_same_global_fence_protocol(
        self,
    ) -> None:
        specs = self.one_spec()
        repository, evaluator, commands = self.make_store("phantom.db", specs)
        database_path = repository.database_path
        repository.close()

        admission_start = self.root / "phantom-admission.start"
        quarantine_start = self.root / "phantom-quarantine.start"
        reached = self.root / "phantom.reached"
        release = self.root / "phantom.release"
        quarantine_attempted = self.root / "phantom-quarantine.attempted"
        admission_payload, admission_ready, admission_output = self._worker_payload(
            name="phantom-admission",
            database_path=database_path,
            evaluator=evaluator,
            specs=specs,
            mode="admit",
            start_path=admission_start,
            command=commands["vm-a"],
            pause_stage=AFTER_AVAILABILITY_ABSENCE_READ,
            reached_path=reached,
            release_path=release,
        )
        quarantine_payload, quarantine_ready, quarantine_output = self._worker_payload(
            name="phantom-quarantine",
            database_path=database_path,
            evaluator=evaluator,
            specs=specs,
            mode="quarantine",
            start_path=quarantine_start,
            attempted_path=quarantine_attempted,
            quarantine={
                "conflictKey": digest("scope:scope-a"),
                "quarantineDigest": digest("quarantine"),
                "resourceVersion": 1,
            },
        )
        admission_process = self._launch(
            "phantom-admission",
            admission_payload,
            admission_ready,
        )
        quarantine_process = self._launch(
            "phantom-quarantine",
            quarantine_payload,
            quarantine_ready,
        )
        admission_start.write_text("start", encoding="utf-8")
        self._wait_for_file(reached, process=admission_process)
        quarantine_start.write_text("start", encoding="utf-8")
        self._wait_for_file(
            quarantine_attempted,
            process=quarantine_process,
        )
        time.sleep(0.25)
        self.assertIsNone(quarantine_process.poll())
        self.assertFalse(quarantine_output.exists())
        release.write_text("release", encoding="utf-8")

        admission_result = self._normal_worker_result(
            admission_process,
            admission_output,
        )
        quarantine_result = self._normal_worker_result(
            quarantine_process,
            quarantine_output,
        )
        self.assertEqual("OK", admission_result["status"])
        self.assertEqual("ERROR", quarantine_result["status"])
        self.assertEqual(
            ReferenceRepositoryReason.DEPENDENCY_BUSY.value,
            quarantine_result["reason"],
        )
        reopened = SqliteReferenceStaticAdmissionRepository(
            database_path,
            evaluator,
            clock=lambda: NOW,
        )
        self.addCleanup(reopened.close)
        state = reopened.inspect_reference_state()
        self.assertEqual(1, state["counts"]["operation_leases"])
        self.assertEqual(0, state["counts"]["quarantines"])


if __name__ == "__main__":
    unittest.main()
