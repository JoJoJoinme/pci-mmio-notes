from __future__ import annotations

import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from qman_directpath_reference import (
    ContractViolation,
    ReferenceQueryContext,
    DeterministicReferenceEvaluator,
    ReferenceSelectionPremise,
    SqliteReferenceDirectPathQuery,
    SqliteReferenceStaticAdmissionRepository,
    StaticAdmissionCommand,
    StaticAdmissionRequestReference,
    canonical_json_bytes,
    sha256_digest,
    parse_reference_query_read_trace,
)
from qman_directpath_reference.query_snapshot import (
    AFTER_QUERY_BEFORE_STATE,
    BEFORE_QUERY_READ_COMMIT,
    ReferenceQueryError,
    ReferenceQueryReason,
    ReferenceRawQueryRead,
    ReferenceSqliteSnapshotReader,
)

WORKER = Path(__file__).with_name("query_worker.py")
ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-07-24T12:00:00.000000Z"
DEADLINE = "2026-07-24T13:00:00.000000Z"
EVALUATION_VALID_UNTIL = "2026-07-24T14:00:00.000000Z"
CURRENT_VALID_UNTIL = "2026-07-24T15:00:00.000000Z"
SPEC = {
    "vm-a": (
        "bundle-a",
        "scope-a",
        ("device-a", "device-b"),
    )
}


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def blob_value(label: str) -> dict[str, str]:
    return {"fixture": label}


def blob_hash(label: str) -> str:
    return sha256_digest(canonical_json_bytes(blob_value(label)))


def evaluator_for() -> DeterministicReferenceEvaluator:
    return DeterministicReferenceEvaluator(
        {
            "vm-a": ReferenceSelectionPremise(
                bundle_id=digest("bundle:bundle-a"),
                scope_hash=digest("scope:scope-a"),
                member_ids=("device-a", "device-b"),
                evidence_blob_hashes=(blob_hash("evaluation:vm-a"),),
                valid_until=EVALUATION_VALID_UNTIL,
            )
        }
    )


def seed_store(
    repository: SqliteReferenceStaticAdmissionRepository,
) -> dict[str, StaticAdmissionCommand]:
    admin = repository.reference_only_bootstrap_admin()
    labels = {
        "controller",
        "artifact:CATALOG",
        "artifact:INVENTORY",
        "artifact:POLICY",
        "artifact:TRUST",
        "request:vm-a",
        "evaluation:vm-a",
        "member:device-a",
        "member:device-b",
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
    admin.set_current_request(
        vm_id="vm-a",
        request_version=1,
        request_hash=blobs["request:vm-a"],
        resource_version=201,
        blob_sha256=blobs["request:vm-a"],
    )
    admin.set_global_availability(
        authority_id="availability-authority-1",
        resource_version=300,
    )
    for generation, member_id in enumerate(("device-a", "device-b"), start=31):
        admin.set_availability_member(
            device_id=member_id,
            generation=generation,
            resource_version=400 + generation,
            evidence_blob_hash=blobs[f"member:{member_id}"],
        )
    admin.set_bundle_members(
        bundle_id=digest("bundle:bundle-a"),
        member_ids=("device-a", "device-b"),
    )
    return {
        "vm-a": StaticAdmissionCommand.create(
            command_id="command-vm-a",
            vm_id="vm-a",
            run_id="run-vm-a",
            idempotency_key="idempotency-vm-a",
            actor="controller:reference-test",
            deadline=DEADLINE,
            request_reference=StaticAdmissionRequestReference(
                request_version=1,
                request_hash=blobs["request:vm-a"],
            ),
        )
    }


class ReferenceQuerySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        self.processes: list[subprocess.Popen[bytes]] = []
        self.addCleanup(self._terminate_processes)

    def _terminate_processes(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def make_store(
        self,
        name: str,
    ) -> tuple[
        SqliteReferenceStaticAdmissionRepository,
        dict[str, object],
    ]:
        repository = SqliteReferenceStaticAdmissionRepository(
            self.root / name,
            evaluator_for(),
            clock=lambda: NOW,
        )
        commands = seed_store(repository)
        repository.reference_only_bootstrap_admin().set_reference_query_observer(
            observer_instance_id="reference-observer-1",
            restart_generation=1,
            resource_version=1,
            host_id="reference-host-1",
            host_epoch=1,
            kernel_boot_id="reference-boot-1",
            agent_generation=1,
            journal_epoch=1,
            counter_epoch=1,
            reset_observer_id="reference-reset-observer-1",
            host_journal_sequence=0,
            driver_bind_count=0,
            driver_unbind_count=0,
            device_reset_count=0,
            vfio_exclusive_open_count=0,
            qemu_spawn_count=0,
            observation_digest=digest("observer:genesis"),
        )
        return repository, commands

    @staticmethod
    def query_context() -> ReferenceQueryContext:
        return ReferenceQueryContext(
            trace_id="reference-trace-1",
            query_command_id="reference-query-command-1",
            transaction_id="reference-read-transaction-1",
            assignment_id="reference-assignment-vm-a",
            vm_id="vm-a",
            captured_at=NOW,
            portable_contract_sha256=digest("portable-contract"),
        )

    @staticmethod
    def validate_shared_trace_and_output(result) -> None:
        trace_schema = json.loads(
            (ROOT / "contracts" / "directpath-query-read-trace.schema.json").read_text(
                encoding="utf-8"
            )
        )
        binding_schema = json.loads(
            (
                ROOT
                / "contracts"
                / "directpath-operation-admission-binding.schema.json"
            ).read_text(encoding="utf-8")
        )
        payload_schema = json.loads(
            (ROOT / "contracts" / "directpath-operation-payload.schema.json").read_text(
                encoding="utf-8"
            )
        )
        registry = Registry().with_resources(
            [
                (trace_schema["$id"], Resource.from_contents(trace_schema)),
                (binding_schema["$id"], Resource.from_contents(binding_schema)),
                (payload_schema["$id"], Resource.from_contents(payload_schema)),
            ]
        )
        Draft202012Validator(
            trace_schema,
            registry=registry,
        ).validate(result.trace.to_wire())
        Draft202012Validator(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": (payload_schema["$id"] + "#/$defs/output_OP_QUERY_DIRECTPATH"),
            },
            registry=registry,
        ).validate(result.output.to_wire())

    def test_three_reads_are_byte_identical_and_issue_no_write_statement(
        self,
    ) -> None:
        repository, _ = self.make_store("repeat.db")
        self.addCleanup(repository.close)
        statements: list[str] = []
        reader = ReferenceSqliteSnapshotReader(
            repository.database_path,
            statement_hook=statements.append,
        )
        results = [reader.read("vm-a") for _ in range(3)]
        self.assertEqual(1, len({item.before_bytes for item in results}))
        self.assertEqual(1, len({item.state_digest for item in results}))
        self.assertEqual({0}, {item.total_changes_before for item in results})
        self.assertEqual({0}, {item.total_changes_after for item in results})
        transactional = [
            statement.strip().upper()
            for statement in statements
            if not statement.lstrip().upper().startswith("PRAGMA")
        ]
        self.assertEqual("BEGIN", transactional[0])
        self.assertTrue(all("INSERT " not in item for item in transactional))
        self.assertTrue(all("UPDATE " not in item for item in transactional))
        self.assertTrue(all("DELETE " not in item for item in transactional))
        self.assertEqual(0, repository.inspect_reference_state()["commitClock"])

    def test_schema_aligned_trace_and_output_are_byte_identical(self) -> None:
        repository, _ = self.make_store("shared-trace.db")
        self.addCleanup(repository.close)
        query = SqliteReferenceDirectPathQuery(repository.database_path)
        results = [query.query_directpath(self.query_context()) for _ in range(3)]
        self.assertEqual(
            1,
            len({item.trace.to_canonical_bytes() for item in results}),
        )
        self.assertEqual(
            1,
            len({item.canonical_output_bytes for item in results}),
        )
        self.assertEqual(
            1,
            len({item.request_envelope_bytes for item in results}),
        )
        self.assertEqual(
            1,
            len({item.result_envelope_bytes for item in results}),
        )
        trace = results[0].trace.to_wire()
        self.assertEqual(
            "REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY",
            trace["evidenceBoundary"],
        )
        self.assertEqual(9, len(trace["before"]["state"]["predicateObservations"]))
        self.assertEqual(
            trace["before"]["state"],
            trace["after"]["state"],
        )
        self.assertTrue(
            all(
                item["canonicalInstanceBase64"]
                for item in trace["before"]["state"]["observedInstances"]
            )
        )
        host_observer_generation_fields = {
            "HOST_JOURNAL_HEAD": "hostEpoch",
            "HOST_SIDE_EFFECT_COUNTER": "agentGeneration",
            "RESET_OBSERVATION": "observerEpoch",
        }
        for wrapper in trace["before"]["state"]["observedInstances"]:
            generation_field = host_observer_generation_fields.get(
                wrapper["instanceKind"]
            )
            if generation_field is None:
                continue
            actual = json.loads(
                base64.b64decode(
                    wrapper["canonicalInstanceBase64"],
                    validate=True,
                )
            )
            self.assertIsNone(wrapper["resourceVersionOrNull"])
            self.assertEqual(
                actual[generation_field],
                wrapper["generationOrNull"],
            )
        self.validate_shared_trace_and_output(results[0])

    def test_observer_lineage_and_current_anchor_instances_are_exact(self) -> None:
        repository, _ = self.make_store("lineage-anchor.db")
        self.addCleanup(repository.close)
        result = SqliteReferenceDirectPathQuery(
            repository.database_path
        ).query_directpath(self.query_context())
        state = result.trace.to_wire()["before"]["state"]
        vector = state["currentAuthorityVector"]
        by_kind: dict[str, list[tuple[dict[str, object], dict[str, object]]]] = {}
        for wrapper in state["observedInstances"]:
            actual = json.loads(
                base64.b64decode(
                    wrapper["canonicalInstanceBase64"],
                    validate=True,
                )
            )
            by_kind.setdefault(wrapper["instanceKind"], []).append((wrapper, actual))
        for wrapper, actual in (
            by_kind["HOST_JOURNAL_HEAD"]
            + by_kind["HOST_SIDE_EFFECT_COUNTER"]
            + by_kind["RESET_OBSERVATION"]
        ):
            self.assertIsNone(wrapper["resourceVersionOrNull"])
            generation_field = {
                "HOST_JOURNAL_HEAD": "hostEpoch",
                "HOST_SIDE_EFFECT_COUNTER": "agentGeneration",
                "RESET_OBSERVATION": "observerEpoch",
            }[wrapper["instanceKind"]]
            expected_generation = actual[generation_field]
            self.assertEqual(
                expected_generation,
                wrapper["generationOrNull"],
            )
        for kind, version_field, digest_field in (
            (
                "CURRENT_TRUST_ANCHOR",
                "trustAnchorVersion",
                "trustAnchorDigest",
            ),
            (
                "CURRENT_CATALOG_ANCHOR",
                "catalogAnchorVersion",
                "catalogAnchorDigest",
            ),
        ):
            self.assertEqual(1, len(by_kind[kind]))
            _, actual = by_kind[kind][0]
            fields = {item["name"]: item["value"] for item in actual["rowFields"]}
            self.assertEqual(vector[version_field], fields[version_field])
            self.assertEqual(vector[digest_field], fields[digest_field])

    def test_reference_trace_is_accepted_by_core_verifier(self) -> None:
        repository, _ = self.make_store("core-verifier.db")
        self.addCleanup(repository.close)
        result = SqliteReferenceDirectPathQuery(
            repository.database_path
        ).query_directpath(self.query_context())
        core_root = ROOT / "qman-directpath-core"
        if str(core_root) not in sys.path:
            sys.path.insert(0, str(core_root))
        from qman_directpath_core import (  # noqa: PLC0415
            ContractSchemas,
            VerifiedQueryReadTrace,
            verify_query_read_trace,
        )

        verified = verify_query_read_trace(
            result.trace.to_canonical_bytes(),
            request_envelope_bytes=result.request_envelope_bytes,
            result_envelope_bytes=result.result_envelope_bytes,
            schemas=ContractSchemas(
                ROOT / "contracts",
                include_query_read_trace=True,
            ),
        )
        self.assertIsInstance(verified, VerifiedQueryReadTrace)
        self.assertEqual(
            result.trace.to_canonical_bytes(),
            verified.canonical_bytes,
        )
        self.assertEqual(
            result.canonical_output_bytes,
            verified.output_canonical_bytes,
        )

    def test_reordered_predicates_are_rejected_by_pure_parser(self) -> None:
        repository, _ = self.make_store("reorder.db")
        self.addCleanup(repository.close)
        result = SqliteReferenceDirectPathQuery(
            repository.database_path
        ).query_directpath(self.query_context())
        wire = result.trace.to_wire()
        for capture in ("before", "after"):
            predicates = wire[capture]["state"]["predicateObservations"]
            wire[capture]["state"]["predicateObservations"] = list(reversed(predicates))
        with self.assertRaisesRegex(ContractViolation, "canonical order"):
            parse_reference_query_read_trace(canonical_json_bytes(wire))

    def test_mode_ro_and_query_only_deny_a_write_attempt(self) -> None:
        repository, _ = self.make_store("deny-write.db")
        self.addCleanup(repository.close)

        def attempt_write(stage: str, connection: sqlite3.Connection) -> None:
            if stage == AFTER_QUERY_BEFORE_STATE:
                connection.execute(
                    "UPDATE commit_clock SET last_sequence = 99 WHERE singleton = 1"
                )

        reader = ReferenceSqliteSnapshotReader(
            repository.database_path,
            transaction_hook=attempt_write,
        )
        with self.assertRaises(ReferenceQueryError) as caught:
            reader.read("vm-a")
        self.assertEqual(
            ReferenceQueryReason.READ_ONLY_VIOLATION,
            caught.exception.reason,
        )
        self.assertEqual(0, repository.inspect_reference_state()["commitClock"])

    def test_busy_lease_and_disjoint_quarantine_are_stably_observed(self) -> None:
        repository, commands = self.make_store("busy-quarantine.db")
        self.addCleanup(repository.close)
        repository.admit_static(commands["vm-a"])
        repository.reference_only_bootstrap_admin().set_quarantine(
            conflict_key=digest("disjoint-quarantine"),
            quarantine_digest=digest("quarantine"),
            resource_version=1,
        )
        reader = ReferenceSqliteSnapshotReader(repository.database_path)
        results = [reader.read("vm-a") for _ in range(3)]
        self.assertEqual(1, len({item.before_bytes for item in results}))
        state = results[0].before
        self.assertEqual(1, len(state["operationLeases"]))
        self.assertEqual(1, len(state["quarantines"]))
        self.assertEqual(
            state["repositoryCommitClock"],
            state["repositoryCommitHead"]["commitSequence"],
        )

    def test_wal_publisher_yields_old_complete_then_new_complete_snapshot(
        self,
    ) -> None:
        repository, _ = self.make_store("publisher.db")
        self.addCleanup(repository.close)
        admin = repository.reference_only_bootstrap_admin()
        new_blob = admin.put_immutable_blob(
            "schema:reference-fixture",
            {"fixture": "artifact:INVENTORY:v2"},
        )
        baseline = ReferenceSqliteSnapshotReader(repository.database_path).read("vm-a")
        reached = threading.Event()
        release = threading.Event()

        def pause(stage: str, _connection: sqlite3.Connection) -> None:
            if stage == AFTER_QUERY_BEFORE_STATE:
                reached.set()
                if not release.wait(10):
                    raise TimeoutError("publisher test release timed out")

        result: list[ReferenceRawQueryRead] = []
        failure: list[BaseException] = []

        def query() -> None:
            try:
                result.append(
                    ReferenceSqliteSnapshotReader(
                        repository.database_path,
                        transaction_hook=pause,
                    ).read("vm-a")
                )
            except BaseException as error:
                failure.append(error)

        thread = threading.Thread(target=query)
        thread.start()
        self.assertTrue(reached.wait(10))
        admin.publish_reference_query_observation(
            inventory_authority_id="authority-inventory",
            inventory_sequence=25,
            inventory_digest=new_blob,
            inventory_resource_version=125,
            inventory_valid_until=CURRENT_VALID_UNTIL,
            inventory_blob_sha256=new_blob,
            observer_instance_id="reference-observer-1",
            restart_generation=1,
            observer_resource_version=2,
            host_id="reference-host-1",
            host_epoch=1,
            kernel_boot_id="reference-boot-1",
            agent_generation=1,
            journal_epoch=1,
            counter_epoch=1,
            reset_observer_id="reference-reset-observer-1",
            host_journal_sequence=1,
            driver_bind_count=0,
            driver_unbind_count=0,
            device_reset_count=0,
            vfio_exclusive_open_count=0,
            qemu_spawn_count=0,
            observation_digest=digest("observer:v2"),
        )
        release.set()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], failure)
        self.assertEqual(baseline.before_bytes, result[0].before_bytes)
        self.assertEqual(result[0].before_bytes, result[0].after_bytes)

        current = ReferenceSqliteSnapshotReader(repository.database_path).read("vm-a")
        self.assertNotEqual(baseline.before_bytes, current.before_bytes)
        self.assertEqual(25, current.before["inventoryCurrent"]["sequence"])
        self.assertEqual(2, current.before["observer"]["resourceVersion"])
        self.assertEqual(
            baseline.before["availabilityAuthority"]["resourceVersion"] + 1,
            current.before["availabilityAuthority"]["resourceVersion"],
        )

    def test_concurrent_admission_and_quarantine_never_mix_availability(
        self,
    ) -> None:
        repository, commands = self.make_store("availability-snapshot.db")
        self.addCleanup(repository.close)
        baseline = ReferenceSqliteSnapshotReader(repository.database_path).read("vm-a")
        reached = threading.Event()
        release = threading.Event()
        result: list[ReferenceRawQueryRead] = []

        def pause(stage: str, _connection: sqlite3.Connection) -> None:
            if stage == AFTER_QUERY_BEFORE_STATE:
                reached.set()
                if not release.wait(10):
                    raise TimeoutError("availability test release timed out")

        thread = threading.Thread(
            target=lambda: result.append(
                ReferenceSqliteSnapshotReader(
                    repository.database_path,
                    transaction_hook=pause,
                ).read("vm-a")
            )
        )
        thread.start()
        self.assertTrue(reached.wait(10))
        repository.admit_static(commands["vm-a"])
        repository.reference_only_bootstrap_admin().set_quarantine(
            conflict_key=digest("other-scope"),
            quarantine_digest=digest("other-quarantine"),
            resource_version=1,
        )
        release.set()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(baseline.before_bytes, result[0].before_bytes)
        self.assertEqual(result[0].before_bytes, result[0].after_bytes)
        self.assertEqual([], result[0].before["operationLeases"])
        self.assertEqual([], result[0].before["quarantines"])

        current = ReferenceSqliteSnapshotReader(repository.database_path).read("vm-a")
        self.assertEqual(1, len(current.before["operationLeases"]))
        self.assertEqual(1, len(current.before["quarantines"]))
        self.assertEqual(
            baseline.before["availabilityAuthority"]["resourceVersion"] + 2,
            current.before["availabilityAuthority"]["resourceVersion"],
        )

    def test_missing_store_instance_or_global_fence_fails_closed(self) -> None:
        for missing in ("store_instance_id", "global_availability"):
            with self.subTest(missing=missing):
                repository, _ = self.make_store(f"missing-{missing}.db")
                path = repository.database_path
                repository.close()
                with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if missing == "store_instance_id":
                        connection.execute(
                            "DELETE FROM metadata WHERE key = 'store_instance_id'"
                        )
                    else:
                        connection.execute(
                            "DELETE FROM global_availability WHERE singleton = 1"
                        )
                    connection.execute("COMMIT")
                with self.assertRaises(ReferenceQueryError) as caught:
                    ReferenceSqliteSnapshotReader(path).read("vm-a")
                expected = (
                    ReferenceQueryReason.STORE_IDENTITY_MISSING
                    if missing == "store_instance_id"
                    else ReferenceQueryReason.AVAILABILITY_FENCE_MISSING
                )
                self.assertEqual(expected, caught.exception.reason)

    def test_observer_counter_or_restart_drift_is_rejected(self) -> None:
        repository, _ = self.make_store("observer-drift.db")
        self.addCleanup(repository.close)
        read = ReferenceSqliteSnapshotReader(repository.database_path).read("vm-a")
        for field in ("deviceResetCount", "restartGeneration"):
            with self.subTest(field=field):
                after = read.after
                after["observer"][field] += 1
                with self.assertRaises(ReferenceQueryError) as caught:
                    ReferenceRawQueryRead(
                        store_instance_id=read.store_instance_id,
                        vm_id=read.vm_id,
                        before_bytes=read.before_bytes,
                        after_bytes=canonical_json_bytes(after),
                        total_changes_before=0,
                        total_changes_after=0,
                    )
                self.assertEqual(
                    ReferenceQueryReason.SNAPSHOT_DRIFT,
                    caught.exception.reason,
                )

    def test_read_process_hard_exit_has_zero_repository_commit(self) -> None:
        repository, _ = self.make_store("query-hard-exit.db")
        path = repository.database_path
        baseline = ReferenceSqliteSnapshotReader(path).read("vm-a").before_bytes
        repository.close()
        payload_path = self.root / "query-hard-exit.json"
        output_path = self.root / "query-hard-exit.out"
        payload_path.write_text(
            json.dumps(
                {
                    "databasePath": str(path),
                    "vmId": "vm-a",
                    "outputPath": str(output_path),
                    "hardExitStage": BEFORE_QUERY_READ_COMMIT,
                    "hardExitCode": 76,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parents[1])
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            package_root if not existing else package_root + os.pathsep + existing
        )
        process = subprocess.Popen(
            [sys.executable, str(WORKER), str(payload_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.processes.append(process)
        stdout, stderr = process.communicate(timeout=20)
        self.assertEqual((b"", b""), (stdout, stderr))
        self.assertEqual(76, process.returncode)
        self.assertFalse(output_path.exists())

        after = ReferenceSqliteSnapshotReader(path).read("vm-a")
        self.assertEqual(baseline, after.before_bytes)
        self.assertEqual(0, after.before["repositoryCommitClock"])


if __name__ == "__main__":
    unittest.main()
