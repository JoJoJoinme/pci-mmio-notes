from __future__ import annotations

import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from pci_resource_model.static_lease import (
    BeginRequest,
    LeaseState,
    LeaseStoreError,
    Reason,
    ReconcileObservation,
    StaticLeaseStore,
)


HOST = "host-a"
AUTHORITY = "inventory-publisher-v1"
EPOCH = 42
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
MEMBERS = ("0000:64:00.0", "0000:65:00.0")
ALL_GENERATIONS = {
    "0000:64:00.0": 7,
    "0000:65:00.0": 8,
    "0000:66:00.0": 9,
    "0000:67:00.0": 10,
}


def bundle_hash(
    bundle_id: str = "bundle-a",
    members: tuple[str, ...] = MEMBERS,
    host_id: str = HOST,
) -> str:
    return StaticLeaseStore.compute_bundle_members_hash(host_id, bundle_id, members)


def request(
    key: str = "request-1",
    *,
    host_id: str = HOST,
    vm_id: str = "vm-1",
    run_id: str = "run-1",
    bundle_id: str = "bundle-a",
    expected_bundle_hash: str | None = None,
    expected_vm_generation: int = 0,
    members: tuple[str, ...] = MEMBERS,
    inventory_epoch: int = EPOCH,
    expected_device_generations: dict[str, int] | None = None,
) -> BeginRequest:
    generations = (
        {member: ALL_GENERATIONS[member] for member in members}
        if expected_device_generations is None
        else expected_device_generations
    )
    return BeginRequest(
        idempotency_key=key,
        host_id=host_id,
        vm_id=vm_id,
        run_id=run_id,
        bundle_id=bundle_id,
        expected_bundle_hash=(
            bundle_hash(bundle_id, members, host_id)
            if expected_bundle_hash is None
            else expected_bundle_hash
        ),
        members=members,
        inventory_epoch=inventory_epoch,
        expected_vm_generation=expected_vm_generation,
        expected_device_generations=generations,
        decision_hash=HASH_A,
        policy_hash=HASH_B,
    )


class StaticLeaseStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "lease.sqlite3"
        self.ids = iter(f"tx-{index}" for index in range(100))
        self.store = self.open_store(transaction_id_factory=self.ids.__next__)
        self.publish_initial_authority()

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def open_store(self, **kwargs) -> StaticLeaseStore:
        return StaticLeaseStore(
            self.db,
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            **kwargs,
        )

    def reopen(self, **kwargs) -> None:
        self.store.close()
        self.store = self.open_store(**kwargs)

    def publish_initial_authority(self) -> None:
        self.store.publish_authoritative_device_generations(
            HOST,
            ALL_GENERATIONS,
            expected_current={bdf: None for bdf in ALL_GENERATIONS},
            authority_id=AUTHORITY,
            authority_epoch=EPOCH,
        )
        self.store.publish_authoritative_bundle(
            HOST,
            "bundle-a",
            MEMBERS,
            expected_current_hash=None,
            authority_id=AUTHORITY,
            authority_epoch=EPOCH,
        )

    def publish_bundle(
        self,
        bundle_id: str,
        members: tuple[str, ...],
        *,
        epoch: int = EPOCH,
        expected_current_hash: str | None = None,
    ) -> str:
        return self.store.publish_authoritative_bundle(
            HOST,
            bundle_id,
            members,
            expected_current_hash=expected_current_hash,
            authority_id=AUTHORITY,
            authority_epoch=epoch,
        )

    def clean_arguments(
        self,
        members: tuple[str, ...] = MEMBERS,
        *,
        side_effects: bool,
    ) -> dict[str, object]:
        current = self.store.current_device_generations(HOST)
        return {
            "next_device_generations": {
                member: current[member] + (1 if side_effects else 0)
                for member in members
            },
            "next_authority_epoch": EPOCH + (1 if side_effects else 0),
            "authority_id": AUTHORITY,
        }

    def assert_reason(self, reason: Reason, operation) -> LeaseStoreError:
        with self.assertRaises(LeaseStoreError) as caught:
            operation()
        self.assertEqual(reason, caught.exception.reason)
        return caught.exception

    def test_memory_uri_relative_and_wrong_host_database_are_rejected(self) -> None:
        self.assert_reason(
            Reason.STORE_NOT_DURABLE,
            lambda: StaticLeaseStore(
                ":memory:", local_host_id=HOST, trusted_authority_id=AUTHORITY
            ),
        )
        self.assert_reason(
            Reason.STORE_NOT_DURABLE,
            lambda: StaticLeaseStore(
                "file:volatile?mode=memory",
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
            ),
        )
        self.assert_reason(
            Reason.STORE_NOT_DURABLE,
            lambda: StaticLeaseStore(
                "relative.sqlite3", local_host_id=HOST, trusted_authority_id=AUTHORITY
            ),
        )
        self.assert_reason(
            Reason.HOST_SCOPE_MISMATCH,
            lambda: StaticLeaseStore(
                self.db,
                local_host_id="host-b",
                trusted_authority_id=AUTHORITY,
            ),
        )
        self.assert_reason(
            Reason.AUTHORITY_SCOPE_MISMATCH,
            lambda: StaticLeaseStore(
                self.db,
                local_host_id=HOST,
                trusted_authority_id="different-authority-v2",
            ),
        )

    @unittest.skipUnless(os.name == "posix" and Path("/dev/shm").is_dir(), "Linux tmpfs only")
    def test_tmpfs_is_not_accepted_as_durable(self) -> None:
        path = Path("/dev/shm") / f"qman-static-lease-{os.getpid()}.sqlite3"
        self.assert_reason(
            Reason.STORE_NOT_DURABLE,
            lambda: StaticLeaseStore(
                path, local_host_id=HOST, trusted_authority_id=AUTHORITY
            ),
        )

    def test_cross_authority_snapshot_is_rejected_before_begin(self) -> None:
        self.assert_reason(
            Reason.AUTHORITY_SCOPE_MISMATCH,
            lambda: self.store.publish_authoritative_bundle(
                HOST,
                "foreign-bundle",
                ("0000:66:00.0",),
                expected_current_hash=None,
                authority_id="different-bundle-publisher-v9",
                authority_epoch=EPOCH,
            ),
        )
        self.assert_reason(
            Reason.AUTHORITY_SCOPE_MISMATCH,
            lambda: self.store.publish_authoritative_device_generations(
                HOST,
                {"0000:68:00.0": 1},
                expected_current={"0000:68:00.0": None},
                authority_id="different-device-publisher-v9",
                authority_epoch=EPOCH,
            ),
        )
        self.assertEqual({}, self.store.claimed_members(HOST))

        reserved = self.store.begin(request("authority-cleanup"))
        self.assert_reason(
            Reason.AUTHORITY_SCOPE_MISMATCH,
            lambda: self.store.rollback(
                reserved.transaction_id,
                reserved.vm_generation,
                reserved.revision,
                cleanup_verified=True,
                reason_code="NO_SIDE_EFFECTS",
                next_device_generations={member: ALL_GENERATIONS[member] for member in MEMBERS},
                next_authority_epoch=EPOCH,
                authority_id="different-cleanup-publisher-v9",
            ),
        )
        self.assertEqual(LeaseState.RESERVED, self.store.get(reserved.transaction_id).state)
        self.assertEqual(
            {member: reserved.transaction_id for member in MEMBERS},
            self.store.claimed_members(HOST),
        )

    def test_begin_is_atomic_persistent_and_exactly_idempotent(self) -> None:
        first = self.store.begin(request())
        replay = self.store.begin(request())
        self.assertEqual(first, replay)
        self.assertEqual(LeaseState.RESERVED, first.state)
        self.assertEqual(1, first.vm_generation)
        self.assertEqual(
            {member: first.transaction_id for member in MEMBERS},
            self.store.claimed_members(HOST),
        )
        self.assertEqual(
            {"bundle-a": first.transaction_id}, self.store.claimed_bundles(HOST)
        )
        self.assertEqual(
            ["BEGIN_RESERVED"],
            [entry.event for entry in self.store.journal(first.transaction_id)],
        )

        self.reopen()
        self.assertEqual(first, self.store.get(first.transaction_id))
        self.assertEqual(1, self.store.current_vm_generation(HOST, "vm-1"))

    def test_idempotency_key_cannot_be_reused_for_different_payload(self) -> None:
        self.store.begin(request())
        self.assert_reason(
            Reason.IDEMPOTENCY_CONFLICT,
            lambda: self.store.begin(request(run_id="different-run")),
        )

    def test_begin_fault_rolls_back_vm_generation_claims_and_journal(self) -> None:
        def fault(point: str) -> None:
            if point == "BEGIN_BEFORE_COMMIT":
                raise RuntimeError("crash")

        self.reopen(fault_hook=fault)
        with self.assertRaisesRegex(RuntimeError, "crash"):
            self.store.begin(request())
        self.reopen()
        self.assertEqual(0, self.store.current_vm_generation(HOST, "vm-1"))
        self.assertEqual({}, self.store.claimed_members(HOST))
        self.assertEqual({}, self.store.claimed_bundles(HOST))
        self.assertEqual((), self.store.recovery_required())

    def test_begin_requires_authoritative_device_and_complete_bundle_facts(self) -> None:
        missing = ("0000:68:00.0",)
        missing_hash = self.publish_bundle("bundle-missing", missing)
        self.assert_reason(
            Reason.DEVICE_GENERATION_UNKNOWN,
            lambda: self.store.begin(
                request(
                    "missing",
                    bundle_id="bundle-missing",
                    members=missing,
                    expected_bundle_hash=missing_hash,
                    expected_device_generations={missing[0]: 1},
                )
            ),
        )
        self.assert_reason(
            Reason.BUNDLE_MEMBERS_MISMATCH,
            lambda: self.store.begin(
                request(
                    "split",
                    members=(MEMBERS[0],),
                    expected_device_generations={MEMBERS[0]: ALL_GENERATIONS[MEMBERS[0]]},
                )
            ),
        )

    def test_host_scope_and_stale_device_generation_fail_before_claim(self) -> None:
        self.assert_reason(
            Reason.HOST_SCOPE_MISMATCH,
            lambda: self.store.begin(request(host_id="host-b")),
        )
        self.assert_reason(
            Reason.DEVICE_GENERATION_MISMATCH,
            lambda: self.store.begin(
                request(
                    expected_device_generations={MEMBERS[0]: 999, MEMBERS[1]: 8}
                )
            ),
        )
        self.assertEqual({}, self.store.claimed_members(HOST))

    def test_active_claim_blocks_device_and_bundle_authority_changes(self) -> None:
        self.store.begin(request())
        self.assert_reason(
            Reason.DEVICE_GENERATION_PUBLISH_BUSY,
            lambda: self.store.publish_authoritative_device_generations(
                HOST,
                {MEMBERS[0]: ALL_GENERATIONS[MEMBERS[0]] + 1},
                expected_current={MEMBERS[0]: ALL_GENERATIONS[MEMBERS[0]]},
                authority_id=AUTHORITY,
                authority_epoch=EPOCH + 1,
            ),
        )

    def test_authority_epoch_is_immutable_and_prevents_bundle_aba(self) -> None:
        self.assert_reason(
            Reason.BUNDLE_PUBLISH_CONFLICT,
            lambda: self.publish_bundle(
                "bundle-a",
                (MEMBERS[0], "0000:66:00.0"),
                epoch=EPOCH,
                expected_current_hash=bundle_hash(),
            ),
        )
        self.assert_reason(
            Reason.DEVICE_GENERATION_PUBLISH_CONFLICT,
            lambda: self.store.publish_authoritative_device_generations(
                HOST,
                {MEMBERS[0]: ALL_GENERATIONS[MEMBERS[0]] + 1},
                expected_current={MEMBERS[0]: ALL_GENERATIONS[MEMBERS[0]]},
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            ),
        )
        accepted = self.store.begin(request())
        self.assertEqual(LeaseState.RESERVED, accepted.state)
        self.assert_reason(
            Reason.BUNDLE_PUBLISH_BUSY,
            lambda: self.publish_bundle(
                "bundle-a",
                MEMBERS + ("0000:66:00.0",),
                epoch=EPOCH + 1,
                expected_current_hash=bundle_hash(),
            ),
        )

    def test_vm_generation_and_active_vm_cas_reject_stale_or_parallel_begin(self) -> None:
        self.store.begin(request())
        self.publish_bundle("bundle-b", ("0000:66:00.0",))
        self.assert_reason(
            Reason.VM_TRANSACTION_BUSY,
            lambda: self.store.begin(
                request(
                    "parallel",
                    run_id="run-2",
                    bundle_id="bundle-b",
                    members=("0000:66:00.0",),
                )
            ),
        )

    def test_reserved_clean_rollback_and_old_replays_do_not_touch_new_claim(self) -> None:
        old = self.store.begin(request())
        clean = self.clean_arguments(side_effects=False)
        old_released = self.store.rollback(
            old.transaction_id,
            old.vm_generation,
            old.revision,
            cleanup_verified=True,
            reason_code="NO_SIDE_EFFECTS",
            **clean,
        )
        self.assertEqual(LeaseState.RELEASED, old_released.state)
        self.assert_reason(
            Reason.VM_GENERATION_MISMATCH,
            lambda: self.store.begin(request("request-2", run_id="run-2")),
        )
        current = self.store.begin(
            request(
                "request-2",
                run_id="run-2",
                expected_vm_generation=1,
            )
        )
        self.assertEqual(old_released, self.store.begin(request()))
        replay = self.store.rollback(
            old.transaction_id,
            old.vm_generation,
            old.revision,
            cleanup_verified=True,
            reason_code="NO_SIDE_EFFECTS",
            **clean,
        )
        self.assertEqual(old_released, replay)
        self.assertEqual(
            {member: current.transaction_id for member in MEMBERS},
            self.store.claimed_members(HOST),
        )

    def test_bundle_and_member_claims_are_both_unique(self) -> None:
        first = self.store.begin(request())
        self.assert_reason(
            Reason.BUNDLE_BUSY,
            lambda: self.store.begin(
                request("same-bundle", vm_id="vm-2", run_id="run-2")
            ),
        )
        overlap = (MEMBERS[1], "0000:66:00.0")
        overlap_hash = self.publish_bundle("bundle-b", overlap)
        error = self.assert_reason(
            Reason.MEMBER_BUSY,
            lambda: self.store.begin(
                request(
                    "overlap",
                    vm_id="vm-2",
                    run_id="run-2",
                    bundle_id="bundle-b",
                    expected_bundle_hash=overlap_hash,
                    members=overlap,
                )
            ),
        )
        self.assertIn(MEMBERS[1], error.detail)
        self.assertEqual(first.transaction_id, self.store.claimed_members(HOST)[MEMBERS[1]])

    def test_prepare_commit_release_fsm_and_replays_are_idempotent(self) -> None:
        reserved = self.store.begin(request())
        preparing = self.store.prepare(reserved.transaction_id, 1, 0)
        self.assertEqual(preparing, self.store.prepare(reserved.transaction_id, 1, 0))
        attached = self.store.commit(reserved.transaction_id, 1, 1)
        self.assertEqual(attached, self.store.commit(reserved.transaction_id, 1, 1))
        releasing = self.store.begin_release(reserved.transaction_id, 1, 2)
        self.assertEqual(releasing, self.store.begin_release(reserved.transaction_id, 1, 2))
        clean = self.clean_arguments(side_effects=True)
        released = self.store.complete_release(
            reserved.transaction_id,
            1,
            3,
            cleanup_verified=True,
            **clean,
        )
        self.assertEqual(
            released,
            self.store.complete_release(
                reserved.transaction_id,
                1,
                3,
                cleanup_verified=True,
                **clean,
            ),
        )
        self.assertEqual(LeaseState.RELEASED, released.state)
        self.assertEqual({}, self.store.claimed_members(HOST))
        self.assertEqual({}, self.store.claimed_bundles(HOST))
        self.assertEqual(
            {MEMBERS[0]: 8, MEMBERS[1]: 9},
            {key: self.store.current_device_generations(HOST)[key] for key in MEMBERS},
        )
        self.assertEqual(
            [
                "BEGIN_RESERVED",
                "PREPARE_STARTED",
                "ATTACH_COMMITTED",
                "RELEASE_STARTED",
                "RELEASE_CLEAN",
            ],
            [entry.event for entry in self.store.journal(reserved.transaction_id)],
        )

    def test_release_fault_rolls_back_generation_state_journal_and_claim_deletes(self) -> None:
        reserved = self.store.begin(request())
        preparing = self.store.prepare(reserved.transaction_id, 1, 0)
        attached = self.store.commit(preparing.transaction_id, 1, 1)
        releasing = self.store.begin_release(attached.transaction_id, 1, 2)
        clean = self.clean_arguments(side_effects=True)

        def fault(point: str) -> None:
            if point == "RELEASE_CLEAN_BEFORE_COMMIT":
                raise RuntimeError("crash")

        self.reopen(fault_hook=fault)
        with self.assertRaisesRegex(RuntimeError, "crash"):
            self.store.complete_release(
                releasing.transaction_id,
                1,
                3,
                cleanup_verified=True,
                **clean,
            )
        self.reopen()
        self.assertEqual(LeaseState.RELEASING, self.store.get(releasing.transaction_id).state)
        self.assertEqual(
            {MEMBERS[0]: 7, MEMBERS[1]: 8},
            {key: self.store.current_device_generations(HOST)[key] for key in MEMBERS},
        )
        self.assertEqual(set(MEMBERS), set(self.store.claimed_members(HOST)))
        self.assertEqual(
            ["BEGIN_RESERVED", "PREPARE_STARTED", "ATTACH_COMMITTED", "RELEASE_STARTED"],
            [entry.event for entry in self.store.journal(releasing.transaction_id)],
        )

    def test_stale_revision_and_generation_cannot_advance_transaction(self) -> None:
        reserved = self.store.begin(request())
        self.assert_reason(
            Reason.TRANSACTION_GENERATION_MISMATCH,
            lambda: self.store.prepare(reserved.transaction_id, 99, 0),
        )
        preparing = self.store.prepare(reserved.transaction_id, 1, 0)
        self.assert_reason(
            Reason.LEASE_REVISION_MISMATCH,
            lambda: self.store.commit(reserved.transaction_id, 1, 0),
        )
        self.assertEqual(preparing, self.store.get(reserved.transaction_id))

    def test_s03_clean_bind_failure_advances_device_generation_before_reuse(self) -> None:
        reserved = self.store.begin(request())
        preparing = self.store.prepare(reserved.transaction_id, 1, 0)
        clean = self.clean_arguments(side_effects=True)
        released = self.store.rollback(
            preparing.transaction_id,
            1,
            preparing.revision,
            cleanup_verified=True,
            reason_code="BIND_FAILED_ORIGINAL_OWNER_RESTORED",
            **clean,
        )
        self.assertEqual(LeaseState.RELEASED, released.state)
        self.assertEqual({}, self.store.claimed_members(HOST))
        self.publish_bundle(
            "bundle-a",
            MEMBERS,
            epoch=EPOCH + 1,
            expected_current_hash=bundle_hash(),
        )
        replacement = self.store.begin(
            request(
                "request-2",
                run_id="run-2",
                expected_vm_generation=1,
                inventory_epoch=EPOCH + 1,
                expected_device_generations={MEMBERS[0]: 8, MEMBERS[1]: 9},
            )
        )
        self.assertEqual(set(MEMBERS), set(replacement.members))

    def test_s04_reset_failure_quarantines_whole_bundle(self) -> None:
        preparing = self.store.prepare(self.store.begin(request()).transaction_id, 1, 0)
        quarantined = self.store.quarantine(
            preparing.transaction_id,
            1,
            1,
            reason_code="RESET_STATE_VERIFY_FAILED",
        )
        self.assertEqual(LeaseState.QUARANTINED, quarantined.state)
        self.assertEqual(set(MEMBERS), set(self.store.claimed_members(HOST)))
        self.assertEqual({"bundle-a": quarantined.transaction_id}, self.store.claimed_bundles(HOST))

    def test_s05_qemu_failure_without_cleanup_evidence_is_quarantined(self) -> None:
        preparing = self.store.prepare(self.store.begin(request()).transaction_id, 1, 0)
        quarantined = self.store.rollback(
            preparing.transaction_id,
            1,
            1,
            cleanup_verified=False,
            reason_code="QEMU_START_FAILED",
        )
        self.assertEqual(LeaseState.QUARANTINED, quarantined.state)
        self.assertEqual(Reason.CLEANUP_EVIDENCE_REQUIRED.value, quarantined.reason_code)
        self.assertEqual(set(MEMBERS), set(self.store.claimed_members(HOST)))

    def test_f00_unknown_sigkill_reconcile_never_frees_claim(self) -> None:
        preparing = self.store.prepare(self.store.begin(request()).transaction_id, 1, 0)
        attached = self.store.commit(preparing.transaction_id, 1, 1)
        quarantined = self.store.reconcile(
            attached.transaction_id,
            1,
            2,
            ReconcileObservation.UNSAFE_OR_UNKNOWN,
            reason_detail="QEMU absent; DMA teardown not proven",
        )
        self.assertEqual(LeaseState.QUARANTINED, quarantined.state)
        self.assertEqual(set(MEMBERS), set(self.store.claimed_members(HOST)))

    def test_reconcile_active_owner_is_noop_only_for_attached(self) -> None:
        preparing = self.store.prepare(self.store.begin(request()).transaction_id, 1, 0)
        contradiction = self.store.reconcile(
            preparing.transaction_id,
            1,
            1,
            ReconcileObservation.ACTIVE_OWNER_VERIFIED,
        )
        self.assertEqual(LeaseState.QUARANTINED, contradiction.state)

        self.publish_bundle("bundle-b", ("0000:66:00.0",))
        second = self.store.begin(
            request(
                "request-2",
                vm_id="vm-2",
                run_id="run-2",
                bundle_id="bundle-b",
                members=("0000:66:00.0",),
            )
        )
        second = self.store.prepare(second.transaction_id, 1, 0)
        second = self.store.commit(second.transaction_id, 1, 1)
        observed = self.store.reconcile(
            second.transaction_id,
            1,
            2,
            ReconcileObservation.ACTIVE_OWNER_VERIFIED,
        )
        self.assertEqual(second, observed)

    def test_reconcile_cleanup_proof_releases_atomically_after_reopen(self) -> None:
        preparing = self.store.prepare(self.store.begin(request()).transaction_id, 1, 0)
        self.reopen()
        clean = self.clean_arguments(side_effects=True)
        recovered = self.store.reconcile(
            preparing.transaction_id,
            1,
            1,
            ReconcileObservation.CLEANUP_VERIFIED,
            **clean,
        )
        self.assertEqual(LeaseState.RELEASED, recovered.state)
        self.assertEqual({}, self.store.claimed_members(HOST))
        self.assert_reason(
            Reason.IDEMPOTENCY_CONFLICT,
            lambda: self.store.reconcile(
                preparing.transaction_id,
                1,
                1,
                ReconcileObservation.CLEANUP_VERIFIED,
                next_device_generations={MEMBERS[0]: 9, MEMBERS[1]: 10},
                next_authority_epoch=EPOCH + 2,
                authority_id=AUTHORITY,
            ),
        )

    def test_reconcile_rejects_untyped_process_absence_claim(self) -> None:
        reserved = self.store.begin(request())
        self.assert_reason(
            Reason.RECONCILE_OBSERVATION_INVALID,
            lambda: self.store.reconcile(
                reserved.transaction_id,
                1,
                0,
                "PROCESS_ABSENT",  # type: ignore[arg-type]
            ),
        )
        self.assertEqual(LeaseState.RESERVED, self.store.get(reserved.transaction_id).state)
        self.assertEqual(set(MEMBERS), set(self.store.claimed_members(HOST)))

    def test_transition_fault_does_not_partially_change_state_or_journal(self) -> None:
        reserved = self.store.begin(request())

        def fault(point: str) -> None:
            if point == "PREPARE_STARTED_BEFORE_COMMIT":
                raise RuntimeError("crash")

        self.reopen(fault_hook=fault)
        with self.assertRaisesRegex(RuntimeError, "crash"):
            self.store.prepare(reserved.transaction_id, 1, 0)
        self.reopen()
        self.assertEqual(LeaseState.RESERVED, self.store.get(reserved.transaction_id).state)
        self.assertEqual(
            ["BEGIN_RESERVED"],
            [entry.event for entry in self.store.journal(reserved.transaction_id)],
        )

    def test_invalid_request_shapes_fail_before_any_durable_change(self) -> None:
        invalid_members = BeginRequest(
            idempotency_key="bad",
            host_id=HOST,
            vm_id="vm-1",
            run_id="run-1",
            bundle_id="bundle-a",
            expected_bundle_hash=HASH_A,
            members=("not-a-bdf",),
            inventory_epoch=EPOCH,
            expected_vm_generation=0,
            expected_device_generations={"not-a-bdf": 1},
            decision_hash=HASH_A,
            policy_hash=HASH_B,
        )
        self.assert_reason(Reason.INVALID_ARGUMENT, lambda: self.store.begin(invalid_members))
        self.assert_reason(
            Reason.INVALID_ARGUMENT,
            lambda: self.store.begin(
                replace(
                    request(),
                    expected_device_generations=None,  # type: ignore[arg-type]
                )
            ),
        )
        self.assert_reason(
            Reason.INVALID_ARGUMENT,
            lambda: self.store.begin(
                replace(request(), inventory_epoch=1 << 63)
            ),
        )
        self.assertEqual(0, self.store.current_vm_generation(HOST, "vm-1"))
        self.assertEqual({}, self.store.claimed_members(HOST))


class StaticLeaseConcurrencyTest(unittest.TestCase):
    def test_concurrent_begin_has_one_winner_for_shared_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "lease.sqlite3"
            first = StaticLeaseStore(
                db,
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                timeout_seconds=10,
            )
            first.publish_authoritative_device_generations(
                HOST,
                ALL_GENERATIONS,
                expected_current={bdf: None for bdf in ALL_GENERATIONS},
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            )
            first.publish_authoritative_bundle(
                HOST,
                "bundle-a",
                MEMBERS,
                expected_current_hash=None,
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            )
            overlap = (MEMBERS[1], "0000:66:00.0")
            overlap_hash = first.publish_authoritative_bundle(
                HOST,
                "bundle-b",
                overlap,
                expected_current_hash=None,
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            )
            second = StaticLeaseStore(
                db,
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                timeout_seconds=10,
            )
            barrier = threading.Barrier(2)
            results: list[str] = []
            lock = threading.Lock()

            def run(store: StaticLeaseStore, begin_request: BeginRequest) -> None:
                barrier.wait()
                try:
                    store.begin(begin_request)
                    result = "OK"
                except LeaseStoreError as error:
                    result = error.reason.value
                with lock:
                    results.append(result)

            threads = [
                threading.Thread(
                    target=run,
                    args=(first, request("a", vm_id="a", run_id="a")),
                ),
                threading.Thread(
                    target=run,
                    args=(
                        second,
                        request(
                            "b",
                            vm_id="b",
                            run_id="b",
                            bundle_id="bundle-b",
                            expected_bundle_hash=overlap_hash,
                            members=overlap,
                        ),
                    ),
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(15)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual([Reason.MEMBER_BUSY.value, "OK"], sorted(results))
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
