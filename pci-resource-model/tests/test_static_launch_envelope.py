from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from pci_resource_model.static_launch_envelope import (
    EnvelopeReason,
    EnvelopeState,
    EnvelopeStoreError,
    LaunchIntent,
    ReceiptOutcome,
    ReceiptRole,
    RecoveryDisposition,
    SignedReceipt,
    StaticLaunchEnvelopeStore,
)
from pci_resource_model.static_lease import (
    BeginRequest,
    LeaseState,
    LeaseStoreError,
    Reason,
    StaticLeaseStore,
)


HOST = "host-a"
AUTHORITY = "inventory-publisher-v1"
EPOCH = 42
QMP_OBSERVER = "qmp-observer-v1"
DMA_OBSERVER = "dma-observer-v1"
QMP_KEY = b"qmp-observer-secret-key-material-01"
DMA_KEY = b"dma-observer-secret-key-material-01"
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64
HASH_E = "sha256:" + "e" * 64
DEVICE_FACTS = {"0000:64:00.0": 7, "0000:65:00.0": 8}
BUNDLES = {"bundle-1": ("0000:64:00.0",), "bundle-2": ("0000:65:00.0",)}


def verifier_keys() -> dict[ReceiptRole, dict[str, bytes]]:
    return {
        ReceiptRole.QMP: {QMP_OBSERVER: QMP_KEY},
        ReceiptRole.DMA: {DMA_OBSERVER: DMA_KEY},
    }


class ProcessVerifier:
    def __init__(self) -> None:
        self.live = True
        self.raise_error = False
        self.calls: list[tuple[int, str]] = []

    def __call__(self, pid: int, start_token: str) -> bool:
        self.calls.append((pid, start_token))
        if self.raise_error:
            raise OSError("process table unavailable")
        return self.live and pid > 0 and start_token.startswith("proc-start-")


class StaticLaunchEnvelopeStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.lease_db = self.root / "lease.sqlite3"
        self.envelope_db = self.root / "launch-envelope.sqlite3"
        self.ids = iter(("tx-1", "tx-2", "tx-3", "tx-4"))
        self.lease = StaticLeaseStore(
            self.lease_db,
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            transaction_id_factory=self.ids.__next__,
        )
        self.lease.publish_authoritative_device_generations(
            HOST,
            DEVICE_FACTS,
            expected_current={bdf: None for bdf in DEVICE_FACTS},
            authority_id=AUTHORITY,
            authority_epoch=EPOCH,
        )
        for bundle_id, members in BUNDLES.items():
            self.lease.publish_authoritative_bundle(
                HOST,
                bundle_id,
                members,
                expected_current_hash=None,
                authority_id=AUTHORITY,
                authority_epoch=EPOCH,
            )
        self.process = ProcessVerifier()
        self.store = self.open_store()
        self.reserved = self.reserve(1)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except (AttributeError, sqlite3.Error):
            pass
        try:
            self.lease.close()
        except (AttributeError, sqlite3.Error):
            pass
        self.temp.cleanup()

    def open_store(
        self,
        *,
        path: Path | None = None,
        lease: StaticLeaseStore | None = None,
        keys=None,
        process=None,
        process_id: str = "proc-verifier-v1",
        **kwargs,
    ) -> StaticLaunchEnvelopeStore:
        return StaticLaunchEnvelopeStore(
            path or self.envelope_db,
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            authoritative_lease_store=lease or self.lease,
            verifier_keys=verifier_keys() if keys is None else keys,
            process_identity_verifier=self.process if process is None else process,
            process_identity_verifier_id=process_id,
            allow_lab_process_identity_verifier=True,
            **kwargs,
        )

    def reopen(self, **kwargs) -> None:
        self.store.close()
        self.store = self.open_store(**kwargs)

    def reserve(self, number: int):
        bundle_id = f"bundle-{number}"
        members = BUNDLES[bundle_id]
        generations = {member: DEVICE_FACTS[member] for member in members}
        return self.lease.begin(
            BeginRequest(
                idempotency_key=f"request-{number}",
                host_id=HOST,
                vm_id=f"vm-{number}",
                run_id=f"run-{number}",
                bundle_id=bundle_id,
                expected_bundle_hash=StaticLeaseStore.compute_bundle_members_hash(
                    HOST, bundle_id, members
                ),
                members=members,
                inventory_epoch=EPOCH,
                expected_vm_generation=0,
                expected_device_generations=generations,
                decision_hash=HASH_A,
                policy_hash=HASH_B,
            )
        )

    def intent(self, lease=None, *, qmp_name: str | None = None) -> LaunchIntent:
        record = lease or self.reserved
        return LaunchIntent(
            transaction_id=record.transaction_id,
            host_id=record.host_id,
            vm_id=record.vm_id,
            run_id=record.run_id,
            bundle_id=record.bundle_id,
            vm_generation=record.vm_generation,
            planned_preparing_revision=record.revision + 1,
            decision_hash=record.decision_hash,
            policy_hash=record.policy_hash,
            qmp_endpoint=str(
                (
                    self.root / (qmp_name or f"{record.transaction_id}-qmp.sock")
                ).resolve()
            ),
        )

    def assert_reason(self, reason: EnvelopeReason, operation) -> EnvelopeStoreError:
        with self.assertRaises(EnvelopeStoreError) as caught:
            operation()
        self.assertEqual(reason, caught.exception.reason)
        return caught.exception

    def advance_to_prepared(self, lease=None, *, store=None, intent=None):
        authoritative = lease or self.reserved
        envelope = store or self.store
        persisted = envelope.begin(intent or self.intent(authoritative))
        self.assertIsNone(persisted.fd_binding_hash)
        self.assertIsNone(persisted.launch_plan_hash)
        prepared_lease = self.lease.prepare(
            authoritative.transaction_id,
            authoritative.vm_generation,
            authoritative.revision,
        )
        prepared = envelope.mark_lease_prepared(
            authoritative.transaction_id, persisted.revision
        )
        self.assertEqual(prepared_lease.revision, prepared.planned_preparing_revision)
        self.assertIsNone(prepared.fd_binding_hash)
        self.assertIsNone(prepared.launch_plan_hash)
        return prepared

    def advance_to_handles(self, lease=None, *, store=None, intent=None):
        authoritative = lease or self.reserved
        envelope = store or self.store
        prepared = self.advance_to_prepared(
            authoritative, store=envelope, intent=intent
        )
        opened = envelope.mark_handles_open(
            authoritative.transaction_id,
            prepared.revision,
            fd_binding_hash=HASH_D,
            launch_plan_hash=HASH_E,
        )
        self.assertEqual(HASH_D, opened.fd_binding_hash)
        self.assertEqual(HASH_E, opened.launch_plan_hash)
        return opened

    def advance_to_qemu(
        self,
        lease=None,
        *,
        store=None,
        intent=None,
        pid: int = 4242,
        token: str = "proc-start-123456",
    ):
        authoritative = lease or self.reserved
        envelope = store or self.store
        opened = self.advance_to_handles(authoritative, store=envelope, intent=intent)
        return envelope.mark_qemu_running(
            authoritative.transaction_id,
            opened.revision,
            qemu_pid=pid,
            qemu_start_token=token,
        )

    def receipt(
        self,
        role: ReceiptRole,
        *,
        store=None,
        transaction_id: str | None = None,
        nonce: str | None = None,
        **overrides,
    ) -> SignedReceipt:
        envelope = store or self.store
        transaction = transaction_id or self.reserved.transaction_id
        record = envelope.get(transaction)
        is_qmp = role is ReceiptRole.QMP
        values = {
            "observer_id": QMP_OBSERVER if is_qmp else DMA_OBSERVER,
            "envelope_store_id": record.envelope_store_id,
            "lease_store_binding_hash": record.lease_store_binding_hash,
            "receipt_challenge": record.receipt_challenge,
            "transaction_id": record.transaction_id,
            "host_id": record.host_id,
            "authority_id": record.authority_id,
            "lease_revision": record.planned_preparing_revision,
            "vm_generation": record.vm_generation,
            "decision_hash": record.decision_hash,
            "policy_hash": record.policy_hash,
            "launch_plan_hash": record.launch_plan_hash,
            "fd_binding_hash": record.fd_binding_hash,
            "qemu_pid": record.qemu_pid,
            "qemu_start_token": record.qemu_start_token,
            "outcome": (
                ReceiptOutcome.QMP_DEVICE_OBSERVED
                if is_qmp
                else ReceiptOutcome.DMA_ISOLATION_ESTABLISHED
            ),
            "nonce": nonce
            or (
                f"qmp-receipt-{transaction}-0001"
                if is_qmp
                else f"dma-receipt-{transaction}-0001"
            ),
        }
        values.update(overrides)
        return SignedReceipt.sign(
            key=QMP_KEY if is_qmp else DMA_KEY,
            role=role,
            **values,
        )

    def advance_receipts(self, transaction_id: str | None = None, *, store=None):
        envelope = store or self.store
        transaction = transaction_id or self.reserved.transaction_id
        running = envelope.get(transaction)
        qmp = envelope.mark_qmp_receipt_verified(
            transaction,
            running.revision,
            self.receipt(ReceiptRole.QMP, store=envelope, transaction_id=transaction),
        )
        return envelope.mark_dma_receipt_verified(
            transaction,
            qmp.revision,
            self.receipt(ReceiptRole.DMA, store=envelope, transaction_id=transaction),
        )

    def test_intent_reads_real_reserved_lease_and_plan_is_bound_only_with_handles(
        self,
    ) -> None:
        persisted = self.store.begin(self.intent())
        self.assertEqual(EnvelopeState.INTENT_PERSISTED, persisted.state)
        self.assertIsNone(persisted.fd_binding_hash)
        self.assertIsNone(persisted.launch_plan_hash)
        self.assertEqual(tuple(BUNDLES["bundle-1"]), persisted.members)
        self.assertEqual({"0000:64:00.0": 7}, persisted.device_generations)

        self.assert_reason(
            EnvelopeReason.IDEMPOTENCY_CONFLICT,
            lambda: self.store.begin(replace(self.intent(), vm_id="wrong-vm")),
        )
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.mark_lease_prepared(
                self.reserved.transaction_id, persisted.revision
            ),
        )
        self.lease.prepare(
            self.reserved.transaction_id,
            self.reserved.vm_generation,
            self.reserved.revision,
        )
        prepared = self.store.mark_lease_prepared(
            self.reserved.transaction_id, persisted.revision
        )
        self.assertIsNone(prepared.fd_binding_hash)
        self.assertIsNone(prepared.launch_plan_hash)
        opened = self.store.mark_handles_open(
            self.reserved.transaction_id,
            prepared.revision,
            fd_binding_hash=HASH_D,
            launch_plan_hash=HASH_E,
        )
        self.assertEqual(
            (HASH_D, HASH_E), (opened.fd_binding_hash, opened.launch_plan_hash)
        )

    def test_begin_rejects_non_reserved_or_mismatched_planned_revision(self) -> None:
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.begin(
                replace(self.intent(), planned_preparing_revision=99)
            ),
        )
        self.lease.prepare(
            self.reserved.transaction_id,
            self.reserved.vm_generation,
            self.reserved.revision,
        )
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.begin(self.intent()),
        )

    def test_prepared_revalidation_detects_authoritative_snapshot_drift(self) -> None:
        persisted = self.store.begin(self.intent())
        self.lease.prepare(
            self.reserved.transaction_id,
            self.reserved.vm_generation,
            self.reserved.revision,
        )
        self.lease._connection.execute(
            "UPDATE transactions SET decision_hash=? WHERE transaction_id=?",
            (HASH_C, self.reserved.transaction_id),
        )
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.mark_lease_prepared(
                self.reserved.transaction_id, persisted.revision
            ),
        )
        self.assertEqual(EnvelopeState.INTENT_PERSISTED, self.store.get("tx-1").state)

    def test_happy_path_requires_real_attached_lease_and_exact_receipts(self) -> None:
        running = self.advance_to_qemu()
        qmp = self.store.mark_qmp_receipt_verified(
            "tx-1", running.revision, self.receipt(ReceiptRole.QMP)
        )
        dma = self.store.mark_dma_receipt_verified(
            "tx-1", qmp.revision, self.receipt(ReceiptRole.DMA)
        )
        commit_intent = self.store.mark_commit_intent("tx-1", dma.revision)
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.confirm_attached("tx-1", commit_intent.revision),
        )
        attached_lease = self.lease.commit(
            "tx-1",
            self.reserved.vm_generation,
            self.reserved.revision + 1,
        )
        attached = self.store.confirm_attached("tx-1", commit_intent.revision)
        self.assertEqual(EnvelopeState.ATTACHED_CONFIRMED, attached.state)
        self.assertEqual(attached_lease.revision, attached.attached_lease_revision)
        self.assertEqual(
            attached,
            self.store.confirm_attached("tx-1", commit_intent.revision),
        )
        self.assertEqual(
            [
                "INTENT_PERSISTED",
                "LEASE_PREPARED",
                "HANDLES_OPEN",
                "QEMU_RUNNING",
                "QMP_RECEIPT_VERIFIED",
                "DMA_RECEIPT_VERIFIED",
                "COMMIT_INTENT_DURABLE",
                "ATTACHED_CONFIRMED",
            ],
            [entry.event for entry in self.store.journal("tx-1")],
        )

    def test_process_identity_is_live_checked_at_every_launch_gate(self) -> None:
        opened = self.advance_to_handles()
        self.process.live = False
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.mark_qemu_running(
                "tx-1",
                opened.revision,
                qemu_pid=4242,
                qemu_start_token="proc-start-123456",
            ),
        )
        self.process.live = True
        running = self.store.mark_qemu_running(
            "tx-1",
            opened.revision,
            qemu_pid=4242,
            qemu_start_token="proc-start-123456",
        )
        self.process.live = False
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.mark_qmp_receipt_verified(
                "tx-1", running.revision, self.receipt(ReceiptRole.QMP)
            ),
        )
        self.process.live = True
        qmp = self.store.mark_qmp_receipt_verified(
            "tx-1", running.revision, self.receipt(ReceiptRole.QMP)
        )
        self.process.live = False
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.mark_dma_receipt_verified(
                "tx-1", qmp.revision, self.receipt(ReceiptRole.DMA)
            ),
        )
        self.process.live = True
        dma = self.store.mark_dma_receipt_verified(
            "tx-1", qmp.revision, self.receipt(ReceiptRole.DMA)
        )
        self.process.live = False
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.mark_commit_intent("tx-1", dma.revision),
        )
        self.process.raise_error = True
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.mark_commit_intent("tx-1", dma.revision),
        )
        self.process.raise_error = False
        self.process.live = True
        commit_intent = self.store.mark_commit_intent("tx-1", dma.revision)
        self.lease.commit("tx-1", self.reserved.vm_generation, 1)
        self.process.live = False
        self.assert_reason(
            EnvelopeReason.PROCESS_IDENTITY_STALE,
            lambda: self.store.confirm_attached("tx-1", commit_intent.revision),
        )
        self.assertEqual(
            EnvelopeState.COMMIT_INTENT_DURABLE, self.store.get("tx-1").state
        )

    def test_reentrant_write_and_close_cannot_rollback_or_close_outer_write(
        self,
    ) -> None:
        holder: dict[str, StaticLaunchEnvelopeStore] = {}
        caught_reentry: list[EnvelopeReason] = []
        catch_inner = False

        def verifier(pid: int, token: str) -> bool:
            del pid, token
            try:
                with holder["store"]._write():
                    raise AssertionError("nested write must never begin")
            except EnvelopeStoreError as error:
                caught_reentry.append(error.reason)
                if not catch_inner:
                    raise
            try:
                holder["store"].close()
            except EnvelopeStoreError as error:
                caught_reentry.append(error.reason)
            return True

        reentrant = self.open_store(
            path=self.root / "reentrant-envelope.sqlite3",
            process=verifier,
            process_id="reentrant-lab-verifier-v1",
        )
        holder["store"] = reentrant
        try:
            opened = self.advance_to_handles(store=reentrant)
            self.assert_reason(
                EnvelopeReason.PROCESS_IDENTITY_STALE,
                lambda: reentrant.mark_qemu_running(
                    "tx-1",
                    opened.revision,
                    qemu_pid=4242,
                    qemu_start_token="proc-start-reentrant",
                ),
            )
            after_failure = reentrant.get("tx-1")
            self.assertEqual(EnvelopeState.HANDLES_OPEN, after_failure.state)
            self.assertEqual(opened.revision, after_failure.revision)
            self.assertNotIn(
                "QEMU_RUNNING", [entry.event for entry in reentrant.journal("tx-1")]
            )

            catch_inner = True
            running = reentrant.mark_qemu_running(
                "tx-1",
                opened.revision,
                qemu_pid=4242,
                qemu_start_token="proc-start-reentrant",
            )
            self.assertEqual(EnvelopeState.QEMU_RUNNING, running.state)
            self.assertEqual(
                [
                    EnvelopeReason.REENTRANT_STORE_OPERATION,
                    EnvelopeReason.REENTRANT_STORE_OPERATION,
                    EnvelopeReason.REENTRANT_STORE_OPERATION,
                ],
                caught_reentry,
            )
            self.assertEqual(
                1,
                sum(
                    entry.event == "QEMU_RUNNING" for entry in reentrant.journal("tx-1")
                ),
            )
        finally:
            reentrant.close()

    def test_production_process_verifier_is_builtin_linux_only_and_pinned(
        self,
    ) -> None:
        production_path = self.root / "production-process-envelope.sqlite3"

        def constructor() -> StaticLaunchEnvelopeStore:
            return StaticLaunchEnvelopeStore(
                production_path,
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                authoritative_lease_store=self.lease,
                verifier_keys=verifier_keys(),
            )

        if not sys.platform.startswith("linux"):
            self.assert_reason(EnvelopeReason.PROCESS_VERIFIER_UNAVAILABLE, constructor)
            return

        token = StaticLaunchEnvelopeStore.capture_linux_process_start_token(os.getpid())
        self.assertTrue(
            StaticLaunchEnvelopeStore._builtin_linux_process_identity_verifier(
                os.getpid(), token
            )
        )
        prefix, starttime = token.rsplit(":", 1)
        self.assertFalse(
            StaticLaunchEnvelopeStore._builtin_linux_process_identity_verifier(
                os.getpid(), f"{prefix}:{int(starttime) + 1}"
            )
        )

        production = constructor()
        try:
            connection = sqlite3.connect(production_path)
            provenance = json.loads(
                connection.execute(
                    "SELECT value FROM metadata "
                    "WHERE key='process_identity_verifier_provenance'"
                ).fetchone()[0]
            )
            connection.close()
            self.assertEqual("PRODUCTION", provenance["mode"])
            self.assertEqual(
                StaticLaunchEnvelopeStore._PRODUCTION_PROCESS_PROVENANCE,
                provenance["implementation"],
            )
        finally:
            production.close()

        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: StaticLaunchEnvelopeStore(
                production_path,
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                authoritative_lease_store=self.lease,
                verifier_keys=verifier_keys(),
                process_identity_verifier=lambda _pid, _token: True,
                process_identity_verifier_id=(
                    StaticLaunchEnvelopeStore._PRODUCTION_PROCESS_PROVENANCE
                ),
                allow_lab_process_identity_verifier=True,
            ),
        )

    def test_injected_process_verifier_requires_explicit_lab_opt_in(self) -> None:
        self.assert_reason(
            EnvelopeReason.PROCESS_VERIFIER_UNAVAILABLE,
            lambda: StaticLaunchEnvelopeStore(
                self.root / "implicit-lab-verifier.sqlite3",
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                authoritative_lease_store=self.lease,
                verifier_keys=verifier_keys(),
                process_identity_verifier=lambda _pid, _token: True,
                process_identity_verifier_id="implicit-lab-verifier-v1",
            ),
        )

    def test_receipt_tamper_cross_role_stale_revision_and_nonce_replay_fail(
        self,
    ) -> None:
        running = self.advance_to_qemu()
        valid = self.receipt(ReceiptRole.QMP)
        self.assert_reason(
            EnvelopeReason.RECEIPT_SIGNATURE_INVALID,
            lambda: self.store.mark_qmp_receipt_verified(
                "tx-1",
                running.revision,
                replace(valid, qemu_start_token="proc-start-tampered"),
            ),
        )
        stale = self.receipt(
            ReceiptRole.QMP,
            nonce="stale-lease-revision-0001",
            lease_revision=99,
        )
        self.assert_reason(
            EnvelopeReason.RECEIPT_BINDING_MISMATCH,
            lambda: self.store.mark_qmp_receipt_verified(
                "tx-1", running.revision, stale
            ),
        )
        qmp = self.store.mark_qmp_receipt_verified("tx-1", running.revision, valid)
        self.assert_reason(
            EnvelopeReason.RECEIPT_ROLE_MISMATCH,
            lambda: self.store.mark_dma_receipt_verified("tx-1", qmp.revision, valid),
        )

        second = self.reserve(2)
        second_running = self.advance_to_qemu(
            second,
            intent=self.intent(second, qmp_name="tx-2-qmp.sock"),
            pid=4343,
            token="proc-start-654321",
        )
        replay = self.receipt(
            ReceiptRole.QMP,
            transaction_id="tx-2",
            nonce=valid.nonce,
        )
        self.assert_reason(
            EnvelopeReason.RECEIPT_REPLAY,
            lambda: self.store.mark_qmp_receipt_verified(
                "tx-2", second_running.revision, replay
            ),
        )

    def test_receipt_is_bound_to_envelope_store_host_authority_and_challenge(
        self,
    ) -> None:
        second_db = self.root / "second-envelope.sqlite3"
        second_store = self.open_store(path=second_db)
        try:
            first_persisted = self.store.begin(self.intent())
            second_persisted = second_store.begin(
                self.intent(qmp_name="second-store-qmp.sock")
            )
            self.assertNotEqual(
                first_persisted.envelope_store_id,
                second_persisted.envelope_store_id,
            )
            self.assertNotEqual(
                first_persisted.receipt_challenge,
                second_persisted.receipt_challenge,
            )
            self.lease.prepare("tx-1", self.reserved.vm_generation, 0)
            first = self.store.mark_lease_prepared("tx-1", 0)
            second = second_store.mark_lease_prepared("tx-1", 0)
            first = self.store.mark_handles_open(
                "tx-1", first.revision, fd_binding_hash=HASH_D, launch_plan_hash=HASH_E
            )
            second = second_store.mark_handles_open(
                "tx-1", second.revision, fd_binding_hash=HASH_D, launch_plan_hash=HASH_E
            )
            first = self.store.mark_qemu_running(
                "tx-1",
                first.revision,
                qemu_pid=4242,
                qemu_start_token="proc-start-123456",
            )
            second = second_store.mark_qemu_running(
                "tx-1",
                second.revision,
                qemu_pid=4242,
                qemu_start_token="proc-start-123456",
            )
            cross_store = self.receipt(ReceiptRole.QMP, store=self.store)
            self.assert_reason(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                lambda: second_store.mark_qmp_receipt_verified(
                    "tx-1", second.revision, cross_store
                ),
            )
            cross_host = self.receipt(
                ReceiptRole.QMP,
                store=self.store,
                nonce="cross-host-receipt-0001",
                host_id="host-b",
            )
            self.assert_reason(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                lambda: self.store.mark_qmp_receipt_verified(
                    "tx-1", first.revision, cross_host
                ),
            )
            cross_authority = self.receipt(
                ReceiptRole.QMP,
                store=self.store,
                nonce="cross-authority-receipt-01",
                authority_id="inventory-publisher-v2",
            )
            self.assert_reason(
                EnvelopeReason.RECEIPT_BINDING_MISMATCH,
                lambda: self.store.mark_qmp_receipt_verified(
                    "tx-1", first.revision, cross_authority
                ),
            )
        finally:
            second_store.close()

    def test_persisted_receipts_are_reverified_and_both_are_required_for_commit(
        self,
    ) -> None:
        self.advance_to_qemu()
        dma = self.advance_receipts()
        self.store.close()
        connection = sqlite3.connect(self.envelope_db)
        connection.execute(
            """UPDATE receipts SET payload_json=replace(
                   payload_json,'proc-start-123456','proc-start-tampered')
               WHERE transaction_id='tx-1' AND role='QMP'"""
        )
        connection.commit()
        connection.close()
        self.store = self.open_store()
        self.assert_reason(
            EnvelopeReason.RECEIPT_BINDING_MISMATCH,
            lambda: self.store.mark_commit_intent("tx-1", dma.revision),
        )

        self.store.close()
        connection = sqlite3.connect(self.envelope_db)
        connection.execute(
            "DELETE FROM receipts WHERE transaction_id='tx-1' AND role='DMA'"
        )
        connection.commit()
        connection.close()
        self.store = self.open_store()
        self.assert_reason(
            EnvelopeReason.RECEIPTS_REQUIRED,
            lambda: self.store.mark_commit_intent("tx-1", dma.revision),
        )

    def test_clean_success_is_unreachable_and_quarantine_requires_real_lease_state(
        self,
    ) -> None:
        persisted = self.store.begin(self.intent())
        cleaning = self.store.start_cleaning(
            "tx-1", persisted.revision, reason_code="LAUNCH_ABORTED"
        )
        self.assertFalse(hasattr(self.store, "mark_rolled_back_clean"))
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.confirm_quarantined("tx-1", cleaning.revision),
        )
        quarantined_lease = self.lease.quarantine(
            "tx-1",
            self.reserved.vm_generation,
            self.reserved.revision,
            reason_code="CLEANUP_NOT_PROVEN",
        )
        quarantined = self.store.confirm_quarantined("tx-1", cleaning.revision)
        self.assertEqual(LeaseState.QUARANTINED, quarantined_lease.state)
        self.assertEqual(EnvelopeState.QUARANTINED, quarantined.state)
        self.assertEqual(
            RecoveryDisposition.MAINTAIN_QUARANTINE,
            self.store.recovery_disposition("tx-1"),
        )

    def test_recovery_origin_commit_can_confirm_real_attached(self) -> None:
        self.advance_to_qemu()
        dma = self.advance_receipts()
        commit_intent = self.store.mark_commit_intent("tx-1", dma.revision)
        recovery = self.store.mark_recovery_required(
            "tx-1",
            commit_intent.revision,
            reason_code="LEASE_COMMIT_RESULT_UNKNOWN",
        )
        self.assertEqual(
            EnvelopeState.COMMIT_INTENT_DURABLE, recovery.recovery_origin_state
        )
        self.reopen()
        self.assertEqual(
            EnvelopeState.COMMIT_INTENT_DURABLE,
            self.store.get("tx-1").recovery_origin_state,
        )
        self.assert_reason(
            EnvelopeReason.LEASE_FACT_MISMATCH,
            lambda: self.store.confirm_attached("tx-1", recovery.revision),
        )
        self.lease.commit("tx-1", self.reserved.vm_generation, 1)
        attached = self.store.confirm_attached("tx-1", recovery.revision)
        self.assertEqual(EnvelopeState.ATTACHED_CONFIRMED, attached.state)

    def test_any_recovery_origin_can_confirm_real_quarantine_but_not_attach(
        self,
    ) -> None:
        prepared = self.advance_to_prepared()
        recovery = self.store.mark_recovery_required(
            "tx-1", prepared.revision, reason_code="UNKNOWN_PREPARE_RESULT"
        )
        self.assertEqual(EnvelopeState.LEASE_PREPARED, recovery.recovery_origin_state)
        self.assert_reason(
            EnvelopeReason.INVALID_STATE_TRANSITION,
            lambda: self.store.confirm_attached("tx-1", recovery.revision),
        )
        self.lease.quarantine(
            "tx-1", self.reserved.vm_generation, 1, reason_code="RECOVERY_UNSAFE"
        )
        quarantined = self.store.confirm_quarantined("tx-1", recovery.revision)
        self.assertEqual(EnvelopeState.QUARANTINED, quarantined.state)

    def test_schema_and_metadata_initialization_is_one_atomic_transaction(self) -> None:
        for index, fault_point in enumerate(
            ("SCHEMA_AFTER_DDL", "SCHEMA_INITIALIZE_BEFORE_COMMIT")
        ):
            path = self.root / f"faulted-init-{index}.sqlite3"

            def fault(point: str, expected=fault_point) -> None:
                if point == expected:
                    raise RuntimeError("initialization crash")

            with self.assertRaisesRegex(RuntimeError, "initialization crash"):
                self.open_store(path=path, fault_hook=fault)
            connection = sqlite3.connect(path)
            objects = connection.execute(
                """SELECT type,name FROM sqlite_master
                   WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%'"""
            ).fetchall()
            connection.close()
            self.assertEqual([], objects)
            recovered = self.open_store(path=path)
            recovered.close()

    def test_live_malicious_trigger_is_rejected_before_it_can_mutate_state(
        self,
    ) -> None:
        persisted = self.store.begin(self.intent())
        self.lease.prepare("tx-1", self.reserved.vm_generation, self.reserved.revision)
        connection = sqlite3.connect(self.envelope_db)
        connection.execute(
            """CREATE TRIGGER force_attached_after_update
               AFTER UPDATE ON envelopes
               BEGIN
                 UPDATE envelopes SET state='ATTACHED_CONFIRMED', revision=999
                  WHERE transaction_id=NEW.transaction_id;
               END"""
        )
        connection.commit()
        connection.close()

        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.store.mark_lease_prepared("tx-1", persisted.revision),
        )
        connection = sqlite3.connect(self.envelope_db)
        state, revision = connection.execute(
            "SELECT state,revision FROM envelopes WHERE transaction_id='tx-1'"
        ).fetchone()
        journal_count = connection.execute(
            "SELECT COUNT(*) FROM journal WHERE transaction_id='tx-1'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER force_attached_after_update")
        connection.commit()
        connection.close()
        self.assertEqual((EnvelopeState.INTENT_PERSISTED.value, 0), (state, revision))
        self.assertEqual(1, journal_count)
        self.assertEqual(
            EnvelopeState.LEASE_PREPARED,
            self.store.mark_lease_prepared("tx-1", persisted.revision).state,
        )

    def test_extra_schema_objects_and_structural_drift_are_rejected(self) -> None:
        mutations = {
            "extra-view": "CREATE VIEW unexpected_view AS SELECT vm_id FROM envelopes",
            "extra-index": "CREATE INDEX unexpected_index ON envelopes(vm_id)",
            "extra-column": "ALTER TABLE envelopes ADD COLUMN injected TEXT",
        }
        for name, statement in mutations.items():
            with self.subTest(name=name):
                path = self.root / f"{name}.sqlite3"
                created = self.open_store(path=path)
                created.close()
                connection = sqlite3.connect(path)
                connection.execute(statement)
                connection.commit()
                connection.close()
                self.assert_reason(
                    EnvelopeReason.METADATA_INTEGRITY_FAILURE,
                    lambda path=path: self.open_store(path=path),
                )

    def test_existing_metadata_must_be_exact_and_is_never_backfilled(self) -> None:
        self.store.close()
        connection = sqlite3.connect(self.envelope_db)
        connection.execute("DELETE FROM metadata WHERE key='trusted_authority_id'")
        connection.commit()
        connection.close()
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(),
        )
        changed_keys = {
            ReceiptRole.QMP: {QMP_OBSERVER: b"replacement-qmp-key-material-0001"},
            ReceiptRole.DMA: {DMA_OBSERVER: DMA_KEY},
        }
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(keys=changed_keys),
        )

        extra_path = self.root / "extra-metadata.sqlite3"
        extra = self.open_store(path=extra_path)
        extra.close()
        connection = sqlite3.connect(extra_path)
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('unexpected','value')"
        )
        connection.commit()
        connection.close()
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(path=extra_path),
        )

        missing_index_path = self.root / "missing-index.sqlite3"
        missing_index = self.open_store(path=missing_index_path)
        missing_index.close()
        connection = sqlite3.connect(missing_index_path)
        connection.execute("DROP INDEX journal_transaction_sequence")
        connection.commit()
        connection.close()
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(path=missing_index_path),
        )

    def test_verifier_key_and_process_verifier_identity_are_pinned(self) -> None:
        self.store.close()
        changed_keys = {
            ReceiptRole.QMP: {QMP_OBSERVER: b"replacement-qmp-key-material-0001"},
            ReceiptRole.DMA: {DMA_OBSERVER: DMA_KEY},
        }
        self.assert_reason(
            EnvelopeReason.VERIFIER_CONFIG_MISMATCH,
            lambda: self.open_store(keys=changed_keys),
        )
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(process_id="different-proc-verifier-v2"),
        )

    def test_lease_database_copy_and_same_path_replacement_break_binding(self) -> None:
        original_binding = self.store.lease_store_binding_hash
        self.store.close()
        self.lease.close()
        copied_path = self.root / "copied-lease.sqlite3"
        shutil.copy2(self.lease_db, copied_path)
        copied = StaticLeaseStore(
            copied_path,
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
        )
        try:
            self.assert_reason(
                EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                lambda: self.open_store(lease=copied),
            )
        finally:
            copied.close()

        os.replace(copied_path, self.lease_db)
        self.lease = StaticLeaseStore(
            self.lease_db,
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
        )
        self.assert_reason(
            EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
            lambda: self.open_store(),
        )
        replacement_envelope = self.open_store(
            path=self.root / "replacement-envelope.sqlite3"
        )
        try:
            self.assertNotEqual(
                original_binding, replacement_envelope.lease_store_binding_hash
            )
        finally:
            replacement_envelope.close()

    def test_envelope_database_copy_cannot_reuse_store_identity_or_receipts(self) -> None:
        running = self.advance_to_qemu()
        receipt = self.receipt(ReceiptRole.QMP)
        original_store_id = running.envelope_store_id
        self.store.close()

        copied_path = self.root / "copied-envelope.sqlite3"
        shutil.copy2(self.envelope_db, copied_path)
        self.store = self.open_store()
        self.assertEqual(original_store_id, self.store.envelope_store_id)
        verified = self.store.mark_qmp_receipt_verified(
            "tx-1", running.revision, receipt
        )
        self.assertEqual(EnvelopeState.QMP_RECEIPT_VERIFIED, verified.state)

        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.open_store(path=copied_path),
        )

    def test_temporary_schema_objects_are_rejected_before_authoritative_write(self) -> None:
        prepared = self.advance_to_prepared()
        self.store._connection.execute(
            """CREATE TEMP TRIGGER corrupt_handles
               AFTER UPDATE ON main.envelopes
               BEGIN
                   UPDATE envelopes
                      SET reason_code='TEMP_TRIGGER_MUTATION'
                    WHERE transaction_id=NEW.transaction_id;
               END"""
        )
        self.assert_reason(
            EnvelopeReason.METADATA_INTEGRITY_FAILURE,
            lambda: self.store.mark_handles_open(
                "tx-1",
                prepared.revision,
                fd_binding_hash=HASH_D,
                launch_plan_hash=HASH_E,
            ),
        )
        self.store._connection.execute("DROP TRIGGER temp.corrupt_handles")
        unchanged = self.store.get("tx-1")
        self.assertEqual(EnvelopeState.LEASE_PREPARED, unchanged.state)
        self.assertEqual(prepared.revision, unchanged.revision)
        self.assertIsNone(unchanged.reason_code)

    def test_final_lease_binding_failure_rolls_back_staged_envelope_write(self) -> None:
        prepared = self.advance_to_prepared()
        original_check = self.store._assert_live_lease_store_binding
        after_staged_update = False
        injected = False

        def fault(point: str) -> None:
            nonlocal after_staged_update
            if point == "HANDLES_OPEN_BEFORE_COMMIT":
                after_staged_update = True

        def final_check() -> None:
            nonlocal injected
            if after_staged_update and not injected:
                injected = True
                raise EnvelopeStoreError(
                    EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
                    "injected final lease binding drift",
                )
            original_check()

        self.store._fault_hook = fault
        self.store._assert_live_lease_store_binding = final_check  # type: ignore[method-assign]
        self.assert_reason(
            EnvelopeReason.LEASE_STORE_BINDING_MISMATCH,
            lambda: self.store.mark_handles_open(
                "tx-1",
                prepared.revision,
                fd_binding_hash=HASH_D,
                launch_plan_hash=HASH_E,
            ),
        )
        self.store._fault_hook = None
        self.store._assert_live_lease_store_binding = original_check  # type: ignore[method-assign]
        unchanged = self.store.get("tx-1")
        self.assertEqual(EnvelopeState.LEASE_PREPARED, unchanged.state)
        self.assertEqual(prepared.revision, unchanged.revision)
        self.assertIsNone(unchanged.fd_binding_hash)
        self.assertIsNone(unchanged.launch_plan_hash)
        self.assertNotIn(
            "HANDLES_OPEN", [entry.event for entry in self.store.journal("tx-1")]
        )

    def test_constructor_rejects_volatile_paths_closed_or_nonconcrete_lease(
        self,
    ) -> None:
        for path in (":memory:", "file:volatile?mode=memory", "relative.sqlite3"):
            self.assert_reason(
                EnvelopeReason.STORE_NOT_DURABLE,
                lambda path=path: StaticLaunchEnvelopeStore(
                    path,
                    local_host_id=HOST,
                    trusted_authority_id=AUTHORITY,
                    authoritative_lease_store=self.lease,
                    verifier_keys=verifier_keys(),
                    process_identity_verifier=self.process,
                    process_identity_verifier_id="proc-verifier-v1",
                    allow_lab_process_identity_verifier=True,
                ),
            )
        self.assert_reason(
            EnvelopeReason.LEASE_STORE_INVALID,
            lambda: StaticLaunchEnvelopeStore(
                self.root / "invalid-lease.sqlite3",
                local_host_id=HOST,
                trusted_authority_id=AUTHORITY,
                authoritative_lease_store=object(),  # type: ignore[arg-type]
                verifier_keys=verifier_keys(),
                process_identity_verifier=self.process,
                process_identity_verifier_id="proc-verifier-v1",
                allow_lab_process_identity_verifier=True,
            ),
        )
        self.lease.close()
        self.assert_reason(
            EnvelopeReason.LEASE_STORE_UNAVAILABLE,
            lambda: self.open_store(path=self.root / "closed-lease.sqlite3"),
        )

    def test_wal_full_scope_metadata_and_secret_keys_are_not_persisted(self) -> None:
        profile = self.store.durability_profile()
        self.assertEqual(("wal", 2), (profile.journal_mode, profile.synchronous))
        self.store.begin(self.intent())
        self.store.close()
        material = b""
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.envelope_db) + suffix)
            if candidate.exists():
                material += candidate.read_bytes()
        self.assertNotIn(QMP_KEY, material)
        self.assertNotIn(DMA_KEY, material)
        connection = sqlite3.connect(self.envelope_db)
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        connection.close()
        self.assertEqual(set(StaticLaunchEnvelopeStore._METADATA_KEYS), set(metadata))
        self.assertEqual(HOST, metadata["local_host_id"])
        self.assertEqual(AUTHORITY, metadata["trusted_authority_id"])
        self.store = self.open_store()

    def test_concurrent_envelope_revision_cas_has_one_winner(self) -> None:
        prepared = self.advance_to_prepared()
        second = self.open_store()
        try:
            barrier = threading.Barrier(2)
            results: list[str] = []
            lock = threading.Lock()

            def run(
                store: StaticLaunchEnvelopeStore, fd_hash: str, plan_hash: str
            ) -> None:
                barrier.wait()
                try:
                    store.mark_handles_open(
                        "tx-1",
                        prepared.revision,
                        fd_binding_hash=fd_hash,
                        launch_plan_hash=plan_hash,
                    )
                    result = "OK"
                except EnvelopeStoreError as error:
                    result = error.reason.value
                with lock:
                    results.append(result)

            threads = [
                threading.Thread(target=run, args=(self.store, HASH_C, HASH_D)),
                threading.Thread(target=run, args=(second, HASH_D, HASH_E)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(15)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(1, results.count("OK"))
            self.assertIn(
                next(result for result in results if result != "OK"),
                {
                    EnvelopeReason.IDEMPOTENCY_CONFLICT.value,
                    EnvelopeReason.LEASE_STORE_UNAVAILABLE.value,
                },
            )
        finally:
            second.close()

    def test_lease_snapshot_is_held_through_envelope_commit(self) -> None:
        prepared = self.advance_to_prepared()
        static_reentry: list[Reason] = []
        envelope_reentry: list[EnvelopeReason] = []

        def fault(point: str) -> None:
            if point != "HANDLES_OPEN_BEFORE_COMMIT":
                return
            try:
                with self.store._write():
                    raise AssertionError("nested envelope write must never begin")
            except EnvelopeStoreError as error:
                envelope_reentry.append(error.reason)
            try:
                self.store.close()
            except EnvelopeStoreError as error:
                envelope_reentry.append(error.reason)
            try:
                self.lease.quarantine(
                    "tx-1",
                    self.reserved.vm_generation,
                    self.reserved.revision + 1,
                    reason_code="RACING_QUARANTINE",
                )
            except LeaseStoreError as error:
                static_reentry.append(error.reason)

        self.store._fault_hook = fault
        opened = self.store.mark_handles_open(
            "tx-1",
            prepared.revision,
            fd_binding_hash=HASH_D,
            launch_plan_hash=HASH_E,
        )
        self.assertEqual(EnvelopeState.HANDLES_OPEN, opened.state)
        self.assertEqual(
            [
                EnvelopeReason.REENTRANT_STORE_OPERATION,
                EnvelopeReason.REENTRANT_STORE_OPERATION,
            ],
            envelope_reentry,
        )
        self.assertEqual([Reason.STORE_TRANSACTION_ACTIVE], static_reentry)
        self.assertEqual(LeaseState.PREPARING, self.lease.get("tx-1").state)

    def test_uncaught_reentry_after_staged_update_rolls_back_outer_api(self) -> None:
        prepared = self.advance_to_prepared()

        def fault(point: str) -> None:
            if point == "HANDLES_OPEN_BEFORE_COMMIT":
                with self.store._write():
                    raise AssertionError("nested envelope write must never begin")

        self.store._fault_hook = fault
        self.assert_reason(
            EnvelopeReason.REENTRANT_STORE_OPERATION,
            lambda: self.store.mark_handles_open(
                "tx-1",
                prepared.revision,
                fd_binding_hash=HASH_D,
                launch_plan_hash=HASH_E,
            ),
        )
        after_failure = self.store.get("tx-1")
        self.assertEqual(EnvelopeState.LEASE_PREPARED, after_failure.state)
        self.assertEqual(prepared.revision, after_failure.revision)
        self.assertIsNone(after_failure.fd_binding_hash)
        self.assertIsNone(after_failure.launch_plan_hash)
        self.assertNotIn(
            "HANDLES_OPEN", [entry.event for entry in self.store.journal("tx-1")]
        )

    def test_envelope_snapshot_guard_reuses_active_launch_authorization(self) -> None:
        prepared = self.advance_to_prepared()
        with self.lease.authorize_launch(
            "tx-1",
            self.reserved.vm_generation,
            self.reserved.revision + 1,
        ) as authorization:
            opened = self.store.mark_handles_open(
                "tx-1",
                prepared.revision,
                fd_binding_hash=HASH_D,
                launch_plan_hash=HASH_E,
            )
            running = self.store.mark_qemu_running(
                "tx-1",
                opened.revision,
                qemu_pid=4242,
                qemu_start_token="proc-start-authorized",
            )
            self.assertTrue(authorization.is_active)
            self.assertEqual(EnvelopeState.QEMU_RUNNING, running.state)
        self.assertFalse(authorization.is_active)

    @unittest.skipUnless(
        os.name == "posix" and Path("/mnt/e").is_dir(), "WSL DrvFS path only"
    )
    def test_wsl_drvfs_live_database_is_denied(self) -> None:
        path = Path("/mnt/e") / f"qman-launch-envelope-{os.getpid()}.sqlite3"
        try:
            self.assert_reason(
                EnvelopeReason.STORE_NOT_DURABLE,
                lambda: self.open_store(path=path),
            )
            self.assertFalse(path.exists())
        finally:
            if path.exists():
                path.unlink()


if __name__ == "__main__":
    unittest.main()
