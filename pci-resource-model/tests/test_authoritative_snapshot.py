from __future__ import annotations

import copy
import json
import pickle
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from pci_resource_model import vfio_launch_handles as launch
from pci_resource_model import vfio_provider as vfio
from pci_resource_model.authoritative_snapshot import (
    AuthoritativeSnapshotStore,
    ComponentHmacAuthenticator,
    LaunchDeviceFacts,
    LiveCapturePhase,
    SnapshotCapture,
    SnapshotError,
    SnapshotLaunchAuthorization,
    SnapshotReason,
    compute_full_topology_hash,
    validate_launch_authorization,
)
from pci_resource_model.model import (
    DeviceInventory,
    DmaIsolationMode,
    FactEvidence,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
    MemberAction,
)


HOST = "host-a"
AUTHORITY = "inventory-publisher-v1"
KEY_ID = "snapshot-component-key-v1"
KEY = b"snapshot-component-key-v1-0123456789abcdef"
BDF1 = "0000:65:00.0"
BDF2 = "0000:65:00.1"


def pci_identity(*, device_id: int = 0x10D3) -> vfio.PciIdentity:
    return vfio.PciIdentity(
        vendor_id=0x8086,
        device_id=device_id,
        subsystem_vendor_id=0x8086,
        subsystem_device_id=0xA01F,
        class_code=0x020000,
        revision=2,
    )


def device(bdf: str, *, device_id: int = 0x10D3) -> DeviceInventory:
    return DeviceInventory(
        bdf=bdf,
        vendor_id=0x8086,
        device_id=device_id,
        class_code=0x020000,
        header_type=0,
        function_role=FunctionRole.ENDPOINT,
        iommu_group=(BDF1, BDF2),
        physical_isolation_domain=(BDF1, BDF2),
        physical_isolation_domain_source="stock-kernel-iommu-group",
        reset_methods=("flr",),
        reset_domain=(bdf,),
        reset_domain_source="sysfs-function-reset",
        multifunction_aliases=(BDF1, BDF2),
        multifunction_source="linux-slot-scan",
        owner_activation_group="bundle-a",
        exclusive_attach_group="bundle-a",
        isolation_provenance=IsolationProvenance.KERNEL_GROUP,
        dma_isolation_mode=DmaIsolationMode.IOMMU,
        dma_isolation_source="linux-iommu-group",
        device_generation=3 if bdf == BDF1 else 4,
        driver="vfio-pci",
        acs_native_isolation=True,
        acs_effective_isolation=True,
        acs_override_source="none",
    )


def make_capture(
    *,
    boot_id: str = "boot-a",
    first_device_id: int = 0x10D3,
    scanned_count: int = 2,
    returned_count: int = 2,
    include_second_fact: bool = True,
    inventory_epoch: int | None = None,
) -> SnapshotCapture:
    devices = {
        BDF1: device(BDF1, device_id=first_device_id),
        BDF2: device(BDF2),
    }
    inventory = HostInventory(
        iommu_present=True,
        interrupt_remapping=True,
        no_iommu_mode=False,
        acs_override_active=False,
        devices=devices,
        source="test-full-host-capture",
        metadata={
            "scannedDeviceCount": scanned_count,
            "returnedDeviceCount": returned_count,
        },
        host_id=HOST,
        kernel_boot_id=boot_id,
        inventory_epoch=inventory_epoch,
        topology_hash="1" * 64,
    )
    members = (BDF1, BDF2)
    facts = {
        BDF1: LaunchDeviceFacts(
            bdf=BDF1,
            identity=pci_identity(device_id=first_device_id),
            iommu_group="7",
            group_members=members,
            device_generation=3,
        )
    }
    if include_second_fact:
        facts[BDF2] = LaunchDeviceFacts(
            bdf=BDF2,
            identity=pci_identity(),
            iommu_group="7",
            group_members=members,
            device_generation=4,
        )
    return SnapshotCapture(inventory=inventory, launch_facts=facts)


def vfio_state(bdf: str) -> vfio.DeviceState:
    minor = 0 if bdf == BDF1 else 1
    return vfio.DeviceState(
        bdf=bdf,
        identity=pci_identity(),
        driver="vfio-pci",
        iommu_group="7",
        group_members=(BDF1, BDF2),
        noiommu_node_present=False,
        group_node=Path("/dev/vfio/7"),
        cdev_node=Path(f"/dev/vfio/devices/vfio{minor}"),
        cdev_device_number=(241, minor),
    )


class FakeLaunchReader:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def capture(self, bdf: str) -> vfio.DeviceState:
        self.calls.append(bdf)
        return vfio_state(bdf)


class FakeLaunchKernel:
    def __init__(self) -> None:
        self.next_fd = 10
        self.opens: list[tuple[str, str]] = []
        self.close_attempts: list[int] = []
        self.open_fds: set[int] = set()

    def open_char_node(
        self,
        path: Path,
        *,
        role: str,
        failure_reason: str,
        expected_device_number: tuple[int, int] | None,
        bdf: str,
    ) -> launch.OpenedNode:
        del failure_reason
        fd = self.next_fd
        self.next_fd += 1
        self.open_fds.add(fd)
        self.opens.append((role, bdf))
        major, minor = expected_device_number or (10, 196)
        return launch.OpenedNode(
            fd=fd,
            metadata=launch.OpenHandleMetadata(
                role=role,
                path=Path(path),
                inode=100 + fd,
                filesystem_device=8,
                character_device_major=major,
                character_device_minor=minor,
                cloexec=True,
            ),
        )

    def close(self, fd: int) -> None:
        self.close_attempts.append(fd)
        self.open_fds.remove(fd)


class MutableCaptureProvider:
    """One stable provider identity whose live observations can drift."""

    def __init__(self, current: SnapshotCapture) -> None:
        self.current = current
        self.sequence: list[SnapshotCapture] = []
        self.calls = 0

    def __call__(self) -> SnapshotCapture:
        self.calls += 1
        if self.sequence:
            return self.sequence.pop(0)
        return self.current

    def select(self, capture: SnapshotCapture) -> None:
        self.current = capture
        self.sequence.clear()

    def select_sequence(self, *captures: SnapshotCapture) -> None:
        self.sequence[:] = captures


class AuthoritativeSnapshotStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.database = self.root / "snapshot.sqlite3"
        self.boot_id = "boot-a"
        self.authenticator = ComponentHmacAuthenticator({KEY_ID: KEY})
        self.store = self.open_store()
        self.capture_provider = MutableCaptureProvider(make_capture())

    def open_store(self, path: Path | None = None, **changes) -> AuthoritativeSnapshotStore:
        values = {
            "path": self.database if path is None else path,
            "local_host_id": HOST,
            "trusted_authority_id": AUTHORITY,
            "authenticator": self.authenticator,
            "current_boot_id": lambda: self.boot_id,
            "allow_unverified_filesystem_for_lab": True,
            "clock": lambda: datetime(2026, 7, 21, 1, 2, 3, tzinfo=timezone.utc),
        }
        values.update(changes)
        store = AuthoritativeSnapshotStore(**values)
        self.addCleanup(store.close)
        return store

    def assert_reason(self, reason: SnapshotReason, callback) -> SnapshotError:
        with self.assertRaises(SnapshotError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason)
        return raised.exception

    def publish(self, expected=None, capture=None):
        selected = make_capture() if capture is None else capture
        self.capture_provider.select(selected)
        return self.store.capture_and_publish(
            self.capture_provider,
            key_id=KEY_ID,
            expected_current_hash=expected,
        )

    def test_publish_is_signed_monotonic_and_export_is_cache_only(self) -> None:
        first = self.publish()
        self.assertEqual(1, first.inventory_epoch)
        self.assertEqual(64, len(first.snapshot_hash))
        self.assertEqual(64, len(first.topology_hash))
        self.assertEqual(
            "COMPONENT_AUTHENTICITY_ONLY", first.envelope.trust_boundary
        )
        self.assertEqual(first.snapshot_hash, self.store.current().snapshot_hash)
        self.assertEqual(first.topology_hash, first.inventory.topology_hash)
        self.assertIsNotNone(first.inventory.inventory_epoch)

        second = self.publish(expected=first.snapshot_hash)
        self.assertEqual(2, second.inventory_epoch)
        self.assertNotEqual(first.snapshot_hash, second.snapshot_hash)
        self.assertEqual(first.topology_hash, second.topology_hash)

        export = self.root / "current.json"
        exported = self.store.export_current(export)
        self.assertEqual(second.snapshot_hash, exported.snapshot_hash)
        value = json.loads(export.read_text(encoding="utf-8"))
        self.assertEqual(second.snapshot_hash, value["snapshotHash"])
        self.assertFalse(export.is_symlink())

    def test_publish_requires_cas_and_does_not_accept_caller_epoch(self) -> None:
        first = self.publish()
        self.assert_reason(
            SnapshotReason.PUBLISH_CONFLICT,
            lambda: self.publish(expected=None),
        )
        self.assert_reason(
            SnapshotReason.PUBLISH_CONFLICT,
            lambda: self.publish(expected="a" * 64),
        )
        self.assert_reason(
            SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
            lambda: self.publish(
                expected=first.snapshot_hash,
                capture=make_capture(inventory_epoch=99),
            ),
        )
        self.assertEqual(1, self.store.current().inventory_epoch)

    def test_double_capture_drift_and_subset_scan_publish_nothing(self) -> None:
        captures = iter(
            [make_capture(), make_capture(first_device_id=0x10D4)]
        )
        self.assert_reason(
            SnapshotReason.CAPTURE_UNSTABLE,
            lambda: self.store.capture_and_publish(
                captures.__next__, key_id=KEY_ID, expected_current_hash=None
            ),
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_NOT_FOUND, self.store.current)

    def test_launch_facts_must_match_inventory_decision_facts(self) -> None:
        baseline = make_capture()
        base_fact = baseline.launch_facts[BDF1]
        mismatches = {
            "vendor": replace(
                base_fact,
                identity=replace(base_fact.identity, vendor_id=0x1234),
            ),
            "device": replace(
                base_fact,
                identity=replace(base_fact.identity, device_id=0x10D4),
            ),
            "class": replace(
                base_fact,
                identity=replace(base_fact.identity, class_code=0x030000),
            ),
            "group members": replace(base_fact, group_members=(BDF1,)),
            "device generation": replace(base_fact, device_generation=99),
        }
        for label, changed_fact in mismatches.items():
            with self.subTest(field=label):
                changed = SnapshotCapture(
                    inventory=baseline.inventory,
                    launch_facts={
                        **baseline.launch_facts,
                        BDF1: changed_fact,
                    },
                )
                self.assert_reason(
                    SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
                    lambda changed=changed: self.publish(capture=changed),
                )
        self.assert_reason(SnapshotReason.SNAPSHOT_NOT_FOUND, self.store.current)

        subset = make_capture(scanned_count=3, returned_count=2)
        self.assert_reason(
            SnapshotReason.CAPTURE_NOT_FULL_HOST,
            lambda: self.publish(capture=subset),
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_NOT_FOUND, self.store.current)

    def test_fault_before_commit_retains_old_complete_snapshot(self) -> None:
        first = self.publish()
        self.store.close()
        faulted = self.open_store(
            fault_hook=lambda stage: (_ for _ in ()).throw(RuntimeError(stage))
            if stage == "PUBLISH_AFTER_INSERT"
            else None
        )
        with self.assertRaisesRegex(RuntimeError, "PUBLISH_AFTER_INSERT"):
            faulted.capture_and_publish(
                lambda: make_capture(),
                key_id=KEY_ID,
                expected_current_hash=first.snapshot_hash,
            )
        faulted.close()
        self.store = self.open_store()
        self.assertEqual(first.snapshot_hash, self.store.current().snapshot_hash)
        self.assertEqual(1, self.store.current().inventory_epoch)

    def test_signature_payload_duplicate_key_and_row_tamper_fail_closed(self) -> None:
        self.publish()
        original = self.store._connection.execute(
            "SELECT envelope_json FROM snapshots WHERE inventory_epoch=1"
        ).fetchone()[0]
        value = json.loads(original)
        value["signature"] = "0" * 64
        self.store._connection.execute(
            "UPDATE snapshots SET envelope_json=? WHERE inventory_epoch=1",
            (json.dumps(value, sort_keys=True, separators=(",", ":")),),
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_SIGNATURE_INVALID, self.store.current)

        self.store._connection.execute(
            "UPDATE snapshots SET envelope_json=? WHERE inventory_epoch=1", (original,)
        )
        duplicate = '{"schemaVersion":1,"schemaVersion":1}'
        self.store._connection.execute(
            "UPDATE snapshots SET envelope_json=? WHERE inventory_epoch=1", (duplicate,)
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_HASH_MISMATCH, self.store.current)

        self.store._connection.execute(
            "UPDATE snapshots SET envelope_json=? WHERE inventory_epoch=1", (original,)
        )
        self.store._connection.execute(
            "UPDATE snapshots SET topology_hash=? WHERE inventory_epoch=1", ("f" * 64,)
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_HASH_MISMATCH, self.store.current)

    def test_boot_and_minimum_epoch_replay_checks_fail_closed(self) -> None:
        first = self.publish()
        self.assert_reason(
            SnapshotReason.SNAPSHOT_STALE,
            lambda: self.store.current(minimum_epoch=first.inventory_epoch + 1),
        )
        self.boot_id = "boot-b"
        self.assert_reason(SnapshotReason.BOOT_ID_CHANGED, self.store.current)

    def test_publisher_rejects_capture_from_a_noncurrent_boot(self) -> None:
        self.boot_id = "boot-b"
        self.assert_reason(
            SnapshotReason.BOOT_ID_CHANGED,
            lambda: self.publish(capture=make_capture(boot_id="boot-a")),
        )
        self.assert_reason(SnapshotReason.SNAPSHOT_NOT_FOUND, self.store.current)

    def test_authorization_is_sealed_complete_and_expires(self) -> None:
        current = self.publish()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF2, BDF1)
        ) as authorization:
            self.assertIs(
                authorization, validate_launch_authorization(authorization)
            )
            self.assertEqual((BDF1, BDF2), authorization.authorized_bdfs)
            self.assertTrue(authorization.is_active)
            self.assertEqual(current.snapshot_hash, authorization.snapshot_hash)
            self.assertEqual(64, len(authorization.binding_hash))
            self.assertEqual(
                "COMPONENT_CAPTURE_PROVIDER",
                authorization.capture_provider_boundary,
            )
            self.assertEqual(64, len(authorization.capture_provider_binding_hash))
            self.assert_reason(
                SnapshotReason.AUTHORIZATION_ACTIVE,
                lambda: self.publish(expected=current.snapshot_hash),
            )
            with self.assertRaises(TypeError):
                copy.copy(authorization)
            with self.assertRaises(TypeError):
                copy.deepcopy(authorization)
            with self.assertRaises(TypeError):
                pickle.dumps(authorization)
            with self.assertRaises(TypeError):
                SnapshotLaunchAuthorization()

        self.assertFalse(authorization.is_active)
        self.assert_reason(
            SnapshotReason.AUTHORIZATION_INACTIVE, authorization.require_current
        )
        self.assert_reason(
            SnapshotReason.AUTHORIZATION_INACTIVE,
            lambda: validate_launch_authorization(object()),
        )

    def test_incomplete_group_or_missing_launch_fact_is_not_authorized(self) -> None:
        current = self.publish()
        self.assert_reason(
            SnapshotReason.INCOMPLETE_IOMMU_GROUP,
            lambda: self.store.authorize_launch(
                current.snapshot_hash, (BDF1,)
            ).__enter__(),
        )

        self.store.close()
        self.database.unlink()
        for suffix in ("-wal", "-shm"):
            path = Path(str(self.database) + suffix)
            if path.exists():
                path.unlink()
        self.store = self.open_store()
        missing = self.publish(capture=make_capture(include_second_fact=False))
        self.assert_reason(
            SnapshotReason.CAPTURE_IDENTITY_INCOMPLETE,
            lambda: self.store.authorize_launch(
                missing.snapshot_hash, (BDF2,)
            ).__enter__(),
        )

    def test_live_pre_post_revalidation_detects_boot_topology_and_identity(self) -> None:
        current = self.publish()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            authorization.revalidate_live(LiveCapturePhase.PRE_OPEN)
            self.capture_provider.select(make_capture(first_device_id=0x10D4))
            error = self.assert_reason(
                SnapshotReason.TOPOLOGY_CHANGED,
                lambda: authorization.revalidate_live(LiveCapturePhase.POST_OPEN),
            )
            self.assertEqual(LiveCapturePhase.POST_OPEN, error.phase)
            self.capture_provider.select(make_capture(boot_id="boot-b"))
            error = self.assert_reason(
                SnapshotReason.BOOT_ID_CHANGED,
                lambda: authorization.revalidate_live(LiveCapturePhase.PRE_SPAWN),
            )
            self.assertEqual(LiveCapturePhase.PRE_SPAWN, error.phase)

    def test_replayed_provider_capture_cannot_hide_current_boot_change(self) -> None:
        current = self.publish()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            # The bound provider still returns the old boot-a capture.  The
            # store's separately bound current-boot authority must still deny.
            self.boot_id = "boot-b"
            error = self.assert_reason(
                SnapshotReason.BOOT_ID_CHANGED,
                lambda: authorization.revalidate_live(
                    LiveCapturePhase.PRE_SPAWN
                ),
            )
            self.assertIsNone(error.phase)

    def test_full_topology_hash_covers_safety_provenance_and_exact_identity(self) -> None:
        baseline = make_capture()
        changed_identity = make_capture(first_device_id=0x10D4)
        first = baseline.inventory.devices[BDF1]
        fact = FactEvidence(
            source="qualification-db",
            rule_id="rule-1",
            subject_hash="a" * 64,
            evidence_hash="b" * 64,
            inventory_epoch=9,
            topology_hash="c" * 64,
        )
        mutations = {
            "dependency action": {"dependency_action": MemberAction.ASSIGN_TO_GUEST},
            "dependency action fact": {"dependency_action_fact": fact},
            "device generation": {"device_generation": 7},
            "driver": {"driver": "ixgbe"},
            "errata denial": {"errata_denied": True},
            "host reservation": {"host_reservation": "firmware"},
            "isolation provenance": {
                "isolation_provenance": IsolationProvenance.UNKNOWN
            },
            "platform reservation": {"platform_reserved": True},
            "qualification fact": {"qualification_fact": fact},
            "qualified actions": {
                "qualified_actions": (MemberAction.ASSIGN_TO_GUEST,)
            },
            "reset contract fact": {"reset_contract_fact": fact},
            "RMRR conflict": {"rmrr_conflict": True},
        }

        self.assertNotEqual(
            compute_full_topology_hash(baseline),
            compute_full_topology_hash(changed_identity),
        )
        for label, changes in mutations.items():
            with self.subTest(field=label):
                changed_inventory = replace(
                    baseline.inventory,
                    devices={
                        **baseline.inventory.devices,
                        BDF1: replace(first, **changes),
                    },
                )
                changed = SnapshotCapture(
                    inventory=changed_inventory,
                    launch_facts=baseline.launch_facts,
                )
                self.assertNotEqual(
                    compute_full_topology_hash(baseline),
                    compute_full_topology_hash(changed),
                )

        changed_source = SnapshotCapture(
            inventory=replace(baseline.inventory, source="replayed-cache"),
            launch_facts=baseline.launch_facts,
        )
        self.assertNotEqual(
            compute_full_topology_hash(baseline),
            compute_full_topology_hash(changed_source),
        )

        changed_host_provenance = SnapshotCapture(
            inventory=replace(
                baseline.inventory,
                metadata={
                    **baseline.inventory.metadata,
                    "kernelCommandLine": "iommu=off",
                },
            ),
            launch_facts=baseline.launch_facts,
        )
        self.assertNotEqual(
            compute_full_topology_hash(baseline),
            compute_full_topology_hash(changed_host_provenance),
        )

        debug_only_metadata = SnapshotCapture(
            inventory=replace(
                baseline.inventory,
                metadata={**baseline.inventory.metadata, "debugCounter": 1},
            ),
            launch_facts=baseline.launch_facts,
        )
        self.assertEqual(
            compute_full_topology_hash(baseline),
            compute_full_topology_hash(debug_only_metadata),
        )

    def test_live_semantic_device_drift_fails_closed(self) -> None:
        current = self.publish()
        baseline = make_capture()
        first = baseline.inventory.devices[BDF1]
        mutations = {
            "driver": {"driver": "ixgbe"},
            "isolation provenance": {
                "isolation_provenance": IsolationProvenance.UNKNOWN
            },
            "platform reservation": {"platform_reserved": True},
            "RMRR conflict": {"rmrr_conflict": True},
        }
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            for label, changes in mutations.items():
                with self.subTest(field=label):
                    changed = SnapshotCapture(
                        inventory=replace(
                            baseline.inventory,
                            devices={
                                **baseline.inventory.devices,
                                BDF1: replace(first, **changes),
                            },
                        ),
                        launch_facts=baseline.launch_facts,
                    )
                    self.capture_provider.select(changed)
                    error = self.assert_reason(
                        SnapshotReason.TOPOLOGY_CHANGED,
                        lambda: authorization.revalidate_live(
                            LiveCapturePhase.PRE_SPAWN
                        ),
                    )
                    self.assertEqual(LiveCapturePhase.PRE_SPAWN, error.phase)

    def test_live_fact_coordinates_are_independently_bound_and_fail_closed(self) -> None:
        baseline = make_capture()
        old_fact = FactEvidence(
            source="reset-provider",
            rule_id="reset-rule-v1",
            subject_hash="a" * 64,
            evidence_hash="b" * 64,
            inventory_epoch=1,
            topology_hash="c" * 64,
        )
        first = baseline.inventory.devices[BDF1]
        fact_fields = (
            "dependency_action_fact",
            "qualification_fact",
            "reset_contract_fact",
        )
        coordinate_changes = {
            "inventoryEpoch": {"inventory_epoch": 999},
            "topologyHash": {"topology_hash": "d" * 64},
        }
        expected_current_hash = None

        for fact_field in fact_fields:
            for coordinate, changes in coordinate_changes.items():
                with self.subTest(fact_field=fact_field, coordinate=coordinate):
                    published = SnapshotCapture(
                        inventory=replace(
                            baseline.inventory,
                            devices={
                                **baseline.inventory.devices,
                                BDF1: replace(first, **{fact_field: old_fact}),
                            },
                        ),
                        launch_facts=baseline.launch_facts,
                    )
                    current = self.publish(
                        expected=expected_current_hash,
                        capture=published,
                    )
                    expected_current_hash = current.snapshot_hash
                    changed_fact = replace(old_fact, **changes)
                    changed = SnapshotCapture(
                        inventory=replace(
                            baseline.inventory,
                            devices={
                                **baseline.inventory.devices,
                                BDF1: replace(first, **{fact_field: changed_fact}),
                            },
                        ),
                        launch_facts=baseline.launch_facts,
                    )
                    self.assertNotEqual(
                        compute_full_topology_hash(published),
                        compute_full_topology_hash(changed),
                    )
                    with self.store.authorize_launch(
                        current.snapshot_hash, (BDF1, BDF2)
                    ) as authorization:
                        self.capture_provider.select(changed)
                        error = self.assert_reason(
                            SnapshotReason.TOPOLOGY_CHANGED,
                            lambda: authorization.revalidate_live(
                                LiveCapturePhase.PRE_SPAWN
                            ),
                        )
                    self.assertEqual(LiveCapturePhase.PRE_SPAWN, error.phase)

    def test_fact_evidence_preimage_canonical_hash_remains_stable(self) -> None:
        baseline = make_capture()
        first = baseline.inventory.devices[BDF1]
        fact = FactEvidence(
            source="reset-provider",
            rule_id="reset-rule-v1",
            subject_hash="a" * 64,
            evidence_hash="b" * 64,
            inventory_epoch=1,
            topology_hash="c" * 64,
        )
        capture = SnapshotCapture(
            inventory=replace(
                baseline.inventory,
                devices={
                    **baseline.inventory.devices,
                    BDF1: replace(first, reset_contract_fact=fact),
                },
            ),
            launch_facts=baseline.launch_facts,
        )

        self.assertEqual(
            "a5661ef533d145fe5f599399d12e5179678d921b0c1707b4df65c9d363b7499f",
            compute_full_topology_hash(capture),
        )

    def test_authorized_bundle_derives_requests_and_retains_snapshot_guard(self) -> None:
        current = self.publish()
        reader = FakeLaunchReader()
        kernel = FakeLaunchKernel()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF2, BDF1)
        ) as authorization:
            bundle = launch.open_authorized_vfio_launch_bundle(
                authorization,
                state_reader=reader,
                kernel=kernel,
            )
            self.assertEqual((BDF1, BDF2), tuple(r.request.bdf for r in bundle.results))
            self.assertEqual(
                [BDF1, BDF2, BDF1, BDF2],
                reader.calls,
            )
            self.assertEqual(3, len(kernel.opens))
            for result in bundle.results:
                metadata = result.metadata
                self.assertEqual(
                    launch.AUTHORITATIVE_SNAPSHOT_BINDING,
                    metadata.snapshot_binding,
                )
                self.assertEqual(current.snapshot_hash, metadata.snapshot_hash)
                self.assertEqual(AUTHORITY, metadata.snapshot_authority_id)
                self.assertEqual(KEY_ID, metadata.snapshot_key_id)
                self.assertEqual(authorization.binding_hash, metadata.snapshot_authorization_hash)
                self.assertEqual(64, len(metadata.fd_binding_hash))
                self.assertEqual(
                    current.snapshot_hash,
                    metadata.to_json()["publisherSnapshot"]["snapshotHash"],
                )
                result.revalidate_snapshot_live(LiveCapturePhase.PRE_SPAWN)
                self.assertFalse(launch.is_authoritative_snapshot_launch_result(result))

        self.assert_reason(
            SnapshotReason.AUTHORIZATION_INACTIVE,
            bundle.results[0].require_snapshot_authorization_current,
        )
        bundle.close()
        self.assertEqual([12, 11, 10], kernel.close_attempts)

    def test_authorized_bundle_live_drift_is_preopen_or_atomic_postopen_denial(self) -> None:
        current = self.publish()
        replay_kernel = FakeLaunchKernel()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            self.assert_reason(
                SnapshotReason.CAPTURE_PROVIDER_MISMATCH,
                lambda: launch.open_authorized_vfio_launch_bundle(
                    authorization,
                    lambda: make_capture(),
                    state_reader=FakeLaunchReader(),
                    kernel=replay_kernel,
                ),
            )
            self.assertEqual([], replay_kernel.opens)

        pre_kernel = FakeLaunchKernel()
        self.capture_provider.select(make_capture(first_device_id=0x10D4))
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            error = self.assert_reason(
                SnapshotReason.TOPOLOGY_CHANGED,
                lambda: launch.open_authorized_vfio_launch_bundle(
                    authorization,
                    state_reader=FakeLaunchReader(),
                    kernel=pre_kernel,
                ),
            )
            self.assertEqual(LiveCapturePhase.PRE_OPEN, error.phase)
            self.assertEqual([], pre_kernel.opens)

        self.capture_provider.select_sequence(
            make_capture(), make_capture(first_device_id=0x10D4)
        )
        post_kernel = FakeLaunchKernel()
        with self.store.authorize_launch(
            current.snapshot_hash, (BDF1, BDF2)
        ) as authorization:
            error = self.assert_reason(
                SnapshotReason.TOPOLOGY_CHANGED,
                lambda: launch.open_authorized_vfio_launch_bundle(
                    authorization,
                    self.capture_provider,
                    state_reader=FakeLaunchReader(),
                    kernel=post_kernel,
                ),
            )
            self.assertEqual(LiveCapturePhase.POST_OPEN, error.phase)
            self.assertEqual([12, 11, 10], post_kernel.close_attempts)
            self.assertEqual(set(), post_kernel.open_fds)

    def test_store_copy_and_authenticator_change_are_rejected(self) -> None:
        self.publish()
        self.store.close()
        copied = self.root / "copied.sqlite3"
        shutil.copy2(self.database, copied)
        self.assert_reason(
            SnapshotReason.STORE_IDENTITY_MISMATCH,
            lambda: self.open_store(copied),
        )
        wrong = ComponentHmacAuthenticator(
            {KEY_ID: b"different-component-key-0123456789abcdef"}
        )
        self.assert_reason(
            SnapshotReason.SNAPSHOT_SIGNATURE_INVALID,
            lambda: self.open_store(authenticator=wrong).current(),
        )

    def test_reopened_store_cannot_invent_a_live_capture_provider(self) -> None:
        current = self.publish()
        self.store.close()
        self.store = self.open_store()
        self.assert_reason(
            SnapshotReason.CAPTURE_PROVIDER_UNAVAILABLE,
            lambda: self.store.authorize_launch(
                current.snapshot_hash, (BDF1, BDF2)
            ).__enter__(),
        )

    def test_same_key_earlier_valid_row_replay_needs_external_monotonic_anchor(self) -> None:
        first = self.publish()
        second = self.publish(expected=first.snapshot_hash)
        self.store._connection.execute(
            "DELETE FROM snapshots WHERE inventory_epoch=?",
            (second.inventory_epoch,),
        )

        # The earlier row remains correctly signed by the same trusted key, so
        # this component can verify authenticity but cannot infer time rollback.
        self.assertEqual(first.snapshot_hash, self.store.current().snapshot_hash)
        # The process-local provider is snapshot-bound, so launch still fails
        # closed instead of silently reusing snapshot 2's live capability.
        self.assert_reason(
            SnapshotReason.CAPTURE_PROVIDER_UNAVAILABLE,
            lambda: self.store.authorize_launch(
                first.snapshot_hash, (BDF1, BDF2)
            ).__enter__(),
        )

    def test_sqlite_unique_index_target_is_fixed(self) -> None:
        self.publish()
        connection = self.store._connection
        connection.execute("ALTER TABLE snapshots RENAME TO snapshots_old")
        connection.execute(
            "CREATE TABLE snapshots ("
            "inventory_epoch INTEGER PRIMARY KEY,"
            "snapshot_hash TEXT NOT NULL,"
            "topology_hash TEXT NOT NULL UNIQUE,"
            "kernel_boot_id TEXT NOT NULL,"
            "key_id TEXT NOT NULL,"
            "captured_at TEXT NOT NULL,"
            "envelope_json TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO snapshots SELECT * FROM snapshots_old"
        )
        connection.execute("DROP TABLE snapshots_old")
        target = tuple(
            row[2]
            for row in connection.execute(
                "PRAGMA index_info('sqlite_autoindex_snapshots_1')"
            ).fetchall()
        )
        self.assertEqual(("topology_hash",), target)
        self.assert_reason(SnapshotReason.STORE_UNAVAILABLE, self.store.current)

    def test_persistent_and_temp_schema_extensions_fail_closed(self) -> None:
        self.publish()
        self.store._connection.execute("CREATE TEMP TABLE injected(value TEXT)")
        self.assert_reason(SnapshotReason.STORE_UNAVAILABLE, self.store.current)
        self.store._connection.execute("DROP TABLE injected")
        self.assertEqual(1, self.store.current().inventory_epoch)

        self.store._connection.execute("CREATE TABLE injected(value TEXT)")
        self.assert_reason(SnapshotReason.STORE_UNAVAILABLE, self.store.current)

    def test_hidden_generated_column_fails_closed(self) -> None:
        self.publish()
        connection = self.store._connection
        connection.execute("ALTER TABLE snapshots RENAME TO snapshots_old")
        connection.execute(
            "CREATE TABLE snapshots ("
            "inventory_epoch INTEGER PRIMARY KEY,"
            "snapshot_hash TEXT NOT NULL UNIQUE,"
            "topology_hash TEXT NOT NULL,"
            "kernel_boot_id TEXT NOT NULL,"
            "key_id TEXT NOT NULL,"
            "captured_at TEXT NOT NULL,"
            "envelope_json TEXT NOT NULL,"
            "hidden_shadow TEXT GENERATED ALWAYS AS (snapshot_hash) VIRTUAL)"
        )
        connection.execute(
            "INSERT INTO snapshots("
            "inventory_epoch,snapshot_hash,topology_hash,kernel_boot_id,"
            "key_id,captured_at,envelope_json) "
            "SELECT inventory_epoch,snapshot_hash,topology_hash,kernel_boot_id,"
            "key_id,captured_at,envelope_json FROM snapshots_old"
        )
        connection.execute("DROP TABLE snapshots_old")
        self.assert_reason(SnapshotReason.STORE_UNAVAILABLE, self.store.current)


if __name__ == "__main__":
    unittest.main()
