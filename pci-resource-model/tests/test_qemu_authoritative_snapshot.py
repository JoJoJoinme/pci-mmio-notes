from __future__ import annotations

import os
import stat
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pci_resource_model import qemu_launch_contract as qemu
from pci_resource_model import static_lease
from pci_resource_model import vfio_launch_handles as handles
from pci_resource_model import vfio_provider as vfio
from pci_resource_model.authoritative_snapshot import (
    AuthoritativeSnapshotStore,
    ComponentHmacAuthenticator,
)
from tests.test_authoritative_snapshot import (
    AUTHORITY,
    BDF1,
    BDF2,
    HOST,
    KEY,
    KEY_ID,
    make_capture,
    vfio_state,
)


HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def _character_stat(*, inode: int, major: int, minor: int) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=8,
        st_ino=inode,
        st_rdev=(major << 8) | minor,
        st_mode=stat.S_IFCHR | 0o600,
    )


class QemuAuthoritativeSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

        authenticator = ComponentHmacAuthenticator({KEY_ID: KEY})
        self.snapshot_store = AuthoritativeSnapshotStore(
            self.root / "snapshot.sqlite3",
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            authenticator=authenticator,
            current_boot_id=lambda: "boot-a",
            allow_unverified_filesystem_for_lab=True,
            clock=lambda: datetime(2026, 7, 21, 1, 2, 3, tzinfo=timezone.utc),
        )
        self.addCleanup(self.snapshot_store.close)
        self.live_device_id = {"value": 0x10D3}

        def live_capture():
            return make_capture(first_device_id=self.live_device_id["value"])

        self.live_capture = live_capture
        self.snapshot = self.snapshot_store.capture_and_publish(
            self.live_capture,
            key_id=KEY_ID,
            expected_current_hash=None,
        )

        generations = {BDF1: 3, BDF2: 4}
        self.lease_store = static_lease.StaticLeaseStore(
            self.root / "lease.sqlite3",
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            allow_unverified_filesystem_for_lab=True,
            transaction_id_factory=lambda: "tx-authoritative",
        )
        self.addCleanup(self.lease_store.close)
        self.lease_store.publish_authoritative_device_generations(
            HOST,
            generations,
            expected_current={BDF1: None, BDF2: None},
            authority_id=AUTHORITY,
            authority_epoch=self.snapshot.inventory_epoch,
        )
        bundle_hash = self.lease_store.publish_authoritative_bundle(
            HOST,
            "bundle-a",
            (BDF1, BDF2),
            expected_current_hash=None,
            authority_id=AUTHORITY,
            authority_epoch=self.snapshot.inventory_epoch,
        )
        reserved = self.lease_store.begin(
            static_lease.BeginRequest(
                idempotency_key="idem-authoritative",
                host_id=HOST,
                vm_id="vm-a",
                run_id="run-a",
                bundle_id="bundle-a",
                expected_bundle_hash=bundle_hash,
                members=(BDF1, BDF2),
                inventory_epoch=self.snapshot.inventory_epoch,
                expected_vm_generation=0,
                expected_device_generations=generations,
                decision_hash=HASH_A,
                policy_hash=HASH_B,
            )
        )
        preparing = self.lease_store.prepare(
            reserved.transaction_id,
            reserved.vm_generation,
            reserved.revision,
        )
        self.lease_context = self.lease_store.authorize_launch(
            preparing.transaction_id,
            preparing.vm_generation,
            preparing.revision,
        )
        self.lease_authorization = self.lease_context.__enter__()
        self.addCleanup(self.lease_context.__exit__, None, None, None)
        self.lease = qemu.lease_binding_from_launch_authorization(
            self.lease_authorization
        )

        self.qemu_path = self.root / "qemu-system-x86_64"
        self.qemu_path.write_bytes(b"test-qemu-binary-v1")
        self.qemu_path.chmod(0o755)
        self.qemu_identity = qemu.capture_qemu_binary_identity(self.qemu_path)
        self.qmp_directory = self.root / "qmp"
        self.qmp_directory.mkdir(mode=0o700)
        self.qmp_directory.chmod(0o700)
        runtime_stat = os.stat(self.qmp_directory)
        self.qmp_observation = SimpleNamespace(
            st_dev=runtime_stat.st_dev,
            st_ino=runtime_stat.st_ino,
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=getattr(runtime_stat, "st_uid", 0),
        )
        nonce = "1" * 32
        self.qmp = qemu.QmpSocketBinding(
            runtime_directory=self.qmp_directory,
            runtime_stat=qemu.DirectoryStatToken.from_stat(self.qmp_observation),
            socket_path=self.qmp_directory / f"backend-{nonce}.qmp",
            nonce=nonce,
        )
        self.fd_stats = {
            20: _character_stat(inode=120, major=10, minor=196),
            11: _character_stat(inode=111, major=241, minor=0),
            12: _character_stat(inode=112, major=241, minor=1),
        }

    def _stat_path(self, path: Path):
        if path == self.qmp_directory:
            return self.qmp_observation
        return os.stat(path)

    def _open_node(
        self,
        _kernel,
        path: Path,
        *,
        role: str,
        failure_reason: str,
        expected_device_number,
        bdf: str,
    ) -> handles.OpenedNode:
        del failure_reason
        if role == "iommufd":
            fd = 20
            major, minor = (10, 196)
        else:
            fd = 11 if bdf == BDF1 else 12
            major, minor = expected_device_number
        observed = self.fd_stats[fd]
        return handles.OpenedNode(
            fd=fd,
            metadata=handles.OpenHandleMetadata(
                role=role,
                path=Path(path),
                inode=observed.st_ino,
                filesystem_device=observed.st_dev,
                character_device_major=major,
                character_device_minor=minor,
                cloexec=True,
            ),
        )

    def _plan(
        self,
        bindings: tuple[qemu.DeviceFdBinding, ...],
    ) -> qemu.DirectPathLaunchPlan:
        return qemu.DirectPathLaunchPlan(
            qemu=self.qemu_identity,
            lease=self.lease,
            profile=qemu.MachineProfile(
                profile_id="q35-static-v1",
                machine_type="pc-q35-11.0",
                memory_mib=4096,
                vcpu_count=4,
            ),
            qmp=self.qmp,
            devices=bindings,
        )

    def test_authoritative_result_is_bound_and_revalidated_before_spawn(self) -> None:
        def capture_state(_reader, bdf: str) -> vfio.DeviceState:
            return vfio_state(bdf)

        def open_node(
            kernel,
            path: Path,
            *,
            role: str,
            failure_reason: str,
            expected_device_number,
            bdf: str,
        ) -> handles.OpenedNode:
            return self._open_node(
                kernel,
                path,
                role=role,
                failure_reason=failure_reason,
                expected_device_number=expected_device_number,
                bdf=bdf,
            )

        def major(value: int) -> int:
            return value >> 8

        def minor(value: int) -> int:
            return value & 0xFF

        with (
            self.snapshot_store.authorize_launch(
                self.snapshot.snapshot_hash,
                (BDF1, BDF2),
            ) as snapshot_authorization,
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture_state),
            mock.patch.object(
                handles.PosixLaunchKernel,
                "open_char_node",
                open_node,
            ),
            mock.patch.object(handles.PosixLaunchKernel, "close", return_value=None),
            mock.patch.object(os, "major", major, create=True),
            mock.patch.object(os, "minor", minor, create=True),
        ):
            bundle = handles.open_authorized_vfio_launch_bundle(
                snapshot_authorization,
                self.live_capture,
            )
            self.assertTrue(handles.is_authoritative_snapshot_launch_bundle(bundle))
            with self.assertRaises(qemu.LaunchContractError):
                qemu.device_binding_from_vfio_launch_result(
                    bundle.results[0],
                    qemu.GuestSlot(index=0, root_port_address=2),
                    self.lease,
                    fstat=self.fd_stats.__getitem__,
                )

            bindings = tuple(
                qemu.device_binding_from_authorized_vfio_launch_result(
                    result,
                    qemu.GuestSlot(index=index, root_port_address=2 + index),
                    self.lease,
                    fstat=self.fd_stats.__getitem__,
                )
                for index, result in enumerate(bundle.results)
            )
            admission = bindings[0].provider_admission
            self.assertEqual(
                qemu.AUTHORITATIVE_COMPONENT_SNAPSHOT_BINDING,
                admission.snapshot_binding,
            )
            self.assertEqual(
                "sha256:" + self.snapshot.snapshot_hash,
                admission.to_json()["publisherSnapshot"]["snapshotHash"],
            )
            self.assertIs(bundle.results[0], admission._snapshot_result)

            with self.assertRaises(qemu.LaunchContractError) as truncated:
                self._plan((bindings[0],))
            self.assertEqual(
                qemu.Reason.INVALID_PROVIDER_ADMISSION,
                truncated.exception.reason_code,
            )

            plan = self._plan(bindings)
            spec = qemu.render_launch(
                plan,
                fstat=self.fd_stats.__getitem__,
                stat_path=self._stat_path,
            )
            qemu.validate_before_spawn(
                spec,
                fstat=self.fd_stats.__getitem__,
                stat_path=self._stat_path,
                platform_name="posix",
            )
            self.assertEqual((11, 12, 20), spec.pass_fds)

            self.live_device_id["value"] = 0x10D4
            with self.assertRaises(qemu.LaunchContractError) as raised:
                spec.popen_kwargs()
            self.assertEqual(
                qemu.Reason.INVALID_PROVIDER_ADMISSION,
                raised.exception.reason_code,
            )
            bundle.close()

    def test_authoritative_plan_cannot_omit_an_entire_authorized_group(self) -> None:
        def split_group_capture():
            capture = make_capture()
            groups = {BDF1: "7", BDF2: "8"}
            devices = {
                bdf: replace(
                    device,
                    iommu_group=(bdf,),
                    physical_isolation_domain=(bdf,),
                    multifunction_aliases=(bdf,),
                )
                for bdf, device in capture.inventory.devices.items()
            }
            launch_facts = {
                bdf: replace(
                    capture.launch_facts[bdf],
                    iommu_group=groups[bdf],
                    group_members=(bdf,),
                )
                for bdf in (BDF1, BDF2)
            }
            return replace(
                capture,
                inventory=replace(capture.inventory, devices=devices),
                launch_facts=launch_facts,
            )

        split_store = AuthoritativeSnapshotStore(
            self.root / "split-groups-snapshot.sqlite3",
            local_host_id=HOST,
            trusted_authority_id=AUTHORITY,
            authenticator=ComponentHmacAuthenticator({KEY_ID: KEY}),
            current_boot_id=lambda: "boot-a",
            allow_unverified_filesystem_for_lab=True,
            clock=lambda: datetime(2026, 7, 21, 1, 2, 3, tzinfo=timezone.utc),
        )
        self.addCleanup(split_store.close)
        split_snapshot = split_store.capture_and_publish(
            split_group_capture,
            key_id=KEY_ID,
            expected_current_hash=None,
        )

        def capture_state(_reader, bdf: str) -> vfio.DeviceState:
            group = "7" if bdf == BDF1 else "8"
            return replace(
                vfio_state(bdf),
                iommu_group=group,
                group_members=(bdf,),
                group_node=Path("/dev/vfio") / group,
            )

        def open_node(
            kernel,
            path: Path,
            *,
            role: str,
            failure_reason: str,
            expected_device_number,
            bdf: str,
        ) -> handles.OpenedNode:
            return self._open_node(
                kernel,
                path,
                role=role,
                failure_reason=failure_reason,
                expected_device_number=expected_device_number,
                bdf=bdf,
            )

        with (
            split_store.authorize_launch(
                split_snapshot.snapshot_hash,
                (BDF1, BDF2),
            ) as snapshot_authorization,
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture_state),
            mock.patch.object(handles.PosixLaunchKernel, "open_char_node", open_node),
            mock.patch.object(handles.PosixLaunchKernel, "close", return_value=None),
            mock.patch.object(os, "major", lambda value: value >> 8, create=True),
            mock.patch.object(os, "minor", lambda value: value & 0xFF, create=True),
        ):
            bundle = handles.open_authorized_vfio_launch_bundle(
                snapshot_authorization,
                split_group_capture,
            )
            try:
                bindings = tuple(
                    qemu.device_binding_from_authorized_vfio_launch_result(
                        result,
                        qemu.GuestSlot(index=index, root_port_address=2 + index),
                        self.lease,
                        fstat=self.fd_stats.__getitem__,
                    )
                    for index, result in enumerate(bundle.results)
                )
                self.assertEqual((BDF1,), bindings[0].provider_admission.group_members)
                self.assertEqual((BDF2,), bindings[1].provider_admission.group_members)

                with self.assertRaises(qemu.LaunchContractError) as omitted_group:
                    self._plan((bindings[0],))
                self.assertEqual(
                    qemu.Reason.INVALID_PROVIDER_ADMISSION,
                    omitted_group.exception.reason_code,
                )
                self.assertIn(
                    "retained authorization scope",
                    str(omitted_group.exception),
                )

                complete_plan = self._plan(bindings)
                self.assertEqual((BDF1, BDF2), tuple(d.bdf for d in complete_plan.devices))
            finally:
                bundle.close()


if __name__ == "__main__":
    unittest.main()
