import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pci_resource_model import qemu_launch_contract as launch
from pci_resource_model import static_lease as leases


HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64


def char_stat(*, device: int, inode: int, rdev: int) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=device,
        st_ino=inode,
        st_rdev=rdev,
        st_mode=stat.S_IFCHR | 0o600,
    )


class QemuLaunchContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.qemu_path = self.root / "qemu-system-x86_64"
        self.qemu_path.write_bytes(b"test-qemu-binary-v1")
        self.qemu_path.chmod(0o755)
        self.qemu = launch.capture_qemu_binary_identity(self.qemu_path)

        self.runtime = self.root / "qmp"
        self.runtime.mkdir(mode=0o700)
        self.runtime.chmod(0o700)
        runtime_stat = os.stat(self.runtime)
        self.runtime_observation = SimpleNamespace(
            st_dev=runtime_stat.st_dev,
            st_ino=runtime_stat.st_ino,
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=getattr(runtime_stat, "st_uid", 0),
        )
        self.runtime_stat = launch.DirectoryStatToken.from_stat(self.runtime_observation)
        self.nonce = "1" * 32
        self.qmp = launch.QmpSocketBinding(
            runtime_directory=self.runtime,
            runtime_stat=self.runtime_stat,
            socket_path=self.runtime / f"backend-{self.nonce}.qmp",
            nonce=self.nonce,
        )
        (
            self.lease_store,
            self.lease_record,
            self.lease_authorization,
            self.lease,
            self.lease_context,
        ) = self.open_active_lease("main")
        self.profile = launch.MachineProfile(
            profile_id="q35-static-v1",
            machine_type="pc-q35-11.0",
            memory_mib=4096,
            vcpu_count=4,
        )
        self.fd_stats = {
            11: char_stat(device=1, inode=101, rdev=201),
            12: char_stat(device=1, inode=102, rdev=202),
            21: char_stat(device=1, inode=121, rdev=221),
            22: char_stat(device=1, inode=122, rdev=222),
        }

    def open_active_lease(
        self,
        name: str,
        *,
        transaction_id: str = "tx-001",
        run_id: str = "run-a",
        policy_hash: str = HASH_A,
        register_context_cleanup: bool = True,
    ):
        members = (
            "0000:00:1f.0",
            "0000:65:00.0",
            "0000:66:00.0",
        )
        authority = "authority-a"
        generations = {member: 4 for member in members}
        store = leases.StaticLeaseStore(
            self.root / f"lease-{name}.sqlite3",
            local_host_id="host-a",
            trusted_authority_id=authority,
            allow_unverified_filesystem_for_lab=True,
            transaction_id_factory=lambda: transaction_id,
        )
        self.addCleanup(store.close)
        store.publish_authoritative_device_generations(
            "host-a",
            generations,
            expected_current={member: None for member in members},
            authority_id=authority,
            authority_epoch=17,
        )
        bundle_hash = store.publish_authoritative_bundle(
            "host-a",
            "bundle-a",
            members,
            expected_current_hash=None,
            authority_id=authority,
            authority_epoch=17,
        )
        reserved = store.begin(
            leases.BeginRequest(
                idempotency_key=f"idem-{name}",
                host_id="host-a",
                vm_id="vm-a",
                run_id=run_id,
                bundle_id="bundle-a",
                expected_bundle_hash=bundle_hash,
                members=members,
                inventory_epoch=17,
                expected_vm_generation=0,
                expected_device_generations=generations,
                decision_hash=HASH_B,
                policy_hash=policy_hash,
            )
        )
        preparing = store.prepare(
            reserved.transaction_id,
            reserved.vm_generation,
            reserved.revision,
        )
        context = store.authorize_launch(
            preparing.transaction_id,
            preparing.vm_generation,
            preparing.revision,
        )
        authorization = context.__enter__()
        if register_context_cleanup:
            self.addCleanup(context.__exit__, None, None, None)
        binding = launch.lease_binding_from_launch_authorization(authorization)
        return store, preparing, authorization, binding, context

    def fstat(self, fd: int) -> SimpleNamespace:
        return self.fd_stats[fd]

    def stat_path(self, path: Path):
        if path == self.runtime:
            return self.runtime_observation
        return os.stat(path)

    def device(
        self,
        *,
        bdf: str = "0000:65:00.0",
        index: int = 0,
        root_port_address: int = 2,
        cdev_fd: int = 11,
        iommufd_fd: int = 21,
        identity_hash: str = HASH_C,
        group_hash: str = HASH_D,
        provider_binding_hash: str | None = None,
        iommu_group: str | None = None,
        group_members: tuple[str, ...] | None = None,
        snapshot_epoch: int = 17,
        lease: launch.LeaseBinding | None = None,
    ) -> launch.DeviceFdBinding:
        if provider_binding_hash is None:
            provider_binding_hash = f"sha256:{cdev_fd:064x}"
        if group_members is None:
            group_members = (bdf,)
        if iommu_group is None:
            iommu_group = {
                "0000:65:00.0": "7",
                "0000:66:00.0": "8",
            }.get(bdf, "9")
        if lease is None:
            lease = self.lease
        return launch.DeviceFdBinding._from_verified(
            bdf=bdf,
            guest_slot=launch.GuestSlot(
                index=index,
                root_port_address=root_port_address,
            ),
            cdev_fd=cdev_fd,
            cdev_stat=launch.FdStatToken.from_stat(self.fd_stats[cdev_fd]),
            iommufd_fd=iommufd_fd,
            iommufd_stat=launch.FdStatToken.from_stat(self.fd_stats[iommufd_fd]),
            identity_hash=identity_hash,
            group_hash=group_hash,
            provider_admission=launch.ProviderAdmission(
                snapshot_epoch=snapshot_epoch,
                topology_hash=HASH_A,
                fd_binding_hash=provider_binding_hash,
                iommu_group=iommu_group,
                group_members=group_members,
                lease_binding_hash=lease.binding_hash,
            ),
        )

    def replace_device(
        self,
        device: launch.DeviceFdBinding,
        **changes,
    ) -> launch.DeviceFdBinding:
        values = {
            "bdf": device.bdf,
            "guest_slot": device.guest_slot,
            "cdev_fd": device.cdev_fd,
            "cdev_stat": device.cdev_stat,
            "iommufd_fd": device.iommufd_fd,
            "iommufd_stat": device.iommufd_stat,
            "identity_hash": device.identity_hash,
            "group_hash": device.group_hash,
            "provider_admission": device.provider_admission,
        }
        values.update(changes)
        return launch.DeviceFdBinding._from_verified(**values)

    def plan(self, devices=None, **changes) -> launch.DirectPathLaunchPlan:
        selected_lease = changes.get("lease", self.lease)
        values = {
            "qemu": self.qemu,
            "lease": selected_lease,
            "profile": self.profile,
            "qmp": self.qmp,
            "devices": (self.device(lease=selected_lease),) if devices is None else devices,
        }
        values.update(changes)
        return launch.DirectPathLaunchPlan(**values)

    def render(self, plan=None) -> launch.SpawnSpec:
        return launch.render_launch(
            self.plan() if plan is None else plan,
            fstat=self.fstat,
            stat_path=self.stat_path,
        )

    def assert_reason(self, reason: str, callback) -> launch.LaunchContractError:
        with self.assertRaises(launch.LaunchContractError) as raised:
            callback()
        self.assertEqual(raised.exception.reason_code, reason)
        return raised.exception

    def test_single_device_golden_argv_and_spawn_policy(self) -> None:
        spec = self.render()

        self.assertEqual(
            spec.argv,
            (
                str(self.qemu_path),
                "-machine",
                "pc-q35-11.0",
                "-accel",
                "kvm",
                "-S",
                "-nodefaults",
                "-display",
                "none",
                "-serial",
                "none",
                "-m",
                "4096",
                "-smp",
                "4",
                "-monitor",
                "none",
                "-qmp",
                f"unix:{self.qmp.socket_path},server=on,wait=off",
                "-object",
                "iommufd,id=iommufd0,fd=21",
                "-device",
                (
                    "pcie-root-port,id=rp-dp0,bus=pcie.0,addr=02.0,chassis=1,slot=2,"
                    "hotplug=off,x-do-not-expose-native-hotplug-cap=on"
                ),
                "-device",
                "vfio-pci,id=dp0,fd=11,iommufd=iommufd0,bus=rp-dp0,addr=00.0,rombar=0",
            ),
        )
        self.assertEqual(spec.pass_fds, (11, 21))
        self.assertIs(spec.shell, False)
        self.assertIs(spec.close_fds, True)
        self.assertEqual(spec.environment, ())
        self.assertEqual(spec.trusted_cwd, "/")
        self.assertEqual(
            spec.popen_kwargs(),
            {
                "args": spec.argv,
                "close_fds": True,
                "cwd": "/",
                "env": {},
                "pass_fds": (11, 21),
                "shell": False,
            },
        )
        self.assertEqual(spec.qemu_binary_hash, self.qemu.sha256)
        self.assertEqual(spec.argv.count("-qmp"), 1)
        self.assertEqual(spec.argv.count("-monitor"), 1)
        self.assertEqual(spec.argv.count("-accel"), 1)
        self.assertEqual(spec.argv.count("-S"), 1)
        self.assertEqual(spec.argv.count("-nodefaults"), 1)
        self.assertEqual(spec.argv.count("-display"), 1)
        self.assertEqual(spec.argv.count("-serial"), 1)

    def test_renderer_has_no_raw_argv_and_never_renders_bypass_tokens(self) -> None:
        self.assertNotIn("argv", launch.DirectPathLaunchPlan.__dataclass_fields__)
        spec = self.render()
        rendered = " ".join(spec.argv).lower()
        for forbidden in ("host=", "sysfsdev=", "noiommu", "legacy", "getfd", "add-fd"):
            self.assertNotIn(forbidden, rendered)

    def test_multiple_devices_are_canonical_and_share_one_iommufd_object(self) -> None:
        first = self.device()
        second = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=21,
            identity_hash=HASH_D,
            group_hash=HASH_C,
        )
        spec = self.render(self.plan(devices=[second, first]))
        reverse_spec = self.render(self.plan(devices=[first, second]))

        self.assertEqual(spec, reverse_spec)
        self.assertEqual(spec.pass_fds, (11, 12, 21))
        self.assertEqual(spec.argv.count("-object"), 1)
        first_position = spec.argv.index(
            "vfio-pci,id=dp0,fd=11,iommufd=iommufd0,bus=rp-dp0,addr=00.0,rombar=0"
        )
        second_position = spec.argv.index(
            "vfio-pci,id=dp1,fd=12,iommufd=iommufd0,bus=rp-dp1,addr=00.0,rombar=0"
        )
        self.assertLess(first_position, second_position)

    def test_distinct_iommufds_get_stable_objects_and_sorted_pass_fds(self) -> None:
        first = self.device(cdev_fd=12, iommufd_fd=22)
        second = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=11,
            iommufd_fd=21,
        )
        spec = self.render(self.plan(devices=(first, second)))

        self.assertEqual(spec.pass_fds, (11, 12, 21, 22))
        self.assertIn("iommufd,id=iommufd0,fd=21", spec.argv)
        self.assertIn("iommufd,id=iommufd1,fd=22", spec.argv)

    def test_distinct_iommufd_opens_may_share_one_character_node_identity(self) -> None:
        self.fd_stats[22] = char_stat(device=1, inode=121, rdev=221)
        first = self.device(cdev_fd=11, iommufd_fd=21)
        second = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
        )

        spec = self.render(self.plan(devices=(first, second)))

        self.assertEqual(spec.pass_fds, (11, 12, 21, 22))
        self.assertIn("iommufd,id=iommufd0,fd=21", spec.argv)
        self.assertIn("iommufd,id=iommufd1,fd=22", spec.argv)

    def test_overlapping_iommu_groups_require_one_shared_iommufd_description(self) -> None:
        shared_group = ("0000:65:00.0", "0000:66:00.0")
        first = self.device(
            group_members=shared_group,
            iommu_group="7",
            iommufd_fd=21,
        )
        second_shared = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=21,
            iommu_group="7",
            group_members=shared_group,
        )
        spec = self.render(self.plan(devices=(first, second_shared)))
        self.assertEqual(spec.pass_fds, (11, 12, 21))

        second_conflicting_stat = self.replace_device(
            second_shared,
            iommufd_stat=launch.FdStatToken.from_stat(self.fd_stats[22]),
        )
        self.assert_reason(
            launch.Reason.FD_ROLE_CONFLICT,
            lambda: self.plan(devices=(first, second_conflicting_stat)),
        )

        self.fd_stats[22] = char_stat(device=1, inode=121, rdev=221)
        second_distinct_description = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
            iommu_group="7",
            group_members=shared_group,
        )
        self.assert_reason(
            launch.Reason.FD_ROLE_CONFLICT,
            lambda: self.plan(devices=(first, second_distinct_description)),
        )

        overlapping = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
            group_members=("0000:00:1f.0", "0000:66:00.0"),
        )
        bridge_group = self.device(
            group_members=("0000:00:1f.0", "0000:65:00.0"),
        )
        self.assert_reason(
            launch.Reason.INVALID_PROVIDER_ADMISSION,
            lambda: self.plan(devices=(bridge_group, overlapping)),
        )

    def test_iommu_group_id_member_matrix_is_fail_closed(self) -> None:
        self.assert_reason(
            launch.Reason.INVALID_PROVIDER_ADMISSION,
            lambda: self.device(iommu_group="group-7"),
        )

        first = self.device(
            iommu_group="7",
            group_members=("0000:65:00.0", "0000:66:00.0"),
        )
        same_id_member_drift = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=21,
            iommu_group="7",
            group_members=("0000:66:00.0",),
        )
        self.assert_reason(
            launch.Reason.INVALID_PROVIDER_ADMISSION,
            lambda: self.plan(devices=(first, same_id_member_drift)),
        )

        different_id_overlap = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=21,
            iommu_group="8",
            group_members=("0000:65:00.0", "0000:66:00.0"),
        )
        self.assert_reason(
            launch.Reason.INVALID_PROVIDER_ADMISSION,
            lambda: self.plan(devices=(first, different_id_overlap)),
        )

        disjoint = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
            iommu_group="8",
            group_members=("0000:66:00.0",),
        )
        isolated_first = self.device(
            iommu_group="7",
            group_members=("0000:65:00.0",),
        )
        spec = self.render(self.plan(devices=(isolated_first, disjoint)))
        self.assertEqual(spec.pass_fds, (11, 12, 21, 22))

    def test_iommu_group_id_is_bound_into_fd_and_plan_hashes(self) -> None:
        baseline = self.render(self.plan(devices=(self.device(iommu_group="7"),)))
        changed = self.render(self.plan(devices=(self.device(iommu_group="70"),)))

        self.assertEqual(baseline.argv_hash, changed.argv_hash)
        self.assertNotEqual(baseline.fd_binding_hash, changed.fd_binding_hash)
        self.assertNotEqual(baseline.plan_hash, changed.plan_hash)

    def test_plan_is_frozen_and_defensively_copies_device_sequence(self) -> None:
        source = [self.device()]
        plan = self.plan(devices=source)
        source.clear()

        self.assertEqual(len(plan.devices), 1)
        self.assertIsInstance(plan.devices, tuple)
        with self.assertRaises(FrozenInstanceError):
            plan.devices = ()

    def test_rejects_empty_duplicate_or_cross_role_device_sets(self) -> None:
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: self.plan(devices=()),
        )
        duplicate = self.replace_device(
            self.device(),
            cdev_fd=12,
            cdev_stat=launch.FdStatToken.from_stat(self.fd_stats[12]),
        )
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: self.plan(devices=(self.device(), duplicate)),
        )
        cross_role = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=21,
            iommufd_fd=22,
        )
        self.assert_reason(
            launch.Reason.FD_ROLE_CONFLICT,
            lambda: self.plan(devices=(self.device(), cross_role)),
        )

    def test_rejects_distinct_fd_numbers_aliasing_one_character_inode(self) -> None:
        first = self.device()
        self.fd_stats[12] = char_stat(device=1, inode=101, rdev=201)
        alias = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
        )
        self.assert_reason(
            launch.Reason.FD_ROLE_CONFLICT,
            lambda: self.plan(devices=(first, alias)),
        )

        self.fd_stats[12] = char_stat(device=1, inode=102, rdev=202)
        self.fd_stats[22] = char_stat(device=1, inode=101, rdev=201)
        cross_role_alias = self.device(
            bdf="0000:66:00.0",
            index=1,
            root_port_address=3,
            cdev_fd=12,
            iommufd_fd=22,
        )
        self.assert_reason(
            launch.Reason.FD_ROLE_CONFLICT,
            lambda: self.plan(devices=(first, cross_role_alias)),
        )

    def test_rejects_non_character_fd_tokens_and_invalid_fd_values(self) -> None:
        regular = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_rdev=0,
            st_mode=stat.S_IFREG | 0o600,
        )
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: launch.FdStatToken.from_stat(regular),
        )
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: self.replace_device(self.device(), cdev_fd=2),
        )

    def test_rejects_fd_substitution_at_render_and_immediately_before_spawn(self) -> None:
        plan = self.plan()
        self.fd_stats[11] = char_stat(device=9, inode=999, rdev=999)
        self.assert_reason(
            launch.Reason.FD_IDENTITY_MISMATCH,
            lambda: self.render(plan),
        )

        self.fd_stats[11] = char_stat(device=1, inode=101, rdev=201)
        spec = self.render(plan)
        self.fd_stats[21] = char_stat(device=9, inode=999, rdev=999)
        self.assert_reason(
            launch.Reason.FD_IDENTITY_MISMATCH,
            lambda: launch.validate_before_spawn(
                spec,
                fstat=self.fstat,
                stat_path=self.stat_path,
                platform_name="posix",
            ),
        )

    def test_closed_fd_is_a_stable_identity_failure(self) -> None:
        def closed(_fd: int):
            raise OSError(9, "bad fd")

        self.assert_reason(
            launch.Reason.FD_IDENTITY_MISMATCH,
            lambda: launch.render_launch(
                self.plan(),
                fstat=closed,
                stat_path=self.stat_path,
            ),
        )

    def test_binary_stat_and_content_substitution_are_rejected(self) -> None:
        original = self.plan()
        self.qemu_path.write_bytes(b"different-size")
        self.qemu_path.chmod(0o755)
        self.assert_reason(
            launch.Reason.QEMU_BINARY_IDENTITY_MISMATCH,
            lambda: self.render(original),
        )

        self.qemu_path.write_bytes(b"test-qemu-binary-v1")
        self.qemu_path.chmod(0o755)
        refreshed = self.plan(qemu=launch.capture_qemu_binary_identity(self.qemu_path))
        self.assert_reason(
            launch.Reason.QEMU_BINARY_HASH_MISMATCH,
            lambda: launch.render_launch(
                refreshed,
                fstat=self.fstat,
                stat_path=self.stat_path,
                file_hasher=lambda _path: HASH_A,
            ),
        )

    def test_qemu_identity_capture_rejects_relative_and_non_executable_paths(self) -> None:
        self.assert_reason(
            launch.Reason.INVALID_QEMU_PATH,
            lambda: launch.capture_qemu_binary_identity(Path("qemu-system-x86_64")),
        )
        if os.name != "nt":
            self.qemu_path.chmod(0o600)
            self.assert_reason(
                launch.Reason.INVALID_QEMU_PATH,
                lambda: launch.capture_qemu_binary_identity(self.qemu_path),
            )

    def test_profile_lease_and_qmp_are_canonical_and_bounded(self) -> None:
        self.assert_reason(
            launch.Reason.INVALID_PROFILE,
            lambda: replace(self.profile, machine_type="pc-i440fx-11.0"),
        )
        self.assert_reason(
            launch.Reason.INVALID_PROFILE,
            lambda: replace(self.profile, memory_mib=255),
        )
        self.assert_reason(
            launch.Reason.INVALID_QMP_SOCKET,
            lambda: replace(self.qmp, socket_path=self.runtime / "backend-wrong.qmp"),
        )
        self.assert_reason(
            launch.Reason.INVALID_QMP_SOCKET,
            lambda: replace(
                self.runtime_stat,
                mode=stat.S_IFDIR | 0o755,
            ),
        )

    def test_q35_root_port_address_reserves_ich9_lpc_slot_31(self) -> None:
        self.assertEqual(
            launch.GuestSlot(index=29, root_port_address=30).root_port_address,
            30,
        )
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: launch.GuestSlot(index=29, root_port_address=31),
        )

    def test_product_bindings_cannot_be_directly_constructed(self) -> None:
        with self.assertRaises(TypeError):
            launch.LeaseBinding(
                transaction_id="tx-bypass",
                host_id="host-a",
                vm_id="vm-a",
                run_id="run-a",
                bundle_id="bundle-a",
                authority_id="authority-a",
                bundle_members_hash=HASH_A,
                members=("0000:65:00.0",),
                inventory_epoch=17,
                device_generations=(("0000:65:00.0", 1),),
                vm_generation=1,
                lease_revision=1,
                policy_hash=HASH_A,
                decision_hash=HASH_B,
                state="PREPARING",
            )
        with self.assertRaises(TypeError):
            launch.DeviceFdBinding(
                bdf="0000:65:00.0",
                guest_slot=launch.GuestSlot(index=0, root_port_address=2),
                cdev_fd=11,
                cdev_stat=launch.FdStatToken.from_stat(self.fd_stats[11]),
                iommufd_fd=21,
                iommufd_stat=launch.FdStatToken.from_stat(self.fd_stats[21]),
                identity_hash=HASH_C,
                group_hash=HASH_D,
                provider_admission=launch.ProviderAdmission(
                    snapshot_epoch=17,
                    topology_hash=HASH_A,
                    fd_binding_hash=HASH_B,
                    iommu_group="7",
                    group_members=("0000:65:00.0",),
                    lease_binding_hash=self.lease.binding_hash,
                ),
            )

    def test_lease_adapter_rejects_raw_records_and_public_capability_construction(self) -> None:
        self.assert_reason(
            launch.Reason.INVALID_LEASE_AUTHORIZATION,
            lambda: launch.lease_binding_from_launch_authorization(self.lease_record),
        )
        with self.assertRaises(TypeError):
            leases.LeaseLaunchAuthorization()

    def test_authorization_context_exit_invalidates_plan_render_and_spawn_spec(self) -> None:
        _store, _record, authorization, binding, context = self.open_active_lease(
            "expires",
            transaction_id="tx-expires",
            run_id="run-expires",
            register_context_cleanup=False,
        )
        device = self.device(lease=binding)
        plan = self.plan(devices=(device,), lease=binding)
        spec = self.render(plan)
        context.__exit__(None, None, None)

        self.assertFalse(authorization.is_active)
        for callback in (
            lambda: launch.lease_binding_from_launch_authorization(authorization),
            lambda: self.plan(devices=(device,), lease=binding),
            lambda: self.render(plan),
            lambda: launch.validate_before_spawn(
                spec,
                fstat=self.fstat,
                stat_path=self.stat_path,
                platform_name="posix",
            ),
            spec.popen_kwargs,
        ):
            self.assert_reason(launch.Reason.LEASE_AUTHORIZATION_INACTIVE, callback)

    def test_plan_enforces_lease_members_epoch_and_transaction_binding(self) -> None:
        # The lease may contain dependency/bridge members not presented to QEMU.
        scoped = self.device(group_members=("0000:65:00.0",))
        self.assertEqual(self.plan(devices=(scoped,)).devices, (scoped,))

        outside = self.device(
            group_members=("0000:65:00.0", "0000:67:00.0"),
        )
        self.assert_reason(
            launch.Reason.LEASE_DEVICE_SCOPE_MISMATCH,
            lambda: self.plan(devices=(outside,)),
        )
        stale_epoch = self.device(snapshot_epoch=18)
        self.assert_reason(
            launch.Reason.LEASE_DEVICE_SCOPE_MISMATCH,
            lambda: self.plan(devices=(stale_epoch,)),
        )

        _store, _record, _auth, other_lease, _context = self.open_active_lease(
            "other",
            transaction_id="tx-002",
            run_id="run-b",
        )
        original_lease_device = self.device(lease=self.lease)
        self.assert_reason(
            launch.Reason.LEASE_DEVICE_SCOPE_MISMATCH,
            lambda: self.plan(
                devices=(original_lease_device,),
                lease=other_lease,
            ),
        )

    def test_qmp_runtime_identity_change_is_rejected(self) -> None:
        expected_path = self.runtime

        def changed(path: Path):
            if path == expected_path:
                value = self.runtime_observation
                return SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino + 1,
                    st_mode=value.st_mode,
                    st_uid=getattr(value, "st_uid", 0),
                )
            return self.stat_path(path)

        self.assert_reason(
            launch.Reason.QMP_RUNTIME_IDENTITY_MISMATCH,
            lambda: launch.render_launch(self.plan(), fstat=self.fstat, stat_path=changed),
        )

    def test_qmp_socket_must_not_exist_at_render_or_pre_spawn(self) -> None:
        self.qmp.socket_path.write_text("stale", encoding="utf-8")
        self.assert_reason(
            launch.Reason.QMP_SOCKET_ALREADY_EXISTS,
            lambda: self.render(),
        )
        self.qmp.socket_path.unlink()
        spec = self.render()
        self.qmp.socket_path.write_text("raced", encoding="utf-8")
        self.assert_reason(
            launch.Reason.QMP_SOCKET_ALREADY_EXISTS,
            lambda: launch.validate_before_spawn(
                spec,
                fstat=self.fstat,
                stat_path=self.stat_path,
                platform_name="posix",
            ),
        )

    def test_qmp_socket_rejects_qemu_option_parser_delimiters(self) -> None:
        unsafe_runtime = self.root / "qmp,unsafe"
        self.assert_reason(
            launch.Reason.INVALID_QMP_SOCKET,
            lambda: launch.QmpSocketBinding(
                runtime_directory=unsafe_runtime,
                runtime_stat=self.runtime_stat,
                socket_path=unsafe_runtime / f"backend-{self.nonce}.qmp",
                nonce=self.nonce,
            ),
        )

    def test_pre_spawn_validation_is_explicitly_posix_only(self) -> None:
        spec = self.render()
        self.assert_reason(
            launch.Reason.UNSUPPORTED_SPAWN_PLATFORM,
            lambda: launch.validate_before_spawn(
                spec,
                fstat=self.fstat,
                stat_path=self.stat_path,
                platform_name="nt",
            ),
        )

    def test_spawn_spec_rejects_every_noncanonical_public_field(self) -> None:
        spec = self.render()
        nonce = "3" * 32
        other_qmp = launch.QmpSocketBinding(
            runtime_directory=self.runtime,
            runtime_stat=self.runtime_stat,
            socket_path=self.runtime / f"backend-{nonce}.qmp",
            nonce=nonce,
        )
        mutations = {
            "argv": {"argv": spec.argv + ("-enable-kvm",)},
            "pass_fds": {"pass_fds": spec.pass_fds + (99,)},
            "expectations": {"fd_expectations": tuple(reversed(spec.fd_expectations))},
            "qemu_identity": {
                "qemu_identity": replace(spec.qemu_identity, sha256=HASH_A)
            },
            "qmp_binding": {"qmp_binding": other_qmp},
            "qemu_binary_hash": {"qemu_binary_hash": HASH_A},
            "fd_binding_hash": {"fd_binding_hash": HASH_A},
            "argv_hash": {"argv_hash": HASH_A},
            "plan_hash": {"plan_hash": HASH_A},
            "shell": {"shell": True},
            "close_fds": {"close_fds": False},
            "platform": {"spawn_platform": "nt"},
            "environment": {"environment": (("LD_PRELOAD", "/tmp/inject.so"),)},
            "cwd": {"trusted_cwd": "/tmp"},
            "plan": {
                "plan": replace(
                    spec.plan,
                    profile=replace(self.profile, memory_mib=8192),
                )
            },
        }
        for label, changes in mutations.items():
            with self.subTest(field=label):
                self.assert_reason(
                    launch.Reason.NON_CANONICAL_SPAWN_SPEC,
                    lambda changes=changes: replace(spec, **changes),
                )

    def test_pre_spawn_rechecks_canonical_fields_after_object_level_tamper(self) -> None:
        spec = self.render()
        object.__setattr__(spec, "argv", spec.argv + ("-enable-kvm",))

        self.assert_reason(
            launch.Reason.NON_CANONICAL_SPAWN_SPEC,
            lambda: launch.validate_before_spawn(
                spec,
                fstat=self.fstat,
                stat_path=self.stat_path,
                platform_name="posix",
            ),
        )

    def test_hashes_bind_lease_policy_device_fds_profile_and_qmp(self) -> None:
        baseline = self.render()
        _store, _record, _auth, changed_lease, _context = self.open_active_lease(
            "changed-policy",
            transaction_id="tx-policy",
            run_id="run-policy",
            policy_hash=HASH_C,
        )
        lease_changed = self.render(self.plan(lease=changed_lease))
        identity_changed = self.render(
            self.plan(devices=(self.replace_device(self.device(), identity_hash=HASH_A),))
        )
        profile_changed = self.render(
            self.plan(profile=replace(self.profile, memory_mib=8192))
        )
        nonce = "2" * 32
        qmp_changed = self.render(
            self.plan(
                qmp=launch.QmpSocketBinding(
                    runtime_directory=self.runtime,
                    runtime_stat=self.runtime_stat,
                    socket_path=self.runtime / f"backend-{nonce}.qmp",
                    nonce=nonce,
                )
            )
        )

        self.assertEqual(baseline.argv_hash, lease_changed.argv_hash)
        self.assertNotEqual(baseline.plan_hash, lease_changed.plan_hash)
        self.assertNotEqual(baseline.fd_binding_hash, identity_changed.fd_binding_hash)
        self.assertNotEqual(baseline.plan_hash, identity_changed.plan_hash)
        self.assertNotEqual(baseline.argv_hash, profile_changed.argv_hash)
        self.assertNotEqual(baseline.plan_hash, profile_changed.plan_hash)
        self.assertNotEqual(baseline.argv_hash, qmp_changed.argv_hash)
        self.assertNotEqual(baseline.plan_hash, qmp_changed.plan_hash)

    def test_capture_fd_stat_is_typed_and_fail_closed(self) -> None:
        token = launch.capture_fd_stat(11, fstat=self.fstat)
        self.assertEqual(token, launch.FdStatToken.from_stat(self.fd_stats[11]))
        self.assert_reason(
            launch.Reason.INVALID_DEVICE_BINDING,
            lambda: launch.capture_fd_stat(True, fstat=self.fstat),
        )

    @unittest.skipUnless(hasattr(os, "major"), "provider fd adapter is POSIX-only")
    def test_provider_result_adapter_binds_raw_admission_metadata(self) -> None:
        from pci_resource_model import vfio_launch_handles as handles
        from pci_resource_model import vfio_provider as vfio

        def opened(role: str, path: str, fd: int) -> handles.OpenHandleMetadata:
            observed = self.fd_stats[fd]
            return handles.OpenHandleMetadata(
                role=role,
                path=Path(path),
                inode=observed.st_ino,
                filesystem_device=observed.st_dev,
                character_device_major=os.major(observed.st_rdev),
                character_device_minor=os.minor(observed.st_rdev),
                cloexec=True,
            )

        identity = vfio.PciIdentity(
            vendor_id=0x8086,
            device_id=0x10D3,
            subsystem_vendor_id=0x8086,
            subsystem_device_id=0xA01F,
            class_code=0x020000,
            revision=2,
        )
        bdf = "0000:65:00.0"
        identity_hash = vfio.compute_identity_hash(bdf, identity)
        group_hash = vfio.compute_group_hash(bdf, "7", (bdf,))
        request = handles.VfioLaunchRequest(
            bdf=bdf,
            snapshot_epoch=17,
            topology_hash="a" * 64,
            expected_identity_hash=identity_hash,
            expected_group_hash=group_hash,
        )
        observed_state = vfio.DeviceState(
            bdf=bdf,
            identity=identity,
            driver="vfio-pci",
            iommu_group="7",
            group_members=(bdf,),
            noiommu_node_present=False,
            group_node=Path("/dev/vfio/7"),
            cdev_node=Path("/dev/vfio/devices/vfio0"),
            cdev_device_number=(
                os.major(self.fd_stats[11].st_rdev),
                os.minor(self.fd_stats[11].st_rdev),
            ),
        )

        def capture(_reader, captured_bdf: str):
            self.assertEqual(bdf, captured_bdf)
            return observed_state

        def open_node(
            _kernel,
            path: Path,
            *,
            role: str,
            failure_reason: str,
            expected_device_number,
            bdf: str,
        ) -> handles.OpenedNode:
            del failure_reason, expected_device_number, bdf
            fd = 21 if role == "iommufd" else 11
            return handles.OpenedNode(fd=fd, metadata=opened(role, str(path), fd))

        with (
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture),
            mock.patch.object(handles.PosixLaunchKernel, "open_char_node", open_node),
            mock.patch.object(handles.PosixLaunchKernel, "close", return_value=None),
        ):
            result = handles.open_vfio_launch_handles(request)
            self.assertTrue(handles.is_production_launch_result(result))
            binding = launch.device_binding_from_vfio_launch_result(
                result,
                launch.GuestSlot(index=0, root_port_address=2),
                self.lease,
                fstat=self.fstat,
            )
            self.assertEqual(binding.bdf, result.metadata.bdf)
            self.assertEqual(
                binding.identity_hash,
                "sha256:" + result.metadata.identity_hash,
            )
            result.close()

            injected = handles.open_vfio_launch_handles(
                request,
                state_reader=None,
                kernel=None,
            )
            self.assertFalse(handles.is_production_launch_result(injected))
            self.assert_reason(
                launch.Reason.INVALID_PROVIDER_ADMISSION,
                lambda: launch.device_binding_from_vfio_launch_result(
                    injected,
                    launch.GuestSlot(index=0, root_port_address=2),
                    self.lease,
                    fstat=self.fstat,
                ),
            )
            injected.close()

    @unittest.skipUnless(hasattr(os, "major"), "provider fd adapter is POSIX-only")
    def test_complete_group_bundle_adapts_to_one_qemu_iommufd_object(self) -> None:
        from pci_resource_model import vfio_launch_handles as handles
        from pci_resource_model import vfio_provider as vfio

        bdfs = ("0000:65:00.0", "0000:66:00.0")
        identity = vfio.PciIdentity(
            vendor_id=0x8086,
            device_id=0x10D3,
            subsystem_vendor_id=0x8086,
            subsystem_device_id=0xA01F,
            class_code=0x020000,
            revision=2,
        )
        states = {
            bdf: vfio.DeviceState(
                bdf=bdf,
                identity=identity,
                driver="vfio-pci",
                iommu_group="7",
                group_members=bdfs,
                noiommu_node_present=False,
                group_node=Path("/dev/vfio/7"),
                cdev_node=Path(f"/dev/vfio/devices/vfio{index}"),
                cdev_device_number=(
                    os.major(self.fd_stats[11 + index].st_rdev),
                    os.minor(self.fd_stats[11 + index].st_rdev),
                ),
            )
            for index, bdf in enumerate(bdfs)
        }
        requests = [
            handles.VfioLaunchRequest(
                bdf=bdf,
                snapshot_epoch=17,
                topology_hash="a" * 64,
                expected_identity_hash=vfio.compute_identity_hash(bdf, identity),
                expected_group_hash=vfio.compute_group_hash(bdf, "7", bdfs),
            )
            for bdf in bdfs
        ]

        def capture(_reader, captured_bdf: str):
            return states[captured_bdf]

        def opened(role: str, path: Path, fd: int) -> handles.OpenHandleMetadata:
            observed = self.fd_stats[fd]
            return handles.OpenHandleMetadata(
                role=role,
                path=path,
                inode=observed.st_ino,
                filesystem_device=observed.st_dev,
                character_device_major=os.major(observed.st_rdev),
                character_device_minor=os.minor(observed.st_rdev),
                cloexec=True,
            )

        def open_node(
            _kernel,
            path: Path,
            *,
            role: str,
            failure_reason: str,
            expected_device_number,
            bdf: str,
        ) -> handles.OpenedNode:
            del failure_reason, expected_device_number
            fd = 21 if role == "iommufd" else 11 + bdfs.index(bdf)
            return handles.OpenedNode(fd=fd, metadata=opened(role, Path(path), fd))

        with (
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture),
            mock.patch.object(handles.PosixLaunchKernel, "open_char_node", open_node),
            mock.patch.object(handles.PosixLaunchKernel, "close", return_value=None),
        ):
            bundle = handles.open_vfio_launch_bundle(requests)
            self.assertTrue(handles.is_production_launch_bundle(bundle))
            bindings = tuple(
                launch.device_binding_from_vfio_launch_result(
                    result,
                    launch.GuestSlot(index=index, root_port_address=2 + index),
                    self.lease,
                    fstat=self.fstat,
                )
                for index, result in enumerate(bundle.results)
            )
            spec = self.render(self.plan(devices=bindings))
            self.assertEqual((11, 12, 21), spec.pass_fds)
            self.assertEqual(
                1,
                sum(
                    token.startswith("iommufd,id=iommufd0,fd=21")
                    for token in spec.argv
                ),
            )
            self.assertEqual(
                2,
                sum("iommufd=iommufd0" in token for token in spec.argv),
            )
            bundle.results[0].close()
            self.assertFalse(bundle.results[1].handles_usable)
            self.assert_reason(
                launch.Reason.INVALID_PROVIDER_ADMISSION,
                lambda: launch.device_binding_from_vfio_launch_result(
                    bundle.results[1],
                    launch.GuestSlot(index=1, root_port_address=3),
                    self.lease,
                    fstat=self.fstat,
                ),
            )


if __name__ == "__main__":
    unittest.main()
