from __future__ import annotations

import copy
import errno
import json
import os
import pickle
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

from pci_resource_model import vfio_launch_handles as launch
from pci_resource_model import vfio_provider as vfio


BDF = "0000:65:00.0"
BDF2 = "0000:65:00.1"
TOPOLOGY_HASH = "1" * 64


def state(**changes):
    values = {
        "bdf": BDF,
        "identity": vfio.PciIdentity(
            vendor_id=0x8086,
            device_id=0x10D3,
            subsystem_vendor_id=0x8086,
            subsystem_device_id=0xA01F,
            class_code=0x020000,
            revision=2,
        ),
        "driver": "vfio-pci",
        "iommu_group": "7",
        "group_members": (BDF,),
        "noiommu_node_present": False,
        "group_node": Path("/dev/vfio/7"),
        "cdev_node": Path("/dev/vfio/devices/vfio0"),
        "cdev_device_number": (241, 0),
    }
    values.update(changes)
    return vfio.DeviceState(**values)


def request(observed=None, **changes):
    observed = state() if observed is None else observed
    values = {
        "bdf": BDF,
        "snapshot_epoch": 17,
        "topology_hash": TOPOLOGY_HASH,
        "expected_identity_hash": vfio.compute_identity_hash(BDF, observed.identity),
        "expected_group_hash": vfio.compute_group_hash(
            BDF, observed.iommu_group, observed.group_members
        ),
    }
    values.update(changes)
    return launch.VfioLaunchRequest(**values)


def request_for_state(observed, **changes):
    values = {
        "bdf": observed.bdf,
        "snapshot_epoch": 17,
        "topology_hash": TOPOLOGY_HASH,
        "expected_identity_hash": vfio.compute_identity_hash(
            observed.bdf, observed.identity
        ),
        "expected_group_hash": vfio.compute_group_hash(
            observed.bdf, observed.iommu_group, observed.group_members
        ),
    }
    values.update(changes)
    return launch.VfioLaunchRequest(**values)


class FakeReader:
    def __init__(self, *states_or_errors):
        self.values = list(states_or_errors)
        self.calls = []

    def capture(self, bdf):
        self.calls.append(bdf)
        value = self.values[min(len(self.calls) - 1, len(self.values) - 1)]
        if isinstance(value, BaseException):
            raise value
        return value


class FakeKernel:
    def __init__(self, *, next_fd=10):
        self.next_fd = next_fd
        self.open_fds = set()
        self.opens = []
        self.close_attempts = []
        self.ioctls = []
        self.fail_open_roles = set()
        self.fail_close_fds = set()
        self.metadata_changes = {}
        self.same_fd = None

    def open_char_node(
        self,
        path,
        *,
        role,
        failure_reason,
        expected_device_number,
        bdf,
    ):
        self.opens.append(
            {
                "path": Path(path),
                "role": role,
                "failureReason": failure_reason,
                "expectedDeviceNumber": expected_device_number,
                "bdf": bdf,
            }
        )
        if role in self.fail_open_roles:
            raise vfio.ProviderError(failure_reason, bdf=bdf, stage="fake-open")
        if self.same_fd is None:
            fd = self.next_fd
            self.next_fd += 1
        else:
            fd = self.same_fd
        self.open_fds.add(fd)
        device_number = expected_device_number or (10, 196)
        metadata = launch.OpenHandleMetadata(
            role=role,
            path=Path(path),
            inode=100 if role == "iommufd" else 200,
            filesystem_device=8,
            character_device_major=device_number[0],
            character_device_minor=device_number[1],
            cloexec=True,
        )
        if role in self.metadata_changes:
            metadata = replace(metadata, **self.metadata_changes[role])
        return launch.OpenedNode(fd=fd, metadata=metadata)

    def ioctl(self, *args, **kwargs):
        self.ioctls.append((args, kwargs))
        raise AssertionError("raw launch opener must never issue an ioctl")

    def close(self, fd):
        self.close_attempts.append(fd)
        if fd in self.fail_close_fds:
            raise OSError(errno.EIO, "injected close failure")
        if fd not in self.open_fds:
            raise OSError(errno.EBADF, "double close")
        self.open_fds.remove(fd)


def opened(reader=None, kernel=None, launch_request=None):
    observed = state()
    reader = reader or FakeReader(observed, observed)
    kernel = kernel or FakeKernel()
    result = launch.open_vfio_launch_handles(
        launch_request or request(observed),
        state_reader=reader,
        kernel=kernel,
    )
    return result, reader, kernel


class VfioLaunchHandlesTests(unittest.TestCase):
    def assert_reason(self, expected, operation):
        with self.assertRaises(vfio.ProviderError) as raised:
            operation()
        self.assertEqual(expected, raised.exception.reason_code)
        return raised.exception

    def test_fresh_cdev_and_iommufd_handles_are_rechecked_without_ioctl(self):
        result, reader, kernel = opened(launch_request=request(bdf=BDF.upper()))

        self.assertEqual([BDF, BDF], reader.calls)
        self.assertEqual(
            [
                (launch.IOMMUFD_PATH, "iommufd", None),
                (Path("/dev/vfio/devices/vfio0"), "vfio-cdev", (241, 0)),
            ],
            [
                (item["path"], item["role"], item["expectedDeviceNumber"])
                for item in kernel.opens
            ],
        )
        self.assertEqual([], kernel.ioctls)
        self.assertEqual((11, 10), result.pass_fds)
        self.assertEqual(BDF, result.request.bdf)
        self.assertEqual("vfio-cdev", result.metadata.cdev.role)
        self.assertEqual("iommufd", result.metadata.iommufd.role)
        self.assertTrue(result.metadata.cdev.cloexec)
        self.assertTrue(result.metadata.iommufd.cloexec)
        self.assertEqual(64, len(result.metadata.fd_binding_hash))
        self.assertEqual("CALLER_CORRELATION_ONLY", result.metadata.snapshot_binding)
        self.assertEqual("PYTHON_SUBPROCESS_PASS_FDS", result.metadata.handoff_mode)
        self.assertTrue(result.handles_usable)
        self.assertFalse(result.production_provenance)

        result.close()
        self.assertEqual([11, 10], kernel.close_attempts)
        self.assertFalse(result.handles_usable)
        self.assertFalse(result.production_provenance)
        result.close()
        self.assertEqual([11, 10], kernel.close_attempts)

    def test_bundle_opens_complete_group_on_one_iommufd_and_closes_atomically(self):
        members = (BDF, BDF2)
        first = state(group_members=members)
        second = state(
            bdf=BDF2,
            group_members=members,
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        reader = FakeReader(first, second, first, second)
        kernel = FakeKernel()

        bundle = launch.open_vfio_launch_bundle(
            [request_for_state(second), request_for_state(first)],
            state_reader=reader,
            kernel=kernel,
        )

        self.assertEqual([BDF, BDF2, BDF, BDF2], reader.calls)
        self.assertEqual([BDF, BDF2], [item.metadata.bdf for item in bundle.results])
        self.assertEqual(3, len(kernel.opens))
        self.assertEqual(1, sum(item["role"] == "iommufd" for item in kernel.opens))
        self.assertEqual(
            bundle.results[0].iommufd_fd, bundle.results[1].iommufd_fd
        )
        self.assertIs(bundle.results[0]._close_state, bundle.results[1]._close_state)
        self.assertEqual((11, 12, 10), bundle.pass_fds)
        self.assertTrue(bundle.handles_usable)
        self.assertTrue(all(result.handles_usable for result in bundle.results))

        bundle.results[0].close()
        self.assertEqual([12, 11, 10], kernel.close_attempts)
        self.assertTrue(bundle.closed)
        self.assertFalse(bundle.handles_usable)
        self.assertTrue(all(result.closed for result in bundle.results))
        self.assertTrue(all(not result.handles_usable for result in bundle.results))
        bundle.close()
        bundle.results[1].close()
        self.assertEqual([12, 11, 10], kernel.close_attempts)
        self.assert_reason(vfio.Reason.INVALID_ARGUMENT, lambda: bundle.pass_fds)

    def test_bundle_rejects_partial_group_before_open_and_recheck_drift_cleans_all(self):
        members = (BDF, BDF2)
        first = state(group_members=members)
        second = state(
            bdf=BDF2,
            group_members=members,
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        kernel = FakeKernel()
        error = self.assert_reason(
            vfio.Reason.IOMMU_GROUP_STALE,
            lambda: launch.open_vfio_launch_bundle(
                [request_for_state(first)],
                state_reader=FakeReader(first),
                kernel=kernel,
            ),
        )
        self.assertEqual("incomplete-launch-bundle-iommu-group", error.stage)
        self.assertEqual([], kernel.opens)

        stale_second = state(
            bdf=BDF2,
            iommu_group="8",
            group_members=(BDF2,),
            group_node=Path("/dev/vfio/8"),
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        kernel = FakeKernel()
        self.assert_reason(
            vfio.Reason.IOMMU_GROUP_STALE,
            lambda: launch.open_vfio_launch_bundle(
                [request_for_state(first), request_for_state(second)],
                state_reader=FakeReader(first, second, first, stale_second),
                kernel=kernel,
            ),
        )
        self.assertEqual([12, 11, 10], kernel.close_attempts)
        self.assertFalse(kernel.open_fds)

    def test_bundle_rejects_mixed_snapshot_duplicate_and_capability_forgery(self):
        observed = state()
        kernel = FakeKernel()
        self.assert_reason(
            vfio.Reason.INVALID_ARGUMENT,
            lambda: launch.open_vfio_launch_bundle(
                [request_for_state(observed), request_for_state(observed)],
                state_reader=FakeReader(observed),
                kernel=kernel,
            ),
        )
        other = state(
            bdf=BDF2,
            iommu_group="8",
            group_members=(BDF2,),
            group_node=Path("/dev/vfio/8"),
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        self.assert_reason(
            vfio.Reason.INVALID_SNAPSHOT_EPOCH,
            lambda: launch.open_vfio_launch_bundle(
                [
                    request_for_state(observed),
                    request_for_state(other, snapshot_epoch=18),
                ],
                state_reader=FakeReader(observed),
                kernel=kernel,
            ),
        )
        self.assertEqual([], kernel.opens)
        with self.assertRaisesRegex(TypeError, "created only"):
            launch.VfioLaunchBundle()
        blank = object.__new__(launch.VfioLaunchBundle)
        self.assertFalse(blank.production_provenance)
        self.assertFalse(blank.handles_usable)
        self.assertFalse(launch.is_production_launch_bundle(blank))
        self.assertTrue(blank.closed)
        self.assert_reason(vfio.Reason.INVALID_ARGUMENT, lambda: blank.pass_fds)

    def test_bundle_default_path_is_production_and_explicit_dependencies_are_lab(self):
        members = (BDF, BDF2)
        first = state(group_members=members)
        second = state(
            bdf=BDF2,
            group_members=members,
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        states = {BDF: first, BDF2: second}
        capture_calls = []
        fake_kernel = FakeKernel()

        def capture(_reader, bdf):
            capture_calls.append(bdf)
            return states[bdf]

        def open_char_node(
            _kernel,
            path,
            *,
            role,
            failure_reason,
            expected_device_number,
            bdf,
        ):
            return fake_kernel.open_char_node(
                path,
                role=role,
                failure_reason=failure_reason,
                expected_device_number=expected_device_number,
                bdf=bdf,
            )

        def close(_kernel, fd):
            fake_kernel.close(fd)

        launch_requests = [request_for_state(first), request_for_state(second)]
        with (
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture),
            mock.patch.object(
                launch.PosixLaunchKernel, "open_char_node", open_char_node
            ),
            mock.patch.object(launch.PosixLaunchKernel, "close", close),
        ):
            production = launch.open_vfio_launch_bundle(launch_requests)
            self.assertTrue(production.production_provenance)
            self.assertTrue(launch.is_production_launch_bundle(production))
            self.assertTrue(
                all(
                    launch.is_production_launch_result(result)
                    for result in production.results
                )
            )
            production.close()

            explicit_none = launch.open_vfio_launch_bundle(
                launch_requests, state_reader=None, kernel=None
            )
            self.assertFalse(explicit_none.production_provenance)
            self.assertFalse(launch.is_production_launch_bundle(explicit_none))
            explicit_none.close()
        self.assertEqual([BDF, BDF2, BDF, BDF2] * 2, capture_calls)
        self.assertFalse(fake_kernel.open_fds)

    def test_result_rejects_direct_public_data_object_construction(self):
        with self.assertRaisesRegex(
            TypeError, "created only by open_vfio_launch_handles"
        ):
            launch.VfioLaunchResult(
                request=request(),
                device_fd=11,
                iommufd_fd=10,
                metadata=None,
                _kernel=FakeKernel(),
            )

        class PropertyMasquerade(launch.VfioLaunchResult):
            def __init__(self):
                pass

            @property
            def production_provenance(self):
                return True

        forged = PropertyMasquerade()
        self.assertTrue(forged.production_provenance)
        self.assertFalse(launch.is_production_launch_result(forged))

    def test_capability_object_rejects_alias_copy_replace_and_pickle(self):
        result, _, kernel = opened()

        for operation in (
            lambda: copy.copy(result),
            lambda: copy.deepcopy(result),
            lambda: replace(result),
            lambda: pickle.dumps(result),
        ):
            with self.subTest(operation=operation):
                with self.assertRaises(TypeError):
                    operation()

        self.assertTrue(result.handles_usable)
        self.assertEqual([], kernel.close_attempts)
        result.close()

    def test_pickle_build_and_blank_new_cannot_create_usable_result(self):
        # Protocol-4 NEWOBJ + BUILD models a legacy/data-only pickle that tries
        # to bypass __init__.  BUILD must reach the explicit rejecting
        # __setstate__ rather than populate a capability object's __dict__.
        legacy_pickle = (
            b"\x80\x04"
            b"cpci_resource_model.vfio_launch_handles\nVfioLaunchResult\n"
            b")\x81}\x94b."
        )
        with self.assertRaisesRegex(TypeError, "cannot be unpickled"):
            pickle.loads(legacy_pickle)

        blank = object.__new__(launch.VfioLaunchResult)
        self.assertFalse(blank.production_provenance)
        self.assertFalse(launch.is_production_launch_result(blank))
        self.assertFalse(blank.handles_usable)
        self.assertTrue(blank.closed)
        self.assert_reason(vfio.Reason.INVALID_ARGUMENT, lambda: blank.pass_fds)

    def test_only_exact_fully_omitted_builtin_path_has_production_provenance(self):
        observed = state()
        capture_calls = []
        fake_kernel = FakeKernel()

        def capture(_reader, bdf):
            capture_calls.append(bdf)
            return observed

        def open_char_node(
            _kernel,
            path,
            *,
            role,
            failure_reason,
            expected_device_number,
            bdf,
        ):
            return fake_kernel.open_char_node(
                path,
                role=role,
                failure_reason=failure_reason,
                expected_device_number=expected_device_number,
                bdf=bdf,
            )

        def close(_kernel, fd):
            fake_kernel.close(fd)

        with (
            mock.patch.object(vfio.LinuxSysfsStateReader, "capture", capture),
            mock.patch.object(
                launch.PosixLaunchKernel, "open_char_node", open_char_node
            ),
            mock.patch.object(launch.PosixLaunchKernel, "close", close),
        ):
            production = launch.open_vfio_launch_handles(request(observed))
            self.assertTrue(production.production_provenance)
            self.assertTrue(launch.is_production_launch_result(production))
            self.assertTrue(production.handles_usable)
            production.close()
            self.assertTrue(production.production_provenance)
            self.assertTrue(launch.is_production_launch_result(production))
            self.assertFalse(production.handles_usable)

            explicit_none = launch.open_vfio_launch_handles(
                request(observed), state_reader=None, kernel=None
            )
            self.assertFalse(explicit_none.production_provenance)
            self.assertFalse(launch.is_production_launch_result(explicit_none))
            explicit_none.close()

        self.assertEqual([BDF, BDF, BDF, BDF], capture_calls)
        self.assertFalse(fake_kernel.open_fds)

    def test_injected_exact_builtin_instances_remain_test_lab_provenance(self):
        observed = state()
        fake_reader = FakeReader(observed, observed)
        exact_reader = vfio.LinuxSysfsStateReader()
        exact_reader.capture = fake_reader.capture
        fake_kernel = FakeKernel()
        exact_kernel = launch.PosixLaunchKernel()
        exact_kernel.open_char_node = fake_kernel.open_char_node
        exact_kernel.close = fake_kernel.close

        result = launch.open_vfio_launch_handles(
            request(observed),
            state_reader=exact_reader,
            kernel=exact_kernel,
        )

        self.assertFalse(result.production_provenance)
        self.assertFalse(launch.is_production_launch_result(result))
        result.close()
        self.assertFalse(result.handles_usable)

    def test_replaced_default_constructors_cannot_masquerade_as_production(self):
        observed = state()

        class ReplacementReader(FakeReader):
            def __init__(self, *, sysfs_root, vfio_root):
                self.sysfs_root = sysfs_root
                self.vfio_root = vfio_root
                super().__init__(observed, observed)

        class ReplacementKernel(FakeKernel):
            pass

        with (
            mock.patch.object(launch.vfio, "LinuxSysfsStateReader", ReplacementReader),
            mock.patch.object(launch, "PosixLaunchKernel", ReplacementKernel),
        ):
            result = launch.open_vfio_launch_handles(request(observed))

        self.assertFalse(result.production_provenance)
        self.assertFalse(launch.is_production_launch_result(result))
        result.close()

    def test_binding_hash_uses_immutable_inode_metadata_not_fd_numbers(self):
        first, _, first_kernel = opened(kernel=FakeKernel(next_fd=10))
        second, _, second_kernel = opened(kernel=FakeKernel(next_fd=1000))

        self.assertNotEqual(first.pass_fds, second.pass_fds)
        self.assertEqual(
            first.metadata.fd_binding_hash, second.metadata.fd_binding_hash
        )
        preimage = json.loads(
            launch.canonical_fd_binding_preimage(
                request=first.request,
                state=state(),
                identity_hash=first.metadata.identity_hash,
                group_hash=first.metadata.group_hash,
                cdev=first.metadata.cdev,
                iommufd=first.metadata.iommufd,
            )
        )
        self.assertNotIn("deviceFd", preimage)
        self.assertNotIn("iommufdFd", preimage)
        changed_cdev = replace(first.metadata.cdev, inode=201)
        changed_hash = launch.compute_fd_binding_hash(
            request=first.request,
            state=state(),
            identity_hash=first.metadata.identity_hash,
            group_hash=first.metadata.group_hash,
            cdev=changed_cdev,
            iommufd=first.metadata.iommufd,
        )
        self.assertNotEqual(first.metadata.fd_binding_hash, changed_hash)

        first.close()
        second.close()
        self.assertFalse(first_kernel.open_fds)
        self.assertFalse(second_kernel.open_fds)

    def test_request_result_and_handle_metadata_are_frozen(self):
        result, _, _ = opened()
        with self.assertRaises(FrozenInstanceError):
            result.request.bdf = "0000:00:00.0"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            result.device_fd = 999  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            result.metadata.cdev.inode = 999  # type: ignore[misc]
        result.close()

    def test_invalid_request_fields_fail_before_sysfs_or_open(self):
        invalid = [
            (request(bdf="65:00.0"), vfio.Reason.INVALID_BDF),
            (request(snapshot_epoch=True), vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            (request(snapshot_epoch=-1), vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            (request(snapshot_epoch=1 << 64), vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            (request(topology_hash="bad"), vfio.Reason.INVALID_TOPOLOGY_HASH),
            (
                request(expected_identity_hash="bad"),
                vfio.Reason.INVALID_EXPECTED_IDENTITY_HASH,
            ),
            (
                request(expected_group_hash="bad"),
                vfio.Reason.INVALID_EXPECTED_GROUP_HASH,
            ),
        ]
        for invalid_request, reason in invalid:
            with self.subTest(reason=reason):
                reader = FakeReader(state())
                kernel = FakeKernel()
                self.assert_reason(
                    reason,
                    lambda: launch.open_vfio_launch_handles(
                        invalid_request, state_reader=reader, kernel=kernel
                    ),
                )
                self.assertEqual([], reader.calls)
                self.assertEqual([], kernel.opens)
                self.assertEqual([], kernel.ioctls)

    def test_expected_identity_and_group_hashes_gate_all_opens(self):
        for changes, reason in (
            (
                {"expected_identity_hash": "b" * 64},
                vfio.Reason.DEVICE_IDENTITY_STALE,
            ),
            (
                {"expected_group_hash": "b" * 64},
                vfio.Reason.IOMMU_GROUP_STALE,
            ),
        ):
            with self.subTest(reason=reason):
                reader = FakeReader(state())
                kernel = FakeKernel()
                self.assert_reason(
                    reason,
                    lambda: launch.open_vfio_launch_handles(
                        request(**changes), state_reader=reader, kernel=kernel
                    ),
                )
                self.assertEqual([], kernel.opens)

    def test_wrong_owner_noiommu_and_missing_cdev_are_stable_preopen_denials(self):
        cases = (
            (
                state(driver="ixgbe"),
                vfio.Reason.DEVICE_NOT_VFIO_BOUND,
            ),
            (
                state(noiommu_node_present=True),
                vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION,
            ),
            (
                state(cdev_node=None, cdev_device_number=None),
                vfio.Reason.VFIO_CDEV_UNAVAILABLE,
            ),
        )
        for observed, reason in cases:
            with self.subTest(reason=reason):
                kernel = FakeKernel()
                self.assert_reason(
                    reason,
                    lambda: launch.open_vfio_launch_handles(
                        request(observed),
                        state_reader=FakeReader(observed),
                        kernel=kernel,
                    ),
                )
                self.assertEqual([], kernel.opens)
                self.assertEqual([], kernel.ioctls)

    def test_injected_reader_cannot_redirect_cdev_or_group_paths(self):
        cases = (
            state(cdev_node=Path("/tmp/vfio0")),
            state(group_node=Path("/tmp/7")),
        )
        for observed in cases:
            with self.subTest(observed=observed):
                kernel = FakeKernel()
                self.assert_reason(
                    vfio.Reason.VFIO_NODE_UNKNOWN
                    if observed.cdev_node == Path("/tmp/vfio0")
                    else vfio.Reason.VFIO_NODE_MISMATCH,
                    lambda: launch.open_vfio_launch_handles(
                        request(observed),
                        state_reader=FakeReader(observed),
                        kernel=kernel,
                    ),
                )
                self.assertEqual([], kernel.opens)

    def test_cdev_devt_from_sysfs_is_required_of_opened_inode(self):
        kernel = FakeKernel()
        kernel.metadata_changes["vfio-cdev"] = {"character_device_minor": 99}

        self.assert_reason(
            vfio.Reason.VFIO_NODE_MISMATCH,
            lambda: launch.open_vfio_launch_handles(
                request(), state_reader=FakeReader(state()), kernel=kernel
            ),
        )

        self.assertEqual([11, 10], kernel.close_attempts)
        self.assertFalse(kernel.open_fds)
        self.assertEqual([], kernel.ioctls)

    def test_cloexec_is_mandatory_for_explicit_pass_fds_handoff(self):
        kernel = FakeKernel()
        kernel.metadata_changes["iommufd"] = {"cloexec": False}

        self.assert_reason(
            vfio.Reason.VFIO_NODE_MISMATCH,
            lambda: launch.open_vfio_launch_handles(
                request(), state_reader=FakeReader(state()), kernel=kernel
            ),
        )

        self.assertEqual([10], kernel.close_attempts)
        self.assertFalse(kernel.open_fds)

    def test_iommufd_and_cdev_open_failures_have_distinct_reasons_and_cleanup(self):
        for role, reason, expected_closes in (
            ("iommufd", vfio.Reason.IOMMUFD_OPEN_FAILED, []),
            ("vfio-cdev", vfio.Reason.VFIO_CDEV_OPEN_FAILED, [10]),
        ):
            with self.subTest(role=role):
                kernel = FakeKernel()
                kernel.fail_open_roles.add(role)
                self.assert_reason(
                    reason,
                    lambda: launch.open_vfio_launch_handles(
                        request(), state_reader=FakeReader(state()), kernel=kernel
                    ),
                )
                self.assertEqual(expected_closes, kernel.close_attempts)
                self.assertFalse(kernel.open_fds)
                self.assertEqual([], kernel.ioctls)

    def test_exact_state_is_revalidated_after_both_opens_and_fails_closed(self):
        baseline = state()
        changes = (
            (
                replace(
                    baseline,
                    identity=replace(baseline.identity, device_id=0xFFFF),
                ),
                vfio.Reason.DEVICE_IDENTITY_STALE,
            ),
            (replace(baseline, driver="ixgbe"), vfio.Reason.DEVICE_OWNER_STALE),
            (
                replace(
                    baseline,
                    iommu_group="8",
                    group_node=Path("/dev/vfio/8"),
                ),
                vfio.Reason.IOMMU_GROUP_STALE,
            ),
            (
                replace(baseline, noiommu_node_present=True),
                vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION,
            ),
            (
                replace(
                    baseline,
                    cdev_node=Path("/dev/vfio/devices/vfio1"),
                    cdev_device_number=(241, 1),
                ),
                vfio.Reason.VFIO_NODE_MISMATCH,
            ),
        )
        for after, reason in changes:
            with self.subTest(reason=reason):
                kernel = FakeKernel()
                reader = FakeReader(baseline, after)
                self.assert_reason(
                    reason,
                    lambda: launch.open_vfio_launch_handles(
                        request(), state_reader=reader, kernel=kernel
                    ),
                )
                self.assertEqual([BDF, BDF], reader.calls)
                self.assertEqual([11, 10], kernel.close_attempts)
                self.assertFalse(kernel.open_fds)
                self.assertEqual([], kernel.ioctls)

    def test_duplicate_fds_are_rejected_and_closed_once(self):
        kernel = FakeKernel()
        kernel.same_fd = 77

        self.assert_reason(
            vfio.Reason.VFIO_NODE_MISMATCH,
            lambda: launch.open_vfio_launch_handles(
                request(), state_reader=FakeReader(state()), kernel=kernel
            ),
        )

        self.assertEqual([77], kernel.close_attempts)
        self.assertFalse(kernel.open_fds)

    def test_malformed_injected_open_result_cannot_mask_prior_handle_cleanup(self):
        class RaisingFd:
            @property
            def fd(self):
                raise RuntimeError("injected malformed fd property")

        malformed_values = (
            object(),
            launch.OpenedNode(fd="not-an-int", metadata=None),
            RaisingFd(),
        )

        for malformed in malformed_values:
            with self.subTest(malformed=type(malformed).__name__):

                class MalformedSecondOpenKernel(FakeKernel):
                    def open_char_node(self, path, **kwargs):
                        if kwargs["role"] == "vfio-cdev":
                            return malformed
                        return super().open_char_node(path, **kwargs)

                kernel = MalformedSecondOpenKernel()
                self.assert_reason(
                    vfio.Reason.VFIO_NODE_MISMATCH,
                    lambda: launch.open_vfio_launch_handles(
                        request(), state_reader=FakeReader(state()), kernel=kernel
                    ),
                )
                self.assertEqual([10], kernel.close_attempts)
                self.assertFalse(kernel.open_fds)

    def test_close_failure_is_surfaced_after_both_reverse_close_attempts(self):
        result, _, kernel = opened()
        kernel.fail_close_fds.add(result.device_fd)

        error = self.assert_reason(vfio.Reason.PROVIDER_CLEANUP_FAILED, result.close)

        self.assertEqual("launch-handle-close", error.stage)
        self.assertEqual([result.device_fd, result.iommufd_fd], kernel.close_attempts)
        self.assertTrue(result.closed)
        self.assertTrue(result.cleanup_failed)
        self.assertFalse(result.handles_usable)
        before = list(kernel.close_attempts)
        result.close()
        self.assertEqual(before, kernel.close_attempts)
        self.assert_reason(vfio.Reason.INVALID_ARGUMENT, lambda: result.pass_fds)

    def test_partial_cleanup_failure_replaces_primary_open_error(self):
        kernel = FakeKernel()
        kernel.fail_open_roles.add("vfio-cdev")
        kernel.fail_close_fds.add(10)

        error = self.assert_reason(
            vfio.Reason.PROVIDER_CLEANUP_FAILED,
            lambda: launch.open_vfio_launch_handles(
                request(), state_reader=FakeReader(state()), kernel=kernel
            ),
        )

        self.assertEqual("partial-launch-open-cleanup", error.stage)
        self.assertEqual([10], kernel.close_attempts)
        self.assertEqual([], kernel.ioctls)

    @unittest.skipUnless(os.name == "posix", "real character-node gate is POSIX-only")
    def test_posix_kernel_rejects_regular_file_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-a-character-device"
            path.touch()
            self.assert_reason(
                vfio.Reason.VFIO_NODE_MISMATCH,
                lambda: launch.PosixLaunchKernel().open_char_node(
                    path,
                    role="iommufd",
                    failure_reason=vfio.Reason.IOMMUFD_OPEN_FAILED,
                    expected_device_number=None,
                    bdf=BDF,
                ),
            )


if __name__ == "__main__":
    unittest.main()
