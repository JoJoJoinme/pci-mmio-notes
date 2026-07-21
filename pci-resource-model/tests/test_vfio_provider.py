import contextlib
import errno
import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from pci_resource_model import vfio_provider as vfio


BDF = "0000:65:00.0"
TOPOLOGY_HASH = "a" * 64


def state(**changes) -> vfio.DeviceState:
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
    def __init__(self):
        self.next_fd = 10
        self.open_fds = set()
        self.opens = []
        self.closes = []
        self.ioctls = []
        self.fail_requests = set()
        self.api_version = vfio.VFIO_API_VERSION
        self.viable = True
        self.supported_iommus = {vfio.VFIO_TYPE1V2_IOMMU, vfio.VFIO_TYPE1_IOMMU}

    def open_node(
        self,
        path,
        *,
        failure_reason,
        expected_device_number=None,
        bdf,
    ):
        fd = self.next_fd
        self.next_fd += 1
        self.open_fds.add(fd)
        self.opens.append((Path(path), failure_reason, expected_device_number, bdf, fd))
        return fd

    def ioctl(self, fd, request, argument=0, *, mutate=False):
        self.ioctls.append((fd, request, argument, mutate))
        if request in self.fail_requests:
            raise OSError(errno.EIO, "injected ioctl failure")
        if request == vfio.IOMMU_IOAS_ALLOC:
            argument[:] = vfio.struct.pack("=III", 12, 0, 41)
            return 0
        if request == vfio.VFIO_DEVICE_BIND_IOMMUFD:
            argsz, flags, iommufd, _, token = vfio.struct.unpack("=IIiIQ", argument)
            argument[:] = vfio.struct.pack("=IIiIQ", argsz, flags, iommufd, 51, token)
            return 0
        if request == vfio.VFIO_DEVICE_ATTACH_IOMMUFD_PT:
            argsz, flags, _, pasid = vfio.struct.unpack("=IIII", argument)
            argument[:] = vfio.struct.pack("=IIII", argsz, flags, 61, pasid)
            return 0
        if request == vfio.VFIO_GROUP_GET_STATUS:
            argument[:] = vfio.struct.pack(
                "=II", 8, vfio.VFIO_GROUP_FLAGS_VIABLE if self.viable else 0
            )
            return 0
        if request == vfio.VFIO_GET_API_VERSION:
            return self.api_version
        if request == vfio.VFIO_CHECK_EXTENSION:
            return int(argument in self.supported_iommus)
        if request == vfio.VFIO_GROUP_GET_DEVICE_FD:
            new_fd = self.next_fd
            self.next_fd += 1
            self.open_fds.add(new_fd)
            return new_fd
        return 0

    def close(self, fd):
        if fd not in self.open_fds:
            raise OSError(errno.EBADF, "double close")
        self.open_fds.remove(fd)
        self.closes.append(fd)


def acquire(reader, kernel, **changes):
    baseline = reader.values[0] if isinstance(reader.values[0], vfio.DeviceState) else state()
    values = {
        "snapshot_epoch": 17,
        "topology_hash": TOPOLOGY_HASH,
        "expected_identity_hash": vfio.compute_identity_hash(
            baseline.bdf, baseline.identity
        ),
        "expected_group_hash": vfio.compute_group_hash(
            baseline.bdf, baseline.iommu_group, baseline.group_members
        ),
        "state_reader": reader,
        "kernel": kernel,
    }
    values.update(changes)
    return vfio.open_vfio_provider(BDF, **values)


class VfioProviderTests(unittest.TestCase):
    def test_supported_uapi_constants_and_struct_layouts_match_linux_headers(self):
        self.assertEqual(vfio.VFIO_GET_API_VERSION, 0x3B64)
        self.assertEqual(vfio.VFIO_GROUP_GET_DEVICE_FD, 0x3B6A)
        self.assertEqual(vfio.VFIO_DEVICE_BIND_IOMMUFD, 0x3B76)
        self.assertEqual(vfio.VFIO_DEVICE_ATTACH_IOMMUFD_PT, 0x3B77)
        self.assertEqual(vfio.VFIO_DEVICE_DETACH_IOMMUFD_PT, 0x3B78)
        self.assertEqual(vfio.IOMMU_DESTROY, 0x3B80)
        self.assertEqual(vfio.IOMMU_IOAS_ALLOC, 0x3B81)
        self.assertEqual(vfio.struct.calcsize("=IIiIQ"), 24)
        self.assertEqual(vfio.struct.calcsize("=IIII"), 16)
        self.assertEqual(vfio.struct.calcsize("=III"), 12)
        self.assertEqual(vfio.struct.calcsize("=II"), 8)

    def test_canonical_snapshot_hashes_cover_exact_identity_and_group(self):
        observed = state(group_members=(BDF, "0000:65:00.1"))

        identity = vfio.json.loads(
            vfio.canonical_identity_preimage(BDF.upper(), observed.identity)
        )
        group = vfio.json.loads(
            vfio.canonical_group_preimage(
                BDF.upper(), "7", ("0000:65:00.1", BDF.upper())
            )
        )

        self.assertEqual(identity["kind"], "qman-vfio-identity-v1")
        self.assertEqual(identity["bdf"], BDF)
        self.assertEqual(identity["vendorId"], 0x8086)
        self.assertEqual(identity["deviceId"], 0x10D3)
        self.assertEqual(identity["subsystemVendorId"], 0x8086)
        self.assertEqual(identity["subsystemDeviceId"], 0xA01F)
        self.assertEqual(identity["classCode"], 0x020000)
        self.assertEqual(identity["revision"], 2)
        self.assertEqual(group["kind"], "qman-vfio-iommu-group-v1")
        self.assertEqual(group["bdf"], BDF)
        self.assertEqual(group["groupId"], "7")
        self.assertEqual(group["members"], [BDF, "0000:65:00.1"])

    def test_snapshot_identity_hash_mismatch_opens_nothing(self):
        reader = FakeReader(state())
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(reader, kernel, expected_identity_hash="b" * 64)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.DEVICE_IDENTITY_STALE)
        self.assertEqual(kernel.opens, [])
        self.assertEqual(kernel.ioctls, [])

    def test_snapshot_group_hash_mismatch_opens_nothing(self):
        reader = FakeReader(state())
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(reader, kernel, expected_group_hash="b" * 64)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.IOMMU_GROUP_STALE)
        self.assertEqual(kernel.opens, [])
        self.assertEqual(kernel.ioctls, [])

    def test_cdev_binds_iommufd_allocates_ioas_and_rechecks_state(self):
        observed = state()
        reader = FakeReader(observed, observed)
        kernel = FakeKernel()

        session = acquire(reader, kernel)

        self.assertEqual(session.proof["provider"], "vfio-cdev-iommufd")
        self.assertEqual(session.proof["deviceId"], 51)
        self.assertEqual(session.proof["ioasId"], 41)
        self.assertEqual(session.proof["hwptId"], 61)
        self.assertEqual(session.proof["snapshotEpoch"], 17)
        self.assertEqual(session.proof["lifecycle"], "LIVE_SESSION")
        self.assertTrue(session.proof["handlesUsable"])
        self.assertEqual(
            session.proof["snapshotBinding"], "CALLER_CORRELATION_ONLY"
        )
        self.assertNotIn("reverified", session.proof)
        self.assertEqual(reader.calls, [BDF, BDF])
        self.assertEqual(
            [call[1] for call in kernel.ioctls[:3]],
            [
                vfio.IOMMU_IOAS_ALLOC,
                vfio.VFIO_DEVICE_BIND_IOMMUFD,
                vfio.VFIO_DEVICE_ATTACH_IOMMUFD_PT,
            ],
        )
        self.assertEqual(len(kernel.open_fds), 2)

        session.close()

        self.assertFalse(kernel.open_fds)
        self.assertEqual(session.proof["lifecycle"], "CLOSED")
        self.assertFalse(session.proof["handlesUsable"])
        self.assertIn(
            vfio.VFIO_DEVICE_DETACH_IOMMUFD_PT,
            [call[1] for call in kernel.ioctls],
        )
        self.assertIn(vfio.IOMMU_DESTROY, [call[1] for call in kernel.ioctls])
        session.close()

    def test_noiommu_node_is_an_immediate_negative_proof(self):
        reader = FakeReader(state(noiommu_node_present=True))
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(reader, kernel, allow_legacy_lab=True)

        self.assertEqual(
            raised.exception.reason_code,
            vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION,
        )
        self.assertEqual(kernel.opens, [])

    def test_legacy_is_disabled_without_explicit_lab_opt_in(self):
        reader = FakeReader(state(cdev_node=None, cdev_device_number=None))

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(reader, FakeKernel())

        self.assertEqual(
            raised.exception.reason_code, vfio.Reason.LEGACY_LAB_ONLY_DISABLED
        )

    def test_explicit_legacy_prefers_type1v2_and_returns_device_fd(self):
        observed = state(cdev_node=None, cdev_device_number=None)
        reader = FakeReader(observed, observed)
        kernel = FakeKernel()

        session = acquire(reader, kernel, allow_legacy_lab=True)

        self.assertEqual(session.proof["provider"], "vfio-legacy-type1v2")
        self.assertEqual(session.proof["iommuType"], "TYPE1v2")
        self.assertTrue(session.proof["labOnly"])
        self.assertIn(
            (session.container_fd, vfio.VFIO_SET_IOMMU, vfio.VFIO_TYPE1V2_IOMMU, False),
            kernel.ioctls,
        )
        session.close()
        self.assertFalse(kernel.open_fds)
        self.assertIn(
            vfio.VFIO_GROUP_UNSET_CONTAINER,
            [call[1] for call in kernel.ioctls],
        )

    def test_legacy_falls_back_only_to_type1(self):
        observed = state(cdev_node=None, cdev_device_number=None)
        kernel = FakeKernel()
        kernel.supported_iommus = {vfio.VFIO_TYPE1_IOMMU}

        session = acquire(
            FakeReader(observed, observed), kernel, allow_legacy_lab=True
        )

        self.assertEqual(session.proof["provider"], "vfio-legacy-type1")
        self.assertEqual(session.proof["iommuType"], "TYPE1")
        session.close()

    def test_legacy_never_selects_noiommu_extension(self):
        observed = state(cdev_node=None, cdev_device_number=None)
        kernel = FakeKernel()
        kernel.supported_iommus = {vfio.VFIO_NOIOMMU_IOMMU}

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(observed), kernel, allow_legacy_lab=True)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.VFIO_TYPE1_UNSUPPORTED)
        checked = [
            call[2] for call in kernel.ioctls if call[1] == vfio.VFIO_CHECK_EXTENSION
        ]
        self.assertEqual(checked, [vfio.VFIO_TYPE1V2_IOMMU, vfio.VFIO_TYPE1_IOMMU])
        self.assertFalse(kernel.open_fds)

    def test_group_must_be_viable(self):
        observed = state(cdev_node=None, cdev_device_number=None)
        kernel = FakeKernel()
        kernel.viable = False

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(observed), kernel, allow_legacy_lab=True)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.VFIO_GROUP_NOT_VIABLE)
        self.assertFalse(kernel.open_fds)

    def test_legacy_api_version_must_match(self):
        observed = state(cdev_node=None, cdev_device_number=None)
        kernel = FakeKernel()
        kernel.api_version = 99

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(observed), kernel, allow_legacy_lab=True)

        self.assertEqual(
            raised.exception.reason_code, vfio.Reason.VFIO_API_VERSION_MISMATCH
        )
        self.assertFalse(kernel.open_fds)

    def test_each_cdev_ioctl_failure_closes_every_open_fd(self):
        expected = {
            vfio.IOMMU_IOAS_ALLOC: vfio.Reason.IOMMUFD_IOAS_ALLOC_FAILED,
            vfio.VFIO_DEVICE_BIND_IOMMUFD: vfio.Reason.VFIO_DEVICE_BIND_IOMMUFD_FAILED,
            vfio.VFIO_DEVICE_ATTACH_IOMMUFD_PT: vfio.Reason.VFIO_DEVICE_ATTACH_IOAS_FAILED,
        }
        for request, reason in expected.items():
            with self.subTest(request=request):
                kernel = FakeKernel()
                kernel.fail_requests.add(request)
                with self.assertRaises(vfio.ProviderError) as raised:
                    acquire(FakeReader(state()), kernel, allow_legacy_lab=True)
                self.assertEqual(raised.exception.reason_code, reason)
                self.assertFalse(kernel.open_fds)
                self.assertNotIn(
                    vfio.VFIO_GROUP_GET_STATUS,
                    [call[1] for call in kernel.ioctls],
                )

    def test_identity_change_after_attach_fails_closed_and_cleans_up(self):
        before = state()
        after = replace(
            before,
            identity=replace(before.identity, device_id=0xFFFF),
        )
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(before, after), kernel)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.DEVICE_IDENTITY_STALE)
        self.assertFalse(kernel.open_fds)

    def test_group_change_after_attach_fails_closed_and_cleans_up(self):
        before = state()
        after = replace(before, iommu_group="8", group_node=Path("/dev/vfio/8"))
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(before, after), kernel)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.IOMMU_GROUP_STALE)
        self.assertFalse(kernel.open_fds)

    def test_owner_change_after_attach_fails_closed(self):
        before = state()
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(before, replace(before, driver="ixgbe")), kernel)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.DEVICE_OWNER_STALE)
        self.assertFalse(kernel.open_fds)

    def test_cdev_change_after_attach_is_a_node_mismatch(self):
        before = state()
        after = replace(
            before,
            cdev_node=Path("/dev/vfio/devices/vfio1"),
            cdev_device_number=(241, 1),
        )
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(before, after), kernel)

        self.assertEqual(raised.exception.reason_code, vfio.Reason.VFIO_NODE_MISMATCH)
        self.assertFalse(kernel.open_fds)

    def test_noiommu_appearing_during_attach_is_rejected(self):
        before = state()
        kernel = FakeKernel()

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(
                FakeReader(before, replace(before, noiommu_node_present=True)),
                kernel,
            )

        self.assertEqual(
            raised.exception.reason_code,
            vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION,
        )
        self.assertFalse(kernel.open_fds)

    def test_cleanup_error_is_stable_but_all_descriptors_are_closed(self):
        observed = state()
        kernel = FakeKernel()
        session = acquire(FakeReader(observed, observed), kernel)
        kernel.fail_requests.add(vfio.VFIO_DEVICE_DETACH_IOMMUFD_PT)

        with self.assertRaises(vfio.ProviderError) as raised:
            session.close()

        self.assertEqual(
            raised.exception.reason_code, vfio.Reason.PROVIDER_CLEANUP_FAILED
        )
        self.assertFalse(kernel.open_fds)
        self.assertEqual(
            session.proof["lifecycle"], "CLOSED_WITH_CLEANUP_ERROR"
        )
        self.assertFalse(session.proof["handlesUsable"])

    def test_invalid_contract_fields_fail_before_reading_sysfs(self):
        reader = FakeReader(state())
        invalid = [
            ({"bdf": "65:00.0"}, vfio.Reason.INVALID_BDF),
            ({"snapshot_epoch": -1}, vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            ({"snapshot_epoch": True}, vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            ({"snapshot_epoch": 1 << 64}, vfio.Reason.INVALID_SNAPSHOT_EPOCH),
            ({"topology_hash": "not-a-hash"}, vfio.Reason.INVALID_TOPOLOGY_HASH),
            ({"topology_hash": None}, vfio.Reason.INVALID_TOPOLOGY_HASH),
            ({"allow_legacy_lab": "false"}, vfio.Reason.INVALID_ARGUMENT),
        ]
        for changes, reason in invalid:
            with self.subTest(changes=changes):
                arguments = {
                    "bdf": BDF,
                    "snapshot_epoch": 17,
                    "topology_hash": TOPOLOGY_HASH,
                    "expected_identity_hash": vfio.compute_identity_hash(
                        BDF, state().identity
                    ),
                    "expected_group_hash": vfio.compute_group_hash(BDF, "7", (BDF,)),
                    "state_reader": reader,
                    "kernel": FakeKernel(),
                }
                arguments.update(changes)
                with self.assertRaises(vfio.ProviderError) as raised:
                    vfio.open_vfio_provider(**arguments)
                self.assertEqual(raised.exception.reason_code, reason)
        self.assertEqual(reader.calls, [])

    def test_non_asm_generic_ioctl_architecture_fails_before_sysfs(self):
        reader = FakeReader(state())
        with mock.patch.object(vfio.platform, "machine", return_value="ppc64le"):
            with self.assertRaises(vfio.ProviderError) as raised:
                acquire(reader, FakeKernel())

        self.assertEqual(raised.exception.reason_code, vfio.Reason.UNSUPPORTED_IOCTL_ABI)
        self.assertEqual(reader.calls, [])

    def test_injected_reader_cannot_redirect_the_vfio_node(self):
        redirected = state(cdev_node=Path("/tmp/vfio0"))

        with self.assertRaises(vfio.ProviderError) as raised:
            acquire(FakeReader(redirected), FakeKernel())

        self.assertEqual(raised.exception.reason_code, vfio.Reason.VFIO_NODE_UNKNOWN)

    def test_posix_kernel_rejects_a_regular_file_as_device_node(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-a-device"
            path.touch()
            with self.assertRaises(vfio.ProviderError) as raised:
                vfio.PosixVfioKernel().open_node(
                    path,
                    failure_reason=vfio.Reason.VFIO_CDEV_OPEN_FAILED,
                    bdf=BDF,
                )
        self.assertEqual(raised.exception.reason_code, vfio.Reason.VFIO_NODE_MISMATCH)

    def test_cli_emits_one_success_json_object_and_closes_session(self):
        fake_session = mock.Mock()
        fake_session.proof = {"provider": "vfio-cdev-iommufd", "bdf": BDF}
        output = io.StringIO()
        with mock.patch.object(vfio, "open_vfio_provider", return_value=fake_session):
            with contextlib.redirect_stdout(output):
                result = vfio.main(
                    [
                        "--bdf",
                        BDF,
                        "--snapshot-epoch",
                        "17",
                        "--topology-hash",
                        TOPOLOGY_HASH,
                        "--expected-identity-hash",
                        "b" * 64,
                        "--expected-group-hash",
                        "c" * 64,
                    ]
                )

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().count("\n"), 1)
        payload = vfio.json.loads(output.getvalue())
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["proof"]["lifecycle"], "ACQUIRED_AND_CLOSED")
        self.assertFalse(payload["proof"]["handlesUsable"])
        fake_session.close.assert_called_once_with()

    def test_cli_emits_one_stable_error_json_object(self):
        output = io.StringIO()
        with mock.patch.object(
            vfio,
            "open_vfio_provider",
            side_effect=vfio.ProviderError(
                vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION, bdf=BDF
            ),
        ):
            with contextlib.redirect_stdout(output):
                result = vfio.main(
                    [
                        "--bdf",
                        BDF,
                        "--snapshot-epoch",
                        "17",
                        "--topology-hash",
                        TOPOLOGY_HASH,
                        "--expected-identity-hash",
                        "b" * 64,
                        "--expected-group-hash",
                        "c" * 64,
                    ]
                )

        payload = vfio.json.loads(output.getvalue())
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertEqual(
            payload["reasonCode"], vfio.Reason.DEVICE_NO_IOMMU_DMA_ISOLATION
        )

    def test_cli_parse_failure_is_also_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = vfio.main([])

        self.assertEqual(result, 2)
        self.assertEqual(vfio.json.loads(output.getvalue())["reasonCode"], "INVALID_ARGUMENT")

    def test_cli_help_cannot_escape_the_single_json_contract(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = vfio.main(["--help"])

        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertEqual(
            vfio.json.loads(output.getvalue())["reasonCode"], "INVALID_ARGUMENT"
        )


if __name__ == "__main__":
    unittest.main()
