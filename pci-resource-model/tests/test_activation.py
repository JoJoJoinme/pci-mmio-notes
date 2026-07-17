import unittest

from pci_resource_model.activation import (
    ActivationDisposition,
    ActivationMember,
    ActivationRequestMode,
    DeviceOwner,
    QuiesceState,
    plan_activation,
)


def member(bdf: str = "0000:65:00.0", **changes) -> ActivationMember:
    values = {
        "bdf": bdf,
        "current_owner": DeviceOwner.HOST,
    }
    values.update(changes)
    return ActivationMember(**values)


def reason_codes(plan) -> set[str]:
    return {reason.code for reason in plan.reasons}


class ActivationTests(unittest.TestCase):
    def test_empty_bundle_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "bundle must not be empty"):
            plan_activation([], desired_owner=DeviceOwner.PASSTHROUGH)

    def test_unknown_desired_owner_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "desired owner"):
            plan_activation([member()], desired_owner=DeviceOwner.UNKNOWN)

    def test_already_active_is_observed_state_not_reboot_history(self) -> None:
        plan = plan_activation(
            [member(current_owner=DeviceOwner.PASSTHROUGH)],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.ALREADY_ACTIVE)
        self.assertTrue(plan.host_active)
        self.assertTrue(plan.available_for_start_transaction)

    def test_idle_bundle_can_switch_live(self) -> None:
        plan = plan_activation(
            [member(), member("0000:65:00.1")],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.LIVE_APPLY)
        self.assertFalse(plan.host_active)
        self.assertTrue(plan.available_for_start_transaction)
        self.assertEqual(
            plan.transition_members,
            ("0000:65:00.0", "0000:65:00.1"),
        )

    def test_no_apply_now_semantics_force_deferred_transition(self) -> None:
        plan = plan_activation(
            [member()],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.DEFER_TO_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.REBOOT_REQUIRED)
        self.assertIn("REQUESTED_DEFERRED_APPLY", reason_codes(plan))

    def test_busy_driver_changes_same_device_to_reboot_required(self) -> None:
        plan = plan_activation(
            [member(quiesce_state=QuiesceState.BUSY)],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.REBOOT_REQUIRED)
        self.assertIn("HOST_DRIVER_BUSY", reason_codes(plan))
        self.assertFalse(plan.available_for_start_transaction)

    def test_one_busy_dependency_defers_the_whole_bundle(self) -> None:
        plan = plan_activation(
            [member(), member("0000:65:00.1", quiesce_state=QuiesceState.BUSY)],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.REBOOT_REQUIRED)
        self.assertEqual(plan.members, ("0000:65:00.0", "0000:65:00.1"))

    def test_host_critical_dependency_is_denied_not_fixed_by_reboot(self) -> None:
        plan = plan_activation(
            [member(quiesce_state=QuiesceState.HOST_CRITICAL)],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("HOST_CRITICAL_DEPENDENCY", reason_codes(plan))

    def test_unknown_current_owner_is_denied(self) -> None:
        plan = plan_activation(
            [member(current_owner=DeviceOwner.UNKNOWN)],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("CURRENT_OWNER_UNKNOWN", reason_codes(plan))

    def test_unknown_quiesce_state_is_denied(self) -> None:
        plan = plan_activation(
            [member(quiesce_state=QuiesceState.UNKNOWN)],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("QUIESCE_STATE_UNKNOWN", reason_codes(plan))

    def test_unknown_dependency_action_is_denied(self) -> None:
        plan = plan_activation(
            [member(action_known=False)],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("DEPENDENCY_ACTION_UNKNOWN", reason_codes(plan))

    def test_live_unsupported_requires_a_proven_boot_claim(self) -> None:
        plan = plan_activation(
            [member(live_transition_supported=False)],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.REBOOT_REQUIRED)
        self.assertIn("LIVE_TRANSITION_UNSUPPORTED", reason_codes(plan))

    def test_stale_identity_is_denied_before_owner_change(self) -> None:
        plan = plan_activation(
            [member(identity_matches=False)],
            desired_owner=DeviceOwner.PASSTHROUGH,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertEqual(plan.transition_members, ())
        self.assertIn("ACTIVATION_IDENTITY_MISMATCH", reason_codes(plan))

    def test_other_lease_is_not_converted_to_reboot_workaround(self) -> None:
        plan = plan_activation(
            [member(leased_by_other=True)],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("DEPENDENCY_BUSY", reason_codes(plan))

    def test_boot_claim_must_be_proven_before_reboot_is_recommended(self) -> None:
        plan = plan_activation(
            [
                member(
                    quiesce_state=QuiesceState.BUSY,
                    boot_claim_supported=False,
                )
            ],
            desired_owner=DeviceOwner.PASSTHROUGH,
            request_mode=ActivationRequestMode.LIVE_OR_REBOOT,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.DENIED)
        self.assertIn("BOOT_CLAIM_UNSUPPORTED", reason_codes(plan))

    def test_disable_can_live_rebind_to_host_when_idle(self) -> None:
        plan = plan_activation(
            [member(current_owner=DeviceOwner.PASSTHROUGH)],
            desired_owner=DeviceOwner.HOST,
        )

        self.assertEqual(plan.disposition, ActivationDisposition.LIVE_APPLY)
        self.assertEqual(plan.transition_members, ("0000:65:00.0",))


if __name__ == "__main__":
    unittest.main()
