#!/usr/bin/env python3
"""Offline timing regressions for the ESXi Correctable AER gate lease."""

from __future__ import annotations

import copy
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import test_esxi_aer_correctable_matrix as matrix
import test_qemu_aer_correctable_matrix as qemu_aer


CONTROLLED_BITS = (
    matrix.SAFE_CORRECTABLE_BITS["receiver_error"]
    | matrix.SAFE_CORRECTABLE_BITS["bad_tlp"]
)
REQUESTED_GATE = matrix.GateTuple(True, False, True)


def clean_outer_snapshot() -> dict[str, Any]:
    return {
        "endpointState": {
            "deviceControl": qemu_aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": 0,
            "uncorrectableErrorStatus": 0,
            "uncorrectableErrorMask": 0,
            "correctableErrorStatus": 0,
            "correctableErrorMask": 0,
        },
        "rootState": {
            "bridgeControl": qemu_aer.PCI_BRIDGE_CTL_SERR,
            "deviceControl": qemu_aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": 0,
            "uncorrectableErrorStatus": 0,
            "correctableErrorStatus": 0,
            "correctableErrorMask": 0,
            "rootErrorCommand": qemu_aer.PCI_ERR_ROOT_CMD_COR_EN,
            "rootErrorStatus": 0,
            "errorSourceIdentification": 0,
        },
    }


class GateLeaseStopTailTests(unittest.TestCase):
    def assert_no_gate_stop_threads(self) -> None:
        self.assertEqual(
            [],
            [
                thread.name
                for thread in threading.enumerate()
                if thread.name.startswith("esxi-aer-gate-stop")
            ],
        )

    def delayed_second_stop(
        self,
        *,
        delay: float,
        failure: BaseException | None = None,
    ) -> tuple[list[str], Any]:
        transitions: list[str] = []
        lock = threading.Lock()

        def transition(
            _monitor: Path,
            command: str,
            expected: str,
        ) -> dict[str, Any]:
            with lock:
                transitions.append(command)
                stop_count = transitions.count("stop")
            if command == "stop" and stop_count == 2:
                time.sleep(delay)
                if failure is not None:
                    raise failure
            return {"command": command, "state": expected}

        return transitions, transition

    def assert_delayed_stop_was_covered(
        self,
        record: dict[str, Any],
    ) -> None:
        poll = record["timeline"]["resumedSafetyPoll"]
        samples = poll["samples"]
        closure = poll["closure"]
        self.assertGreaterEqual(len(samples), 4)
        self.assertGreater(
            samples[-1]["actualElapsedSeconds"]
            - samples[0]["actualElapsedSeconds"],
            0.05,
        )
        self.assertLessEqual(
            poll["maximumObservedPollGapSeconds"],
            0.05,
        )
        self.assertLessEqual(
            poll["maximumObservedReadDurationSeconds"],
            0.05,
        )
        self.assertEqual([], poll["pollFaults"])
        self.assertEqual([], poll["safetyEvents"])
        self.assertTrue(poll["complete"])
        self.assertEqual("PAUSED_ACK", closure["mode"])
        self.assertTrue(closure["stopConfirmed"])
        self.assertGreaterEqual(
            closure["stopConfirmedElapsedSeconds"],
            closure["lastSampleFinishedElapsedSeconds"],
        )
        self.assertAlmostEqual(
            closure["tailGapSeconds"],
            closure["stopConfirmedElapsedSeconds"]
            - closure["lastSampleFinishedElapsedSeconds"],
            places=9,
        )
        self.assertLessEqual(closure["tailGapSeconds"], 0.05)
        self.assert_no_gate_stop_threads()

    def test_apply_samples_while_delayed_stop_ack_is_in_flight(self) -> None:
        clean = clean_outer_snapshot()
        transitions, transition = self.delayed_second_stop(delay=0.12)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                return_value=clean,
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            lease = matrix.apply_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                REQUESTED_GATE,
                enable_root_path=True,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual("EFFECTIVE", lease["outcome"])
        self.assertTrue(lease["qemuHeldPaused"])
        self.assert_delayed_stop_was_covered(lease)

    def test_restore_samples_while_delayed_stop_ack_is_in_flight(self) -> None:
        clean = clean_outer_snapshot()
        lease = {
            "original": {"snapshot": copy.deepcopy(clean)},
            "rootPathLease": {"managed": False},
        }
        transitions, transition = self.delayed_second_stop(delay=0.12)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                return_value=clean,
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            result = matrix.restore_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                lease,
                safe_stop=False,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual("RESTORED", result["outcome"])
        self.assertTrue(result["qemuHeldPaused"])
        self.assert_delayed_stop_was_covered(result)

    def test_delayed_stop_tail_safety_is_rebuilt_into_original_poll(
        self,
    ) -> None:
        clean = clean_outer_snapshot()
        unsafe = copy.deepcopy(clean)
        unsafe["endpointState"]["uncorrectableErrorStatus"] = 1
        snapshot_count = 0

        def snapshot(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            nonlocal snapshot_count
            snapshot_count += 1
            return unsafe if snapshot_count >= 4 else clean

        transitions, transition = self.delayed_second_stop(delay=0.08)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                side_effect=snapshot,
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            lease = matrix.apply_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                REQUESTED_GATE,
                enable_root_path=True,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual("SAFETY_FAULT_AFTER_APPLY", lease["outcome"])
        poll = lease["timeline"]["resumedSafetyPoll"]
        self.assertGreaterEqual(poll["sampleCount"], 2)
        self.assertTrue(poll["safetyEvents"])
        self.assertTrue(lease["resumedSafetyFaults"])
        self.assertFalse(poll["complete"])
        self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])

    def test_stop_keyboard_interrupt_retains_tail_and_unconfirmed_closure(
        self,
    ) -> None:
        clean = clean_outer_snapshot()
        transitions, transition = self.delayed_second_stop(
            delay=0.08,
            failure=KeyboardInterrupt("fixture stop interrupt"),
        )
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                return_value=clean,
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            with self.assertRaises(matrix.GateLeaseApplyFailure) as captured:
                matrix.apply_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    CONTROLLED_BITS,
                    REQUESTED_GATE,
                    enable_root_path=True,
                    timeline_delays=(0.0,),
                    maximum_safety_poll_interval=0.05,
                    safety_poll_target_interval=0.01,
                    hold_paused_after_sampling=True,
                )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        lease = captured.exception.lease
        poll = lease["timeline"]["resumedSafetyPoll"]
        self.assertGreaterEqual(poll["sampleCount"], 3)
        self.assertEqual("STOP_UNCONFIRMED", poll["closure"]["mode"])
        self.assertFalse(poll["closure"]["stopConfirmed"])
        self.assertFalse(poll["complete"])
        self.assertEqual(
            "KeyboardInterrupt",
            lease["safetyHoldFault"]["type"],
        )
        self.assertEqual(
            "POST_SAMPLING_HOLD_UNCONFIRMED",
            lease["outcome"],
        )
        self.assert_no_gate_stop_threads()

    def test_apply_first_qtest_read_failure_still_sync_stops(self) -> None:
        clean = clean_outer_snapshot()
        transitions, transition = self.delayed_second_stop(delay=0.0)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                side_effect=[
                    copy.deepcopy(clean),
                    copy.deepcopy(clean),
                    TimeoutError("fixture first resumed read timeout"),
                ],
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            lease = matrix.apply_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                REQUESTED_GATE,
                enable_root_path=True,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual(
            "SAFETY_POLL_INCOMPLETE_AFTER_APPLY",
            lease["outcome"],
        )
        self.assertTrue(lease["qemuHeldPaused"])
        poll = lease["timeline"]["resumedSafetyPoll"]
        self.assertEqual(0, poll["sampleCount"])
        self.assertFalse(poll["complete"])
        self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
        self.assertTrue(poll["closure"]["stopConfirmed"])
        self.assertIn(
            "qtest-safety-read",
            {fault.get("phase") for fault in poll["pollFaults"]},
        )
        self.assertIn(
            "safety-poll-tail-precondition",
            {fault.get("phase") for fault in poll["pollFaults"]},
        )
        self.assert_no_gate_stop_threads()

    def test_restore_first_qtest_read_failure_still_sync_stops(self) -> None:
        clean = clean_outer_snapshot()
        lease = {
            "original": {"snapshot": copy.deepcopy(clean)},
            "rootPathLease": {"managed": False},
        }
        transitions, transition = self.delayed_second_stop(delay=0.0)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                side_effect=[
                    copy.deepcopy(clean),
                    copy.deepcopy(clean),
                    TimeoutError("fixture first restore read timeout"),
                ],
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            result = matrix.restore_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                lease,
                safe_stop=False,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual(
            "RESTORE_SAFETY_POLL_INCOMPLETE_HELD_PAUSED",
            result["outcome"],
        )
        self.assertTrue(result["qemuHeldPaused"])
        poll = result["timeline"]["resumedSafetyPoll"]
        self.assertEqual(0, poll["sampleCount"])
        self.assertFalse(poll["complete"])
        self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
        self.assertTrue(poll["closure"]["stopConfirmed"])
        self.assertIn(
            "qtest-safety-read",
            {fault.get("phase") for fault in poll["pollFaults"]},
        )
        self.assertIn(
            "safety-poll-tail-precondition",
            {fault.get("phase") for fault in poll["pollFaults"]},
        )
        self.assert_no_gate_stop_threads()

    def test_apply_executor_bootstrap_failure_sync_stops(self) -> None:
        clean = clean_outer_snapshot()

        for failure_mode in ("constructor", "submit"):
            with self.subTest(failure_mode=failure_mode):
                transitions, transition = self.delayed_second_stop(delay=0.0)

                class SubmitFailureExecutor:
                    def __init__(self) -> None:
                        self.shutdown_calls = 0

                    def submit(self, *_args: Any, **_kwargs: Any) -> Any:
                        raise RuntimeError("fixture submit failure")

                    def shutdown(self, **_kwargs: Any) -> None:
                        self.shutdown_calls += 1

                executor = SubmitFailureExecutor()
                executor_patch = (
                    mock.patch.object(
                        matrix.concurrent.futures,
                        "ThreadPoolExecutor",
                        side_effect=RuntimeError(
                            "fixture constructor failure"
                        ),
                    )
                    if failure_mode == "constructor"
                    else mock.patch.object(
                        matrix.concurrent.futures,
                        "ThreadPoolExecutor",
                        return_value=executor,
                    )
                )
                with (
                    mock.patch.object(
                        matrix,
                        "transition_qemu",
                        side_effect=transition,
                    ),
                    mock.patch.object(
                        matrix,
                        "outer_qemu_aer_snapshot",
                        return_value=clean,
                    ),
                    mock.patch.object(matrix, "write_gate_tuple"),
                    mock.patch.object(matrix.qemu_aer, "QTestClient"),
                    executor_patch,
                ):
                    lease = matrix.apply_gate_lease(
                        Path("monitor.sock"),
                        Path("qtest.sock"),
                        "0000:01:00.1",
                        "0000:00:01.0",
                        CONTROLLED_BITS,
                        REQUESTED_GATE,
                        enable_root_path=True,
                        timeline_delays=(0.0,),
                        maximum_safety_poll_interval=0.05,
                        safety_poll_target_interval=0.01,
                        hold_paused_after_sampling=True,
                    )

                self.assertEqual(["stop", "cont", "stop"], transitions)
                self.assertEqual(
                    "SAFETY_POLL_INCOMPLETE_AFTER_APPLY",
                    lease["outcome"],
                )
                self.assertTrue(lease["qemuHeldPaused"])
                poll = lease["timeline"]["resumedSafetyPoll"]
                self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
                self.assertFalse(poll["complete"])
                self.assertIn(
                    "safety-poll-tail-executor-bootstrap",
                    {fault.get("phase") for fault in poll["pollFaults"]},
                )
                if failure_mode == "submit":
                    self.assertEqual(1, executor.shutdown_calls)
                self.assert_no_gate_stop_threads()

    def test_restore_executor_bootstrap_failure_sync_stops(self) -> None:
        clean = clean_outer_snapshot()

        for failure_mode in ("constructor", "submit"):
            with self.subTest(failure_mode=failure_mode):
                lease = {
                    "original": {"snapshot": copy.deepcopy(clean)},
                    "rootPathLease": {"managed": False},
                }
                transitions, transition = self.delayed_second_stop(delay=0.0)

                class SubmitFailureExecutor:
                    def __init__(self) -> None:
                        self.shutdown_calls = 0

                    def submit(self, *_args: Any, **_kwargs: Any) -> Any:
                        raise RuntimeError("fixture submit failure")

                    def shutdown(self, **_kwargs: Any) -> None:
                        self.shutdown_calls += 1

                executor = SubmitFailureExecutor()
                executor_patch = (
                    mock.patch.object(
                        matrix.concurrent.futures,
                        "ThreadPoolExecutor",
                        side_effect=RuntimeError(
                            "fixture constructor failure"
                        ),
                    )
                    if failure_mode == "constructor"
                    else mock.patch.object(
                        matrix.concurrent.futures,
                        "ThreadPoolExecutor",
                        return_value=executor,
                    )
                )
                with (
                    mock.patch.object(
                        matrix,
                        "transition_qemu",
                        side_effect=transition,
                    ),
                    mock.patch.object(
                        matrix,
                        "outer_qemu_aer_snapshot",
                        return_value=clean,
                    ),
                    mock.patch.object(matrix, "write_gate_tuple"),
                    mock.patch.object(matrix.qemu_aer, "QTestClient"),
                    executor_patch,
                ):
                    result = matrix.restore_gate_lease(
                        Path("monitor.sock"),
                        Path("qtest.sock"),
                        "0000:01:00.1",
                        "0000:00:01.0",
                        CONTROLLED_BITS,
                        lease,
                        safe_stop=False,
                        timeline_delays=(0.0,),
                        maximum_safety_poll_interval=0.05,
                        safety_poll_target_interval=0.01,
                        hold_paused_after_sampling=True,
                    )

                self.assertEqual(["stop", "cont", "stop"], transitions)
                self.assertEqual(
                    "RESTORE_SAFETY_POLL_INCOMPLETE_HELD_PAUSED",
                    result["outcome"],
                )
                self.assertTrue(result["qemuHeldPaused"])
                poll = result["timeline"]["resumedSafetyPoll"]
                self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
                self.assertFalse(poll["complete"])
                self.assertIn(
                    "safety-poll-tail-executor-bootstrap",
                    {fault.get("phase") for fault in poll["pollFaults"]},
                )
                if failure_mode == "submit":
                    self.assertEqual(1, executor.shutdown_calls)
                self.assert_no_gate_stop_threads()

    def test_executor_bootstrap_fault_retains_unsafe_sample(self) -> None:
        clean = clean_outer_snapshot()
        unsafe = copy.deepcopy(clean)
        unsafe["endpointState"]["uncorrectableErrorStatus"] = 1
        transitions, transition = self.delayed_second_stop(delay=0.0)
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                side_effect=[
                    copy.deepcopy(clean),
                    copy.deepcopy(clean),
                    unsafe,
                ],
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
            mock.patch.object(
                matrix.concurrent.futures,
                "ThreadPoolExecutor",
                side_effect=RuntimeError("fixture constructor failure"),
            ),
        ):
            lease = matrix.apply_gate_lease(
                Path("monitor.sock"),
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                CONTROLLED_BITS,
                REQUESTED_GATE,
                enable_root_path=True,
                timeline_delays=(0.0,),
                maximum_safety_poll_interval=0.05,
                safety_poll_target_interval=0.01,
                hold_paused_after_sampling=True,
            )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        self.assertEqual("SAFETY_FAULT_AFTER_APPLY", lease["outcome"])
        self.assertTrue(lease["qemuHeldPaused"])
        poll = lease["timeline"]["resumedSafetyPoll"]
        self.assertTrue(poll["safetyEvents"])
        self.assertTrue(lease["resumedSafetyFaults"])
        self.assertFalse(poll["complete"])
        self.assert_no_gate_stop_threads()

    def test_first_read_failure_and_fallback_stop_interrupt_is_unconfirmed(
        self,
    ) -> None:
        clean = clean_outer_snapshot()
        transitions, transition = self.delayed_second_stop(
            delay=0.0,
            failure=KeyboardInterrupt("fixture fallback stop interrupt"),
        )
        with (
            mock.patch.object(
                matrix,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                matrix,
                "outer_qemu_aer_snapshot",
                side_effect=[
                    copy.deepcopy(clean),
                    copy.deepcopy(clean),
                    TimeoutError("fixture first resumed read timeout"),
                ],
            ),
            mock.patch.object(matrix, "write_gate_tuple"),
            mock.patch.object(matrix.qemu_aer, "QTestClient"),
        ):
            with self.assertRaises(matrix.GateLeaseApplyFailure) as captured:
                matrix.apply_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    CONTROLLED_BITS,
                    REQUESTED_GATE,
                    enable_root_path=True,
                    timeline_delays=(0.0,),
                    maximum_safety_poll_interval=0.05,
                    safety_poll_target_interval=0.01,
                    hold_paused_after_sampling=True,
                )

        self.assertEqual(["stop", "cont", "stop"], transitions)
        lease = captured.exception.lease
        poll = lease["timeline"]["resumedSafetyPoll"]
        self.assertEqual("STOP_UNCONFIRMED", poll["closure"]["mode"])
        self.assertFalse(poll["closure"]["stopConfirmed"])
        self.assertFalse(poll["complete"])
        self.assertEqual(
            "KeyboardInterrupt",
            lease["safetyHoldFault"]["type"],
        )
        self.assertEqual(
            "SAFETY_POLL_INCOMPLETE_AND_HOLD_UNCONFIRMED",
            lease["outcome"],
        )
        self.assertIn(
            "safety-poll-tail-fallback-stop",
            {fault.get("phase") for fault in poll["pollFaults"]},
        )
        self.assert_no_gate_stop_threads()


if __name__ == "__main__":
    unittest.main()
