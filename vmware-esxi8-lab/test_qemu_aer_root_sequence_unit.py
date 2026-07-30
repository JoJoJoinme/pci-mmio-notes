#!/usr/bin/env python3
"""Unit tests for the QEMU Correctable AER root-sequence oracle."""

from __future__ import annotations

import copy
import unittest
from typing import Any

import test_qemu_aer_correctable_matrix as aer
import test_qemu_aer_root_sequence as sequence


REQUESTER_ID = 0x0100


def state(
    *,
    ces: int = 0,
    ced: bool = False,
    root_status: int = 0,
    source: int = 0,
    root_command: bool = True,
) -> dict[str, dict[str, int]]:
    return {
        "endpoint": {
            "deviceControl": aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": aer.PCI_EXP_DEVSTA_CED if ced else 0,
            "uncorrectableErrorStatus": 0,
            "correctableErrorStatus": ces,
            "correctableErrorMask": 0,
        },
        "rootPort": {
            "bridgeControl": aer.PCI_BRIDGE_CTL_SERR,
            "deviceControl": aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": 0,
            "uncorrectableErrorStatus": 0,
            "correctableErrorStatus": 0,
            "rootErrorCommand": (
                aer.PCI_ERR_ROOT_CMD_COR_EN if root_command else 0
            ),
            "rootErrorStatus": root_status,
            "errorSourceIdentification": source,
        },
    }


def matched_fixture(
    name: str,
    *,
    root_command: bool = True,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    clean = state(root_command=root_command)
    first = state(
        ces=sequence.B0,
        ced=True,
        root_status=sequence.ROOT_COR_FIRST,
        source=REQUESTER_ID,
        root_command=root_command,
    )
    multiple_b0 = state(
        ces=sequence.B0,
        ced=True,
        root_status=sequence.ROOT_COR_MULTIPLE,
        source=REQUESTER_ID,
        root_command=root_command,
    )
    snapshots: dict[str, dict[str, Any]] = {
        "effective-controls": copy.deepcopy(clean),
        "pre-injection": copy.deepcopy(clean),
    }
    if name == "first-multiple":
        snapshots.update(
            {
                "first-b0": first,
                "repeated-b0": multiple_b0,
                "stable-after-repeat": copy.deepcopy(multiple_b0),
                "post-cleanup": copy.deepcopy(clean),
            }
        )
    elif name == "independent-w1c":
        endpoint_cleared_root_live = state(
            root_status=sequence.ROOT_COR_FIRST,
            source=REQUESTER_ID,
            root_command=root_command,
        )
        root_cleared_endpoint_live = state(
            ces=sequence.B0,
            ced=True,
            source=REQUESTER_ID,
            root_command=root_command,
        )
        clean_source_persists = state(
            source=REQUESTER_ID,
            root_command=root_command,
        )
        snapshots.update(
            {
                "initial-b0": first,
                "initial-window": copy.deepcopy(first),
                "after-endpoint-clear-only": endpoint_cleared_root_live,
                "after-root-cleanup-for-rebuild": clean_source_persists,
                "rebuilt-b0": copy.deepcopy(first),
                "after-root-clear-only": root_cleared_endpoint_live,
                "post-cleanup": clean_source_persists,
            }
        )
    elif name == "bit-or":
        both = state(
            ces=sequence.B0 | sequence.B1,
            ced=True,
            root_status=sequence.ROOT_COR_MULTIPLE,
            source=REQUESTER_ID,
            root_command=root_command,
        )
        snapshots.update(
            {
                "first-b0": first,
                "second-b1": both,
                "stable-after-or": copy.deepcopy(both),
                "post-cleanup": state(
                    source=REQUESTER_ID,
                    root_command=root_command,
                ),
            }
        )
    elif name == "rearm":
        root_live_ces_clear = state(
            ced=True,
            root_status=sequence.ROOT_COR_FIRST,
            source=REQUESTER_ID,
            root_command=root_command,
        )
        root_live_endpoint_clear = state(
            root_status=sequence.ROOT_COR_FIRST,
            source=REQUESTER_ID,
            root_command=root_command,
        )
        clean_source_persists = state(
            source=REQUESTER_ID,
            root_command=root_command,
        )
        snapshots.update(
            {
                "initial-b0": first,
                "initial-window": copy.deepcopy(first),
                "after-ces-clear-only": root_live_ces_clear,
                "after-ced-clear-only": root_live_endpoint_clear,
                "after-root-clear": clean_source_persists,
                "rearmed-b0": copy.deepcopy(first),
                "rearmed-window": copy.deepcopy(first),
                "post-cleanup": clean_source_persists,
            }
        )
    else:
        raise ValueError(name)
    injections = [
        {"label": label, "accepted": True}
        for label in sequence.expected_injection_labels(name)
    ]
    return snapshots, injections


class SequenceOracleTests(unittest.TestCase):
    def test_all_sequences_match_g101(self) -> None:
        for name in sequence.SEQUENCES:
            with self.subTest(sequence=name):
                snapshots, injections = matched_fixture(name)
                result = sequence.evaluate_sequence(
                    sequence=name,
                    gate=aer.GATES["g101"],
                    endpoint_requester_id=REQUESTER_ID,
                    snapshots=snapshots,
                    injections=injections,
                )
                self.assertEqual(sequence.OBSERVATION_MATCH,
                                 result["observationState"])
                self.assertEqual("PASS", result["verdict"])
                self.assertFalse(result["failedChecks"])

    def test_g100_deposition_matches_with_root_command_disabled(self) -> None:
        snapshots, injections = matched_fixture(
            "first-multiple",
            root_command=False,
        )
        result = sequence.evaluate_sequence(
            sequence="first-multiple",
            gate=aer.GATES["g100"],
            endpoint_requester_id=REQUESTER_ID,
            snapshots=snapshots,
            injections=injections,
        )
        self.assertEqual(sequence.OBSERVATION_MATCH,
                         result["observationState"])

    def test_missing_snapshot_is_inconclusive(self) -> None:
        snapshots, injections = matched_fixture("bit-or")
        del snapshots["stable-after-or"]
        result = sequence.evaluate_sequence(
            sequence="bit-or",
            gate=aer.GATES["g101"],
            endpoint_requester_id=REQUESTER_ID,
            snapshots=snapshots,
            injections=injections,
        )
        self.assertEqual(sequence.OBSERVATION_INCONCLUSIVE,
                         result["observationState"])
        self.assertIn("stable-after-or", result["missingSnapshots"])

    def test_missing_multiple_bit_is_diverged(self) -> None:
        snapshots, injections = matched_fixture("first-multiple")
        snapshots["repeated-b0"]["rootPort"]["rootErrorStatus"] = (
            sequence.ROOT_COR_FIRST
        )
        result = sequence.evaluate_sequence(
            sequence="first-multiple",
            gate=aer.GATES["g101"],
            endpoint_requester_id=REQUESTER_ID,
            snapshots=snapshots,
            injections=injections,
        )
        self.assertEqual(sequence.OBSERVATION_DIVERGED,
                         result["observationState"])
        self.assertIn(
            "repeated-b0:root-correctable-exact",
            result["failedChecks"],
        )

    def test_uncorrectable_side_effect_is_diverged(self) -> None:
        snapshots, injections = matched_fixture("rearm")
        snapshots["rearmed-b0"]["endpoint"][
            "uncorrectableErrorStatus"
        ] = 1
        result = sequence.evaluate_sequence(
            sequence="rearm",
            gate=aer.GATES["g101"],
            endpoint_requester_id=REQUESTER_ID,
            snapshots=snapshots,
            injections=injections,
        )
        self.assertEqual(sequence.OBSERVATION_DIVERGED,
                         result["observationState"])
        self.assertIn(
            "rearmed-b0:endpoint-ues-zero",
            result["failedChecks"],
        )

    def test_root_source_may_persist_after_root_w1c(self) -> None:
        snapshots, injections = matched_fixture("independent-w1c")
        self.assertEqual(
            REQUESTER_ID,
            snapshots["after-root-clear-only"]["rootPort"][
                "errorSourceIdentification"
            ],
        )
        result = sequence.evaluate_sequence(
            sequence="independent-w1c",
            gate=aer.GATES["g101"],
            endpoint_requester_id=REQUESTER_ID,
            snapshots=snapshots,
            injections=injections,
        )
        self.assertEqual(sequence.OBSERVATION_MATCH,
                         result["observationState"])


if __name__ == "__main__":
    unittest.main()
