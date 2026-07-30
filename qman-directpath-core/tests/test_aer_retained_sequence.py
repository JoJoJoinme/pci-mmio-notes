from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from qman_directpath_core.aer_retained_sequence import (
    AerRetainedAction,
    AerRetainedSequence,
    AerRetainedState,
    FROZEN_OBSERVED_PROFILE_SHA256,
    FROZEN_REQUESTER_ID,
    RETAINED_REFERENCE_CLAIM_BOUNDARY,
    RETAINED_REFERENCE_MODEL_ID,
    simulate_frozen_g101_retained_sequence,
)
from qman_directpath_core.errors import DirectPathVerificationError


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = (
    ROOT
    / "contracts"
    / "vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json"
)
PROFILE_SCHEMA_PATH = (
    ROOT
    / "contracts"
    / "vmware-aer-root-sequence-oracle-profile.schema.json"
)
PROFILE_SHA256 = (
    "cafa083512697f5361d6e8385d2685b676ac896672439c36bd6e21574f531a6e"
)
STATE_FIELDS = (
    "endpointCorrectableStatus",
    "endpointCed",
    "rootErrorStatus",
    "rootSource",
    "endpointCere",
    "controlledBitsMasked",
    "rootCorEnabled",
    "rootPathOpen",
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _contract_states(trace) -> dict[str, list[dict[str, object]]]:
    return {
        checkpoint.name.value: [
            {
                name: getattr(checkpoint.state, name)
                for name in STATE_FIELDS
            }
        ]
        for checkpoint in trace.checkpoints
    }


@pytest.fixture(scope="module")
def frozen_profile() -> dict[str, Any]:
    profile = _load_json(PROFILE_PATH)
    schema = _load_json(PROFILE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(profile)
    return profile


def test_frozen_profile_hash_and_closed_state_fields(
    frozen_profile: dict[str, Any],
) -> None:
    assert FROZEN_OBSERVED_PROFILE_SHA256 == PROFILE_SHA256
    assert hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest() == (
        PROFILE_SHA256
    )
    assert frozen_profile["profileState"] == "FROZEN_OBSERVED_PROFILE"
    assert frozen_profile["gate"] == "g101"
    assert frozen_profile["sourcePolicy"] == (
        "MEANINGFUL_ONLY_WHEN_ROOT_COR_RCV_SET"
    )
    assert tuple(field.name for field in fields(AerRetainedState)) == (
        STATE_FIELDS
    )


@pytest.mark.parametrize("sequence", list(AerRetainedSequence))
def test_o0_and_o4_match_every_frozen_checkpoint_exactly(
    frozen_profile: dict[str, Any],
    sequence: AerRetainedSequence,
) -> None:
    trace = simulate_frozen_g101_retained_sequence(sequence=sequence)
    assert trace.requesterId == FROZEN_REQUESTER_ID
    assert trace.modelId == RETAINED_REFERENCE_MODEL_ID
    assert trace.claimBoundary == RETAINED_REFERENCE_CLAIM_BOUNDARY
    assert trace.comparisonProfileSha256 == FROZEN_OBSERVED_PROFILE_SHA256

    # Owner is external evidence, not a simulator input.  Each independently
    # retained profile branch must match the one pure public-model trace.
    for owner in ("O0", "O4"):
        assert _contract_states(trace) == frozen_profile[
            "expectedStates"
        ][owner][sequence.value]


def test_trace_and_checkpoint_state_are_immutable() -> None:
    trace = simulate_frozen_g101_retained_sequence(
        sequence=AerRetainedSequence.FIRST_MULTIPLE,
    )

    with pytest.raises(FrozenInstanceError):
        trace.requesterId = 0  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        trace.checkpoints[0].state.endpointCed = False  # type: ignore[misc]
    assert isinstance(trace.checkpoints, tuple)


def test_illegal_sequence_fails_closed() -> None:
    with pytest.raises(DirectPathVerificationError) as sequence_error:
        simulate_frozen_g101_retained_sequence(
            sequence="first-multiple",  # type: ignore[arg-type]
        )
    assert sequence_error.value.code == "AER_RETAINED_SEQUENCE_INVALID"


@pytest.mark.parametrize(
    ("requester_id", "expected_code"),
    (
        (0x0100, "AER_RETAINED_REQUESTER_UNSUPPORTED"),
        (0x10000, "AER_RETAINED_REQUESTER_INVALID"),
        (True, "AER_RETAINED_REQUESTER_INVALID"),
    ),
)
def test_illegal_requester_fails_closed(
    requester_id: object,
    expected_code: str,
) -> None:
    with pytest.raises(DirectPathVerificationError) as error:
        simulate_frozen_g101_retained_sequence(
            sequence=AerRetainedSequence.FIRST_MULTIPLE,
            requester_id=requester_id,  # type: ignore[arg-type]
        )
    assert error.value.code == expected_code


def test_ced_and_ces_remain_independent_register_facts() -> None:
    state = AerRetainedState(
        endpointCorrectableStatus=0,
        endpointCed=True,
        rootErrorStatus=1,
        rootSource="REQUESTER_ID",
        endpointCere=True,
        controlledBitsMasked=False,
        rootCorEnabled=True,
        rootPathOpen=True,
    )
    assert state.endpointCed
    assert state.endpointCorrectableStatus == 0


def test_action_history_locks_the_linear_independent_w1c_rebuild() -> None:
    trace = simulate_frozen_g101_retained_sequence(
        sequence=AerRetainedSequence.INDEPENDENT_W1C
    )
    assert trace.actions == (
        AerRetainedAction.INJECT_B0,
        AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1,
        AerRetainedAction.CLEAR_ENDPOINT_CED,
        AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
        AerRetainedAction.INJECT_B0,
        AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
    )
    assert tuple(
        checkpoint.afterActionCount for checkpoint in trace.checkpoints
    ) == (1, 3, 6)
