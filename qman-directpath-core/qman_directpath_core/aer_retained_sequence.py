"""Executable retained-state parity slice for the frozen Correctable AER profile.

This component deliberately covers only the fixed ``g101`` retained-register
contract: Receiver Error (B0), Bad TLP (B1), Requester ID ``0x0101``, and the
four frozen sequences.  It is a Qman component premise, not product/E4
qualification and not a claim about VMware private owner, interrupt, service,
guest-write, lifecycle, or physical-recovery mechanisms.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal

from .aer_policy import (
    AER_POLICY_DIGEST_DOMAIN,
    CORRECTABLE_ERROR_ALLOW_MASK,
    FILTER_BEFORE_VFIO,
    VerifiedAerPolicy,
    verify_aer_policy,
)
from .aer_reference_model import (
    AerReferenceModel,
    CorrectableRouteControl,
    ROOT_CORRECTABLE_RECEIVED,
    ROOT_CORRECTABLE_STATUS_MASK,
)
from .canonical import canonical_json_bytes, sha256_digest
from .errors import fail, require


RECEIVER_ERROR: Final = 0x00000001
BAD_TLP: Final = 0x00000040
CONTROLLED_CORRECTABLE_BITS: Final = RECEIVER_ERROR | BAD_TLP
FROZEN_REQUESTER_ID: Final = 0x0101
FROZEN_ROOT_BRIDGE_SERR_ENABLED: Final = True
FROZEN_OBSERVED_PROFILE_SHA256: Final = (
    "cafa083512697f5361d6e8385d2685b676ac896672439c36bd6e21574f531a6e"
)
RETAINED_REFERENCE_MODEL_ID: Final = (
    "QMAN-AER-G101-RETAINED-REFERENCE-MODEL-V1"
)
RETAINED_REFERENCE_CLAIM_BOUNDARY: Final = "REFERENCE_MODEL_ONLY"

RootSourceSemantic = Literal[
    "REQUESTER_ID",
    "IGNORED_WITHOUT_COR_RCV",
]


class AerRetainedSequence(str, Enum):
    """The four retained-state sequences authorized by the frozen profile."""

    FIRST_MULTIPLE = "first-multiple"
    INDEPENDENT_W1C = "independent-w1c"
    BIT_OR = "bit-or"
    REARM = "rearm"


class AerRetainedAction(str, Enum):
    INJECT_B0 = "inject-b0"
    INJECT_B1 = "inject-b1"
    CLEAR_ENDPOINT_CES_B0_B1 = "clear-endpoint-ces-b0-b1"
    CLEAR_ENDPOINT_CED = "clear-endpoint-ced"
    CLEAR_ROOT_CORRECTABLE_STATUS = "clear-root-correctable-status"


class AerRetainedCheckpointName(str, Enum):
    FIRST_WINDOW_OBSERVATION = "first-window-observation"
    STABLE_AFTER_REPEAT = "stable-after-repeat"
    INITIAL_WINDOW = "initial-window"
    AFTER_ENDPOINT_CLEAR_ONLY = "after-endpoint-clear-only"
    AFTER_ROOT_CLEAR_ONLY = "after-root-clear-only"
    STABLE_AFTER_OR = "stable-after-or"
    REARMED_WINDOW = "rearmed-window"


_EXPECTED_CHECKPOINTS = MappingProxyType(
    {
        AerRetainedSequence.FIRST_MULTIPLE: (
            AerRetainedCheckpointName.FIRST_WINDOW_OBSERVATION,
            AerRetainedCheckpointName.STABLE_AFTER_REPEAT,
        ),
        AerRetainedSequence.INDEPENDENT_W1C: (
            AerRetainedCheckpointName.INITIAL_WINDOW,
            AerRetainedCheckpointName.AFTER_ENDPOINT_CLEAR_ONLY,
            AerRetainedCheckpointName.AFTER_ROOT_CLEAR_ONLY,
        ),
        AerRetainedSequence.BIT_OR: (
            AerRetainedCheckpointName.STABLE_AFTER_OR,
        ),
        AerRetainedSequence.REARM: (
            AerRetainedCheckpointName.INITIAL_WINDOW,
            AerRetainedCheckpointName.REARMED_WINDOW,
        ),
    }
)

_EXPECTED_ACTIONS = MappingProxyType(
    {
        AerRetainedSequence.FIRST_MULTIPLE: (
            AerRetainedAction.INJECT_B0,
            AerRetainedAction.INJECT_B0,
        ),
        AerRetainedSequence.INDEPENDENT_W1C: (
            AerRetainedAction.INJECT_B0,
            AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1,
            AerRetainedAction.CLEAR_ENDPOINT_CED,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
            AerRetainedAction.INJECT_B0,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
        ),
        AerRetainedSequence.BIT_OR: (
            AerRetainedAction.INJECT_B0,
            AerRetainedAction.INJECT_B1,
        ),
        AerRetainedSequence.REARM: (
            AerRetainedAction.INJECT_B0,
            AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1,
            AerRetainedAction.CLEAR_ENDPOINT_CED,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
            AerRetainedAction.INJECT_B0,
        ),
    }
)

_EXPECTED_CHECKPOINT_ACTION_COUNTS = MappingProxyType(
    {
        AerRetainedSequence.FIRST_MULTIPLE: (1, 2),
        AerRetainedSequence.INDEPENDENT_W1C: (1, 3, 6),
        AerRetainedSequence.BIT_OR: (2,),
        AerRetainedSequence.REARM: (1, 5),
    }
)


def _uint16(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFF
    ):
        fail(
            "AER_RETAINED_REQUESTER_INVALID",
            path,
            "expected a 16-bit Requester ID",
        )
    return value


def _fixed_requester(value: object, path: str) -> int:
    requester_id = _uint16(value, path)
    require(
        requester_id == FROZEN_REQUESTER_ID,
        "AER_RETAINED_REQUESTER_UNSUPPORTED",
        path,
        "the frozen retained-state slice is bound to Requester ID 0x0101",
    )
    return requester_id


@dataclass(frozen=True, slots=True)
class AerRetainedState:
    """One closed register checkpoint using the frozen profile field names."""

    endpointCorrectableStatus: int
    endpointCed: bool
    rootErrorStatus: int
    rootSource: RootSourceSemantic
    endpointCere: bool
    controlledBitsMasked: bool
    rootCorEnabled: bool
    rootPathOpen: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.endpointCorrectableStatus, int)
            or isinstance(self.endpointCorrectableStatus, bool)
            or self.endpointCorrectableStatus
            & ~CONTROLLED_CORRECTABLE_BITS
        ):
            fail(
                "AER_RETAINED_STATE_INVALID",
                "state.endpointCorrectableStatus",
                "expected a B0/B1-only Correctable status value",
            )
        if (
            not isinstance(self.rootErrorStatus, int)
            or isinstance(self.rootErrorStatus, bool)
            or self.rootErrorStatus not in (0, 1, 3)
        ):
            fail(
                "AER_RETAINED_STATE_INVALID",
                "state.rootErrorStatus",
                "expected one frozen Root Correctable status value",
            )
        for name in (
            "endpointCed",
            "endpointCere",
            "controlledBitsMasked",
            "rootCorEnabled",
            "rootPathOpen",
        ):
            if not isinstance(getattr(self, name), bool):
                fail(
                    "AER_RETAINED_STATE_INVALID",
                    f"state.{name}",
                    "expected bool",
                )
        has_cor_rcv = bool(
            self.rootErrorStatus & ROOT_CORRECTABLE_RECEIVED
        )
        expected_source: RootSourceSemantic = (
            "REQUESTER_ID"
            if has_cor_rcv
            else "IGNORED_WITHOUT_COR_RCV"
        )
        require(
            self.rootSource == expected_source,
            "AER_RETAINED_SOURCE_INVALID",
            "state.rootSource",
            "Root Source is meaningful only while COR_RCV is set",
        )
        require(
            self.endpointCere
            and not self.controlledBitsMasked
            and self.rootCorEnabled,
            "AER_RETAINED_GATE_INVALID",
            "state",
            "the retained-state parity slice is fixed to gate g101",
        )
        require(
            self.rootPathOpen,
            "AER_RETAINED_ROOT_PATH_INVALID",
            "state.rootPathOpen",
            "the frozen comparison envelope requires Root BridgeControl.SERR "
            "and Root DeviceControl.CERE",
        )


@dataclass(frozen=True, slots=True)
class AerRetainedCheckpoint:
    name: AerRetainedCheckpointName
    afterActionCount: int
    state: AerRetainedState

    def __post_init__(self) -> None:
        if not isinstance(self.name, AerRetainedCheckpointName):
            fail(
                "AER_RETAINED_CHECKPOINT_INVALID",
                "checkpoint.name",
                "expected a closed checkpoint name",
            )
        if (
            not isinstance(self.afterActionCount, int)
            or isinstance(self.afterActionCount, bool)
            or self.afterActionCount <= 0
        ):
            fail(
                "AER_RETAINED_CHECKPOINT_INVALID",
                "checkpoint.afterActionCount",
                "expected a positive action count",
            )
        if not isinstance(self.state, AerRetainedState):
            fail(
                "AER_RETAINED_CHECKPOINT_INVALID",
                "checkpoint.state",
                "expected AerRetainedState",
            )


@dataclass(frozen=True, slots=True)
class AerRetainedTrace:
    """Immutable pure-model trace, not a verified owner or product receipt."""

    modelId: str
    claimBoundary: str
    comparisonProfileSha256: str
    sequence: AerRetainedSequence
    requesterId: int
    actions: tuple[AerRetainedAction, ...]
    checkpoints: tuple[AerRetainedCheckpoint, ...]

    def __post_init__(self) -> None:
        require(
            self.modelId == RETAINED_REFERENCE_MODEL_ID,
            "AER_RETAINED_TRACE_INVALID",
            "trace.modelId",
            "unexpected retained reference model identity",
        )
        require(
            self.claimBoundary == RETAINED_REFERENCE_CLAIM_BOUNDARY,
            "AER_RETAINED_TRACE_INVALID",
            "trace.claimBoundary",
            "the pure simulator cannot claim product authority",
        )
        require(
            self.comparisonProfileSha256
            == FROZEN_OBSERVED_PROFILE_SHA256,
            "AER_RETAINED_TRACE_INVALID",
            "trace.comparisonProfileSha256",
            "unexpected frozen comparison profile identity",
        )
        if not isinstance(self.sequence, AerRetainedSequence):
            fail(
                "AER_RETAINED_SEQUENCE_INVALID",
                "trace.sequence",
                "expected a closed retained-state sequence",
            )
        _fixed_requester(self.requesterId, "trace.requesterId")
        if (
            not isinstance(self.actions, tuple)
            or not all(
                isinstance(action, AerRetainedAction)
                for action in self.actions
            )
        ):
            fail(
                "AER_RETAINED_TRACE_INVALID",
                "trace.actions",
                "actions must be an immutable tuple of closed actions",
            )
        require(
            self.actions == _EXPECTED_ACTIONS[self.sequence],
            "AER_RETAINED_TRACE_INVALID",
            "trace.actions",
            "action history does not match the closed sequence",
        )
        if not isinstance(self.checkpoints, tuple):
            fail(
                "AER_RETAINED_TRACE_INVALID",
                "trace.checkpoints",
                "checkpoints must be an immutable tuple",
            )
        if not all(
            isinstance(checkpoint, AerRetainedCheckpoint)
            for checkpoint in self.checkpoints
        ):
            fail(
                "AER_RETAINED_TRACE_INVALID",
                "trace.checkpoints",
                "expected only AerRetainedCheckpoint values",
            )
        actual_names = tuple(
            checkpoint.name for checkpoint in self.checkpoints
        )
        require(
            actual_names == _EXPECTED_CHECKPOINTS[self.sequence],
            "AER_RETAINED_TRACE_INVALID",
            "trace.checkpoints",
            "checkpoint names do not match the closed sequence",
        )
        require(
            tuple(
                checkpoint.afterActionCount
                for checkpoint in self.checkpoints
            )
            == _EXPECTED_CHECKPOINT_ACTION_COUNTS[self.sequence],
            "AER_RETAINED_TRACE_INVALID",
            "trace.checkpoints",
            "checkpoint action positions do not match the closed sequence",
        )


def _state(model: AerReferenceModel) -> AerRetainedState:
    physical = model.physical
    semantic_source: RootSourceSemantic
    if physical.root_source_semantic is None:
        semantic_source = "IGNORED_WITHOUT_COR_RCV"
    else:
        require(
            physical.root_source_semantic == model.endpoint_requester_id,
            "AER_RETAINED_SOURCE_MISMATCH",
            "physical.root_correctable_source_raw",
            "retained Root Source does not identify this Endpoint",
        )
        semantic_source = "REQUESTER_ID"
    controlled_bits_masked = bool(
        model.route.correctable_error_mask
        & CONTROLLED_CORRECTABLE_BITS
    )
    # rootPathOpen is not the R bit in g101 and is unrelated to the Root
    # Correctable Mask.  The frozen runner derives it from Root
    # BridgeControl.SERR and Root DeviceControl.CERE.
    root_path_open = (
        FROZEN_ROOT_BRIDGE_SERR_ENABLED
        and model.route.root_port_reporting_enabled
    )
    return AerRetainedState(
        endpointCorrectableStatus=(
            physical.endpoint_correctable_status
        ),
        endpointCed=physical.endpoint_correctable_detected,
        rootErrorStatus=physical.root_correctable_status,
        rootSource=semantic_source,
        endpointCere=model.route.endpoint_reporting_enabled,
        controlledBitsMasked=controlled_bits_masked,
        rootCorEnabled=(
            model.route.root_correctable_notification_enabled
        ),
        rootPathOpen=root_path_open,
    )


def _checkpoint(
    name: AerRetainedCheckpointName,
    model: AerReferenceModel,
    *,
    action_count: int,
) -> AerRetainedCheckpoint:
    require(
        model.transition_count == action_count,
        "AER_RETAINED_ACTION_HISTORY_INVALID",
        "checkpoint.afterActionCount",
        "recorded actions and model transitions have diverged",
    )
    return AerRetainedCheckpoint(
        name=name,
        afterActionCount=action_count,
        state=_state(model),
    )


def _reference_model_policy() -> VerifiedAerPolicy:
    """Build fixed visible-field scaffolding for the pure physical model.

    Host-side reference transitions below are not guest-write authorization.
    Product guest writes must continue through the verified filter-before-VFIO
    plan in ``aer_policy``.
    """

    field_specs = {
        "PCIE_DEVICE_CONTROL": ("PHYSICAL", 0x1, "DENY", 0),
        "PCIE_DEVICE_STATUS": (
            "PHYSICAL",
            0x1,
            "FILTERED_W1C",
            0x1,
        ),
        "CORRECTABLE_ERROR_STATUS": (
            "PHYSICAL",
            CORRECTABLE_ERROR_ALLOW_MASK,
            "FILTERED_W1C",
            CORRECTABLE_ERROR_ALLOW_MASK,
        ),
        "CORRECTABLE_ERROR_MASK": (
            "PHYSICAL",
            CORRECTABLE_ERROR_ALLOW_MASK,
            "DENY",
            0,
        ),
        "ROOT_ERROR_COMMAND": ("PHYSICAL", 0x1, "DENY", 0),
        "ROOT_ERROR_STATUS": (
            "PHYSICAL",
            ROOT_CORRECTABLE_STATUS_MASK,
            "FILTERED_W1C",
            ROOT_CORRECTABLE_STATUS_MASK,
        ),
        "ERROR_SOURCE_ID": ("PHYSICAL", 0xFFFF, "DENY", 0),
    }
    document = {
        "subjectType": "QMAN_AER_POLICY",
        "schemaVersion": 1,
        "policyId": "g101-retained-reference-model",
        "correctableOnly": True,
        "extendedCapability": {
            "headerExposure": "VISIBLE",
            "bodyExposure": "VISIBLE",
            "hiddenBodyReadProjection": "ZERO",
        },
        "writePipeline": FILTER_BEFORE_VFIO,
        "unknownFieldAction": "DENY",
        "fields": {
            name: {
                "readProjection": read,
                "guestReadAllowMask": read_mask,
                "writeDisposition": disposition,
                "physicalW1cAllowMask": physical_mask,
                "shadowW1cMask": 0,
            }
            for name, (
                read,
                read_mask,
                disposition,
                physical_mask,
            ) in field_specs.items()
        },
        "aerPolicyDigest": None,
    }
    document["aerPolicyDigest"] = sha256_digest(
        AER_POLICY_DIGEST_DOMAIN + canonical_json_bytes(document)
    )
    return verify_aer_policy(document)


def simulate_frozen_g101_retained_sequence(
    *,
    sequence: AerRetainedSequence,
    requester_id: int = FROZEN_REQUESTER_ID,
) -> AerRetainedTrace:
    """Simulate one fixed-g101 retained-state sequence.

    Owner is deliberately not an input.  The conformance test independently
    compares this pure public-model trace with both externally observed O0 and
    O4 profile branches.  Matching both branches does not validate an owner
    envelope or prove VMware owner-independent internals.

    This function simulates host-side reference transitions.  It does not
    authorize or execute a guest config-space write and does not replace the
    verified filter-before-VFIO write pipeline.
    """

    if not isinstance(sequence, AerRetainedSequence):
        fail(
            "AER_RETAINED_SEQUENCE_INVALID",
            "sequence",
            "expected a closed retained-state sequence",
        )
    endpoint_requester = _fixed_requester(
        requester_id,
        "requester_id",
    )
    reference_policy = _reference_model_policy()

    route = CorrectableRouteControl(
        endpoint_reporting_enabled=True,
        correctable_error_mask=0,
        root_correctable_notification_enabled=True,
        root_port_reporting_enabled=True,
        root_port_correctable_error_mask=0,
    )

    def initial_model() -> AerReferenceModel:
        return AerReferenceModel.initial(
            policy=reference_policy,
            route=route,
            endpoint_requester_id=endpoint_requester,
        )

    recorded_actions: list[AerRetainedAction] = []

    def apply_action(
        model: AerReferenceModel,
        action: AerRetainedAction,
    ) -> AerReferenceModel:
        if action is AerRetainedAction.INJECT_B0:
            next_model = model.inject_correctable(
                RECEIVER_ERROR,
                requester_id=endpoint_requester,
            )
        elif action is AerRetainedAction.INJECT_B1:
            next_model = model.inject_correctable(
                BAD_TLP,
                requester_id=endpoint_requester,
            )
        elif action is AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1:
            next_model = model.endpoint_status_w1c(
                CONTROLLED_CORRECTABLE_BITS
            )
        elif action is AerRetainedAction.CLEAR_ENDPOINT_CED:
            next_model = model.endpoint_device_status_w1c()
        elif action is AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS:
            next_model = model.root_status_w1c(
                ROOT_CORRECTABLE_STATUS_MASK
            )
        else:  # pragma: no cover - callers use the closed action enum.
            fail(
                "AER_RETAINED_ACTION_INVALID",
                "action",
                "unsupported retained-state action",
            )
        recorded_actions.append(action)
        require(
            next_model.transition_count == len(recorded_actions),
            "AER_RETAINED_ACTION_HISTORY_INVALID",
            "actions",
            "recorded actions and model transitions have diverged",
        )
        return next_model

    checkpoints: tuple[AerRetainedCheckpoint, ...]
    if sequence is AerRetainedSequence.FIRST_MULTIPLE:
        after_first = apply_action(
            initial_model(),
            AerRetainedAction.INJECT_B0,
        )
        first_checkpoint = _checkpoint(
            AerRetainedCheckpointName.FIRST_WINDOW_OBSERVATION,
            after_first,
            action_count=len(recorded_actions),
        )
        after_repeat = apply_action(
            after_first,
            AerRetainedAction.INJECT_B0,
        )
        repeat_checkpoint = _checkpoint(
            AerRetainedCheckpointName.STABLE_AFTER_REPEAT,
            after_repeat,
            action_count=len(recorded_actions),
        )
        checkpoints = (
            first_checkpoint,
            repeat_checkpoint,
        )
    elif sequence is AerRetainedSequence.INDEPENDENT_W1C:
        initial = apply_action(
            initial_model(),
            AerRetainedAction.INJECT_B0,
        )
        initial_checkpoint = _checkpoint(
            AerRetainedCheckpointName.INITIAL_WINDOW,
            initial,
            action_count=len(recorded_actions),
        )
        endpoint_ces_cleared = apply_action(
            initial,
            AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1,
        )
        endpoint_only = apply_action(
            endpoint_ces_cleared,
            AerRetainedAction.CLEAR_ENDPOINT_CED,
        )
        endpoint_only_checkpoint = _checkpoint(
            AerRetainedCheckpointName.AFTER_ENDPOINT_CLEAR_ONLY,
            endpoint_only,
            action_count=len(recorded_actions),
        )
        root_cleanup = apply_action(
            endpoint_only,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
        )
        require(
            root_cleanup.physical.clean,
            "AER_RETAINED_CLEANUP_INCOMPLETE",
            "independent-w1c.root-cleanup",
            "the endpoint-cleared state must be clean before rebuilding B0",
        )
        rebuilt = apply_action(
            root_cleanup,
            AerRetainedAction.INJECT_B0,
        )
        root_only = apply_action(
            rebuilt,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
        )
        root_only_checkpoint = _checkpoint(
            AerRetainedCheckpointName.AFTER_ROOT_CLEAR_ONLY,
            root_only,
            action_count=len(recorded_actions),
        )
        checkpoints = (
            initial_checkpoint,
            endpoint_only_checkpoint,
            root_only_checkpoint,
        )
    elif sequence is AerRetainedSequence.BIT_OR:
        after_b0 = apply_action(
            initial_model(),
            AerRetainedAction.INJECT_B0,
        )
        after_or = apply_action(
            after_b0,
            AerRetainedAction.INJECT_B1,
        )
        checkpoints = (
            _checkpoint(
                AerRetainedCheckpointName.STABLE_AFTER_OR,
                after_or,
                action_count=len(recorded_actions),
            ),
        )
    elif sequence is AerRetainedSequence.REARM:
        initial = apply_action(
            initial_model(),
            AerRetainedAction.INJECT_B0,
        )
        initial_checkpoint = _checkpoint(
            AerRetainedCheckpointName.INITIAL_WINDOW,
            initial,
            action_count=len(recorded_actions),
        )
        endpoint_ces_cleared = apply_action(
            initial,
            AerRetainedAction.CLEAR_ENDPOINT_CES_B0_B1,
        )
        endpoint_ced_cleared = apply_action(
            endpoint_ces_cleared,
            AerRetainedAction.CLEAR_ENDPOINT_CED,
        )
        cleaned = apply_action(
            endpoint_ced_cleared,
            AerRetainedAction.CLEAR_ROOT_CORRECTABLE_STATUS,
        )
        require(
            cleaned.physical.clean,
            "AER_RETAINED_CLEANUP_INCOMPLETE",
            "rearm.cleanup",
            "Endpoint CES/CED and Root status must be clean before re-arm",
        )
        rearmed = apply_action(
            cleaned,
            AerRetainedAction.INJECT_B0,
        )
        rearmed_checkpoint = _checkpoint(
            AerRetainedCheckpointName.REARMED_WINDOW,
            rearmed,
            action_count=len(recorded_actions),
        )
        checkpoints = (
            initial_checkpoint,
            rearmed_checkpoint,
        )
    else:  # pragma: no cover - the enum/type guard above closes this branch.
        fail(
            "AER_RETAINED_SEQUENCE_INVALID",
            "sequence",
            "unsupported retained-state sequence",
        )

    return AerRetainedTrace(
        modelId=RETAINED_REFERENCE_MODEL_ID,
        claimBoundary=RETAINED_REFERENCE_CLAIM_BOUNDARY,
        comparisonProfileSha256=FROZEN_OBSERVED_PROFILE_SHA256,
        sequence=sequence,
        requesterId=endpoint_requester,
        actions=tuple(recorded_actions),
        checkpoints=checkpoints,
    )


__all__ = [
    "AerRetainedAction",
    "AerRetainedCheckpoint",
    "AerRetainedCheckpointName",
    "AerRetainedSequence",
    "AerRetainedState",
    "AerRetainedTrace",
    "BAD_TLP",
    "CONTROLLED_CORRECTABLE_BITS",
    "FROZEN_OBSERVED_PROFILE_SHA256",
    "FROZEN_REQUESTER_ID",
    "FROZEN_ROOT_BRIDGE_SERR_ENABLED",
    "RECEIVER_ERROR",
    "RETAINED_REFERENCE_CLAIM_BOUNDARY",
    "RETAINED_REFERENCE_MODEL_ID",
    "simulate_frozen_g101_retained_sequence",
]
