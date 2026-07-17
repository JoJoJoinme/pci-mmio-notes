from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class DeviceOwner(str, Enum):
    HOST = "host"
    PASSTHROUGH = "passthrough"
    UNKNOWN = "unknown"


class QuiesceState(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    HOST_CRITICAL = "host-critical"
    UNKNOWN = "unknown"


class ActivationRequestMode(str, Enum):
    LIVE_ONLY = "live-only"
    LIVE_OR_REBOOT = "live-or-reboot"
    DEFER_TO_REBOOT = "defer-to-reboot"


class ActivationDisposition(str, Enum):
    ALREADY_ACTIVE = "already-active"
    LIVE_APPLY = "live-apply"
    REBOOT_REQUIRED = "reboot-required"
    DENIED = "denied"


@dataclass(frozen=True)
class ActivationMember:
    bdf: str
    current_owner: DeviceOwner
    quiesce_state: QuiesceState = QuiesceState.IDLE
    live_transition_supported: bool = True
    boot_claim_supported: bool = True
    identity_matches: bool = True
    action_known: bool = True
    leased_by_other: bool = False


@dataclass(frozen=True)
class ActivationReason:
    code: str
    devices: tuple[str, ...]


@dataclass(frozen=True)
class ActivationPlan:
    desired_owner: DeviceOwner
    disposition: ActivationDisposition
    members: tuple[str, ...]
    transition_members: tuple[str, ...]
    reasons: tuple[ActivationReason, ...]

    @property
    def host_active(self) -> bool:
        return self.disposition == ActivationDisposition.ALREADY_ACTIVE

    @property
    def available_for_start_transaction(self) -> bool:
        return self.disposition in {
            ActivationDisposition.ALREADY_ACTIVE,
            ActivationDisposition.LIVE_APPLY,
        }


def _reason(code: str, members: Iterable[ActivationMember]) -> ActivationReason:
    return ActivationReason(code, tuple(sorted(member.bdf for member in members)))


def plan_activation(
    members: Iterable[ActivationMember],
    *,
    desired_owner: DeviceOwner,
    request_mode: ActivationRequestMode = ActivationRequestMode.LIVE_ONLY,
) -> ActivationPlan:
    """Plan host ownership transition without changing device state.

    The caller must pass the complete owner/reset/isolation dependency bundle.
    Reset capability is deliberately not an input: it is a separate attach and
    reuse safety gate, not proof that a currently busy host driver can detach.
    """

    ordered = tuple(sorted(members, key=lambda member: member.bdf))
    if not ordered:
        raise ValueError("activation bundle must not be empty")
    if desired_owner == DeviceOwner.UNKNOWN:
        raise ValueError("desired owner must be host or passthrough")

    reasons: list[ActivationReason] = []

    identity_bad = tuple(member for member in ordered if not member.identity_matches)
    if identity_bad:
        reasons.append(_reason("ACTIVATION_IDENTITY_MISMATCH", identity_bad))

    action_unknown = tuple(member for member in ordered if not member.action_known)
    if action_unknown:
        reasons.append(_reason("DEPENDENCY_ACTION_UNKNOWN", action_unknown))

    unknown_owner = tuple(
        member for member in ordered if member.current_owner == DeviceOwner.UNKNOWN
    )
    if unknown_owner:
        reasons.append(_reason("CURRENT_OWNER_UNKNOWN", unknown_owner))

    leased = tuple(member for member in ordered if member.leased_by_other)
    if leased:
        reasons.append(_reason("DEPENDENCY_BUSY", leased))

    host_critical = tuple(
        member for member in ordered
        if member.quiesce_state == QuiesceState.HOST_CRITICAL
    )
    if host_critical:
        reasons.append(_reason("HOST_CRITICAL_DEPENDENCY", host_critical))

    quiesce_unknown = tuple(
        member for member in ordered
        if member.quiesce_state == QuiesceState.UNKNOWN
    )
    if quiesce_unknown:
        reasons.append(_reason("QUIESCE_STATE_UNKNOWN", quiesce_unknown))

    if reasons:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=tuple(reasons),
        )

    transition = tuple(
        member for member in ordered if member.current_owner != desired_owner
    )
    if not transition:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.ALREADY_ACTIVE,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=(),
        )

    if request_mode != ActivationRequestMode.DEFER_TO_REBOOT:
        live_blocked = tuple(
            member for member in transition
            if not member.live_transition_supported
            or member.quiesce_state != QuiesceState.IDLE
        )
        if not live_blocked:
            return ActivationPlan(
                desired_owner=desired_owner,
                disposition=ActivationDisposition.LIVE_APPLY,
                members=tuple(member.bdf for member in ordered),
                transition_members=tuple(member.bdf for member in transition),
                reasons=(),
            )
    else:
        live_blocked = transition

    reboot_blocked = tuple(
        member for member in transition if not member.boot_claim_supported
    )
    if reboot_blocked:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=(_reason("BOOT_CLAIM_UNSUPPORTED", reboot_blocked),),
        )

    reboot_reasons: list[ActivationReason] = []
    busy = tuple(
        member for member in transition
        if member.quiesce_state == QuiesceState.BUSY
    )
    if busy:
        reboot_reasons.append(_reason("HOST_DRIVER_BUSY", busy))
    unsupported = tuple(
        member for member in transition if not member.live_transition_supported
    )
    if unsupported:
        reboot_reasons.append(_reason("LIVE_TRANSITION_UNSUPPORTED", unsupported))
    if request_mode == ActivationRequestMode.DEFER_TO_REBOOT:
        reboot_reasons.append(_reason("REQUESTED_DEFERRED_APPLY", transition))

    return ActivationPlan(
        desired_owner=desired_owner,
        disposition=ActivationDisposition.REBOOT_REQUIRED,
        members=tuple(member.bdf for member in ordered),
        transition_members=tuple(member.bdf for member in transition),
        reasons=tuple(reboot_reasons),
    )
