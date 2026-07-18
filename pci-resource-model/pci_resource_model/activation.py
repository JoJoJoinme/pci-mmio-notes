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
    TRANSIENT_BUSY = "transient-busy"
    PERSISTENT_HOST_USE = "persistent-host-use"
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
    owner_group: str
    owner_group_complete: bool
    quiesce_state: QuiesceState = QuiesceState.IDLE
    live_transition_supported: bool = True
    boot_claim_supported: bool = False
    identity_matches: bool = True
    action_known: bool = True
    leased_by_other: bool = False
    host_reservation: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "bdf", self.bdf.lower())
        if not self.owner_group:
            raise ValueError("owner activation group must be explicit")
        object.__setattr__(self, "owner_group", self.owner_group.lower())


@dataclass(frozen=True)
class ActivationReason:
    code: str
    devices: tuple[str, ...]


@dataclass(frozen=True)
class ActivationPlan:
    desired_owner: DeviceOwner
    disposition: ActivationDisposition
    requested_members: tuple[str, ...]
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


def _select_owner_members(
    inventory: tuple[ActivationMember, ...],
    requested_bdfs: Iterable[str] | None,
) -> tuple[tuple[str, ...], tuple[ActivationMember, ...]]:
    by_bdf = {member.bdf: member for member in inventory}
    if len(by_bdf) != len(inventory):
        raise ValueError("activation inventory contains duplicate BDFs")

    requested = (
        tuple(sorted(by_bdf))
        if requested_bdfs is None
        else tuple(sorted({bdf.lower() for bdf in requested_bdfs}))
    )
    if not requested:
        raise ValueError("activation request must not be empty")
    missing = tuple(bdf for bdf in requested if bdf not in by_bdf)
    if missing:
        raise ValueError(f"requested BDFs are absent from inventory: {missing}")

    requested_groups = {by_bdf[bdf].owner_group for bdf in requested}
    selected = tuple(
        member
        for member in inventory
        if member.bdf in requested or (member.owner_group in requested_groups)
    )
    return requested, selected


def plan_activation(
    members: Iterable[ActivationMember],
    *,
    desired_owner: DeviceOwner,
    request_mode: ActivationRequestMode = ActivationRequestMode.LIVE_ONLY,
    requested_bdfs: Iterable[str] | None = None,
) -> ActivationPlan:
    """Plan host ownership transition without changing device state.

    ``members`` is the complete inventory snapshot for the requested owner
    groups.  ``requested_bdfs`` is the user/API request; members sharing its
    non-null ``owner_group`` are expanded before any preflight check.  Reset,
    isolation, and VM admission leases are separate attach/reuse safety gates.
    """

    inventory = tuple(sorted(members, key=lambda member: member.bdf))
    if not inventory:
        raise ValueError("activation inventory must not be empty")
    if desired_owner == DeviceOwner.UNKNOWN:
        raise ValueError("desired owner must be host or passthrough")
    requested, ordered = _select_owner_members(inventory, requested_bdfs)

    reasons: list[ActivationReason] = []

    incomplete_groups = tuple(
        member for member in ordered if not member.owner_group_complete
    )
    if incomplete_groups:
        reasons.append(_reason("OWNER_ACTIVATION_GROUP_INCOMPLETE", incomplete_groups))

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

    host_reserved = tuple(
        member
        for member in ordered
        if desired_owner == DeviceOwner.PASSTHROUGH and member.host_reservation
    )
    if host_reserved:
        reasons.append(_reason("HOST_DEVICE_RESERVED", host_reserved))

    if reasons:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            requested_members=requested,
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
            requested_members=requested,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=(),
        )

    leased = tuple(member for member in transition if member.leased_by_other)
    if leased:
        reasons.append(_reason("DEPENDENCY_BUSY", leased))

    host_critical = tuple(
        member
        for member in transition
        if member.quiesce_state == QuiesceState.HOST_CRITICAL
    )
    if host_critical:
        reasons.append(_reason("HOST_CRITICAL_DEPENDENCY", host_critical))

    persistent_use = tuple(
        member
        for member in transition
        if member.quiesce_state == QuiesceState.PERSISTENT_HOST_USE
    )
    if persistent_use:
        reasons.append(_reason("PERSISTENT_HOST_USE", persistent_use))

    quiesce_unknown = tuple(
        member for member in transition if member.quiesce_state == QuiesceState.UNKNOWN
    )
    if quiesce_unknown:
        reasons.append(_reason("QUIESCE_STATE_UNKNOWN", quiesce_unknown))

    if reasons:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            requested_members=requested,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=tuple(reasons),
        )

    if request_mode != ActivationRequestMode.DEFER_TO_REBOOT:
        live_blocked = tuple(
            member
            for member in transition
            if not member.live_transition_supported
            or member.quiesce_state == QuiesceState.TRANSIENT_BUSY
        )
        if not live_blocked:
            return ActivationPlan(
                desired_owner=desired_owner,
                disposition=ActivationDisposition.LIVE_APPLY,
                requested_members=requested,
                members=tuple(member.bdf for member in ordered),
                transition_members=tuple(member.bdf for member in transition),
                reasons=(),
            )
    else:
        live_blocked = transition

    if request_mode == ActivationRequestMode.LIVE_ONLY:
        live_reasons: list[ActivationReason] = []
        transient = tuple(
            member
            for member in live_blocked
            if member.quiesce_state == QuiesceState.TRANSIENT_BUSY
        )
        if transient:
            live_reasons.append(_reason("HOST_DRIVER_TRANSIENT_BUSY", transient))
        unsupported = tuple(
            member for member in live_blocked if not member.live_transition_supported
        )
        if unsupported:
            live_reasons.append(_reason("LIVE_TRANSITION_UNSUPPORTED", unsupported))
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            requested_members=requested,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=tuple(live_reasons),
        )

    reboot_blocked = tuple(
        member for member in transition if not member.boot_claim_supported
    )
    if reboot_blocked:
        return ActivationPlan(
            desired_owner=desired_owner,
            disposition=ActivationDisposition.DENIED,
            requested_members=requested,
            members=tuple(member.bdf for member in ordered),
            transition_members=(),
            reasons=(_reason("BOOT_CLAIM_UNSUPPORTED", reboot_blocked),),
        )

    reboot_reasons: list[ActivationReason] = []
    busy = tuple(
        member
        for member in transition
        if member.quiesce_state == QuiesceState.TRANSIENT_BUSY
    )
    if busy:
        reboot_reasons.append(_reason("HOST_DRIVER_TRANSIENT_BUSY", busy))
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
        requested_members=requested,
        members=tuple(member.bdf for member in ordered),
        transition_members=tuple(member.bdf for member in transition),
        reasons=tuple(reboot_reasons),
    )
