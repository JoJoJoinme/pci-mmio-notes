"""Executable Correctable-only PCIe AER reference transitions.

The model separates four state machines:

* guest configuration virtualization;
* physical Endpoint/Root retained register state;
* notification/service observations;
* lifecycle cleanup, reuse and quarantine.

It is a deterministic component reference, not a VFIO backend, interrupt
controller, ESXi implementation reconstruction, physical error generator or
physical recovery claim.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from .aer_policy import (
    AerFunctionRole,
    AerField,
    CORRECTABLE_ERROR_ALLOW_MASK,
    RootSourceReadProjection,
    VerifiedAerConfigLayout,
    VerifiedExecutableAerWritePlan,
    VerifiedAerPolicy,
    consume_executable_aer_write,
    plan_guest_config_write,
    project_guest_aer_snapshot,
    project_guest_read,
    project_guest_root_source_read,
    require_pre_vfio_plan,
)
from .errors import fail, require


ROOT_CORRECTABLE_RECEIVED = 0x00000001
ROOT_MULTIPLE_CORRECTABLE_RECEIVED = 0x00000002
ROOT_CORRECTABLE_STATUS_MASK = (
    ROOT_CORRECTABLE_RECEIVED | ROOT_MULTIPLE_CORRECTABLE_RECEIVED
)
DEVICE_STATUS_CORRECTABLE_DETECTED = 0x00000001


def _uint32(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        fail("AER_VALUE_INVALID", path, "expected an unsigned 32-bit integer")
    return value


def _requester_id(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFF
    ):
        fail("AER_REQUESTER_ID_INVALID", path, "expected a 16-bit Requester ID")
    return value


class Observation(str, Enum):
    UNKNOWN = "UNKNOWN"
    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    CONFLICT = "CONFLICT"


class LifecyclePhase(str, Enum):
    CLEAN = "CLEAN"
    DIRTY = "DIRTY"
    CLEANUP_VERIFIED = "CLEANUP_VERIFIED"
    REUSABLE = "REUSABLE"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True, slots=True)
class CorrectableRouteControl:
    """E/M route controls plus independent Root notification enable R."""

    endpoint_reporting_enabled: bool
    correctable_error_mask: int
    root_correctable_notification_enabled: bool
    root_port_reporting_enabled: bool = True
    root_port_correctable_error_mask: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint_reporting_enabled, bool):
            fail(
                "AER_ROUTE_CONTROL_INVALID",
                "route.endpoint_reporting_enabled",
                "expected bool",
            )
        mask = _uint32(
            self.correctable_error_mask,
            "route.correctable_error_mask",
        )
        require(
            mask & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_CORRECTABLE_MASK_INVALID",
            "route.correctable_error_mask",
            "mask contains a bit outside the closed Correctable allow-list",
        )
        if not isinstance(self.root_correctable_notification_enabled, bool):
            fail(
                "AER_ROUTE_CONTROL_INVALID",
                "route.root_correctable_notification_enabled",
                "expected bool",
            )
        if not isinstance(self.root_port_reporting_enabled, bool):
            fail(
                "AER_ROUTE_CONTROL_INVALID",
                "route.root_port_reporting_enabled",
                "expected bool",
            )
        root_mask = _uint32(
            self.root_port_correctable_error_mask,
            "route.root_port_correctable_error_mask",
        )
        require(
            root_mask & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_CORRECTABLE_MASK_INVALID",
            "route.root_port_correctable_error_mask",
            "mask contains a bit outside the closed Correctable allow-list",
        )


@dataclass(frozen=True, slots=True)
class GuestConfigVirtualizationState:
    """Hypervisor-owned shadow values; never aliases physical VFIO storage."""

    shadow_values: tuple[tuple[AerField, int], ...]

    def __post_init__(self) -> None:
        fields: set[AerField] = set()
        for index, item in enumerate(self.shadow_values):
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], AerField)
            ):
                fail(
                    "AER_GUEST_SHADOW_INVALID",
                    f"guest.shadow_values[{index}]",
                    "expected (AerField, uint32)",
                )
            if item[0] in fields:
                fail(
                    "AER_GUEST_SHADOW_INVALID",
                    f"guest.shadow_values[{index}]",
                    "duplicate shadow field",
                )
            fields.add(item[0])
            _uint32(item[1], f"guest.shadow_values[{index}].value")
        require(
            tuple(field.value for field, _ in self.shadow_values)
            == tuple(sorted(field.value for field, _ in self.shadow_values)),
            "AER_GUEST_SHADOW_INVALID",
            "guest.shadow_values",
            "shadow fields must be sorted by their stable field name",
        )

    @classmethod
    def empty(cls) -> "GuestConfigVirtualizationState":
        return cls(
            tuple(
                sorted(
                    (
                        (field, 0)
                        for field in AerField
                        if field is not AerField.EXT_CAP_HEADER
                    ),
                    key=lambda item: item[0].value,
                )
            )
        )

    def value(self, field: AerField) -> int:
        for candidate, value in self.shadow_values:
            if candidate is field:
                return value
        return 0

    def replace_value(
        self,
        field: AerField,
        value: int,
    ) -> "GuestConfigVirtualizationState":
        checked = _uint32(value, "guest.shadow_value")
        values = dict(self.shadow_values)
        values[field] = checked
        return GuestConfigVirtualizationState(
            tuple(sorted(values.items(), key=lambda item: item[0].value))
        )

    def apply_w1c(
        self,
        field: AerField,
        bits: int,
    ) -> "GuestConfigVirtualizationState":
        return self.replace_value(field, self.value(field) & ~_uint32(bits, "bits"))

    @property
    def error_state_clean(self) -> bool:
        return all(
            self.value(field) == 0
            for field in (
                AerField.PCIE_DEVICE_STATUS,
                AerField.CORRECTABLE_ERROR_STATUS,
                AerField.ROOT_ERROR_STATUS,
                AerField.ERROR_SOURCE_ID,
            )
        )

    def reset_error_state(self) -> "GuestConfigVirtualizationState":
        state = self
        for field in (
            AerField.PCIE_DEVICE_STATUS,
            AerField.CORRECTABLE_ERROR_STATUS,
            AerField.ROOT_ERROR_STATUS,
            AerField.ERROR_SOURCE_ID,
        ):
            state = state.replace_value(field, 0)
        return state


@dataclass(frozen=True, slots=True)
class PhysicalCorrectableState:
    endpoint_correctable_status: int = 0
    endpoint_correctable_detected: bool = False
    endpoint_uncorrectable_status: int = 0
    root_port_correctable_error_status: int = 0
    root_port_correctable_detected: bool = False
    root_correctable_status: int = 0
    root_correctable_source_raw: int = 0
    root_uncorrectable_status: int = 0

    def __post_init__(self) -> None:
        endpoint_status = _uint32(
            self.endpoint_correctable_status,
            "physical.endpoint_correctable_status",
        )
        require(
            endpoint_status & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_CORRECTABLE_STATUS_INVALID",
            "physical.endpoint_correctable_status",
            "status contains a bit outside the closed Correctable allow-list",
        )
        if not isinstance(self.endpoint_correctable_detected, bool):
            fail(
                "AER_PHYSICAL_STATE_INVALID",
                "physical.endpoint_correctable_detected",
                "expected bool",
            )
        require(
            _uint32(
                self.endpoint_uncorrectable_status,
                "physical.endpoint_uncorrectable_status",
            )
            == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "physical.endpoint_uncorrectable_status",
            "Uncorrectable state is outside this model",
        )
        root_port_status = _uint32(
            self.root_port_correctable_error_status,
            "physical.root_port_correctable_error_status",
        )
        require(
            root_port_status & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_CORRECTABLE_STATUS_INVALID",
            "physical.root_port_correctable_error_status",
            "status contains a bit outside the closed Correctable allow-list",
        )
        if not isinstance(self.root_port_correctable_detected, bool):
            fail(
                "AER_PHYSICAL_STATE_INVALID",
                "physical.root_port_correctable_detected",
                "expected bool",
            )
        root_status = _uint32(
            self.root_correctable_status,
            "physical.root_correctable_status",
        )
        require(
            root_status & ~ROOT_CORRECTABLE_STATUS_MASK == 0,
            "AER_ROOT_STATUS_INVALID",
            "physical.root_correctable_status",
            "unknown Root Correctable status bits",
        )
        _requester_id(
            self.root_correctable_source_raw,
            "physical.root_correctable_source_raw",
        )
        require(
            _uint32(
                self.root_uncorrectable_status,
                "physical.root_uncorrectable_status",
            )
            == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "physical.root_uncorrectable_status",
            "Uncorrectable state is outside this model",
        )

    @property
    def root_source_semantic(self) -> int | None:
        """Source is meaningful only while Root COR_RCV is set."""

        if self.root_correctable_status & ROOT_CORRECTABLE_RECEIVED:
            return self.root_correctable_source_raw
        return None

    @property
    def clean(self) -> bool:
        return (
            self.endpoint_correctable_status == 0
            and not self.endpoint_correctable_detected
            and self.endpoint_uncorrectable_status == 0
            and self.root_port_correctable_error_status == 0
            and not self.root_port_correctable_detected
            and self.root_correctable_status == 0
            and self.root_uncorrectable_status == 0
        )


@dataclass(frozen=True, slots=True)
class NotificationServiceState:
    """Eligibility is modeled; delivery/health/recovery stay explicit evidence."""

    routed_message_count: int = 0
    notification_eligible_count: int = 0
    irq: Observation = Observation.UNKNOWN
    service: Observation = Observation.UNKNOWN
    health: Observation = Observation.UNKNOWN
    physical_recovery: Observation = Observation.UNKNOWN

    def __post_init__(self) -> None:
        for name in ("routed_message_count", "notification_eligible_count"):
            value = getattr(self, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                fail(
                    "AER_NOTIFICATION_STATE_INVALID",
                    f"notification.{name}",
                    "expected a non-negative integer",
                )
        require(
            self.notification_eligible_count <= self.routed_message_count,
            "AER_NOTIFICATION_STATE_INVALID",
            "notification.notification_eligible_count",
            "notification eligibility cannot exceed routed messages",
        )
        for name in ("irq", "service", "health", "physical_recovery"):
            if not isinstance(getattr(self, name), Observation):
                fail(
                    "AER_NOTIFICATION_STATE_INVALID",
                    f"notification.{name}",
                    "expected Observation",
                )


@dataclass(frozen=True, slots=True)
class LifecycleState:
    phase: LifecyclePhase = LifecyclePhase.CLEAN
    quarantine_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.phase, LifecyclePhase):
            fail(
                "AER_LIFECYCLE_INVALID",
                "lifecycle.phase",
                "expected LifecyclePhase",
            )
        if self.phase is LifecyclePhase.QUARANTINED:
            require(
                isinstance(self.quarantine_reason, str)
                and bool(self.quarantine_reason),
                "AER_LIFECYCLE_INVALID",
                "lifecycle.quarantine_reason",
                "a quarantined device needs a non-empty reason",
            )
        else:
            require(
                self.quarantine_reason is None,
                "AER_LIFECYCLE_INVALID",
                "lifecycle.quarantine_reason",
                "only a quarantined device may carry a quarantine reason",
            )


@dataclass(frozen=True, slots=True)
class AerReferenceModel:
    """Immutable aggregate of the four orthogonal reference state machines."""

    policy: VerifiedAerPolicy
    route: CorrectableRouteControl
    guest: GuestConfigVirtualizationState
    physical: PhysicalCorrectableState
    notification: NotificationServiceState
    lifecycle: LifecycleState
    endpoint_requester_id: int
    physical_ext_cap_header: int
    transition_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.policy, VerifiedAerPolicy) or not (
            self.policy._factory_verified()
        ):
            fail(
                "AER_POLICY_INPUT_INVALID",
                "model.policy",
                "policy must come from verify_aer_policy",
            )
        if not isinstance(self.route, CorrectableRouteControl):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.route",
                "expected CorrectableRouteControl",
            )
        if not isinstance(self.guest, GuestConfigVirtualizationState):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.guest",
                "expected GuestConfigVirtualizationState",
            )
        if not isinstance(self.physical, PhysicalCorrectableState):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.physical",
                "expected PhysicalCorrectableState",
            )
        if not isinstance(self.notification, NotificationServiceState):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.notification",
                "expected NotificationServiceState",
            )
        if not isinstance(self.lifecycle, LifecycleState):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.lifecycle",
                "expected LifecycleState",
            )
        _uint32(self.physical_ext_cap_header, "model.physical_ext_cap_header")
        _requester_id(
            self.endpoint_requester_id,
            "model.endpoint_requester_id",
        )
        if (
            not isinstance(self.transition_count, int)
            or isinstance(self.transition_count, bool)
            or self.transition_count < 0
        ):
            fail(
                "AER_MODEL_INPUT_INVALID",
                "model.transition_count",
                "expected a non-negative integer",
            )

    @classmethod
    def initial(
        cls,
        *,
        policy: VerifiedAerPolicy,
        route: CorrectableRouteControl,
        endpoint_requester_id: int,
        physical_ext_cap_header: int = 0x00010001,
    ) -> "AerReferenceModel":
        source = _requester_id(
            endpoint_requester_id,
            "endpoint_requester_id",
        )
        guest = (
            GuestConfigVirtualizationState.empty()
            .replace_value(
                AerField.PCIE_DEVICE_CONTROL,
                int(route.endpoint_reporting_enabled),
            )
            .replace_value(
                AerField.CORRECTABLE_ERROR_MASK,
                route.correctable_error_mask,
            )
            .replace_value(
                AerField.ROOT_ERROR_COMMAND,
                int(route.root_correctable_notification_enabled),
            )
        )
        return cls(
            policy=policy,
            route=route,
            guest=guest,
            physical=PhysicalCorrectableState(),
            notification=NotificationServiceState(),
            lifecycle=LifecycleState(),
            endpoint_requester_id=source,
            physical_ext_cap_header=physical_ext_cap_header,
        )

    def _transition(self, **changes: object) -> "AerReferenceModel":
        return replace(self, transition_count=self.transition_count + 1, **changes)

    def _shadow_backed(self, field: AerField) -> bool:
        field_policy = self.policy.field_policy(field)
        projection = field_policy.read_projection
        if (
            self.policy.body_exposure.value == "HIDDEN"
            and field
            not in {
                AerField.PCIE_DEVICE_CONTROL,
                AerField.PCIE_DEVICE_STATUS,
            }
        ):
            projection = self.policy.hidden_body_read_projection
        return (
            projection.value == "SHADOW"
            or field_policy.shadow_w1c_mask != 0
        )

    def inject_correctable(
        self,
        status_bits: int,
        *,
        requester_id: int,
        uncorrectable_status: int = 0,
    ) -> "AerReferenceModel":
        """Deposit one Correctable event and independently model E/M/R.

        Endpoint CES/CED records the event.  E (Endpoint CERE) and M
        (Correctable Mask) decide whether a Correctable message reaches the
        Root retained state.  R (Root Correctable Command) controls only
        notification eligibility; it does not suppress Root COR_RCV/Source.
        """

        if uncorrectable_status != 0:
            fail(
                "AER_UNCORRECTABLE_FORBIDDEN",
                "uncorrectable_status",
                "only Correctable error injection is supported",
            )
        require(
            self.lifecycle.phase is not LifecyclePhase.QUARANTINED,
            "AER_DEVICE_QUARANTINED",
            "lifecycle.phase",
            "a quarantined device cannot accept a new reference event",
        )
        bits = _uint32(status_bits, "status_bits")
        require(
            bits != 0 and bits & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_CORRECTABLE_STATUS_INVALID",
            "status_bits",
            "expected a non-zero subset of the closed Correctable allow-list",
        )
        source = _requester_id(requester_id, "requester_id")
        require(
            source == self.endpoint_requester_id,
            "AER_REQUESTER_ID_MISMATCH",
            "requester_id",
            "one Endpoint state cannot accept an event from another Requester",
        )
        physical = self.physical
        require(
            physical.endpoint_uncorrectable_status == 0
            and physical.root_uncorrectable_status == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "physical",
            "cannot transition from Uncorrectable state",
        )

        unmasked_bits = bits & ~self.route.correctable_error_mask
        routed = self.route.endpoint_reporting_enabled and bool(unmasked_bits)
        root_status = physical.root_correctable_status
        root_source = physical.root_correctable_source_raw
        if routed:
            if root_status & ROOT_CORRECTABLE_RECEIVED:
                root_status |= ROOT_MULTIPLE_CORRECTABLE_RECEIVED
            else:
                root_status |= ROOT_CORRECTABLE_RECEIVED
                root_source = source

        notification = self.notification
        routed_count = notification.routed_message_count + int(routed)
        eligible = routed and self.route.root_correctable_notification_enabled
        notification = replace(
            notification,
            routed_message_count=routed_count,
            notification_eligible_count=(
                notification.notification_eligible_count + int(eligible)
            ),
        )
        guest = self.guest
        if self._shadow_backed(AerField.CORRECTABLE_ERROR_STATUS):
            shadow_ces_mask = self.policy.field_policy(
                AerField.CORRECTABLE_ERROR_STATUS
            ).guest_read_allow_mask
            guest = guest.replace_value(
                AerField.CORRECTABLE_ERROR_STATUS,
                guest.value(AerField.CORRECTABLE_ERROR_STATUS)
                | (bits & shadow_ces_mask),
            )
        if self._shadow_backed(AerField.PCIE_DEVICE_STATUS):
            guest = guest.replace_value(
                AerField.PCIE_DEVICE_STATUS,
                guest.value(AerField.PCIE_DEVICE_STATUS)
                | DEVICE_STATUS_CORRECTABLE_DETECTED,
            )
        if routed:
            shadow_root_status_before = guest.value(
                AerField.ROOT_ERROR_STATUS
            )
            shadow_first_message = not bool(
                shadow_root_status_before & ROOT_CORRECTABLE_RECEIVED
            )
            if self._shadow_backed(AerField.ROOT_ERROR_STATUS):
                shadow_root_status = shadow_root_status_before
                if shadow_root_status & ROOT_CORRECTABLE_RECEIVED:
                    shadow_root_status |= ROOT_MULTIPLE_CORRECTABLE_RECEIVED
                else:
                    shadow_root_status |= ROOT_CORRECTABLE_RECEIVED
                shadow_root_status &= self.policy.field_policy(
                    AerField.ROOT_ERROR_STATUS
                ).guest_read_allow_mask
                guest = guest.replace_value(
                    AerField.ROOT_ERROR_STATUS,
                    shadow_root_status,
                )
            if (
                self._shadow_backed(AerField.ERROR_SOURCE_ID)
                and shadow_first_message
            ):
                guest = guest.replace_value(
                    AerField.ERROR_SOURCE_ID,
                    source
                    & self.policy.field_policy(
                        AerField.ERROR_SOURCE_ID
                    ).guest_read_allow_mask,
                )
        return self._transition(
            physical=replace(
                physical,
                endpoint_correctable_status=(
                    physical.endpoint_correctable_status | bits
                ),
                endpoint_correctable_detected=True,
                root_correctable_status=root_status,
                root_correctable_source_raw=root_source,
            ),
            notification=notification,
            guest=guest,
            lifecycle=LifecycleState(phase=LifecyclePhase.DIRTY),
        )

    def endpoint_status_w1c(self, bits: int) -> "AerReferenceModel":
        """Clear Endpoint CES only; Device Status.CED is independent."""

        checked = _uint32(bits, "bits")
        require(
            checked & ~CORRECTABLE_ERROR_ALLOW_MASK == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "bits",
            "Endpoint CES W1C contains a non-Correctable bit",
        )
        return self._transition(
            physical=replace(
                self.physical,
                endpoint_correctable_status=(
                    self.physical.endpoint_correctable_status & ~checked
                ),
            )
        )

    def endpoint_device_status_w1c(
        self,
        bits: int = DEVICE_STATUS_CORRECTABLE_DETECTED,
    ) -> "AerReferenceModel":
        """Clear Endpoint Device Status.CED without changing CES or Root."""

        checked = _uint32(bits, "bits")
        require(
            checked & ~DEVICE_STATUS_CORRECTABLE_DETECTED == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "bits",
            "Device Status W1C contains a non-Correctable bit",
        )
        detected = self.physical.endpoint_correctable_detected
        if checked & DEVICE_STATUS_CORRECTABLE_DETECTED:
            detected = False
        return self._transition(
            physical=replace(
                self.physical,
                endpoint_correctable_detected=detected,
            )
        )

    def root_status_w1c(self, bits: int) -> "AerReferenceModel":
        """Clear Root status independently and retain raw Source storage."""

        checked = _uint32(bits, "bits")
        require(
            checked & ~ROOT_CORRECTABLE_STATUS_MASK == 0,
            "AER_UNCORRECTABLE_FORBIDDEN",
            "bits",
            "Root Status W1C contains a non-Correctable bit",
        )
        return self._transition(
            physical=replace(
                self.physical,
                root_correctable_status=(
                    self.physical.root_correctable_status & ~checked
                ),
            )
        )

    def guest_read(
        self,
        field: AerField,
        *,
        function_role: AerFunctionRole = AerFunctionRole.ENDPOINT,
    ) -> int:
        if not isinstance(function_role, AerFunctionRole):
            fail(
                "AER_CONFIG_LAYOUT_INVALID",
                "function_role",
                "expected AerFunctionRole",
            )
        if not isinstance(field, AerField):
            fail("AER_FIELD_UNSUPPORTED", "field", "expected AerField")
        if function_role is AerFunctionRole.ENDPOINT:
            if field in {
                AerField.ROOT_ERROR_COMMAND,
                AerField.ROOT_ERROR_STATUS,
                AerField.ERROR_SOURCE_ID,
            }:
                fail(
                    "AER_MODEL_FIELD_UNMODELED",
                    "field",
                    "Root-only AER field requested from an Endpoint",
                )
            physical_values = {
                AerField.EXT_CAP_HEADER: self.physical_ext_cap_header,
                AerField.PCIE_DEVICE_CONTROL: int(
                    self.route.endpoint_reporting_enabled
                ),
                AerField.PCIE_DEVICE_STATUS: int(
                    self.physical.endpoint_correctable_detected
                ),
                AerField.CORRECTABLE_ERROR_STATUS: (
                    self.physical.endpoint_correctable_status
                ),
                AerField.CORRECTABLE_ERROR_MASK: (
                    self.route.correctable_error_mask
                ),
            }
        else:
            physical_values = {
                AerField.EXT_CAP_HEADER: self.physical_ext_cap_header,
                AerField.PCIE_DEVICE_CONTROL: int(
                    self.route.root_port_reporting_enabled
                ),
                AerField.PCIE_DEVICE_STATUS: int(
                    self.physical.root_port_correctable_detected
                ),
                AerField.CORRECTABLE_ERROR_STATUS: (
                    self.physical.root_port_correctable_error_status
                ),
                AerField.CORRECTABLE_ERROR_MASK: (
                    self.route.root_port_correctable_error_mask
                ),
                AerField.ROOT_ERROR_COMMAND: int(
                    self.route.root_correctable_notification_enabled
                ),
                AerField.ROOT_ERROR_STATUS: (
                    self.physical.root_correctable_status
                ),
                AerField.ERROR_SOURCE_ID: (
                    self.physical.root_correctable_source_raw
                ),
            }
        return project_guest_read(
            self.policy,
            field,
            physical_value=physical_values[field],
            shadow_value=self.guest.value(field),
        )

    def apply_guest_config_write(
        self,
        *,
        layout: VerifiedAerConfigLayout,
        write_offset: int,
        width: int,
        value: int,
        operation_id: str,
        authority_revision: int,
        expected_device_identity_digest: str,
        expected_bdf: str,
        expected_host_boot_id: str,
        expected_assignment_id: str,
        expected_lease_generation: int,
        expected_owner_epoch: int,
        expected_pcie_capability_offset: int,
        expected_pcie_capability_header: int,
        expected_pcie_capabilities_register: int,
        expected_aer_capability_offset: int,
        expected_aer_capability_header: int,
        expected_aer_predecessor_offset_or_none: int | None,
        expected_aer_predecessor_header_or_none: int | None,
    ) -> tuple["AerReferenceModel", VerifiedExecutableAerWritePlan]:
        """Bind, consume and apply one current-authority write deterministically."""

        require(
            self.lifecycle.phase is not LifecyclePhase.QUARANTINED,
            "AER_DEVICE_QUARANTINED",
            "lifecycle.phase",
            "a quarantined device rejects guest configuration writes",
        )
        classification = plan_guest_config_write(
            self.policy,
            layout,
            write_offset=write_offset,
            width=width,
            value=value,
        )
        plan = require_pre_vfio_plan(
            classification,
            self.policy,
            layout,
            operation_id=operation_id,
            authority_revision=authority_revision,
            expected_device_identity_digest=expected_device_identity_digest,
            expected_bdf=expected_bdf,
            expected_host_boot_id=expected_host_boot_id,
            expected_assignment_id=expected_assignment_id,
            expected_lease_generation=expected_lease_generation,
            expected_owner_epoch=expected_owner_epoch,
            expected_pcie_capability_offset=expected_pcie_capability_offset,
            expected_pcie_capability_header=expected_pcie_capability_header,
            expected_pcie_capabilities_register=(
                expected_pcie_capabilities_register
            ),
            expected_aer_capability_offset=expected_aer_capability_offset,
            expected_aer_capability_header=expected_aer_capability_header,
            expected_aer_predecessor_offset_or_none=(
                expected_aer_predecessor_offset_or_none
            ),
            expected_aer_predecessor_header_or_none=(
                expected_aer_predecessor_header_or_none
            ),
        )
        physical_writes = consume_executable_aer_write(
            plan,
            expected_operation_id=operation_id,
            expected_authority_revision=authority_revision,
            expected_aer_policy_digest=self.policy.aer_policy_digest,
            expected_layout_digest=layout.layout_digest,
        )
        physical = self.physical
        for write in physical_writes:
            if write.field is AerField.CORRECTABLE_ERROR_STATUS:
                if write.function_role is AerFunctionRole.ENDPOINT:
                    physical = replace(
                        physical,
                        endpoint_correctable_status=(
                            physical.endpoint_correctable_status & ~write.value
                        ),
                    )
                else:
                    physical = replace(
                        physical,
                        root_port_correctable_error_status=(
                            physical.root_port_correctable_error_status
                            & ~write.value
                        ),
                    )
            elif write.field is AerField.PCIE_DEVICE_STATUS:
                if write.value & DEVICE_STATUS_CORRECTABLE_DETECTED:
                    if write.function_role is AerFunctionRole.ENDPOINT:
                        physical = replace(
                            physical,
                            endpoint_correctable_detected=False,
                        )
                    else:
                        physical = replace(
                            physical,
                            root_port_correctable_detected=False,
                        )
            elif (
                write.field is AerField.ROOT_ERROR_STATUS
                and write.function_role is AerFunctionRole.ROOT_PORT
            ):
                physical = replace(
                    physical,
                    root_correctable_status=(
                        physical.root_correctable_status & ~write.value
                    ),
                )
            else:
                fail(
                    "AER_WRITE_PLAN_INVALID",
                    "executableWritePlan.physicalWrites",
                    "non-W1C physical write escaped the policy",
                )
        guest = self.guest
        for shadow_write in classification.shadow_w1c:
            guest = guest.apply_w1c(shadow_write.field, shadow_write.value)
        return self._transition(physical=physical, guest=guest), plan

    def guest_root_source_read(
        self,
        *,
        layout: VerifiedAerConfigLayout,
        snapshot_id: str,
        authority_revision: int,
        expected_device_identity_digest: str,
        expected_bdf: str,
        expected_host_boot_id: str,
        expected_assignment_id: str,
        expected_lease_generation: int,
        expected_owner_epoch: int,
        expected_pcie_capability_offset: int,
        expected_pcie_capability_header: int,
        expected_pcie_capabilities_register: int,
        expected_aer_capability_offset: int,
        expected_aer_capability_header: int,
        expected_aer_predecessor_offset_or_none: int | None,
        expected_aer_predecessor_header_or_none: int | None,
    ) -> RootSourceReadProjection:
        """Read Source from one immutable, current-bound model snapshot."""

        snapshot = project_guest_aer_snapshot(
            self.policy,
            layout,
            snapshot_id=snapshot_id,
            authority_revision=authority_revision,
            physical_field_values={
                AerField.ROOT_ERROR_STATUS: (
                    self.physical.root_correctable_status
                ),
                AerField.ERROR_SOURCE_ID: (
                    self.physical.root_correctable_source_raw
                ),
            },
            shadow_field_values={
                AerField.ROOT_ERROR_STATUS: self.guest.value(
                    AerField.ROOT_ERROR_STATUS
                ),
                AerField.ERROR_SOURCE_ID: self.guest.value(
                    AerField.ERROR_SOURCE_ID
                ),
            },
            expected_device_identity_digest=expected_device_identity_digest,
            expected_bdf=expected_bdf,
            expected_host_boot_id=expected_host_boot_id,
            expected_assignment_id=expected_assignment_id,
            expected_lease_generation=expected_lease_generation,
            expected_owner_epoch=expected_owner_epoch,
            expected_pcie_capability_offset=expected_pcie_capability_offset,
            expected_pcie_capability_header=expected_pcie_capability_header,
            expected_pcie_capabilities_register=(
                expected_pcie_capabilities_register
            ),
            expected_aer_capability_offset=expected_aer_capability_offset,
            expected_aer_capability_header=expected_aer_capability_header,
            expected_aer_predecessor_offset_or_none=(
                expected_aer_predecessor_offset_or_none
            ),
            expected_aer_predecessor_header_or_none=(
                expected_aer_predecessor_header_or_none
            ),
        )
        return project_guest_root_source_read(
            snapshot,
            expected_snapshot_id=snapshot_id,
            expected_authority_revision=authority_revision,
        )

    def record_observations(
        self,
        *,
        irq: Observation | None = None,
        service: Observation | None = None,
        health: Observation | None = None,
        physical_recovery: Observation | None = None,
    ) -> "AerReferenceModel":
        """Record explicit observations without inferring them from registers."""

        updates: dict[str, Observation] = {}
        for name, value in (
            ("irq", irq),
            ("service", service),
            ("health", health),
            ("physical_recovery", physical_recovery),
        ):
            if value is not None:
                if not isinstance(value, Observation):
                    fail(
                        "AER_OBSERVATION_INVALID",
                        f"observation.{name}",
                        "expected Observation",
                    )
                current = getattr(self.notification, name)
                if value is Observation.UNKNOWN:
                    merged = current
                elif current is Observation.UNKNOWN:
                    merged = value
                elif current is value:
                    merged = current
                else:
                    merged = Observation.CONFLICT
                updates[name] = merged
        return self._transition(
            notification=replace(self.notification, **updates)
        )

    def assess_cleanup(self) -> "AerReferenceModel":
        """Verify retained state is clean or quarantine the device."""

        if self.lifecycle.phase is LifecyclePhase.QUARANTINED:
            lifecycle = self.lifecycle
        elif self.physical.clean and self.guest.error_state_clean:
            lifecycle = LifecycleState(phase=LifecyclePhase.CLEANUP_VERIFIED)
        else:
            lifecycle = LifecycleState(
                phase=LifecyclePhase.QUARANTINED,
                quarantine_reason="AER_RETAINED_STATE_NOT_CLEAN",
            )
        return self._transition(lifecycle=lifecycle)

    def host_cleanup_guest_shadow(self) -> "AerReferenceModel":
        """Host-only cleanup; guest writes never receive this capability."""

        return self._transition(guest=self.guest.reset_error_state())

    def assess_reuse_gate(self, *, passed: bool) -> "AerReferenceModel":
        if not isinstance(passed, bool):
            fail("AER_REUSE_GATE_INVALID", "passed", "expected bool")
        if self.lifecycle.phase is LifecyclePhase.QUARANTINED:
            lifecycle = self.lifecycle
        elif self.lifecycle.phase is LifecyclePhase.CLEANUP_VERIFIED and passed:
            lifecycle = LifecycleState(phase=LifecyclePhase.REUSABLE)
        else:
            lifecycle = LifecycleState(
                phase=LifecyclePhase.QUARANTINED,
                quarantine_reason="AER_REUSE_GATE_NOT_SATISFIED",
            )
        return self._transition(lifecycle=lifecycle)

    def quarantine(self, reason: str) -> "AerReferenceModel":
        require(
            isinstance(reason, str) and bool(reason),
            "AER_QUARANTINE_REASON_INVALID",
            "reason",
            "expected a non-empty reason",
        )
        return self._transition(
            lifecycle=LifecycleState(
                phase=LifecyclePhase.QUARANTINED,
                quarantine_reason=reason,
            )
        )


__all__ = [
    "AerReferenceModel",
    "CorrectableRouteControl",
    "DEVICE_STATUS_CORRECTABLE_DETECTED",
    "GuestConfigVirtualizationState",
    "LifecyclePhase",
    "LifecycleState",
    "NotificationServiceState",
    "Observation",
    "PhysicalCorrectableState",
    "ROOT_CORRECTABLE_RECEIVED",
    "ROOT_CORRECTABLE_STATUS_MASK",
    "ROOT_MULTIPLE_CORRECTABLE_RECEIVED",
]
