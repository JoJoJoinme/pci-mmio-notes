"""Field-level Correctable AER guest-configuration policy.

This module never accepts a VFIO callback and never performs host I/O.
``plan_guest_config_write`` returns a non-executable classification with no
physical offset/value tuple.  Only ``require_pre_vfio_plan`` may construct a
current-bound ``VerifiedExecutableAerWritePlan``; its filtered writes are
exposed once through ``consume_executable_aer_write``.  Writing the guest value
to VFIO first, bypassing the current binding, or replaying a consumed plan
violates this contract.

The policy is Correctable-only.  Uncorrectable Status/Mask/Severity byte lanes
are a hard-deny region, and unknown fields never acquire a physical write by
default.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
import re
from threading import Lock
from types import MappingProxyType
from typing import Any

from ._verified import FactoryVerified
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .errors import fail, require


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview

AER_POLICY_DIGEST_DOMAIN = b"QMAN-DIRECTPATH/AER-POLICY/V1\x00"
AER_CONFIG_LAYOUT_DIGEST_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-CONFIG-LAYOUT/V1\x00"
)
FILTER_BEFORE_VFIO = "FILTER_BEFORE_VFIO"
CORRECTABLE_ERROR_ALLOW_MASK = 0x0000F1C1

_POLICY_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "policyId",
        "correctableOnly",
        "extendedCapability",
        "writePipeline",
        "unknownFieldAction",
        "fields",
        "aerPolicyDigest",
    }
)
_EXTENDED_CAPABILITY_KEYS = frozenset(
    {"headerExposure", "bodyExposure", "hiddenBodyReadProjection"}
)
_FIELD_POLICY_KEYS = frozenset(
    {
        "readProjection",
        "guestReadAllowMask",
        "writeDisposition",
        "physicalW1cAllowMask",
        "shadowW1cMask",
    }
)
_CONFIG_LAYOUT_KEYS = frozenset(
    {
        "subjectType",
        "schemaVersion",
        "deviceIdentityDigest",
        "bdf",
        "hostBootId",
        "assignmentId",
        "leaseGeneration",
        "ownerEpoch",
        "pcieCapabilityOffset",
        "pcieCapabilityHeader",
        "pcieCapabilitiesRegister",
        "aerCapabilityOffset",
        "aerCapabilityHeader",
        "aerPredecessorOffsetOrNull",
        "aerPredecessorHeaderOrNull",
        "layoutDigest",
    }
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_EXECUTABLE_AER_PLAN_FACTORY_TOKEN = object()
_GUEST_PROJECTED_AER_SNAPSHOT_FACTORY_TOKEN = object()
_BDF_RE = re.compile(
    r"^[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$"
)


class AerField(str, Enum):
    """Closed AER fields implemented by the portable policy."""

    EXT_CAP_HEADER = "EXT_CAP_HEADER"
    PCIE_DEVICE_CONTROL = "PCIE_DEVICE_CONTROL"
    PCIE_DEVICE_STATUS = "PCIE_DEVICE_STATUS"
    CORRECTABLE_ERROR_STATUS = "CORRECTABLE_ERROR_STATUS"
    CORRECTABLE_ERROR_MASK = "CORRECTABLE_ERROR_MASK"
    ROOT_ERROR_COMMAND = "ROOT_ERROR_COMMAND"
    ROOT_ERROR_STATUS = "ROOT_ERROR_STATUS"
    ERROR_SOURCE_ID = "ERROR_SOURCE_ID"


class HeaderExposure(str, Enum):
    VISIBLE = "VISIBLE"
    HIDDEN = "HIDDEN"


class BodyExposure(str, Enum):
    VISIBLE = "VISIBLE"
    HIDDEN = "HIDDEN"


class ReadProjection(str, Enum):
    PHYSICAL = "PHYSICAL"
    ZERO = "ZERO"
    SHADOW = "SHADOW"


class WriteDisposition(str, Enum):
    DENY = "DENY"
    FILTERED_W1C = "FILTERED_W1C"


class AerFunctionRole(str, Enum):
    ENDPOINT = "ENDPOINT"
    ROOT_PORT = "ROOT_PORT"


_AER_MANDATORY_EXTENT: Mapping[AerFunctionRole, int] = MappingProxyType(
    {
        # Endpoint AER includes the common registers through the four-DWORD
        # Header Log.  Root Ports additionally implement Root Command, Root
        # Status and Error Source Identification through +0x37.
        AerFunctionRole.ENDPOINT: 0x2C,
        AerFunctionRole.ROOT_PORT: 0x38,
    }
)


class WriteDenyReason(str, Enum):
    UNCORRECTABLE_FIELD_FORBIDDEN = "UNCORRECTABLE_FIELD_FORBIDDEN"
    UNKNOWN_FIELD_DENIED = "UNKNOWN_FIELD_DENIED"
    EXT_CAP_HEADER_WRITE_DENIED = "EXT_CAP_HEADER_WRITE_DENIED"
    FIELD_WRITE_DENIED = "FIELD_WRITE_DENIED"
    W1C_BITS_FILTERED = "W1C_BITS_FILTERED"


class ReadLaneDisposition(str, Enum):
    PROJECTED = "PROJECTED"
    HIDDEN_ZEROED = "HIDDEN_ZEROED"
    UNCORRECTABLE_ZEROED = "UNCORRECTABLE_ZEROED"
    UNKNOWN_ZEROED = "UNKNOWN_ZEROED"
    MISSING_FIELD_ZEROED = "MISSING_FIELD_ZEROED"


_BODY_FIELDS = (
    AerField.PCIE_DEVICE_CONTROL,
    AerField.PCIE_DEVICE_STATUS,
    AerField.CORRECTABLE_ERROR_STATUS,
    AerField.CORRECTABLE_ERROR_MASK,
    AerField.ROOT_ERROR_COMMAND,
    AerField.ROOT_ERROR_STATUS,
    AerField.ERROR_SOURCE_ID,
)
_W1C_FIELDS = frozenset(
    {
        AerField.CORRECTABLE_ERROR_STATUS,
        AerField.PCIE_DEVICE_STATUS,
        AerField.ROOT_ERROR_STATUS,
    }
)

# Each entry is ``(capability space, relative offset, width)``.  The PCIe
# Capability and the AER Extended Capability have independent dynamic offsets.
_FIELD_LAYOUT: Mapping[AerField, tuple[str, int, int]] = MappingProxyType(
    {
        AerField.EXT_CAP_HEADER: ("AER", 0x00, 4),
        AerField.PCIE_DEVICE_CONTROL: ("PCIE", 0x08, 2),
        AerField.PCIE_DEVICE_STATUS: ("PCIE", 0x0A, 2),
        AerField.CORRECTABLE_ERROR_STATUS: ("AER", 0x10, 4),
        AerField.CORRECTABLE_ERROR_MASK: ("AER", 0x14, 4),
        AerField.ROOT_ERROR_COMMAND: ("AER", 0x2C, 4),
        AerField.ROOT_ERROR_STATUS: ("AER", 0x30, 4),
        # Error Source Identification is a mixed-semantics DWORD: the lower
        # half is Correctable Source ID and the upper half is Uncorrectable
        # Source ID.  The Correctable-only overlay owns only +0x34..+0x35.
        AerField.ERROR_SOURCE_ID: ("AER", 0x34, 2),
    }
)
# UES, UEM and Uncorrectable Severity.  Any overlapping write is denied as a
# whole rather than split into a superficially safe Correctable write.  Error
# Source Identification's upper half is the Uncorrectable Source ID and is
# therefore an independent hard-deny/zero region as well.
_UNCORRECTABLE_RELATIVE_RANGES = (
    range(0x04, 0x10),
    range(0x36, 0x38),
)
_FIELD_W1C_ALLOW_MASK: Mapping[AerField, int] = MappingProxyType(
    {
        AerField.CORRECTABLE_ERROR_STATUS: CORRECTABLE_ERROR_ALLOW_MASK,
        AerField.PCIE_DEVICE_STATUS: 0x00000001,
        AerField.ROOT_ERROR_STATUS: 0x00000003,
    }
)
_FIELD_READ_ALLOW_MASK: Mapping[AerField, int] = MappingProxyType(
    {
        AerField.PCIE_DEVICE_CONTROL: 0x00000001,
        AerField.PCIE_DEVICE_STATUS: 0x00000001,
        AerField.CORRECTABLE_ERROR_STATUS: CORRECTABLE_ERROR_ALLOW_MASK,
        AerField.CORRECTABLE_ERROR_MASK: CORRECTABLE_ERROR_ALLOW_MASK,
        AerField.ROOT_ERROR_COMMAND: 0x00000001,
        AerField.ROOT_ERROR_STATUS: 0x00000003,
        AerField.ERROR_SOURCE_ID: 0x0000FFFF,
    }
)


def _is_uncorrectable_relative_byte(relative_offset: int) -> bool:
    return any(
        relative_offset in forbidden_range
        for forbidden_range in _UNCORRECTABLE_RELATIVE_RANGES
    )


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _closed_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    path: str,
) -> None:
    actual = set(value)
    require(
        actual == expected,
        "AER_POLICY_SHAPE_INVALID",
        path,
        (
            "object members are not the closed policy shape: "
            f"missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}"
        ),
    )


def _uint32(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        fail("AER_VALUE_INVALID", path, "expected an unsigned 32-bit integer")
    return value


def _document(
    value: JsonDocument,
    path: str = "aerPolicy",
) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    elif isinstance(value, Mapping):
        try:
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        except (CanonicalizationError, TypeError, ValueError) as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            path,
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "DOCUMENT_TYPE_INVALID",
        path,
        "expected a JSON object",
    )
    return loaded, raw


def _enum(enum_type: type[Enum], value: object, path: str) -> Enum:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        fail(
            "AER_POLICY_ENUM_INVALID",
            path,
            f"expected one of {[item.value for item in enum_type]!r}",
        )


@dataclass(frozen=True, slots=True)
class AerFieldPolicy:
    """One verified field projection and pre-VFIO W1C split."""

    read_projection: ReadProjection
    guest_read_allow_mask: int
    write_disposition: WriteDisposition
    physical_w1c_allow_mask: int
    shadow_w1c_mask: int

    def __post_init__(self) -> None:
        if not isinstance(self.read_projection, ReadProjection):
            fail(
                "AER_POLICY_INPUT_INVALID",
                "field_policy.read_projection",
                "expected ReadProjection",
            )
        if not isinstance(self.write_disposition, WriteDisposition):
            fail(
                "AER_POLICY_INPUT_INVALID",
                "field_policy.write_disposition",
                "expected WriteDisposition",
            )
        _uint32(
            self.guest_read_allow_mask,
            "field_policy.guest_read_allow_mask",
        )
        _uint32(
            self.physical_w1c_allow_mask,
            "field_policy.physical_w1c_allow_mask",
        )
        _uint32(self.shadow_w1c_mask, "field_policy.shadow_w1c_mask")


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAerPolicy(FactoryVerified):
    """Canonical, closed Correctable-only AER policy."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    policy_id: str
    aer_policy_digest: str
    header_exposure: HeaderExposure
    body_exposure: BodyExposure
    hidden_body_read_projection: ReadProjection
    field_policies: Mapping[AerField, AerFieldPolicy]

    def field_policy(self, field: AerField) -> AerFieldPolicy:
        if not isinstance(field, AerField) or field is AerField.EXT_CAP_HEADER:
            fail(
                "AER_FIELD_UNSUPPORTED",
                "field",
                "expected one supported AER body field",
            )
        return self.field_policies[field]

    def to_subject(self) -> Mapping[str, Any]:
        return self.document


def verify_aer_policy(value: JsonDocument) -> VerifiedAerPolicy:
    """Verify a canonical null-hash policy and all isolation invariants."""

    document, raw = _document(value)
    _closed_keys(document, _POLICY_KEYS, "aerPolicy")
    require(
        document["subjectType"] == "QMAN_AER_POLICY"
        and isinstance(document["schemaVersion"], int)
        and not isinstance(document["schemaVersion"], bool)
        and document["schemaVersion"] == 1,
        "AER_POLICY_VERSION_UNSUPPORTED",
        "aerPolicy",
        "expected QMAN_AER_POLICY schemaVersion 1",
    )
    require(
        isinstance(document["policyId"], str) and bool(document["policyId"]),
        "AER_POLICY_ID_INVALID",
        "aerPolicy.policyId",
        "expected a non-empty policy identifier",
    )
    require(
        document["correctableOnly"] is True,
        "AER_UNCORRECTABLE_FORBIDDEN",
        "aerPolicy.correctableOnly",
        "the portable AER model is Correctable-only",
    )
    require(
        document["writePipeline"] == FILTER_BEFORE_VFIO,
        "AER_WRITE_ORDER_INVALID",
        "aerPolicy.writePipeline",
        "guest writes must be filtered before any physical VFIO write",
    )
    require(
        document["unknownFieldAction"] == "DENY",
        "AER_UNKNOWN_FIELD_POLICY_INVALID",
        "aerPolicy.unknownFieldAction",
        "unknown guest configuration fields must default to DENY",
    )

    extended = document["extendedCapability"]
    require(
        isinstance(extended, dict),
        "AER_POLICY_SHAPE_INVALID",
        "aerPolicy.extendedCapability",
        "expected an object",
    )
    _closed_keys(
        extended,
        _EXTENDED_CAPABILITY_KEYS,
        "aerPolicy.extendedCapability",
    )
    header_exposure = _enum(
        HeaderExposure,
        extended["headerExposure"],
        "aerPolicy.extendedCapability.headerExposure",
    )
    body_exposure = _enum(
        BodyExposure,
        extended["bodyExposure"],
        "aerPolicy.extendedCapability.bodyExposure",
    )
    hidden_projection = _enum(
        ReadProjection,
        extended["hiddenBodyReadProjection"],
        "aerPolicy.extendedCapability.hiddenBodyReadProjection",
    )
    require(
        hidden_projection in (ReadProjection.ZERO, ReadProjection.SHADOW),
        "AER_HIDDEN_READ_POLICY_INVALID",
        "aerPolicy.extendedCapability.hiddenBodyReadProjection",
        "a hidden capability body may read only ZERO or SHADOW",
    )

    fields = document["fields"]
    require(
        isinstance(fields, dict),
        "AER_POLICY_SHAPE_INVALID",
        "aerPolicy.fields",
        "expected an object",
    )
    expected_field_names = {field.value for field in _BODY_FIELDS}
    require(
        set(fields) == expected_field_names,
        "AER_POLICY_SHAPE_INVALID",
        "aerPolicy.fields",
        (
            "field policies must cover the exact Correctable field set: "
            f"missing={sorted(expected_field_names - set(fields))!r}, "
            f"extra={sorted(set(fields) - expected_field_names)!r}"
        ),
    )

    checked_fields: dict[AerField, AerFieldPolicy] = {}
    for field in _BODY_FIELDS:
        path = f"aerPolicy.fields.{field.value}"
        candidate = fields[field.value]
        require(
            isinstance(candidate, dict),
            "AER_POLICY_SHAPE_INVALID",
            path,
            "expected an object",
        )
        _closed_keys(candidate, _FIELD_POLICY_KEYS, path)
        read_projection = _enum(
            ReadProjection,
            candidate["readProjection"],
            f"{path}.readProjection",
        )
        read_allow_mask = _uint32(
            candidate["guestReadAllowMask"],
            f"{path}.guestReadAllowMask",
        )
        require(
            read_allow_mask & ~_FIELD_READ_ALLOW_MASK[field] == 0,
            "AER_READ_MASK_INVALID",
            f"{path}.guestReadAllowMask",
            "guest read mask contains a non-Correctable or out-of-field bit",
        )
        disposition = _enum(
            WriteDisposition,
            candidate["writeDisposition"],
            f"{path}.writeDisposition",
        )
        physical_mask = _uint32(
            candidate["physicalW1cAllowMask"],
            f"{path}.physicalW1cAllowMask",
        )
        shadow_mask = _uint32(
            candidate["shadowW1cMask"],
            f"{path}.shadowW1cMask",
        )
        require(
            not (physical_mask & shadow_mask),
            "AER_W1C_MASK_OVERLAP",
            path,
            "physical and shadow W1C ownership must be disjoint",
        )
        require(
            not (physical_mask and shadow_mask),
            "AER_POLICY_COMBINATION_INVALID",
            path,
            "V1 assigns each field wholly to physical or shadow W1C ownership",
        )
        allowed_w1c = _FIELD_W1C_ALLOW_MASK.get(field, 0)
        require(
            (physical_mask | shadow_mask) & ~allowed_w1c == 0,
            "AER_W1C_MASK_INVALID",
            path,
            "W1C masks contain a bit outside this field's closed allow-list",
        )
        require(
            (physical_mask | shadow_mask) & ~read_allow_mask == 0,
            "AER_W1C_MASK_NOT_READABLE",
            path,
            "V1 cannot clear a status bit hidden from the same guest",
        )
        if disposition is WriteDisposition.DENY:
            require(
                physical_mask == 0 and shadow_mask == 0,
                "AER_W1C_MASK_INVALID",
                path,
                "DENY fields cannot own physical or shadow W1C bits",
            )
        else:
            require(
                field in _W1C_FIELDS and bool(physical_mask | shadow_mask),
                "AER_W1C_FIELD_INVALID",
                path,
                "FILTERED_W1C is allowed only on a W1C status field",
            )
        if (
            body_exposure is BodyExposure.HIDDEN
            and _FIELD_LAYOUT[field][0] == "AER"
        ):
            require(
                physical_mask == 0,
                "AER_HIDDEN_WRITE_LEAK",
                path,
                "a hidden AER body cannot forward guest writes to VFIO",
            )
        effective_read = read_projection
        if (
            body_exposure is BodyExposure.HIDDEN
            and _FIELD_LAYOUT[field][0] == "AER"
        ):
            effective_read = hidden_projection
        require(
            not physical_mask or effective_read is ReadProjection.PHYSICAL,
            "AER_POLICY_COMBINATION_INVALID",
            path,
            "physical W1C ownership requires a PHYSICAL field projection",
        )
        require(
            not shadow_mask or effective_read is ReadProjection.SHADOW,
            "AER_POLICY_COMBINATION_INVALID",
            path,
            "shadow W1C ownership requires a SHADOW field projection",
        )
        checked_fields[field] = AerFieldPolicy(
            read_projection=read_projection,
            guest_read_allow_mask=read_allow_mask,
            write_disposition=disposition,
            physical_w1c_allow_mask=physical_mask,
            shadow_w1c_mask=shadow_mask,
        )

    def effective_read(field: AerField) -> ReadProjection:
        if (
            body_exposure is BodyExposure.HIDDEN
            and _FIELD_LAYOUT[field][0] == "AER"
        ):
            return hidden_projection
        return checked_fields[field].read_projection

    require(
        effective_read(AerField.ERROR_SOURCE_ID)
        is effective_read(AerField.ROOT_ERROR_STATUS),
        "AER_POLICY_COMBINATION_INVALID",
        "aerPolicy.fields.ERROR_SOURCE_ID",
        "Root Source and Root Status must share one semantic projection owner",
    )

    declared_digest = document["aerPolicyDigest"]
    projection = copy.deepcopy(document)
    projection["aerPolicyDigest"] = None
    expected_digest = sha256_digest(
        AER_POLICY_DIGEST_DOMAIN + canonical_json_bytes(projection)
    )
    require(
        declared_digest == expected_digest,
        "AER_POLICY_DIGEST_INVALID",
        "aerPolicy.aerPolicyDigest",
        "digest does not match the canonical null-hash policy projection",
    )

    return VerifiedAerPolicy._construct(
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        policy_id=document["policyId"],
        aer_policy_digest=expected_digest,
        header_exposure=header_exposure,
        body_exposure=body_exposure,
        hidden_body_read_projection=hidden_projection,
        field_policies=MappingProxyType(checked_fields),
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAerConfigLayout(FactoryVerified):
    """Canonical discovered PCIe/AER layout bound to owner generations.

    This value is still not proof of a live configuration-space read.  A
    product adapter must compare every binding to its current device/owner
    authority and re-read the capability headers immediately before I/O.
    """

    document: Mapping[str, Any]
    canonical_bytes: bytes
    device_identity_digest: str
    bdf: str
    host_boot_id: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    function_role: AerFunctionRole
    pcie_capability_offset: int
    pcie_capability_header: int
    pcie_capabilities_register: int
    aer_capability_offset: int
    aer_capability_header: int
    aer_predecessor_offset_or_none: int | None
    aer_predecessor_header_or_none: int | None
    layout_digest: str

    def to_subject(self) -> Mapping[str, Any]:
        return self.document


def verify_aer_config_layout(value: JsonDocument) -> VerifiedAerConfigLayout:
    """Verify one closed capability layout without claiming live-read origin."""

    document, raw = _document(value, "aerConfigLayout")
    _closed_keys(document, _CONFIG_LAYOUT_KEYS, "aerConfigLayout")
    require(
        document["subjectType"] == "QMAN_AER_CONFIG_LAYOUT"
        and isinstance(document["schemaVersion"], int)
        and not isinstance(document["schemaVersion"], bool)
        and document["schemaVersion"] == 1,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout",
        "expected QMAN_AER_CONFIG_LAYOUT schemaVersion 1",
    )
    device_digest = document["deviceIdentityDigest"]
    require(
        isinstance(device_digest, str)
        and _DIGEST_RE.fullmatch(device_digest) is not None,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.deviceIdentityDigest",
        "expected sha256:<64 lowercase hex>",
    )
    bdf = document["bdf"]
    require(
        isinstance(bdf, str) and _BDF_RE.fullmatch(bdf) is not None,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.bdf",
        "expected canonical lowercase PCI BDF",
    )
    host_boot_id = document["hostBootId"]
    require(
        isinstance(host_boot_id, str) and bool(host_boot_id),
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.hostBootId",
        "expected a non-empty boot identifier",
    )
    assignment_id = document["assignmentId"]
    require(
        isinstance(assignment_id, str) and bool(assignment_id),
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.assignmentId",
        "expected a non-empty assignment identifier",
    )
    lease_generation = document["leaseGeneration"]
    require(
        isinstance(lease_generation, int)
        and not isinstance(lease_generation, bool)
        and 1 <= lease_generation <= 9_007_199_254_740_991,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.leaseGeneration",
        "expected a positive safe lease generation",
    )
    owner_epoch = document["ownerEpoch"]
    require(
        isinstance(owner_epoch, int)
        and not isinstance(owner_epoch, bool)
        and 1 <= owner_epoch <= 9_007_199_254_740_991,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.ownerEpoch",
        "expected a positive safe owner epoch",
    )
    pcie_offset = document["pcieCapabilityOffset"]
    if (
        not isinstance(pcie_offset, int)
        or isinstance(pcie_offset, bool)
        or pcie_offset < 0x40
        or pcie_offset % 4
        or pcie_offset + 0x0C > 0x100
    ):
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.pcieCapabilityOffset",
            "PCIe capability layout must fit conventional config space",
        )
    pcie_header = document["pcieCapabilityHeader"]
    require(
        isinstance(pcie_header, int)
        and not isinstance(pcie_header, bool)
        and 0 <= pcie_header <= 0xFFFF
        and (pcie_header & 0xFF) == 0x10,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.pcieCapabilityHeader",
        "header does not identify a PCI Express Capability",
    )
    pcie_next = (pcie_header >> 8) & 0xFF
    require(
        pcie_next == 0
        or (
            pcie_next >= 0x40
            and pcie_next <= 0xFC
            and pcie_next % 4 == 0
        ),
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.pcieCapabilityHeader",
        "PCI capability Next pointer is not aligned/in range",
    )
    pcie_capabilities = document["pcieCapabilitiesRegister"]
    require(
        isinstance(pcie_capabilities, int)
        and not isinstance(pcie_capabilities, bool)
        and 0 <= pcie_capabilities <= 0xFFFF,
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.pcieCapabilitiesRegister",
        "expected the raw 16-bit PCIe Capabilities register",
    )
    device_port_type = (pcie_capabilities >> 4) & 0xF
    if device_port_type in (0x0, 0x1):
        function_role = AerFunctionRole.ENDPOINT
    elif device_port_type == 0x4:
        function_role = AerFunctionRole.ROOT_PORT
    else:
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.pcieCapabilitiesRegister",
            "Device/Port Type is outside the Endpoint/Root-Port model",
        )
    aer_offset = document["aerCapabilityOffset"]
    mandatory_aer_extent = _AER_MANDATORY_EXTENT[function_role]
    if (
        not isinstance(aer_offset, int)
        or isinstance(aer_offset, bool)
        or aer_offset < 0x100
        or aer_offset % 4
        or aer_offset + mandatory_aer_extent > 0x1000
    ):
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.aerCapabilityOffset",
            (
                "the complete mandatory AER layout must be DWORD-aligned "
                "and contained in 4KiB config"
            ),
        )
    aer_header = _uint32(
        document["aerCapabilityHeader"],
        "aerConfigLayout.aerCapabilityHeader",
    )
    require(
        (aer_header & 0xFFFF) == 0x0001
        and ((aer_header >> 16) & 0xF) in (1, 2),
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.aerCapabilityHeader",
        "header does not identify the AER Extended Capability",
    )
    aer_next = (aer_header >> 20) & 0xFFF
    require(
        aer_next == 0
        or (
            aer_next >= aer_offset + mandatory_aer_extent
            and aer_next <= 0xFFC
            and aer_next % 4 == 0
        ),
        "AER_CONFIG_LAYOUT_INVALID",
        "aerConfigLayout.aerCapabilityHeader",
        "AER Next pointer targets the AER body or is not one valid forward link",
    )
    predecessor_offset = document["aerPredecessorOffsetOrNull"]
    predecessor_header = document["aerPredecessorHeaderOrNull"]
    if predecessor_offset is None or predecessor_header is None:
        require(
            predecessor_offset is None
            and predecessor_header is None
            and aer_offset == 0x100,
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.aerPredecessorOffsetOrNull",
            "only an AER capability at 0x100 may have no predecessor",
        )
    else:
        require(
            isinstance(predecessor_offset, int)
            and not isinstance(predecessor_offset, bool)
            and 0x100 <= predecessor_offset < aer_offset
            and predecessor_offset % 4 == 0,
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.aerPredecessorOffsetOrNull",
            "expected one aligned predecessor before AER",
        )
        predecessor_header = _uint32(
            predecessor_header,
            "aerConfigLayout.aerPredecessorHeaderOrNull",
        )
        require(
            ((predecessor_header >> 20) & 0xFFF) == aer_offset,
            "AER_CONFIG_LAYOUT_INVALID",
            "aerConfigLayout.aerPredecessorHeaderOrNull",
            "predecessor Next pointer does not identify AER",
        )
    projection = copy.deepcopy(document)
    projection["layoutDigest"] = None
    expected_digest = sha256_digest(
        AER_CONFIG_LAYOUT_DIGEST_DOMAIN + canonical_json_bytes(projection)
    )
    require(
        document["layoutDigest"] == expected_digest,
        "AER_CONFIG_LAYOUT_DIGEST_INVALID",
        "aerConfigLayout.layoutDigest",
        "digest does not match the canonical null-hash layout projection",
    )
    return VerifiedAerConfigLayout._construct(
        document=_deep_freeze(copy.deepcopy(document)),
        canonical_bytes=raw,
        device_identity_digest=device_digest,
        bdf=bdf,
        host_boot_id=host_boot_id,
        assignment_id=assignment_id,
        lease_generation=lease_generation,
        owner_epoch=owner_epoch,
        function_role=function_role,
        pcie_capability_offset=pcie_offset,
        pcie_capability_header=pcie_header,
        pcie_capabilities_register=pcie_capabilities,
        aer_capability_offset=aer_offset,
        aer_capability_header=aer_header,
        aer_predecessor_offset_or_none=predecessor_offset,
        aer_predecessor_header_or_none=predecessor_header,
        layout_digest=expected_digest,
    )


def _project_guest_read_value(
    policy: VerifiedAerPolicy,
    field: AerField,
    *,
    physical_value: int,
    shadow_value: int = 0,
) -> int:
    """Project one 32-bit field without granting physical read authority."""

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    physical = _uint32(physical_value, "physical_value")
    shadow = _uint32(shadow_value, "shadow_value")
    if not isinstance(field, AerField):
        fail("AER_FIELD_UNSUPPORTED", "field", "expected AerField")
    if field is AerField.EXT_CAP_HEADER:
        return physical if policy.header_exposure is HeaderExposure.VISIBLE else 0
    projection = _effective_read_projection(policy, field)
    read_mask = policy.field_policy(field).guest_read_allow_mask
    if projection is ReadProjection.PHYSICAL:
        return physical & read_mask
    if projection is ReadProjection.SHADOW:
        return shadow & read_mask
    return 0


def project_guest_read(
    policy: VerifiedAerPolicy,
    field: AerField,
    *,
    physical_value: int,
    shadow_value: int = 0,
) -> int:
    """Project one non-Root-pair field without physical read authority.

    Root Status and Correctable Source cannot be projected independently;
    callers must use ``project_guest_aer_snapshot`` so both values and their
    owner/layout generation share one receipt.
    """

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    if not isinstance(field, AerField):
        fail("AER_FIELD_UNSUPPORTED", "field", "expected AerField")
    require(
        field
        not in {
            AerField.ROOT_ERROR_STATUS,
            AerField.ERROR_SOURCE_ID,
        },
        "AER_ROOT_SNAPSHOT_REQUIRED",
        "field",
        (
            "Root Status and Correctable Source require one atomic guest "
            "projection receipt"
        ),
    )
    return _project_guest_read_value(
        policy,
        field,
        physical_value=physical_value,
        shadow_value=shadow_value,
    )


@dataclass(frozen=True, slots=True)
class RootSourceReadProjection:
    """Raw guest-visible Correctable Source plus separate attribution validity."""

    raw_value: int
    semantic_valid: bool
    semantic_requester_id: int | None


def _effective_read_projection(
    policy: VerifiedAerPolicy,
    field: AerField,
) -> ReadProjection:
    """Resolve the one effective guest projection owner for an AER field."""

    if (
        policy.body_exposure is BodyExposure.HIDDEN
        and _FIELD_LAYOUT[field][0] == "AER"
    ):
        return policy.hidden_body_read_projection
    return policy.field_policy(field).read_projection


def require_current_aer_layout(
    layout: VerifiedAerConfigLayout,
    *,
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
) -> VerifiedAerConfigLayout:
    """Bind a canonical layout to independently current ownership and headers.

    The ``expected_*`` values are a product trust-port input: they must come
    from the current owner authority and fresh configuration-space reads, not
    from ``layout`` itself.  Requiring the same guard on reads and writes keeps
    a stale AER base from reclassifying Uncorrectable registers as Correctable.
    """

    if (
        not isinstance(layout, VerifiedAerConfigLayout)
        or not layout._factory_verified()
    ):
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "layout",
            "layout must come from verify_aer_config_layout",
        )
    replayed = verify_aer_config_layout(layout.canonical_bytes)
    require(
        layout == replayed,
        "AER_CONFIG_LAYOUT_INVALID",
        "layout",
        "layout does not equal deterministic replay from canonical bytes",
    )
    current_bindings = (
        ("deviceIdentityDigest", expected_device_identity_digest),
        ("bdf", expected_bdf),
        ("hostBootId", expected_host_boot_id),
        ("assignmentId", expected_assignment_id),
        ("leaseGeneration", expected_lease_generation),
        ("ownerEpoch", expected_owner_epoch),
        ("pcieCapabilityOffset", expected_pcie_capability_offset),
        ("pcieCapabilityHeader", expected_pcie_capability_header),
        (
            "pcieCapabilitiesRegister",
            expected_pcie_capabilities_register,
        ),
        ("aerCapabilityOffset", expected_aer_capability_offset),
        ("aerCapabilityHeader", expected_aer_capability_header),
        (
            "aerPredecessorOffsetOrNull",
            expected_aer_predecessor_offset_or_none,
        ),
        (
            "aerPredecessorHeaderOrNull",
            expected_aer_predecessor_header_or_none,
        ),
    )
    stored_bindings = (
        layout.device_identity_digest,
        layout.bdf,
        layout.host_boot_id,
        layout.assignment_id,
        layout.lease_generation,
        layout.owner_epoch,
        layout.pcie_capability_offset,
        layout.pcie_capability_header,
        layout.pcie_capabilities_register,
        layout.aer_capability_offset,
        layout.aer_capability_header,
        layout.aer_predecessor_offset_or_none,
        layout.aer_predecessor_header_or_none,
    )
    for (field_name, current), stored in zip(
        current_bindings,
        stored_bindings,
        strict=True,
    ):
        require(
            type(current) is type(stored) and current == stored,
            "AER_CONFIG_LAYOUT_STALE",
            f"layout.{field_name}",
            "verified layout differs from current owner/config observation",
        )
    return replayed


@dataclass(frozen=True, slots=True, init=False)
class VerifiedGuestProjectedAerSnapshot(FactoryVerified):
    """One atomic guest projection of Root Status and Correctable Source.

    ``snapshot_id`` and ``authority_revision`` identify the product adapter's
    single capture boundary.  The receipt copies every owner/layout binding so
    a later read cannot combine Root Status from one generation with Source
    from another.
    """

    aer_policy_digest: str
    layout_digest: str
    snapshot_id: str
    authority_revision: int
    device_identity_digest: str
    bdf: str
    host_boot_id: str
    assignment_id: str
    lease_generation: int
    owner_epoch: int
    function_role: AerFunctionRole
    pcie_capability_offset: int
    pcie_capability_header: int
    pcie_capabilities_register: int
    aer_capability_offset: int
    aer_capability_header: int
    aer_predecessor_offset_or_none: int | None
    aer_predecessor_header_or_none: int | None
    projection_owner: ReadProjection
    root_status_value: int
    correctable_source_raw: int
    source_semantic_valid: bool
    source_semantic_requester_id: int | None

    @classmethod
    def _construct(
        cls,
        **_values: Any,
    ) -> "VerifiedGuestProjectedAerSnapshot":
        raise TypeError(
            "VerifiedGuestProjectedAerSnapshot is constructed only by the "
            "current-bound atomic projection factory"
        )

    @classmethod
    def _construct_projected(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedGuestProjectedAerSnapshot":
        if factory_token is not _GUEST_PROJECTED_AER_SNAPSHOT_FACTORY_TOKEN:
            raise TypeError("invalid guest-projected AER snapshot factory token")
        return FactoryVerified._construct.__func__(cls, **values)


def _root_snapshot_id(value: object, path: str) -> str:
    if (
        not isinstance(value, str)
        or _OPERATION_ID_RE.fullmatch(value) is None
    ):
        fail(
            "AER_ROOT_SNAPSHOT_INVALID",
            path,
            "expected a closed portable snapshot identifier",
        )
    return value


def _root_snapshot_authority_revision(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 9_007_199_254_740_991
    ):
        fail(
            "AER_ROOT_SNAPSHOT_INVALID",
            path,
            "expected a positive safe authority revision",
        )
    return value


def project_guest_aer_snapshot(
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    snapshot_id: str,
    authority_revision: int,
    physical_field_values: Mapping[AerField, int],
    shadow_field_values: Mapping[AerField, int],
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
) -> VerifiedGuestProjectedAerSnapshot:
    """Project one product-atomic Root Status/Correctable Source capture.

    The two mappings are a product trust-port input and must represent one
    indivisible capture.  This factory resolves the effective PHYSICAL,
    SHADOW, or ZERO owner once and emits the only receipt accepted by Root
    Source semantic reads.
    """

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    replayed_policy = verify_aer_policy(policy.canonical_bytes)
    require(
        policy == replayed_policy,
        "AER_POLICY_INPUT_INVALID",
        "policy",
        "policy does not equal deterministic replay from canonical bytes",
    )
    policy = replayed_policy
    layout = require_current_aer_layout(
        layout,
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
    require(
        layout.function_role is AerFunctionRole.ROOT_PORT,
        "AER_ROOT_SNAPSHOT_INVALID",
        "layout.functionRole",
        "Root Status/Source snapshots require a Root Port layout",
    )
    checked_snapshot_id = _root_snapshot_id(snapshot_id, "snapshot_id")
    checked_authority_revision = _root_snapshot_authority_revision(
        authority_revision,
        "authority_revision",
    )
    if not isinstance(physical_field_values, Mapping) or not isinstance(
        shadow_field_values,
        Mapping,
    ):
        fail(
            "AER_ROOT_SNAPSHOT_INVALID",
            "field_values",
            "expected physical and shadow mappings keyed by AerField",
        )

    root_owner = _effective_read_projection(
        policy,
        AerField.ROOT_ERROR_STATUS,
    )
    source_owner = _effective_read_projection(
        policy,
        AerField.ERROR_SOURCE_ID,
    )
    require(
        root_owner is source_owner,
        "AER_POLICY_COMBINATION_INVALID",
        "aerPolicy.fields.ERROR_SOURCE_ID",
        "Root Source and Root Status must share one projection owner",
    )
    selected_values = (
        physical_field_values
        if root_owner is ReadProjection.PHYSICAL
        else shadow_field_values
    )
    selected_mapping_name = (
        "physical_field_values"
        if root_owner is ReadProjection.PHYSICAL
        else "shadow_field_values"
    )
    if root_owner is ReadProjection.ZERO:
        selected_root_status = 0
        selected_source = 0
    else:
        try:
            selected_root_status = selected_values[
                AerField.ROOT_ERROR_STATUS
            ]
            selected_source = selected_values[AerField.ERROR_SOURCE_ID]
        except KeyError:
            fail(
                "AER_ROOT_SNAPSHOT_INCOMPLETE",
                selected_mapping_name,
                (
                    "the selected projection owner must atomically supply "
                    "Root Status and Correctable Source"
                ),
            )
        selected_root_status = _uint32(
            selected_root_status,
            f"{selected_mapping_name}.ROOT_ERROR_STATUS",
        )
        selected_source = _uint32(
            selected_source,
            f"{selected_mapping_name}.ERROR_SOURCE_ID",
        )

    root_status_value = _project_guest_read_value(
        policy,
        AerField.ROOT_ERROR_STATUS,
        physical_value=(
            selected_root_status
            if root_owner is ReadProjection.PHYSICAL
            else 0
        ),
        shadow_value=(
            selected_root_status
            if root_owner is ReadProjection.SHADOW
            else 0
        ),
    )
    correctable_source_raw = _project_guest_read_value(
        policy,
        AerField.ERROR_SOURCE_ID,
        physical_value=(
            selected_source
            if root_owner is ReadProjection.PHYSICAL
            else 0
        ),
        shadow_value=(
            selected_source
            if root_owner is ReadProjection.SHADOW
            else 0
        ),
    )
    full_source_identity_visible = (
        policy.field_policy(
            AerField.ERROR_SOURCE_ID
        ).guest_read_allow_mask
        == _FIELD_READ_ALLOW_MASK[AerField.ERROR_SOURCE_ID]
    )
    source_semantic_valid = bool(root_status_value & 0x1) and (
        full_source_identity_visible
    )
    source_semantic_requester_id = (
        correctable_source_raw & 0xFFFF
        if source_semantic_valid
        else None
    )
    return VerifiedGuestProjectedAerSnapshot._construct_projected(
        _GUEST_PROJECTED_AER_SNAPSHOT_FACTORY_TOKEN,
        aer_policy_digest=policy.aer_policy_digest,
        layout_digest=layout.layout_digest,
        snapshot_id=checked_snapshot_id,
        authority_revision=checked_authority_revision,
        device_identity_digest=layout.device_identity_digest,
        bdf=layout.bdf,
        host_boot_id=layout.host_boot_id,
        assignment_id=layout.assignment_id,
        lease_generation=layout.lease_generation,
        owner_epoch=layout.owner_epoch,
        function_role=layout.function_role,
        pcie_capability_offset=layout.pcie_capability_offset,
        pcie_capability_header=layout.pcie_capability_header,
        pcie_capabilities_register=layout.pcie_capabilities_register,
        aer_capability_offset=layout.aer_capability_offset,
        aer_capability_header=layout.aer_capability_header,
        aer_predecessor_offset_or_none=(
            layout.aer_predecessor_offset_or_none
        ),
        aer_predecessor_header_or_none=(
            layout.aer_predecessor_header_or_none
        ),
        projection_owner=root_owner,
        root_status_value=root_status_value,
        correctable_source_raw=correctable_source_raw,
        source_semantic_valid=source_semantic_valid,
        source_semantic_requester_id=source_semantic_requester_id,
    )


def _require_root_snapshot_identity(
    snapshot: object,
    *,
    expected_snapshot_id: str,
    expected_authority_revision: int,
) -> VerifiedGuestProjectedAerSnapshot:
    if (
        not isinstance(snapshot, VerifiedGuestProjectedAerSnapshot)
        or not snapshot._factory_verified()
    ):
        fail(
            "AER_ROOT_SNAPSHOT_INVALID",
            "root_snapshot",
            "expected a factory-produced guest-projected AER snapshot",
        )
    checked_snapshot_id = _root_snapshot_id(
        expected_snapshot_id,
        "expected_root_snapshot_id",
    )
    checked_authority_revision = _root_snapshot_authority_revision(
        expected_authority_revision,
        "expected_root_snapshot_authority_revision",
    )
    require(
        snapshot.snapshot_id == checked_snapshot_id
        and snapshot.authority_revision == checked_authority_revision,
        "AER_ROOT_SNAPSHOT_BINDING_MISMATCH",
        "root_snapshot",
        "snapshot identity or authority revision is no longer current",
    )
    return snapshot


def _require_root_snapshot_binding(
    snapshot: object,
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    expected_snapshot_id: str,
    expected_authority_revision: int,
) -> VerifiedGuestProjectedAerSnapshot:
    snapshot = _require_root_snapshot_identity(
        snapshot,
        expected_snapshot_id=expected_snapshot_id,
        expected_authority_revision=expected_authority_revision,
    )
    expected_bindings = (
        policy.aer_policy_digest,
        layout.layout_digest,
        layout.device_identity_digest,
        layout.bdf,
        layout.host_boot_id,
        layout.assignment_id,
        layout.lease_generation,
        layout.owner_epoch,
        layout.function_role,
        layout.pcie_capability_offset,
        layout.pcie_capability_header,
        layout.pcie_capabilities_register,
        layout.aer_capability_offset,
        layout.aer_capability_header,
        layout.aer_predecessor_offset_or_none,
        layout.aer_predecessor_header_or_none,
    )
    actual_bindings = (
        snapshot.aer_policy_digest,
        snapshot.layout_digest,
        snapshot.device_identity_digest,
        snapshot.bdf,
        snapshot.host_boot_id,
        snapshot.assignment_id,
        snapshot.lease_generation,
        snapshot.owner_epoch,
        snapshot.function_role,
        snapshot.pcie_capability_offset,
        snapshot.pcie_capability_header,
        snapshot.pcie_capabilities_register,
        snapshot.aer_capability_offset,
        snapshot.aer_capability_header,
        snapshot.aer_predecessor_offset_or_none,
        snapshot.aer_predecessor_header_or_none,
    )
    require(
        all(
            type(actual) is type(expected) and actual == expected
            for actual, expected in zip(
                actual_bindings,
                expected_bindings,
                strict=True,
            )
        ),
        "AER_ROOT_SNAPSHOT_BINDING_MISMATCH",
        "root_snapshot",
        "snapshot policy, owner generation, or layout is no longer current",
    )
    expected_owner = _effective_read_projection(
        policy,
        AerField.ROOT_ERROR_STATUS,
    )
    require(
        snapshot.function_role is AerFunctionRole.ROOT_PORT
        and snapshot.projection_owner is expected_owner,
        "AER_ROOT_SNAPSHOT_BINDING_MISMATCH",
        "root_snapshot.projection_owner",
        "snapshot role or guest projection owner differs from current policy",
    )
    root_status_value = _uint32(
        snapshot.root_status_value,
        "root_snapshot.root_status_value",
    )
    source_raw = _uint32(
        snapshot.correctable_source_raw,
        "root_snapshot.correctable_source_raw",
    )
    expected_semantic_valid = bool(root_status_value & 0x1) and (
        policy.field_policy(
            AerField.ERROR_SOURCE_ID
        ).guest_read_allow_mask
        == _FIELD_READ_ALLOW_MASK[AerField.ERROR_SOURCE_ID]
    )
    expected_requester_id = (
        source_raw & 0xFFFF if expected_semantic_valid else None
    )
    require(
        snapshot.source_semantic_valid is expected_semantic_valid
        and snapshot.source_semantic_requester_id == expected_requester_id,
        "AER_ROOT_SNAPSHOT_INVALID",
        "root_snapshot.source_semantics",
        "Source semantics do not derive from guest-visible COR_RCV and mask",
    )
    return snapshot


def project_guest_root_source_read(
    snapshot: VerifiedGuestProjectedAerSnapshot,
    *,
    expected_snapshot_id: str,
    expected_authority_revision: int,
) -> RootSourceReadProjection:
    """Return Source semantics derived only by the atomic snapshot factory."""

    snapshot = _require_root_snapshot_identity(
        snapshot,
        expected_snapshot_id=expected_snapshot_id,
        expected_authority_revision=expected_authority_revision,
    )
    return RootSourceReadProjection(
        raw_value=snapshot.correctable_source_raw,
        semantic_valid=snapshot.source_semantic_valid,
        semantic_requester_id=snapshot.source_semantic_requester_id,
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedGuestConfigReadProjection(FactoryVerified):
    """Closed byte-lane projection; no configuration read may raw-fallback."""

    aer_policy_digest: str
    layout_digest: str
    request_offset: int
    request_width: int
    value: int
    lane_dispositions: tuple[ReadLaneDisposition, ...]
    root_snapshot_id: str | None
    root_snapshot_authority_revision: int | None
    root_source_semantic_valid: bool | None
    root_source_semantic_requester_id: int | None


def project_guest_config_read(
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    read_offset: int,
    width: int,
    physical_field_values: Mapping[AerField, int],
    shadow_field_values: Mapping[AerField, int],
    root_snapshot: VerifiedGuestProjectedAerSnapshot | None = None,
    expected_root_snapshot_id: str | None = None,
    expected_root_snapshot_authority_revision: int | None = None,
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
) -> VerifiedGuestConfigReadProjection:
    """Project the closed AER overlay after binding fresh current inputs.

    Unknown lanes deliberately read zero.  This function is not a complete
    4KiB configuration-space passthrough policy; BAR/MSI/vendor and all other
    fields require a separate closed product policy and may not raw-fallback
    through this overlay.
    """

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    layout = require_current_aer_layout(
        layout,
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
    if isinstance(width, bool) or width not in (1, 2, 4):
        fail(
            "AER_CONFIG_ACCESS_INVALID",
            "width",
            "expected width 1, 2 or 4",
        )
    if (
        not isinstance(read_offset, int)
        or isinstance(read_offset, bool)
        or read_offset < 0
        or read_offset + width > 0x1000
    ):
        fail(
            "AER_CONFIG_ACCESS_INVALID",
            "read_offset",
            "configuration read is outside the 4KiB space",
        )
    if not isinstance(physical_field_values, Mapping) or not isinstance(
        shadow_field_values,
        Mapping,
    ):
        fail(
            "AER_CONFIG_READ_INPUT_INVALID",
            "field_values",
            "expected physical and shadow mappings keyed by AerField",
        )
    for mapping_name, values in (
        ("physical_field_values", physical_field_values),
        ("shadow_field_values", shadow_field_values),
    ):
        for field, field_value in values.items():
            if not isinstance(field, AerField):
                fail(
                    "AER_CONFIG_READ_INPUT_INVALID",
                    mapping_name,
                    "all mapping keys must be AerField",
                )
            _uint32(field_value, f"{mapping_name}.{field.value}")
    checked_root_snapshot = (
        _require_root_snapshot_binding(
            root_snapshot,
            policy,
            layout,
            expected_snapshot_id=expected_root_snapshot_id,
            expected_authority_revision=(
                expected_root_snapshot_authority_revision
            ),
        )
        if root_snapshot is not None
        else None
    )
    require(
        root_snapshot is not None
        or (
            expected_root_snapshot_id is None
            and expected_root_snapshot_authority_revision is None
        ),
        "AER_ROOT_SNAPSHOT_UNUSED",
        "expected_root_snapshot",
        "snapshot identity/revision is accepted only with a Root snapshot",
    )

    predecessor_projection: ExtCapabilityChainProjection | None = None
    if policy.header_exposure is HeaderExposure.HIDDEN:
        aer_successor = (layout.aer_capability_header >> 20) & 0xFFF
        if layout.aer_predecessor_offset_or_none is None:
            require(
                aer_successor == 0,
                "AER_HIDDEN_CHAIN_UNREPRESENTABLE",
                "aerConfigLayout.aerCapabilityHeader",
                (
                    "a hidden first Extended Capability cannot preserve a "
                    "non-empty successor chain"
                ),
            )
        else:
            assert layout.aer_predecessor_header_or_none is not None
            predecessor_projection = project_hidden_ext_cap_chain(
                policy,
                function_role=layout.function_role,
                predecessor_offset=layout.aer_predecessor_offset_or_none,
                predecessor_header=layout.aer_predecessor_header_or_none,
                aer_capability_offset=layout.aer_capability_offset,
                aer_header=layout.aer_capability_header,
            )

    root_snapshot_used = False
    source_overlapped = False
    value = 0
    dispositions: list[ReadLaneDisposition] = []
    for lane in range(width):
        absolute_offset = read_offset + lane
        predecessor_offset = layout.aer_predecessor_offset_or_none
        if (
            predecessor_offset is not None
            and predecessor_offset <= absolute_offset < predecessor_offset + 4
        ):
            predecessor_header = layout.aer_predecessor_header_or_none
            assert predecessor_header is not None
            projected_header = (
                predecessor_projection.projected_predecessor_header
                if predecessor_projection is not None
                else predecessor_header
            )
            byte_value = (
                projected_header >> ((absolute_offset - predecessor_offset) * 8)
            ) & 0xFF
            disposition = ReadLaneDisposition.PROJECTED
        else:
            aer_relative = absolute_offset - layout.aer_capability_offset
            if _is_uncorrectable_relative_byte(aer_relative):
                byte_value = 0
                disposition = ReadLaneDisposition.UNCORRECTABLE_ZEROED
            else:
                located = _field_for_absolute_byte(
                    function_role=layout.function_role,
                    aer_capability_offset=layout.aer_capability_offset,
                    pcie_capability_offset=layout.pcie_capability_offset,
                    absolute_offset=absolute_offset,
                )
                if located is None:
                    byte_value = 0
                    disposition = ReadLaneDisposition.UNKNOWN_ZEROED
                else:
                    field, field_byte = located
                    if field is AerField.EXT_CAP_HEADER:
                        projected = project_guest_read(
                            policy,
                            field,
                            physical_value=layout.aer_capability_header,
                        )
                        disposition = (
                            ReadLaneDisposition.HIDDEN_ZEROED
                            if policy.header_exposure is HeaderExposure.HIDDEN
                            else ReadLaneDisposition.PROJECTED
                        )
                    elif field in (
                        AerField.ROOT_ERROR_STATUS,
                        AerField.ERROR_SOURCE_ID,
                    ):
                        require(
                            checked_root_snapshot is not None,
                            "AER_ROOT_SNAPSHOT_REQUIRED",
                            "root_snapshot",
                            (
                                "Root Status and Correctable Source reads "
                                "require one atomic guest projection receipt"
                            ),
                        )
                        root_snapshot_used = True
                        effective_projection = (
                            checked_root_snapshot.projection_owner
                        )
                        projected = (
                            checked_root_snapshot.root_status_value
                            if field is AerField.ROOT_ERROR_STATUS
                            else checked_root_snapshot.correctable_source_raw
                        )
                        disposition = (
                            ReadLaneDisposition.HIDDEN_ZEROED
                            if effective_projection is ReadProjection.ZERO
                            else ReadLaneDisposition.PROJECTED
                        )
                        if field is AerField.ERROR_SOURCE_ID:
                            source_overlapped = True
                    else:
                        effective_projection = _effective_read_projection(
                            policy,
                            field,
                        )
                        selected_mapping = (
                            physical_field_values
                            if effective_projection is ReadProjection.PHYSICAL
                            else shadow_field_values
                        )
                        missing = (
                            effective_projection is not ReadProjection.ZERO
                            and field not in selected_mapping
                        )
                        projected = project_guest_read(
                            policy,
                            field,
                            physical_value=physical_field_values.get(field, 0),
                            shadow_value=shadow_field_values.get(field, 0),
                        )
                        if missing:
                            disposition = (
                                ReadLaneDisposition.MISSING_FIELD_ZEROED
                            )
                        elif effective_projection is ReadProjection.ZERO:
                            disposition = ReadLaneDisposition.HIDDEN_ZEROED
                        else:
                            disposition = ReadLaneDisposition.PROJECTED
                    byte_value = (projected >> (field_byte * 8)) & 0xFF
        value |= byte_value << (lane * 8)
        dispositions.append(disposition)

    require(
        root_snapshot is None or root_snapshot_used,
        "AER_ROOT_SNAPSHOT_UNUSED",
        "root_snapshot",
        "a Root snapshot is accepted only when Root Status or Source overlaps",
    )
    root_source_semantic_valid = (
        checked_root_snapshot.source_semantic_valid
        if source_overlapped and checked_root_snapshot is not None
        else None
    )
    semantic_requester = (
        checked_root_snapshot.source_semantic_requester_id
        if source_overlapped and checked_root_snapshot is not None
        else None
    )
    return VerifiedGuestConfigReadProjection._construct(
        aer_policy_digest=policy.aer_policy_digest,
        layout_digest=layout.layout_digest,
        request_offset=read_offset,
        request_width=width,
        value=value,
        lane_dispositions=tuple(dispositions),
        root_snapshot_id=(
            checked_root_snapshot.snapshot_id
            if root_snapshot_used and checked_root_snapshot is not None
            else None
        ),
        root_snapshot_authority_revision=(
            checked_root_snapshot.authority_revision
            if root_snapshot_used and checked_root_snapshot is not None
            else None
        ),
        root_source_semantic_valid=root_source_semantic_valid,
        root_source_semantic_requester_id=semantic_requester,
    )


@dataclass(frozen=True, slots=True)
class PhysicalConfigWrite:
    """One already-filtered VFIO write, expressed at the complete W1C field."""

    offset: int
    width: int
    value: int
    field: AerField
    function_role: AerFunctionRole


@dataclass(frozen=True, slots=True)
class ShadowW1c:
    field: AerField
    value: int


@dataclass(frozen=True, slots=True, init=False)
class VerifiedGuestConfigWriteClassification(FactoryVerified):
    """Non-executable classification of one guest configuration write.

    This object deliberately contains no physical write tuple, physical field
    offset or complete-field physical value.  It may be inspected before a
    current owner/layout check, but it cannot be consumed by a VFIO adapter.
    """

    aer_policy_digest: str
    layout_digest: str
    function_role: AerFunctionRole
    request_offset: int
    request_width: int
    request_value: int
    filter_stage: str
    shadow_w1c: tuple[ShadowW1c, ...]
    forwarded_request_mask: int
    shadow_request_mask: int
    discarded_request_mask: int
    deny_reasons: tuple[WriteDenyReason, ...]
    physical_write_required: bool


# Compatibility name for callers that imported the old type.  It now denotes
# the non-executable classification and intentionally has no physical_writes.
VerifiedGuestConfigWritePlan = VerifiedGuestConfigWriteClassification


class _AerWriteConsumeState:
    """Process-local single-use state; product adapters still need durable CAS."""

    __slots__ = ("lock", "consumed")

    def __init__(self) -> None:
        self.lock = Lock()
        self.consumed = False


@dataclass(frozen=True, slots=True, init=False)
class VerifiedExecutableAerWritePlan(FactoryVerified):
    """Current-bound physical W1C plan with one process-local consumption."""

    classification: VerifiedGuestConfigWriteClassification
    aer_policy_digest: str
    layout_digest: str
    operation_id: str
    authority_revision: int
    physical_write_count: int
    _physical_writes: tuple[PhysicalConfigWrite, ...] = dataclass_field(
        repr=False,
    )
    _consume_state: _AerWriteConsumeState = dataclass_field(
        repr=False,
        compare=False,
    )

    @property
    def consumed(self) -> bool:
        with self._consume_state.lock:
            return self._consume_state.consumed

    @classmethod
    def _construct(cls, **_values: Any) -> "VerifiedExecutableAerWritePlan":
        raise TypeError(
            "VerifiedExecutableAerWritePlan is constructed only by the "
            "current-authority write factory"
        )

    @classmethod
    def _construct_current_bound(
        cls,
        factory_token: object,
        **values: Any,
    ) -> "VerifiedExecutableAerWritePlan":
        if factory_token is not _EXECUTABLE_AER_PLAN_FACTORY_TOKEN:
            raise TypeError("invalid executable AER plan factory token")
        return FactoryVerified._construct.__func__(cls, **values)


@dataclass(frozen=True, slots=True)
class _GuestConfigWriteDerivation:
    classification: VerifiedGuestConfigWriteClassification
    physical_writes: tuple[PhysicalConfigWrite, ...]


def _field_for_absolute_byte(
    *,
    function_role: AerFunctionRole,
    aer_capability_offset: int,
    pcie_capability_offset: int,
    absolute_offset: int,
) -> tuple[AerField, int] | None:
    for field, (space, relative_offset, field_width) in _FIELD_LAYOUT.items():
        if (
            function_role is AerFunctionRole.ENDPOINT
            and field
            in {
                AerField.ROOT_ERROR_COMMAND,
                AerField.ROOT_ERROR_STATUS,
                AerField.ERROR_SOURCE_ID,
            }
        ):
            continue
        base = (
            aer_capability_offset
            if space == "AER"
            else pcie_capability_offset
        )
        start = base + relative_offset
        if start <= absolute_offset < start + field_width:
            return field, absolute_offset - start
    return None


def _verified_plan(
    *,
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    request_offset: int,
    request_width: int,
    request_value: int,
    physical_writes: tuple[PhysicalConfigWrite, ...],
    shadow_w1c: tuple[ShadowW1c, ...],
    forwarded_request_mask: int,
    shadow_request_mask: int,
    discarded_request_mask: int,
    deny_reasons: tuple[WriteDenyReason, ...],
) -> VerifiedGuestConfigWriteClassification:
    access_mask = (1 << (request_width * 8)) - 1
    require(
        not (forwarded_request_mask & shadow_request_mask)
        and not (forwarded_request_mask & discarded_request_mask)
        and not (shadow_request_mask & discarded_request_mask)
        and (
            forwarded_request_mask
            | shadow_request_mask
            | discarded_request_mask
        )
        == access_mask,
        "AER_WRITE_PLAN_INVALID",
        "writePlan",
        "request-bit ownership masks must be disjoint and complete",
    )
    return VerifiedGuestConfigWriteClassification._construct(
        aer_policy_digest=policy.aer_policy_digest,
        layout_digest=layout.layout_digest,
        function_role=layout.function_role,
        request_offset=request_offset,
        request_width=request_width,
        request_value=request_value,
        filter_stage=FILTER_BEFORE_VFIO,
        shadow_w1c=shadow_w1c,
        forwarded_request_mask=forwarded_request_mask,
        shadow_request_mask=shadow_request_mask,
        discarded_request_mask=discarded_request_mask,
        deny_reasons=deny_reasons,
        physical_write_required=bool(physical_writes),
    )


def _derive_guest_config_write(
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    write_offset: int,
    width: int,
    value: int,
) -> _GuestConfigWriteDerivation:
    """Derive classification plus module-private physical W1C candidates."""

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    if (
        not isinstance(layout, VerifiedAerConfigLayout)
        or not layout._factory_verified()
    ):
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "layout",
            "layout must come from verify_aer_config_layout",
        )
    if isinstance(width, bool) or width not in (1, 2, 4):
        fail(
            "AER_CONFIG_ACCESS_INVALID",
            "width",
            "expected width 1, 2 or 4",
        )
    if (
        not isinstance(write_offset, int)
        or isinstance(write_offset, bool)
        or write_offset < 0
        or write_offset + width > 0x1000
    ):
        fail(
            "AER_CONFIG_ACCESS_INVALID",
            "write_offset",
            "configuration write is outside the 4KiB space",
        )
    max_value = (1 << (width * 8)) - 1
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > max_value
    ):
        fail(
            "AER_CONFIG_ACCESS_INVALID",
            "value",
            "guest value does not fit the requested access width",
        )

    aer_relative_lanes = tuple(
        write_offset + lane - layout.aer_capability_offset
        for lane in range(width)
    )
    if any(
        _is_uncorrectable_relative_byte(lane) for lane in aer_relative_lanes
    ):
        return _GuestConfigWriteDerivation(
            classification=_verified_plan(
                policy=policy,
                layout=layout,
                request_offset=write_offset,
                request_width=width,
                request_value=value,
                physical_writes=(),
                shadow_w1c=(),
                forwarded_request_mask=0,
                shadow_request_mask=0,
                discarded_request_mask=max_value,
                deny_reasons=(
                    WriteDenyReason.UNCORRECTABLE_FIELD_FORBIDDEN,
                ),
            ),
            physical_writes=(),
        )

    physical_by_field: dict[AerField, int] = {}
    shadow_by_field: dict[AerField, int] = {}
    forwarded_request_mask = 0
    shadow_request_mask = 0
    reasons: set[WriteDenyReason] = set()

    for lane in range(width):
        absolute_offset = write_offset + lane
        lane_value = (value >> (lane * 8)) & 0xFF
        located = _field_for_absolute_byte(
            function_role=layout.function_role,
            aer_capability_offset=layout.aer_capability_offset,
            pcie_capability_offset=layout.pcie_capability_offset,
            absolute_offset=absolute_offset,
        )
        if located is None:
            reasons.add(WriteDenyReason.UNKNOWN_FIELD_DENIED)
            continue
        field, field_byte = located
        if field is AerField.EXT_CAP_HEADER:
            reasons.add(WriteDenyReason.EXT_CAP_HEADER_WRITE_DENIED)
            continue
        field_policy = policy.field_policy(field)
        if field_policy.write_disposition is WriteDisposition.DENY:
            reasons.add(WriteDenyReason.FIELD_WRITE_DENIED)
            continue

        field_bits = lane_value << (field_byte * 8)
        field_lane_mask = 0xFF << (field_byte * 8)
        physical_allowed = (
            field_policy.physical_w1c_allow_mask & field_lane_mask
        )
        shadow_allowed = field_policy.shadow_w1c_mask & field_lane_mask
        physical_bits = field_bits & field_policy.physical_w1c_allow_mask
        shadow_bits = field_bits & field_policy.shadow_w1c_mask
        forwarded_request_mask |= (
            physical_allowed >> (field_byte * 8)
        ) << (lane * 8)
        shadow_request_mask |= (
            shadow_allowed >> (field_byte * 8)
        ) << (lane * 8)
        if physical_bits:
            physical_by_field[field] = (
                physical_by_field.get(field, 0) | physical_bits
            )
        if shadow_bits:
            shadow_by_field[field] = shadow_by_field.get(field, 0) | shadow_bits
        if field_bits & ~(
            field_policy.physical_w1c_allow_mask | field_policy.shadow_w1c_mask
        ):
            reasons.add(WriteDenyReason.W1C_BITS_FILTERED)

    physical_writes = tuple(
        PhysicalConfigWrite(
            offset=(
                layout.aer_capability_offset
                if _FIELD_LAYOUT[field][0] == "AER"
                else layout.pcie_capability_offset
            )
            + _FIELD_LAYOUT[field][1],
            width=_FIELD_LAYOUT[field][2],
            value=bits,
            field=field,
            function_role=layout.function_role,
        )
        for field, bits in sorted(
            physical_by_field.items(),
            key=lambda item: (
                _FIELD_LAYOUT[item[0]][0],
                _FIELD_LAYOUT[item[0]][1],
            ),
        )
    )
    shadow_w1c = tuple(
        ShadowW1c(field=field, value=bits)
        for field, bits in sorted(
            shadow_by_field.items(),
            key=lambda item: (
                _FIELD_LAYOUT[item[0]][0],
                _FIELD_LAYOUT[item[0]][1],
            ),
        )
    )
    consumed_request_mask = forwarded_request_mask | shadow_request_mask
    return _GuestConfigWriteDerivation(
        classification=_verified_plan(
            policy=policy,
            layout=layout,
            request_offset=write_offset,
            request_width=width,
            request_value=value,
            physical_writes=physical_writes,
            shadow_w1c=shadow_w1c,
            forwarded_request_mask=forwarded_request_mask,
            shadow_request_mask=shadow_request_mask,
            discarded_request_mask=max_value & ~consumed_request_mask,
            deny_reasons=tuple(sorted(reasons, key=lambda item: item.value)),
        ),
        physical_writes=physical_writes,
    )


def plan_guest_config_write(
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
    write_offset: int,
    width: int,
    value: int,
) -> VerifiedGuestConfigWriteClassification:
    """Classify a guest write without exposing physical offset/value pairs.

    The returned object is deliberately non-executable.  Product code must
    pass it through ``require_pre_vfio_plan`` with independently current owner,
    layout, operation and authority-revision inputs before physical writes can
    be consumed.
    """

    return _derive_guest_config_write(
        policy,
        layout,
        write_offset=write_offset,
        width=width,
        value=value,
    ).classification


def _operation_id(value: object, path: str) -> str:
    if (
        not isinstance(value, str)
        or _OPERATION_ID_RE.fullmatch(value) is None
    ):
        fail(
            "AER_WRITE_OPERATION_INVALID",
            path,
            "expected a closed portable operation identifier",
        )
    return value


def _authority_revision(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 9_007_199_254_740_991
    ):
        fail(
            "AER_WRITE_AUTHORITY_REVISION_INVALID",
            path,
            "expected a positive safe authority revision",
        )
    return value


def require_pre_vfio_plan(
    classification: object,
    policy: VerifiedAerPolicy,
    layout: VerifiedAerConfigLayout,
    *,
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
) -> VerifiedExecutableAerWritePlan:
    """Construct one executable plan only after a current-authority replay."""

    checked_operation_id = _operation_id(operation_id, "operation_id")
    checked_authority_revision = _authority_revision(
        authority_revision,
        "authority_revision",
    )
    replayed_layout = require_current_aer_layout(
        layout,
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
    if (
        not isinstance(
            classification,
            VerifiedGuestConfigWriteClassification,
        )
        or not classification._factory_verified()
        or not isinstance(policy, VerifiedAerPolicy)
        or not policy._factory_verified()
        or classification.aer_policy_digest != policy.aer_policy_digest
        or classification.layout_digest != layout.layout_digest
        or classification.filter_stage != FILTER_BEFORE_VFIO
    ):
        fail(
            "AER_WRITE_PLAN_INVALID",
            "writeClassification",
            (
                "expected a factory classification bound to the current "
                "pre-VFIO policy"
            ),
        )
    replayed_policy = verify_aer_policy(policy.canonical_bytes)
    replayed = _derive_guest_config_write(
        replayed_policy,
        replayed_layout,
        write_offset=classification.request_offset,
        width=classification.request_width,
        value=classification.request_value,
    )
    require(
        classification == replayed.classification,
        "AER_WRITE_PLAN_INVALID",
        "writeClassification",
        (
            "classification does not equal deterministic replay from "
            "canonical current inputs"
        ),
    )
    return VerifiedExecutableAerWritePlan._construct_current_bound(
        _EXECUTABLE_AER_PLAN_FACTORY_TOKEN,
        classification=replayed.classification,
        aer_policy_digest=replayed_policy.aer_policy_digest,
        layout_digest=replayed_layout.layout_digest,
        operation_id=checked_operation_id,
        authority_revision=checked_authority_revision,
        physical_write_count=len(replayed.physical_writes),
        _physical_writes=replayed.physical_writes,
        _consume_state=_AerWriteConsumeState(),
    )


def consume_executable_aer_write(
    plan: object,
    *,
    expected_operation_id: str,
    expected_authority_revision: int,
    expected_aer_policy_digest: str,
    expected_layout_digest: str,
) -> tuple[PhysicalConfigWrite, ...]:
    """Atomically expose one current-bound physical batch exactly once."""

    checked_operation_id = _operation_id(
        expected_operation_id,
        "expected_operation_id",
    )
    checked_authority_revision = _authority_revision(
        expected_authority_revision,
        "expected_authority_revision",
    )
    if (
        not isinstance(plan, VerifiedExecutableAerWritePlan)
        or not plan._factory_verified()
    ):
        fail(
            "AER_EXECUTABLE_WRITE_PLAN_INVALID",
            "executableWritePlan",
            "expected a current-bound VerifiedExecutableAerWritePlan",
        )
    if (
        plan.operation_id != checked_operation_id
        or plan.authority_revision != checked_authority_revision
        or plan.aer_policy_digest != expected_aer_policy_digest
        or plan.layout_digest != expected_layout_digest
    ):
        fail(
            "AER_EXECUTABLE_WRITE_BINDING_MISMATCH",
            "executableWritePlan",
            (
                "operation, authority revision, policy or layout is no longer "
                "current"
            ),
        )
    with plan._consume_state.lock:
        require(
            not plan._consume_state.consumed,
            "AER_EXECUTABLE_WRITE_PLAN_REPLAYED",
            "executableWritePlan",
            "the current-bound physical write plan was already consumed",
        )
        plan._consume_state.consumed = True
        return plan._physical_writes


@dataclass(frozen=True, slots=True)
class ExtCapabilityChainProjection:
    """Read projection that removes AER from discovery without breaking chain."""

    aer_policy_digest: str
    predecessor_offset: int
    successor_offset: int
    projected_predecessor_header: int
    projected_aer_header: int


def project_hidden_ext_cap_chain(
    policy: VerifiedAerPolicy,
    *,
    function_role: AerFunctionRole,
    predecessor_offset: int,
    predecessor_header: int,
    aer_capability_offset: int,
    aer_header: int,
) -> ExtCapabilityChainProjection:
    """Rewire the predecessor Next pointer when the AER header is hidden."""

    if not isinstance(policy, VerifiedAerPolicy) or not policy._factory_verified():
        fail(
            "AER_POLICY_INPUT_INVALID",
            "policy",
            "policy must come from verify_aer_policy",
        )
    if not isinstance(function_role, AerFunctionRole):
        fail(
            "AER_CONFIG_LAYOUT_INVALID",
            "function_role",
            "expected AerFunctionRole",
        )
    require(
        policy.header_exposure is HeaderExposure.HIDDEN,
        "AER_POLICY_COMBINATION_INVALID",
        "aerPolicy.extendedCapability.headerExposure",
        "chain removal is valid only for a hidden header",
    )
    for name, offset in (
        ("predecessor_offset", predecessor_offset),
        ("aer_capability_offset", aer_capability_offset),
    ):
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0x100
            or offset > 0xFFC
            or offset % 4
        ):
            fail(
                "AER_CONFIG_LAYOUT_INVALID",
                name,
                "expected a DWORD-aligned extended-capability offset",
            )
    predecessor = _uint32(predecessor_header, "predecessor_header")
    aer = _uint32(aer_header, "aer_header")
    predecessor_next = (predecessor >> 20) & 0xFFF
    successor = (aer >> 20) & 0xFFF
    mandatory_aer_end = (
        aer_capability_offset + _AER_MANDATORY_EXTENT[function_role]
    )
    require(
        mandatory_aer_end <= 0x1000,
        "AER_CONFIG_LAYOUT_INVALID",
        "aer_capability_offset",
        "the complete mandatory AER layout exceeds 4KiB config",
    )
    require(
        predecessor_offset < aer_capability_offset
        and predecessor_next == aer_capability_offset
        and (aer & 0xFFFF) == 0x0001
        and (
            successor == 0
            or (
                successor >= mandatory_aer_end
                and successor <= 0xFFC
                and successor % 4 == 0
            )
        ),
        "AER_CONFIG_LAYOUT_INVALID",
        "extendedCapabilityChain",
        (
            "predecessor/AER/successor links overlap the mandatory AER body "
            "or are not one valid forward chain"
        ),
    )
    projected_predecessor = (predecessor & 0x000FFFFF) | (successor << 20)
    return ExtCapabilityChainProjection(
        aer_policy_digest=policy.aer_policy_digest,
        predecessor_offset=predecessor_offset,
        successor_offset=successor,
        projected_predecessor_header=projected_predecessor,
        projected_aer_header=0,
    )


__all__ = [
    "AER_CONFIG_LAYOUT_DIGEST_DOMAIN",
    "AER_POLICY_DIGEST_DOMAIN",
    "AerFunctionRole",
    "AerField",
    "AerFieldPolicy",
    "BodyExposure",
    "CORRECTABLE_ERROR_ALLOW_MASK",
    "FILTER_BEFORE_VFIO",
    "ExtCapabilityChainProjection",
    "HeaderExposure",
    "PhysicalConfigWrite",
    "ReadProjection",
    "ReadLaneDisposition",
    "RootSourceReadProjection",
    "ShadowW1c",
    "VerifiedAerPolicy",
    "VerifiedAerConfigLayout",
    "VerifiedExecutableAerWritePlan",
    "VerifiedGuestConfigWriteClassification",
    "VerifiedGuestConfigWritePlan",
    "VerifiedGuestConfigReadProjection",
    "VerifiedGuestProjectedAerSnapshot",
    "WriteDenyReason",
    "WriteDisposition",
    "consume_executable_aer_write",
    "plan_guest_config_write",
    "project_hidden_ext_cap_chain",
    "project_guest_read",
    "project_guest_config_read",
    "project_guest_aer_snapshot",
    "project_guest_root_source_read",
    "require_current_aer_layout",
    "require_pre_vfio_plan",
    "verify_aer_policy",
    "verify_aer_config_layout",
]
