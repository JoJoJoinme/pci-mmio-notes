"""Replayable PCI configuration-space structure and FLR facts.

The component accepts either one exact 256-byte conventional PCI configuration
space image or an explicit unavailable disposition.  It performs no sysfs,
VFIO, QEMU, hypervisor, or physical-device I/O.  Consequently its outputs are
component facts, not product authority or proof that a reset is safe to run.

Two independent PCI fields are deliberately kept orthogonal:

* class code bytes 0x09..0x0b are cross-checked against immutable identity;
* Header Type byte 0x0e determines Type-0/Type-1/CardBus layout and its high
  bit determines multifunction status.

FLR capability is replayed from the standard PCI Express conventional
capability (ID 0x10), Device Capabilities dword bit 28.  It is not inferred
from class code, reset method names, technical traits, or Device Capabilities
2.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ._verified import FactoryVerified
from .canonical import canonical_json_bytes, sha256_digest
from .errors import fail, require


PCI_CONFIG_CAPTURE_EVIDENCE_DOMAIN = (
    b"QMAN-DIRECTPATH/PCI-CONFIG-CAPTURE-EVIDENCE/V1\x00"
)
PCI_STRUCTURE_FACT_DOMAIN = b"QMAN-DIRECTPATH/PCI-STRUCTURE-FACT/V1\x00"
PCI_FLR_CAPABILITY_FACT_DOMAIN = (
    b"QMAN-DIRECTPATH/PCI-FLR-CAPABILITY-FACT/V1\x00"
)
PCI_CONFIG_CAPTURE_AUTHORITY_BOUNDARY = (
    "COMPONENT_CALLER_SUPPLIED_RAW_CONFIG_BYTES_ONLY"
)
PCI_CONFIG_CAPTURE_PRODUCT_AUTHORIZED = False

_PCIE_CAPABILITY_ID = 0x10
_PCI_STATUS_CAPABILITIES_LIST = 1 << 4
_PCI_EXP_DEVCAP_FLR = 1 << 28
_ENDPOINT_PORT_TYPES = frozenset(
    {
        "ENDPOINT",
        "LEGACY_ENDPOINT",
        "ROOT_COMPLEX_INTEGRATED_ENDPOINT",
    }
)
_PCIE_PORT_TYPES = {
    0x0: "ENDPOINT",
    0x1: "LEGACY_ENDPOINT",
    0x4: "ROOT_PORT",
    0x5: "UPSTREAM_PORT",
    0x6: "DOWNSTREAM_PORT",
    0x7: "PCIE_TO_PCI_BRIDGE",
    0x8: "PCI_TO_PCIE_BRIDGE",
    0x9: "ROOT_COMPLEX_INTEGRATED_ENDPOINT",
    0xA: "ROOT_COMPLEX_EVENT_COLLECTOR",
}


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _u16(raw: bytes, offset: int) -> int:
    return int.from_bytes(raw[offset : offset + 2], "little")


def _u32(raw: bytes, offset: int) -> int:
    return int.from_bytes(raw[offset : offset + 4], "little")


def _hex16(value: int) -> str:
    return f"{value:04x}"


def _header_layout(raw_header_type: int) -> str:
    layout = raw_header_type & 0x7F
    if layout == 0:
        return "TYPE_0"
    if layout == 1:
        return "TYPE_1"
    if layout == 2:
        return "CARDBUS"
    return "RESERVED"


def _capability_pointer_offset(header_layout: str) -> int:
    if header_layout in {"TYPE_0", "TYPE_1"}:
        return 0x34
    if header_layout == "CARDBUS":
        return 0x14
    fail(
        "PCI_CONFIG_CAPTURE_INVALID",
        "pciStructureFact.rawHeaderTypeByteOrNull",
        "reserved PCI header layout cannot be traversed safely",
    )


def _find_pcie_capability(
    raw: bytes,
    *,
    header_layout: str,
) -> tuple[int | None, int | None, int | None]:
    """Return PCIe capability offset/register/Device Capabilities dword."""

    status = _u16(raw, 0x06)
    if not status & _PCI_STATUS_CAPABILITIES_LIST:
        return None, None, None

    pointer = raw[_capability_pointer_offset(header_layout)]
    require(
        pointer != 0,
        "PCI_CAPABILITY_CHAIN_INVALID",
        "pciStructureFact.rawConfigSpaceHexOrNull",
        "PCI Status advertises a capabilities list but its pointer is zero",
    )
    visited: set[int] = set()
    pcie: tuple[int, int, int] | None = None
    while pointer:
        require(
            0x40 <= pointer <= 0xFC and pointer % 4 == 0,
            "PCI_CAPABILITY_CHAIN_INVALID",
            "pciStructureFact.rawConfigSpaceHexOrNull",
            f"capability pointer 0x{pointer:02x} is outside aligned 0x40..0xfc",
        )
        require(
            pointer not in visited,
            "PCI_CAPABILITY_CHAIN_INVALID",
            "pciStructureFact.rawConfigSpaceHexOrNull",
            f"capability chain contains a cycle at 0x{pointer:02x}",
        )
        visited.add(pointer)
        capability_id = raw[pointer]
        next_pointer = raw[pointer + 1]
        require(
            capability_id not in {0x00, 0xFF},
            "PCI_CAPABILITY_CHAIN_INVALID",
            "pciStructureFact.rawConfigSpaceHexOrNull",
            f"malformed capability ID 0x{capability_id:02x} at 0x{pointer:02x}",
        )
        if capability_id == _PCIE_CAPABILITY_ID:
            require(
                pointer <= 0xF8,
                "PCI_CAPABILITY_CHAIN_INVALID",
                "pciStructureFact.rawConfigSpaceHexOrNull",
                "PCI Express capability is truncated before Device Capabilities",
            )
            require(
                pcie is None,
                "PCI_CAPABILITY_CHAIN_INVALID",
                "pciStructureFact.rawConfigSpaceHexOrNull",
                "multiple PCI Express capabilities are ambiguous",
            )
            capabilities_register = _u16(raw, pointer + 2)
            require(
                capabilities_register & 0xF != 0,
                "PCI_CAPABILITY_CHAIN_INVALID",
                "pciStructureFact.rawConfigSpaceHexOrNull",
                "PCI Express capability version zero is invalid",
            )
            pcie = (
                pointer,
                capabilities_register,
                _u32(raw, pointer + 4),
            )
        if next_pointer:
            require(
                0x40 <= next_pointer <= 0xFC and next_pointer % 4 == 0,
                "PCI_CAPABILITY_CHAIN_INVALID",
                "pciStructureFact.rawConfigSpaceHexOrNull",
                (
                    f"next capability pointer 0x{next_pointer:02x} is "
                    "outside aligned 0x40..0xfc"
                ),
            )
        pointer = next_pointer
    if pcie is None:
        return None, None, None
    return pcie


def _capture_evidence_subject(
    *,
    device_uid: str,
    current_bdf: str,
    captured_at: str,
    provider_fact_id: str,
    provider_id: str,
    provider_version: int,
    provider_definition_digest: str,
    capture_status: str,
    raw_config_space_hex_or_null: str | None,
    raw_config_space_sha256_or_null: str | None,
    failure_reason_code_or_null: str | None,
) -> dict[str, Any]:
    return {
        "subjectType": "PCI_CONFIG_CAPTURE_EVIDENCE",
        "schemaVersion": 1,
        "deviceUid": device_uid,
        "currentBdf": current_bdf,
        "capturedAt": captured_at,
        "providerFactId": provider_fact_id,
        "providerId": provider_id,
        "providerVersion": provider_version,
        "providerDefinitionDigest": provider_definition_digest,
        "captureStatus": capture_status,
        "rawConfigSpaceHexOrNull": raw_config_space_hex_or_null,
        "rawConfigSpaceSha256OrNull": raw_config_space_sha256_or_null,
        "failureReasonCodeOrNull": failure_reason_code_or_null,
    }


def _fact_digest(
    domain: bytes,
    value: Mapping[str, Any],
    digest_field: str,
) -> str:
    projection = copy.deepcopy(dict(value))
    projection[digest_field] = None
    return sha256_digest(domain + canonical_json_bytes(projection))


@dataclass(frozen=True, slots=True, init=False)
class VerifiedPciConfigFacts(FactoryVerified):
    """Factory-only replay result for one DeviceRecord PCI fact pair."""

    structure_fact: Mapping[str, Any]
    flr_fact: Mapping[str, Any]
    provider_fact: Mapping[str, Any]
    raw_config_space: bytes | None
    capture_evidence_digest: str
    structure_fact_digest: str
    flr_fact_digest: str
    header_layout: str
    multifunction: bool | None
    pcie_device_port_type: str | None
    function_level_reset_capable: bool | None


def normalize_pci_config_capture(
    *,
    device_uid: str,
    current_bdf: str,
    captured_at: str,
    provider_fact_id: str,
    provider_id: str,
    provider_version: int,
    provider_definition_digest: str,
    raw_config_space: bytes | bytearray | memoryview | None,
    failure_reason_code: str | None = None,
) -> VerifiedPciConfigFacts:
    """Normalize one retained caller-supplied conventional config capture."""

    require(
        isinstance(device_uid, str) and bool(device_uid),
        "PCI_CONFIG_CAPTURE_INVALID",
        "deviceUid",
        "a non-empty device UID is required",
    )
    require(
        isinstance(current_bdf, str) and bool(current_bdf),
        "PCI_CONFIG_CAPTURE_INVALID",
        "currentBdf",
        "a non-empty current BDF is required",
    )
    require(
        isinstance(captured_at, str) and bool(captured_at),
        "PCI_CONFIG_CAPTURE_INVALID",
        "capturedAt",
        "a retained capture timestamp is required",
    )
    require(
        isinstance(provider_fact_id, str)
        and bool(provider_fact_id)
        and isinstance(provider_id, str)
        and bool(provider_id)
        and isinstance(provider_version, int)
        and not isinstance(provider_version, bool)
        and provider_version > 0
        and isinstance(provider_definition_digest, str),
        "PCI_CONFIG_CAPTURE_INVALID",
        "providerFact",
        "a complete provider identity is required",
    )

    raw: bytes | None
    if raw_config_space is None:
        raw = None
        require(
            isinstance(failure_reason_code, str) and bool(failure_reason_code),
            "PCI_CONFIG_CAPTURE_INVALID",
            "failureReasonCodeOrNull",
            "an unavailable capture requires an explicit stable failure reason",
        )
        capture_status = "UNAVAILABLE"
        raw_hex = None
        raw_sha = None
    else:
        raw = bytes(raw_config_space)
        require(
            len(raw) == 256,
            "PCI_CONFIG_CAPTURE_INVALID",
            "rawConfigSpaceHexOrNull",
            "exactly 256 conventional PCI configuration bytes are required",
        )
        require(
            failure_reason_code is None,
            "PCI_CONFIG_CAPTURE_INVALID",
            "failureReasonCodeOrNull",
            "a complete capture cannot carry a failure reason",
        )
        require(
            raw != b"\xff" * 256 and raw != b"\x00" * 256,
            "PCI_CONFIG_CAPTURE_INVALID",
            "rawConfigSpaceHexOrNull",
            "all-ones or all-zero configuration space is not a present device",
        )
        vendor_id = _u16(raw, 0x00)
        device_id = _u16(raw, 0x02)
        require(
            vendor_id not in {0x0000, 0xFFFF}
            and device_id not in {0x0000, 0xFFFF},
            "PCI_CONFIG_CAPTURE_INVALID",
            "rawConfigSpaceHexOrNull",
            "configuration-space identity is absent or reserved",
        )
        capture_status = "COMPLETE"
        raw_hex = raw.hex()
        raw_sha = sha256_digest(raw)

    capture_subject = _capture_evidence_subject(
        device_uid=device_uid,
        current_bdf=current_bdf,
        captured_at=captured_at,
        provider_fact_id=provider_fact_id,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_definition_digest=provider_definition_digest,
        capture_status=capture_status,
        raw_config_space_hex_or_null=raw_hex,
        raw_config_space_sha256_or_null=raw_sha,
        failure_reason_code_or_null=failure_reason_code,
    )
    capture_evidence_digest = sha256_digest(
        PCI_CONFIG_CAPTURE_EVIDENCE_DOMAIN
        + canonical_json_bytes(capture_subject)
    )
    provider_fact = {
        "factId": provider_fact_id,
        "providerId": provider_id,
        "providerVersion": provider_version,
        "providerDefinitionDigest": provider_definition_digest,
        "observedAt": captured_at,
        "evidenceHash": capture_evidence_digest,
    }

    if raw is None:
        structure_fact: dict[str, Any] = {
            "state": "UNKNOWN",
            "captureStatus": "UNAVAILABLE",
            "providerFactId": provider_fact_id,
            "rawConfigSpaceHexOrNull": None,
            "rawConfigSpaceSha256OrNull": None,
            "failureReasonCodeOrNull": failure_reason_code,
            "captureEvidenceDigest": capture_evidence_digest,
            "vendorIdOrNull": None,
            "deviceIdOrNull": None,
            "revisionIdOrNull": None,
            "classCodeOrNull": None,
            "subsystemVendorIdOrNull": None,
            "subsystemDeviceIdOrNull": None,
            "rawHeaderTypeByteOrNull": None,
            "headerLayout": "UNKNOWN",
            "multifunctionOrNull": None,
            "subordinateBusNumberOrNull": None,
            "subordinateBusPresentOrNull": None,
            "pcieCapabilityState": "UNKNOWN",
            "pcieCapabilityOffsetOrNull": None,
            "pcieCapabilityVersionOrNull": None,
            "pcieDevicePortTypeOrNull": None,
            "rawPcieCapabilitiesRegisterOrNull": None,
            "structureFactDigest": None,
            "authorityBoundary": PCI_CONFIG_CAPTURE_AUTHORITY_BOUNDARY,
            "productAuthorized": PCI_CONFIG_CAPTURE_PRODUCT_AUTHORIZED,
        }
        structure_digest = _fact_digest(
            PCI_STRUCTURE_FACT_DOMAIN,
            structure_fact,
            "structureFactDigest",
        )
        structure_fact["structureFactDigest"] = structure_digest
        flr_fact: dict[str, Any] = {
            "state": "UNKNOWN",
            "structureFactDigest": structure_digest,
            "pcieCapabilityOffsetOrNull": None,
            "deviceCapabilitiesDwordOrNull": None,
            "functionLevelResetCapableOrNull": None,
            "flrFactDigest": None,
        }
    else:
        raw_header = raw[0x0E]
        layout = _header_layout(raw_header)
        pcie_offset, pcie_register, device_capabilities = (
            _find_pcie_capability(raw, header_layout=layout)
        )
        if pcie_offset is None:
            pcie_state = "ABSENT"
            pcie_version = None
            pcie_port_type = None
        else:
            assert pcie_register is not None and device_capabilities is not None
            pcie_state = "PRESENT"
            pcie_version = pcie_register & 0xF
            pcie_port_type = _PCIE_PORT_TYPES.get(
                (pcie_register >> 4) & 0xF,
                "RESERVED",
            )
        type_zero = layout == "TYPE_0"
        structure_fact = {
            "state": "KNOWN",
            "captureStatus": "COMPLETE",
            "providerFactId": provider_fact_id,
            "rawConfigSpaceHexOrNull": raw_hex,
            "rawConfigSpaceSha256OrNull": raw_sha,
            "failureReasonCodeOrNull": None,
            "captureEvidenceDigest": capture_evidence_digest,
            "vendorIdOrNull": _hex16(_u16(raw, 0x00)),
            "deviceIdOrNull": _hex16(_u16(raw, 0x02)),
            "revisionIdOrNull": f"{raw[0x08]:02x}",
            "classCodeOrNull": (
                f"{raw[0x0b]:02x}{raw[0x0a]:02x}{raw[0x09]:02x}"
            ),
            "subsystemVendorIdOrNull": (
                _hex16(_u16(raw, 0x2C)) if type_zero else None
            ),
            "subsystemDeviceIdOrNull": (
                _hex16(_u16(raw, 0x2E)) if type_zero else None
            ),
            "rawHeaderTypeByteOrNull": raw_header,
            "headerLayout": layout,
            "multifunctionOrNull": bool(raw_header & 0x80),
            "subordinateBusNumberOrNull": (
                raw[0x1A] if layout == "TYPE_1" else None
            ),
            "subordinateBusPresentOrNull": layout == "TYPE_1",
            "pcieCapabilityState": pcie_state,
            "pcieCapabilityOffsetOrNull": pcie_offset,
            "pcieCapabilityVersionOrNull": pcie_version,
            "pcieDevicePortTypeOrNull": pcie_port_type,
            "rawPcieCapabilitiesRegisterOrNull": pcie_register,
            "structureFactDigest": None,
            "authorityBoundary": PCI_CONFIG_CAPTURE_AUTHORITY_BOUNDARY,
            "productAuthorized": PCI_CONFIG_CAPTURE_PRODUCT_AUTHORIZED,
        }
        structure_digest = _fact_digest(
            PCI_STRUCTURE_FACT_DOMAIN,
            structure_fact,
            "structureFactDigest",
        )
        structure_fact["structureFactDigest"] = structure_digest
        if pcie_offset is None:
            flr_fact = {
                "state": "ABSENT",
                "structureFactDigest": structure_digest,
                "pcieCapabilityOffsetOrNull": None,
                "deviceCapabilitiesDwordOrNull": None,
                "functionLevelResetCapableOrNull": None,
                "flrFactDigest": None,
            }
        else:
            assert device_capabilities is not None
            flr_fact = {
                "state": "PRESENT",
                "structureFactDigest": structure_digest,
                "pcieCapabilityOffsetOrNull": pcie_offset,
                "deviceCapabilitiesDwordOrNull": device_capabilities,
                "functionLevelResetCapableOrNull": bool(
                    device_capabilities & _PCI_EXP_DEVCAP_FLR
                ),
                "flrFactDigest": None,
            }

    flr_digest = _fact_digest(
        PCI_FLR_CAPABILITY_FACT_DOMAIN,
        flr_fact,
        "flrFactDigest",
    )
    flr_fact["flrFactDigest"] = flr_digest
    return VerifiedPciConfigFacts._construct(
        structure_fact=_freeze(structure_fact),
        flr_fact=_freeze(flr_fact),
        provider_fact=_freeze(provider_fact),
        raw_config_space=raw,
        capture_evidence_digest=capture_evidence_digest,
        structure_fact_digest=structure_digest,
        flr_fact_digest=flr_digest,
        header_layout=structure_fact["headerLayout"],
        multifunction=structure_fact["multifunctionOrNull"],
        pcie_device_port_type=structure_fact["pcieDevicePortTypeOrNull"],
        function_level_reset_capable=flr_fact[
            "functionLevelResetCapableOrNull"
        ],
    )


def _provider_fact(
    provider_facts: Sequence[Mapping[str, Any]],
    fact_id: str,
    *,
    path: str,
) -> Mapping[str, Any]:
    matches = [fact for fact in provider_facts if fact["factId"] == fact_id]
    require(
        len(matches) == 1,
        "PCI_PROVIDER_FACT_INVALID",
        path,
        f"provider fact {fact_id!r} must resolve exactly once",
    )
    return matches[0]


def verify_device_record_pci_facts(
    record: Mapping[str, Any],
    *,
    path: str,
) -> VerifiedPciConfigFacts:
    """Replay and cross-check the complete V3 DeviceRecord PCI fact chain."""

    structure = record["role"]["pciStructureFact"]
    flr = record["resetContract"]["pciFlrCapabilityFact"]
    provider_facts = record["provenance"]["providerFacts"]
    provider = _provider_fact(
        provider_facts,
        structure["providerFactId"],
        path=f"{path}.role.pciStructureFact.providerFactId",
    )
    require(
        record["provenance"]["captureStartedAt"]
        <= provider["observedAt"]
        <= record["provenance"]["capturedAt"],
        "PCI_PROVIDER_FACT_INVALID",
        f"{path}.provenance.providerFacts",
        "PCI provider fact must lie inside the retained capture interval",
    )
    raw_hex = structure["rawConfigSpaceHexOrNull"]
    replayed = normalize_pci_config_capture(
        device_uid=record["deviceUid"],
        current_bdf=record["currentBdf"],
        captured_at=provider["observedAt"],
        provider_fact_id=provider["factId"],
        provider_id=provider["providerId"],
        provider_version=provider["providerVersion"],
        provider_definition_digest=provider["providerDefinitionDigest"],
        raw_config_space=(
            None if raw_hex is None else bytes.fromhex(raw_hex)
        ),
        failure_reason_code=structure["failureReasonCodeOrNull"],
    )
    require(
        canonical_json_bytes(structure)
        == canonical_json_bytes(replayed.structure_fact),
        "PCI_STRUCTURE_FACT_MISMATCH",
        f"{path}.role.pciStructureFact",
        "retained structure fact does not exactly replay from raw bytes",
    )
    require(
        canonical_json_bytes(flr) == canonical_json_bytes(replayed.flr_fact),
        "PCI_FLR_FACT_MISMATCH",
        f"{path}.resetContract.pciFlrCapabilityFact",
        "retained FLR fact does not exactly replay from the structure capture",
    )
    require(
        canonical_json_bytes(provider)
        == canonical_json_bytes(replayed.provider_fact),
        "PCI_PROVIDER_FACT_INVALID",
        f"{path}.provenance.providerFacts",
        "provider fact does not bind the exact replayed raw capture",
    )
    require(
        record["role"]["roleFactsDigest"] == replayed.structure_fact_digest
        and record["role"]["provenanceDigest"]
        == replayed.capture_evidence_digest,
        "PCI_STRUCTURE_FACT_MISMATCH",
        f"{path}.role",
        "role digest/provenance does not bind the replayed PCI structure",
    )

    identity_ids = record["immutableIdentity"]["pciIds"]
    if structure["state"] == "KNOWN":
        for fact_field, identity_field in (
            ("vendorIdOrNull", "vendorId"),
            ("deviceIdOrNull", "deviceId"),
            ("revisionIdOrNull", "revisionId"),
            ("classCodeOrNull", "classCode"),
        ):
            require(
                structure[fact_field] == identity_ids[identity_field],
                "PCI_IDENTITY_MISMATCH",
                f"{path}.role.pciStructureFact.{fact_field}",
                f"raw PCI {fact_field} does not match immutable identity",
            )
        if structure["headerLayout"] == "TYPE_0":
            for fact_field, identity_field in (
                ("subsystemVendorIdOrNull", "subsystemVendorId"),
                ("subsystemDeviceIdOrNull", "subsystemDeviceId"),
            ):
                require(
                    structure[fact_field] == identity_ids[identity_field],
                    "PCI_IDENTITY_MISMATCH",
                    f"{path}.role.pciStructureFact.{fact_field}",
                    f"raw PCI {fact_field} does not match immutable identity",
                )

    structural_role = record["role"]["structuralRole"]
    if structural_role == "ENDPOINT_PAYLOAD":
        require(
            structure["state"] == "KNOWN"
            and structure["headerLayout"] == "TYPE_0"
            and structure["pcieCapabilityState"] == "PRESENT"
            and structure["pcieDevicePortTypeOrNull"] in _ENDPOINT_PORT_TYPES,
            "PCI_PAYLOAD_ROLE_INVALID",
            f"{path}.role.structuralRole",
            (
                "ENDPOINT_PAYLOAD requires a known Type-0 PCIe endpoint "
                "structure; class code is not a structural substitute"
            ),
        )

    reset = record["resetContract"]
    reset_provider = _provider_fact(
        provider_facts,
        reset["resetProviderFactId"],
        path=f"{path}.resetContract.resetProviderFactId",
    )
    require(
        record["provenance"]["captureStartedAt"]
        <= reset_provider["observedAt"]
        <= record["provenance"]["capturedAt"]
        and reset["contractDigest"] == reset_provider["evidenceHash"]
        and reset["provenanceDigest"] == reset_provider["evidenceHash"],
        "PCI_RESET_FACT_INVALID",
        f"{path}.resetContract",
        "reset contract is not bound to exactly one same-capture provider fact",
    )
    if reset["selectedMethodOrNull"] == "PCI_FLR":
        require(
            reset["state"] == "KNOWN"
            and structural_role == "ENDPOINT_PAYLOAD"
            and reset["resetProviderFactId"]
            == structure["providerFactId"]
            and canonical_json_bytes(reset_provider)
            == canonical_json_bytes(replayed.provider_fact)
            and reset_provider["evidenceHash"]
            == replayed.capture_evidence_digest
            and structure["state"] == "KNOWN"
            and structure["headerLayout"] == "TYPE_0"
            and structure["pcieCapabilityState"] == "PRESENT"
            and structure["pcieDevicePortTypeOrNull"] in _ENDPOINT_PORT_TYPES
            and flr["state"] == "PRESENT"
            and flr["functionLevelResetCapableOrNull"] is True,
            "PCI_RESET_FACT_INVALID",
            f"{path}.resetContract.selectedMethodOrNull",
            (
                "PCI_FLR requires the same retained Type-0 PCIe endpoint "
                "capture with Device Capabilities bit 28 set"
            ),
        )
    return replayed


__all__ = [
    "PCI_CONFIG_CAPTURE_AUTHORITY_BOUNDARY",
    "PCI_CONFIG_CAPTURE_EVIDENCE_DOMAIN",
    "PCI_CONFIG_CAPTURE_PRODUCT_AUTHORIZED",
    "PCI_FLR_CAPABILITY_FACT_DOMAIN",
    "PCI_STRUCTURE_FACT_DOMAIN",
    "VerifiedPciConfigFacts",
    "normalize_pci_config_capture",
    "verify_device_record_pci_facts",
]
