"""Closed IDENTITY-V1 verification for product inventory inputs.

JSON Schema fixes the wire shape and provider registry.  This module enforces
the derivation rules that JSON Schema cannot express: exact source slicing,
provider-specific serial normalization, the domain-separated serial hash, the
identity fingerprint, and the host-scoped device UID.

``VENDOR_QUALIFIED_BYTES_V1`` deliberately fails closed here.  Its canonical
bytes are defined by a separately signed, qualification-bound executable
extractor profile.  Accepting caller-supplied derived bytes without replaying
that extractor would turn a fake provider into product proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any
import unicodedata

from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import fail, require
from ._verified import FactoryVerified


IdentityDocument = Mapping[str, Any] | bytes | bytearray | memoryview

_SERIAL_HASH_DOMAIN = b"QMAN-DIRECTPATH/SERIAL-VALUE/V1\x00"
_SMBIOS_PATH_RE = re.compile(
    r"^smbios-system-slot:/slot-id=(?P<slot>[0-9a-f]{4})"
    r"/designation=(?P<designation>(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+)"
    r"/function=(?P<function>[0-7])$"
)
_RFC3986_UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _document(
    value: IdentityDocument,
    path: str,
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
        except (
            CanonicalizationError,
            KeyError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
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


def _hex_bytes(value: Any, path: str) -> bytes:
    require(
        isinstance(value, str),
        "IDENTITY_SERIAL_MATERIAL_INVALID",
        path,
        "expected lowercase hexadecimal bytes",
    )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        fail("IDENTITY_SERIAL_MATERIAL_INVALID", path, str(exc))
    require(
        decoded.hex() == value,
        "IDENTITY_SERIAL_MATERIAL_INVALID",
        path,
        "hexadecimal bytes are not canonical lowercase text",
    )
    return decoded


def _extract_serial_slice(
    material: Mapping[str, Any],
) -> tuple[bytes, int, bytes]:
    source = _hex_bytes(
        material["sourceBytesHex"],
        "identity.serialMaterial.sourceBytesHex",
    )
    offset = material["extractionOffsetBytes"]
    length = material["extractionLengthBytes"]
    require(
        offset + length <= len(source),
        "IDENTITY_SERIAL_SLICE_INVALID",
        "identity.serialMaterial",
        "declared serial slice exceeds the retained provider source bytes",
    )
    extracted = source[offset : offset + length]
    declared = _hex_bytes(
        material["extractedBytesHex"],
        "identity.serialMaterial.extractedBytesHex",
    )
    require(
        extracted == declared,
        "IDENTITY_SERIAL_SLICE_INVALID",
        "identity.serialMaterial.extractedBytesHex",
        "declared bytes do not equal the exact retained source slice",
    )
    return source, offset, extracted


def _dsn_canonical(source: bytes) -> bytes:
    require(
        len(source) == 8,
        "IDENTITY_SERIAL_TRANSFORM_INVALID",
        "identity.serialMaterial.sourceBytesHex",
        "PCI DSN provider requires exactly eight configuration-space bytes",
    )
    low = int.from_bytes(source[:4], "little")
    high = int.from_bytes(source[4:], "little")
    result = ((high << 32) | low).to_bytes(8, "big")
    require(
        result not in (b"\x00" * 8, b"\xff" * 8),
        "IDENTITY_SERIAL_TRANSFORM_INVALID",
        "identity.serialMaterial.canonicalSerialBytesHex",
        "PCI DSN zero and all-ones values are forbidden",
    )
    return result


def _parse_vpd_serial(source: bytes) -> tuple[int, bytes]:
    """Return the unique PCI VPD read-only-product-data SN value."""

    position = 0
    serials: list[tuple[int, bytes]] = []
    end_seen = False
    while position < len(source):
        tag_offset = position
        tag = source[position]
        position += 1

        if tag & 0x80:
            require(
                position + 2 <= len(source),
                "IDENTITY_VPD_INVALID",
                "identity.serialMaterial.sourceBytesHex",
                "truncated large-resource header",
            )
            length = int.from_bytes(source[position : position + 2], "little")
            position += 2
            payload_start = position
            payload_end = payload_start + length
            require(
                payload_end <= len(source),
                "IDENTITY_VPD_INVALID",
                "identity.serialMaterial.sourceBytesHex",
                "truncated large-resource payload",
            )
            if tag == 0x90:
                keyword = payload_start
                while keyword < payload_end:
                    require(
                        keyword + 3 <= payload_end,
                        "IDENTITY_VPD_INVALID",
                        "identity.serialMaterial.sourceBytesHex",
                        "truncated read-only keyword header",
                    )
                    name = source[keyword : keyword + 2]
                    value_length = source[keyword + 2]
                    value_start = keyword + 3
                    value_end = value_start + value_length
                    require(
                        value_end <= payload_end,
                        "IDENTITY_VPD_INVALID",
                        "identity.serialMaterial.sourceBytesHex",
                        "read-only keyword exceeds its resource payload",
                    )
                    if name == b"SN":
                        serials.append((value_start, source[value_start:value_end]))
                    keyword = value_end
            position = payload_end
            continue

        small_name = (tag >> 3) & 0x0F
        small_length = tag & 0x07
        if small_name == 0x0F:
            require(
                tag == 0x78 and small_length == 0,
                "IDENTITY_VPD_INVALID",
                "identity.serialMaterial.sourceBytesHex",
                "invalid PCI VPD End Tag",
            )
            require(
                position == len(source),
                "IDENTITY_VPD_INVALID",
                "identity.serialMaterial.sourceBytesHex",
                "bytes follow the PCI VPD End Tag",
            )
            end_seen = True
            break
        require(
            position + small_length <= len(source),
            "IDENTITY_VPD_INVALID",
            "identity.serialMaterial.sourceBytesHex",
            f"truncated small resource at byte {tag_offset}",
        )
        position += small_length

    require(
        end_seen,
        "IDENTITY_VPD_INVALID",
        "identity.serialMaterial.sourceBytesHex",
        "complete PCI VPD image has no valid End Tag",
    )
    require(
        len(serials) == 1,
        "IDENTITY_VPD_INVALID",
        "identity.serialMaterial.sourceBytesHex",
        f"expected exactly one read-only SN keyword, found {len(serials)}",
    )
    return serials[0]


def _vpd_canonical(source: bytes) -> tuple[int, bytes, bytes]:
    offset, extracted = _parse_vpd_serial(source)
    try:
        text = extracted.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(
            "IDENTITY_SERIAL_TRANSFORM_INVALID",
            "identity.serialMaterial.extractedBytesHex",
            f"VPD SN is not strict UTF-8: {exc}",
        )
    require(
        all(unicodedata.category(character) != "Cc" for character in text),
        "IDENTITY_SERIAL_TRANSFORM_INVALID",
        "identity.serialMaterial.extractedBytesHex",
        "VPD SN contains a forbidden control character",
    )
    normalized = unicodedata.normalize("NFC", text.strip(" "))
    require(
        bool(normalized),
        "IDENTITY_SERIAL_TRANSFORM_INVALID",
        "identity.serialMaterial.canonicalSerialBytesHex",
        "VPD SN is empty after trimming U+0020",
    )
    return offset, extracted, normalized.encode("utf-8")


def _verify_serial(identity: Mapping[str, Any]) -> str:
    provider = identity["serialProvider"]
    material = identity["serialMaterial"]
    source, offset, extracted = _extract_serial_slice(material)
    provider_id = provider["providerId"]

    if provider_id == "PCI_DSN_EUI64_V1":
        require(
            offset == 0 and extracted == source,
            "IDENTITY_SERIAL_SLICE_INVALID",
            "identity.serialMaterial",
            "PCI DSN must retain and select the complete eight-byte payload",
        )
        canonical = _dsn_canonical(source)
    elif provider_id == "PCI_VPD_SN_UTF8_V1":
        parsed_offset, parsed, canonical = _vpd_canonical(source)
        require(
            offset == parsed_offset and extracted == parsed,
            "IDENTITY_SERIAL_SLICE_INVALID",
            "identity.serialMaterial",
            "declared slice is not the unique PCI VPD read-only SN value",
        )
    elif provider_id == "VENDOR_QUALIFIED_BYTES_V1":
        fail(
            "VENDOR_EXTRACTOR_UNVERIFIED",
            "identity.serialProvider.providerId",
            (
                "vendor-qualified identity requires replay of the separately "
                "signed extractor profile; caller-supplied derived bytes are "
                "not product proof"
            ),
        )
    else:  # The closed schema should reject this first.
        fail(
            "IDENTITY_PROVIDER_UNKNOWN",
            "identity.serialProvider.providerId",
            f"unsupported serial provider {provider_id!r}",
        )

    declared_canonical = _hex_bytes(
        material["canonicalSerialBytesHex"],
        "identity.serialMaterial.canonicalSerialBytesHex",
    )
    require(
        canonical == declared_canonical,
        "IDENTITY_SERIAL_TRANSFORM_INVALID",
        "identity.serialMaterial.canonicalSerialBytesHex",
        "declared canonical serial bytes do not match the provider algorithm",
    )
    expected_hash = sha256_digest(
        _SERIAL_HASH_DOMAIN + provider_id.encode("ascii") + b"\x00" + canonical
    )
    require(
        identity["serialValueHash"] == expected_hash,
        "IDENTITY_SERIAL_HASH_INVALID",
        "identity.serialValueHash",
        f"declared serial hash does not equal {expected_hash}",
    )
    return expected_hash


def _decode_percent_bytes(value: str, path: str) -> bytes:
    result = bytearray()
    position = 0
    while position < len(value):
        character = value[position]
        if character != "%":
            result.append(ord(character))
            position += 1
            continue
        try:
            result.append(int(value[position + 1 : position + 3], 16))
        except (IndexError, ValueError) as exc:
            fail(
                "IDENTITY_PHYSICAL_PATH_INVALID",
                path,
                f"invalid percent-encoded octet: {exc}",
            )
        position += 3
    return bytes(result)


def _encode_rfc3986_bytes(value: bytes) -> str:
    return "".join(
        chr(byte) if byte in _RFC3986_UNRESERVED else f"%{byte:02X}" for byte in value
    )


def _verify_smbios_path(value: str) -> str:
    path = "identity.physicalPath"
    match = _SMBIOS_PATH_RE.fullmatch(value)
    require(
        match is not None,
        "IDENTITY_PHYSICAL_PATH_INVALID",
        path,
        "SMBIOS path does not match the closed provider grammar",
    )
    assert match is not None
    encoded = match.group("designation")
    source = _decode_percent_bytes(encoded, path)
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(
            "IDENTITY_PHYSICAL_PATH_INVALID",
            path,
            f"SMBIOS Slot Designation is not strict UTF-8: {exc}",
        )
    normalized = unicodedata.normalize("NFC", text.strip(" "))
    require(
        bool(normalized),
        "IDENTITY_PHYSICAL_PATH_INVALID",
        path,
        "SMBIOS Slot Designation is empty after trimming U+0020",
    )
    canonical_designation = _encode_rfc3986_bytes(normalized.encode("utf-8"))
    canonical_path = (
        "smbios-system-slot:/slot-id="
        f"{match.group('slot')}/designation={canonical_designation}"
        f"/function={match.group('function')}"
    )
    require(
        value == canonical_path,
        "IDENTITY_PHYSICAL_PATH_NONCANONICAL",
        path,
        f"SMBIOS path is not canonical; expected {canonical_path!r}",
    )
    return canonical_path


def _verify_physical_path(identity: Mapping[str, Any]) -> str:
    value = identity["physicalPath"]
    provider_id = identity["physicalPathProvider"]["providerId"]
    if provider_id == "SMBIOS_SYSTEM_SLOT_V1":
        return _verify_smbios_path(value)
    if provider_id in {
        "ACPI_FIRMWARE_PATH_V1",
        "DEVICETREE_FULL_PATH_V1",
    }:
        # Their closed schema grammars already have one textual spelling for
        # every accepted component and unit-address value.
        return value
    fail(
        "IDENTITY_PROVIDER_UNKNOWN",
        "identity.physicalPathProvider.providerId",
        f"unsupported physical path provider {provider_id!r}",
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedIdentity(FactoryVerified):
    """One schema-valid, derivation-checked immutable device identity."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    identity_fingerprint: str
    device_uid: str
    host_stable_id: str
    identity_variant: str
    function_role: str
    serial_value_hash: str | None
    physical_path: str | None


def verify_identity(
    schemas: ContractSchemas,
    document: IdentityDocument,
) -> VerifiedIdentity:
    """Verify IDENTITY-V1 bytes and return its exact derived identifiers."""

    identity, raw = _document(document, "identity")
    schemas.validate("identity", identity, "identity")

    variant = identity["identityVariant"]
    serial_hash: str | None = None
    physical_path: str | None = None
    if variant == "STRONG_SERIAL":
        serial_hash = _verify_serial(identity)
    elif variant == "SLOT_BOUND":
        physical_path = _verify_physical_path(identity)
    else:  # The closed schema should reject this first.
        fail(
            "IDENTITY_VARIANT_UNKNOWN",
            "identity.identityVariant",
            f"unsupported identity variant {variant!r}",
        )

    fingerprint = sha256_digest(raw)
    host_stable_id = identity["hostStableId"]
    device_uid = f"urn:qman:directpath:device:v1:{host_stable_id}:{fingerprint}"
    return VerifiedIdentity._construct(
        document=_freeze(identity),
        canonical_bytes=raw,
        identity_fingerprint=fingerprint,
        device_uid=device_uid,
        host_stable_id=host_stable_id,
        identity_variant=variant,
        function_role=identity["pciIds"]["functionRole"],
        serial_value_hash=serial_hash,
        physical_path=physical_path,
    )


__all__ = [
    "IdentityDocument",
    "VerifiedIdentity",
    "verify_identity",
]
