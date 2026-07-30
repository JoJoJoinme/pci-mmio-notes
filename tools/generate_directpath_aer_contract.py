#!/usr/bin/env python3
"""Generate the candidate Correctable-only AER component contract.

This generator is intentionally independent from ``qman_directpath_core``.
It materializes every M24-M29 tuple, replays the candidate digest rules, and
emits positive/negative policy vectors.  Successful generation proves only
that these candidate bytes are internally closed; it cannot prove live VFIO
enforcement, E4 provenance, product Case closure, or product authorization.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"

POLICY_SCHEMA = CONTRACTS / "directpath-aer-correctable-policy.schema.json"
MATRIX_SCHEMA = CONTRACTS / "directpath-aer-case-matrix.schema.json"
RECEIPT_SCHEMA = CONTRACTS / "directpath-aer-component-receipt.schema.json"
ALGORITHM_SCHEMA = CONTRACTS / "directpath-aer-verifier-algorithm.schema.json"
MATRIX_OUTPUT = CONTRACTS / "directpath-aer-case-matrix-v1.json"
GOLDEN_OUTPUT = CONTRACTS / "directpath-aer-correctable.golden-vectors.json"
GENERATOR_PATH = ROOT / "tools/generate_directpath_aer_contract.py"
CONFORMANCE_TEST_PATH = (
    ROOT / "qman-directpath-core/tests/test_aer_normative_contract.py"
)
FIXED_SOURCE_PATHS = (
    POLICY_SCHEMA,
    MATRIX_SCHEMA,
    RECEIPT_SCHEMA,
    ALGORITHM_SCHEMA,
    GENERATOR_PATH,
    CONFORMANCE_TEST_PATH,
)

POLICY_DOMAIN = b"QMAN-DIRECTPATH/AER-POLICY/V1\x00"
TUPLE_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-TUPLE/V1\x00"
MATRIX_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-MATRIX/V1\x00"
OWNER_BINDING_DOMAIN = b"QMAN-DIRECTPATH/AER-OWNER-BINDING/V1\x00"
LAYOUT_BINDING_DOMAIN = b"QMAN-DIRECTPATH/AER-LAYOUT-BINDING/V1\x00"
ORACLE_BINDING_DOMAIN = b"QMAN-DIRECTPATH/AER-ORACLE-BINDING/V1\x00"
CASE_RESULT_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-RESULT/V1\x00"
COMPONENT_RECEIPT_DOMAIN = (
    b"QMAN-DIRECTPATH/AER-COMPONENT-RECEIPT/V1\x00"
)
ALGORITHM_DOMAIN = b"QMAN-DIRECTPATH/AER-VERIFIER-ALGORITHM/V1\x00"
GOLDEN_DOMAIN = b"QMAN-DIRECTPATH/AER-GOLDEN-VECTORS/V1\x00"

CORRECTABLE_BITS = [1, 64, 128, 256, 4096, 8192, 16384, 32768]
CORRECTABLE_ERROR_ALLOW_MASK = 0x0000F1C1
REQUIRED_CASE_IDS = ["M24", "M25", "M26", "M27", "M28", "M29"]
REQUIRED_DIMENSIONS = [
    "GUEST_WRITES",
    "IRQ_DELIVERY",
    "SERVICE_ATTRIBUTION",
    "DEVICE_HEALTH",
    "PHYSICAL_RECOVERY",
]
CASE_TUPLE_COUNTS = {
    "M24": 8,
    "M25": 64,
    "M26": 24,
    "M27": 9,
    "M28": 15,
    "M29": 13,
}
VALIDATION_STAGES = [
    "RESOURCE_BUDGETS",
    "DUPLICATE_SAFE_JSON_PARSE",
    "SCHEMA_CLOSURE",
    "FIXED_BUNDLE_REPLAY",
    "POLICY_SEMANTIC_MASKS",
    "POLICY_DIGEST_REPLAY",
    "MATRIX_TUPLE_DIGEST_REPLAY",
    "MATRIX_COVERAGE_EXACT",
    "OWNER_LAYOUT_BINDING",
    "ORACLE_STATE_BOUNDARY",
    "CASE_RESULT_EXACTNESS",
    "DIMENSION_CLEANUP_REUSE",
    "ARTIFACT_AUTHORITY_BOUNDARY",
    "COMPONENT_RECEIPT_DIGEST_REPLAY",
    "PRODUCT_AUTHORIZATION_HARD_FALSE",
]

RESOURCE_BUDGETS = {
    "policyMaxBytes": 65_536,
    "matrixMaxBytes": 524_288,
    "goldenMaxBytes": 524_288,
    "receiptMaxBytes": 2_097_152,
    "schemaMaxBytes": 1_048_576,
    "boundFileMaxBytes": 1_048_576,
    "maxNodes": 100_000,
    "maxDepth": 32,
    "maxStringUtf8Bytes": 4_096,
    "maxTotalStringUtf8Bytes": 8_388_608,
}

FIELD_ORDER = [
    "PCIE_DEVICE_CONTROL",
    "PCIE_DEVICE_STATUS",
    "CORRECTABLE_ERROR_STATUS",
    "CORRECTABLE_ERROR_MASK",
    "ROOT_ERROR_COMMAND",
    "ROOT_ERROR_STATUS",
    "ERROR_SOURCE_ID",
]
FIELD_READ_ALLOW_MASKS = {
    "PCIE_DEVICE_CONTROL": 0x1,
    "PCIE_DEVICE_STATUS": 0x1,
    "CORRECTABLE_ERROR_STATUS": CORRECTABLE_ERROR_ALLOW_MASK,
    "CORRECTABLE_ERROR_MASK": CORRECTABLE_ERROR_ALLOW_MASK,
    "ROOT_ERROR_COMMAND": 0x1,
    "ROOT_ERROR_STATUS": 0x3,
    "ERROR_SOURCE_ID": 0xFFFF,
}
FIELD_W1C_ALLOW_MASKS = {
    "PCIE_DEVICE_STATUS": 0x1,
    "CORRECTABLE_ERROR_STATUS": CORRECTABLE_ERROR_ALLOW_MASK,
    "ROOT_ERROR_STATUS": 0x3,
}
AER_BODY_FIELDS = {
    "CORRECTABLE_ERROR_STATUS",
    "CORRECTABLE_ERROR_MASK",
    "ROOT_ERROR_COMMAND",
    "ROOT_ERROR_STATUS",
    "ERROR_SOURCE_ID",
}
RESULT_PRECEDENCE = (
    "MISMATCH",
    "INCONCLUSIVE",
    "CANDIDATE",
    "MATCH",
)


def aggregate_results(results: list[str]) -> str:
    if not results:
        raise ValueError("cannot aggregate an empty result set")
    unknown = set(results) - set(RESULT_PRECEDENCE)
    if unknown:
        raise ValueError(f"unknown result classification: {sorted(unknown)!r}")
    return next(
        result
        for result in RESULT_PRECEDENCE
        if result in results
    )


def structural_deny_reasons(classification: str) -> list[str]:
    reasons = {
        "AUTHORITY_RECEIPT_UNAVAILABLE",
        "CLEANUP_UNVERIFIED",
        "DIMENSION_UNVERIFIED",
        "REUSE_UNVERIFIED",
    }
    if classification == "MISMATCH":
        reasons.add("REFERENCE_MISMATCH")
    return sorted(reasons)


def render(value: Any) -> bytes:
    """Render review-friendly deterministic JSON."""

    return (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")


class DuplicateKeyError(ValueError):
    """A JSON object attempted to replace an earlier member."""


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-JSON numeric constant {token!r}")


def _enforce_tree_budgets(value: Any, label: str) -> None:
    node_count = 0
    total_string_bytes = 0
    stack: list[tuple[Any, int, str]] = [(value, 1, "$")]
    while stack:
        item, depth, path = stack.pop()
        node_count += 1
        if node_count > RESOURCE_BUDGETS["maxNodes"]:
            raise ValueError(f"{label}: node budget exceeded")
        if depth > RESOURCE_BUDGETS["maxDepth"]:
            raise ValueError(f"{label}: depth budget exceeded at {path}")
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if abs(item) > 9_007_199_254_740_991:
                raise ValueError(f"{label}: unsafe integer at {path}")
            continue
        if isinstance(item, float):
            raise ValueError(f"{label}: floating-point value at {path}")
        if isinstance(item, str):
            encoded_length = len(item.encode("utf-8", errors="strict"))
            if encoded_length > RESOURCE_BUDGETS["maxStringUtf8Bytes"]:
                raise ValueError(f"{label}: string budget exceeded at {path}")
            total_string_bytes += encoded_length
            if (
                total_string_bytes
                > RESOURCE_BUDGETS["maxTotalStringUtf8Bytes"]
            ):
                raise ValueError(f"{label}: total string budget exceeded")
            continue
        if isinstance(item, list):
            stack.extend(
                (child, depth + 1, f"{path}[{index}]")
                for index, child in reversed(list(enumerate(item)))
            )
            continue
        if isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                stack.append((child, depth + 1, f"{path}.{key}"))
                stack.append((key, depth + 1, f"{path}.<key>"))
            continue
        raise ValueError(
            f"{label}: unsupported JSON type {type(item).__name__} at {path}"
        )


def _preflight_json_tokens(text: str, label: str) -> None:
    """Bound depth, nodes and strings before constructing a JSON tree."""

    depth = 0
    nodes = 0
    total_string_bytes = 0
    index = 0
    length = len(text)
    delimiters = frozenset(" \t\r\n,:{}[]")
    while index < length:
        token = text[index]
        if token in " \t\r\n,:":
            index += 1
            continue
        if token in "{[":
            nodes += 1
            if nodes > RESOURCE_BUDGETS["maxNodes"]:
                raise ValueError(f"{label}: node budget exceeded")
            depth += 1
            if depth > RESOURCE_BUDGETS["maxDepth"]:
                raise ValueError(f"{label}: depth budget exceeded")
            index += 1
            continue
        if token in "}]":
            depth -= 1
            index += 1
            continue
        if token == '"':
            nodes += 1
            if nodes > RESOURCE_BUDGETS["maxNodes"]:
                raise ValueError(f"{label}: node budget exceeded")
            string_bytes = 0
            index += 1
            while index < length:
                character = text[index]
                if character == '"':
                    index += 1
                    break
                if character == "\\":
                    index += 1
                    if index >= length:
                        raise ValueError(f"{label}: incomplete JSON escape")
                    escape = text[index]
                    if escape == "u":
                        if index + 4 >= length:
                            raise ValueError(
                                f"{label}: incomplete Unicode escape"
                            )
                        digits = text[index + 1 : index + 5]
                        if any(
                            item not in "0123456789abcdefABCDEF"
                            for item in digits
                        ):
                            raise ValueError(
                                f"{label}: invalid Unicode escape"
                            )
                        string_bytes += 4
                        index += 5
                    else:
                        string_bytes += 1
                        index += 1
                else:
                    string_bytes += len(
                        character.encode("utf-8", errors="strict")
                    )
                    index += 1
                if (
                    string_bytes
                    > RESOURCE_BUDGETS["maxStringUtf8Bytes"]
                ):
                    raise ValueError(
                        f"{label}: string budget exceeded"
                    )
            else:
                raise ValueError(f"{label}: unterminated JSON string")
            total_string_bytes += string_bytes
            if (
                total_string_bytes
                > RESOURCE_BUDGETS["maxTotalStringUtf8Bytes"]
            ):
                raise ValueError(f"{label}: total string budget exceeded")
        else:
            nodes += 1
            if nodes > RESOURCE_BUDGETS["maxNodes"]:
                raise ValueError(f"{label}: node budget exceeded")
            while index < length and text[index] not in delimiters:
                index += 1


def parse_bounded_json(
    raw: bytes,
    *,
    label: str,
    max_bytes: int,
) -> dict[str, Any]:
    """Apply the byte budget before parsing, then all structural budgets."""

    if type(raw) is not bytes:
        raise TypeError(f"{label}: expected immutable raw bytes")
    if len(raw) > max_bytes:
        raise ValueError(f"{label}: byte budget exceeded")
    try:
        text = raw.decode("utf-8", errors="strict")
        _preflight_json_tokens(text, label)
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}: invalid UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label}: root must be a JSON object")
    _enforce_tree_budgets(value, label)
    return value


@dataclass(frozen=True, slots=True)
class ContractSourceSnapshot:
    """One immutable read of every file that defines verifier identity."""

    entries: tuple[tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple:
            raise TypeError("source snapshot entries must be an exact tuple")
        expected_paths = tuple(
            path.relative_to(ROOT).as_posix()
            for path in FIXED_SOURCE_PATHS
        )
        if len(self.entries) != len(expected_paths):
            raise ValueError("source snapshot path coverage is not exact")
        for ordinal, (entry, expected_path) in enumerate(
            zip(self.entries, expected_paths, strict=True)
        ):
            if type(entry) is not tuple or len(entry) != 2:
                raise TypeError(
                    f"source snapshot entry {ordinal} must be an exact pair"
                )
            relative, payload = entry
            if type(relative) is not str:
                raise TypeError(
                    f"source snapshot path {ordinal} is not an exact string"
                )
            if relative != expected_path:
                raise ValueError(
                    f"source snapshot path order drift at {ordinal}"
                )
            if type(payload) is not bytes:
                raise TypeError(
                    f"source snapshot payload {relative} is not exact bytes"
                )

    def raw(self, path: Path) -> bytes:
        relative = path.relative_to(ROOT).as_posix()
        for candidate, payload in self.entries:
            if candidate == relative:
                return payload
        raise ValueError(f"source snapshot is missing {relative}")

    def digest(self, path: Path) -> str:
        return sha256_digest(self.raw(path))

    def json_schema(self, path: Path) -> dict[str, Any]:
        return parse_bounded_json(
            self.raw(path),
            label=path.relative_to(ROOT).as_posix(),
            max_bytes=RESOURCE_BUDGETS["schemaMaxBytes"],
        )


def capture_source_snapshot() -> ContractSourceSnapshot:
    entries: list[tuple[str, bytes]] = []
    for path in FIXED_SOURCE_PATHS:
        max_bytes = RESOURCE_BUDGETS["boundFileMaxBytes"]
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(
                f"{path.relative_to(ROOT).as_posix()}: byte budget exceeded"
            )
        entries.append((path.relative_to(ROOT).as_posix(), raw))
    return ContractSourceSnapshot(entries=tuple(entries))


def _validate_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError(f"{path}: integer is outside the JSON safe range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floating-point values are forbidden")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError(f"{path}: string is not Unicode NFC")
        value.encode("utf-8", errors="strict")
        value.encode("utf-16-be", errors="strict")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object key is not a string")
            _validate_canonical_value(key, f"{path}.<key>")
            _validate_canonical_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the generated ASCII-keyed objects as CANONICAL-JSON-V1."""

    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def null_hash(
    document: dict[str, Any],
    digest_member: str,
    domain: bytes,
) -> str:
    projection = copy.deepcopy(document)
    projection[digest_member] = None
    return sha256_digest(domain + canonical_json_bytes(projection))


def _field(
    read_projection: str,
    read_mask: int,
    write_disposition: str = "DENY",
    physical_w1c: int = 0,
    shadow_w1c: int = 0,
) -> dict[str, Any]:
    return {
        "readProjection": read_projection,
        "guestReadAllowMask": read_mask,
        "writeDisposition": write_disposition,
        "physicalW1cAllowMask": physical_w1c,
        "shadowW1cMask": shadow_w1c,
    }


def _base_policy(policy_id: str) -> dict[str, Any]:
    return {
        "subjectType": "QMAN_AER_POLICY",
        "schemaVersion": 1,
        "policyId": policy_id,
        "correctableOnly": True,
        "extendedCapability": {
            "headerExposure": "VISIBLE",
            "bodyExposure": "VISIBLE",
            "hiddenBodyReadProjection": "ZERO",
        },
        "writePipeline": "FILTER_BEFORE_VFIO",
        "unknownFieldAction": "DENY",
        "fields": {
            "PCIE_DEVICE_CONTROL": _field("PHYSICAL", 0x1),
            "PCIE_DEVICE_STATUS": _field(
                "PHYSICAL",
                0x1,
                "FILTERED_W1C",
                physical_w1c=0x1,
            ),
            "CORRECTABLE_ERROR_STATUS": _field(
                "PHYSICAL",
                CORRECTABLE_ERROR_ALLOW_MASK,
                "FILTERED_W1C",
                physical_w1c=CORRECTABLE_ERROR_ALLOW_MASK,
            ),
            "CORRECTABLE_ERROR_MASK": _field(
                "PHYSICAL",
                CORRECTABLE_ERROR_ALLOW_MASK,
            ),
            "ROOT_ERROR_COMMAND": _field("PHYSICAL", 0x1),
            "ROOT_ERROR_STATUS": _field(
                "PHYSICAL",
                0x3,
                "FILTERED_W1C",
                physical_w1c=0x3,
            ),
            "ERROR_SOURCE_ID": _field("PHYSICAL", 0xFFFF),
        },
        "aerPolicyDigest": None,
    }


def _finalize_policy(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result["aerPolicyDigest"] = null_hash(
        result,
        "aerPolicyDigest",
        POLICY_DOMAIN,
    )
    return result


def positive_policy_documents() -> list[tuple[str, dict[str, Any]]]:
    visible = _base_policy("qman-aer-visible-physical-v1")

    hidden_zero = _base_policy("qman-aer-hidden-zero-deny-v1")
    hidden_zero["extendedCapability"] = {
        "headerExposure": "VISIBLE",
        "bodyExposure": "HIDDEN",
        "hiddenBodyReadProjection": "ZERO",
    }
    for field in hidden_zero["fields"].values():
        field["writeDisposition"] = "DENY"
        field["physicalW1cAllowMask"] = 0
        field["shadowW1cMask"] = 0

    hidden_shadow = _base_policy("qman-aer-hidden-shadow-v1")
    hidden_shadow["extendedCapability"] = {
        "headerExposure": "HIDDEN",
        "bodyExposure": "HIDDEN",
        "hiddenBodyReadProjection": "SHADOW",
    }
    for name in (
        "PCIE_DEVICE_STATUS",
        "CORRECTABLE_ERROR_STATUS",
        "ROOT_ERROR_STATUS",
    ):
        field = hidden_shadow["fields"][name]
        field["readProjection"] = "SHADOW"
        field["physicalW1cAllowMask"] = 0
        field["shadowW1cMask"] = FIELD_W1C_ALLOW_MASKS[name]

    return [
        ("VISIBLE_PHYSICAL_FILTERED_W1C", _finalize_policy(visible)),
        ("HIDDEN_ZERO_DENY", _finalize_policy(hidden_zero)),
        ("HIDDEN_SHADOW_FILTERED_W1C", _finalize_policy(hidden_shadow)),
    ]


def _mutated_policy(
    source: dict[str, Any],
    vector_id: str,
    mutate: Any,
) -> tuple[str, dict[str, Any]]:
    document = copy.deepcopy(source)
    document["policyId"] = f"negative-{vector_id.lower().replace('_', '-')}"
    mutate(document)
    return vector_id, _finalize_policy(document)


def negative_policy_documents() -> list[tuple[str, dict[str, Any], str]]:
    source = _base_policy("unused-negative-source")
    mutations = [
        (
            "UNCORRECTABLE_MODE_FORBIDDEN",
            lambda value: value.__setitem__("correctableOnly", False),
            "AER_UNCORRECTABLE_FORBIDDEN",
        ),
        (
            "VFIO_BEFORE_FILTER_FORBIDDEN",
            lambda value: value.__setitem__(
                "writePipeline",
                "VFIO_BEFORE_FILTER",
            ),
            "AER_WRITE_ORDER_INVALID",
        ),
        (
            "UNKNOWN_FIELD_ALLOW_FORBIDDEN",
            lambda value: value.__setitem__("unknownFieldAction", "ALLOW"),
            "AER_UNKNOWN_FIELD_POLICY_INVALID",
        ),
        (
            "PHYSICAL_SHADOW_W1C_OVERLAP",
            lambda value: value["fields"][
                "CORRECTABLE_ERROR_STATUS"
            ].__setitem__("shadowW1cMask", CORRECTABLE_ERROR_ALLOW_MASK),
            "AER_W1C_MASK_OVERLAP",
        ),
        (
            "HIDDEN_BODY_PHYSICAL_WRITE_LEAK",
            lambda value: value["extendedCapability"].__setitem__(
                "bodyExposure",
                "HIDDEN",
            ),
            "AER_HIDDEN_WRITE_LEAK",
        ),
    ]
    result: list[tuple[str, dict[str, Any], str]] = []
    for vector_id, mutate, error_code in mutations:
        item_id, document = _mutated_policy(source, vector_id, mutate)
        result.append((item_id, document, error_code))
    return result


def policy_semantic_error(document: dict[str, Any]) -> str | None:
    """Return the first candidate verifier error without target-code imports."""

    if document.get("correctableOnly") is not True:
        return "AER_UNCORRECTABLE_FORBIDDEN"
    if document.get("writePipeline") != "FILTER_BEFORE_VFIO":
        return "AER_WRITE_ORDER_INVALID"
    if document.get("unknownFieldAction") != "DENY":
        return "AER_UNKNOWN_FIELD_POLICY_INVALID"
    extended = document.get("extendedCapability")
    if not isinstance(extended, dict):
        return "AER_POLICY_SHAPE_INVALID"
    body_exposure = extended.get("bodyExposure")
    hidden_projection = extended.get("hiddenBodyReadProjection")
    fields = document.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(FIELD_ORDER):
        return "AER_POLICY_SHAPE_INVALID"

    effective_reads: dict[str, str] = {}
    for name in FIELD_ORDER:
        field = fields.get(name)
        if not isinstance(field, dict):
            return "AER_POLICY_SHAPE_INVALID"
        read_mask = field.get("guestReadAllowMask")
        physical = field.get("physicalW1cAllowMask")
        shadow = field.get("shadowW1cMask")
        if not all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in (read_mask, physical, shadow)
        ):
            return "AER_VALUE_INVALID"
        if read_mask & ~FIELD_READ_ALLOW_MASKS[name]:
            return "AER_READ_MASK_INVALID"
        if physical & shadow:
            return "AER_W1C_MASK_OVERLAP"
        if physical and shadow:
            return "AER_POLICY_COMBINATION_INVALID"
        allowed_w1c = FIELD_W1C_ALLOW_MASKS.get(name, 0)
        if (physical | shadow) & ~allowed_w1c:
            return "AER_W1C_MASK_INVALID"
        if (physical | shadow) & ~read_mask:
            return "AER_W1C_MASK_NOT_READABLE"
        disposition = field.get("writeDisposition")
        if disposition == "DENY" and (physical or shadow):
            return "AER_W1C_MASK_INVALID"
        if disposition == "FILTERED_W1C" and (
            name not in FIELD_W1C_ALLOW_MASKS or not (physical or shadow)
        ):
            return "AER_W1C_FIELD_INVALID"
        effective = field.get("readProjection")
        if body_exposure == "HIDDEN" and name in AER_BODY_FIELDS:
            effective = hidden_projection
            if physical:
                return "AER_HIDDEN_WRITE_LEAK"
        if physical and effective != "PHYSICAL":
            return "AER_POLICY_COMBINATION_INVALID"
        if shadow and effective != "SHADOW":
            return "AER_POLICY_COMBINATION_INVALID"
        effective_reads[name] = str(effective)
    if (
        effective_reads["ERROR_SOURCE_ID"]
        != effective_reads["ROOT_ERROR_STATUS"]
    ):
        return "AER_POLICY_COMBINATION_INVALID"
    if document.get("aerPolicyDigest") != null_hash(
        document,
        "aerPolicyDigest",
        POLICY_DOMAIN,
    ):
        return "AER_POLICY_DIGEST_INVALID"
    return None


def _finalize_tuple(document: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result["tupleDigest"] = null_hash(result, "tupleDigest", TUPLE_DOMAIN)
    return result


def _m24_tuples() -> list[dict[str, Any]]:
    result = []
    for bit_index, bit in enumerate(CORRECTABLE_BITS):
        result.append(
            _finalize_tuple(
                {
                    "tupleId": f"M24-B{bit_index}",
                    "caseId": "M24",
                    "ordinal": bit_index + 1,
                    "scenario": (
                        "CORRECTABLE_DEPOSITION_AND_INDEPENDENT_ENDPOINT_W1C"
                    ),
                    "correctableBit": bit,
                    "endpointCere": False,
                    "controlledBitMasked": False,
                    "rootCorEnabled": False,
                    "expectedEndpointDeposition": True,
                    "expectedRootDeposition": False,
                    "expectedIndependentCesCedW1c": True,
                    "expectedOwnerPhases": ["O4"],
                    "expectedLayoutRoles": ["ENDPOINT"],
                    "tupleDigest": None,
                }
            )
        )
    return result


def _m25_tuples() -> list[dict[str, Any]]:
    result = []
    ordinal = 1
    for bit_index, bit in enumerate(CORRECTABLE_BITS):
        for endpoint_cere in (False, True):
            for controlled_bit_masked in (False, True):
                for root_cor_enabled in (False, True):
                    root_deposition = (
                        endpoint_cere and not controlled_bit_masked
                    )
                    gate = "".join(
                        "1" if value else "0"
                        for value in (
                            endpoint_cere,
                            controlled_bit_masked,
                            root_cor_enabled,
                        )
                    )
                    result.append(
                        _finalize_tuple(
                            {
                                "tupleId": (
                                    f"M25-B{bit_index}-G{gate}"
                                ),
                                "caseId": "M25",
                                "ordinal": ordinal,
                                "scenario": "E_M_R_ROUTE_TRUTH_TABLE",
                                "correctableBit": bit,
                                "endpointCere": endpoint_cere,
                                "controlledBitMasked": (
                                    controlled_bit_masked
                                ),
                                "rootCorEnabled": root_cor_enabled,
                                "expectedRootDeposition": root_deposition,
                                "expectedNotificationEligible": (
                                    root_deposition and root_cor_enabled
                                ),
                                "expectedOwnerPhases": ["O4"],
                                "expectedLayoutRoles": [
                                    "ENDPOINT",
                                    "ROOT_PORT",
                                ],
                                "tupleDigest": None,
                            }
                        )
                    )
                    ordinal += 1
    return result


def _m26_tuples() -> list[dict[str, Any]]:
    result = []
    ordinal = 1
    owners = [
        ("O0", "HOST_OWNED_IDLE"),
        ("O4", "ACTIVE_DIRECTPATH"),
    ]
    sequences = [
        "FIRST_MULTIPLE",
        "INDEPENDENT_W1C",
        "BIT_OR",
        "REARM",
    ]
    for owner_phase, semantic_class in owners:
        for sequence in sequences:
            for repeat_index in range(1, 4):
                result.append(
                    _finalize_tuple(
                        {
                            "tupleId": (
                                f"M26-{owner_phase}-{sequence}"
                                f"-R{repeat_index:02d}"
                            ),
                            "caseId": "M26",
                            "ordinal": ordinal,
                            "scenario": "RETAINED_ROOT_SEQUENCE",
                            "referenceOwnerPhase": owner_phase,
                            "ownerSemanticClass": semantic_class,
                            "gateId": "g101",
                            "gate": {
                                "endpointCere": True,
                                "controlledBitMasked": False,
                                "rootCorEnabled": True,
                            },
                            "sequence": sequence,
                            "repeatIndex": repeat_index,
                            "minimumRepeatCount": 3,
                            "sourceSemanticPolicy": (
                                "MEANINGFUL_ONLY_WHEN_ROOT_COR_RCV_SET"
                            ),
                            "expectedOwnerPhases": [owner_phase],
                            "expectedLayoutRoles": ["ROOT_PORT"],
                            "tupleDigest": None,
                        }
                    )
                )
                ordinal += 1
    return result


def _m27_tuples() -> list[dict[str, Any]]:
    rows = [
        ("DIRTY_CLEANUP_QUARANTINES", "QUARANTINED"),
        ("PHYSICAL_CLEAR_CLEANUP_VERIFIED", "CLEANUP_VERIFIED"),
        ("SHADOW_REQUIRES_HOST_CLEANUP", "CLEANUP_VERIFIED"),
        ("CLEANUP_THEN_REUSE_PASS", "REUSABLE"),
        ("CLEANUP_THEN_REUSE_FAIL", "QUARANTINED"),
        ("STALE_ASSIGNMENT_DENIED", "DENIED"),
        ("STALE_LEASE_DENIED", "DENIED"),
        ("STALE_OWNER_EPOCH_DENIED", "DENIED"),
        ("STALE_BOOT_DENIED", "DENIED"),
    ]
    return [
        _finalize_tuple(
            {
                "tupleId": f"M27-T{index}",
                "caseId": "M27",
                "ordinal": index + 1,
                "scenario": scenario,
                "expectedOutcome": outcome,
                "expectedOwnerPhases": ["O0", "O4"],
                "expectedLayoutRoles": ["ENDPOINT", "ROOT_PORT"],
                "tupleDigest": None,
            }
        )
        for index, (scenario, outcome) in enumerate(rows)
    ]


def _m28_tuples() -> list[dict[str, Any]]:
    rows = [
        ("ENDPOINT_BYTE_LANE_W1C", "ENDPOINT", "FILTERED"),
        ("UNALIGNED_MULTI_BYTE_W1C", "ENDPOINT", "FILTERED"),
        ("ENDPOINT_ROOT_FIELD_DENIED", "ENDPOINT", "DENIED"),
        ("ROOT_STATUS_W1C_FILTERED", "ROOT_PORT", "FILTERED"),
        ("ENDPOINT_READ_MASKED", "ENDPOINT", "PROJECTED"),
        ("ROOT_READ_MASKED", "ROOT_PORT", "PROJECTED"),
        ("UNCORRECTABLE_READ_ZEROED", "BOTH", "ZEROED"),
        ("UNKNOWN_READ_ZEROED", "BOTH", "ZEROED"),
        ("MISSING_READ_ZEROED", "BOTH", "ZEROED"),
        ("UNCORRECTABLE_WRITE_DENIED", "BOTH", "DENIED"),
        (
            "HIDDEN_HEADER_VISIBLE_BODY_REWIRED",
            "NOT_APPLICABLE",
            "REWIRED",
        ),
        ("HIDDEN_BODY_ZERO", "BOTH", "ZEROED"),
        ("HIDDEN_BODY_SHADOW", "BOTH", "SHADOWED"),
        ("FORGED_PLAN_REJECTED", "NOT_APPLICABLE", "REJECTED"),
        ("STALE_LAYOUT_REJECTED", "BOTH", "REJECTED"),
    ]
    return [
        _finalize_tuple(
            {
                "tupleId": f"M28-T{index:02d}",
                "caseId": "M28",
                "ordinal": index + 1,
                "scenario": scenario,
                "functionRole": function_role,
                "expectedOutcome": outcome,
                "expectedOwnerPhases": ["O4"],
                "expectedLayoutRoles": (
                    ["ENDPOINT"]
                    if function_role == "ENDPOINT"
                    else (
                        ["ROOT_PORT"]
                        if function_role == "ROOT_PORT"
                        else ["ENDPOINT", "ROOT_PORT"]
                    )
                ),
                "tupleDigest": None,
            }
        )
        for index, (scenario, function_role, outcome) in enumerate(rows)
    ]


def _m29_tuples() -> list[dict[str, Any]]:
    rows = [
        (
            "MISSING_INPUT_DENIED",
            "NOT_APPLICABLE",
            False,
            "MISSING_INPUT",
        ),
        ("EXACT_COMPONENT_PREMISE", "MATCH", True, None),
        (
            "FAKE_REPLAYER_CANNOT_AUTHORIZE_PRODUCT",
            "MATCH",
            False,
            "PRODUCT_AUTHORIZATION_ATTEMPTED",
        ),
        (
            "CANDIDATE_DENIED",
            "CANDIDATE",
            False,
            "EVIDENCE_NOT_AUTHORITATIVE",
        ),
        (
            "INCONCLUSIVE_DENIED",
            "INCONCLUSIVE",
            False,
            "DIMENSION_UNVERIFIED",
        ),
        (
            "NESTED_CANNOT_CLAIM_PHYSICAL",
            "CANDIDATE",
            False,
            "PHYSICAL_E4_REQUIRED",
        ),
        ("CONTAINMENT_LANES_INDEPENDENT", "MATCH", True, None),
        (
            "CASE_SET_INCOMPLETE",
            "INCONCLUSIVE",
            False,
            "REQUIRED_CASES_INCOMPLETE",
        ),
        (
            "DIGEST_TAMPER_DENIED",
            "MISMATCH",
            False,
            "DIGEST_INVALID",
        ),
        (
            "EXPIRED_AUTHORITY_DENIED",
            "INCONCLUSIVE",
            False,
            "STALE_AUTHORITY_REJECTED",
        ),
        (
            "LAYOUT_CHANGE_DENIED",
            "MISMATCH",
            False,
            "CONFIG_LAYOUT_MISMATCH",
        ),
        (
            "DIMENSION_UNKNOWN_DENIED",
            "INCONCLUSIVE",
            False,
            "DIMENSION_UNVERIFIED",
        ),
        (
            "CLEANUP_REUSE_RESET_QUARANTINE_DENIED",
            "INCONCLUSIVE",
            False,
            "LIFECYCLE_GATE_FAILED",
        ),
    ]
    return [
        _finalize_tuple(
            {
                "tupleId": f"M29-T{index:02d}",
                "caseId": "M29",
                "ordinal": index + 1,
                "scenario": scenario,
                "evidenceClassification": classification,
                "expectedComponentEligible": eligible,
                "expectedDenyReasonOrNull": deny_reason,
                "productAuthorized": False,
                "expectedOwnerPhases": ["O0", "O4"],
                "expectedLayoutRoles": ["ENDPOINT", "ROOT_PORT"],
                "tupleDigest": None,
            }
        )
        for index, (
            scenario,
            classification,
            eligible,
            deny_reason,
        ) in enumerate(rows)
    ]


def build_matrix() -> dict[str, Any]:
    case_rows = [
        (
            "M24",
            "Correctable deposition and independent Endpoint status clear",
            _m24_tuples(),
        ),
        (
            "M25",
            "Eight Correctable bits by eight E/M/R route tuples",
            _m25_tuples(),
        ),
        (
            "M26",
            (
                "Owner-bound retained Root first/multiple, W1C, OR and "
                "rearm sequence"
            ),
            _m26_tuples(),
        ),
        (
            "M27",
            "Cleanup, quarantine, reuse and stale-owner fences",
            _m27_tuples(),
        ),
        (
            "M28",
            (
                "Pre-VFIO guest configuration isolation and dynamic "
                "layout replay"
            ),
            _m28_tuples(),
        ),
        (
            "M29",
            (
                "Evidence, qualification and admission remain "
                "non-self-authorizing"
            ),
            _m29_tuples(),
        ),
    ]
    matrix = {
        "subjectType": "QMAN_AER_CASE_MATRIX",
        "schemaVersion": 1,
        "matrixId": "QMAN-AER-M24-M29-COMPONENT-MATRIX-V1",
        "authorityBoundary": "COMPONENT_PREMISE",
        "productAuthorized": False,
        "correctableBits": CORRECTABLE_BITS,
        "requiredCaseIds": REQUIRED_CASE_IDS,
        "cases": [
            {
                "caseId": case_id,
                "title": title,
                "tupleCount": len(tuples),
                "tuples": tuples,
            }
            for case_id, title, tuples in case_rows
        ],
        "caseTupleCounts": CASE_TUPLE_COUNTS,
        "tupleCount": sum(CASE_TUPLE_COUNTS.values()),
        "matrixDigest": None,
    }
    matrix["matrixDigest"] = null_hash(
        matrix,
        "matrixDigest",
        MATRIX_DOMAIN,
    )
    return matrix


def digest_domains() -> dict[str, str]:
    domains = {
        "policy": POLICY_DOMAIN,
        "caseTuple": TUPLE_DOMAIN,
        "caseMatrix": MATRIX_DOMAIN,
        "ownerBinding": OWNER_BINDING_DOMAIN,
        "layoutBinding": LAYOUT_BINDING_DOMAIN,
        "oracleBinding": ORACLE_BINDING_DOMAIN,
        "caseResult": CASE_RESULT_DOMAIN,
        "componentReceipt": COMPONENT_RECEIPT_DOMAIN,
        "verifierAlgorithm": ALGORITHM_DOMAIN,
        "goldenVectors": GOLDEN_DOMAIN,
    }
    return {
        name: value.decode("ascii")
        for name, value in domains.items()
    }


def implementation_bindings(
    snapshot: ContractSourceSnapshot,
) -> list[dict[str, str]]:
    return [
        {
            "role": "INDEPENDENT_GENERATOR_VERIFIER",
            "path": GENERATOR_PATH.relative_to(ROOT).as_posix(),
            "sha256": snapshot.digest(GENERATOR_PATH),
        },
        {
            "role": "CONFORMANCE_TEST",
            "path": CONFORMANCE_TEST_PATH.relative_to(ROOT).as_posix(),
            "sha256": snapshot.digest(CONFORMANCE_TEST_PATH),
        },
    ]


def build_algorithm(
    matrix: dict[str, Any],
    *,
    snapshot: ContractSourceSnapshot | None = None,
) -> dict[str, Any]:
    source_snapshot = snapshot or capture_source_snapshot()
    schema_paths = [
        POLICY_SCHEMA,
        MATRIX_SCHEMA,
        RECEIPT_SCHEMA,
        ALGORITHM_SCHEMA,
    ]
    algorithm = {
        "subjectType": "QMAN_AER_VERIFIER_ALGORITHM",
        "schemaVersion": 1,
        "algorithmId": "QMAN-AER-COMPONENT-VERIFIER-V1",
        "authorityBoundary": "COMPONENT_PREMISE",
        "productAuthorized": False,
        "normativeSourceState": "CANDIDATE_NOT_IN_PORTABLE_CLOSURE",
        "canonicalization": "CANONICAL-JSON-V1",
        "verifierImplementationClass": (
            "INDEPENDENT_FROM_TARGET_IMPLEMENTATION"
        ),
        "targetImplementationImportsAllowed": False,
        "resourceBudgets": RESOURCE_BUDGETS,
        "schemaBindings": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": source_snapshot.digest(path),
            }
            for path in schema_paths
        ],
        "implementationBindings": implementation_bindings(source_snapshot),
        "caseMatrixDigest": matrix["matrixDigest"],
        "goldenVectorSetId": "QMAN-AER-CORRECTABLE-GOLDEN-V1",
        "requiredCaseIds": REQUIRED_CASE_IDS,
        "requiredDimensions": REQUIRED_DIMENSIONS,
        "validationStages": VALIDATION_STAGES,
        "digestDomains": digest_domains(),
        "algorithmDigest": None,
    }
    algorithm["algorithmDigest"] = null_hash(
        algorithm,
        "algorithmDigest",
        ALGORITHM_DOMAIN,
    )
    return algorithm


def _schema_valid(
    validator: Draft202012Validator,
    document: dict[str, Any],
) -> bool:
    return not list(validator.iter_errors(document))


def build_golden(
    matrix: dict[str, Any],
    algorithm: dict[str, Any],
    *,
    snapshot: ContractSourceSnapshot | None = None,
) -> dict[str, Any]:
    source_snapshot = snapshot or capture_source_snapshot()
    policy_schema = source_snapshot.json_schema(POLICY_SCHEMA)
    policy_validator = Draft202012Validator(policy_schema)
    positives = [
        {
            "vectorId": vector_id,
            "document": document,
            "expectedAerPolicyDigest": document["aerPolicyDigest"],
        }
        for vector_id, document in positive_policy_documents()
    ]
    negatives = [
        {
            "vectorId": vector_id,
            "document": document,
            "expectedSchemaValid": _schema_valid(
                policy_validator,
                document,
            ),
            "expectedErrorCode": error_code,
        }
        for vector_id, document, error_code in negative_policy_documents()
    ]
    golden = {
        "subjectType": "QMAN_AER_GOLDEN_VECTOR_SET",
        "schemaVersion": 1,
        "vectorSetId": "QMAN-AER-CORRECTABLE-GOLDEN-V1",
        "authorityBoundary": "COMPONENT_PREMISE",
        "productAuthorized": False,
        "normativeSourceState": "CANDIDATE_NOT_IN_PORTABLE_CLOSURE",
        "implementationBindings": implementation_bindings(source_snapshot),
        "digestDomains": digest_domains(),
        "positivePolicyVectors": positives,
        "negativePolicyVectors": negatives,
        "matrixVector": {
            "matrixId": matrix["matrixId"],
            "matrixDigest": matrix["matrixDigest"],
            "matrixDocumentSha256": sha256_digest(render(matrix)),
            "tupleCount": matrix["tupleCount"],
            "caseTupleCounts": matrix["caseTupleCounts"],
        },
        "verifierAlgorithm": {
            "document": algorithm,
            "expectedAlgorithmDigest": algorithm["algorithmDigest"],
        },
        "goldenVectorSetDigest": None,
    }
    golden["goldenVectorSetDigest"] = null_hash(
        golden,
        "goldenVectorSetDigest",
        GOLDEN_DOMAIN,
    )
    return golden


def _validate_matrix_semantics(matrix: dict[str, Any]) -> None:
    if matrix["requiredCaseIds"] != REQUIRED_CASE_IDS:
        raise ValueError("matrix requiredCaseIds drift")
    if matrix["caseTupleCounts"] != CASE_TUPLE_COUNTS:
        raise ValueError("matrix caseTupleCounts drift")
    if matrix["tupleCount"] != 133:
        raise ValueError("matrix must contain exactly 133 tuple rows")
    if matrix["productAuthorized"] is not False:
        raise ValueError("matrix must never authorize a product")

    tuple_ids: set[str] = set()
    tuple_digests: set[str] = set()
    flattened: list[dict[str, Any]] = []
    for expected_case_id, case in zip(
        REQUIRED_CASE_IDS,
        matrix["cases"],
        strict=True,
    ):
        if case["caseId"] != expected_case_id:
            raise ValueError("matrix Case order drift")
        expected_count = CASE_TUPLE_COUNTS[expected_case_id]
        if (
            case["tupleCount"] != expected_count
            or len(case["tuples"]) != expected_count
        ):
            raise ValueError(f"{expected_case_id} tuple count drift")
        for ordinal, row in enumerate(case["tuples"], start=1):
            if row["caseId"] != expected_case_id:
                raise ValueError(f"{expected_case_id} row Case mismatch")
            if row["ordinal"] != ordinal:
                raise ValueError(f"{expected_case_id} row ordinal drift")
            if row["tupleDigest"] != null_hash(
                row,
                "tupleDigest",
                TUPLE_DOMAIN,
            ):
                raise ValueError(f"{row['tupleId']} tuple digest mismatch")
            if row["tupleId"] in tuple_ids:
                raise ValueError(f"duplicate tuple ID {row['tupleId']}")
            if row["tupleDigest"] in tuple_digests:
                raise ValueError(f"duplicate tuple digest {row['tupleDigest']}")
            tuple_ids.add(row["tupleId"])
            tuple_digests.add(row["tupleDigest"])
            flattened.append(row)

    m24 = matrix["cases"][0]["tuples"]
    if [row["correctableBit"] for row in m24] != CORRECTABLE_BITS:
        raise ValueError("M24 Correctable bit coverage drift")
    m25 = matrix["cases"][1]["tuples"]
    expected_m25 = [
        (
            bit,
            endpoint_cere,
            controlled_bit_masked,
            root_cor_enabled,
        )
        for bit in CORRECTABLE_BITS
        for endpoint_cere in (False, True)
        for controlled_bit_masked in (False, True)
        for root_cor_enabled in (False, True)
    ]
    actual_m25 = [
        (
            row["correctableBit"],
            row["endpointCere"],
            row["controlledBitMasked"],
            row["rootCorEnabled"],
        )
        for row in m25
    ]
    if actual_m25 != expected_m25:
        raise ValueError("M25 E/M/R truth-table coverage drift")
    for row in m25:
        routed = row["endpointCere"] and not row["controlledBitMasked"]
        if row["expectedRootDeposition"] is not routed:
            raise ValueError(f"{row['tupleId']} root route truth mismatch")
        if (
            row["expectedNotificationEligible"]
            is not (routed and row["rootCorEnabled"])
        ):
            raise ValueError(
                f"{row['tupleId']} notification truth mismatch"
            )
    if len(flattened) != 133:
        raise ValueError("matrix flattened tuple count drift")
    if matrix["matrixDigest"] != null_hash(
        matrix,
        "matrixDigest",
        MATRIX_DOMAIN,
    ):
        raise ValueError("matrix digest mismatch")
    if matrix != build_matrix():
        raise ValueError(
            "matrix differs from the fixed M24-M29 declarative table"
        )


def validate_generated(
    matrix: dict[str, Any],
    golden: dict[str, Any],
    *,
    snapshot: ContractSourceSnapshot | None = None,
) -> None:
    source_snapshot = snapshot or capture_source_snapshot()
    schemas = {
        "policy": source_snapshot.json_schema(POLICY_SCHEMA),
        "matrix": source_snapshot.json_schema(MATRIX_SCHEMA),
        "receipt": source_snapshot.json_schema(RECEIPT_SCHEMA),
        "algorithm": source_snapshot.json_schema(ALGORITHM_SCHEMA),
    }
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise ValueError(f"{name} schema is invalid: {exc}") from exc

    Draft202012Validator(schemas["matrix"]).validate(matrix)
    _validate_matrix_semantics(matrix)
    policy_validator = Draft202012Validator(schemas["policy"])
    for vector in golden["positivePolicyVectors"]:
        policy_validator.validate(vector["document"])
        if policy_semantic_error(vector["document"]) is not None:
            raise ValueError(
                f"positive policy {vector['vectorId']} is not valid"
            )
        if (
            vector["expectedAerPolicyDigest"]
            != vector["document"]["aerPolicyDigest"]
        ):
            raise ValueError(
                f"positive policy {vector['vectorId']} digest drift"
            )
    for vector in golden["negativePolicyVectors"]:
        schema_valid = _schema_valid(policy_validator, vector["document"])
        if schema_valid is not vector["expectedSchemaValid"]:
            raise ValueError(
                f"negative policy {vector['vectorId']} schema result drift"
            )
        if (
            policy_semantic_error(vector["document"])
            != vector["expectedErrorCode"]
        ):
            raise ValueError(
                f"negative policy {vector['vectorId']} error-code drift"
            )

    algorithm_schema_validator = Draft202012Validator(schemas["algorithm"])
    golden_validator = algorithm_schema_validator.evolve(
        schema=schemas["algorithm"]["$defs"]["goldenVectorSet"]
    )
    golden_validator.validate(golden)
    algorithm = golden["verifierAlgorithm"]["document"]
    algorithm_schema_validator.validate(algorithm)
    if algorithm["algorithmDigest"] != null_hash(
        algorithm,
        "algorithmDigest",
        ALGORITHM_DOMAIN,
    ):
        raise ValueError("verifier algorithm digest mismatch")
    for binding in algorithm["schemaBindings"]:
        path = ROOT / binding["path"]
        if binding["sha256"] != source_snapshot.digest(path):
            raise ValueError(f"schema binding drift: {binding['path']}")
    for binding in algorithm["implementationBindings"]:
        path = ROOT / binding["path"]
        if binding["sha256"] != source_snapshot.digest(path):
            raise ValueError(
                f"implementation binding drift: {binding['path']}"
            )
    if algorithm["implementationBindings"] != implementation_bindings(
        source_snapshot
    ):
        raise ValueError("algorithm implementation binding order drift")
    if golden["implementationBindings"] != implementation_bindings(
        source_snapshot
    ):
        raise ValueError("golden implementation binding order drift")
    if algorithm["resourceBudgets"] != RESOURCE_BUDGETS:
        raise ValueError("algorithm resource budget drift")
    if algorithm["caseMatrixDigest"] != matrix["matrixDigest"]:
        raise ValueError("algorithm matrix binding drift")
    if algorithm["productAuthorized"] is not False:
        raise ValueError("algorithm must never authorize a product")
    if golden["productAuthorized"] is not False:
        raise ValueError("golden vectors must never authorize a product")
    if golden["matrixVector"]["matrixDocumentSha256"] != sha256_digest(
        render(matrix)
    ):
        raise ValueError("golden matrix byte binding drift")
    if golden["goldenVectorSetDigest"] != null_hash(
        golden,
        "goldenVectorSetDigest",
        GOLDEN_DOMAIN,
    ):
        raise ValueError("golden vector-set digest mismatch")
    expected_algorithm = build_algorithm(
        matrix,
        snapshot=source_snapshot,
    )
    if algorithm != expected_algorithm:
        raise ValueError("algorithm differs from the fixed candidate identity")
    expected_golden = build_golden(
        matrix,
        expected_algorithm,
        snapshot=source_snapshot,
    )
    if golden != expected_golden:
        raise ValueError(
            "golden vectors differ from the fixed conformance table"
        )


@dataclass(frozen=True, slots=True)
class ComponentReceiptVerification:
    """Non-authorizing result of the candidate structural verifier."""

    verification_disposition: str
    component_eligible: bool
    authority_boundary: str
    product_authorized: bool
    receipt_digest: str


def _preflight_raw_document(
    raw: bytes,
    *,
    label: str,
    max_bytes: int,
) -> None:
    if type(raw) is not bytes:
        raise TypeError(f"{label}: expected immutable raw bytes")
    if len(raw) > max_bytes:
        raise ValueError(f"{label}: byte budget exceeded")


def verify_component_receipt(
    *,
    receipt_bytes: bytes,
    policy_bytes: bytes,
    matrix_bytes: bytes,
    golden_bytes: bytes,
) -> ComponentReceiptVerification:
    """Verify fixed candidate bytes without accepting caller-made authority.

    V1 intentionally has no artifact-resolver or typed authority-receipt
    parameter.  It can therefore return only ``STRUCTURALLY_VALID`` with
    ``component_eligible=False``.  A future promotion API must be separately
    normative and must not reinterpret this result as physical or E4 proof.
    """

    raw_inputs = (
        (
            receipt_bytes,
            "componentReceipt",
            RESOURCE_BUDGETS["receiptMaxBytes"],
        ),
        (policy_bytes, "aerPolicy", RESOURCE_BUDGETS["policyMaxBytes"]),
        (matrix_bytes, "caseMatrix", RESOURCE_BUDGETS["matrixMaxBytes"]),
        (golden_bytes, "goldenVectors", RESOURCE_BUDGETS["goldenMaxBytes"]),
    )
    for raw, label, max_bytes in raw_inputs:
        _preflight_raw_document(
            raw,
            label=label,
            max_bytes=max_bytes,
        )
    receipt = parse_bounded_json(
        receipt_bytes,
        label="componentReceipt",
        max_bytes=RESOURCE_BUDGETS["receiptMaxBytes"],
    )
    policy = parse_bounded_json(
        policy_bytes,
        label="aerPolicy",
        max_bytes=RESOURCE_BUDGETS["policyMaxBytes"],
    )
    matrix = parse_bounded_json(
        matrix_bytes,
        label="caseMatrix",
        max_bytes=RESOURCE_BUDGETS["matrixMaxBytes"],
    )
    golden = parse_bounded_json(
        golden_bytes,
        label="goldenVectors",
        max_bytes=RESOURCE_BUDGETS["goldenMaxBytes"],
    )

    source_snapshot = capture_source_snapshot()
    validate_generated(
        matrix,
        golden,
        snapshot=source_snapshot,
    )
    if matrix_bytes != render(build_matrix()):
        raise ValueError("caseMatrix raw bytes are not the fixed candidate")
    expected_algorithm = build_algorithm(
        matrix,
        snapshot=source_snapshot,
    )
    expected_golden = build_golden(
        matrix,
        expected_algorithm,
        snapshot=source_snapshot,
    )
    if golden_bytes != render(expected_golden):
        raise ValueError("goldenVectors raw bytes are not the fixed candidate")

    receipt_schema = source_snapshot.json_schema(RECEIPT_SCHEMA)
    errors = sorted(
        Draft202012Validator(receipt_schema).iter_errors(receipt),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ValueError(f"component receipt schema failure at {path}")
    if (
        receipt["authorityBoundary"] != "COMPONENT_PREMISE"
        or receipt["productAuthorized"] is not False
        or receipt["normativeSourceState"]
        != "CANDIDATE_NOT_IN_PORTABLE_CLOSURE"
        or receipt["verificationDisposition"] != "STRUCTURALLY_VALID"
        or receipt["componentEligible"] is not False
    ):
        raise ValueError("component receipt authority boundary invalid")
    if receipt["artifactAuthority"] != {
        "resolverState": "UNAVAILABLE",
        "resolverIdentityDigestOrNull": None,
        "typedAuthorityReceiptDigests": [],
    }:
        raise ValueError("component receipt artifact authority invalid")
    if "AUTHORITY_RECEIPT_UNAVAILABLE" not in receipt["denyReasons"]:
        raise ValueError("missing authority-receipt denial")

    contract = receipt["contractBinding"]
    algorithm = golden["verifierAlgorithm"]["document"]
    expected_contract = {
        "aerPolicySchemaSha256": source_snapshot.digest(POLICY_SCHEMA),
        "caseMatrixDigest": matrix["matrixDigest"],
        "caseMatrixSchemaSha256": source_snapshot.digest(MATRIX_SCHEMA),
        "verifierAlgorithmDigest": algorithm["algorithmDigest"],
        "verifierAlgorithmSchemaSha256": source_snapshot.digest(
            ALGORITHM_SCHEMA
        ),
        "componentReceiptSchemaSha256": source_snapshot.digest(
            RECEIPT_SCHEMA
        ),
        "goldenVectorSetDigest": golden["goldenVectorSetDigest"],
        "generatorRawSha256": source_snapshot.digest(GENERATOR_PATH),
        "conformanceTestRawSha256": source_snapshot.digest(
            CONFORMANCE_TEST_PATH
        ),
    }
    for name, expected in expected_contract.items():
        if contract[name] != expected:
            raise ValueError(f"component receipt contract drift: {name}")
    policy_errors = sorted(
        Draft202012Validator(
            source_snapshot.json_schema(POLICY_SCHEMA)
        ).iter_errors(policy),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if policy_errors:
        raise ValueError("component receipt policy schema failure")
    policy_error = policy_semantic_error(policy)
    if policy_error is not None:
        raise ValueError(f"component receipt policy invalid: {policy_error}")
    if contract["aerPolicyDigest"] != policy["aerPolicyDigest"]:
        raise ValueError("component receipt policy digest binding drift")

    child_maps: dict[str, dict[str, dict[str, Any]]] = {}
    for collection_name, digest_member, domain in (
        ("ownerBindings", "ownerBindingDigest", OWNER_BINDING_DOMAIN),
        ("layoutBindings", "layoutBindingDigest", LAYOUT_BINDING_DOMAIN),
        ("oracleBindings", "oracleBindingDigest", ORACLE_BINDING_DOMAIN),
    ):
        seen: dict[str, dict[str, Any]] = {}
        for child in receipt[collection_name]:
            declared = child[digest_member]
            if declared != null_hash(child, digest_member, domain):
                raise ValueError(
                    f"{collection_name} child digest mismatch: {declared}"
                )
            if declared in seen:
                raise ValueError(
                    f"{collection_name} contains duplicate child digest"
                )
            seen[declared] = child
        child_maps[collection_name] = seen

    layout_by_role = {
        layout["functionRole"]: layout
        for layout in receipt["layoutBindings"]
    }
    if set(layout_by_role) != {"ENDPOINT", "ROOT_PORT"}:
        raise ValueError("layout binding roles are not exact")
    endpoint_layout = layout_by_role["ENDPOINT"]
    root_layout = layout_by_role["ROOT_PORT"]
    layout_extent_rules = {
        "ENDPOINT": {
            "pcieCapabilityOffset": (0x100, 0x0C),
            "aerCapabilityOffset": (0x1000, 0x2C),
        },
        "ROOT_PORT": {
            "pcieCapabilityOffset": (0x100, 0x0C),
            "aerCapabilityOffset": (0x1000, 0x38),
        },
    }
    for layout in receipt["layoutBindings"]:
        role = layout["functionRole"]
        for offset_member, (limit, extent) in layout_extent_rules[
            role
        ].items():
            if layout[offset_member] + extent > limit:
                raise ValueError(
                    f"{role} {offset_member} extent exceeds config space"
                )
    for identity_member in (
        "bdf",
        "deviceIdentityDigest",
        "layoutDigest",
    ):
        if endpoint_layout[identity_member] == root_layout[identity_member]:
            raise ValueError(
                "endpoint/root layout identities not distinct: "
                + identity_member
            )

    expected_oracle_profiles = {
        "CANDIDATE_RUNTIME": ("SYNTHETIC", "NONE"),
        "REFERENCE_BEHAVIOR": (
            "PHYSICAL",
            "REFERENCE_BEHAVIOR_ONLY",
        ),
    }
    oracle_by_role: dict[str, dict[str, Any]] = {}
    for oracle in receipt["oracleBindings"]:
        role = oracle["oracleRole"]
        if role in oracle_by_role:
            raise ValueError("duplicate typed oracle role")
        expected_profile = expected_oracle_profiles.get(role)
        actual_profile = (
            oracle["environmentKind"],
            oracle["authorityClosure"],
        )
        if expected_profile is None or actual_profile != expected_profile:
            raise ValueError(f"{role} oracle profile mismatch")
        oracle_by_role[role] = oracle
    if set(oracle_by_role) != set(expected_oracle_profiles):
        raise ValueError("oracle binding roles are not exact")
    candidate_oracle = oracle_by_role["CANDIDATE_RUNTIME"]
    reference_oracle = oracle_by_role["REFERENCE_BEHAVIOR"]
    for identity_member in ("artifactManifestDigest", "oracleDigest"):
        if (
            candidate_oracle[identity_member]
            == reference_oracle[identity_member]
        ):
            raise ValueError(
                "candidate/reference oracle identities not distinct: "
                + identity_member
            )

    if [case["caseId"] for case in receipt["caseResults"]] != REQUIRED_CASE_IDS:
        raise ValueError("component receipt Case order drift")
    all_tuple_results: list[dict[str, Any]] = []
    run_result_digests: set[str] = set()
    artifact_digest_roles: dict[str, str] = {}
    for matrix_case, receipt_case in zip(
        matrix["cases"],
        receipt["caseResults"],
        strict=True,
    ):
        expected_rows = matrix_case["tuples"]
        actual_rows = receipt_case["tupleResults"]
        if receipt_case["expectedTupleCount"] != len(expected_rows):
            raise ValueError(
                f"{receipt_case['caseId']} expected tuple count drift"
            )
        if [row["tupleId"] for row in actual_rows] != [
            row["tupleId"] for row in expected_rows
        ]:
            raise ValueError(
                f"{receipt_case['caseId']} tuple ID coverage drift"
            )
        if [row["tupleDigest"] for row in actual_rows] != [
            row["tupleDigest"] for row in expected_rows
        ]:
            raise ValueError(
                f"{receipt_case['caseId']} tuple digest coverage drift"
            )
        for expected_row, row in zip(
            expected_rows,
            actual_rows,
            strict=True,
        ):
            try:
                bound_owner_phases = [
                    child_maps["ownerBindings"][digest][
                        "referenceOwnerPhase"
                    ]
                    for digest in row["ownerBindingDigests"]
                ]
            except KeyError as exc:
                raise ValueError(
                    f"{row['tupleId']} owner binding missing"
                ) from exc
            if bound_owner_phases != expected_row["expectedOwnerPhases"]:
                raise ValueError(
                    f"{row['tupleId']} owner phase binding mismatch"
                )
            try:
                bound_layout_roles = [
                    child_maps["layoutBindings"][digest]["functionRole"]
                    for digest in row["layoutBindingDigests"]
                ]
            except KeyError as exc:
                raise ValueError(
                    f"{row['tupleId']} layout binding missing"
                ) from exc
            if bound_layout_roles != expected_row["expectedLayoutRoles"]:
                raise ValueError(
                    f"{row['tupleId']} layout role binding mismatch"
                )
            candidate_digest = row["candidateOracleBindingDigest"]
            reference_digest = row["referenceOracleBindingDigest"]
            if candidate_digest == reference_digest:
                raise ValueError(
                    f"{row['tupleId']} oracle roles are not distinct"
                )
            try:
                candidate = child_maps["oracleBindings"][candidate_digest]
                reference = child_maps["oracleBindings"][reference_digest]
            except KeyError as exc:
                raise ValueError(
                    f"{row['tupleId']} oracle binding missing"
                ) from exc
            if candidate["oracleRole"] != "CANDIDATE_RUNTIME":
                raise ValueError(
                    f"{row['tupleId']} candidate oracle role mismatch"
                )
            if reference["oracleRole"] != "REFERENCE_BEHAVIOR":
                raise ValueError(
                    f"{row['tupleId']} reference oracle role mismatch"
                )
            typed_artifacts = (
                ("runResultBinding", "RUN_RESULT"),
                ("artifactManifestBinding", "ARTIFACT_MANIFEST"),
                ("evidenceIndexBinding", "EVIDENCE_INDEX"),
            )
            artifact_digests: list[str] = []
            artifact_entries: list[tuple[str, str]] = []
            for member, artifact_type in typed_artifacts:
                binding = row[member]
                if binding["artifactType"] != artifact_type:
                    raise ValueError(
                        f"{row['tupleId']} typed artifact role mismatch"
                    )
                digest = binding["digest"]
                artifact_digests.append(digest)
                artifact_entries.append((digest, artifact_type))
            if len(set(artifact_digests)) != len(artifact_digests):
                raise ValueError(
                    f"{row['tupleId']} typed artifact digests not distinct"
                )
            for digest, artifact_type in artifact_entries:
                previous_role = artifact_digest_roles.setdefault(
                    digest,
                    artifact_type,
                )
                if previous_role != artifact_type:
                    raise ValueError(
                        f"{row['tupleId']} typed artifact digest reused "
                        "across roles"
                    )
            run_result_digest = row["runResultBinding"]["digest"]
            if run_result_digest in run_result_digests:
                raise ValueError(
                    f"{row['tupleId']} run-result digest is not "
                    "tuple-specific"
                )
            run_result_digests.add(run_result_digest)
        aggregated_case_result = aggregate_results(
            [row["result"] for row in actual_rows]
        )
        if receipt_case["result"] != aggregated_case_result:
            raise ValueError(
                f"{receipt_case['caseId']} Case result aggregation mismatch"
            )
        if receipt_case["caseResultDigest"] != null_hash(
            receipt_case,
            "caseResultDigest",
            CASE_RESULT_DOMAIN,
        ):
            raise ValueError(
                f"{receipt_case['caseId']} Case-result digest mismatch"
            )
        all_tuple_results.extend(actual_rows)
    if len(all_tuple_results) != matrix["tupleCount"]:
        raise ValueError("component receipt does not bind all matrix tuples")
    if len(run_result_digests) != matrix["tupleCount"]:
        raise ValueError("run-result digest coverage is not exact")

    actual_unverified = [
        dimension
        for dimension in REQUIRED_DIMENSIONS
        if receipt["dimensions"][dimension]["result"] != "VERIFIED"
    ]
    if receipt["unverifiedDimensions"] != actual_unverified:
        raise ValueError("component receipt unverifiedDimensions drift")
    expected_classification = aggregate_results(
        [case["result"] for case in receipt["caseResults"]]
    )
    if receipt["classification"] != expected_classification:
        raise ValueError("top classification aggregation mismatch")
    expected_deny_reasons = structural_deny_reasons(
        expected_classification
    )
    if receipt["denyReasons"] != expected_deny_reasons:
        raise ValueError("receipt denyReasons aggregation mismatch")
    if receipt["componentEligible"] is not False:
        raise ValueError("structural receipt attempted component eligibility")
    if receipt["receiptDigest"] != null_hash(
        receipt,
        "receiptDigest",
        COMPONENT_RECEIPT_DOMAIN,
    ):
        raise ValueError("component receipt digest mismatch")
    return ComponentReceiptVerification(
        verification_disposition="STRUCTURALLY_VALID",
        component_eligible=False,
        authority_boundary="COMPONENT_PREMISE",
        product_authorized=False,
        receipt_digest=receipt["receiptDigest"],
    )


def build_outputs() -> tuple[dict[str, Any], dict[str, Any]]:
    source_snapshot = capture_source_snapshot()
    matrix = build_matrix()
    algorithm = build_algorithm(matrix, snapshot=source_snapshot)
    golden = build_golden(
        matrix,
        algorithm,
        snapshot=source_snapshot,
    )
    validate_generated(
        matrix,
        golden,
        snapshot=source_snapshot,
    )
    return matrix, golden


def _check_output(
    path: Path,
    expected: bytes,
    *,
    max_bytes: int,
) -> bool:
    try:
        relative = path.relative_to(ROOT)
        if not path.is_file():
            print(f"missing generated file: {relative}")
            return False
        with path.open("rb") as handle:
            actual = handle.read(max_bytes + 1)
        if len(actual) > max_bytes:
            print(f"generated file exceeds budget: {relative}")
            return False
        if actual != expected:
            print(f"generated file drift: {relative}")
            return False
        print(f"ok: {relative}")
        return True
    except OSError as exc:
        print(f"cannot read generated file: {path}: {exc}")
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify generated files are exact without writing",
    )
    args = parser.parse_args(argv)

    try:
        matrix, golden = build_outputs()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"AER contract generation failed: {exc}", file=sys.stderr)
        return 1

    outputs = [
        (
            MATRIX_OUTPUT,
            render(matrix),
            RESOURCE_BUDGETS["matrixMaxBytes"],
        ),
        (
            GOLDEN_OUTPUT,
            render(golden),
            RESOURCE_BUDGETS["goldenMaxBytes"],
        ),
    ]
    if args.check:
        checks = [
            _check_output(
                path,
                expected,
                max_bytes=max_bytes,
            )
            for path, expected, max_bytes in outputs
        ]
        return 0 if all(checks) else 1

    for path, payload, _max_bytes in outputs:
        path.write_bytes(payload)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
