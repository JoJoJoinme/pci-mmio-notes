"""Strict CANONICAL-JSON-V1 encoding used by the portable DirectPath contract."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
import unicodedata


SAFE_INTEGER = 9_007_199_254_740_991


class CanonicalizationError(ValueError):
    """A value cannot be represented by the closed portable JSON profile."""


class DuplicateKeyError(CanonicalizationError):
    """A JSON object contains the same member name more than once."""


class CanonicalJsonLimitError(CanonicalizationError):
    """A JSON value exceeds a caller-supplied closed resource limit."""

    def __init__(self, limit_kind: str, message: str):
        super().__init__(message)
        self.limit_kind = limit_kind


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(token: str) -> Any:
    raise CanonicalizationError(f"non-JSON numeric constant is forbidden: {token}")


def _validate_string(value: str, path: str) -> None:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalizationError(f"{path}: string is not Unicode NFC")
    try:
        value.encode("utf-8", errors="strict")
        value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{path}: unpaired Unicode surrogate") from exc


def _utf16_sort_key(value: str) -> bytes:
    _validate_string(value, "object key")
    return value.encode("utf-16-be")


def _canonical_text(value: Any, path: str = "$") -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise CanonicalizationError(
                f"{path}: integer {value} is outside the interoperable safe range"
            )
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floating-point values are forbidden")
    if isinstance(value, str):
        _validate_string(value, path)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return (
            "["
            + ",".join(
                _canonical_text(item, f"{path}[{index}]")
                for index, item in enumerate(value)
            )
            + "]"
        )
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: JSON object key is not a string")
        members: list[str] = []
        for key in sorted(value, key=_utf16_sort_key):
            _validate_string(key, f"{path} object key")
            encoded_key = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
            members.append(
                encoded_key + ":" + _canonical_text(value[key], f"{path}.{key}")
            )
        return "{" + ",".join(members) + "}"
    raise CanonicalizationError(
        f"{path}: unsupported JSON value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return exact UTF-8 bytes for the repository's strict JCS subset."""

    return _canonical_text(value).encode("utf-8")


def _bounded_add(current: int, amount: int, maximum: int, kind: str) -> int:
    if amount < 0 or current > maximum - amount:
        raise CanonicalJsonLimitError(
            kind,
            f"canonical JSON exceeds the configured {kind} limit",
        )
    return current + amount


def _json_string_utf8_size(value: str, *, maximum: int) -> int:
    """Return the exact encoded JSON-string size without materializing it."""

    # Every scalar contributes at least one byte per code point plus quotes.
    # Reject that lower bound before normalization or encoding can allocate a
    # second copy of an attacker-sized string.
    if len(value) > maximum - 2:
        raise CanonicalJsonLimitError(
            "bytes",
            "canonical JSON string exceeds the configured byte limit",
        )
    if not unicodedata.is_normalized("NFC", value):
        raise CanonicalizationError("string is not Unicode NFC")

    size = 2
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalizationError("unpaired Unicode surrogate")
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            width = 2
        elif codepoint <= 0x1F:
            width = 6
        elif codepoint <= 0x7F:
            width = 1
        elif codepoint <= 0x7FF:
            width = 2
        elif codepoint <= 0xFFFF:
            width = 3
        else:
            width = 4
        size = _bounded_add(size, width, maximum, "bytes")
    return size


def measure_canonical_json(
    value: Any,
    *,
    max_bytes: int,
    max_nodes: int,
    max_depth: int,
) -> tuple[int, int]:
    """Measure canonical bytes and JSON nodes under closed limits.

    The walk is iterative and does not construct the canonical string.  It is
    intended as a fail-fast guard before ``canonical_json_bytes`` is called on
    a caller-supplied in-memory mapping.
    """

    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < 1
        or not isinstance(max_nodes, int)
        or isinstance(max_nodes, bool)
        or max_nodes < 1
        or not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or max_depth < 0
    ):
        raise ValueError("canonical JSON limits must be positive integers")

    total_bytes = 0
    total_nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        total_nodes += 1
        if total_nodes > max_nodes:
            raise CanonicalJsonLimitError(
                "nodes",
                "canonical JSON exceeds the configured node limit",
            )
        if depth > max_depth:
            raise CanonicalJsonLimitError(
                "depth",
                "canonical JSON exceeds the configured depth limit",
            )

        if current is None:
            total_bytes = _bounded_add(total_bytes, 4, max_bytes, "bytes")
        elif current is True:
            total_bytes = _bounded_add(total_bytes, 4, max_bytes, "bytes")
        elif current is False:
            total_bytes = _bounded_add(total_bytes, 5, max_bytes, "bytes")
        elif isinstance(current, int):
            if abs(current) > SAFE_INTEGER:
                raise CanonicalizationError(
                    "integer is outside the interoperable safe range"
                )
            total_bytes = _bounded_add(
                total_bytes,
                len(str(current)),
                max_bytes,
                "bytes",
            )
        elif isinstance(current, float):
            raise CanonicalizationError("floating-point values are forbidden")
        elif isinstance(current, str):
            remaining = max_bytes - total_bytes
            total_bytes = _bounded_add(
                total_bytes,
                _json_string_utf8_size(current, maximum=remaining),
                max_bytes,
                "bytes",
            )
        elif isinstance(current, list):
            overhead = 2 + max(0, len(current) - 1)
            total_bytes = _bounded_add(
                total_bytes,
                overhead,
                max_bytes,
                "bytes",
            )
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, Mapping):
            member_count = len(current)
            # Braces, one colon per member and commas between members.
            overhead = 2 + member_count + max(0, member_count - 1)
            total_bytes = _bounded_add(
                total_bytes,
                overhead,
                max_bytes,
                "bytes",
            )
            for key, item in current.items():
                if not isinstance(key, str):
                    raise CanonicalizationError("JSON object key is not a string")
                remaining = max_bytes - total_bytes
                total_bytes = _bounded_add(
                    total_bytes,
                    _json_string_utf8_size(key, maximum=remaining),
                    max_bytes,
                    "bytes",
                )
                stack.append((item, depth + 1))
        else:
            raise CanonicalizationError(
                f"unsupported JSON value type {type(current).__name__}"
            )
    return total_bytes, total_nodes


def sha256_digest(data: bytes | bytearray | memoryview) -> str:
    """Return the contract's ``sha256:<lowercase-hex>`` representation."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256_digest() requires a bytes-like value")
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def load_canonical_json(data: bytes | bytearray | memoryview) -> Any:
    """Parse closed JSON and require its input bytes to already be canonical."""

    raw = bytes(data)
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalizationError(f"invalid UTF-8 JSON: {exc}") from exc
    canonical = canonical_json_bytes(value)
    if raw != canonical:
        raise CanonicalizationError("input is not exact CANONICAL-JSON-V1 bytes")
    return value
