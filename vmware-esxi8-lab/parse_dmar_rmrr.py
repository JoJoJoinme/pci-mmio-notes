#!/usr/bin/env python3
"""Extract and validate endpoint-scoped RMRR entries from a serial log."""

from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path


def parse_int(value: str) -> int:
    return int(value, 0)


def extract_table(text: str) -> bytes:
    match = re.search(
        r"DMAR-RAW-BEGIN\s*\r?\n(?P<hex>.*?)DMAR-RAW-END",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("DMAR raw markers were not found")
    hex_text = "".join(re.findall(r"[0-9a-fA-F]", match.group("hex")))
    return bytes.fromhex(hex_text)


def parse_scopes(payload: bytes) -> list[dict[str, object]]:
    scopes: list[dict[str, object]] = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 6:
            raise ValueError("truncated DMAR device scope")
        scope_type, scope_len = struct.unpack_from("<BB", payload, offset)
        if scope_len < 6 or offset + scope_len > len(payload):
            raise ValueError(f"invalid DMAR device scope length {scope_len}")
        enumeration_id = payload[offset + 4]
        start_bus = payload[offset + 5]
        path_data = payload[offset + 6 : offset + scope_len]
        if len(path_data) % 2:
            raise ValueError("DMAR device path has an odd byte count")
        paths = [
            {"device": path_data[index], "function": path_data[index + 1]}
            for index in range(0, len(path_data), 2)
        ]
        scopes.append(
            {
                "type": scope_type,
                "length": scope_len,
                "enumerationId": enumeration_id,
                "startBus": start_bus,
                "paths": paths,
            }
        )
        offset += scope_len
    return scopes


def parse_dmar(table: bytes) -> dict[str, object]:
    if len(table) < 48 or table[:4] != b"DMAR":
        raise ValueError("not a complete ACPI DMAR table")
    declared_length = struct.unpack_from("<I", table, 4)[0]
    if declared_length != len(table):
        raise ValueError(
            f"DMAR length mismatch: header={declared_length} bytes={len(table)}"
        )
    if sum(table) & 0xFF:
        raise ValueError("DMAR checksum is invalid")

    entries: list[dict[str, object]] = []
    offset = 48
    while offset < len(table):
        if len(table) - offset < 4:
            raise ValueError("truncated DMAR remapping structure")
        entry_type, entry_length = struct.unpack_from("<HH", table, offset)
        if entry_length < 4 or offset + entry_length > len(table):
            raise ValueError(f"invalid DMAR structure length {entry_length}")
        entry: dict[str, object] = {
            "type": entry_type,
            "length": entry_length,
        }
        if entry_type == 1:
            if entry_length < 24:
                raise ValueError("RMRR structure is shorter than 24 bytes")
            segment = struct.unpack_from("<H", table, offset + 6)[0]
            base, limit = struct.unpack_from("<QQ", table, offset + 8)
            entry.update(
                {
                    "kind": "RMRR",
                    "segment": segment,
                    "base": base,
                    "limit": limit,
                    "scopes": parse_scopes(table[offset + 24 : offset + entry_length]),
                }
            )
        entries.append(entry)
        offset += entry_length

    return {
        "signature": "DMAR",
        "length": declared_length,
        "checksumValid": True,
        "hostAddressWidth": table[36] + 1,
        "flags": table[37],
        "entries": entries,
    }


def parse_iomem(text: str, expected_base: int, expected_limit: int) -> dict[str, object]:
    match = re.search(
        r"=== iomem ===\s*\r?\n(?P<body>.*?)=== PCI target ===",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("iomem markers were not found")
    overlaps: list[dict[str, object]] = []
    for line in match.group("body").splitlines():
        item = re.match(
            r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+?)\s*$",
            line,
        )
        if not item:
            continue
        start = int(item.group(1), 16)
        end = int(item.group(2), 16)
        if end < expected_base or start > expected_limit:
            continue
        overlaps.append(
            {
                "start": start,
                "end": end,
                "label": item.group(3),
                "coversRange": start <= expected_base and end >= expected_limit,
            }
        )
    return {
        "overlaps": overlaps,
        "systemRamOverlap": any(item["label"] == "System RAM" for item in overlaps),
        "coveringLabels": [item["label"] for item in overlaps if item["coversRange"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("serial_log", type=Path)
    parser.add_argument("--expect-base", type=parse_int)
    parser.add_argument("--expect-limit", type=parse_int)
    parser.add_argument("--expect-sid", type=parse_int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    serial_text = args.serial_log.read_text(errors="replace")
    result = parse_dmar(extract_table(serial_text))
    rmrr_entries = [entry for entry in result["entries"] if entry.get("kind") == "RMRR"]
    matches = rmrr_entries
    if args.expect_base is not None:
        matches = [entry for entry in matches if entry["base"] == args.expect_base]
    if args.expect_limit is not None:
        matches = [entry for entry in matches if entry["limit"] == args.expect_limit]
    if args.expect_sid is not None:
        expected_bus = args.expect_sid >> 8
        expected_device = (args.expect_sid & 0xFF) >> 3
        expected_function = args.expect_sid & 7
        matches = [
            entry
            for entry in matches
            if any(
                scope["startBus"] == expected_bus
                and scope["paths"]
                and scope["paths"][0]
                == {"device": expected_device, "function": expected_function}
                for scope in entry["scopes"]
            )
        ]

    result["matchingRmrrCount"] = len(matches)
    if args.expect_base is not None and args.expect_limit is not None:
        result["iomem"] = parse_iomem(
            serial_text,
            args.expect_base,
            args.expect_limit,
        )
    result["pass"] = (
        len(matches) > 0
        and not result.get("iomem", {}).get("systemRamOverlap", False)
    )
    encoded = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(encoded + "\n")
    print(encoded)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
