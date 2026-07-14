#!/usr/bin/env python3
"""Pad a compressed EFI PCI ROM to its decompressed allocation size."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


SECTOR_SIZE = 512
EFI_SIGNATURE = 0x0EF1
PCIR_SIGNATURE = b"PCIR"


def round_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def normalize(source: Path, output: Path) -> dict[str, int]:
    data = bytearray(source.read_bytes())
    if len(data) < 64 or data[:2] != b"\x55\xaa":
        raise ValueError("not a PCI expansion ROM")
    if struct.unpack_from("<I", data, 4)[0] != EFI_SIGNATURE:
        raise ValueError("not an EFI PCI expansion ROM")
    compression_type = struct.unpack_from("<H", data, 12)[0]
    if compression_type != 1:
        raise ValueError(f"expected compression type 1, got {compression_type}")

    image_offset = struct.unpack_from("<H", data, 22)[0]
    pcir_offset = struct.unpack_from("<H", data, 24)[0]
    if data[pcir_offset : pcir_offset + 4] != PCIR_SIGNATURE:
        raise ValueError("missing PCIR structure")
    pcir_length = struct.unpack_from("<H", data, pcir_offset + 10)[0]
    checksum_offset = pcir_offset + pcir_length
    compressed_size, decompressed_size = struct.unpack_from(
        "<II", data, image_offset
    )
    compressed_end = image_offset + 8 + compressed_size
    if compressed_end > len(data):
        raise ValueError("compressed payload extends beyond ROM image")

    allocation_size = round_up(
        image_offset + decompressed_size, SECTOR_SIZE
    )
    if allocation_size > 0xFFFF * SECTOR_SIZE:
        raise ValueError("decompressed allocation exceeds ROM field width")
    if len(data) > allocation_size:
        raise ValueError("ROM is larger than decompressed allocation")
    data.extend(b"\x00" * (allocation_size - len(data)))

    sectors = allocation_size // SECTOR_SIZE
    struct.pack_into("<H", data, 2, sectors)
    struct.pack_into("<H", data, pcir_offset + 16, sectors)
    data[checksum_offset] = 0
    data[checksum_offset] = (-sum(data)) & 0xFF
    if sum(data) & 0xFF:
        raise AssertionError("ROM checksum repair failed")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return {
        "compressedSize": compressed_size,
        "decompressedSize": decompressed_size,
        "allocationSize": allocation_size,
        "sectors": sectors,
        "checksumOffset": checksum_offset,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(normalize(args.source, args.output))


if __name__ == "__main__":
    main()
