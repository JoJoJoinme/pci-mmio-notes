#!/usr/bin/env python3
"""Decode one QEMU simpletrace run with its matching event table."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


DEFAULT_SOURCE_DIR = Path("/root/src/qemu-6.2.0")
DEFAULT_BUILD_DIR = DEFAULT_SOURCE_DIR / "build-capability-lab"
SIMPLETRACE_HEADER_EVENT_ID = b"\xff" * 8


def decode_simpletrace(
    trace_path: Path,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    build_dir: Path = DEFAULT_BUILD_DIR,
) -> str:
    if not trace_path.exists():
        raise FileNotFoundError(f"Missing trace input: {trace_path}")
    with trace_path.open("rb") as handle:
        header = handle.read(8)
    if header != SIMPLETRACE_HEADER_EVENT_ID:
        return trace_path.read_text(encoding="utf-8", errors="replace")

    script = source_dir / "scripts/simpletrace.py"
    events = build_dir / "trace/trace-events-all"
    missing = [str(path) for path in (script, events) if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing simpletrace input: " + ", ".join(missing))

    # The live backend can append while the decoder reads.  Decode a stable copy
    # so a partial final record cannot turn a valid run into a parser failure.
    with tempfile.TemporaryDirectory(prefix="qemu-simpletrace-") as temp_dir:
        snapshot = Path(temp_dir) / trace_path.name
        shutil.copyfile(trace_path, snapshot)
        completed = subprocess.run(
            ["python3", str(script), str(events), str(snapshot)],
            check=False,
            capture_output=True,
            text=True,
        )
    if completed.returncode:
        raise RuntimeError(
            f"simpletrace decoder exited {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def selected_reset_lines(text: str) -> list[str]:
    names = (
        "qdev_reset ",
        "qdev_reset_all ",
        "qdev_reset_tree ",
        "qbus_reset ",
        "qbus_reset_all ",
        "qbus_reset_tree ",
        "resettable_",
    )
    return [line for line in text.splitlines() if line.startswith(names)]
