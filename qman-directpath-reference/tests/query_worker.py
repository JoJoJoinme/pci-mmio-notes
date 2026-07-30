"""Independent-process worker for reference query crash tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from qman_directpath_reference.query_snapshot import ReferenceSqliteSnapshotReader


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    def hook(stage, _connection) -> None:
        if stage == payload.get("hardExitStage"):
            os._exit(int(payload.get("hardExitCode", 77)))

    reader = ReferenceSqliteSnapshotReader(
        Path(payload["databasePath"]),
        transaction_hook=hook,
    )
    result = reader.read(payload["vmId"])
    Path(payload["outputPath"]).write_bytes(result.before_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
