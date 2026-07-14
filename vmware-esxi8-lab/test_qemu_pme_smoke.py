#!/usr/bin/env python3
"""Smoke-test the default-off QEMU PCIe PME injection properties."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


QOM_PATH = "/machine/peripheral/test_fn0"


def command(execute: str, arguments: dict | None = None) -> dict:
    value = {"execute": execute}
    if arguments is not None:
        value["arguments"] = arguments
    return value


def qom_get(prop: str) -> dict:
    return command("qom-get", {"path": QOM_PATH, "property": prop})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64",
    )
    parser.add_argument("--output")
    args = parser.parse_args()

    requests = [
        command("qmp_capabilities"),
        qom_get("x-pme-status"),
        qom_get("x-upstream-pme-status"),
        command(
            "qom-set",
            {"path": QOM_PATH, "property": "x-pme-inject", "value": True},
        ),
        qom_get("x-pme-status"),
        qom_get("x-upstream-pme-status"),
        command("quit"),
    ]
    completed = subprocess.run(
        [
            args.qemu,
            "-machine", "q35,accel=tcg",
            "-nodefaults",
            "-display", "none",
            "-S",
            "-device", "pcie-root-port,id=pme_rp,bus=pcie.0,chassis=8,slot=8,addr=0x08.0",
            "-device", "e1000e,id=test_fn0,bus=pme_rp,addr=0",
            "-qmp", "stdio",
        ],
        input="\n".join(json.dumps(item) for item in requests) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    responses = []
    for line in completed.stdout.splitlines():
        try:
            responses.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    returns = [item["return"] for item in responses if "return" in item]
    checks = {
        "qemuExitedCleanly": completed.returncode == 0,
        "responseCount": len(returns) == len(requests),
        "endpointStatusInitiallyClear": len(returns) > 2 and returns[1] is False,
        "rootStatusInitiallyClear": len(returns) > 2 and returns[2] is False,
        "endpointStatusSetAfterInjection": len(returns) > 5 and returns[4] is True,
        "rootStatusSetAfterInjection": len(returns) > 5 and returns[5] is True,
    }
    result = {
        "qemu": args.qemu,
        "requests": requests,
        "responses": responses,
        "stderr": completed.stderr.splitlines(),
        "checks": checks,
        "verdict": "pass" if all(checks.values()) else "fail",
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
