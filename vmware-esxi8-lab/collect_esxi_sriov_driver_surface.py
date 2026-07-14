#!/usr/bin/env python3
"""Collect ESXi's public SR-IOV NIC and loaded-driver surfaces."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from esxi_passthru_capability import EsxiSsh, caveat_field, utc_now, wait_for_esxi


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--bdf", default="0000:02:00.0")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password, args.user)
    version = wait_for_esxi(ssh, timeout=args.timeout)

    commands = {
        "network-nic-list": "esxcli network nic list",
        "network-sriovnic-list": "esxcli network sriovnic list",
        "network-sriovnic-help": "esxcli network sriovnic --help",
        "system-module-list": "esxcli system module list",
        "igbn-module-get": "esxcli system module get -m igbn",
        "igbn-module-parameters": "esxcli system module parameters list -m igbn",
        "igbn-module-map": "vmkload_mod -p igbn",
        "igbn-module-info": "vmkload_mod -s igbn",
        "vmkload-mod-help": "vmkload_mod --help",
        "software-vib-list": "esxcli software vib list",
        "vmkload-modules": "vmkload_mod -l",
        "target-pci": "esxcli hardware pci list",
        "driver-log": (
            "grep -Ei 'igbn|0000:02:00.0|8086:1521|0x1521' "
            "/var/run/log/vmkernel.log | tail -n 1000"
        ),
    }
    records: dict[str, Any] = {}
    for name, command in commands.items():
        completed = ssh.run(command, check=False, timeout=180)
        (output / f"{name}.stdout.txt").write_text(
            completed.stdout, encoding="utf-8"
        )
        (output / f"{name}.stderr.txt").write_text(
            completed.stderr, encoding="utf-8"
        )
        records[name] = {
            "command": command,
            "returnCode": completed.returncode,
            "stdout": f"{name}.stdout.txt",
            "stderr": f"{name}.stderr.txt",
        }

    sriov_text = (output / "network-sriovnic-list.stdout.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    target_text = (output / "target-pci.stdout.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    checks = {
        "hostReady": bool(version.strip()),
        "commandsCompleted": all(
            records[name]["returnCode"] == 0
            for name in (
                "network-nic-list",
                "network-sriovnic-list",
                "system-module-list",
                "software-vib-list",
                "vmkload-modules",
                "target-pci",
            )
        ),
        "targetCaptured": args.bdf in target_text,
    }
    result = {
        "case": "ESXi-SR-IOV-driver-surface",
        "startedAt": started_at,
        "input": {"host": args.host, "bdf": args.bdf},
        "hostVersion": version,
        "commands": records,
        "observed": {
            "sriovNicListEmpty": not any(
                line.strip() and not line.lstrip().startswith("Name")
                and not set(line.strip()) <= {"-"}
                for line in sriov_text.splitlines()
            ),
            "targetModuleNone": "Module Name: None" in target_text,
        },
        "checks": checks,
        "verdict": "pass" if all(checks.values()) else "fail",
        "finishedAt": utc_now(),
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
