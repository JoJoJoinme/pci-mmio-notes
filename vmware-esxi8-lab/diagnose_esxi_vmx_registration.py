#!/usr/bin/env python3
"""Diagnose an ESXi VMX registration through public SSH/vim-cmd interfaces."""

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path

from esxi_passthru_capability import EsxiSsh, caveat_field, utc_now


def command_snapshot(ssh: EsxiSsh, command: str) -> dict[str, object]:
    completed = ssh.run(command, check=False, timeout=120)
    return {
        "command": command,
        "exitCode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--vmx", required=True)
    parser.add_argument("--name", default="vmx-registration-diagnostic")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    ssh = EsxiSsh(args.host, caveat_field(args.caveat, "Password"))
    quoted_vmx = shlex.quote(args.vmx)
    quoted_name = shlex.quote(args.name)
    result: dict[str, object] = {
        "startedAt": utc_now(),
        "host": args.host,
        "vmx": args.vmx,
        "name": args.name,
    }
    result["pathProbe"] = command_snapshot(
        ssh, f"ls -l {quoted_vmx}; head -n 80 {quoted_vmx}"
    )
    registration = command_snapshot(
        ssh, f"vim-cmd solo/registervm {quoted_vmx} {quoted_name}"
    )
    result["registration"] = registration
    vmid = next(
        (
            line.strip()
            for line in reversed(str(registration["stdout"]).splitlines())
            if line.strip().isdigit()
        ),
        None,
    )
    result["vmid"] = vmid
    try:
        if vmid is not None:
            result["summary"] = command_snapshot(
                ssh, f"vim-cmd vmsvc/get.summary {vmid}"
            )
            result["config"] = command_snapshot(
                ssh, f"vim-cmd vmsvc/get.config {vmid}"
            )
        result["hostd"] = command_snapshot(
            ssh,
            "grep -F "
            + shlex.quote(args.name)
            + " /var/log/hostd.log | tail -n 200",
        )
    finally:
        if vmid is not None:
            result["cleanup"] = command_snapshot(
                ssh, f"vim-cmd vmsvc/unregister {vmid}"
            )
    result["finishedAt"] = utc_now()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
