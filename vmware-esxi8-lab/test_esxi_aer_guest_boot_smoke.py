#!/usr/bin/env python3
"""Boot-smoke the AER probe ISO on ESXi without issuing any AER injection.

The two modes isolate guest-media regressions from DirectPath effects:

* ``no-passthrough`` boots the exact ISO without a passthrough device.
* ``directpath-unmonitored`` adds the target DirectPath function but performs
  no QTest polling or HMP mutation while the guest boots.

Only public ESXi inventory, VMX, serial and ``vmware.log`` surfaces are used.
There is deliberately no AER injection command or QTest write path here.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import time
from pathlib import Path
from typing import Any

from esxi_passthru_capability import EsxiSsh, caveat_field
from test_esxi_aer_correctable_matrix import (
    ApiSession,
    BlockedEnvironment,
    EsxiScp,
    canonical_bdf,
    isolated_active_passthrough_users,
    save_json,
    save_text,
    sha256_file,
    utc_now,
    validate_safe_id,
    vmx_pci_id,
)


MODES = ("no-passthrough", "directpath-unmonitored")
DEFAULT_LOCAL_ISO = (
    Path(__file__).resolve().parents[2]
    / "_artifacts"
    / "esxi-l3-aer-probe.iso"
)
DEFAULT_BASE_VMX = Path(__file__).resolve().parent / "mf-passthru-probe-local.vmx"
BASE_REQUIRED_MARKERS = (
    "=== AER guest probe start ===",
    "cmdline:",
    "=== AER injection window open ===",
)
BASE_REQUIRED_CMDLINE_TOKENS = (
    "console=ttyS0,115200n8",
    "rdinit=/init",
)


def create_smoke_vmx(
    *,
    base_vmx: Path,
    output: Path,
    vm_name: str,
    serial_name: str,
    remote_iso: str,
    mode: str,
    bdf: str,
    vendor_id: int,
    device_id: int,
    system_uuid: str | None,
) -> None:
    """Create one generated VMX while keeping the mode delta explicit."""

    if mode not in MODES:
        raise ValueError(f"unsupported smoke mode: {mode}")
    lines = base_vmx.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        if re.match(r"^pciPassthru\d+\.", line):
            continue
        if re.match(r"^displayName\s*=", line):
            rewritten.append(f'displayName = "{vm_name}"')
        elif re.match(r"^serial0\.fileName\s*=", line):
            rewritten.append(f'serial0.fileName = "{serial_name}"')
        elif re.match(r"^ide1:0\.fileName\s*=", line):
            rewritten.append(f'ide1:0.fileName = "{remote_iso}"')
        else:
            rewritten.append(line)
    if mode == "directpath-unmonitored":
        if system_uuid is None:
            raise ValueError("DirectPath smoke requires the ESXi system UUID")
        rewritten.extend(
            (
                f'pciPassthru0.id = "{vmx_pci_id(bdf)}"',
                f'pciPassthru0.deviceId = "0x{device_id:04x}"',
                f'pciPassthru0.vendorId = "0x{vendor_id:04x}"',
                f'pciPassthru0.systemId = "{system_uuid}"',
                'pciPassthru0.present = "TRUE"',
            )
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def remote_sha256(ssh: EsxiSsh, path: str) -> str:
    result = ssh.run(
        f"sha256sum {shlex.quote(path)}",
        check=False,
        timeout=120,
    )
    match = re.search(r"(?m)^([0-9a-fA-F]{64})\s+", result.stdout)
    if result.returncode != 0 or match is None:
        raise BlockedEnvironment(
            f"could not hash remote probe ISO {path!r}: "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
    return match.group(1).lower()


def parse_serial_contract(
    text: str,
    *,
    expected_window_seconds: int,
    expect_runner_managed: bool,
) -> dict[str, Any]:
    required_markers = (
        *BASE_REQUIRED_MARKERS,
        f"AER-WINDOW seconds={expected_window_seconds}",
        *(("AER-HEARTBEAT index=0",) if expect_runner_managed else ()),
    )
    marker_checks = {marker: marker in text for marker in required_markers}
    cmdline_line = next(
        (
            line
            for line in text.splitlines()
            if line.startswith("cmdline:")
        ),
        "",
    )
    required_cmdline_tokens = list(BASE_REQUIRED_CMDLINE_TOKENS)
    if expect_runner_managed:
        required_cmdline_tokens.extend(
            (
                f"aer_window_seconds={expected_window_seconds}",
                "aer_runner_managed=1",
                "aer_runner_grace_seconds=300",
            )
        )
    token_checks = {
        token: token in cmdline_line
        for token in required_cmdline_tokens
    }
    return {
        "bytes": len(text.encode("utf-8")),
        "markerChecks": marker_checks,
        "cmdline": cmdline_line,
        "cmdlineTokenChecks": token_checks,
        "complete": all(marker_checks.values()) and all(token_checks.values()),
    }


def read_remote_text(ssh: EsxiSsh, path: str) -> str:
    result = ssh.run(
        f"test -f {shlex.quote(path)} && cat {shlex.quote(path)}",
        check=False,
        timeout=30,
    )
    return result.stdout if result.returncode == 0 else ""


def wait_for_powered_on(
    ssh: EsxiSsh,
    vmid: str,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        state = ssh.run(
            f"vim-cmd vmsvc/power.getstate {vmid}",
            check=False,
            timeout=30,
        )
        last = state.stdout + state.stderr
        if state.returncode == 0 and "Powered on" in state.stdout:
            return {
                "observedAt": utc_now(),
                "state": "poweredOn",
                "raw": last.strip(),
            }
        time.sleep(2)
    raise BlockedEnvironment(
        f"smoke VM did not reach powered-on state: {last.strip()}"
    )


def wait_for_serial_contract(
    ssh: EsxiSsh,
    serial_path: str,
    *,
    timeout_seconds: int,
    expected_window_seconds: int,
    expect_runner_managed: bool,
) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    text = ""
    contract = parse_serial_contract(
        text,
        expected_window_seconds=expected_window_seconds,
        expect_runner_managed=expect_runner_managed,
    )
    while time.monotonic() < deadline:
        text = read_remote_text(ssh, serial_path)
        contract = parse_serial_contract(
            text,
            expected_window_seconds=expected_window_seconds,
            expect_runner_managed=expect_runner_managed,
        )
        if contract["complete"]:
            contract["observedAt"] = utc_now()
            return text, contract
        time.sleep(2)
    raise BlockedEnvironment(
        "AER probe ISO did not satisfy the boot serial contract: "
        + json.dumps(contract, sort_keys=True)
    )


def collect_vm_artifacts(
    transfer: EsxiScp,
    remote_dir: str,
    remote_vmx_name: str,
    serial_name: str,
    output_dir: Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for remote_name, local_name in (
        (serial_name, "guest-serial-final.log"),
        ("vmware.log", "vmware.log"),
        (remote_vmx_name, "effective.vmx"),
    ):
        copied = transfer.from_esxi(
            f"{remote_dir}/{remote_name}",
            output_dir / local_name,
            required=False,
        )
        records.append(
            {
                "remote": remote_name,
                "local": local_name,
                "copied": copied,
            }
        )
    return records


def cleanup_vm(
    *,
    ssh: EsxiSsh,
    transfer: EsxiScp,
    api: ApiSession | None,
    bdf: str,
    vmid: str | None,
    remote_dir: str,
    remote_vmx_name: str,
    serial_name: str,
    output_dir: Path,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "startedAt": utc_now(),
        "artifactCopies": collect_vm_artifacts(
            transfer,
            remote_dir,
            remote_vmx_name,
            serial_name,
            output_dir,
        ),
        "actions": [],
    }
    if vmid is not None:
        state = ssh.run(
            f"vim-cmd vmsvc/power.getstate {vmid}",
            check=False,
            timeout=30,
        )
        if "Powered on" in state.stdout:
            power = ssh.run(
                f"vim-cmd vmsvc/power.off {vmid}",
                check=False,
                timeout=180,
            )
            record["actions"].append(
                {
                    "action": "powerOff",
                    "returnCode": power.returncode,
                    "output": (power.stdout + power.stderr).strip(),
                }
            )
        unregister = ssh.run(
            f"vim-cmd vmsvc/unregister {vmid}",
            check=False,
            timeout=60,
        )
        record["actions"].append(
            {
                "action": "unregister",
                "returnCode": unregister.returncode,
                "output": (unregister.stdout + unregister.stderr).strip(),
            }
        )
    if api is not None:
        probe = isolated_active_passthrough_users(api, bdf)
        record["remainingActivePassthroughUsers"] = probe["users"]
        record["activeUserProbe"] = {
            "mode": "ISOLATED_PROCESS",
            "capturedAt": probe.get("capturedAt"),
        }
    inventory = ssh.run(
        "vim-cmd vmsvc/getallvms",
        check=False,
        timeout=60,
    )
    record["matchingRegisteredRows"] = [
        line
        for line in inventory.stdout.splitlines()
        if remote_dir in line
    ]
    record["finishedAt"] = utc_now()
    return record


def write_manifest(output_dir: Path) -> str:
    manifest_path = output_dir / "artifact-manifest.sha256"
    lines = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        lines.append(f"{sha256_file(path)}  {path.relative_to(output_dir).as_posix()}")
    save_text(manifest_path, "\n".join(lines) + "\n")
    return sha256_file(manifest_path)


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.authorized_lab_target:
        raise BlockedEnvironment("--authorized-lab-target is required")
    if args.mode not in MODES:
        raise ValueError(f"unsupported mode: {args.mode}")
    if canonical_bdf(args.bdf) is None:
        raise ValueError(f"invalid target BDF: {args.bdf}")
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    run_id = validate_safe_id(output_dir.name, "run ID")
    local_iso = Path(args.local_iso).resolve()
    base_vmx = Path(args.base_vmx).resolve()
    if not local_iso.is_file() or not base_vmx.is_file():
        raise BlockedEnvironment("local ISO or base VMX is absent")

    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password)
    transfer = EsxiScp(args.host, "root", password)
    api: ApiSession | None = None
    directpath = args.mode == "directpath-unmonitored"
    if directpath:
        api = ApiSession(
            args.host,
            "root",
            password,
            http_connection_timeout=15,
        )
    local_iso_hash = sha256_file(local_iso)
    remote_iso_hash = remote_sha256(ssh, args.remote_iso)
    if local_iso_hash != remote_iso_hash:
        raise BlockedEnvironment(
            "local/remote AER probe ISO hash mismatch: "
            f"local={local_iso_hash}, remote={remote_iso_hash}"
        )

    vm_name = validate_safe_id(
        f"aer-smoke-{run_id}-{args.mode}",
        "VM name",
    )
    case_id = validate_safe_id(args.mode, "case ID")
    serial_name = f"guest-serial-{case_id}.log"
    remote_dir = (
        f"/vmfs/volumes/{args.datastore}/directpath-cases/"
        f"aer-boot-smoke/{run_id}/{case_id}"
    )
    remote_vmx_name = f"{case_id}.vmx"
    remote_vmx = f"{remote_dir}/{remote_vmx_name}"
    local_vmx = output_dir / "input.vmx"
    system_uuid = api.system_uuid if api is not None else None
    create_smoke_vmx(
        base_vmx=base_vmx,
        output=local_vmx,
        vm_name=vm_name,
        serial_name=serial_name,
        remote_iso=args.remote_iso,
        mode=args.mode,
        bdf=args.bdf,
        vendor_id=args.vendor_id,
        device_id=args.device_id,
        system_uuid=system_uuid,
    )

    result: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "ESXI_AER_GUEST_BOOT_SMOKE",
        "runId": run_id,
        "mode": args.mode,
        "startedAt": utc_now(),
        "claimBoundary": {
            "scope": (
                "Public ESXi VMX, inventory, serial and vmware.log "
                "boot observability"
            ),
            "aerInjectionAttempted": False,
            "qtestWritesIssued": False,
            "doesNotProveVmwareBehavior": True,
        },
        "iso": {
            "localPath": str(local_iso),
            "remotePath": args.remote_iso,
            "localSha256": local_iso_hash,
            "remoteSha256": remote_iso_hash,
            "exact": True,
        },
        "serialExpectations": {
            "windowSeconds": args.expected_window_seconds,
            "runnerManaged": args.expect_runner_managed,
        },
        "vm": {
            "name": vm_name,
            "remoteDirectory": remote_dir,
            "remoteVmx": remote_vmx,
            "directpath": directpath,
        },
        "status": "RUNNING",
        "fault": None,
        "cleanup": None,
    }
    save_json(output_dir / "run-manifest.json", result)

    vmid: str | None = None
    try:
        if api is not None:
            initial_probe = isolated_active_passthrough_users(api, args.bdf)
            result["initialActivePassthroughUsers"] = initial_probe["users"]
            if initial_probe["users"]:
                raise BlockedEnvironment(
                    "target already has active passthrough users"
                )
        prepare = ssh.run(
            f"mkdir -p {shlex.quote(remote_dir)} && "
            f"test ! -e {shlex.quote(remote_vmx)}",
            check=False,
            timeout=60,
        )
        if prepare.returncode != 0:
            raise BlockedEnvironment(
                f"remote smoke path already exists or is unavailable: {remote_dir}"
            )
        transfer.to_esxi(local_vmx, remote_vmx)
        registration = ssh.run(
            f"vim-cmd solo/registervm {shlex.quote(remote_vmx)}",
            timeout=60,
        )
        candidates = [
            line.strip()
            for line in registration.stdout.splitlines()
            if re.fullmatch(r"\d+", line.strip())
        ]
        if not candidates:
            raise BlockedEnvironment(
                f"could not parse smoke VMID: {registration.stdout!r}"
            )
        vmid = candidates[-1]
        result["vm"]["vmid"] = vmid
        power = ssh.run(
            f"vim-cmd vmsvc/power.on {vmid}",
            check=False,
            timeout=180,
        )
        save_text(
            output_dir / "power-on.txt",
            power.stdout + power.stderr,
        )
        if power.returncode != 0:
            raise BlockedEnvironment(
                "smoke VM failed to power on: "
                + (power.stdout + power.stderr).strip()
            )
        result["poweredOn"] = wait_for_powered_on(
            ssh,
            vmid,
            timeout_seconds=min(args.timeout, 180),
        )
        serial_path = f"{remote_dir}/{serial_name}"
        serial_text, serial_contract = wait_for_serial_contract(
            ssh,
            serial_path,
            timeout_seconds=args.timeout,
            expected_window_seconds=args.expected_window_seconds,
            expect_runner_managed=args.expect_runner_managed,
        )
        save_text(output_dir / "guest-serial-observed.log", serial_text)
        result["serialContract"] = serial_contract
        if api is not None:
            active_probe = isolated_active_passthrough_users(api, args.bdf)
            result["activePassthroughUsers"] = active_probe["users"]
            if not any(
                item.get("vm") == vm_name
                for item in active_probe["users"]
                if isinstance(item, dict)
            ):
                raise BlockedEnvironment(
                    "DirectPath smoke VM was not correlated to the target BDF"
                )
        result["status"] = "PASS"
    except BaseException as error:
        result["status"] = "BLOCKED"
        result["fault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        try:
            result["cleanup"] = cleanup_vm(
                ssh=ssh,
                transfer=transfer,
                api=api,
                bdf=args.bdf,
                vmid=vmid,
                remote_dir=remote_dir,
                remote_vmx_name=remote_vmx_name,
                serial_name=serial_name,
                output_dir=output_dir,
            )
        except BaseException as cleanup_error:
            result["cleanup"] = {
                "fault": {
                    "type": type(cleanup_error).__name__,
                    "message": str(cleanup_error),
                }
            }
            result["status"] = "BLOCKED"
        if api is not None:
            api.close(remote_logout=True)
        result["finishedAt"] = utc_now()
        cleanup = result.get("cleanup")
        cleanup_complete = bool(
            isinstance(cleanup, dict)
            and not cleanup.get("fault")
            and not cleanup.get("matchingRegisteredRows")
            and not cleanup.get("remainingActivePassthroughUsers")
            and all(
                item.get("returnCode") == 0
                for item in cleanup.get("actions", [])
                if item.get("action") in {"powerOff", "unregister"}
            )
        )
        result["cleanupComplete"] = cleanup_complete
        if not cleanup_complete:
            result["status"] = "BLOCKED"
        save_json(output_dir / "result.json", result)
        result_hash = sha256_file(output_dir / "result.json")
        save_text(
            output_dir / "result.json.sha256",
            f"{result_hash}  result.json\n",
        )
        result["artifactManifestSha256"] = write_manifest(output_dir)
        result["resultSha256"] = result_hash
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument(
        "--remote-iso",
        default=(
            "/vmfs/volumes/pci-mmio-local/iso/"
            "esxi-l3-aer-probe.iso"
        ),
    )
    parser.add_argument("--local-iso", default=str(DEFAULT_LOCAL_ISO))
    parser.add_argument("--base-vmx", default=str(DEFAULT_BASE_VMX))
    parser.add_argument("--bdf", default="0000:01:00.1")
    parser.add_argument("--vendor-id", type=lambda value: int(value, 0), default=0x1AF4)
    parser.add_argument("--device-id", type=lambda value: int(value, 0), default=0x1041)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--expected-window-seconds", type=int, default=90)
    parser.add_argument(
        "--expect-runner-managed",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--authorized-lab-target", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.timeout <= 0 or args.expected_window_seconds <= 0:
        raise SystemExit("timeout/window values must be positive")
    result = run(args)
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
