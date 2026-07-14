#!/usr/bin/env python3
"""Observe ESXi DirectPath behavior for an emulated SR-IOV PF and VF."""

from __future__ import annotations

import argparse
import atexit
import json
import re
import shutil
import ssl
import time
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field,
    collect_case,
    ensure_nfs_datastore,
    utc_now,
    wait_for_esxi,
)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def api_passthru(result: dict[str, Any], bdf: str) -> dict[str, Any] | None:
    for item in result.get("esxi", {}).get("api", {}).get("pciPassthruInfo", []):
        if item.get("id") == bdf:
            return item
    return None


def host_object(content) -> vim.HostSystem:
    view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True
    )
    try:
        hosts = list(view.view)
    finally:
        view.Destroy()
    if len(hosts) != 1:
        raise RuntimeError(f"expected one direct ESXi host, found {len(hosts)}")
    return hosts[0]


def wait_serial(path: Path, marker: str, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if marker in text:
                return text
        time.sleep(2)
    raise TimeoutError(f"missing {marker!r} in {path}")


def parse_surface(serial: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    pattern = re.compile(
        r"^SRIOV-SURFACE bdf=(?P<bdf>\S+) vendor=(?P<vendor>\S+) "
        r"device=(?P<device>\S+) totalvfs=(?P<totalvfs>\S+) "
        r"numvfs=(?P<numvfs>\S+) physfn=(?P<physfn>\S+) "
        r"h100=(?P<h100>\S+) h120=(?P<h120>\S+) "
        r"ctrl=(?P<ctrl>\S+) counts=(?P<counts>\S+)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(serial):
        records.append(match.groupdict())
    return records


def parse_actions(serial: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    pattern = re.compile(
        r"^SRIOV-ACTION bdf=(?P<bdf>\S+) driver=(?P<driver>\S+) "
        r"num-before=(?P<num_before>\S+) enable=(?P<enable>\S+) "
        r"num-after=(?P<num_after>\S+) vf-count=(?P<vf_count>\S+) "
        r"disable=(?P<disable>\S+) num-final=(?P<num_final>\S+)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(serial):
        records.append(match.groupdict())
    return records


def sriov_capability_visible(record: dict[str, str] | None, serial: str) -> bool:
    if record is not None:
        try:
            if int(record["h120"], 0) & 0xFFFF == 0x10:
                return True
        except (KeyError, ValueError):
            pass
    return "single root i/o virtualization" in serial.lower()


def run_guest_case(
    *,
    case_name: str,
    bdf: str,
    host: vim.HostSystem,
    ssh: EsxiSsh,
    output: Path,
    nfs_root: Path,
    datastore: str,
    iso_name: str,
    timeout: int,
    pf_capability_expectation: str,
    pf_functional_expectation: str,
    expected_vendor: str,
    expected_device: str,
) -> dict[str, Any]:
    case_dir = output / case_name
    case_dir.mkdir(parents=True, exist_ok=True)
    vm_name = f"sriov-{output.name}-{case_name}"
    relative_root = f"sriov/{output.name}/{case_name}/{vm_name}"
    vm_root = nfs_root / relative_root
    serial_path = vm_root / "guest-serial.log"
    vmware_log = vm_root / "vmware.log"
    registered_id: str | None = None
    result: dict[str, Any] = {
        "case": case_name,
        "hostBdf": bdf,
        "startedAt": utc_now(),
        "verdict": "running",
    }

    owner_enable = ssh.run(
        f"esxcli hardware pci pcipassthru set -d {bdf} -e true -a",
        check=False,
        timeout=90,
    )
    result["ownerEnable"] = {
        "returnCode": owner_enable.returncode,
        "stdout": owner_enable.stdout.splitlines(),
        "stderr": owner_enable.stderr.splitlines(),
    }
    if owner_enable.returncode != 0:
        result["verdict"] = "fail"
        result["finishedAt"] = utc_now()
        return result

    try:
        extra = lab.static_pci_lines(host, bdf, index=0)
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{datastore}/iso/{iso_name}",
            extra_lines=extra,
        )
        register = ssh.run(
            "vim-cmd solo/registervm "
            f"/vmfs/volumes/{datastore}/{relative_root}/{vmx_path.name}",
            check=False,
            timeout=90,
        )
        result["register"] = {
            "returnCode": register.returncode,
            "stdout": register.stdout.splitlines(),
            "stderr": register.stderr.splitlines(),
        }
        match = re.search(r"(?m)^\s*(\d+)\s*$", register.stdout)
        if register.returncode != 0 or not match:
            result["verdict"] = "fail"
            return result
        registered_id = match.group(1)
        if serial_path.exists():
            serial_path.unlink()
        power = ssh.run(
            f"vim-cmd vmsvc/power.on {registered_id}",
            check=False,
            timeout=120,
        )
        result["powerOn"] = {
            "returnCode": power.returncode,
            "stdout": power.stdout.splitlines(),
            "stderr": power.stderr.splitlines(),
        }
        if power.returncode != 0:
            result["verdict"] = "fail"
            return result

        serial = wait_serial(serial_path, "SRIOV-SURFACE-PROBE-COMPLETE", timeout)
        records = parse_surface(serial)
        actions = parse_actions(serial)
        expected_record = next(
            (
                item
                for item in records
                if item["vendor"] == expected_vendor
                and item["device"] == expected_device
            ),
            None,
        )
        expected_action = next(
            (
                item
                for item in actions
                if expected_record is not None and item["bdf"] == expected_record["bdf"]
            ),
            None,
        )
        capability_visible = sriov_capability_visible(expected_record, serial)
        functional_counts_nonzero = False
        if expected_record is not None:
            try:
                functional_counts_nonzero = int(expected_record["counts"], 0) != 0
            except (KeyError, ValueError):
                pass
            functional_counts_nonzero = functional_counts_nonzero or (
                expected_record.get("totalvfs") not in {None, "absent", "0"}
            )
        if case_name == "pf":
            capability_expectation_met = (
                pf_capability_expectation == "any"
                or (pf_capability_expectation == "visible" and capability_visible)
                or (pf_capability_expectation == "hidden" and not capability_visible)
            )
            functional_expectation_met = (
                pf_functional_expectation == "any"
                or (
                    pf_functional_expectation == "enabled"
                    and functional_counts_nonzero
                )
                or (
                    pf_functional_expectation == "disabled"
                    and not functional_counts_nonzero
                )
            )
        else:
            capability_expectation_met = not capability_visible
            functional_expectation_met = True
        checks = {
            "oneTargetVisible": len(records) == 1,
            "targetIdMatches": expected_record is not None,
            "targetModulesLoaded": (
                "igb=ok igbvf=ok" in serial
                if expected_vendor == "0x8086"
                else "SRIOV-MODULES nvme-core=ok nvme=ok" in serial
            ),
            "actionRecorded": expected_action is not None,
            "capabilityExpectationMet": capability_expectation_met,
            "functionalExpectationMet": functional_expectation_met,
            "probeCompleted": "SRIOV-SURFACE-PROBE-COMPLETE" in serial,
        }
        result["guest"] = {
            "records": records,
            "actions": actions,
            "observed": {
                "sriovCapabilityVisible": capability_visible,
                "functionalSriovAdvertised": functional_counts_nonzero,
                "pfCapabilityExpectation": (
                    pf_capability_expectation if case_name == "pf" else None
                ),
                "pfFunctionalExpectation": (
                    pf_functional_expectation if case_name == "pf" else None
                ),
            },
            "checks": checks,
            "serialEvidence": "guest-serial.log",
        }
        result["verdict"] = "pass" if all(checks.values()) else "fail"
        shutil.copyfile(serial_path, case_dir / "guest-serial.log")
        if vmware_log.exists():
            shutil.copyfile(vmware_log, case_dir / "vmware.log")
        shutil.copyfile(vmx_path, case_dir / "effective.vmx")
        return result
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["verdict"] = "fail"
        return result
    finally:
        if registered_id is not None:
            ssh.run(
                f"vim-cmd vmsvc/power.off {registered_id}",
                check=False,
                timeout=90,
            )
            ssh.run(
                f"vim-cmd vmsvc/unregister {registered_id}",
                check=False,
                timeout=90,
            )
        disable = ssh.run(
            f"esxcli hardware pci pcipassthru set -d {bdf} -e false -a",
            check=False,
            timeout=90,
        )
        result["ownerDisable"] = {
            "returnCode": disable.returncode,
            "stdout": disable.stdout.splitlines(),
            "stderr": disable.stderr.splitlines(),
        }
        result["finishedAt"] = utc_now()
        save(case_dir / "result.json", result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--pf", default="0000:02:00.0")
    parser.add_argument("--vf", default="0000:02:00.1")
    parser.add_argument("--pf-vendor", default="0x1b36")
    parser.add_argument("--pf-device", default="0x0010")
    parser.add_argument("--vf-vendor", default="0x1b36")
    parser.add_argument("--vf-device", default="0x0010")
    parser.add_argument("--root-port", default="0000:00:0a.0")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument(
        "--iso", default="/mnt/e/Code/PCI/_artifacts/esxi-l3-sriov-probe.iso"
    )
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--host-timeout", type=int, default=600)
    parser.add_argument(
        "--pf-capability-expectation",
        choices=("any", "visible", "hidden"),
        default="any",
    )
    parser.add_argument(
        "--pf-functional-expectation",
        choices=("any", "enabled", "disabled"),
        default="any",
    )
    parser.add_argument(
        "--require-vf",
        action="store_true",
        help="fail if the VF is absent, incapable, or fails its guest probe",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password, args.user)
    wait_for_esxi(ssh, timeout=args.host_timeout)
    ensure_nfs_datastore(ssh, volume=args.datastore)
    nfs_root = Path(args.nfs_root)
    iso_source = Path(args.iso)
    if not iso_source.is_file():
        raise FileNotFoundError(iso_source)
    iso_target = nfs_root / "iso" / iso_source.name
    iso_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(iso_source, iso_target)

    host_result = collect_case(
        output / "host-surface",
        case_id="ESXi-SR-IOV-host-surface",
        host=args.host,
        user=args.user,
        password=password,
        qemu_name=args.qemu_name,
        monitor=Path(args.monitor),
        targets=[args.root_port, args.pf, args.vf],
        requested={
            "mode": "SR-IOV PF/VF DirectPath surface",
            "pf": args.pf,
            "vf": args.vf,
        },
    )

    context = ssl._create_unverified_context()
    service_instance = SmartConnect(
        host=args.host,
        user=args.user,
        pwd=password,
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)
    host = host_object(service_instance.RetrieveContent())

    result: dict[str, Any] = {
        "case": "ESXi-DirectPath-SR-IOV-PF-VF",
        "startedAt": utc_now(),
        "input": {
            "pf": args.pf,
            "vf": args.vf,
            "rootPort": args.root_port,
            "pfId": f"{args.pf_vendor}:{args.pf_device}",
            "vfId": f"{args.vf_vendor}:{args.vf_device}",
            "pfCapabilityExpectation": args.pf_capability_expectation,
            "pfFunctionalExpectation": args.pf_functional_expectation,
            "requireVf": args.require_vf,
        },
        "hostSurface": {
            bdf: {
                "present": (
                    host_result.get("devices", {})
                    .get(bdf, {})
                    .get("config", {})
                    .get("vendorId")
                    not in {None, "0x0000", "0xffff"}
                ),
                "passthru": api_passthru(host_result, bdf),
                "config": host_result.get("devices", {}).get(bdf, {}).get("config"),
            }
            for bdf in (args.pf, args.vf)
        },
        "guests": {},
    }
    # Exercise the VF first. A PF reset is allowed to disable all VFs.
    for case_name, bdf in (("vf", args.vf), ("pf", args.pf)):
        passthru = api_passthru(host_result, bdf)
        if not passthru or not passthru.get("passthruCapable"):
            result["guests"][case_name] = {
                "verdict": "blocked-by-host-admission",
                "passthru": passthru,
            }
            continue
        result["guests"][case_name] = run_guest_case(
            case_name=case_name,
            bdf=bdf,
            host=host,
            ssh=ssh,
            output=output,
            nfs_root=nfs_root,
            datastore=args.datastore,
            iso_name=iso_source.name,
            timeout=args.timeout,
            pf_capability_expectation=args.pf_capability_expectation,
            pf_functional_expectation=args.pf_functional_expectation,
            expected_vendor=(
                args.pf_vendor if case_name == "pf" else args.vf_vendor
            ),
            expected_device=(
                args.pf_device if case_name == "pf" else args.vf_device
            ),
        )

    guest_verdicts = [item.get("verdict") for item in result["guests"].values()]
    if args.require_vf and result["guests"].get("vf", {}).get("verdict") != "pass":
        result["verdict"] = "fail"
    else:
        result["verdict"] = (
            "pass" if guest_verdicts and all(item == "pass" for item in guest_verdicts)
            else "partial" if any(item == "pass" for item in guest_verdicts)
            else "blocked" if guest_verdicts and all(
                item == "blocked-by-host-admission" for item in guest_verdicts
            )
            else "fail"
        )
    result["finishedAt"] = utc_now()
    save(output / "result.json", result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] in {"pass", "partial", "blocked"} else 1)


if __name__ == "__main__":
    main()
