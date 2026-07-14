#!/usr/bin/env python3
"""Exercise DirectPath peer DMA with a QEMU EDU source and ivshmem BAR."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import shlex
import shutil
import time
from pathlib import Path

from pyVim.connect import Disconnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import (
    EsxiSsh,
    collect_case,
    ensure_nfs_datastore,
    parse_esxcli_pci,
    utc_now,
)
from qemu_simpletrace import decode_simpletrace
from test_esxi_flr_reset import connect_vcenter, wait_connected_host
from test_esxi_passthru_capability_matrix import (
    CAPABILITY_QEMU,
    MONITOR,
    RESTORE_ENV,
    start_outer,
    stop_outer,
)


TRACE_FILE = Path("/root/vm/esxi8-mf/qemu-trace.log")
PEER_BACKING = Path("/root/vm/esxi8-mf/p2p-peer.bin")
PEER_PATTERN = bytes(value ^ 0x6D for value in range(256))
P2P_ENV = {
    "QEMU_ESXI_TOPOLOGY": "pcie",
    "QEMU_ESXI_PRIMARY_DEDICATED_ROOT_PORT": "1",
    "QEMU_ESXI_IVSHMEM_SIZE": "0",
    "QEMU_ESXI_IVSHMEM_ALT_SIZE": "1M",
    "QEMU_ESXI_IVSHMEM_ALT_MEM_PATH": "/root/vm/esxi8-mf/p2p-peer.bin",
    "QEMU_ESXI_IVSHMEM_ALT_OPTIONS": ",x-page-aligned-bar0=on",
    "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
    "QEMU_ESXI_EDU": "1",
    "QEMU_ESXI_EDU_DMA_MASK": "0xffffffffffffffff",
    "QEMU_ESXI_VIRTIO_NET": "0",
    "QEMU_ESXI_TRACE": "1",
    "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
}
CASES = {
    "default": {},
    "allow-only": {"pciPassthru.allowP2P": "TRUE"},
    "relax-only": {"pciPassthru.relaxACSforP2P": "TRUE"},
    "allow-and-relax": {
        "pciPassthru.allowP2P": "TRUE",
        "pciPassthru.relaxACSforP2P": "TRUE",
    },
}


def save(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def selected_trace(source_bdf: str) -> list[str]:
    decoded = decode_simpletrace(TRACE_FILE)
    _, bus, slot_function = source_bdf.split(":")
    slot, function = slot_function.split(".")
    qemu_requester = f"dev {bus}:{slot}.{int(function):02d}"
    structured_requester = (
        f"bus=0x{int(bus, 16):x} slot=0x{int(slot, 16):x} "
        f"func=0x{int(function, 16):x}"
    )
    return [
        line
        for line in decoded.splitlines()
        if (
            (
                line.startswith("vtd_dmar_translate ")
                and (qemu_requester in line or structured_requester in line)
            )
            or line.startswith("vtd_dmar_fault ")
        )
    ]


def passthrough_info(host, bdf: str) -> dict:
    item = next(entry for entry in host.config.pciPassthruInfo if entry.id == bdf)
    return {
        "enabled": item.passthruEnabled,
        "active": item.passthruActive,
        "capable": item.passthruCapable,
        "dependent": item.dependentDevice,
    }


def log_excerpt(path: Path) -> list[str]:
    if not path.exists():
        return []
    pattern = re.compile(r"PCIPassthru|IOMMU|P2P|peer|DevicePowerOn", re.IGNORECASE)
    return [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if pattern.search(line)
    ][-500:]


def wait_p2p_terminal(vm, serial_path: Path, timeout: int) -> str:
    """Wait for the probe marker or an ESXi-enforced VM power-off."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if serial_path.exists():
            serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
            if "P2P-TEST-COMPLETE" in serial_text:
                return "guest-complete"
        vm.Reload()
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
            return "vm-powered-off"
        time.sleep(2)
    raise TimeoutError(f"P2P probe did not reach a terminal state in {timeout}s")


def peer_bus_from_serial(serial_text: str) -> int | None:
    result_match = re.search(
        r"EDU-P2P-(?:PASS|FAIL).*peer_bus=0x([0-9a-fA-F]+)",
        serial_text,
    )
    if result_match:
        return int(result_match.group(1), 16)

    resource_match = re.search(
        r"(?ms)^[^\r\n]+ vendor=0x1af4 device=0x1110\r?\n"
        r"(?P<resources>(?:0x[0-9a-fA-F]+ 0x[0-9a-fA-F]+ 0x[0-9a-fA-F]+\r?\n)+)",
        serial_text,
    )
    if not resource_match:
        return None
    starts = [
        int(start, 16)
        for start in re.findall(
            r"(?m)^(0x[0-9a-fA-F]+) ",
            resource_match["resources"],
        )
    ]
    # ivshmem BAR2 is the peer-memory aperture; BAR0 is only registers.
    if len(starts) > 2 and starts[2]:
        return starts[2]
    return None


def peer_backing_snapshot(case_dir: Path) -> dict:
    data = PEER_BACKING.read_bytes()[: len(PEER_PATTERN)]
    (case_dir / "outer-peer-backing-first-256.hex").write_text(
        data.hex() + "\n",
        encoding="ascii",
    )
    return {
        "path": str(PEER_BACKING),
        "bytesRead": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "matchesDmaPattern": data == PEER_PATTERN,
    }


def register_vm_with_host_fallback(
    ssh: EsxiSsh,
    content,
    datacenter,
    cluster,
    host,
    datastore: str,
    relative_path: str,
    name: str,
    timeout: int,
) -> tuple[object, dict]:
    try:
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            datastore,
            relative_path,
            name,
        )
        return vm, {"method": "vcenter-RegisterVM_Task"}
    except Exception as primary_error:
        evidence = {
            "method": "host-vim-cmd-fallback",
            "vcenterFault": lab.fault_snapshot(primary_error),
        }

    datastore_path = f"[{datastore}] {relative_path}"
    host_path = f"/vmfs/volumes/{datastore}/{relative_path}"
    command = (
        f"vim-cmd solo/registervm {shlex.quote(host_path)} "
        f"{shlex.quote(name)}"
    )
    completed = ssh.run(command, check=False, timeout=120)
    evidence["hostRegistration"] = {
        "command": command,
        "exitCode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        raise RuntimeError(
            "Both vCenter and host VM registration failed: "
            f"{completed.stdout}{completed.stderr}"
        )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        vm = content.searchIndex.FindByDatastorePath(
            datacenter=datacenter,
            path=datastore_path,
        )
        if vm is None:
            vm = next(
                (
                    item
                    for item in lab.inventory(content, vim.VirtualMachine)
                    if item.name == name
                ),
                None,
            )
        if vm is not None:
            evidence["vcenterInventorySynchronized"] = True
            evidence["datastorePath"] = datastore_path
            return vm, evidence
        time.sleep(2)
    evidence["vcenterInventorySynchronized"] = False
    raise TimeoutError(
        f"Host-registered VM {name!r} did not appear in vCenter inventory"
    )


def run_case(
    case_id: str,
    flags: dict[str, str],
    expected_outcome: str,
    output_dir: Path,
    ssh: EsxiSsh,
    content,
    datacenter,
    cluster,
    host,
    datastore: str,
    nfs_root: Path,
    iso: str,
    timeout: int,
    source_bdf: str,
    peer_bdf: str,
) -> dict:
    case_dir = output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "startedAt": utc_now(),
        "vmxP2PFlags": flags,
        "expectedOutcome": expected_outcome,
        "verdict": "running",
    }
    vm = None
    vm_name = None
    vm_root = None
    serial_path = None
    vmware_log = None
    before = selected_trace(source_bdf)
    try:
        vm_name = f"p2p-{output_dir.name}-{case_id}"
        relative_root = f"p2p/{output_dir.name}/{case_id}"
        vm_root = nfs_root / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        vmware_log = vm_root / "vmware.log"

        existing = [
            item for item in lab.inventory(content, vim.VirtualMachine) if item.name == vm_name
        ]
        if existing:
            lab.power_off(existing[0])
            existing[0].UnregisterVM()

        extra = lab.static_pci_lines(host, source_bdf, index=0)
        extra.extend(lab.static_pci_lines(host, peer_bdf, index=1))
        extra.extend(f'{key} = "{value}"' for key, value in flags.items())
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{datastore}/iso/{iso}",
            extra_lines=extra,
        )
        vm, record["registration"] = register_vm_with_host_fallback(
            ssh,
            content,
            datacenter,
            cluster,
            host,
            datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
            timeout,
        )
        record["configured"] = lab.vm_snapshot(vm)

        if serial_path.exists():
            serial_path.unlink()
        lab.wait_task(vm.PowerOnVM_Task(host=host))
        record["terminalReason"] = wait_p2p_terminal(vm, serial_path, timeout)
        record["poweredOn"] = lab.vm_snapshot(vm)
        serial_text = (
            serial_path.read_text(encoding="utf-8", errors="replace")
            if serial_path.exists()
            else ""
        )
        record["guest"] = {
            "p2pPass": "EDU-P2P-PASS" in serial_text,
            "p2pFail": "EDU-P2P-FAIL" in serial_text,
            "result": next(
                iter(re.findall(r"(?m)^P2P-RESULT=(\w+)", serial_text)),
                None,
            ),
            "complete": "P2P-TEST-COMPLETE" in serial_text,
        }
        peer_bus = peer_bus_from_serial(serial_text)
        record["guest"]["peerBus"] = f"0x{peer_bus:x}" if peer_bus is not None else None

        lab.power_off(vm)
        time.sleep(2)

        # The guest only clears this BAR through CPU MMIO; the XOR pattern is
        # written exclusively by EDU DMA.  Reading the shared backing here is
        # an independent outer-QEMU witness even when the IOMMU trace hits a
        # cached translation and emits no new translate event.
        record["outerPeerBacking"] = peer_backing_snapshot(case_dir)

        after = selected_trace(source_bdf)
        delta = after[len(before) :]
        (case_dir / "outer-vtd-delta.log").write_text(
            "\n".join(delta) + ("\n" if delta else ""),
            encoding="utf-8",
        )
        translations = [line for line in delta if line.startswith("vtd_dmar_translate ")]
        faults = [line for line in delta if line.startswith("vtd_dmar_fault ")]
        peer_translations = []
        if peer_bus is not None:
            for line in translations:
                match = re.search(r"iova 0x([0-9a-fA-F]+).*mask 0x([0-9a-fA-F]+)", line)
                if not match:
                    continue
                base = int(match.group(1), 16)
                mask = int(match.group(2), 16)
                if base <= peer_bus <= base + mask:
                    peer_translations.append(line)
        record["outerVtd"] = {
            "sourceTranslationCount": len(translations),
            "faultCount": len(faults),
            "peerIovaTranslationCount": len(peer_translations),
            "peerIovaTranslations": peer_translations,
        }
        for source, name in (
            (serial_path, "guest-serial.log"),
            (vmware_log, "vmware.log"),
            (vm_root / f"{vm_name}.vmx", "effective.vmx"),
        ):
            if source.exists():
                shutil.copyfile(source, case_dir / name)
        record["vmwareLogExcerpt"] = log_excerpt(vmware_log)
        vmware_text = (
            vmware_log.read_text(encoding="utf-8", errors="replace")
            if vmware_log.exists()
            else ""
        )
        iommu_fault = re.search(
            r"IOMMU fault type \d+ at address 0x[0-9a-fA-F]+",
            vmware_text,
        )
        verify_panic = re.search(r"PANIC: VERIFY [^\r\n]+", vmware_text)
        record["policyObservation"] = {
            "iommuFault": iommu_fault.group(0) if iommu_fault else None,
            "verifyPanic": verify_panic.group(0) if verify_panic else None,
            "devicePowerOnRejected": bool(
                re.search(r"DevicePowerOn.*(?:fail|error)", vmware_text, re.IGNORECASE)
            ),
            "vmxPanic": "PANIC:" in vmware_text,
        }

        mapping_created = "successfully created the IOMMU mappings" in vmware_text
        if expected_outcome == "dma-pass":
            checks = {
                "guestCompleted": record["guest"]["complete"],
                "mappingCreated": mapping_created,
                "peerDmaPassed": record["guest"]["p2pPass"],
                "outerPeerBackingMatchesDmaPattern": record[
                    "outerPeerBacking"
                ]["matchesDmaPattern"],
                "noOuterDmarFault": not faults,
                "noVmxIommuFault": iommu_fault is None,
            }
        elif expected_outcome == "dma-reject":
            checks = {
                "mappingCreated": mapping_created,
                "peerDmaRejected": iommu_fault is not None or verify_panic is not None,
                "vmPoweredOffByPolicy": record["terminalReason"] == "vm-powered-off",
                "noFalseGuestPass": not record["guest"]["p2pPass"],
                "outerPeerBackingDoesNotMatchDmaPattern": not record[
                    "outerPeerBacking"
                ]["matchesDmaPattern"],
            }
        else:
            checks = {
                "unexpectedPowerOn": False,
                "expectedAdmissionReject": False,
            }
        record["checks"] = checks
        record["verdict"] = "pass" if all(checks.values()) else "fail"
    except Exception as error:
        fault = lab.fault_snapshot(error)
        record["fault"] = fault
        if expected_outcome == "admission-reject":
            fault_text = fault.get("message", "")
            checks = {
                "noCompatibleHost": fault.get("type") == "vim.fault.NoCompatibleHost",
                "assignHwNotAvailable": "assignHwNotAvailable" in fault_text,
                "bothPassthruDevicesMissing": all(
                    device in fault_text for device in ("pciPassthru0", "pciPassthru1")
                ),
            }
            record["checks"] = checks
            record["verdict"] = "pass" if all(checks.values()) else "fail"
        else:
            record["verdict"] = "blocked"
        for source, name in (
            (serial_path, "guest-serial.log"),
            (vmware_log, "vmware.log"),
            (
                vm_root / f"{vm_name}.vmx"
                if vm_root is not None and vm_name is not None
                else None,
                "effective.vmx",
            ),
        ):
            if source is not None and source.exists():
                shutil.copyfile(source, case_dir / name)
    finally:
        if vm is not None:
            try:
                lab.power_off(vm)
            except Exception as error:
                record["cleanupPowerFault"] = lab.fault_snapshot(error)
            try:
                vm.UnregisterVM()
            except Exception as error:
                record["cleanupUnregisterFault"] = lab.fault_snapshot(error)
        record["finishedAt"] = utc_now()
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--esxi-caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-p2p-probe.iso")
    parser.add_argument("--timeout", type=int, default=720)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--cases",
        nargs="+",
        choices=CASES,
        default=list(CASES),
    )
    parser.add_argument(
        "--disable-acs",
        action="store_true",
        help="disable ACS on both dedicated P2P root ports",
    )
    parser.add_argument(
        "--strict-acs-check",
        action="store_true",
        help="boot ESXi with enableACSCheckForRP=TRUE",
    )
    parser.add_argument("--no-restore", action="store_true")
    args = parser.parse_args()

    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "matrix-result.json"
    result = {
        "runId": output_dir.name,
        "case": "S04-ESXi-DirectPath-peer-DMA-policy-matrix",
        "startedAt": utc_now(),
        "sourceBdf": None,
        "peerBdf": None,
        "outerTopology": {
            "dedicatedRootPorts": True,
            "acsDisabled": args.disable_acs,
            "esxiStrictAcsCheck": args.strict_acs_check,
        },
        "casesRequested": args.cases,
        "cases": {},
        "verdict": "running",
    }
    save(result_path, result)

    esxi_password = lab.caveat_field(args.esxi_caveat, "Password")
    ssh = EsxiSsh(args.host, esxi_password)
    service_instance = None
    try:
        stop_outer(ssh)
        outer_env = dict(P2P_ENV)
        if args.disable_acs:
            outer_env["QEMU_ESXI_P2P_DISABLE_ACS"] = "1"
        result["esxiVersion"] = start_outer(
            outer_env,
            ssh,
            args.timeout,
            output_dir / "outer-start.log",
            boot_options=(
                " enableACSCheckForRP=TRUE"
                if args.strict_acs_check
                else None
            ),
        ).splitlines()
        result["nfsDatastore"] = ensure_nfs_datastore(ssh, args.datastore)
        pci_records = parse_esxcli_pci(
            ssh.run("esxcli hardware pci list", timeout=120).stdout
        )
        source_matches = [
            bdf
            for bdf, item in pci_records.items()
            if item.get("Vendor ID") == "0x1234" and item.get("Device ID") == "0x11e8"
        ]
        peer_matches = [
            bdf
            for bdf, item in pci_records.items()
            if item.get("Vendor ID") == "0x1af4" and item.get("Device ID") == "0x1110"
        ]
        if len(source_matches) != 1 or len(peer_matches) != 1:
            raise RuntimeError(
                f"Expected one EDU and one ivshmem endpoint, got "
                f"EDU={source_matches}, ivshmem={peer_matches}"
            )
        source_bdf = source_matches[0]
        peer_bdf = peer_matches[0]
        result["sourceBdf"] = source_bdf
        result["peerBdf"] = peer_bdf
        for bdf in (source_bdf, peer_bdf):
            ssh.run(
                f"esxcli hardware pci pcipassthru set -d {bdf} -e true -a",
                check=False,
                timeout=120,
            )
        time.sleep(5)

        capability = collect_case(
            output_dir / "capability",
            case_id="p2p-edu-ivshmem",
            host=args.host,
            user="root",
            password=esxi_password,
            qemu_name="esxi8-a",
            monitor=MONITOR,
            targets=[source_bdf, peer_bdf],
            requested={"purpose": "DirectPath peer DMA policy matrix"},
        )
        result["capability"] = {
            bdf: capability["devices"][bdf]["esxcli"]
            for bdf in (source_bdf, peer_bdf)
        }

        service_instance = connect_vcenter(
            args.vcenter,
            lab.caveat_field(args.vcsa_caveat, "SSO Username"),
            lab.caveat_field(args.vcsa_caveat, "SSO Password"),
            args.timeout,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        host = wait_connected_host(content, args.host, args.timeout)
        datacenter = next(
            item
            for item in content.rootFolder.childEntity
            if isinstance(item, vim.Datacenter) and item.name == args.datacenter
        )
        cluster = next(
            item
            for item in datacenter.hostFolder.childEntity
            if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
        )
        if host.runtime.inMaintenanceMode:
            lab.wait_task(host.ExitMaintenanceMode_Task(timeout=300))
        result["vSpherePassthruInfo"] = {
            bdf: passthrough_info(host, bdf) for bdf in (source_bdf, peer_bdf)
        }

        for case_id in args.cases:
            flags = CASES[case_id]
            if args.disable_acs and args.strict_acs_check:
                expected_outcome = "admission-reject"
            elif "pciPassthru.allowP2P" in flags:
                expected_outcome = "dma-pass"
            else:
                expected_outcome = "dma-reject"
            result["cases"][case_id] = run_case(
                case_id,
                flags,
                expected_outcome,
                output_dir,
                ssh,
                content,
                datacenter,
                cluster,
                host,
                args.datastore,
                Path(args.nfs_root),
                args.iso,
                args.timeout,
                source_bdf,
                peer_bdf,
            )
            save(result_path, result)

        result["verdict"] = (
            "pass"
            if all(case["verdict"] == "pass" for case in result["cases"].values())
            else "fail"
        )
        trace_bytes = TRACE_FILE.read_bytes()
        result["outerTrace"] = {
            "size": len(trace_bytes),
            "sha256": hashlib.sha256(trace_bytes).hexdigest(),
        }
    except Exception as error:
        result["verdict"] = "blocked"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        if not args.no_restore:
            try:
                stop_outer(ssh)
                result["restoreEsxiVersion"] = start_outer(
                    RESTORE_ENV,
                    ssh,
                    args.timeout,
                    output_dir / "restore-start.log",
                ).splitlines()
                result["restoreNfsDatastore"] = ensure_nfs_datastore(
                    ssh, args.datastore
                )
                result["restoreVerdict"] = "pass"
            except Exception as error:
                result["restoreVerdict"] = "blocked"
                result["restoreFault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save(result_path, result)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
