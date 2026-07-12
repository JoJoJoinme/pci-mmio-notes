#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shutil
import ssl
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from test_esxi_dynamic_bar_envelope import qemu_command_line, qemu_hmp_info_pci


VENDOR_ID = 0x1234
DEVICE_ID = 0x11E8


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def copy_if_present(source, destination):
    if source.exists():
        shutil.copyfile(source, destination)
        return True
    return False


def vmware_log_excerpt(path):
    if not path.exists():
        return []
    pattern = re.compile(
        r"PCIPassthru|IOMMU mappings|physical MSI|reset|DevicePowerOn",
        re.IGNORECASE,
    )
    return [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if pattern.search(line)
    ][-500:]


def trace_delta(path, offset, physical_bdf):
    if not path.exists():
        return "", []
    if path.stat().st_size < offset:
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        text = handle.read()

    domain, bus, slot_function = physical_bdf.split(":")
    slot, function = slot_function.split(".")
    qemu_device = f"{bus}:{slot}.{int(function):02d}"
    selected = [
        line
        for line in text.splitlines()
        if (
            ("vtd_dmar_translate" in line and f"dev {qemu_device}" in line)
            or "vtd_ir_remap_msi" in line
            or "vtd_ir_irte_get" in line
            or "vtd_dmar_fault" in line
            or "qdev_reset" in line
        )
    ]
    return qemu_device, selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-edu-probe.iso")
    parser.add_argument("--bdf", default="0000:01:01.0")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--qemu-trace", default="/root/vm/esxi8-mf/qemu-trace.log")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--output", required=True)
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

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    trace_path = Path(args.qemu_trace)
    trace_offset = trace_path.stat().st_size if trace_path.exists() else 0
    result = {
        "runId": output_dir.name,
        "case": "I02-D00-R00-ESXi-DirectPath-QEMU-EDU",
        "startedAt": utc_now(),
        "input": {
            "bdf": args.bdf,
            "candidate": {"vendorId": VENDOR_ID, "deviceId": DEVICE_ID},
            "iso": args.iso,
        },
        "outerQemu": {
            "command": qemu_command_line(args.qemu_name),
            "infoPci": qemu_hmp_info_pci(args.qemu_monitor),
            "tracePath": str(trace_path),
            "traceStartOffset": trace_offset,
        },
        "verdict": "running",
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    save()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = None
    vm = None

    try:
        service_instance = SmartConnect(
            host=args.vcenter,
            user=lab.caveat_field(args.vcsa_caveat, "SSO Username"),
            pwd=lab.caveat_field(args.vcsa_caveat, "SSO Password"),
            sslContext=context,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        datacenter = lab.ensure_datacenter(content, args.datacenter)
        cluster = next(
            item
            for item in datacenter.hostFolder.childEntity
            if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
        )
        host = next(
            item for item in lab.inventory(content, vim.HostSystem) if item.name == args.host
        )
        if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
            raise RuntimeError(f"Host {args.host} is not connected")
        if host.runtime.inMaintenanceMode:
            raise RuntimeError(f"Host {args.host} is still in maintenance mode")

        devices = [item for item in host.hardware.pciDevice if item.id == args.bdf]
        if len(devices) != 1:
            raise RuntimeError(f"Expected one PCI device {args.bdf}, found {len(devices)}")
        device = devices[0]
        identity = (device.vendorId & 0xFFFF, device.deviceId & 0xFFFF)
        if identity != (VENDOR_ID, DEVICE_ID):
            raise RuntimeError(
                f"{args.bdf} is {identity[0]:04x}:{identity[1]:04x}, expected 1234:11e8"
            )
        passthrough = next(
            item for item in host.config.pciPassthruInfo if item.id == args.bdf
        )
        if not passthrough.passthruActive:
            raise RuntimeError(f"PCI device {args.bdf} is not active for passthrough")
        result["host"] = {
            "product": host.config.product.fullName,
            "connectionState": str(host.runtime.connectionState),
            "inMaintenanceMode": host.runtime.inMaintenanceMode,
            "device": {
                "id": device.id,
                "vendorId": identity[0],
                "deviceId": identity[1],
                "deviceName": device.deviceName,
                "passthruActive": passthrough.passthruActive,
            },
        }

        relative_root = f"edu/{output_dir.name}"
        vm_name = f"edu-{output_dir.name}"
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        vmware_log = vm_root / "vmware.log"

        existing = [
            item for item in lab.inventory(content, vim.VirtualMachine) if item.name == vm_name
        ]
        if existing:
            vm = existing[0]
            lab.power_off(vm)
            vm.UnregisterVM()
            vm = None

        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{args.datastore}/iso/{args.iso}",
            extra_lines=lab.static_pci_lines(host, args.bdf),
        )
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            args.datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
        )
        result["configured"] = lab.vm_snapshot(vm)
        result["effectiveInputVmx"] = vmx_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        if serial_path.exists():
            serial_path.unlink()

        lab.wait_task(vm.PowerOnVM_Task(host=host), timeout=args.timeout)
        lab.wait_power_state(vm, vim.VirtualMachinePowerState.poweredOn)
        result["poweredOn"] = lab.vm_snapshot(vm)
        save()

        lab.wait_serial_marker(serial_path, "EDU-TEST-COMPLETE", timeout=args.timeout)
        serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
        copy_if_present(serial_path, output_dir / "guest-serial.log")
        copy_if_present(vmware_log, output_dir / "vmware.log")
        copy_if_present(vm_root / f"{vm_name}.vmx", output_dir / "effective.vmx")

        phases = re.findall(r"EDU-PHASE=(first|second)", serial_text)
        reset_states = re.findall(
            r"EDU-PHASE-PASS phase=(first|second) reset_state=(\w+)", serial_text
        )
        dma_iovas = [
            int(value, 16)
            for value in re.findall(r"EDU-DMA-PASS .*?dma=0x([0-9a-fA-F]+)", serial_text)
        ]
        result["guest"] = {
            "phases": phases,
            "resetStates": [
                {"phase": phase, "state": state} for phase, state in reset_states
            ],
            "probePassCount": serial_text.count("EDU-PROBE-PASS"),
            "msiPassCount": serial_text.count("EDU-MSI-PASS"),
            "dmaPassCount": serial_text.count("EDU-DMA-PASS"),
            "msiEnableCount": serial_text.count("MSI: Enable+"),
            "dmaIovas": [f"0x{address:x}" for address in dma_iovas],
            "complete": "EDU-TEST-COMPLETE" in serial_text,
            "failureMarker": "EDU-TEST-FAIL" in serial_text,
        }

        result["vmwareLogExcerpt"] = vmware_log_excerpt(vmware_log)
        result["mappingCreated"] = any(
            "successfully created the IOMMU mappings" in line
            for line in result["vmwareLogExcerpt"]
        )

        qemu_device, selected_trace = trace_delta(trace_path, trace_offset, args.bdf)
        (output_dir / "outer-qemu-trace-selected.log").write_text(
            "\n".join(selected_trace) + ("\n" if selected_trace else ""),
            encoding="utf-8",
        )
        dma_lines = [line for line in selected_trace if "vtd_dmar_translate" in line]
        msi_lines = [line for line in selected_trace if "vtd_ir_remap_msi (" in line]
        fault_lines = [line for line in selected_trace if "vtd_dmar_fault" in line]
        dma_completion_msi = []
        for index, line in enumerate(selected_trace):
            if "vtd_dmar_translate" not in line:
                continue
            following = selected_trace[index + 1 : index + 4]
            if (
                len(following) == 3
                and "vtd_ir_remap_msi_req" in following[0]
                and "vtd_ir_irte_get" in following[1]
                and "vtd_ir_remap_msi (" in following[2]
            ):
                dma_completion_msi.append(
                    {"dma": line, "request": following[0], "irte": following[1], "remap": following[2]}
                )
        translated_ranges = []
        for line in dma_lines:
            match = re.search(
                r"iova 0x([0-9a-fA-F]+).*?mask 0x([0-9a-fA-F]+)", line
            )
            if match:
                base = int(match.group(1), 16)
                mask = int(match.group(2), 16)
                translated_ranges.append((base, base + mask))
        matched_dma_iovas = [
            address
            for address in dma_iovas
            if any(start <= address <= end for start, end in translated_ranges)
        ]
        result["outerQemu"]["trace"] = {
            "qemuDevice": qemu_device,
            "deviceDmaTranslationCount": len(dma_lines),
            "msiRemapCount": len(msi_lines),
            "dmaCompletionMsiCorrelationCount": len(dma_completion_msi),
            "dmaCompletionMsiEvidence": dma_completion_msi,
            "dmarFaultCount": len(fault_lines),
            "guestDmaIovasMatched": [f"0x{address:x}" for address in matched_dma_iovas],
            "deviceDmaTranslationRanges": [
                {"start": f"0x{start:x}", "end": f"0x{end:x}"}
                for start, end in sorted(set(translated_ranges))
            ],
            "selectedLineCount": len(selected_trace),
            "selectedEvidence": str(output_dir / "outer-qemu-trace-selected.log"),
        }

        known_second_reset = any(
            phase == "second" and state in {"reset", "persisted"}
            for phase, state in reset_states
        )
        checks = {
            "mappingCreated": result["mappingCreated"],
            "twoBootPhases": phases == ["first", "second"],
            "twoProbePasses": result["guest"]["probePassCount"] == 2,
            "twoMsiPasses": result["guest"]["msiPassCount"] == 2,
            "twoDmaPasses": result["guest"]["dmaPassCount"] == 2,
            "guestMsiEnabled": result["guest"]["msiEnableCount"] >= 2,
            "guestCompleted": result["guest"]["complete"],
            "noGuestFailure": not result["guest"]["failureMarker"],
            "knownSecondBootResetState": known_second_reset,
            "endpointDmaReachedOuterIommu": len(dma_lines) > 0,
            "guestDmaIovaCorrelated": bool(dma_iovas)
            and set(matched_dma_iovas) == set(dma_iovas),
            "dmaCompletionMsiReachedOuterInterruptRemapper": bool(dma_lines)
            and len(dma_completion_msi) == len(dma_lines),
            "noOuterDmarFault": not fault_lines,
        }
        result["checks"] = checks
        result["verdict"] = "pass" if all(checks.values()) else "fail"
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        if vm is not None:
            try:
                lab.power_off(vm)
                result["poweredOffFinal"] = lab.vm_snapshot(vm)
            except Exception as error:
                result["cleanupFault"] = lab.fault_snapshot(error)
            try:
                vm.UnregisterVM()
            except Exception as error:
                result["unregisterFault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
