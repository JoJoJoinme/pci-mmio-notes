#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field as esxi_caveat_field,
    ensure_nfs_datastore,
)
from test_esxi_dynamic_bar_envelope import qemu_command_line, qemu_hmp_info_pci


VENDOR_ID = 0x1234
DEVICE_ID = 0x11E8
EDU_DMA_SRC = 0x80
EDU_DMA_DST = 0x88
EDU_DMA_COUNT = 0x90
EDU_DMA_COMMAND = 0x98
EDU_INTERNAL_BUFFER = 0x40000


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


def trace_delta(path, offset, physical_bdf, end_offset=None):
    if not path.exists():
        return "", []
    if path.stat().st_size < offset:
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        if end_offset is None:
            text = handle.read()
        else:
            text = handle.read(max(0, end_offset - offset))

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


def qemu_bar_address(info_pci, device_id, bar_index=0):
    blocks = re.split(r"(?=  Bus\s+\d+, device)", info_pci)
    for block in blocks:
        if f'id "{device_id}"' not in block:
            continue
        match = re.search(
            rf"BAR{bar_index}: .*? at 0x([0-9a-fA-F]+)",
            block,
        )
        if match:
            return int(match.group(1), 16)
    raise RuntimeError(f"Could not find BAR{bar_index} for QEMU device {device_id!r}")


def qtest_commands(socket_path, commands):
    responses = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(socket_path)
        pending = b""
        for command in commands:
            stream.sendall(command.encode("ascii") + b"\n")
            while b"\n" not in pending:
                chunk = stream.recv(65536)
                if not chunk:
                    raise RuntimeError("QTest socket closed before replying")
                pending += chunk
            line, pending = pending.split(b"\n", 1)
            response = line.decode("ascii", errors="replace")
            responses.append({"command": command, "response": response})
            if not response.startswith("OK"):
                raise RuntimeError(f"QTest command failed: {command}: {response}")
    return responses


def qtest_response_value(response):
    match = re.fullmatch(r"OK\s+(0x[0-9a-fA-F]+)", response)
    if not match:
        raise RuntimeError(f"QTest response did not contain a value: {response!r}")
    return int(match.group(1), 16)


def qtest_pci_config_read(socket_path, bus, slot, function, offset, width):
    if width not in {2, 4}:
        raise ValueError(f"Unsupported PCI config read width: {width}")
    config_address = (
        0x80000000
        | (bus << 16)
        | (slot << 11)
        | (function << 8)
        | (offset & 0xFC)
    )
    suffix = "w" if width == 2 else "l"
    responses = qtest_commands(
        socket_path,
        [
            f"outl 0xcf8 0x{config_address:x}",
            f"in{suffix} 0x{0xCFC + (offset & 3):x}",
        ],
    )
    return qtest_response_value(responses[-1]["response"]), responses


def qtest_pci_config_write(socket_path, bus, slot, function, offset, width, value):
    if width not in {2, 4}:
        raise ValueError(f"Unsupported PCI config write width: {width}")
    config_address = (
        0x80000000
        | (bus << 16)
        | (slot << 11)
        | (function << 8)
        | (offset & 0xFC)
    )
    suffix = "w" if width == 2 else "l"
    return qtest_commands(
        socket_path,
        [
            f"outl 0xcf8 0x{config_address:x}",
            f"out{suffix} 0x{0xCFC + (offset & 3):x} 0x{value:x}",
        ],
    )


def qtest_rearm_pci_bus_master(socket_path, bdf, bar0):
    _, bus_text, slot_function = bdf.split(":")
    slot_text, function_text = slot_function.split(".")
    bus = int(bus_text, 16)
    slot = int(slot_text, 16)
    function = int(function_text, 16)
    command_before, command_read = qtest_pci_config_read(
        socket_path, bus, slot, function, 0x04, 2
    )
    bar_before, bar_read = qtest_pci_config_read(
        socket_path, bus, slot, function, 0x10, 4
    )
    writes = []
    if (bar_before & ~0xF) != bar0:
        writes.extend(
            qtest_pci_config_write(
                socket_path, bus, slot, function, 0x10, 4, bar0
            )
        )
    command_after = command_before | 0x0006
    if command_after != command_before:
        writes.extend(
            qtest_pci_config_write(
                socket_path, bus, slot, function, 0x04, 2, command_after
            )
        )
    command_verified, command_verify = qtest_pci_config_read(
        socket_path, bus, slot, function, 0x04, 2
    )
    bar_verified, bar_verify = qtest_pci_config_read(
        socket_path, bus, slot, function, 0x10, 4
    )
    return {
        "commandBefore": f"0x{command_before:04x}",
        "commandAfter": f"0x{command_verified:04x}",
        "bar0Before": f"0x{bar_before & ~0xF:x}",
        "bar0After": f"0x{bar_verified & ~0xF:x}",
        "readCommands": command_read + bar_read,
        "writeCommands": writes,
        "verifyCommands": command_verify + bar_verify,
        "memoryAndBusMasterEnabled": (command_verified & 0x0006) == 0x0006,
        "barRestored": (bar_verified & ~0xF) == bar0,
    }


def trigger_edu_dma(socket_path, bar0, iova, count=64):
    return qtest_commands(
        socket_path,
        [
            f"writeq 0x{bar0 + EDU_DMA_SRC:x} 0x{iova:x}",
            f"writeq 0x{bar0 + EDU_DMA_DST:x} 0x{EDU_INTERNAL_BUFFER:x}",
            f"writeq 0x{bar0 + EDU_DMA_COUNT:x} 0x{count:x}",
            f"writel 0x{bar0 + EDU_DMA_COMMAND:x} 0x1",
        ],
    )


def trace_text_since(path, offset):
    if not path.exists():
        return ""
    if path.stat().st_size < offset:
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        return handle.read()


def wait_for_trace(path, offset, predicate, timeout=10):
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = trace_text_since(path, offset)
        if predicate(text):
            return text
        time.sleep(0.2)
    return text


def iommu_dma_observation(text, qemu_device, sid, iova):
    sid_token = f"sid 0x{sid:x}"
    domains = []
    translations = []
    faults = []
    for line in text.splitlines():
        if (
            ("vtd_iotlb_page_hit" in line or "vtd_iotlb_page_update" in line)
            and sid_token in line
        ):
            match = re.search(
                r"iova 0x([0-9a-fA-F]+).*?domain 0x([0-9a-fA-F]+)",
                line,
            )
            if match and int(match.group(1), 16) == iova:
                domains.append(int(match.group(2), 16))
        if "vtd_dmar_translate" in line and f"dev {qemu_device}" in line:
            match = re.search(
                r"iova 0x([0-9a-fA-F]+) -> gpa 0x([0-9a-fA-F]+) "
                r"mask 0x([0-9a-fA-F]+)",
                line,
            )
            if match:
                iova_base = int(match.group(1), 16)
                gpa_base = int(match.group(2), 16)
                mask = int(match.group(3), 16)
                if iova_base <= iova <= iova_base + mask:
                    translations.append(
                        {
                            "iovaBase": iova_base,
                            "gpaBase": gpa_base,
                            "mask": mask,
                            "resolvedGpa": gpa_base + (iova - iova_base),
                            "line": line,
                        }
                    )
        if "vtd_dmar_fault" in line and sid_token in line:
            match = re.search(r"addr 0x([0-9a-fA-F]+)", line)
            if match and int(match.group(1), 16) == iova:
                faults.append(line)

    translation = translations[-1] if translations else None
    domain = domains[-1] if domains else None
    return {
        "domain": domain,
        "translation": translation,
        "faults": faults,
    }


def json_iommu_dma_observation(observation):
    translation = observation["translation"]
    return {
        "domain": (
            f"0x{observation['domain']:x}"
            if observation["domain"] is not None
            else None
        ),
        "translation": (
            {
                "iovaBase": f"0x{translation['iovaBase']:x}",
                "gpaBase": f"0x{translation['gpaBase']:x}",
                "mask": f"0x{translation['mask']:x}",
                "resolvedGpa": f"0x{translation['resolvedGpa']:x}",
                "line": translation["line"],
            }
            if translation is not None
            else None
        ),
        "faults": observation["faults"],
    }


def ensure_local_datastore(ssh, datastore):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", datastore):
        raise ValueError(f"Unsafe datastore label: {datastore!r}")
    mount_path = f"/vmfs/volumes/{datastore}"
    before = ssh.run(
        f"test -d {shlex.quote(mount_path)}",
        check=False,
        timeout=30,
    )
    actions = []
    if before.returncode != 0:
        volumes = ssh.run("esxcfg-volume -l", timeout=60).stdout
        match = re.search(
            rf"(?m)^VMFS UUID/label:\s*([^/\s]+)/{re.escape(datastore)}\s*$",
            volumes,
        )
        if not match:
            raise RuntimeError(f"Local VMFS datastore {datastore!r} was not found")
        ssh.run(f"esxcfg-volume -M {shlex.quote(match.group(1))}", timeout=120)
        actions.append("persistent-mount")
    after = ssh.run(
        f"test -d {shlex.quote(mount_path)} && df -h {shlex.quote(mount_path)}",
        timeout=60,
    )
    return {
        "mode": "esxi-local-vmfs",
        "mountPath": mount_path,
        "actions": actions,
        "df": after.stdout.splitlines(),
    }


def scp_file(ssh, source, destination, *, download=False, check=True):
    env = os.environ.copy()
    env["SSHPASS"] = ssh.password
    remote = f"{ssh.user}@{ssh.host}:"
    if download:
        argv_source = remote + str(source)
        argv_destination = str(destination)
    else:
        argv_source = str(source)
        argv_destination = remote + str(destination)
    completed = subprocess.run(
        [
            "sshpass",
            "-e",
            "scp",
            "-q",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=12",
            argv_source,
            argv_destination,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"ESXi SCP failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return completed.returncode == 0


def wait_remote_marker(ssh, path, marker, timeout):
    deadline = time.time() + timeout
    command = (
        f"test -f {shlex.quote(path)} && "
        f"grep -Fq {shlex.quote(marker)} {shlex.quote(path)}"
    )
    while time.time() < deadline:
        if ssh.run(command, check=False, timeout=30).returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError(f"Serial marker {marker!r} not found in {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--esxi-caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-edu-probe.iso")
    parser.add_argument(
        "--iso-source",
        default="/mnt/e/Code/PCI/_artifacts/esxi-l3-edu-probe.iso",
    )
    parser.add_argument("--esxi-local-storage", action="store_true")
    parser.add_argument("--bdf", default="0000:01:01.0")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--qemu-trace", default="/root/vm/esxi8-mf/qemu-trace.log")
    parser.add_argument("--qtest-socket")
    parser.add_argument("--verify-dma-teardown", action="store_true")
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
    info_pci = qemu_hmp_info_pci(args.qemu_monitor)
    result = {
        "runId": output_dir.name,
        "case": (
            "I02-D00-D01-R00-ESXi-DirectPath-QEMU-EDU"
            if args.verify_dma_teardown
            else "I02-D00-R00-ESXi-DirectPath-QEMU-EDU"
        ),
        "startedAt": utc_now(),
        "input": {
            "bdf": args.bdf,
            "candidate": {"vendorId": VENDOR_ID, "deviceId": DEVICE_ID},
            "iso": args.iso,
            "storageMode": "esxi-local-vmfs" if args.esxi_local_storage else "nfs",
            "verifyDmaTeardown": args.verify_dma_teardown,
        },
        "outerQemu": {
            "command": qemu_command_line(args.qemu_name),
            "infoPci": info_pci,
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
    ssh = None
    remote_vm_root = None
    remote_serial_path = None
    remote_vmware_log = None
    remote_vmx_path = None
    guest_trace_end_offset = None

    try:
        if args.verify_dma_teardown:
            if not args.qtest_socket:
                raise RuntimeError("--verify-dma-teardown requires --qtest-socket")
            if not Path(args.qtest_socket).is_socket():
                raise RuntimeError(f"QTest socket is not ready: {args.qtest_socket}")
            result["outerQemu"]["qtestSocket"] = args.qtest_socket

        ssh = EsxiSsh(
            args.host,
            esxi_caveat_field(args.esxi_caveat, "Password"),
        )
        if args.esxi_local_storage:
            result["datastore"] = ensure_local_datastore(ssh, args.datastore)
        else:
            result["nfsDatastore"] = ensure_nfs_datastore(
                ssh,
                volume=args.datastore,
            )
        save()

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
        if args.esxi_local_storage:
            vm_root = output_dir / "vmx-input"
            serial_path = output_dir / "guest-serial.log"
            vmware_log = output_dir / "vmware.log"
            remote_vm_root = (
                f"/vmfs/volumes/{args.datastore}/{relative_root}/{vm_name}"
            )
            remote_serial_path = f"{remote_vm_root}/guest-serial.log"
            remote_vmware_log = f"{remote_vm_root}/vmware.log"
            remote_vmx_path = f"{remote_vm_root}/{vm_name}.vmx"
        else:
            vm_root = Path(args.nfs_root) / relative_root / vm_name
            serial_path = vm_root / "guest-serial.log"
            vmware_log = vm_root / "vmware.log"
            remote_vm_root = None
            remote_serial_path = None
            remote_vmware_log = None
            remote_vmx_path = None

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
        if args.esxi_local_storage:
            iso_source = Path(args.iso_source)
            if not iso_source.is_file():
                raise FileNotFoundError(f"ISO source not found: {iso_source}")
            remote_iso_dir = f"/vmfs/volumes/{args.datastore}/iso"
            remote_iso_path = f"{remote_iso_dir}/{args.iso}"
            ssh.run(
                f"mkdir -p {shlex.quote(remote_iso_dir)} "
                f"{shlex.quote(remote_vm_root)}",
                timeout=60,
            )
            scp_file(ssh, iso_source, remote_iso_path)
            scp_file(ssh, vmx_path, remote_vmx_path)
            result["datastore"].update(
                {
                    "isoPath": remote_iso_path,
                    "vmRoot": remote_vm_root,
                }
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

        if args.esxi_local_storage:
            wait_remote_marker(
                ssh,
                remote_serial_path,
                "EDU-TEST-COMPLETE",
                timeout=args.timeout,
            )
            scp_file(ssh, remote_serial_path, serial_path, download=True)
        else:
            lab.wait_serial_marker(
                serial_path,
                "EDU-TEST-COMPLETE",
                timeout=args.timeout,
            )
        serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
        if not args.esxi_local_storage:
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

        if args.verify_dma_teardown:
            live_info_pci = qemu_hmp_info_pci(args.qemu_monitor)
            bar0 = qemu_bar_address(live_info_pci, "test_edu")
            iova = dma_iovas[-1]
            _, bus, slot_function = args.bdf.split(":")
            slot, function = slot_function.split(".")
            sid = (int(bus, 16) << 8) | (int(slot, 16) << 3) | int(function)
            qemu_device = f"{bus}:{slot}.{int(function):02d}"
            sid_token = f"sid 0x{sid:x}"

            def live_translation_seen(text):
                return iommu_dma_observation(
                    text, qemu_device, sid, iova
                )["translation"] is not None

            def matching_fault_seen(text):
                return any(
                    "vtd_dmar_fault" in line
                    and sid_token in line
                    and f"addr 0x{iova:x}" in line
                    for line in text.splitlines()
                )

            live_offset = trace_path.stat().st_size
            guest_trace_end_offset = live_offset
            live_responses = trigger_edu_dma(args.qtest_socket, bar0, iova)
            live_text = wait_for_trace(
                trace_path,
                live_offset,
                live_translation_seen,
            )
            live_lines = [
                line
                for line in live_text.splitlines()
                if ("vtd_dmar_translate" in line and f"dev {qemu_device}" in line)
                or ("vtd_iotlb_page_" in line and sid_token in line)
                or ("vtd_dmar_fault" in line and sid_token in line)
            ]
            (output_dir / "dma-live-trace.log").write_text(
                "\n".join(live_lines) + ("\n" if live_lines else ""),
                encoding="utf-8",
            )

            transition_offset = trace_path.stat().st_size
            lab.wait_power_state(
                vm,
                vim.VirtualMachinePowerState.poweredOff,
                timeout=90,
            )
            time.sleep(1)
            transition_text = trace_text_since(trace_path, transition_offset)
            transition_lines = [
                line
                for line in transition_text.splitlines()
                if "vtd_inv_desc_" in line
                or "vtd_iotlb_reset" in line
                or "vtd_as_unmap_whole" in line
                or "vtd_replay_ce_" in line
                or "qdev_reset" in line
            ]
            (output_dir / "dma-poweroff-transition-trace.log").write_text(
                "\n".join(transition_lines) + ("\n" if transition_lines else ""),
                encoding="utf-8",
            )

            post_poweroff_info_pci = qemu_hmp_info_pci(args.qemu_monitor)
            rearm = qtest_rearm_pci_bus_master(
                args.qtest_socket,
                args.bdf,
                bar0,
            )
            rearmed_info_pci = qemu_hmp_info_pci(args.qemu_monitor)
            post_offset = trace_path.stat().st_size
            post_responses = trigger_edu_dma(args.qtest_socket, bar0, iova)
            post_text = wait_for_trace(
                trace_path,
                post_offset,
                lambda text: live_translation_seen(text)
                or matching_fault_seen(text),
            )
            post_lines = [
                line
                for line in post_text.splitlines()
                if ("vtd_dmar_translate" in line and f"dev {qemu_device}" in line)
                or ("vtd_iotlb_page_" in line and sid_token in line)
                or ("vtd_dmar_fault" in line and sid_token in line)
            ]
            (output_dir / "dma-post-poweroff-trace.log").write_text(
                "\n".join(post_lines) + ("\n" if post_lines else ""),
                encoding="utf-8",
            )

            live_translated = live_translation_seen(live_text)
            live_faulted = matching_fault_seen(live_text)
            post_faulted = matching_fault_seen(post_text)
            post_translated = live_translation_seen(post_text)
            live_observation = iommu_dma_observation(
                live_text, qemu_device, sid, iova
            )
            post_observation = iommu_dma_observation(
                post_text, qemu_device, sid, iova
            )
            live_translation = live_observation["translation"]
            post_translation = post_observation["translation"]
            context_changed = (
                live_observation["domain"] is not None
                and post_observation["domain"] is not None
                and live_observation["domain"] != post_observation["domain"]
                and live_translation is not None
                and post_translation is not None
                and live_translation["resolvedGpa"]
                != post_translation["resolvedGpa"]
            )
            post_identity = (
                post_translation is not None
                and post_translation["resolvedGpa"] == iova
            )
            result["dmaTeardown"] = {
                "bar0": f"0x{bar0:x}",
                "iova": f"0x{iova:x}",
                "outerRequester": qemu_device,
                "sid": f"0x{sid:x}",
                "live": {
                    "infoPci": live_info_pci,
                    "qtest": live_responses,
                    "translationObserved": live_translated,
                    "faultObserved": live_faulted,
                    "iommu": json_iommu_dma_observation(live_observation),
                    "evidence": str(output_dir / "dma-live-trace.log"),
                },
                "powerOffTransition": {
                    "iommuInvalidationObserved": any(
                        "vtd_inv_desc_" in line or "vtd_iotlb_reset" in line
                        for line in transition_lines
                    ),
                    "evidence": str(
                        output_dir / "dma-poweroff-transition-trace.log"
                    ),
                },
                "postPowerOff": {
                    "infoPciBeforeRearm": post_poweroff_info_pci,
                    "probeRearm": rearm,
                    "infoPciAfterRearm": rearmed_info_pci,
                    "qtest": post_responses,
                    "translationObserved": post_translated,
                    "faultObserved": post_faulted,
                    "iommu": json_iommu_dma_observation(post_observation),
                    "evidence": str(output_dir / "dma-post-poweroff-trace.log"),
                },
                "contextDisposition": (
                    "guest-domain-to-host-identity-domain"
                    if context_changed and post_identity
                    else "unclassified"
                ),
            }
            if args.esxi_local_storage:
                scp_file(ssh, remote_vmware_log, vmware_log, download=True)
                scp_file(
                    ssh,
                    remote_vmx_path,
                    output_dir / "effective.vmx",
                    download=True,
                )
            else:
                copy_if_present(vmware_log, output_dir / "vmware.log")

        result["vmwareLogExcerpt"] = vmware_log_excerpt(vmware_log)
        result["mappingCreated"] = any(
            "successfully created the IOMMU mappings" in line
            for line in result["vmwareLogExcerpt"]
        )

        qemu_device, selected_trace = trace_delta(
            trace_path,
            trace_offset,
            args.bdf,
            end_offset=guest_trace_end_offset,
        )
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
        if args.verify_dma_teardown:
            checks.update(
                {
                    "liveExternalDmaTranslated": live_translated and not live_faulted,
                    "powerOffTransitionInvalidatedIommu": result["dmaTeardown"][
                        "powerOffTransition"
                    ]["iommuInvalidationObserved"],
                    "dmaContextChangedAcrossPowerOff": context_changed,
                    "postPowerOffIdentityMappingObserved": post_identity
                    and not post_faulted,
                    "postPowerOffProbeReady": rearm[
                        "memoryAndBusMasterEnabled"
                    ]
                    and rearm["barRestored"],
                }
            )
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
        if args.esxi_local_storage and ssh is not None and remote_vm_root is not None:
            for remote_path, local_path in (
                (remote_serial_path, output_dir / "guest-serial.log"),
                (remote_vmware_log, output_dir / "vmware.log"),
                (remote_vmx_path, output_dir / "effective.vmx"),
            ):
                try:
                    scp_file(
                        ssh,
                        remote_path,
                        local_path,
                        download=True,
                        check=False,
                    )
                except Exception as error:
                    result.setdefault("evidenceFetchFaults", []).append(
                        lab.fault_snapshot(error)
                    )
        result["finishedAt"] = utc_now()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
