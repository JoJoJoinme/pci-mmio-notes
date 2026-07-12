#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from test_esxi_dynamic_bar_envelope import qemu_command_line


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def wait_process_exit(pid: int, timeout: int = 30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    raise TimeoutError(f"Outer QEMU pid {pid} did not exit")


def wait_tcp(address: str, port: int, timeout: int = 600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((address, port), timeout=2):
                return
        except OSError:
            time.sleep(5)
    raise TimeoutError(f"Timed out waiting for {address}:{port}")


def find_host(content, name: str):
    hosts = [item for item in lab.inventory(content, vim.HostSystem) if item.name == name]
    if len(hosts) != 1:
        raise RuntimeError(f"Expected one host {name!r}, found {len(hosts)}")
    return hosts[0]


def wait_host_connected(content, name: str, result: dict, timeout: int = 600):
    deadline = time.time() + timeout
    previous = None
    while time.time() < deadline:
        host = find_host(content, name)
        state = str(host.runtime.connectionState)
        if state != previous:
            result.setdefault("hostConnectionTransitions", []).append(
                {"at": utc_now(), "state": state}
            )
            previous = state
        if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
            return host
        time.sleep(5)
    raise TimeoutError(f"Host {name} did not reconnect to vCenter")


def wait_vm_powered_off(vm, timeout: int = 180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        vm.Reload()
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
            return
        time.sleep(3)
    raise TimeoutError(f"VM {vm.name} did not settle to poweredOff after host crash")


def traffic_snapshot(serial_path: Path):
    text = serial_path.read_text(encoding="utf-8", errors="replace")
    traffic = re.findall(r"DMA-TRAFFIC interface=(\S+) rx=(\d+) tx=(\d+)", text)
    return {
        "heartbeat": "VMOTION-HEARTBEAT" in text,
        "trafficObserved": bool(traffic),
        "lastTraffic": (
            {
                "interface": traffic[-1][0],
                "rxPackets": int(traffic[-1][1]),
                "txPackets": int(traffic[-1][2]),
            }
            if traffic
            else None
        ),
        "bytes": len(text.encode("utf-8")),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.11")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--qemu-name", default="esxi8-b")
    parser.add_argument(
        "--start-script",
        default="/mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-b.sh",
    )
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
    run_id = output_dir.name
    result = {
        "runId": run_id,
        "startedAt": utc_now(),
        "case": "L04-outer-QEMU-SIGKILL-while-DirectPath-guest-running",
        "verdict": "running",
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.vcenter,
        user=lab.caveat_field(args.vcsa_caveat, "SSO Username"),
        pwd=lab.caveat_field(args.vcsa_caveat, "SSO Password"),
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    datacenter = lab.ensure_datacenter(content, args.datacenter)
    clusters = [
        item
        for item in datacenter.hostFolder.childEntity
        if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
    ]
    if len(clusters) != 1:
        raise RuntimeError(f"Expected one cluster {args.cluster!r}")
    cluster = clusters[0]
    host = find_host(content, args.host)
    if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
        raise RuntimeError(f"Host {args.host} is not connected")

    relative_root = f"host-crash/{run_id}"
    vm_name = f"host-crash-probe-{run_id}"
    vm_root = Path(args.nfs_root) / relative_root / vm_name
    serial_path = vm_root / "guest-serial.log"
    existing = [vm for vm in lab.inventory(content, vim.VirtualMachine) if vm.name == vm_name]
    if existing:
        vm = existing[0]
    else:
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{args.datastore}/iso/esxi-l3-vmotion-probe.iso",
        )
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            args.datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
        )
        lab.add_dynamic_devices(vm, 1, label_prefix="Host crash dynamic e1000e")

    restarted = False
    try:
        lab.power_off(vm)
        lab.power_on(vm, host, serial_path, marker_timeout=600)
        before_serial = output_dir / "before-crash-serial.log"
        shutil.copyfile(serial_path, before_serial)
        result["beforeCrash"] = {
            "vm": lab.vm_snapshot(vm),
            "serial": before_serial.name,
            "guest": traffic_snapshot(before_serial),
            "hostDatastores": sorted(item.name for item in host.datastore),
        }
        if not result["beforeCrash"]["guest"]["trafficObserved"]:
            raise RuntimeError("DirectPath guest did not emit DMA-TRAFFIC before crash")

        outer = qemu_command_line(args.qemu_name)
        result["crash"] = {
            "at": utc_now(),
            "signal": "SIGKILL",
            "outerQemu": outer,
        }
        result["hostConnectionTransitions"] = [
            {"at": utc_now(), "state": str(host.runtime.connectionState)}
        ]
        save()
        os.kill(outer["pid"], signal.SIGKILL)
        wait_process_exit(outer["pid"])

        environment = os.environ.copy()
        environment["QEMU_ESXI_IVSHMEM_SIZE"] = "1G"
        environment["QEMU_ESXI_IVSHMEM_ALT_SIZE"] = "2G"
        subprocess.run([args.start_script], check=True, env=environment)
        restarted = True
        result["restart"] = {
            "launchedAt": utc_now(),
            "outerQemu": qemu_command_line(args.qemu_name),
        }
        save()

        wait_tcp(args.host, 443, timeout=600)
        host = wait_host_connected(content, args.host, result, timeout=600)
        wait_vm_powered_off(vm)
        result["afterHostReconnect"] = {
            "vm": lab.vm_snapshot(vm),
            "hostDatastores": sorted(item.name for item in host.datastore),
            "passthroughActive": sorted(
                item.id for item in host.config.pciPassthruInfo if item.passthruActive
            ),
        }
        save()

        lab.power_on(vm, host, serial_path, marker_timeout=600)
        after_serial = output_dir / "after-recovery-serial.log"
        shutil.copyfile(serial_path, after_serial)
        result["afterRecovery"] = {
            "vm": lab.vm_snapshot(vm),
            "serial": after_serial.name,
            "guest": traffic_snapshot(after_serial),
        }
        lab.power_off(vm)
        result["poweredOffFinal"] = lab.vm_snapshot(vm)

        required_datastore = args.datastore in result["afterHostReconnect"]["hostDatastores"]
        guest = result["afterRecovery"]["guest"]
        result["verdict"] = (
            "pass"
            if required_datastore
            and guest["heartbeat"]
            and guest["trafficObserved"]
            and result["poweredOffFinal"]["devices"][0]["assignedId"] is None
            else "fail"
        )
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
        if not restarted:
            try:
                qemu_command_line(args.qemu_name)
            except RuntimeError:
                environment = os.environ.copy()
                environment["QEMU_ESXI_IVSHMEM_SIZE"] = "1G"
                environment["QEMU_ESXI_IVSHMEM_ALT_SIZE"] = "2G"
                subprocess.run([args.start_script], check=False, env=environment)
    finally:
        result["finishedAt"] = utc_now()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
