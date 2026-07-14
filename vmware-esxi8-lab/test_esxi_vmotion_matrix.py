#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import ssl
import subprocess
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl


def caveat_field(caveat_id: str, label: str) -> str:
    text = subprocess.run(
        ["caveat", "show", caveat_id],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    match = re.search(
        rf"(?m)^\s*(?:-\s*)?{re.escape(label)}:\s*(\S+)\s*$",
        text,
    )
    if not match:
        raise RuntimeError(f"Caveat {caveat_id!r} does not contain {label!r}")
    return match.group(1)


def wait_task(task, timeout: int = 1200):
    deadline = time.time() + timeout
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        if time.time() >= deadline:
            raise TimeoutError(f"Timed out waiting for task {task._moId}")
        time.sleep(1)
    if task.info.state != vim.TaskInfo.State.success:
        raise task.info.error
    return task.info.result


def inventory(content, object_type):
    view = content.viewManager.CreateContainerView(content.rootFolder, [object_type], True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def fault_snapshot(error):
    result = {
        "type": type(error).__name__,
        "module": type(error).__module__,
        "message": str(error),
    }
    formatted_traceback = traceback.format_exc()
    if formatted_traceback.strip() != "NoneType: None":
        result["traceback"] = formatted_traceback
    for name in ("msg", "localizedMessage"):
        value = getattr(error, name, None)
        if value:
            result[name] = str(value)
    fault_messages = getattr(error, "faultMessage", None) or []
    if fault_messages:
        result["faultMessage"] = [
            {
                "key": getattr(item, "key", None),
                "message": getattr(item, "message", None),
            }
            for item in fault_messages
        ]
    return result


def wait_vm_config(vm, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        vm.Reload()
        config = vm.config
        if config is not None and config.hardware is not None:
            return config
        time.sleep(1)
    readiness = {}
    for name, getter in (
        ("name", lambda: vm.name),
        ("configStatus", lambda: str(vm.configStatus)),
        ("overallStatus", lambda: str(vm.overallStatus)),
        ("connectionState", lambda: str(vm.runtime.connectionState)),
        ("powerState", lambda: str(vm.runtime.powerState)),
        ("vmPathName", lambda: vm.summary.config.vmPathName),
    ):
        try:
            readiness[name] = getter()
        except Exception as error:
            readiness[name] = f"unavailable: {type(error).__name__}: {error}"
    raise TimeoutError(
        "VM configuration did not become available: "
        + json.dumps(readiness, ensure_ascii=False, sort_keys=True)
    )


def dynamic_backing_snapshot(vm, config=None):
    config = config or wait_vm_config(vm)
    result = []
    for device in config.hardware.device:
        if not isinstance(device, vim.vm.device.VirtualPCIPassthrough):
            continue
        backing = device.backing
        allowed = []
        for item in getattr(backing, "allowedDevice", None) or []:
            allowed.append(
                {
                    "vendorId": item.vendorId,
                    "deviceId": item.deviceId,
                    "subVendorId": item.subVendorId,
                    "subDeviceId": item.subDeviceId,
                }
            )
        result.append(
            {
                "key": device.key,
                "label": device.deviceInfo.label if device.deviceInfo else None,
                "backingType": type(backing).__name__,
                "allowedDevice": allowed,
                "assignedId": getattr(backing, "assignedId", None),
                "customLabel": getattr(backing, "customLabel", None),
                "staticId": getattr(backing, "id", None),
            }
        )
    return result


def vm_snapshot(vm):
    config = wait_vm_config(vm)
    host = vm.runtime.host
    return {
        "name": vm.name,
        "powerState": str(vm.runtime.powerState),
        "host": host.name if host else None,
        "connectionState": str(vm.runtime.connectionState),
        "devices": dynamic_backing_snapshot(vm, config=config),
    }


def wait_power_state(vm, state, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        vm.Reload()
        if vm.runtime.powerState == state:
            return
        time.sleep(1)
    raise TimeoutError(f"VM {vm.name} did not reach {state}")


def wait_serial_marker(path: Path, marker: str, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and marker in path.read_text(encoding="utf-8", errors="replace"):
            return
        time.sleep(2)
    raise TimeoutError(f"Serial marker {marker!r} not found in {path}")


def ensure_datacenter(content, name):
    for item in content.rootFolder.childEntity:
        if isinstance(item, vim.Datacenter) and item.name == name:
            return item
    return content.rootFolder.CreateDatacenter(name)


def ensure_cluster(datacenter, name):
    for item in datacenter.hostFolder.childEntity:
        if isinstance(item, vim.ClusterComputeResource) and item.name == name:
            return item
    return datacenter.hostFolder.CreateClusterEx(name, vim.cluster.ConfigSpecEx())


def ensure_host(content, cluster, address, password):
    for host in inventory(content, vim.HostSystem):
        if host.name == address:
            if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
                wait_task(host.ReconnectHost_Task())
            return host
    spec = vim.host.ConnectSpec(
        hostName=address,
        userName="root",
        password=password,
        force=True,
    )
    try:
        host = wait_task(cluster.AddHost_Task(spec=spec, asConnected=True))
    except vim.fault.SSLVerifyFault as error:
        spec.sslThumbprint = error.thumbprint
        host = wait_task(cluster.AddHost_Task(spec=spec, asConnected=True))
    deadline = time.time() + 600
    while time.time() < deadline:
        host.Reload()
        if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
            return host
        time.sleep(2)
    raise TimeoutError(f"Host {address} did not become connected")


def host_snapshot(host):
    host.Reload()
    vmotion_vnics = []
    for vnic in host.config.network.vnic:
        selected = getattr(vnic.spec, "selectedVnic", None)
        vmotion_vnics.append(
            {
                "device": vnic.device,
                "ip": vnic.spec.ip.ipAddress,
                "portgroup": vnic.portgroup,
                "selectedVnic": selected,
            }
        )
    passthrough = []
    for item in host.config.pciPassthruInfo or []:
        if item.id in ("0000:01:00.0", "0000:01:00.1", "0000:01:01.0"):
            passthrough.append(
                {
                    "id": item.id,
                    "passthruEnabled": item.passthruEnabled,
                    "passthruActive": item.passthruActive,
                    "directPathState": str(item.directPathState),
                }
            )
    dynamic = host.configManager.assignableHardwareManager.RetrieveDynamicPassthroughInfo()
    return {
        "name": host.name,
        "connectionState": str(host.runtime.connectionState),
        "product": host.config.product.fullName,
        "uuid": host.hardware.systemInfo.uuid,
        "vmk": vmotion_vnics,
        "passthrough": passthrough,
        "dynamicCandidates": [
            {
                "vendorId": item.vendorId,
                "deviceId": item.deviceId,
                "vendorName": item.vendorName,
                "deviceName": item.deviceName,
                "customLabel": item.customLabel,
            }
            for item in dynamic
        ],
    }


def vmx_pci_id(bdf: str) -> str:
    match = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)[.]([0-7])", bdf)
    if not match:
        raise ValueError(f"Unexpected PCI id: {bdf}")
    domain, bus, slot, function = [int(value, 16) for value in match.groups()]
    return f"{domain:05x}:{bus:03x}:{slot:02x}.{function:x}"


def static_pci_lines(host, bdf="0000:01:00.0", index=0, slot_number=None):
    host = wait_host_hardware(host, bdf)
    hardware = host.hardware
    matches = [item for item in hardware.pciDevice if item.id == bdf]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one PCI device {bdf} on {host.name}, found {len(matches)}")
    device = matches[0]
    slot_number = 32 + index if slot_number is None else slot_number
    prefix = f"pciPassthru{index}"
    return [
        f'{prefix}.id = "{vmx_pci_id(device.id)}"',
        f'{prefix}.deviceId = "0x{device.deviceId & 0xffff:04x}"',
        f'{prefix}.vendorId = "0x{device.vendorId & 0xffff:04x}"',
        f'{prefix}.systemId = "{hardware.systemInfo.uuid}"',
        f'{prefix}.present = "TRUE"',
        f'{prefix}.pciSlotNumber = "{slot_number}"',
    ]


def wait_host_hardware(host, bdf=None, timeout=240):
    """Wait until vCenter has repopulated hardware inventory after host reboot."""
    deadline = time.time() + timeout
    last_state = None
    while time.time() < deadline:
        host.Reload()
        hardware = host.hardware
        devices = hardware.pciDevice if hardware is not None else None
        last_state = {
            "connection": str(host.runtime.connectionState),
            "hardware": hardware is not None,
            "pciDeviceCount": len(devices or []),
        }
        if hardware is not None and hardware.systemInfo is not None and devices:
            if bdf is None or any(device.id == bdf for device in devices):
                return host
        time.sleep(3)
    raise TimeoutError(f"Host hardware inventory did not populate: {last_state}")


def write_vmx(
    vm_dir: Path,
    name: str,
    iso_path: str,
    extra_lines=None,
    memory_mb: int = 1024,
    firmware: str = "efi",
):
    vm_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        '.encoding = "UTF-8"',
        'config.version = "8"',
        'virtualHW.version = "20"',
        f'displayName = "{name}"',
        'guestOS = "other5xlinux-64"',
        f'firmware = "{firmware}"',
        f'memSize = "{memory_mb}"',
        'numvcpus = "1"',
        'svga.present = "FALSE"',
        'vmci0.present = "TRUE"',
        'hpet0.present = "TRUE"',
        'floppy0.present = "FALSE"',
        'chipset.motherboardLayout = "acpi"',
        'pciBridge0.present = "TRUE"',
        'pciBridge0.virtualDev = "pciRootBridge"',
        'pciBridge0.functions = "1"',
        'pciBridge1.present = "TRUE"',
        'pciBridge1.virtualDev = "pciRootBridge"',
        'pciBridge1.functions = "1"',
        'ide1:0.present = "TRUE"',
        'ide1:0.deviceType = "cdrom-image"',
        f'ide1:0.fileName = "{iso_path}"',
        'ide1:0.startConnected = "TRUE"',
        'serial0.present = "TRUE"',
        'serial0.fileType = "file"',
        'serial0.fileName = "guest-serial.log"',
        'serial0.yieldOnMsrRead = "TRUE"',
        'bios.bootOrder = "cdrom"',
        f'sched.mem.min = "{memory_mb}"',
        f'sched.mem.minSize = "{memory_mb}"',
        'sched.mem.pin = "TRUE"',
    ]
    lines.extend(extra_lines or [])
    path = vm_dir / f"{name}.vmx"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def register_vm(datacenter, cluster, host, datastore, relative_path, name):
    task = datacenter.vmFolder.RegisterVM_Task(
        path=f"[{datastore}] {relative_path}",
        name=name,
        asTemplate=False,
        pool=cluster.resourcePool,
        host=host,
    )
    return wait_task(task)


def dynamic_device(key, label, vendor_id=0x8086, device_id=0x10D3, custom_label=None):
    allowed = vim.vm.device.VirtualPCIPassthrough.AllowedDevice(
        vendorId=vendor_id,
        deviceId=device_id,
    )
    backing = vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo(
        allowedDevice=[allowed],
        customLabel=custom_label,
    )
    return vim.vm.device.VirtualPCIPassthrough(
        key=key,
        deviceInfo=vim.Description(label=label, summary=label),
        backing=backing,
    )


def add_dynamic_devices(
    vm,
    count,
    vendor_id=0x8086,
    device_id=0x10D3,
    label_prefix="Dynamic e1000e",
):
    changes = []
    for index in range(count):
        device = dynamic_device(
            -100 - index,
            f"{label_prefix} {index}",
            vendor_id=vendor_id,
            device_id=device_id,
        )
        changes.append(
            vim.vm.device.VirtualDeviceSpec(
                operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                device=device,
            )
        )
    wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(deviceChange=changes)))


def power_on(vm, host, serial_path=None, marker_timeout=240):
    if serial_path and serial_path.exists():
        serial_path.unlink()
    wait_task(vm.PowerOnVM_Task(host=host))
    wait_power_state(vm, vim.VirtualMachinePowerState.poweredOn)
    if serial_path:
        wait_serial_marker(serial_path, "VMOTION-HEARTBEAT", timeout=marker_timeout)


def power_off(vm):
    vm.Reload()
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        wait_task(vm.PowerOffVM_Task())
    wait_power_state(vm, vim.VirtualMachinePowerState.poweredOff)


def migrate(vm, cluster, host, state):
    return wait_task(
        vm.MigrateVM_Task(
            pool=cluster.resourcePool,
            host=host,
            priority=vim.VirtualMachine.MovePriority.highPriority,
            state=state,
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host-a", default="172.31.91.10")
    parser.add_argument("--host-b", default="172.31.91.11")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--esxi-caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--output", required=True)
    parser.add_argument("--resume-x02", action="store_true")
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
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host_a, args.host_b))

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = output_dir.name
    result_path = output_dir / "result.json"
    result = {
        "runId": run_id,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "environment": {},
        "cases": {},
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    sso_user = caveat_field(args.vcsa_caveat, "SSO Username")
    sso_password = caveat_field(args.vcsa_caveat, "SSO Password")
    esxi_password = caveat_field(args.esxi_caveat, "Password")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.vcenter,
        user=sso_user,
        pwd=sso_password,
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()

    if args.resume_x02:
        if not result_path.exists():
            raise RuntimeError("--resume-x02 requires an existing result.json")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        run_id = result["runId"]
        hosts = {host.name: host for host in inventory(content, vim.HostSystem)}
        host_b = hosts[args.host_b]
        vm_names = {
            vm.name: vm for vm in inventory(content, vim.VirtualMachine)
        }
        dynamic_name = f"vmotion-dynamic-{run_id}"
        blocker_name = f"vmotion-blocker-{run_id}"
        dynamic = vm_names[dynamic_name]
        blocker = vm_names[blocker_name]
        dynamic_devices = dynamic_backing_snapshot(dynamic)
        if len(dynamic_devices) != 2:
            raise RuntimeError(
                f"Expected two Dynamic DirectPath devices, found {len(dynamic_devices)}"
            )

        vm_root = Path(args.nfs_root) / "vmotion-lab" / run_id
        dynamic_serial = vm_root / dynamic_name / "guest-serial.log"
        unavailable = {
            "resumeStartedAt": datetime.now(timezone.utc).isoformat(),
            "targetBefore": vm_snapshot(dynamic),
        }
        try:
            power_off(dynamic)
            power_off(blocker)
            power_on(blocker, host_b)
            unavailable["blocker"] = vm_snapshot(blocker)
            try:
                wait_task(dynamic.PowerOnVM_Task(host=host_b))
                wait_power_state(dynamic, vim.VirtualMachinePowerState.poweredOn)
                unavailable["verdict"] = "fail-unexpected-success-with-blocker"
                unavailable["targetWithBlocker"] = vm_snapshot(dynamic)
                power_off(dynamic)
            except Exception as error:
                unavailable["faultWithBlocker"] = fault_snapshot(error)
                unavailable["targetWithBlocker"] = vm_snapshot(dynamic)

            power_off(blocker)
            if dynamic_serial.exists():
                dynamic_serial.unlink()
            wait_task(dynamic.PowerOnVM_Task(host=host_b))
            wait_power_state(dynamic, vim.VirtualMachinePowerState.poweredOn)
            unavailable["targetAfterRelease"] = vm_snapshot(dynamic)
            result["cases"]["X02-dynamic-candidate-exhaustion"] = unavailable
            save()
            wait_serial_marker(
                dynamic_serial,
                "VMOTION-HEARTBEAT",
                timeout=600,
            )
            unavailable["guestHeartbeatAfterRelease"] = True
            unavailable["verdict"] = "pass-rejected-then-recovered"
        except Exception as error:
            unavailable["verdict"] = "fail-resume"
            unavailable["fault"] = fault_snapshot(error)
        finally:
            power_off(dynamic)
            power_off(blocker)

        unavailable["resumeFinishedAt"] = datetime.now(timezone.utc).isoformat()
        result["cases"]["X02-dynamic-candidate-exhaustion"] = unavailable
        result["finishedAt"] = datetime.now(timezone.utc).isoformat()
        result["overall"] = (
            "pass"
            if all(
                str(case.get("verdict", "")).startswith("pass")
                for case in result["cases"].values()
            )
            else "fail"
        )
        save()
        print(json.dumps(unavailable, indent=2, ensure_ascii=False))
        return

    datacenter = ensure_datacenter(content, args.datacenter)
    cluster = ensure_cluster(datacenter, args.cluster)
    host_a = ensure_host(content, cluster, args.host_a, esxi_password)
    host_b = ensure_host(content, cluster, args.host_b, esxi_password)
    result["environment"] = {
        "vcenter": content.about.fullName,
        "datacenter": datacenter.name,
        "cluster": cluster.name,
        "hosts": [host_snapshot(host_a), host_snapshot(host_b)],
    }
    save()

    common_a = {item.name: item for item in host_a.datastore}
    common_b = {item.name: item for item in host_b.datastore}
    if args.datastore not in common_a or args.datastore not in common_b:
        raise RuntimeError(f"Datastore {args.datastore!r} is not visible on both hosts")

    nfs_root = Path(args.nfs_root)
    relative_root = f"vmotion-lab/{run_id}"
    vm_root = nfs_root / relative_root
    iso_path = f"/vmfs/volumes/{args.datastore}/iso/esxi-l3-vmotion-probe.iso"
    names = {
        "baseline": f"vmotion-baseline-{run_id}",
        "classic": f"vmotion-classic-{run_id}",
        "dynamic": f"vmotion-dynamic-{run_id}",
        "blocker": f"vmotion-blocker-{run_id}",
    }
    vms = {}
    for role, name in names.items():
        extra = static_pci_lines(host_a) if role == "classic" else []
        vmx_path = write_vmx(vm_root / name, name, iso_path, extra)
        vms[role] = register_vm(
            datacenter,
            cluster,
            host_a,
            args.datastore,
            f"{relative_root}/{name}/{vmx_path.name}",
            name,
        )
    add_dynamic_devices(vms["dynamic"], 1)
    add_dynamic_devices(vms["blocker"], 1)

    baseline = vms["baseline"]
    baseline_serial = vm_root / names["baseline"] / "guest-serial.log"
    baseline_case = result["cases"].setdefault("L02-baseline-live-vmotion", {})
    try:
        power_on(baseline, host_a, baseline_serial)
        baseline_case["before"] = vm_snapshot(baseline)
        migrate(
            baseline,
            cluster,
            host_b,
            vim.VirtualMachinePowerState.poweredOn,
        )
        baseline_case["after"] = vm_snapshot(baseline)
        baseline_case["verdict"] = (
            "pass" if baseline.runtime.host._moId == host_b._moId else "fail"
        )
    except Exception as error:
        baseline_case["verdict"] = "fail"
        baseline_case["fault"] = fault_snapshot(error)
    finally:
        save()
        power_off(baseline)

    classic = vms["classic"]
    classic_serial = vm_root / names["classic"] / "guest-serial.log"
    classic_case = result["cases"].setdefault("L02-classic-live-vmotion", {})
    try:
        power_on(classic, host_a, classic_serial)
        classic_case["before"] = vm_snapshot(classic)
        try:
            migrate(
                classic,
                cluster,
                host_b,
                vim.VirtualMachinePowerState.poweredOn,
            )
            classic_case["verdict"] = "fail-unexpected-success"
            classic_case["after"] = vm_snapshot(classic)
        except Exception as error:
            classic_case["verdict"] = "pass-rejected"
            classic_case["fault"] = fault_snapshot(error)
            classic_case["after"] = vm_snapshot(classic)
    except Exception as error:
        classic_case["verdict"] = "fail-setup"
        classic_case["fault"] = fault_snapshot(error)
    finally:
        save()
        power_off(classic)

    dynamic = vms["dynamic"]
    dynamic_serial = vm_root / names["dynamic"] / "guest-serial.log"
    dynamic_live = result["cases"].setdefault("L02-dynamic-live-vmotion", {})
    try:
        power_on(dynamic, host_a, dynamic_serial)
        dynamic_live["before"] = vm_snapshot(dynamic)
        try:
            migrate(
                dynamic,
                cluster,
                host_b,
                vim.VirtualMachinePowerState.poweredOn,
            )
            dynamic_live["verdict"] = "fail-unexpected-success"
            dynamic_live["after"] = vm_snapshot(dynamic)
        except Exception as error:
            dynamic_live["verdict"] = "pass-rejected"
            dynamic_live["fault"] = fault_snapshot(error)
            dynamic_live["after"] = vm_snapshot(dynamic)
    except Exception as error:
        dynamic_live["verdict"] = "fail-setup"
        dynamic_live["fault"] = fault_snapshot(error)
    finally:
        save()
        power_off(dynamic)

    dynamic_relocate = result["cases"].setdefault("X03-dynamic-powered-off-relocate", {})
    try:
        dynamic_relocate["poweredOffOnA"] = vm_snapshot(dynamic)
        migrate(
            dynamic,
            cluster,
            host_b,
            vim.VirtualMachinePowerState.poweredOff,
        )
        dynamic_relocate["relocated"] = vm_snapshot(dynamic)
        power_on(dynamic, host_b, dynamic_serial)
        dynamic_relocate["poweredOnOnB"] = vm_snapshot(dynamic)
        dynamic_relocate["verdict"] = "pass"
    except Exception as error:
        dynamic_relocate["verdict"] = "fail"
        dynamic_relocate["fault"] = fault_snapshot(error)
    finally:
        save()
        power_off(dynamic)
        dynamic_relocate["poweredOffAgain"] = vm_snapshot(dynamic)
        save()

    unavailable = result["cases"].setdefault("X02-dynamic-candidate-exhaustion", {})
    blocker = vms["blocker"]
    blocker_serial = vm_root / names["blocker"] / "guest-serial.log"
    try:
        migrate(
            blocker,
            cluster,
            host_b,
            vim.VirtualMachinePowerState.poweredOff,
        )
        power_on(blocker, host_b, blocker_serial)
        unavailable["blocker"] = vm_snapshot(blocker)
        add_dynamic_devices(dynamic, 1)
        unavailable["targetBefore"] = vm_snapshot(dynamic)
        try:
            power_on(dynamic, host_b, dynamic_serial)
            unavailable["verdict"] = "fail-unexpected-success"
            unavailable["targetWithBlocker"] = vm_snapshot(dynamic)
        except Exception as error:
            unavailable["faultWithBlocker"] = fault_snapshot(error)
            unavailable["targetWithBlocker"] = vm_snapshot(dynamic)
            power_off(blocker)
            power_on(dynamic, host_b, dynamic_serial)
            unavailable["targetAfterRelease"] = vm_snapshot(dynamic)
            unavailable["verdict"] = "pass-rejected-then-recovered"
    except Exception as error:
        unavailable["verdict"] = "fail-setup"
        unavailable["fault"] = fault_snapshot(error)
    finally:
        save()
        power_off(dynamic)
        power_off(blocker)

    result["finishedAt"] = datetime.now(timezone.utc).isoformat()
    result["overall"] = (
        "pass"
        if all(
            str(case.get("verdict", "")).startswith("pass")
            for case in result["cases"].values()
        )
        else "fail"
    )
    save()
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
