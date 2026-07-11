#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import ssl
import subprocess
import time

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


def password_from_caveat(caveat_id: str) -> str:
    text = subprocess.run(
        ["caveat", "show", caveat_id], check=True, capture_output=True, text=True
    ).stdout
    match = re.search(r"Password:\s*(\S+)", text)
    if not match:
        raise RuntimeError("Password field missing from Caveat")
    return match.group(1)


def wait_task(task):
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        time.sleep(1)
    if task.info.state != vim.TaskInfo.State.success:
        raise task.info.error
    return task.info.result


def backing_snapshot(vm):
    result = []
    for device in vm.config.hardware.device:
        if not isinstance(device, vim.vm.device.VirtualPCIPassthrough):
            continue
        backing = device.backing
        result.append(
            {
                "key": device.key,
                "label": device.deviceInfo.label if device.deviceInfo else None,
                "allowedDevice": [
                    {
                        "vendorId": item.vendorId,
                        "deviceId": item.deviceId,
                        "subVendorId": item.subVendorId,
                        "subDeviceId": item.subDeviceId,
                    }
                    for item in (backing.allowedDevice or [])
                ],
                "assignedId": backing.assignedId,
                "customLabel": backing.customLabel,
            }
        )
    return result


def dynamic_device(key, label, vendor_id, device_id):
    allowed = vim.vm.device.VirtualPCIPassthrough.AllowedDevice(
        vendorId=vendor_id, deviceId=device_id
    )
    backing = vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo(
        allowedDevice=[allowed]
    )
    return vim.vm.device.VirtualPCIPassthrough(
        key=key,
        deviceInfo=vim.Description(label=label, summary=label),
        backing=backing,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--host", default="169.254.239.77")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    args = parser.parse_args()

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = args.host
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.host,
        user="root",
        pwd=password_from_caveat(args.caveat),
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    try:
        matches = [vm for vm in view.view if vm.name == args.vm_name]
    finally:
        view.Destroy()
    if len(matches) != 1:
        raise RuntimeError(f"Expected one VM named {args.vm_name!r}, found {len(matches)}")
    vm = matches[0]

    devices = [
        dynamic_device(-100, "Dynamic e1000e 0", 0x8086, 0x10D3),
        dynamic_device(-101, "Dynamic e1000e 1", 0x8086, 0x10D3),
        dynamic_device(-102, "Dynamic ivshmem", 0x1AF4, 0x1110),
    ]
    changes = [
        vim.vm.device.VirtualDeviceSpec(
            operation=vim.vm.device.VirtualDeviceSpec.Operation.add, device=device
        )
        for device in devices
    ]
    result = {"vm": args.vm_name, "configured": False, "powerOn": None}
    try:
        wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(deviceChange=changes)))
        result["configured"] = True
        vm.Reload()
        result["poweredOffBacking"] = backing_snapshot(vm)

        wait_task(vm.PowerOnVM_Task())
        time.sleep(3)
        vm.Reload()
        result["powerOn"] = "success"
        result["poweredOnBacking"] = backing_snapshot(vm)

        deadline = time.time() + 210
        while vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOff and time.time() < deadline:
            time.sleep(3)
            vm.Reload()
        result["finalPowerState"] = str(vm.runtime.powerState)
        result["poweredOffAgainBacking"] = backing_snapshot(vm)
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = str(error)
        try:
            if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                wait_task(vm.PowerOffVM_Task())
        except Exception:
            pass
    with open(args.output, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
