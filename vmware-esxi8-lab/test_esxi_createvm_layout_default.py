#!/usr/bin/env python3
import argparse
import json
import os
import ssl
import sys
import time

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


def wait_task(task):
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        time.sleep(0.5)
    if task.info.state == vim.TaskInfo.State.error:
        raise task.info.error
    return task.info.result


def first_view(content, vim_type, predicate=lambda _: True):
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
    try:
        for item in view.view:
            if predicate(item):
                return item
    finally:
        view.Destroy()
    return None


def snapshot(vm):
    vm.Reload()
    extra = {
        option.key: option.value
        for option in (vm.config.extraConfig or [])
        if option.key in ("chipset.motherboardLayout", "firmware")
    }
    return {
        "powerState": str(vm.runtime.powerState),
        "firmware": vm.config.firmware,
        "hardwareVersion": vm.config.version,
        "motherboardLayout": str(vm.config.hardware.motherboardLayout),
        "vmPathName": vm.config.files.vmPathName,
        "selectedExtraConfig": extra,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument("--name", required=True)
    parser.add_argument("--firmware", choices=("bios", "efi"), default="efi")
    parser.add_argument(
        "--expected-layout",
        choices=("acpiHostBridges", "i440bxHostBridge"),
    )
    parser.add_argument("--power-on", action="store_true")
    args = parser.parse_args()

    password = os.environ.get("ESXI_PASSWORD")
    if not password:
        raise SystemExit("ESXI_PASSWORD is required")

    result = {
        "schemaVersion": 1,
        "host": args.host,
        "datastore": args.datastore,
        "request": {
            "hardwareVersion": "vmx-20",
            "firmware": args.firmware,
            "motherboardLayout": "unset",
            "expectedMotherboardLayout": args.expected_layout,
            "powerOn": args.power_on,
        },
        "stages": {},
        "cleanup": "not-started",
        "verdict": "running",
    }
    service_instance = None
    vm = None
    failure = None
    context = ssl._create_unverified_context()

    try:
        service_instance = SmartConnect(
            host=args.host,
            user=args.user,
            pwd=password,
            sslContext=context,
        )
        content = service_instance.RetrieveContent()
        datacenter = first_view(content, vim.Datacenter)
        host = first_view(content, vim.HostSystem)
        datastore = first_view(content, vim.Datastore, lambda item: item.name == args.datastore)
        if not datacenter or not host or not datastore:
            raise RuntimeError("Unable to locate datacenter, host, or requested datastore")

        config = vim.vm.ConfigSpec(
            name=args.name,
            memoryMB=128,
            numCPUs=1,
            guestId="otherGuest64",
            version="vmx-20",
            firmware=args.firmware,
            files=vim.vm.FileInfo(vmPathName=f"[{datastore.name}]"),
        )
        vm = wait_task(
            datacenter.vmFolder.CreateVM_Task(
                config=config,
                pool=host.parent.resourcePool,
                host=host,
            )
        )
        result["stages"]["afterCreate"] = snapshot(vm)

        if args.power_on:
            wait_task(vm.PowerOnVM_Task(host=host))
            time.sleep(5)
            result["stages"]["afterPowerOn"] = snapshot(vm)
            wait_task(vm.PowerOffVM_Task())
            result["stages"]["afterPowerOff"] = snapshot(vm)

        observed_layouts = {
            stage: details["motherboardLayout"]
            for stage, details in result["stages"].items()
        }
        layout_matches = args.expected_layout is None or all(
            layout == args.expected_layout for layout in observed_layouts.values()
        )
        result["assertions"] = {
            "observedMotherboardLayouts": observed_layouts,
            "expectedMotherboardLayout": args.expected_layout,
            "layoutMatches": layout_matches,
        }
        if not layout_matches:
            raise RuntimeError(
                f"Expected motherboard layout {args.expected_layout}, "
                f"observed {observed_layouts}"
            )

        result["verdict"] = "pass"
    except Exception as exc:  # pyVmomi faults are not all derived from one public base.
        failure = f"{type(exc).__name__}: {exc}"
        result["failure"] = failure
        result["verdict"] = "fail"
    finally:
        if vm is not None:
            try:
                if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                    wait_task(vm.PowerOffVM_Task())
                wait_task(vm.Destroy_Task())
                result["cleanup"] = "destroyed"
            except Exception as cleanup_exc:
                result["cleanup"] = f"failed: {type(cleanup_exc).__name__}: {cleanup_exc}"
                result["verdict"] = "fail"
        if service_instance is not None:
            Disconnect(service_instance)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
