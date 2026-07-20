#!/usr/bin/env python3
"""Capture QEMU control-plane facts that constrain the Qman DirectPath design.

This is QEMU reference evidence, not proof that a Qman controller or physical
VFIO device is production ready.  It deliberately demonstrates two threat
premises that Qman must close:

* a process with raw QMP access can add a PCI endpoint after machine creation;
* the same guest BDF can identify different endpoint types across launches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QmpClient:
    def __init__(self, path: Path, transcript: list[dict[str, Any]]) -> None:
        self.path = path
        self.transcript = transcript
        self.sequence = 0
        self.events: list[dict[str, Any]] = []
        self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.stream.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        self.reader = self.stream.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.stream.makefile("w", encoding="utf-8", newline="\n")
        greeting = self._read()
        if "QMP" not in greeting:
            raise RuntimeError(f"missing QMP greeting: {greeting!r}")
        self.execute("qmp_capabilities")

    def _read(self) -> dict[str, Any]:
        line = self.reader.readline()
        if not line:
            raise EOFError("QMP socket closed")
        message = json.loads(line)
        self.transcript.append({"direction": "receive", "message": message})
        return message

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> Any:
        self.sequence += 1
        request: dict[str, Any] = {"execute": command, "id": self.sequence}
        if arguments:
            request["arguments"] = arguments
        self.transcript.append({"direction": "send", "message": request})
        self.writer.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.writer.flush()
        while True:
            response = self._read()
            if "event" in response:
                self.events.append(response)
                continue
            if response.get("id") != self.sequence:
                continue
            if "error" in response:
                raise RuntimeError(f"QMP {command} failed: {response['error']}")
            return response.get("return")

    def close(self) -> None:
        self.reader.close()
        self.writer.close()
        self.stream.close()


def flatten_pci(buses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []

    def visit(bus: dict[str, Any]) -> None:
        bus_number = bus.get("bus", bus.get("secondary", bus.get("number")))
        for device in bus.get("devices", []):
            device_bus = device.get("bus", bus_number)
            identity = device.get("id", {})
            flattened.append(
                {
                    "bdf": f"0000:{int(device_bus):02x}:{int(device['slot']):02x}.{int(device['function'])}",
                    "qdevId": device.get("qdev_id", ""),
                    "vendor": identity.get("vendor"),
                    "device": identity.get("device"),
                    "class": device.get("class_info", {}).get("class"),
                }
            )
            bridge = device.get("pci_bridge")
            if isinstance(bridge, dict) and isinstance(bridge.get("bus"), dict):
                child = dict(bridge["bus"])
                child["devices"] = bridge.get("devices", [])
                visit(child)

    for root in buses:
        visit(root)
    return flattened


def endpoint(devices: list[dict[str, Any]], qdev_id: str) -> dict[str, Any]:
    matches = [device for device in devices if device["qdevId"] == qdev_id]
    if not matches:
        matches = [device for device in devices if device["bdf"] == "0000:01:00.0"]
    if len(matches) != 1:
        raise AssertionError(f"expected one {qdev_id!r}, found {matches!r}")
    return matches[0]


def run_qemu(
    qemu: Path,
    runtime: Path,
    name: str,
    output: Path,
    endpoint_argument: str | None,
    raw_hotplug: bool,
) -> dict[str, Any]:
    socket_path = runtime / f"{name}.qmp"
    stderr_path = output / f"{name}-qemu.log"
    transcript_path = output / f"{name}-qmp.jsonl"
    transcript: list[dict[str, Any]] = []
    command = [
        str(qemu),
        "-name",
        name,
        "-machine",
        "q35,accel=kvm:tcg",
        "-m",
        "256M",
        "-nodefaults",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-qmp",
        f"unix:{socket_path},server=on,wait=off",
        "-device",
        "pcie-root-port,id=rp1,bus=pcie.0,addr=0x02,chassis=1",
    ]
    if endpoint_argument:
        command.extend(["-device", endpoint_argument])

    with stderr_path.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            text=True,
        )
        client: QmpClient | None = None
        try:
            client = QmpClient(socket_path, transcript)
            # Let the PC firmware assign the Root Port's secondary bus before
            # freezing the machine.  Querying a never-started bridge reports
            # secondary=0 and hides its child devices from query-pci.
            time.sleep(1)
            client.execute("stop")
            before = flatten_pci(client.execute("query-pci"))
            result: dict[str, Any] = {
                "name": name,
                "command": command,
                "before": before,
            }
            if raw_hotplug:
                client.execute(
                    "device_add",
                    {
                        "driver": "e1000e",
                        "id": "raw-qmp-device",
                        "bus": "rp1",
                        "addr": "0x0",
                    },
                )
                after_add = flatten_pci(client.execute("query-pci"))
                added = endpoint(after_add, "raw-qmp-device")
                client.execute("device_del", {"id": "raw-qmp-device"})
                time.sleep(1)
                after_delete_request = flatten_pci(client.execute("query-pci"))
                result.update(
                    {
                        "afterAdd": after_add,
                        "addedEndpoint": added,
                        "addedEndpointWasAbsentBefore": not any(
                            item["bdf"] == added["bdf"] for item in before
                        ),
                        "deviceDelAccepted": True,
                        "presentAfterDeleteRequest": any(
                            item["bdf"] == added["bdf"]
                            and item["vendor"] == added["vendor"]
                            and item["device"] == added["device"]
                            for item in after_delete_request
                        ),
                        "afterDeleteRequest": after_delete_request,
                        "events": client.events,
                    }
                )
            else:
                result["endpoint"] = endpoint(before, "static-endpoint")
            try:
                client.execute("quit")
            except EOFError:
                pass
        finally:
            transcript_path.write_text(
                "".join(
                    json.dumps(item, sort_keys=True) + "\n" for item in transcript
                ),
                encoding="utf-8",
            )
            if client is not None:
                client.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)

    result["artifacts"] = {
        str(transcript_path.name): sha256(transcript_path),
        str(stderr_path.name): sha256(stderr_path),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        type=Path,
        default=Path(
            os.environ.get(
                "QMAN_QEMU_BINARY",
                "/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64",
            )
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.qemu.is_file():
        raise FileNotFoundError(args.qemu)
    args.output.mkdir(parents=True, exist_ok=True)

    qemu_version = subprocess.check_output(
        [str(args.qemu), "--version"], text=True
    ).splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="qman-qmp-") as temporary:
        runtime = Path(temporary)
        hotplug = run_qemu(
            args.qemu, runtime, "raw-qmp-hotplug", args.output, None, True
        )
        e1000e = run_qemu(
            args.qemu,
            runtime,
            "static-e1000e",
            args.output,
            "e1000e,id=static-endpoint,bus=rp1,addr=0x0",
            False,
        )
        testdev = run_qemu(
            args.qemu,
            runtime,
            "static-testdev",
            args.output,
            "pci-testdev,id=static-endpoint,membar=1M,bus=rp1,addr=0x0,rombar=0",
            False,
        )

    first = e1000e["endpoint"]
    second = testdev["endpoint"]
    same_bdf_different_identity = (
        first["bdf"] == second["bdf"]
        and (first["vendor"], first["device"])
        != (second["vendor"], second["device"])
    )
    raw_qmp_added = hotplug["addedEndpointWasAbsentBefore"]
    device_del_reply_not_cleanup = (
        hotplug["deviceDelAccepted"] and hotplug["presentAfterDeleteRequest"]
    )
    verdict = (
        "pass"
        if raw_qmp_added
        and same_bdf_different_identity
        and device_del_reply_not_cleanup
        else "fail"
    )
    summary = {
        "schemaVersion": 1,
        "id": "QMAN-QEMU-CONTROL-001",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subject": "QEMU_CONTROL_REFERENCE",
        "qemu": {
            "path": str(args.qemu),
            "version": qemu_version,
            "sha256": sha256(args.qemu),
        },
        "claims": {
            "rawQmpCanAddPciAfterMachineCreation": raw_qmp_added,
            "deviceDelResponseIsNotByItselfCleanupProof": device_del_reply_not_cleanup,
            "sameGuestBdfCanCarryDifferentEndpointIdentityAcrossLaunches": same_bdf_different_identity,
        },
        "mapping": {
            "techStories": ["TS-F3-01", "TS-F3-04", "TS-F4-05", "TS-F5-05"],
            "casePremisesOnly": ["S01", "S15", "F09"],
            "riskIds": ["R04", "R17", "R26", "R37"],
        },
        "runs": {
            "rawQmpHotplug": hotplug,
            "staticE1000e": e1000e,
            "staticPciTestdev": testdev,
        },
        "verdict": verdict,
        "limitations": [
            "Uses emulated PCI endpoints and does not prove VFIO or physical-device behavior.",
            "Demonstrates threat premises; it does not prove that the future Qman QMP proxy denies them.",
            "The device_del result demonstrates this run's asynchronous guest-eject boundary; it does not claim that every device or guest delays removal.",
        ],
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if verdict == "pass" else 1)


if __name__ == "__main__":
    main()
