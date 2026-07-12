#!/usr/bin/env bash
set -euo pipefail

workspace=/mnt/e/Code/PCI
repo="$workspace/github-export"
run_id="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
output="${1:-$workspace/_artifacts/mmio-tests/qemu-edu-$run_id}"
iso="$workspace/_artifacts/esxi-l3-edu-probe.iso"
vars_template=/usr/share/OVMF/OVMF_VARS.fd
vars="$output/OVMF_VARS.fd"
serial="$output/serial.log"
trace="$output/qemu-trace.log"
qemu_log="$output/qemu.log"

mkdir -p "$output"
rm -f "$serial" "$trace" "$qemu_log"

PROFILE=edu bash "$repo/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh"
cp "$vars_template" "$vars"

set +e
timeout 180 qemu-system-x86_64 \
  -name qemu-edu-direct \
  -machine q35,accel=kvm,kernel-irqchip=split \
  -cpu host \
  -smp 2 \
  -m 1024 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file="$vars" \
  -drive if=none,id=cd,file="$iso",format=raw,media=cdrom,readonly=on \
  -device ide-cd,drive=cd,bus=ide.0,bootindex=1 \
  -device pcie-root-port,id=edu_rp,bus=pcie.0,chassis=8,slot=8,addr=0x08.0 \
  -device edu,id=test_edu,bus=edu_rp,addr=0x00.0,rombar=0 \
  -display none \
  -monitor none \
  -serial file:"$serial" \
  -trace "events=$repo/vmware-esxi8-lab/qemu-edu-trace-events,file=$trace" \
  -D "$qemu_log"
qemu_status=$?
set -e

python3 - "$serial" "$trace" "$qemu_log" "$output/result.json" "$qemu_status" <<'PY'
import json
import pathlib
import re
import sys

serial_path, trace_path, qemu_log_path, result_path = map(pathlib.Path, sys.argv[1:5])
qemu_status = int(sys.argv[5])

def read(path):
    return path.read_text(errors="replace") if path.exists() else ""

serial = read(serial_path)
trace = read(trace_path)
phases = re.findall(r"EDU-PHASE=(first|second)", serial)
reset_states = re.findall(r"EDU-PHASE-PASS phase=(first|second) reset_state=(\w+)", serial)
checks = {
    "qemuExitZero": qemu_status == 0,
    "twoBootPhases": phases == ["first", "second"],
    "twoProbePasses": serial.count("EDU-PROBE-PASS") == 2,
    "twoMsiPasses": serial.count("EDU-MSI-PASS") == 2,
    "twoDmaPasses": serial.count("EDU-DMA-PASS") == 2,
    "completion": "EDU-TEST-COMPLETE" in serial,
    "firstBootResetState": ("first", "reset") in reset_states,
    "secondBootStatePersisted": ("second", "persisted") in reset_states,
    "qemuResetTraceActive": "qdev_reset" in trace,
}
qdev_reset_objects = re.findall(r"qdev_reset obj=.*?\(([^)]+)\)", trace)
result = {
    "case": "QEMU-EDU-direct-MSI-DMA-reset",
    "qemuStatus": qemu_status,
    "phases": phases,
    "resetStates": [{"phase": phase, "state": state} for phase, state in reset_states],
    "qdevResetObjects": sorted(set(qdev_reset_objects)),
    "checks": checks,
    "evidence": {
        "serial": str(serial_path),
        "trace": str(trace_path),
        "qemuLog": str(qemu_log_path),
    },
    "verdict": "pass" if all(checks.values()) else "fail",
}
result_path.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
raise SystemExit(0 if result["verdict"] == "pass" else 1)
PY
