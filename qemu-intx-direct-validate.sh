#!/usr/bin/env bash
set -euo pipefail

workdir=${WORKDIR:-/tmp/qemu-intx-direct}
runtime_dir=${RUNTIME_DIR:-/tmp/qemu-intx-direct-runtime}
iso=${PROBE_ISO:-/root/vm/esxi8-mf/nfsds/iso/esxi-l3-intx-probe.iso}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
timeout=${TIMEOUT:-240}
settle_seconds=${SETTLE_SECONDS:-60}

mkdir -p "$workdir" "$runtime_dir"
serial="$workdir/serial.log"
monitor="$runtime_dir/monitor.sock"
pid_file="$runtime_dir/qemu.pid"
result="$workdir/result.json"
vars="$workdir/OVMF_VARS.fd"
rm -f "$serial" "$monitor" "$pid_file" "$result"
cp "$ovmf_vars_template" "$vars"

cleanup() {
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    kill "$(cat "$pid_file")" 2>/dev/null || true
    sleep 1
  fi
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    kill -9 "$(cat "$pid_file")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

qemu-system-x86_64 \
  -name qemu-intx-direct \
  -machine q35,accel=kvm:tcg \
  -cpu host \
  -m 1024 \
  -nodefaults \
  -display none \
  -serial "file:$serial" \
  -monitor "unix:$monitor,server,nowait" \
  -pidfile "$pid_file" \
  -daemonize \
  -no-reboot \
  -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
  -drive "if=pflash,format=raw,file=$vars" \
  -drive "if=none,id=cd0,format=raw,readonly=on,file=$iso" \
  -device "ide-cd,drive=cd0,bus=ide.1,bootindex=1" \
  -device "pcie-root-port,id=rp1,bus=pcie.0,chassis=1,slot=1" \
  -netdev "user,id=net0,restrict=on" \
  -device "e1000e,id=nic0,netdev=net0,bus=rp1,addr=0x00.0"

deadline=$((SECONDS + timeout))
while (( SECONDS < deadline )); do
  if [[ -f "$serial" ]] && grep -q 'VMOTION-HEARTBEAT' "$serial"; then
    sleep "$settle_seconds"
    break
  fi
  if ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    break
  fi
  sleep 2
done

python3 - "$serial" "$result" <<'PY'
import json
import re
import sys
from pathlib import Path

serial_path, result_path = map(Path, sys.argv[1:])
text = serial_path.read_text(encoding="utf-8", errors="replace") if serial_path.exists() else ""
traffic = [
    {"rx": int(rx), "tx": int(tx)}
    for rx, tx in re.findall(r"DMA-TRAFFIC .*?rx=(\d+) tx=(\d+)", text)
]
interrupt_lines = [
    line for line in text.splitlines()
    if "IO-APIC" in line and ("eth0" in line or "e1000e" in line)
]
result = {
    "case": "QEMU-direct-e1000e-INTx-pci-nomsi",
    "cmdlineHasPciNomsi": "pci=nomsi" in text,
    "msixDisabled": "MSI-X: Enable-" in text,
    "msiDisabled": "MSI: Enable-" in text,
    "interruptLines": interrupt_lines,
    "traffic": traffic,
    "heartbeat": "VMOTION-HEARTBEAT" in text,
}
result["verdict"] = "pass" if (
    result["cmdlineHasPciNomsi"]
    and result["msixDisabled"]
    and result["msiDisabled"]
    and interrupt_lines
    and traffic
    and max(item["tx"] for item in traffic) > 0
) else "fail"
result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(0 if result["verdict"] == "pass" else 1)
PY
