#!/usr/bin/env bash
set -euo pipefail

workdir=${WORKDIR:-/tmp/qemu-pci-testdev-largebar}
runtime_root=${RUNTIME_DIR:-/tmp/qemu-pci-testdev-largebar-runtime}
probe_iso=${PROBE_ISO:-/root/vm/esxi8-mf/nfsds/iso/esxi-l3-largebar-probe.iso}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
sizes=${SIZES:-"32 64"}
timeout=${TIMEOUT:-180}

for path in "$probe_iso" "$ovmf_code" "$ovmf_vars_template"; do
  if [[ ! -r "$path" ]]; then
    echo "missing required input: $path" >&2
    exit 2
  fi
done

mkdir -p "$workdir" "$runtime_root"
results_tsv="$workdir/results.tsv"
printf 'sizeGb\tverdict\theartbeat\ttargetVisible\tbarSizeBytes\n' >"$results_tsv"

hmp() {
  local monitor=$1
  local command=$2
  QEMU_ESXI_MONITOR="$monitor" \
    python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/qemu-esxi8-monitor-command.py \
    "$command"
}

run_case() {
  local size_gb=$1
  local case_dir="$workdir/${size_gb}g"
  local runtime_dir="$runtime_root/${size_gb}g"
  local monitor="$runtime_dir/monitor.sock"
  local pid_file="$runtime_dir/qemu.pid"
  local serial="$case_dir/serial.log"
  local vars="$case_dir/OVMF_VARS.fd"
  local heartbeat=false

  mkdir -p "$case_dir" "$runtime_dir"
  rm -f "$monitor" "$pid_file" "$serial" "$case_dir/info-pci.log"
  cp "$ovmf_vars_template" "$vars"

  qemu-system-x86_64 \
    -name "pci-testdev-${size_gb}g" \
    -machine pc-q35-jammy,accel=kvm:tcg \
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
    -drive "if=none,id=cd0,format=raw,readonly=on,file=$probe_iso" \
    -device "ide-cd,drive=cd0,bus=ide.1,bootindex=1" \
    -device "pcie-root-port,id=rp1,bus=pcie.0,chassis=1,slot=1" \
    -device "pci-testdev,id=largebar,membar=${size_gb}G,bus=rp1,addr=0x00.0,rombar=0" \
    -fw_cfg "name=opt/ovmf/X-PciMmio64Mb,string=$((size_gb * 1024))" \
    -global "q35-pcihost.pci-hole64-size=${size_gb}G"

  for ((second = 0; second < timeout; second++)); do
    if grep -q 'VMOTION-HEARTBEAT' "$serial" 2>/dev/null; then
      heartbeat=true
      break
    fi
    if [[ -s "$pid_file" ]] && ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  hmp "$monitor" 'info pci' >"$case_dir/info-pci.log" || true
  hmp "$monitor" quit >/dev/null 2>&1 || true

  python3 - "$serial" "$size_gb" "$heartbeat" >>"$results_tsv" <<'PY'
import re
import sys
from pathlib import Path

serial_path = Path(sys.argv[1])
size_gb = int(sys.argv[2])
heartbeat = sys.argv[3] == "true"
text = serial_path.read_text(encoding="utf-8", errors="replace") if serial_path.exists() else ""
target_visible = "vendor=0x1b36 device=0x0005" in text
block = text.split("vendor=0x1b36 device=0x0005", 1)[-1] if target_visible else ""
resources = re.findall(r"0x([0-9a-f]{16}) 0x([0-9a-f]{16}) 0x[0-9a-f]{16}", block)
sizes = [int(end, 16) - int(start, 16) + 1 for start, end in resources if int(end, 16) >= int(start, 16)]
bar_size = max(sizes, default=0)
expected = size_gb * 1024**3
verdict = "pass" if heartbeat and target_visible and bar_size == expected else "fail"
print(f"{size_gb}\t{verdict}\t{str(heartbeat).lower()}\t{str(target_visible).lower()}\t{bar_size}")
PY
}

for size in $sizes; do
  run_case "$size"
done

python3 - "$workdir" <<'PY'
import csv
import json
import pathlib
import subprocess
import sys

workdir = pathlib.Path(sys.argv[1])
with (workdir / "results.tsv").open(encoding="utf-8", newline="") as stream:
    cases = list(csv.DictReader(stream, delimiter="\t"))
for case in cases:
    case["sizeGb"] = int(case["sizeGb"])
    case["heartbeat"] = case["heartbeat"] == "true"
    case["targetVisible"] = case["targetVisible"] == "true"
    case["barSizeBytes"] = int(case["barSizeBytes"])
result = {
    "qemu": subprocess.check_output(["qemu-system-x86_64", "--version"], text=True).splitlines()[0],
    "firmware": "OVMF",
    "device": "pci-testdev",
    "backingStorage": False,
    "cases": cases,
    "verdict": "pass" if cases and all(case["verdict"] == "pass" for case in cases) else "fail",
}
(workdir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(0 if result["verdict"] == "pass" else 1)
PY
