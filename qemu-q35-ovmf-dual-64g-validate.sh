#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
run_id=$(date +%Y%m%d-%H%M%S)-$$
workdir=${WORKDIR:-/tmp/qemu-q35-ovmf-dual-64g-$run_id}
probe_iso=${PROBE_ISO:-/root/vm/esxi8-mf/nfsds/iso/esxi-l3-largebar-probe.iso}
monitor_helper=${MONITOR_HELPER:-$repo_dir/vmware-esxi8-lab/qemu-esxi8-monitor-command.py}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
machine=${MACHINE:-pc-q35-jammy}
qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
bar_size=64G
bar_size_bytes=$((64 * 1024 * 1024 * 1024))
active_pid_file=

for path in \
  "$probe_iso" "$monitor_helper" "$ovmf_code" "$ovmf_vars_template"; do
  if [[ ! -r "$path" ]]; then
    echo "missing required input: $path" >&2
    exit 2
  fi
done

mkdir -p "$workdir"
results="$workdir/results.tsv"
printf 'case\trequestedFloorBytes\tqomFloorBytes\truntimeStart\truntimeEnd\truntimeSpanBytes\ttargetCount\tassignedBarCount\tbarRanges\theartbeat\tverdict\n' >"$results"

hmp() {
  local monitor=$1
  local command=$2
  QEMU_ESXI_MONITOR="$monitor" python3 "$monitor_helper" "$command"
}

cleanup() {
  if [[ -n "$active_pid_file" && -s "$active_pid_file" ]]; then
    local pid
    pid=$(cat "$active_pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

run_case() {
  local case_name=$1
  local floor_setting=$2
  local fw_cfg_mb=$3
  local expected_floor=$4
  local expected_assigned=$5
  local require_heartbeat=$6
  local observe_seconds=$7
  local case_dir="$workdir/$case_name"
  local monitor="$case_dir/monitor.sock"
  local serial="$case_dir/serial.log"
  local pid_file="$case_dir/qemu.pid"
  local vars="$case_dir/OVMF_VARS.fd"
  local heartbeat=false
  local floor_args=()
  local fw_cfg_args=()

  mkdir -p "$case_dir"
  cp "$ovmf_vars_template" "$vars"
  if [[ "$floor_setting" != default ]]; then
    floor_args=(-global "q35-pcihost.pci-hole64-size=$floor_setting")
  fi
  if [[ "$fw_cfg_mb" != default ]]; then
    fw_cfg_args=(-fw_cfg "name=opt/ovmf/X-PciMmio64Mb,string=$fw_cfg_mb")
  fi

  "$qemu_bin" \
    -name "$case_name" \
    -machine "$machine",accel=kvm:tcg \
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
    -device "pci-testdev,id=largebar1,membar=$bar_size,bus=rp1,addr=0x00.0,rombar=0" \
    -device "pcie-root-port,id=rp2,bus=pcie.0,chassis=2,slot=2" \
    -device "pci-testdev,id=largebar2,membar=$bar_size,bus=rp2,addr=0x00.0,rombar=0" \
    "${floor_args[@]}" \
    "${fw_cfg_args[@]}"
  active_pid_file=$pid_file

  for ((second = 0; second < observe_seconds; second++)); do
    if grep -q 'VMOTION-HEARTBEAT' "$serial" 2>/dev/null; then
      heartbeat=true
      break
    fi
    if ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-size' >"$case_dir/hole-size.log"
  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-start' >"$case_dir/hole-start.log"
  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-end' >"$case_dir/hole-end.log"
  hmp "$monitor" 'info pci' >"$case_dir/info-pci.log"
  hmp "$monitor" 'info mtree -f' >"$case_dir/info-mtree.log"
  hmp "$monitor" quit >/dev/null 2>&1 || true
  active_pid_file=

  python3 - \
    "$case_name" "$expected_floor" "$expected_assigned" \
    "$require_heartbeat" "$heartbeat" "$case_dir" "$bar_size_bytes" \
    >>"$results" <<'PY'
import re
import sys
from pathlib import Path

case_name = sys.argv[1]
expected_floor = int(sys.argv[2])
expected_assigned = int(sys.argv[3])
require_heartbeat = sys.argv[4] == "true"
heartbeat = sys.argv[5] == "true"
case_dir = Path(sys.argv[6])
bar_size = int(sys.argv[7])


def read(name: str) -> str:
    path = case_dir / name
    return path.read_text(encoding="utf-8", errors="replace")


def qom_number(name: str) -> int:
    values = [
        int(token, 0)
        for token in re.findall(
            r"(?<![A-Za-z0-9_-])(?:0x[0-9a-fA-F]+|[0-9]+)(?![A-Za-z0-9_-])",
            read(name),
        )
    ]
    return values[-1] if values else -1


floor = qom_number("hole-size.log")
start = qom_number("hole-start.log")
end = qom_number("hole-end.log")
span = end - start if start >= 0 and end >= start else -1
info_pci = read("info-pci.log").lower()
target_blocks = [
    block
    for block in re.findall(r"(?ms)^  bus .*?(?=^  bus |\Z)", info_pci)
    if "1b36:0005" in block
]
bar_ranges = []
for block in target_blocks:
    match = re.search(
        r"bar2: 64 bit prefetchable memory at "
        r"(0x[0-9a-f]+) \[(0x[0-9a-f]+)\]",
        block,
    )
    if not match:
        continue
    base, limit = (int(value, 16) for value in match.groups())
    if limit >= base and limit - base + 1 == bar_size:
        bar_ranges.append((base, limit + 1))

heartbeat_ok = heartbeat if require_heartbeat else True
span_ok = (
    span == expected_floor
    if expected_assigned == 0
    else span >= expected_assigned * bar_size
)
verdict = "pass" if (
    floor == expected_floor
    and len(target_blocks) == 2
    and len(bar_ranges) == expected_assigned
    and heartbeat_ok
    and span_ok
) else "fail"
range_text = ",".join(f"{base:#x}:{limit:#x}" for base, limit in bar_ranges)
print(
    f"{case_name}\t{expected_floor}\t{floor}\t{start}\t{end}\t{span}\t"
    f"{len(target_blocks)}\t{len(bar_ranges)}\t{range_text}\t"
    f"{str(heartbeat).lower()}\t{verdict}"
)
PY
}

gib=$((1024 * 1024 * 1024))
run_case default default default $((32 * gib)) 0 false 20
run_case explicit-128g 128G 131072 $((128 * gib)) 2 true 90

cat "$results"
echo "artifacts: $workdir"

if awk -F '\t' 'NR > 1 && $11 != "pass" { failed = 1 } END { exit failed }' "$results"; then
  exit 0
fi
exit 1
