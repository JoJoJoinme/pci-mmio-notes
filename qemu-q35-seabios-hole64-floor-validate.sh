#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
run_id=$(date +%Y%m%d-%H%M%S)-$$
workdir=${WORKDIR:-/tmp/qemu-q35-seabios-hole64-floor-$run_id}
probe_iso=${PROBE_ISO:-/root/vm/esxi8-mf/nfsds/iso/esxi-l3-largebar-probe.iso}
monitor_helper=${MONITOR_HELPER:-$repo_dir/vmware-esxi8-lab/qemu-esxi8-monitor-command.py}
machine=${MACHINE:-pc-q35-jammy}
bar_size=${BAR_SIZE:-64G}
bar_size_bytes=$(numfmt --from=iec "$bar_size")
timeout=${TIMEOUT:-180}
qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
active_pid_file=

for path in "$probe_iso" "$monitor_helper"; do
  if [[ ! -r "$path" ]]; then
    echo "missing required input: $path" >&2
    exit 2
  fi
done

mkdir -p "$workdir"
results="$workdir/results.tsv"
printf 'case\tdeviceCount\tbarSizeBytes\trequestedFloorBytes\tqomFloorBytes\truntimeStart\truntimeEnd\truntimeSpanBytes\ttargetCount\tassignedBarCount\tbarRanges\theartbeat\tverdict\n' >"$results"

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
  local device_count=$2
  local hole_setting=$3
  local configured_hole_bytes=$4
  local case_dir="$workdir/$case_name"
  local monitor="$case_dir/monitor.sock"
  local serial="$case_dir/serial.log"
  local debug="$case_dir/seabios-debug.log"
  local pid_file="$case_dir/qemu.pid"
  local heartbeat=false
  local hole_args=()
  local device_args=()

  mkdir -p "$case_dir"
  if [[ "$hole_setting" != default ]]; then
    hole_args=(-global "q35-pcihost.pci-hole64-size=$hole_setting")
  fi

  for ((index = 1; index <= device_count; index++)); do
    device_args+=(
      -device "pcie-root-port,id=rp$index,bus=pcie.0,chassis=$index,slot=$index"
      -device "pci-testdev,id=largebar$index,membar=$bar_size,bus=rp$index,addr=0x00.0,rombar=0"
    )
  done

  "$qemu_bin" \
    -name "$case_name" \
    -machine "$machine",accel=kvm:tcg \
    -cpu host \
    -m 1024 \
    -nodefaults \
    -display none \
    -serial "file:$serial" \
    -chardev "file,id=seabios,path=$debug" \
    -device "isa-debugcon,iobase=0x402,chardev=seabios" \
    -monitor "unix:$monitor,server,nowait" \
    -pidfile "$pid_file" \
    -daemonize \
    -no-reboot \
    -boot order=d \
    -drive "if=none,id=cd0,format=raw,readonly=on,file=$probe_iso" \
    -device "ide-cd,drive=cd0,bus=ide.1,bootindex=1" \
    "${hole_args[@]}" \
    "${device_args[@]}"
  active_pid_file=$pid_file

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

  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-size' >"$case_dir/hole-size.log" || true
  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-start' >"$case_dir/hole-start.log" || true
  hmp "$monitor" 'qom-get /machine/q35 pci-hole64-end' >"$case_dir/hole-end.log" || true
  hmp "$monitor" 'info pci' >"$case_dir/info-pci.log" || true
  hmp "$monitor" 'info mtree -f' >"$case_dir/info-mtree.log" || true
  hmp "$monitor" quit >/dev/null 2>&1 || true
  active_pid_file=

  python3 - \
    "$case_name" "$device_count" "$bar_size_bytes" \
    "$configured_hole_bytes" "$heartbeat" \
    "$case_dir" >>"$results" <<'PY'
import re
import sys
from pathlib import Path

case_name = sys.argv[1]
device_count = int(sys.argv[2])
bar_size = int(sys.argv[3])
configured_floor = int(sys.argv[4])
heartbeat = sys.argv[5] == "true"
case_dir = Path(sys.argv[6])


def read(name: str) -> str:
    path = case_dir / name
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def qom_number(name: str) -> int:
    values = []
    for token in re.findall(r"(?<![A-Za-z0-9_-])(?:0x[0-9a-fA-F]+|[0-9]+)(?![A-Za-z0-9_-])", read(name)):
        values.append(int(token, 0))
    return values[-1] if values else -1


hole_size = qom_number("hole-size.log")
hole_start = qom_number("hole-start.log")
hole_end = qom_number("hole-end.log")
span = hole_end - hole_start if hole_start >= 0 and hole_end >= hole_start else -1
info_pci = read("info-pci.log").lower()
target_count = len(re.findall(r"\b1b36:0005\b", info_pci))

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

enough_dynamic_span = span >= device_count * bar_size
verdict = "pass" if (
    heartbeat
    and hole_size == configured_floor
    and target_count == device_count
    and len(bar_ranges) == device_count
    and enough_dynamic_span
) else "fail"

range_text = ",".join(f"{start:#x}:{end:#x}" for start, end in bar_ranges)
print(
    f"{case_name}\t{device_count}\t{bar_size}\t{configured_floor}\t"
    f"{hole_size}\t{hole_start}\t{hole_end}\t{span}\t{target_count}\t"
    f"{len(bar_ranges)}\t{range_text}\t{str(heartbeat).lower()}\t{verdict}"
)
PY
}

gib=$((1024 * 1024 * 1024))
run_case default-1x64 1 default $((32 * gib))
run_case default-2x64 2 default $((32 * gib))
run_case explicit-32g-2x64 2 32G $((32 * gib))
run_case explicit-0-2x64 2 0 0

cat "$results"
echo "artifacts: $workdir"

if awk -F '\t' 'NR > 1 && $13 != "pass" { failed = 1 } END { exit failed }' "$results"; then
  exit 0
fi
exit 1
