#!/usr/bin/env bash
set -euo pipefail

workdir=${WORKDIR:-/tmp/qemu-vmware-default-profile}
runtime_root=${RUNTIME_DIR:-/tmp/qemu-vmware-default-profile-runtime}
probe_iso=${PROBE_ISO:-/root/vm/esxi8-mf/nfsds/iso/esxi-l3-vmotion-probe.iso}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
cases=${CASES:-i440fx_low_1g i440fx_high_2g q35_low_1g_negative}
positive_timeout=${POSITIVE_TIMEOUT:-120}
negative_settle=${NEGATIVE_SETTLE:-30}

for path in "$probe_iso" "$ovmf_code" "$ovmf_vars_template"; do
  if [[ ! -r "$path" ]]; then
    echo "missing required input: $path" >&2
    exit 2
  fi
done

mkdir -p "$workdir"
mkdir -p "$runtime_root"
results_tsv="$workdir/results.tsv"
printf 'name\tverdict\tmachine\tram\tbarSize\tfwCfgMb\thole64\theartbeat\texpectedBar\n' >"$results_tsv"

hmp() {
  local socket_path=$1
  local command=$2
  python3 - "$socket_path" "$command" <<'PY'
import re
import socket
import sys
import time

path, command = sys.argv[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(2)
    stream.connect(path)
    time.sleep(0.1)
    try:
        stream.recv(65536)
    except TimeoutError:
        pass
    stream.sendall(command.encode("ascii") + b"\n")
    time.sleep(0.4)
    chunks = []
    while True:
        try:
            chunk = stream.recv(65536)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        if b"(qemu) " in chunk:
            break
text = b"".join(chunks).decode("utf-8", errors="replace")
print(re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text), end="")
PY
}

run_case() {
  local name=$1
  local machine=$2
  local bridge=$3
  local ram=$4
  local bar_size=$5
  local fw_cfg_mb=$6
  local hole64=$7
  local expected_bar=$8
  local expect_boot=$9
  local case_dir="$workdir/$name"
  local runtime_dir="$runtime_root/$name"
  local monitor="$runtime_dir/monitor.sock"
  local serial="$case_dir/serial.log"
  local pid_file="$runtime_dir/qemu.pid"
  local hmp_log="$case_dir/hmp-info-pci.log"
  local heartbeat=false
  local verdict=fail
  local deadline

  mkdir -p "$case_dir" "$runtime_dir"
  cp "$ovmf_vars_template" "$case_dir/OVMF_VARS.fd"
  rm -f "$monitor" "$serial" "$pid_file" "$hmp_log"

  qemu-system-x86_64 \
    -name "$name" \
    -machine "$machine,accel=kvm:tcg" \
    -cpu host \
    -m "$ram" \
    -nodefaults \
    -display none \
    -serial "file:$serial" \
    -monitor "unix:$monitor,server,nowait" \
    -pidfile "$pid_file" \
    -daemonize \
    -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$case_dir/OVMF_VARS.fd" \
    -drive "if=none,id=cd0,format=raw,readonly=on,file=$probe_iso" \
    -device "ide-cd,drive=cd0,bus=ide.1,bootindex=1" \
    -object "memory-backend-memfd,id=shm,size=$bar_size,share=on" \
    -device "ivshmem-plain,id=probe,memdev=shm" \
    -fw_cfg "name=opt/ovmf/X-PciMmio64Mb,string=$fw_cfg_mb" \
    -global "$bridge.pci-hole64-size=$hole64"

  if [[ "$expect_boot" == true ]]; then
    deadline=$positive_timeout
  else
    deadline=$negative_settle
  fi
  for ((second = 0; second < deadline; second++)); do
    if grep -q 'VMOTION-HEARTBEAT' "$serial" 2>/dev/null; then
      heartbeat=true
      break
    fi
    if [[ -s "$pid_file" ]] && ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  hmp "$monitor" 'info pci' >"$hmp_log"
  if grep -Fq "$expected_bar" "$hmp_log"; then
    if [[ "$expect_boot" == "$heartbeat" ]]; then
      verdict=pass
    fi
  fi

  hmp "$monitor" quit >/dev/null 2>&1 || true
  if [[ -s "$pid_file" ]]; then
    for _ in $(seq 1 20); do
      kill -0 "$(cat "$pid_file")" 2>/dev/null || break
      sleep 0.2
    done
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$verdict" "$machine" "$ram" "$bar_size" "$fw_cfg_mb" \
    "$hole64" "$heartbeat" "$expected_bar" >>"$results_tsv"
  echo "$name: $verdict (heartbeat=$heartbeat)"
}

for case_name in $cases; do
  case "$case_name" in
    i440fx_low_1g)
      run_case "$case_name" pc-i440fx-jammy i440FX-pcihost 1G 1G 0 0 \
        'BAR2: 64 bit prefetchable memory at 0x80000000 [0xbfffffff].' true
      ;;
    i440fx_high_2g)
      run_case "$case_name" pc-i440fx-jammy i440FX-pcihost 1G 2G 2048 2G \
        'BAR2: 64 bit prefetchable memory at 0x100000000 [0x17fffffff].' true
      ;;
    q35_low_1g_negative)
      run_case "$case_name" pc-q35-jammy q35-pcihost 1G 1G 0 0 \
        'BAR2: 64 bit prefetchable memory at 0xffffffffffffffff [0x3ffffffe].' false
      ;;
    *)
      echo "unknown case: $case_name" >&2
      exit 2
      ;;
  esac
done

python3 - "$workdir" "$probe_iso" <<'PY'
import csv
import json
import pathlib
import subprocess
import sys

workdir = pathlib.Path(sys.argv[1])
with (workdir / "results.tsv").open(encoding="utf-8", newline="") as stream:
    cases = list(csv.DictReader(stream, delimiter="\t"))
for case in cases:
    case["heartbeat"] = case["heartbeat"] == "true"
result = {
    "qemu": subprocess.check_output(
        ["qemu-system-x86_64", "--version"], text=True
    ).splitlines()[0],
    "firmware": "OVMF",
    "probeIso": sys.argv[2],
    "overall": "pass" if all(case["verdict"] == "pass" for case in cases) else "fail",
    "cases": cases,
}
(workdir / "result.json").write_text(
    json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
print(json.dumps(result, indent=2, ensure_ascii=False))
raise SystemExit(0 if result["overall"] == "pass" else 1)
PY
