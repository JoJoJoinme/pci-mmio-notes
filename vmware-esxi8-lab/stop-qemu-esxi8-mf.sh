#!/usr/bin/env bash
set -euo pipefail

instance="${QEMU_ESXI_INSTANCE:-mf}"
vm_dir="${QEMU_ESXI_VM_DIR:-/root/vm/esxi8-$instance}"
monitor="$vm_dir/monitor.sock"
pid_file="$vm_dir/qemu.pid"
bridge="${QEMU_ESXI_BRIDGE:-br-esxi8}"
default_tap="tap-esxi8-$instance"
if [[ "$instance" == "mf" ]]; then
  default_tap=tap-esxi8
fi
tap="${QEMU_ESXI_TAP:-$default_tap}"
dhcp_pid_file="/run/qemu-esxi8-$bridge-dnsmasq.pid"

if [[ -S "$monitor" ]]; then
  python3 - <<PY || true
import socket, time
sock = "$monitor"
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(1)
    s.connect(sock)
    time.sleep(0.1)
    try:
        s.recv(4096)
    except Exception:
        pass
    s.sendall(b"system_powerdown\\n")
PY
  sleep 10
fi

if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
  kill "$(cat "$pid_file")"
  sleep 2
fi

if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
  kill -9 "$(cat "$pid_file")"
fi

if [[ "${QEMU_ESXI_STOP_DHCP:-0}" == "1" ]] &&
   [[ -f "$dhcp_pid_file" ]] && kill -0 "$(cat "$dhcp_pid_file")" 2>/dev/null; then
  kill "$(cat "$dhcp_pid_file")" || true
  rm -f "$dhcp_pid_file"
fi

if ip link show "$tap" >/dev/null 2>&1; then
  ip link set "$tap" down || true
  ip tuntap del dev "$tap" mode tap || true
fi

if [[ "${QEMU_ESXI_DELETE_BRIDGE:-0}" == "1" ]] && ip link show "$bridge" >/dev/null 2>&1; then
  ip link set "$bridge" down || true
  ip link del "$bridge" type bridge || true
fi
