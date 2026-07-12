#!/usr/bin/env bash
set -euo pipefail

vcsa_address="${VCSA_ADDRESS:-192.168.91.131}"
caveat_id="${VCSA_CAVEAT_ID:-vcsa803-codex-credentials}"
tun_id="${VCSA_TUN_ID:-7}"
tun_name="tun${tun_id}"
remote_tun_address="${VCSA_TUN_REMOTE:-10.255.91.2}"
esxi_subnet="${ESXI_SUBNET:-172.31.91.0/24}"
esxi_bridge="${ESXI_BRIDGE:-br-esxi8}"
tunnel_port="${VCSA_TUNNEL_PORT:-2222}"
pid_file="${VCSA_TUNNEL_PID_FILE:-/run/vcsa-esxi-tunnel.pid}"

if [[ -s "$pid_file" ]]; then
  tunnel_pid=$(cat "$pid_file")
  if kill -0 "$tunnel_pid" 2>/dev/null; then
    kill -- "-$tunnel_pid" 2>/dev/null || kill "$tunnel_pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
fi

iptables -D FORWARD -i "$tun_name" -o "$esxi_bridge" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$esxi_bridge" -o "$tun_name" -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s "${remote_tun_address}/32" -o "$esxi_bridge" \
  -j SNAT --to-source 172.31.91.1 2>/dev/null || true
vcsa_route=$(ip -4 route get "$vcsa_address" 2>/dev/null || true)
vcsa_egress=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}' <<<"$vcsa_route")
vcsa_source=$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}' <<<"$vcsa_route")
if [[ -n "$vcsa_egress" && -n "$vcsa_source" ]]; then
  iptables -t nat -D POSTROUTING -s "$esxi_subnet" -d "${vcsa_address}/32" \
    -o "$vcsa_egress" -j SNAT --to-source "$vcsa_source" 2>/dev/null || true
fi
ip link delete "$tun_name" 2>/dev/null || true

password=$(caveat show "$caveat_id" | sed -n 's/^[[:space:]]*-[[:space:]]*Root Password:[[:space:]]*//p' | head -n 1)
if [[ -n "$password" ]]; then
  export SSHPASS="$password"
  sshpass -e ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o ConnectTimeout=8 \
    "root@${vcsa_address}" \
    "if test -s /run/sshd-pci-tunnel.pid; then kill \$(cat /run/sshd-pci-tunnel.pid) 2>/dev/null || true; rm -f /run/sshd-pci-tunnel.pid; fi; iptables -D INPUT -s 192.168.91.1/32 -p tcp --dport ${tunnel_port} -j ACCEPT 2>/dev/null || true" || true
fi

echo "VCSA-to-ESXi tunnel stopped."
