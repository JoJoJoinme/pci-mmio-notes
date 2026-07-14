#!/usr/bin/env bash
set -euo pipefail

vcsa_address="${VCSA_ADDRESS:-192.168.91.131}"
caveat_id="${VCSA_CAVEAT_ID:-vcsa803-codex-credentials}"
tun_id="${VCSA_TUN_ID:-7}"
tun_name="tun${tun_id}"
local_tun_address="${VCSA_TUN_LOCAL:-10.255.91.1}"
remote_tun_address="${VCSA_TUN_REMOTE:-10.255.91.2}"
esxi_subnet="${ESXI_SUBNET:-172.31.91.0/24}"
esxi_bridge="${ESXI_BRIDGE:-br-esxi8}"
tunnel_port="${VCSA_TUNNEL_PORT:-2222}"
pid_file="${VCSA_TUNNEL_PID_FILE:-/run/vcsa-esxi-tunnel.pid}"
log_file="${VCSA_TUNNEL_LOG_FILE:-/tmp/vcsa-esxi-tunnel.log}"
verify_hosts="${VCSA_TUNNEL_VERIFY_HOSTS:-172.31.91.10}"

ensure_snat_rule() {
  local source=$1
  local output_interface=$2
  local translated_source=$3
  local rule_comment=$4

  if iptables -t nat -C POSTROUTING -s "$source" -o "$output_interface" \
      -j SNAT --to-source "$translated_source" >/dev/null 2>&1; then
    return
  fi
  if iptables -t nat -I POSTROUTING -s "$source" -o "$output_interface" \
      -j SNAT --to-source "$translated_source" >/dev/null 2>&1; then
    return
  fi
  if ! command -v nft >/dev/null 2>&1; then
    echo "Neither iptables SNAT nor nft is available." >&2
    exit 1
  fi
  nft list table ip nat >/dev/null 2>&1 || nft add table ip nat
  nft list chain ip nat POSTROUTING >/dev/null 2>&1 || \
    nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority srcnat; policy accept; }'
  if nft list chain ip nat POSTROUTING | grep -Fq "comment \"$rule_comment\""; then
    return
  fi
  nft add rule ip nat POSTROUTING \
    ip saddr "$source" oifname "$output_interface" \
    snat to "$translated_source" comment "$rule_comment"
}

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root; creating TUN devices requires CAP_NET_ADMIN." >&2
  exit 1
fi

password=$(caveat show "$caveat_id" | sed -n 's/^[[:space:]]*-[[:space:]]*Root Password:[[:space:]]*//p' | head -n 1)
if [[ -z "$password" ]]; then
  echo "Caveat '$caveat_id' does not contain a Root Password field." >&2
  exit 1
fi
export SSHPASS="$password"

ssh_common=(
  sshpass -e ssh
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=8
)

# A second sshd keeps the appliance's normal SSH policy untouched while allowing
# a root-owned point-to-point TUN for this isolated lab.
"${ssh_common[@]}" "root@${vcsa_address}" \
  "iptables -C INPUT -s 192.168.91.1/32 -p tcp --dport ${tunnel_port} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s 192.168.91.1/32 -p tcp --dport ${tunnel_port} -j ACCEPT; if ! test -s /run/sshd-pci-tunnel.pid || ! kill -0 \$(cat /run/sshd-pci-tunnel.pid) 2>/dev/null; then /usr/sbin/sshd -f /etc/ssh/sshd_config -o PermitTunnel=yes -o Port=${tunnel_port} -o ListenAddress=${vcsa_address} -o PidFile=/run/sshd-pci-tunnel.pid; fi"

tunnel_pid=
if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null && \
   [[ -d "/sys/class/net/$tun_name" ]]; then
  tunnel_pid=$(cat "$pid_file")
else
  if [[ -s "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    kill "$(cat "$pid_file")" 2>/dev/null || true
  fi
  rm -f "$pid_file"
fi

remote_setup="ip addr replace ${remote_tun_address} peer ${local_tun_address} dev ${tun_name}; ip link set ${tun_name} up; ip route replace ${esxi_subnet} via ${local_tun_address} dev ${tun_name}; trap 'ip route del ${esxi_subnet} dev ${tun_name} 2>/dev/null || true' EXIT; while :; do sleep 3600; done"

if [[ -z "$tunnel_pid" ]]; then
  setsid "${ssh_common[@]}" \
    -p "$tunnel_port" \
    -o ServerAliveInterval=10 \
    -o ServerAliveCountMax=3 \
    -w "${tun_id}:${tun_id}" \
    "root@${vcsa_address}" "$remote_setup" \
    </dev/null >"$log_file" 2>&1 &
  tunnel_pid=$!
  printf '%s\n' "$tunnel_pid" >"$pid_file"
fi

for _ in $(seq 1 30); do
  [[ -d "/sys/class/net/$tun_name" ]] && break
  if ! kill -0 "$tunnel_pid" 2>/dev/null; then
    cat "$log_file" >&2
    exit 1
  fi
  sleep 1
done
if [[ ! -d "/sys/class/net/$tun_name" ]]; then
  echo "Timed out waiting for $tun_name." >&2
  cat "$log_file" >&2
  exit 1
fi

ip addr replace "$local_tun_address" peer "$remote_tun_address" dev "$tun_name"
ip link set "$tun_name" up
sysctl -q -w net.ipv4.ip_forward=1
iptables -C FORWARD -i "$tun_name" -o "$esxi_bridge" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i "$tun_name" -o "$esxi_bridge" -j ACCEPT
iptables -C FORWARD -i "$esxi_bridge" -o "$tun_name" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i "$esxi_bridge" -o "$tun_name" -j ACCEPT
ensure_snat_rule \
  "${remote_tun_address}/32" "$esxi_bridge" 172.31.91.1 \
  pci-lab-vcsa-to-esxi

vcsa_route=$(ip -4 route get "$vcsa_address")
vcsa_egress=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}' <<<"$vcsa_route")
vcsa_source=$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}' <<<"$vcsa_route")
if [[ -z "$vcsa_egress" || -z "$vcsa_source" ]]; then
  echo "Unable to resolve the WSL route to VCSA $vcsa_address." >&2
  exit 1
fi
ensure_snat_rule \
  "$esxi_subnet" "$vcsa_egress" "$vcsa_source" \
  pci-lab-esxi-to-vcsa

remote_verify="ip route get ${esxi_subnet%/*}"
for verify_host in ${verify_hosts//,/ }; do
  if [[ ! "$verify_host" =~ ^[0-9A-Fa-f:.]+$ ]]; then
    echo "Invalid VCSA_TUNNEL_VERIFY_HOSTS entry: $verify_host" >&2
    exit 1
  fi
  remote_verify+="; ping -c 2 -W 2 ${verify_host}"
done
"${ssh_common[@]}" "root@${vcsa_address}" "$remote_verify"
echo "VCSA-to-ESXi tunnel verified on $tun_name for: $verify_hosts"
