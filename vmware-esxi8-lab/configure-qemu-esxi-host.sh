#!/bin/sh
set -x

static_address="$1"
fqdn="$2"
interface_name="${3:-vmk0}"
gateway="${4:-172.31.91.1}"
netmask="${5:-255.255.255.0}"
nfs_host="${6:-172.31.91.1}"
nfs_share="${7:-/root/vm/esxi8-mf/nfsds}"
nfs_volume="${8:-qemu-shared}"
portgroup="${9:-Management Network}"
vmk_mac="${10:-}"
remove_interface="${11:-}"
vcenter_network="${12:-192.168.91.0/24}"
tunnel_network="${13:-10.255.91.0/30}"

if ! esxcli network ip interface list | grep -q "^$interface_name$"; then
  esxcli network vswitch standard portgroup add -p "$portgroup" -v vSwitch0 || true
  esxcli network ip interface add \
    -i "$interface_name" \
    -p "$portgroup" \
    -M "$vmk_mac"
fi

esxcli network ip interface tag add -i "$interface_name" -t Management || true
esxcli network ip interface tag add -i "$interface_name" -t VMotion || true
esxcli system hostname set -f "$fqdn"

for device in 0000:01:00.0 0000:01:00.1 0000:01:01.0; do
  esxcli hardware pci pcipassthru set -d "$device" -e true -a || true
done

esxcli network ip interface ipv4 set \
  -i "$interface_name" \
  -I "$static_address" \
  -N "$netmask" \
  -g "$gateway" \
  -t static
sleep 3

esxcli network ip route ipv4 add -n "$vcenter_network" -g "$gateway" || true
esxcli network ip route ipv4 add -n "$tunnel_network" -g "$gateway" || true

if [ -n "$remove_interface" ] && [ "$remove_interface" != "$interface_name" ]; then
  esxcli network ip interface remove -i "$remove_interface" || true
fi

esxcli storage nfs list | grep -q "^$nfs_volume " || \
  esxcli storage nfs add -H "$nfs_host" -s "$nfs_share" -v "$nfs_volume"

/sbin/auto-backup.sh
touch /tmp/codex-configure-host.done
