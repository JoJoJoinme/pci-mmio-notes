#!/usr/bin/env bash
set -euo pipefail

instance="${QEMU_ESXI_INSTANCE:-mf}"
vm_dir="${QEMU_ESXI_VM_DIR:-/root/vm/esxi8-$instance}"
qemu_name="${QEMU_ESXI_NAME:-esxi8-$instance}"
pid_file="$vm_dir/qemu.pid"
log_file="$vm_dir/qemu.log"
bridge="${QEMU_ESXI_BRIDGE:-br-esxi8}"
default_tap="tap-esxi8-$instance"
if [[ "$instance" == "mf" ]]; then
  default_tap=tap-esxi8
fi
tap="${QEMU_ESXI_TAP:-$default_tap}"
mgmt_mac="${QEMU_ESXI_MGMT_MAC:-00:0c:29:ab:af:6d}"
memory_mb="${QEMU_ESXI_MEMORY_MB:-8192}"
vnc_display="${QEMU_ESXI_VNC_DISPLAY:-5}"
system_disk="${QEMU_ESXI_SYSTEM_DISK:-$vm_dir/esxi8-system.qcow2}"
datastore_disk="${QEMU_ESXI_DATASTORE_DISK:-$vm_dir/esxi8-datastore.qcow2}"
ovmf_vars="${QEMU_ESXI_OVMF_VARS:-$vm_dir/OVMF_VARS.fd}"
dhcp_pid_file="/run/qemu-esxi8-$bridge-dnsmasq.pid"
dhcp_log_file="/run/qemu-esxi8-$bridge-dnsmasq.log"
nfs_export_root="${QEMU_ESXI_NFS_EXPORT_ROOT:-/root/vm/esxi8-mf/nfsds}"

if command -v exportfs >/dev/null 2>&1 && [[ -d "$nfs_export_root" ]]; then
  systemctl start nfs-server >/dev/null 2>&1 || true
  nfs_options=rw,sync,no_subtree_check,insecure,no_root_squash
  exportfs -i -o "$nfs_options" "172.31.91.0/24:$nfs_export_root"
  exportfs -i -o "$nfs_options" "169.254.0.0/16:$nfs_export_root"
fi

machine_options="q35,accel=kvm,kernel-irqchip=split"
memory_options=(-m "$memory_mb")
if [[ -n "${QEMU_ESXI_RAM_FILE:-}" ]]; then
  mkdir -p "$(dirname "$QEMU_ESXI_RAM_FILE")"
  truncate -s "${memory_mb}M" "$QEMU_ESXI_RAM_FILE"
  machine_options+=",memory-backend=guest_ram"
  memory_options+=(
    -object "memory-backend-file,id=guest_ram,size=${memory_mb}M,mem-path=$QEMU_ESXI_RAM_FILE,share=on,discard-data=on"
  )
fi

identity_options=()
qemu_uuid="${QEMU_ESXI_UUID:-}"
if [[ -z "$qemu_uuid" && "$instance" == "mf" ]]; then
  qemu_uuid=6a4e818a-51ce-7d7f-a21f-000c29abaf6d
fi
if [[ -n "$qemu_uuid" ]]; then
  identity_options+=(-uuid "$qemu_uuid")
fi

storage_options=()
case "${QEMU_ESXI_SYSTEM_CONTROLLER:-ahci}" in
  ahci)
    storage_options+=(
      -device "ide-hd,drive=system,bus=ide.0,serial=ESXI8SYS-$instance,bootindex=1"
      -device "ide-hd,drive=datastore,bus=ide.1,serial=ESXI8DATA-$instance,bootindex=2"
    )
    ;;
  pvscsi)
    storage_options+=(
      -device "pvscsi,id=scsi0,bus=pcie.0,addr=0x06.0"
      -device "scsi-hd,drive=system,bus=scsi0.0,channel=0,scsi-id=0,lun=0,bootindex=1"
      -device "ide-hd,drive=datastore,bus=ide.0,serial=ESXI8DATA-$instance,bootindex=2"
    )
    ;;
  *)
    echo "unsupported QEMU_ESXI_SYSTEM_CONTROLLER: ${QEMU_ESXI_SYSTEM_CONTROLLER}" >&2
    exit 2
    ;;
esac

root_port_options="id=test_rp,bus=pcie.0,chassis=8,slot=8,addr=0x08.0"
if [[ "${QEMU_ESXI_DISABLE_ACS:-0}" == "1" ]]; then
  root_port_options+=",disable-acs=on"
fi
if [[ -n "${QEMU_ESXI_LINK_SPEED:-}" ]]; then
  root_port_options+=",x-speed=${QEMU_ESXI_LINK_SPEED}"
fi
if [[ -n "${QEMU_ESXI_LINK_WIDTH:-}" ]]; then
  root_port_options+=",x-width=${QEMU_ESXI_LINK_WIDTH}"
fi

test_devices=()

prepare_memory_backend_path() {
  local size=$1
  local path=$2

  if [[ ! -d "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    truncate -s "$size" "$path"
  fi
}

case "${QEMU_ESXI_TOPOLOGY:-pcie}" in
  pcie)
    test_devices+=(
      -device "pcie-root-port,$root_port_options"
      -device "e1000e,id=test_fn0,netdev=test0,mac=52:54:00:08:00:00,bus=test_rp,addr=0x00.0,multifunction=on"
      -device "e1000e,id=test_fn1,netdev=test1,mac=52:54:00:08:00:01,bus=test_rp,addr=0x00.1"
    )
    ivshmem_bus=test_rp
    ivshmem_addr=0x01.0
    if [[ "${QEMU_ESXI_IVSHMEM_ALT_SHARED_ROOT_PORT:-0}" == "1" ]]; then
      ivshmem_alt_bus=test_rp
      ivshmem_alt_addr=0x02.0
    else
      ivshmem_alt_bus=test_alt_rp
      ivshmem_alt_addr=0x00.0
    fi
    ;;
  root)
    test_devices+=(
      -device "e1000e,id=test_fn0,netdev=test0,mac=52:54:00:08:00:00,bus=pcie.0,addr=0x08.0,multifunction=on"
      -device "e1000e,id=test_fn1,netdev=test1,mac=52:54:00:08:00:01,bus=pcie.0,addr=0x08.1"
    )
    ivshmem_bus=pcie.0
    ivshmem_addr=0x09.0
    ivshmem_alt_bus=pcie.0
    ivshmem_alt_addr=0x0a.0
    ;;
  legacy)
    test_devices+=(
      -device "pcie-root-port,$root_port_options"
      -device "pcie-pci-bridge,id=test_legacy,bus=test_rp,addr=0x00.0"
      -device "e1000e,id=test_fn0,netdev=test0,mac=52:54:00:08:00:00,bus=test_legacy,addr=0x01.0,multifunction=on"
      -device "e1000e,id=test_fn1,netdev=test1,mac=52:54:00:08:00:01,bus=test_legacy,addr=0x01.1"
    )
    ivshmem_bus=test_legacy
    ivshmem_addr=0x02.0
    ivshmem_alt_bus=test_legacy
    ivshmem_alt_addr=0x03.0
    ;;
  *)
    echo "unsupported QEMU_ESXI_TOPOLOGY: ${QEMU_ESXI_TOPOLOGY}" >&2
    exit 2
    ;;
esac

if [[ "${QEMU_ESXI_IVSHMEM_SIZE:-0}" != "0" ]]; then
  ivshmem_mem_path="${QEMU_ESXI_IVSHMEM_MEM_PATH:-/dev/shm}"
  prepare_memory_backend_path "$QEMU_ESXI_IVSHMEM_SIZE" "$ivshmem_mem_path"
  test_devices+=(
    -object "memory-backend-file,id=ivmem,size=${QEMU_ESXI_IVSHMEM_SIZE},mem-path=$ivshmem_mem_path,share=on"
    -device "ivshmem-plain,id=test_ivshmem,memdev=ivmem,bus=$ivshmem_bus,addr=$ivshmem_addr,rombar=0"
  )
fi

if [[ "${QEMU_ESXI_IVSHMEM_ALT_SIZE:-0}" != "0" ]]; then
  ivshmem_alt_mem_path="${QEMU_ESXI_IVSHMEM_ALT_MEM_PATH:-/dev/shm}"
  prepare_memory_backend_path "$QEMU_ESXI_IVSHMEM_ALT_SIZE" "$ivshmem_alt_mem_path"
  if [[ "$ivshmem_alt_bus" == "test_alt_rp" ]]; then
    test_devices+=(
      -device "pcie-root-port,id=test_alt_rp,bus=pcie.0,chassis=9,slot=9,addr=0x09.0"
    )
  fi
  test_devices+=(
    -object "memory-backend-file,id=ivmem_alt,size=${QEMU_ESXI_IVSHMEM_ALT_SIZE},mem-path=$ivshmem_alt_mem_path,share=on"
    -device "ivshmem-plain,id=test_ivshmem_alt,memdev=ivmem_alt,bus=$ivshmem_alt_bus,addr=$ivshmem_alt_addr,rombar=0"
  )
fi

trace_options=()
if [[ "${QEMU_ESXI_TRACE:-0}" == "1" ]]; then
  trace_options+=(
    -trace "events=/mnt/e/Code/PCI/_artifacts/qemu-esxi8-trace-events,file=$vm_dir/qemu-trace.log"
  )
fi

mkdir -p "$vm_dir"
rm -f "$pid_file"

ip link show "$bridge" >/dev/null 2>&1 || ip link add name "$bridge" type bridge
ip addr replace 172.31.91.1/24 dev "$bridge"
ip addr add 169.254.239.1/16 dev "$bridge" 2>/dev/null || true
ip link set "$bridge" up

if ip link show "$tap" >/dev/null 2>&1; then
  ip link set "$tap" down || true
  ip tuntap del dev "$tap" mode tap || true
fi
ip tuntap add dev "$tap" mode tap
ip link set "$tap" master "$bridge"
ip link set "$tap" up

# br_netfilter presents bridged TAP-to-TAP traffic on the logical bridge.
# Docker installs a DROP policy on FORWARD, so allow this isolated lab bridge
# explicitly or ESXi management remains host-reachable while vMotion peers fail.
if command -v iptables >/dev/null 2>&1; then
  iptables -C FORWARD -i "$bridge" -o "$bridge" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -i "$bridge" -o "$bridge" -j ACCEPT
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C FORWARD -i "$bridge" -o "$bridge" -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD 1 -i "$bridge" -o "$bridge" -j ACCEPT
fi

# QEMU e1000e/vmxnet3 traffic traverses a TAP and a host-local bridge.  Disable
# each offload independently so one unsupported feature cannot leave GRO or a
# checksum path enabled.  Otherwise Linux nfsd can receive corrupt RPC record
# markers after repeated nested-host restarts.
if command -v ethtool >/dev/null 2>&1; then
  for interface in "$tap" "$bridge"; do
    for feature in tx sg tso gso gro lro txvlan rxvlan rx-gro-list rx-udp-gro-forwarding; do
      ethtool -K "$interface" "$feature" off >/dev/null 2>&1 || true
    done
  done
fi

if [[ "${QEMU_ESXI_DHCP:-0}" == "1" ]]; then
  if [[ -f "$dhcp_pid_file" ]] && kill -0 "$(cat "$dhcp_pid_file")" 2>/dev/null; then
    kill "$(cat "$dhcp_pid_file")" || true
    sleep 1
  fi
  dnsmasq \
    --conf-file=/dev/null \
    --pid-file="$dhcp_pid_file" \
    --port=0 \
    --interface="$bridge" \
    --bind-interfaces \
    --dhcp-range=172.31.91.10,172.31.91.50,255.255.255.0,1h \
    --dhcp-host=00:0c:29:ab:af:6d,172.31.91.10 \
    --dhcp-host=00:0c:29:ab:af:7d,172.31.91.11 \
    --dhcp-option=3,172.31.91.1 \
    --dhcp-option=6,172.31.91.1 \
    --log-dhcp \
    --log-facility="$dhcp_log_file"
fi

exec qemu-system-x86_64 \
  -name "$qemu_name" \
  -machine "$machine_options" \
  -cpu host,+vmx,-vmx-tsc-scaling \
  -smp 4 \
  "${memory_options[@]}" \
  "${identity_options[@]}" \
  -device intel-iommu,intremap=on,caching-mode=on,device-iotlb=on \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file="$ovmf_vars" \
  -drive if=none,id=system,file="$system_disk",format=qcow2,cache=writeback,discard=unmap \
  -drive if=none,id=datastore,file="$datastore_disk",format=qcow2,cache=writeback,discard=unmap \
  "${storage_options[@]}" \
  -netdev tap,id=mgmt,ifname="$tap",script=no,downscript=no,vnet_hdr=off \
  -device e1000e,netdev=mgmt,mac="$mgmt_mac",bus=pcie.0,addr=0x05.0 \
  -netdev user,id=test0,restrict=on \
  -netdev user,id=test1,restrict=on \
  "${test_devices[@]}" \
  -vga std \
  -vnc "127.0.0.1:$vnc_display" \
  -monitor unix:"$vm_dir/monitor.sock",server,nowait \
  -serial file:"$vm_dir/serial.log" \
  "${trace_options[@]}" \
  -pidfile "$pid_file" \
  -daemonize \
  -D "$log_file"
