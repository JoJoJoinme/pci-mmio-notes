#!/usr/bin/env bash
set -euo pipefail

vm_dir=/root/vm/esxi8-mf
pid_file="$vm_dir/qemu.pid"
log_file="$vm_dir/qemu.log"
bridge=br-esxi8
tap=tap-esxi8
dhcp_pid_file="$vm_dir/dnsmasq.pid"
dhcp_log_file="$vm_dir/dnsmasq.log"

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
case "${QEMU_ESXI_TOPOLOGY:-pcie}" in
  pcie)
    test_devices+=(
      -device "pcie-root-port,$root_port_options"
      -device "e1000e,id=test_fn0,netdev=test0,mac=52:54:00:08:00:00,bus=test_rp,addr=0x00.0,multifunction=on"
      -device "e1000e,id=test_fn1,netdev=test1,mac=52:54:00:08:00:01,bus=test_rp,addr=0x00.1"
    )
    ivshmem_bus=test_rp
    ivshmem_addr=0x01.0
    ;;
  root)
    test_devices+=(
      -device "e1000e,id=test_fn0,netdev=test0,mac=52:54:00:08:00:00,bus=pcie.0,addr=0x08.0,multifunction=on"
      -device "e1000e,id=test_fn1,netdev=test1,mac=52:54:00:08:00:01,bus=pcie.0,addr=0x08.1"
    )
    ivshmem_bus=pcie.0
    ivshmem_addr=0x09.0
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
    ;;
  *)
    echo "unsupported QEMU_ESXI_TOPOLOGY: ${QEMU_ESXI_TOPOLOGY}" >&2
    exit 2
    ;;
esac

if [[ "${QEMU_ESXI_IVSHMEM_SIZE:-0}" != "0" ]]; then
  test_devices+=(
    -object "memory-backend-file,id=ivmem,size=${QEMU_ESXI_IVSHMEM_SIZE},mem-path=/dev/shm,share=on"
    -device "ivshmem-plain,id=test_ivshmem,memdev=ivmem,bus=$ivshmem_bus,addr=$ivshmem_addr,rombar=0"
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

if [[ -f "$dhcp_pid_file" ]] && kill -0 "$(cat "$dhcp_pid_file")" 2>/dev/null; then
  kill "$(cat "$dhcp_pid_file")" || true
  sleep 1
fi

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

# QEMU e1000e/vmxnet3 traffic traverses a TAP device, so host-side software
# offloads only add another segmentation layer.  They also caused reproducible
# ESXi NFS RPC stalls in this nested topology.
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K "$tap" tx off sg off gso off gro off txvlan off || true
fi

if [[ "${QEMU_ESXI_DHCP:-0}" == "1" ]]; then
  dnsmasq \
    --conf-file=/dev/null \
    --pid-file="$dhcp_pid_file" \
    --port=0 \
    --interface="$bridge" \
    --bind-interfaces \
    --dhcp-range=172.31.91.10,172.31.91.10,255.255.255.0,1h \
    --dhcp-host=00:0c:29:ab:af:6d,172.31.91.10 \
    --dhcp-option=3,172.31.91.1 \
    --dhcp-option=6,172.31.91.1 \
    --log-dhcp \
    --log-facility="$dhcp_log_file"
fi

exec qemu-system-x86_64 \
  -name esxi8-mf \
  -machine q35,accel=kvm,kernel-irqchip=split \
  -cpu host,+vmx,-vmx-tsc-scaling \
  -smp 4 \
  -m 8192 \
  -device intel-iommu,intremap=on,caching-mode=on,device-iotlb=on \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file="$vm_dir/OVMF_VARS.fd" \
  -drive if=none,id=system,file="$vm_dir/esxi8-system.qcow2",format=qcow2,cache=writeback,discard=unmap \
  -drive if=none,id=datastore,file="$vm_dir/esxi8-datastore.qcow2",format=qcow2,cache=writeback,discard=unmap \
  -device pvscsi,id=scsi0,bus=pcie.0,addr=0x06.0 \
  -device scsi-hd,drive=system,bus=scsi0.0,channel=0,scsi-id=0,lun=0,bootindex=1 \
  -device ide-hd,drive=datastore,bus=ide.0,bootindex=2 \
  -netdev tap,id=mgmt,ifname="$tap",script=no,downscript=no \
  -device e1000e,netdev=mgmt,mac=00:0c:29:ab:af:6d,bus=pcie.0,addr=0x05.0 \
  -netdev user,id=test0,restrict=on \
  -netdev user,id=test1,restrict=on \
  "${test_devices[@]}" \
  -vga std \
  -vnc 127.0.0.1:5 \
  -monitor unix:"$vm_dir/monitor.sock",server,nowait \
  -serial file:"$vm_dir/serial.log" \
  "${trace_options[@]}" \
  -pidfile "$pid_file" \
  -daemonize \
  -D "$log_file"
