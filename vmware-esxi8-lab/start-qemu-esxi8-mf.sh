#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
instance="${QEMU_ESXI_INSTANCE:-mf}"
vm_dir="${QEMU_ESXI_VM_DIR:-/root/vm/esxi8-$instance}"
qemu_name="${QEMU_ESXI_NAME:-esxi8-$instance}"
qemu_binary="${QEMU_ESXI_QEMU_BINARY:-qemu-system-x86_64}"
qemu_data_dir="${QEMU_ESXI_QEMU_DATA_DIR:-/usr/share/qemu}"
pid_file="$vm_dir/qemu.pid"
log_file="$vm_dir/qemu.log"
bridge="${QEMU_ESXI_BRIDGE:-br-esxi8}"
default_tap="tap-esxi8-$instance"
if [[ "$instance" == "mf" ]]; then
  default_tap="tap-esxi8"
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
  if command -v modprobe >/dev/null 2>&1; then
    modprobe sunrpc >/dev/null 2>&1 || true
    modprobe nfsd >/dev/null 2>&1 || true
    modprobe auth_rpcgss >/dev/null 2>&1 || true
  fi
  systemctl start nfs-server >/dev/null 2>&1 || true
  nfs_options=rw,sync,no_subtree_check,insecure,no_root_squash
  exportfs -i -o "$nfs_options" "172.31.91.0/24:$nfs_export_root"
  exportfs -i -o "$nfs_options" "169.254.0.0/16:$nfs_export_root"
fi

machine_options="q35,accel=kvm,kernel-irqchip=split"
if [[ "${QEMU_ESXI_DENY_AER_OSC:-0}" == "1" ]]; then
  machine_options+=",x-vmware-deny-pcie-aer=on"
fi
if [[ -n "${QEMU_ESXI_MAX_RAM_BELOW_4G:-}" ]]; then
  machine_options+=",max-ram-below-4g=${QEMU_ESXI_MAX_RAM_BELOW_4G}"
fi
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
if [[ "${QEMU_ESXI_HIDE_AER:-0}" == "1" ]]; then
  root_port_options+=",x-hide-aer=on"
fi
if [[ -n "${QEMU_ESXI_LINK_SPEED:-}" ]]; then
  root_port_options+=",x-speed=${QEMU_ESXI_LINK_SPEED}"
fi
if [[ -n "${QEMU_ESXI_LINK_WIDTH:-}" ]]; then
  root_port_options+=",x-width=${QEMU_ESXI_LINK_WIDTH}"
fi

test_devices=()
test_fn0_rom_options=""
test_fn_aer_options=""
test_fn0_model="${QEMU_ESXI_TEST_FN0_MODEL:-e1000e}"
test_fn1_model="${QEMU_ESXI_TEST_FN1_MODEL:-e1000e}"
test_fn0_mac="${QEMU_ESXI_TEST_FN0_MAC:-52:54:00:08:00:00}"
test_fn1_mac="${QEMU_ESXI_TEST_FN1_MAC:-52:54:00:08:00:01}"
test_fn0_identity_options=""
test_fn1_identity_options=""

case "$test_fn0_model" in
  e1000e)
    if [[ -n "${QEMU_ESXI_TEST_FN0_SUBSYS_VENDOR:-}" ]]; then
      test_fn0_identity_options+=",subsys_ven=${QEMU_ESXI_TEST_FN0_SUBSYS_VENDOR}"
    fi
    if [[ -n "${QEMU_ESXI_TEST_FN0_SUBSYS_DEVICE:-}" ]]; then
      test_fn0_identity_options+=",subsys=${QEMU_ESXI_TEST_FN0_SUBSYS_DEVICE}"
    fi
    ;;
  virtio-net-pci)
    test_fn0_identity_options+=",disable-legacy=on"
    ;;
  *)
    echo "unsupported QEMU_ESXI_TEST_FN0_MODEL: $test_fn0_model" >&2
    exit 2
    ;;
esac

case "$test_fn1_model" in
  e1000e)
    if [[ -n "${QEMU_ESXI_TEST_FN1_SUBSYS_VENDOR:-}" ]]; then
      test_fn1_identity_options+=",subsys_ven=${QEMU_ESXI_TEST_FN1_SUBSYS_VENDOR}"
    fi
    if [[ -n "${QEMU_ESXI_TEST_FN1_SUBSYS_DEVICE:-}" ]]; then
      test_fn1_identity_options+=",subsys=${QEMU_ESXI_TEST_FN1_SUBSYS_DEVICE}"
    fi
    ;;
  virtio-net-pci)
    test_fn1_identity_options+=",disable-legacy=on"
    ;;
  *)
    echo "unsupported QEMU_ESXI_TEST_FN1_MODEL: $test_fn1_model" >&2
    exit 2
    ;;
esac

if [[ "${QEMU_ESXI_HIDE_AER:-0}" == "1" ]]; then
  test_fn_aer_options=",x-hide-aer=on"
fi
if [[ -n "${QEMU_ESXI_TEST_ROMFILE:-}" ]]; then
  if [[ ! -r "$QEMU_ESXI_TEST_ROMFILE" ]]; then
    echo "QEMU_ESXI_TEST_ROMFILE is not readable: $QEMU_ESXI_TEST_ROMFILE" >&2
    exit 2
  fi
  test_fn0_rom_options=",romfile=$QEMU_ESXI_TEST_ROMFILE"
fi
if [[ -n "${QEMU_ESXI_TEST_ROMBAR:-}" ]]; then
  test_fn0_rom_options+=",rombar=$QEMU_ESXI_TEST_ROMBAR"
fi

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
      -device "$test_fn0_model,id=test_fn0,netdev=test0,mac=$test_fn0_mac,bus=test_rp,addr=0x00.0,multifunction=on$test_fn0_identity_options$test_fn0_rom_options$test_fn_aer_options"
      -device "$test_fn1_model,id=test_fn1,netdev=test1,mac=$test_fn1_mac,bus=test_rp,addr=0x00.1$test_fn1_identity_options$test_fn_aer_options"
    )
    if [[ "${QEMU_ESXI_PRIMARY_DEDICATED_ROOT_PORT:-0}" == "1" ]]; then
      primary_root_port_options="id=test_primary_rp,bus=pcie.0,chassis=10,slot=10,addr=0x0a.0"
      if [[ "${QEMU_ESXI_P2P_DISABLE_ACS:-0}" == "1" ]]; then
        primary_root_port_options+=",disable-acs=on"
      fi
      test_devices+=(
        -device "pcie-root-port,$primary_root_port_options"
      )
      ivshmem_bus=test_primary_rp
      ivshmem_addr=0x00.0
      largebar_bus=test_primary_rp
      largebar_addr=0x00.0
      edu_bus=test_primary_rp
      edu_addr=0x00.0
      virtio_net_bus=test_primary_rp
      virtio_net_addr=0x00.0
    else
      ivshmem_bus=test_rp
      ivshmem_addr=0x01.0
      largebar_bus=test_rp
      largebar_addr=0x01.0
      edu_bus=test_rp
      edu_addr=0x01.0
      virtio_net_bus=test_rp
      virtio_net_addr=0x01.0
    fi
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
      -device "$test_fn0_model,id=test_fn0,netdev=test0,mac=$test_fn0_mac,bus=pcie.0,addr=0x08.0,multifunction=on$test_fn0_identity_options$test_fn0_rom_options$test_fn_aer_options"
      -device "$test_fn1_model,id=test_fn1,netdev=test1,mac=$test_fn1_mac,bus=pcie.0,addr=0x08.1$test_fn1_identity_options$test_fn_aer_options"
    )
    ivshmem_bus=pcie.0
    ivshmem_addr=0x09.0
    largebar_bus=pcie.0
    largebar_addr=0x09.0
    edu_bus=pcie.0
    edu_addr=0x09.0
    virtio_net_bus=pcie.0
    virtio_net_addr=0x09.0
    ivshmem_alt_bus=pcie.0
    ivshmem_alt_addr=0x0a.0
    ;;
  legacy)
    test_devices+=(
      -device "pcie-root-port,$root_port_options"
      -device "pcie-pci-bridge,id=test_legacy,bus=test_rp,addr=0x00.0"
      -device "$test_fn0_model,id=test_fn0,netdev=test0,mac=$test_fn0_mac,bus=test_legacy,addr=0x01.0,multifunction=on$test_fn0_identity_options$test_fn0_rom_options$test_fn_aer_options"
      -device "$test_fn1_model,id=test_fn1,netdev=test1,mac=$test_fn1_mac,bus=test_legacy,addr=0x01.1$test_fn1_identity_options$test_fn_aer_options"
    )
    ivshmem_bus=test_legacy
    ivshmem_addr=0x02.0
    largebar_bus=test_legacy
    largebar_addr=0x02.0
    edu_bus=test_legacy
    edu_addr=0x02.0
    virtio_net_bus=test_legacy
    virtio_net_addr=0x02.0
    ivshmem_alt_bus=test_legacy
    ivshmem_alt_addr=0x03.0
    ;;
  *)
    echo "unsupported QEMU_ESXI_TOPOLOGY: ${QEMU_ESXI_TOPOLOGY}" >&2
    exit 2
    ;;
esac

x3130_upstream_present="${QEMU_ESXI_X3130_UPSTREAM:-0}"
if [[ "$x3130_upstream_present" == "1" ]]; then
  if [[ "${QEMU_ESXI_TOPOLOGY:-pcie}" != "pcie" ]]; then
    echo "QEMU_ESXI_X3130_UPSTREAM requires QEMU_ESXI_TOPOLOGY=pcie" >&2
    exit 2
  fi
  if [[ "${QEMU_ESXI_IVSHMEM_ALT_SHARED_ROOT_PORT:-0}" == "1" ]]; then
    echo "QEMU_ESXI_X3130_UPSTREAM conflicts with the shared alt slot" >&2
    exit 2
  fi
  test_devices+=(
    -device "x3130-upstream,id=test_switch_up,bus=test_rp,addr=0x02.0"
  )
elif [[ "$x3130_upstream_present" != "0" ]]; then
  echo "QEMU_ESXI_X3130_UPSTREAM must be 0 or 1" >&2
  exit 2
fi

largebar_size="${QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE:-0}"
edu_present="${QEMU_ESXI_EDU:-0}"
virtio_net_present="${QEMU_ESXI_VIRTIO_NET:-0}"
eepro100_present="${QEMU_ESXI_EEPRO100:-0}"
nvme_sriov_present="${QEMU_ESXI_NVME_SRIOV:-0}"
nvme_sriov_vf_config_ids="${QEMU_ESXI_NVME_SRIOV_VF_CONFIG_IDS:-0}"
igb_sriov_present="${QEMU_ESXI_IGB_SRIOV:-0}"
if [[ "$edu_present" != "0" && "$edu_present" != "1" ]]; then
  echo "QEMU_ESXI_EDU must be 0 or 1" >&2
  exit 2
fi
if [[ "$virtio_net_present" != "0" && "$virtio_net_present" != "1" ]]; then
  echo "QEMU_ESXI_VIRTIO_NET must be 0 or 1" >&2
  exit 2
fi
if [[ "$eepro100_present" != "0" && "$eepro100_present" != "1" ]]; then
  echo "QEMU_ESXI_EEPRO100 must be 0 or 1" >&2
  exit 2
fi
if [[ "$nvme_sriov_present" != "0" && "$nvme_sriov_present" != "1" ]]; then
  echo "QEMU_ESXI_NVME_SRIOV must be 0 or 1" >&2
  exit 2
fi
if [[ "$nvme_sriov_vf_config_ids" != "0" && "$nvme_sriov_vf_config_ids" != "1" ]]; then
  echo "QEMU_ESXI_NVME_SRIOV_VF_CONFIG_IDS must be 0 or 1" >&2
  exit 2
fi
if [[ "$nvme_sriov_vf_config_ids" == "1" && "$nvme_sriov_present" != "1" ]]; then
  echo "QEMU_ESXI_NVME_SRIOV_VF_CONFIG_IDS requires QEMU_ESXI_NVME_SRIOV=1" >&2
  exit 2
fi
if [[ "$igb_sriov_present" != "0" && "$igb_sriov_present" != "1" ]]; then
  echo "QEMU_ESXI_IGB_SRIOV must be 0 or 1" >&2
  exit 2
fi
primary_endpoint_count=0
[[ "$largebar_size" != "0" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "${QEMU_ESXI_IVSHMEM_SIZE:-0}" != "0" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "$edu_present" == "1" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "$virtio_net_present" == "1" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "$eepro100_present" == "1" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "$nvme_sriov_present" == "1" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
[[ "$igb_sriov_present" == "1" ]] && primary_endpoint_count=$((primary_endpoint_count + 1))
if (( primary_endpoint_count > 1 )); then
  echo "QEMU_ESXI_IVSHMEM_SIZE, QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE, QEMU_ESXI_EDU, QEMU_ESXI_VIRTIO_NET, QEMU_ESXI_EEPRO100, QEMU_ESXI_NVME_SRIOV, and QEMU_ESXI_IGB_SRIOV share one slot" >&2
  exit 2
fi

platform_mmio_options=()
iommu_device_options=()
if [[ "${QEMU_ESXI_IOMMU:-1}" == "1" ]]; then
  iommu_options="intel-iommu,intremap=on,caching-mode=on,device-iotlb=on${QEMU_ESXI_IOMMU_OPTIONS:-}"
  iommu_device_options=(-device "$iommu_options")
elif [[ "${QEMU_ESXI_IOMMU}" != "0" ]]; then
  echo "QEMU_ESXI_IOMMU must be 0 or 1" >&2
  exit 2
fi
host_hole64_size="${QEMU_ESXI_HOST_HOLE64_SIZE:-}"
ovmf_mmio64_mb="${QEMU_ESXI_OVMF_MMIO64_MB:-}"
if [[ "$largebar_size" =~ ^([0-9]+)G$ ]] && (( BASH_REMATCH[1] > 32 )); then
  host_hole64_size="${host_hole64_size:-$largebar_size}"
  ovmf_mmio64_mb="${ovmf_mmio64_mb:-$((BASH_REMATCH[1] * 1024))}"
fi
if [[ -n "$host_hole64_size" ]]; then
  platform_mmio_options+=(
    -global "q35-pcihost.pci-hole64-size=$host_hole64_size"
  )
fi
if [[ -n "$ovmf_mmio64_mb" ]]; then
  platform_mmio_options+=(
    -fw_cfg "name=opt/ovmf/X-PciMmio64Mb,string=$ovmf_mmio64_mb"
  )
fi

if [[ "${QEMU_ESXI_IVSHMEM_SIZE:-0}" != "0" ]]; then
  ivshmem_mem_path="${QEMU_ESXI_IVSHMEM_MEM_PATH:-/dev/shm}"
  prepare_memory_backend_path "$QEMU_ESXI_IVSHMEM_SIZE" "$ivshmem_mem_path"
  test_devices+=(
    -object "memory-backend-file,id=ivmem,size=${QEMU_ESXI_IVSHMEM_SIZE},mem-path=$ivshmem_mem_path,share=on"
    -device "ivshmem-plain,id=test_ivshmem,memdev=ivmem,bus=$ivshmem_bus,addr=$ivshmem_addr,rombar=0"
  )
fi

if [[ "$largebar_size" != "0" ]]; then
  test_devices+=(
    -device "pci-testdev,id=test_largebar,membar=$largebar_size,bus=$largebar_bus,addr=$largebar_addr,rombar=0"
  )
fi

if [[ "$edu_present" == "1" ]]; then
  edu_options="edu,id=test_edu,bus=$edu_bus,addr=$edu_addr,rombar=0"
  if [[ -n "${QEMU_ESXI_EDU_DMA_MASK:-}" ]]; then
    edu_options+=",dma_mask=${QEMU_ESXI_EDU_DMA_MASK}"
  fi
  test_devices+=(
    -device "$edu_options"
  )
fi

if [[ "$virtio_net_present" == "1" ]]; then
  virtio_net_options="virtio-net-pci,id=test_virtio_net,netdev=test2,mac=52:54:00:08:02:00,bus=$virtio_net_bus,addr=$virtio_net_addr,rombar=0"
  virtio_net_options+=",disable-legacy=${QEMU_ESXI_VIRTIO_DISABLE_LEGACY:-on}"
  virtio_net_options+=",x-disable-pcie=${QEMU_ESXI_VIRTIO_DISABLE_PCIE:-off}"
  virtio_net_options+=",x-pcie-flr-init=${QEMU_ESXI_VIRTIO_FLR:-on}"
  virtio_net_options+=",x-pcie-pm-init=${QEMU_ESXI_VIRTIO_PM:-on}"
  if [[ -n "${QEMU_ESXI_VIRTIO_D3HOT_RESET:-}" ]]; then
    virtio_net_options+=",x-pcie-d3hot-reset=${QEMU_ESXI_VIRTIO_D3HOT_RESET}"
  fi
  if [[ -n "${QEMU_ESXI_VIRTIO_PME_D3HOT:-}" ]]; then
    virtio_net_options+=",x-pcie-pme-d3hot=${QEMU_ESXI_VIRTIO_PME_D3HOT}"
  fi
  virtio_net_options+=",x-pcie-deverr-init=${QEMU_ESXI_VIRTIO_DEVERR:-on}"
  virtio_net_options+=",x-pcie-extcap-init=${QEMU_ESXI_VIRTIO_EXTCAP:-on}"
  virtio_net_options+=",aer=${QEMU_ESXI_VIRTIO_AER:-off}"
  if [[ -n "${QEMU_ESXI_VIRTIO_CLASS:-}" ]]; then
    virtio_net_options+=",x-pci-class-code=${QEMU_ESXI_VIRTIO_CLASS}"
  fi
  if [[ -n "${QEMU_ESXI_VIRTIO_ROOT_CAP:-}" ]]; then
    virtio_net_options+=",x-pcie-root-cap-init=${QEMU_ESXI_VIRTIO_ROOT_CAP}"
  fi
  test_devices+=(
    -device "$virtio_net_options"
  )
fi

if [[ "$eepro100_present" == "1" ]]; then
  test_devices+=(
    -device "i82559er,id=test_eepro100,netdev=test2,mac=52:54:00:08:02:00,bus=$virtio_net_bus,addr=$virtio_net_addr,rombar=0"
  )
fi

if [[ "$nvme_sriov_present" == "1" ]]; then
  nvme_sriov_options="nvme,id=test_nvme_pf,serial=directpath-sriov,subsys=test_nvme_subsys,bus=$virtio_net_bus,addr=$virtio_net_addr,rombar=0,sriov_max_vfs=1,sriov_vq_flexible=2,sriov_vi_flexible=1"
  if [[ "$nvme_sriov_vf_config_ids" == "1" ]]; then
    nvme_sriov_options+=",x-sriov-vf-config-ids=on"
  fi
  test_devices+=(
    -device "nvme-subsys,id=test_nvme_subsys"
    -device "$nvme_sriov_options"
  )
fi

if [[ "$igb_sriov_present" == "1" ]]; then
  igb_sriov_options="igb,id=test_igb_pf,netdev=test2,mac=52:54:00:08:02:00,bus=$virtio_net_bus,addr=$virtio_net_addr,rombar=0"
  if [[ -n "${QEMU_ESXI_IGB_DEVICE_ID:-}" ]]; then
    igb_sriov_options+=",x-pci-device-id=${QEMU_ESXI_IGB_DEVICE_ID}"
  fi
  if [[ -n "${QEMU_ESXI_IGB_VF_DEVICE_ID:-}" ]]; then
    igb_sriov_options+=",x-pci-vf-device-id=${QEMU_ESXI_IGB_VF_DEVICE_ID}"
  fi
  if [[ -n "${QEMU_ESXI_IGB_SUBSYSTEM_VENDOR_ID:-}" ]]; then
    igb_sriov_options+=",x-pci-subsystem-vendor-id=${QEMU_ESXI_IGB_SUBSYSTEM_VENDOR_ID}"
  fi
  if [[ -n "${QEMU_ESXI_IGB_SUBSYSTEM_ID:-}" ]]; then
    igb_sriov_options+=",x-pci-subsystem-id=${QEMU_ESXI_IGB_SUBSYSTEM_ID}"
  fi
  test_devices+=(
    -device "$igb_sriov_options"
  )
fi

if [[ "${QEMU_ESXI_IVSHMEM_ALT_SIZE:-0}" != "0" ]]; then
  ivshmem_alt_mem_path="${QEMU_ESXI_IVSHMEM_ALT_MEM_PATH:-/dev/shm}"
  prepare_memory_backend_path "$QEMU_ESXI_IVSHMEM_ALT_SIZE" "$ivshmem_alt_mem_path"
    if [[ "$ivshmem_alt_bus" == "test_alt_rp" ]]; then
      alt_root_port_options="id=test_alt_rp,bus=pcie.0,chassis=9,slot=9,addr=0x09.0"
      if [[ "${QEMU_ESXI_P2P_DISABLE_ACS:-0}" == "1" ]]; then
        alt_root_port_options+=",disable-acs=on"
      fi
      test_devices+=(
      -device "pcie-root-port,$alt_root_port_options"
      )
  fi
  test_devices+=(
    -object "memory-backend-file,id=ivmem_alt,size=${QEMU_ESXI_IVSHMEM_ALT_SIZE},mem-path=$ivshmem_alt_mem_path,share=on"
    -device "ivshmem-plain,id=test_ivshmem_alt,memdev=ivmem_alt,bus=$ivshmem_alt_bus,addr=$ivshmem_alt_addr,rombar=0${QEMU_ESXI_IVSHMEM_ALT_OPTIONS:-}"
  )
fi

trace_options=()
normalize_trace_events() {
  local source=$1
  local destination=$2

  if [[ ! -r "$source" ]]; then
    echo "trace event list is not readable: $source" >&2
    exit 2
  fi
  tr -d '\r' < "$source" > "$destination"
}

if [[ "${QEMU_ESXI_TRACE:-0}" == "1" ]]; then
  trace_events_source="${QEMU_ESXI_TRACE_EVENTS:-$script_dir/qemu-esxi8-trace-events}"
  trace_events="/tmp/qemu-esxi8-$instance-trace-events"
  normalize_trace_events "$trace_events_source" "$trace_events"
  trace_options+=(
    -trace "events=$trace_events,file=$vm_dir/qemu-trace.log"
  )
fi
if [[ "$nvme_sriov_present" == "1" || "$igb_sriov_present" == "1" ]]; then
  sriov_trace_events="/tmp/qemu-esxi8-$instance-sriov-trace-events"
  normalize_trace_events "$script_dir/qemu-sriov-trace-events" "$sriov_trace_events"
  trace_options+=(
    -trace "events=$sriov_trace_events,file=$vm_dir/qemu-sriov-trace.log"
  )
fi

control_options=()
if [[ -n "${QEMU_ESXI_QTEST_SOCKET:-}" ]]; then
  rm -f "$QEMU_ESXI_QTEST_SOCKET"
  control_options+=(
    -qtest "unix:$QEMU_ESXI_QTEST_SOCKET,server=on,wait=off"
  )
fi
if [[ "${QEMU_ESXI_START_PAUSED:-0}" == "1" ]]; then
  control_options+=(-S)
elif [[ "${QEMU_ESXI_START_PAUSED:-0}" != "0" ]]; then
  echo "QEMU_ESXI_START_PAUSED must be 0 or 1" >&2
  exit 2
fi

mkdir -p "$vm_dir"
rm -f "$pid_file"
if [[ "${QEMU_ESXI_TRACE:-0}" == "1" ]] && [[ -e "$vm_dir/qemu-trace.log" ]]; then
  mv -f "$vm_dir/qemu-trace.log" "$vm_dir/qemu-trace.previous.log"
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

exec "$qemu_binary" \
  -L "$qemu_data_dir" \
  -name "$qemu_name" \
  -machine "$machine_options" \
  -cpu host,+vmx,-vmx-tsc-scaling \
  -smp 4 \
  "${memory_options[@]}" \
  "${identity_options[@]}" \
  "${iommu_device_options[@]}" \
  "${platform_mmio_options[@]}" \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file="$ovmf_vars" \
  -drive if=none,id=system,file="$system_disk",format=qcow2,cache=writeback,discard=unmap \
  -drive if=none,id=datastore,file="$datastore_disk",format=qcow2,cache=writeback,discard=unmap \
  "${storage_options[@]}" \
  -netdev tap,id=mgmt,ifname="$tap",script=no,downscript=no,vnet_hdr=off \
  -device e1000e,netdev=mgmt,mac="$mgmt_mac",bus=pcie.0,addr=0x05.0 \
  -netdev user,id=test0,restrict=on \
  -netdev user,id=test1,restrict=on \
  -netdev user,id=test2,restrict=on \
  "${test_devices[@]}" \
  -vga std \
  -vnc "127.0.0.1:$vnc_display" \
  -monitor unix:"$vm_dir/monitor.sock",server,nowait \
  -serial file:"$vm_dir/serial.log" \
  "${control_options[@]}" \
  "${trace_options[@]}" \
  -pidfile "$pid_file" \
  -daemonize \
  -D "$log_file"
