#!/usr/bin/env bash
set -euo pipefail

workdir=${WORKDIR:-/tmp/ovmf-real-linux-mmio}
image_url=${IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}
base_image=${BASE_IMAGE:-"$workdir/noble-server-cloudimg-amd64.img"}
machine=${MACHINE:-pc-i440fx-jammy}
firmware=${FIRMWARE:-ovmf}
ram=${RAM:-3584M}
bar_size=${BAR_SIZE:-1G}
bar_sizes=${BAR_SIZES:-$bar_size}
cases=${CASES:-ovmf_default ovmf_fwcfg_zero ovmf_host_4g ovmf_both_4g ovmf_both_zero}
linux_kernel_args=${LINUX_KERNEL_ARGS:-}
qemu_timeout=${QEMU_TIMEOUT:-420}
cpu=${CPU:-host}
host_bridge=${HOST_BRIDGE:-auto}
no_net=${NO_NET:-0}
no_ivshmem=${NO_IVSHMEM:-0}

mkdir -p "$workdir"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

find_ovmf_file() {
  local env_name=$1
  shift
  local candidate

  if [ -n "${!env_name:-}" ]; then
    printf '%s\n' "${!env_name}"
    return
  fi

  for candidate in "$@"; do
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "unable to find $env_name; set $env_name explicitly" >&2
  exit 1
}

download_base_image() {
  if [ -e "$base_image" ]; then
    return
  fi

  mkdir -p "$(dirname "$base_image")"
  echo "Downloading Linux cloud image to $base_image"
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --output "$base_image.tmp" "$image_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$base_image.tmp" "$image_url"
  else
    echo "missing curl or wget for IMAGE_URL download" >&2
    exit 1
  fi
  mv "$base_image.tmp" "$base_image"
}

make_seed_image() {
  local case_name=$1
  local seed_dir=$2
  local seed_img=$3
  local case_b64 args_b64
  local seed_img_abs

  case_b64=$(printf '%s' "$case_name" | base64 | tr -d '\n')
  args_b64=$(printf '%s' "$linux_kernel_args" | base64 | tr -d '\n')

  mkdir -p "$seed_dir"
  seed_img_abs=$(cd "$(dirname "$seed_img")" && pwd)/$(basename "$seed_img")

  cat > "$seed_dir/meta-data" <<EOF_META
instance-id: mmio-$case_name-$(date +%s%N)
local-hostname: mmio-$case_name
EOF_META

  if [ -z "$linux_kernel_args" ]; then
    cat > "$seed_dir/user-data" <<EOF_USER
#cloud-config
datasource_list: [ NoCloud, None ]
network:
  config: disabled
bootcmd:
  - |
    exec >/dev/ttyS0 2>&1
    echo "===== CASE: $case_name ====="
    echo "=== kernel ==="
    uname -a

    echo
    echo "=== cmdline ==="
    cat /proc/cmdline

    echo
    echo "=== ivshmem target ==="
    found=0
    for d in /sys/bus/pci/devices/*; do
      [ -e "\$d/vendor" ] || continue
      vendor=\$(cat "\$d/vendor")
      device=\$(cat "\$d/device")
      class=\$(cat "\$d/class")
      if [ "\$vendor" = "0x1af4" ] && [ "\$device" = "0x1110" ]; then
        found=1
        printf '%s vendor=%s device=%s class=%s\\n' "\${d##*/}" "\$vendor" "\$device" "\$class"
        n=0
        while read -r start end flags rest; do
          if [ "\$start" != "0x0000000000000000" ] || [ "\$end" != "0x0000000000000000" ]; then
            printf '  BAR/resource%-2s %s %s %s\\n' "\$n" "\$start" "\$end" "\$flags"
          fi
          n=\$((n + 1))
        done < "\$d/resource"
      fi
    done
    if [ "\$found" -eq 0 ]; then
      echo "ivshmem target 1af4:1110 not found"
    fi

    echo
    echo "=== /proc/iomem PCI-ish lines ==="
    while read -r line; do
      case "\$line" in
        *PCI*|*0000:00*|*Window*) printf '%s\\n' "\$line" ;;
      esac
    done < /proc/iomem

    echo
    echo "=== done ==="
    sync
    poweroff -f
EOF_USER
    build_seed_image "$seed_dir" "$seed_img_abs"
    return
  fi

  cat > "$seed_dir/user-data" <<EOF_USER
#cloud-config
datasource_list: [ NoCloud, None ]
network:
  config: disabled
output:
  all: "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"
write_files:
  - path: /etc/systemd/system/mmio-stage.service
    permissions: '0644'
    content: |
      [Unit]
      Description=PCI MMIO validation reporter
      After=cloud-final.service

      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/mmio-stage.sh

      [Install]
      WantedBy=multi-user.target
  - path: /usr/local/sbin/mmio-stage.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      exec >/dev/ttyS0 2>&1

      state_dir=/var/lib/mmio-validate
      mkdir -p "\$state_dir"

      case_name="\$(printf '%s' "$case_b64" | base64 -d)"
      requested_args="\$(printf '%s' "$args_b64" | base64 -d)"
      marker="\$state_dir/kernel-args-applied"

      if [ -n "\$requested_args" ] && [ ! -e "\$marker" ]; then
        echo "=== preparing kernel args for next OVMF boot ==="
        echo "case=\$case_name"
        echo "requested_args=\$requested_args"
        mkdir -p /etc/default/grub.d
        printf 'GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} %s"\\n' "\$requested_args" \
          > /etc/default/grub.d/99-mmio-validate.cfg
        if command -v update-grub >/dev/null 2>&1; then
          update-grub
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
          grub2-mkconfig -o /boot/grub2/grub.cfg
        else
          echo "no grub update command found"
          exit 1
        fi
        touch "\$marker"
        sync
        systemctl reboot --force || reboot -f
        exit 0
      fi

      echo "===== CASE: \$case_name ====="
      echo "=== kernel ==="
      uname -a

      echo
      echo "=== cmdline ==="
      cat /proc/cmdline

      echo
      echo "=== ivshmem target ==="
      found=0
      for d in /sys/bus/pci/devices/*; do
        [ -e "\$d/vendor" ] || continue
        vendor=\$(cat "\$d/vendor")
        device=\$(cat "\$d/device")
        class=\$(cat "\$d/class")
        if [ "\$vendor" = "0x1af4" ] && [ "\$device" = "0x1110" ]; then
          found=1
          printf '%s vendor=%s device=%s class=%s\\n' "\${d##*/}" "\$vendor" "\$device" "\$class"
          n=0
          while read -r start end flags rest; do
            if [ "\$start" != "0x0000000000000000" ] || [ "\$end" != "0x0000000000000000" ]; then
              printf '  BAR/resource%-2s %s %s %s\\n' "\$n" "\$start" "\$end" "\$flags"
            fi
            n=\$((n + 1))
          done < "\$d/resource"
        fi
      done
      if [ "\$found" -eq 0 ]; then
        echo "ivshmem target 1af4:1110 not found"
      fi

      echo
      echo "=== all PCI resources ==="
      for d in /sys/bus/pci/devices/*; do
        [ -e "\$d/vendor" ] || continue
        printf '\\n%s vendor=%s device=%s class=%s\\n' \
          "\${d##*/}" "\$(cat "\$d/vendor")" "\$(cat "\$d/device")" "\$(cat "\$d/class")"
        n=0
        while read -r start end flags rest; do
          if [ "\$start" != "0x0000000000000000" ] || [ "\$end" != "0x0000000000000000" ]; then
            printf '  BAR/resource%-2s %s %s %s\\n' "\$n" "\$start" "\$end" "\$flags"
          fi
          n=\$((n + 1))
        done < "\$d/resource"
      done

      echo
      echo "=== /proc/iomem PCI-ish lines ==="
      while read -r line; do
        case "\$line" in
          *PCI*|*0000:00*|*Window*) printf '%s\\n' "\$line" ;;
        esac
      done < /proc/iomem

      echo
      echo "=== done ==="
      sync
      systemctl poweroff --force --force || poweroff -f
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, mmio-stage.service ]
  - [ systemctl, start, --no-block, mmio-stage.service ]
EOF_USER

  build_seed_image "$seed_dir" "$seed_img_abs"
}

build_seed_image() {
  local seed_dir=$1
  local seed_img_abs=$2

  if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds "$seed_img_abs" "$seed_dir/user-data" "$seed_dir/meta-data"
  elif command -v genisoimage >/dev/null 2>&1; then
    (cd "$seed_dir" && genisoimage -quiet -output "$seed_img_abs" \
      -volid cidata -joliet -rock user-data meta-data)
  elif command -v mkisofs >/dev/null 2>&1; then
    (cd "$seed_dir" && mkisofs -quiet -output "$seed_img_abs" \
      -volid cidata -joliet -rock user-data meta-data)
  elif command -v xorriso >/dev/null 2>&1; then
    (cd "$seed_dir" && xorriso -as mkisofs -quiet -output "$seed_img_abs" \
      -volid cidata -joliet -rock user-data meta-data)
  else
    echo "missing cloud-localds, genisoimage, mkisofs, or xorriso for NoCloud seed image" >&2
    exit 1
  fi
}

run_case() {
  local name=$1
  local bar_size_value=$2
  shift 2
  local case_dir="$workdir/${name}_bar-${bar_size_value}"
  local vars="$case_dir/OVMF_VARS.fd"
  local disk="$case_dir/os.qcow2"
  local seed="$case_dir/seed.iso"
  local log="$case_dir/serial.log"
  local base_format
  local firmware_args=()
  local net_args=()
  local ivshmem_args=()
  local reboot_args=(-no-reboot)

  rm -rf "$case_dir"
  mkdir -p "$case_dir"

  if [ "$firmware" = ovmf ]; then
    cp "$ovmf_vars_template" "$vars"
    firmware_args=(
      -drive if=pflash,format=raw,readonly=on,file="$ovmf_code"
      -drive if=pflash,format=raw,file="$vars"
    )
  elif [ "$firmware" = seabios ]; then
    firmware_args=(-boot order=c)
  else
    echo "unknown FIRMWARE: $firmware" >&2
    exit 1
  fi
  base_format=$(qemu-img info --output=json "$base_image" | sed -n 's/.*"format": *"\([^"]*\)".*/\1/p' | head -1)
  qemu-img create -f qcow2 -F "${base_format:-qcow2}" -b "$base_image" "$disk" >/dev/null
  make_seed_image "${name}_bar-${bar_size_value}" "$case_dir/seed" "$seed"
  if [ "$no_net" != 1 ]; then
    net_args=(-netdev user,id=net0 -device virtio-net-pci,netdev=net0)
  fi
  if [ "$no_ivshmem" != 1 ]; then
    ivshmem_args=(
      -object memory-backend-memfd,id=shm,size="$bar_size_value",share=on
      -device ivshmem-plain,memdev=shm
    )
  fi
  if [ -n "$linux_kernel_args" ]; then
    reboot_args=()
  fi

  echo "===== HOST RUN: $name ====="
  echo "log: $log"
  set +e
  timeout "$qemu_timeout" qemu-system-x86_64 \
    -machine "$machine",accel=kvm:tcg \
    -cpu "$cpu" \
    -m "$ram" \
    -nodefaults \
    -display none \
    -serial mon:stdio \
    "${reboot_args[@]}" \
    "${firmware_args[@]}" \
    -drive if=none,id=osdisk,format=qcow2,file="$disk" \
    -device virtio-blk-pci,drive=osdisk \
    -drive if=none,id=cidata,format=raw,file="$seed",readonly=on \
    -device virtio-blk-pci,drive=cidata \
    "${net_args[@]}" \
    "${ivshmem_args[@]}" \
    "$@" 2>&1 | tee "$log"
  local qemu_status=${PIPESTATUS[0]}
  set -e
  if [ "$qemu_status" -eq 124 ]; then
    echo "case timed out: $name" >&2
  fi
  echo
}

need qemu-system-x86_64
need qemu-img

if [ "$host_bridge" = auto ]; then
  case "$machine" in
    *q35*) host_bridge=q35-pcihost ;;
    *) host_bridge=i440FX-pcihost ;;
  esac
fi

if [ "$firmware" = ovmf ]; then
  ovmf_code=$(find_ovmf_file OVMF_CODE \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.4m.fd)

  ovmf_vars_template=$(find_ovmf_file OVMF_VARS \
    /usr/share/OVMF/OVMF_VARS.fd \
    /usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/edk2/ovmf/OVMF_VARS.fd \
    /usr/share/edk2/ovmf/OVMF_VARS.4m.fd)
else
  ovmf_code="<not used>"
  ovmf_vars_template="<not used>"
fi

download_base_image

echo "OVMF_CODE=$ovmf_code"
echo "OVMF_VARS=$ovmf_vars_template"
echo "BASE_IMAGE=$base_image"
echo "LINUX_KERNEL_ARGS=${linux_kernel_args:-<default image cmdline>}"
echo "FIRMWARE=$firmware"
echo "MACHINE=$machine"
echo "HOST_BRIDGE=$host_bridge"
echo "BAR_SIZES=$bar_sizes"
echo "CASES=$cases"
echo "NO_NET=$no_net"
echo "NO_IVSHMEM=$no_ivshmem"
echo

run_named_case() {
  local case_name=$1
  local bar_size_value=$2

  case "$case_name" in
    ovmf_default)
      run_case "$case_name" "$bar_size_value"
      ;;
    ovmf_fwcfg_zero)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
      ;;
    ovmf_host_zero)
      run_case "$case_name" "$bar_size_value" \
        -global "$host_bridge".pci-hole64-size=0
      ;;
    ovmf_both_zero)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
        -global "$host_bridge".pci-hole64-size=0
      ;;
    ovmf_fwcfg_4g)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
      ;;
    ovmf_host_4g)
      run_case "$case_name" "$bar_size_value" \
        -global "$host_bridge".pci-hole64-size=4G
      ;;
    ovmf_both_4g)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096 \
        -global "$host_bridge".pci-hole64-size=4G
      ;;
    ovmf_both_2g)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=2048 \
        -global "$host_bridge".pci-hole64-size=2G
      ;;
    ovmf_both_8g)
      run_case "$case_name" "$bar_size_value" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=8192 \
        -global "$host_bridge".pci-hole64-size=8G
      ;;
    *)
      echo "unknown case: $case_name" >&2
      exit 1
      ;;
  esac
}

for one_bar_size in $bar_sizes; do
  for one_case in $cases; do
    run_named_case "$one_case" "$one_bar_size"
  done
done

echo "===== SUMMARY ====="
for log in "$workdir"/*/serial.log; do
  [ -e "$log" ] || continue
  echo "--- $log ---"
  grep -E '===== CASE:|=== cmdline ===|BAR/resource|ivshmem target|0x00000001|0x00000002' "$log" || true
done
