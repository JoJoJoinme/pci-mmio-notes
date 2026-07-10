# VMware VMDirectPath MMIO validation plan and QEMU mapping

Date: 2026-07-10

This note narrows the question from "default EFI VM" to "EFI VM with a real PCI
passthrough device". The main VMware reference is Broadcom KB 312208.

The local QEMU-side non-BAR checks that could actually be executed on this host
are recorded in `qemu-vmdirectpath-nonbar-local-validation.md`. That companion
note separates verified QEMU behavior from items that still require real ESXi or
bare-metal Linux/VFIO passthrough hardware.

The acceptance criteria and executable VMware/QEMU test matrix are maintained in
`vmware-directpath-acceptance-test-plan.md`. That document defines the evidence
grade, per-case artifacts, pass/fail rules, and the boundary between nested tests
and mandatory bare-metal confirmation.

## What KB 312208 gives us

KB 312208 makes three useful claims for validation:

1. UEFI firmware is required when the VM needs more than the legacy below-4G BAR
   allocation space.
2. 64-bit MMIO is not implied by UEFI. It is enabled with:

```text
pciPassthru.use64bitMMIO = "TRUE"
```

3. When the VM needs a larger 64-bit MMIO region, the size is configured as a
   power-of-two number of GB:

```text
pciPassthru.64bitMMIOSizeGB = "128"
```

Therefore, the VMware-side hypothesis is:

```text
EFI + passthrough device + no pciPassthru.use64bitMMIO
  = no explicit product-level above-4G passthrough MMIO aperture.

EFI + passthrough device + pciPassthru.use64bitMMIO=TRUE
  = explicit 64-bit passthrough MMIO aperture.

EFI + passthrough device + pciPassthru.use64bitMMIO=TRUE
  + pciPassthru.64bitMMIOSizeGB=N
  = explicit N-GB passthrough MMIO aperture.
```

The point to prove is not merely whether a VM powers on. The point is what
resource window the VMX process and the guest are actually using.

## Current local limitation

The local nested ESXi environments are enough to prove default VMX keys and
power-on behavior for ordinary EFI VMs, but they are not enough to prove
VMDirectPath runtime MMIO behavior. Real VMDirectPath validation needs a bare
metal ESXi host or vCenter-managed host with a PCI device that can be marked for
passthrough.

Nested Workstation/Hyper-V ESXi does not expose a real assignable PCI device in
the way VMDirectPath requires. Treat any nested result here as configuration
evidence only, not passthrough runtime evidence.

## VMware validation matrix

Use the same EFI guest, same passthrough device, and same guest OS for all cases.
Capture VMX, vmware.log, and guest resource output for every case.

| Case | VMware VMX knobs | Expected question answered |
| --- | --- | --- |
| P0 default passthrough | passthrough device present, no global `pciPassthru.use64bitMMIO`, no `pciPassthru.64bitMMIOSizeGB` | Does VMware reserve any above-4G passthrough aperture by default? |
| P1 use64 only | `pciPassthru.use64bitMMIO="TRUE"`, no SizeGB | Does VMware default to a legacy 32G high aperture when use64 is enabled? This must be measured. |
| P2 explicit 4G | `pciPassthru.use64bitMMIO="TRUE"`, `pciPassthru.64bitMMIOSizeGB="4"` | Does a 4G aperture appear, and where does the guest place BARs? |
| P3 explicit N | `pciPassthru.use64bitMMIO="TRUE"`, `pciPassthru.64bitMMIOSizeGB="N"` | Does guest-visible high MMIO track the configured N? |
| P4 SizeGB without use64 | SizeGB set, `use64bitMMIO` absent/false | Is SizeGB ignored or rejected unless use64 is true? |

P1 is intentionally marked as a measurement, not a conclusion. KB 312208 says
that sizes above 32G require `pciPassthru.64bitMMIOSizeGB`, which suggests that
`use64bitMMIO=TRUE` without SizeGB may have a 32G historical/default region. Do
not encode that as a fact until vmware.log and guest resources confirm it on the
target ESXi version.

## VMware evidence to collect

For each case, collect:

```text
VMX:
  firmware
  virtualHW.version
  every pciPassthru* key
  every 64bitMMIO key
  every pciHole / pci.*hole key

vmware.log:
  DICT --- CONFIGURATION block
  PCIPassthru / passthrough lines
  MMIO / 64bitMMIO / pciHole lines
  power-on failure, if any

Guest Linux:
  dmesg | grep -E 'PCI host bridge|root bus resource|BAR'
  cat /proc/iomem
  lspci -nnvv
  /sys/bus/pci/devices/<passthrough-device>/resource
```

Also record the physical device BARs on the ESXi host:

```text
esxcli hardware pci list
esxcli hardware pci pcipassthru list
```

If SSH is disabled, gather equivalent host PCI and passthrough inventory through
PowerCLI or the vSphere UI.

## Automation sketch

Preferred control path on a real ESXi/vCenter lab:

```powershell
Connect-VIServer <vcenter-or-esxi>

$host = Get-VMHost -Name <host>
$dev = Get-PassthroughDevice -VMHost $host |
  Where-Object { $_.Name -match '<device-name-or-vendor>' } |
  Select-Object -First 1

# Create or reuse an EFI VM on the same host, then attach the passthrough device.
# Broadcom PowerCLI documents Get-PassthroughDevice and New-PassthroughDevice for
# retrieving and attaching pass-through devices.
New-PassthroughDevice -VM <vm> -PassthroughDevice $dev

# Use New-AdvancedSetting / Set-AdvancedSetting, or direct ReconfigVM, to toggle:
#   pciPassthru.use64bitMMIO
#   pciPassthru.64bitMMIOSizeGB
```

Exact device selection and host reboot requirements depend on whether the PCI
device is already enabled for passthrough. Preserve the VMX and logs before each
case is modified.

## QEMU mapping

For OVMF, VMware's product-level knobs need two QEMU controls because QEMU splits
the behavior between firmware and the host bridge/ACPI resource.

| VMware case | QEMU/OVMF mapping | Why |
| --- | --- | --- |
| P0 default passthrough, no 64-bit MMIO aperture | `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0` plus `-global <host-bridge>.pci-hole64-size=0` | Disable OVMF's firmware 64-bit aperture and QEMU's ACPI/root 64-bit window. |
| P1 use64 only, if VMware proves 32G | `X-PciMmio64Mb=32768` plus `pci-hole64-size=32G` | Match a measured 32G high aperture. Do not use unless P1 proves it. |
| P2 explicit 4G | `X-PciMmio64Mb=4096` plus `pci-hole64-size=4G` | Match explicit 4GB firmware and OS-visible high MMIO. |
| P3 explicit N GB | `X-PciMmio64Mb=N*1024` plus `pci-hole64-size=NG` | Match VMware's configured N-GB VM-level aperture. |
| P4 SizeGB without use64 | no mapping until measured | If VMware ignores SizeGB without use64, map as P0. If it enables/changes a window, document the observed behavior. |

Host bridge names:

```text
i440fx: i440FX-pcihost
q35:    q35-pcihost
```

Examples:

```bash
# OVMF + q35, VMware default-style passthrough MMIO policy
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global q35-pcihost.pci-hole64-size=0

# OVMF + q35, VMware explicit 4GB passthrough MMIO policy
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
-global q35-pcihost.pci-hole64-size=4G

# OVMF + q35, measured/explicit 128GB passthrough MMIO policy
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=131072
-global q35-pcihost.pci-hole64-size=128G
```

## Why both QEMU knobs are required

OVMF consumes `opt/ovmf/X-PciMmio64Mb` during firmware PCI allocation. QEMU's
host bridge publishes the final guest-visible 64-bit PCI root window through
ACPI. Turning off only one side is not VMware-equivalent:

- `X-PciMmio64Mb=0` alone: OVMF does not reserve its firmware aperture, but QEMU
  can still publish a default high root window to Linux.
- `pci-hole64-size=0` alone: QEMU stops pre-expanding the high root window, but
  OVMF can still allocate real 64-bit BARs above 4G; ACPI may then report the
  minimal range needed to cover those BARs.

This mirrors the VMware distinction: UEFI firmware is necessary but not
sufficient. The product-level passthrough MMIO setting is separate.

## Non-BAR VMDirectPath details and QEMU alignment

KB 312208 is not only about BAR size. Most of its VMDirectPath rules are about
which layer owns isolation, reset, interrupts, topology, and lifecycle. QEMU can
match some of these with command-line options, but several are host/VFIO
preconditions rather than QEMU flags.

### Baseline QEMU/VFIO shape

For PCIe devices, prefer q35 and explicit root ports. That is closer to an ESXi
EFI VM with PCIe root ports than i440fx.

```bash
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -m 16G \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=OVMF_VARS.fd \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
  -global q35-pcihost.pci-hole64-size=0 \
  -device pcie-root-port,id=rp1,chassis=1,slot=1 \
  -device vfio-pci,host=0000:65:00.0,bus=rp1,addr=00.0,rombar=0
```

Use the MMIO pair above for VMware-default-style passthrough policy. Replace it
with `X-PciMmio64Mb=N*1024` and `pci-hole64-size=NG` only when modeling an
explicit VMware 64-bit MMIO aperture.

### Alignment matrix

| KB / VMware detail | QEMU/VFIO alignment | Principle | Verification |
| --- | --- | --- | --- |
| Host IOMMU / DMA isolation | Enable VT-d/AMD-Vi on the host, bind the device to `vfio-pci`, launch with `-device vfio-pci,host=BDF`. Do not confuse this with guest vIOMMU. | ESXi and VFIO both program the host IOMMU so the physical device DMA targets VM memory, not arbitrary host memory. | Host: `dmesg | grep -Ei 'DMAR|IOMMU|AMD-Vi'`; `readlink /sys/bus/pci/devices/0000:BB:DD.F/iommu_group`; guest: device works without host driver owning it. |
| Guest-visible vIOMMU | Usually leave absent for ordinary DirectPath equivalence. Add `-device intel-iommu,intremap=on,caching-mode=on` only when matching a VMware VM with virtual IOMMU exposed. | Host IOMMU is required for passthrough safety; guest vIOMMU is a separate virtual feature. | Guest: `dmesg | grep -Ei 'DMAR|IOMMU'`; ACPI tables show DMAR only when intentionally exposed. |
| ACS / isolation groups | Use real hardware with proper ACS so VFIO groups are isolated. Do not use Linux `pcie_acs_override` for a supported-equivalent proof. | VMware's ACS rule and Linux VFIO groups are both approximations of "can this device DMA outside the assignment boundary?" | Host: every assigned function's `/iommu_group/devices` contains only functions intended for the VM. |
| Relaxed P2P DMA | No generic QEMU equivalent to VMware's relaxed ACS/P2P policy. Use real topology that supports P2P and device-specific support; for NVIDIA GPUDirect, QEMU has `x-nv-gpudirect-clique`, but that is not a general ACS bypass. | P2P is governed by physical switches, ACS forwarding, IOMMU behavior, and device drivers. | Benchmark or driver proof of P2P; inspect IOMMU groups and PCIe switch ACS capabilities. |
| PCIe topology | Use q35 plus `pcie-root-port`; optionally set `x-speed=` and `x-width=` on the root port if guest-visible link characteristics matter. | VMware EFI guests expose PCIe root ports; q35 is the QEMU PCIe machine. | Guest: `lspci -tv` and `lspci -vv` LinkCap/LinkSta. |
| Multifunction devices | Assign all dependent functions. Preserve multifunction layout with `multifunction=on` and same slot when needed. | Reset, power management, and driver binding often operate at device/package scope, not one isolated function. | Host IOMMU group contains all functions assigned; guest sees functions under same slot if required. |
| Reset semantics | Prefer devices with FLR. If only bus reset works, all devices affected by that reset must be safe to reset and usually must be assigned together. Tune host reset choice via `/sys/bus/pci/devices/BDF/reset_method` when available, not via a portable QEMU flag. | VMware and VFIO both need a way to put the device in a clean state before/after VM ownership. | Host: check `/sys/bus/pci/devices/BDF/reset` and `reset_method`; QEMU/vfio logs; repeated VM start/stop without wedging. |
| Legacy PCI bridges | Avoid if possible. If a device is behind a conventional bridge and the IOMMU group includes the bridge/other devices, assign the whole group or do not treat it as supported-equivalent. | Legacy bridges often lack requester isolation, so the assignable unit is larger than a single endpoint. | Host: IOMMU group membership; guest: `lspci -tv` if bridge topology is intentionally reproduced. |
| RCiEP / root-complex devices | VFIO can pass some root-complex integrated endpoints if isolation and reset are acceptable, but QEMU will not perfectly reproduce every RCiEP topology detail. Treat as device-specific. | RCiEPs are not ordinary downstream-port endpoints; reset/isolation rules are platform-specific. | Host group/reset proof plus guest driver proof. |
| SR-IOV | Prefer passing VFs for SR-IOV-style sharing. Do not assume a passthrough PF can create/manage VFs inside the guest. | VMware and VFIO both treat VFs as the intended assignable unit for sharing one physical adapter. | Host creates VFs; bind selected VF BDFs to vfio-pci; guest sees VF, not PF-managed SR-IOV control plane. |
| RMRR / reserved regions | Avoid RMRR-constrained devices for clean equivalence. QEMU has no generic command-line switch that makes a host RMRR-safe device safe. | RMRR is a host firmware/IOMMU identity-mapping requirement, not a guest BAR size issue. | Host `dmesg` RMRR/DMAR lines; VFIO attach succeeds without unsafe patches or override parameters. |
| MSI / MSI-X / INTx | Leave QEMU VFIO interrupt acceleration defaults on. Use `x-no-kvm-intx`, `x-no-kvm-msi`, `x-no-kvm-msix` only for debugging, not normal VMware equivalence. Ensure host interrupt remapping is available; do not use unsafe interrupt mode for proof. | Interrupt delivery has both security and performance semantics. MSI/MSI-X is the normal modern path. | Host dmesg: interrupt remapping enabled; guest `lspci -vv` MSI/MSI-X enabled; `/proc/interrupts`. |
| Expansion ROM / option ROM | VMware default is best modeled with `rombar=0` on `vfio-pci`. To model an explicitly enabled option ROM, use `rombar=1,romfile=/path/to.rom` and verify OVMF can execute that ROM type. | Exposing an option ROM is a separate firmware-boot behavior, not a BAR aperture behavior. | Guest `lspci -vv` ROM BAR; OVMF boot log / device boot behavior. |
| PCIe native hotplug / PME / `_OSC` | QEMU q35/root ports expose PCIe/ACPI control surfaces. Root-port options such as `hotplug=`, `x-native-hotplug=`, `power_controller_present=` can change guest-visible behavior, but VMware's ESXi-owned PME policy is not a simple one-flag match. | Power event ownership is ACPI/root-port policy, separate from passthrough MMIO. | Guest ACPI `_OSC` behavior, hotplug tests, `dmesg` PCIe service messages. |
| AER / PCI error handling | Do not assume physical PCI errors are fully delivered to the guest. Treat AER as host/device-specific for VFIO, similar to VMware host-mediated error handling. | Error containment is usually owned by the host/root complex, not the guest. | Host `dmesg` AER/vfio lines; guest AER only if deliberately exposed and tested. |
| Memory reservation / pinned memory | For deterministic VFIO, use preallocated/hugepage-backed memory and set host memlock limits. | ESXi reserves VM memory for DirectPath because device DMA must target stable machine pages; VFIO also pins mapped pages. | Host memlock/hugepage accounting; QEMU starts without VFIO map failures under load. |
| NUMA locality | Bind vCPUs and memory to the NUMA node near the PCI device. | DMA path and latency depend on socket locality. VMware DRS/NUMA placement and QEMU CPU/memory pinning solve the same class of problem. | Host: `cat /sys/bus/pci/devices/BDF/numa_node`; QEMU launched with `numactl` or memory-backend `host-nodes=`. |
| Lifecycle: suspend, snapshot, live migration | Treat ordinary VFIO passthrough as non-migratable/non-snapshot-friendly, matching classic DirectPath limitations. Use device-specific migration only when proven. | Physical device state is not generally serializable. | QEMU monitor/savevm/migration attempt is disabled or fails; device docs prove otherwise. |

### Useful QEMU/VFIO command fragments

Guest-visible virtual IOMMU, only if deliberately matching that VMware setting:

```bash
-machine q35,kernel_irqchip=split
-device intel-iommu,intremap=on,caching-mode=on
```

Multifunction assignment preserving one slot:

```bash
-device pcie-root-port,id=rp1,chassis=1,slot=1
-device vfio-pci,host=0000:65:00.0,bus=rp1,addr=00.0,multifunction=on,rombar=0
-device vfio-pci,host=0000:65:00.1,bus=rp1,addr=00.1,rombar=0
```

Preallocated NUMA-local memory:

```bash
-object memory-backend-file,id=ram0,size=16G,mem-path=/dev/hugepages,prealloc=on,host-nodes=0,policy=bind
-numa node,nodeid=0,memdev=ram0
```

PCIe link presentation:

```bash
-device pcie-root-port,id=rp1,chassis=1,slot=1,x-speed=16,x-width=16
```

### What not to use as "equivalence proof"

- Do not use `pcie_acs_override` and then claim VMware-supported ACS
  equivalence. That is useful for experiments, not proof.
- Do not use `vfio_iommu_type1.allow_unsafe_interrupts=1` for a supported
  DirectPath-equivalent proof.
- Do not rely on `pci=realloc` to create VMware-like MMIO policy. It changes
  Linux allocation behavior after firmware/ACPI policy already exists.
- Do not treat a successful QEMU start as proof of reset safety. Repeated
  start/stop and host log checks are required.
- Do not expose `rombar=1` by accident if matching VMware's default option-ROM
  behavior; set `rombar=0` unless the ROM is part of the scenario.

## References

- Broadcom KB 312208, vSphere VMDirectPath I/O and Dynamic DirectPath I/O:
  https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html
- Broadcom KB 323402, passthrough power-on failure MMIO fix:
  https://knowledge.broadcom.com/external/article/323402/failed-to-power-on-virtual-machines-with.html
- Broadcom PowerCLI command index, `Get-PassthroughDevice` and
  `New-PassthroughDevice`:
  https://developer.broadcom.com/powercli/latest/products/vmwarevsphereandvsan/commands-index
