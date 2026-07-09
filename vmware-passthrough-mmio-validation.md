# VMware VMDirectPath MMIO validation plan and QEMU mapping

Date: 2026-07-10

This note narrows the question from "default EFI VM" to "EFI VM with a real PCI
passthrough device". The main VMware reference is Broadcom KB 312208.

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

## References

- Broadcom KB 312208, vSphere VMDirectPath I/O and Dynamic DirectPath I/O:
  https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html
- Broadcom KB 323402, passthrough power-on failure MMIO fix:
  https://knowledge.broadcom.com/external/article/323402/failed-to-power-on-virtual-machines-with.html
- Broadcom PowerCLI command index, `Get-PassthroughDevice` and
  `New-PassthroughDevice`:
  https://developer.broadcom.com/powercli/latest/products/vmwarevsphereandvsan/commands-index
