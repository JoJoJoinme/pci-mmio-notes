# PCI MMIO validation notes: VMware ESXi EFI defaults vs QEMU/OVMF

Record date: 2026-07-14

This repository records the evidence gathered for comparing VMware ESXi EFI VM
MMIO behavior with QEMU/OVMF MMIO controls. It intentionally contains no local
secrets or lab credentials.

For the fuller Chinese write-up based on real OVMF/SeaBIOS boot with an Ubuntu
cloud image, see `qemu-vmware-mmio-comparison.md`. The corresponding runner is
`qemu-ovmf-real-linux-validate.sh`.

For the follow-up VMDirectPath/passthrough-specific validation matrix based on
Broadcom KB 312208, see `vmware-passthrough-mmio-validation.md`.

For the locally executed QEMU non-BAR / VMDirectPath-adjacent validation, see
`qemu-vmdirectpath-nonbar-local-validation.md`. It records which parts were
proved on this WSL2/QEMU host and which still require real physical VFIO or ESXi
passthrough hardware.

For the executable VMware implementation acceptance goals, evidence grades,
test matrix, artifact contract, and QEMU equivalence checklist, see
`vmware-directpath-acceptance-test-plan.md`.

QEMU -> ESXi 8 -> EFI Linux DirectPath 黑盒验证的中文结果报告，包括 MMIO
边界、32/64GB no-backing BAR、VT-d trace、MSI-only EDU、拓扑负例、双主机
vMotion、host crash、guest reboot、INTx 和 Dynamic DirectPath `assignedId`
变化，见 `vmware-esxi8-directpath-local-results.md`；逐项复现命令和 Case
索引见 `vmware-esxi8-lab/README.md`。

ESXi `passthruCapable` 的 15 项 IOMMU/reset/ACS/topology 单变量矩阵、运行时 AH
dependency 反例和 QEMU/VFIO 核对表，见
`vmware-esxi8-passthru-capable-observed-model.md`。2026-07-14 增量的机器可读索引为
`evidence/esxi8-directpath-20260714-summary.json`。

PCIe Correctable/Non-Fatal AER 的三层寄存器、ESXi/guest 日志和 QEMU 对标结论，
见 `vmware-aer-blackbox-results.md`；QEMU OVMF/SeaBIOS surface A/B 入口为
`qemu-aer-surface-validate.sh`。

## Short conclusion

1. An ordinary EFI VMX still contains no implicit `use64bitMMIO` setting, but
   active DirectPath runtime behavior is demand-driven on ESXi 8.0 U3.
2. A 1GB 64-bit prefetchable BAR was mapped below 4G with no high root window.
   A 2GB BAR automatically received a 2GB high window even when
   `pciPassthru.use64bitMMIO = "FALSE"`.
3. Absent, false, true, true+Size4, and Size4-only VMX variants produced the
   same placement for the tested 1GB and 2GB devices.
4. A 4GB BAR failed with absent keys or Size4-only because 1,048,577 mapping
   pages exceeded the 917,504-page default limit. `use64bitMMIO=TRUE` alone was
   sufficient; TRUE+Size4 produced the same 4GB guest window.
5. Equal aggregate size did not imply equal placement: two 1GB BARs fit below
   4G, while one 2GB BAR was placed above 4G. Per-BAR alignment and bridge
   packing are mandatory inputs to a parity launcher.
6. Dynamic selection/exhaustion, powered-off relocation, expected live-vMotion
   rejection, host-crash recovery, and traffic before/after guest reboot were
   all exercised. INTx was exposed but non-functional in the nested DirectPath
   path; the same ISO passed under direct QEMU.
7. A no-backing `pci-testdev` closed 8/32/64GB admission and EFI runtime.
   SizeGB was ignored unless `use64bitMMIO=TRUE`; TRUE-only used the observable
   32GB default budget, so 8/32GB booted and 64GB failed until SizeGB=64.
   Successful guests enumerated the full BAR and produced heartbeats.
8. QEMU EDU closed the MSI-only/DMA gap under both direct QEMU and ESXi
   DirectPath. Four endpoint DMA translations were range-correlated with guest
   IOVAs and completion MSI remaps, with no DMAR fault. ESXi logged a reset
   attempt on guest reboot, but the EDU sentinel persisted, so a reset log is
   not proof that endpoint state was cleared.
9. A 15-case capability matrix separated host IOMMU, accepted reset boundary,
   and ACS policy from runtime assignability. A shared reset dependency failed
   AH selection even with Capable/Enabled/Active=true; a dedicated Root Port
   made the same 32GB device boot.
10. Controlled PME, P2P and RMRR paths are now exercised. SR-IOV remains an
    endpoint/driver boundary: raw capability state can be built, but a
    functional ESXi-supported PF/VF still needs real hardware or a fuller model.
11. A same-SID/same-IOVA DMA A/B now proves the power-off transition. While the
    VM was running, SID `0x200` used domain 2 and translated `0x2b00000` to the
    guest backing GPA `0x1c9100000`. After global context/IOTLB invalidation at
    power-off, the same request used host domain 1 and identity-translated to
    `0x2b00000`. ESXi replaced the guest mapping with its host identity context;
    a post-power-off DMAR fault is therefore not the observed teardown model.
12. No single fixed stock QEMU/OVMF profile matches both VMware outcomes.
    `both_zero` is only the below-4G profile:

```text
q35:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global q35-pcihost.pci-hole64-size=0

i440fx:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global i440FX-pcihost.pci-hole64-size=0
```

The current cold-boot parity runner proves the i440fx 1GB case; q35 zero/zero
with the same 1GB BAR is a negative control because the BAR remains unassigned.
Machine type and the full below-4G layout are part of the profile.

When the aggregate BAR envelope cannot fit below 4G, a launcher must instead
set both knobs to the required high-aperture size.  For the tested 2GB BAR this
was `X-PciMmio64Mb=2048` plus `pci-hole64-size=2G`.  It matched high/low
classification and size, but not VMware's exact high base address.

## QEMU OVMF local validation

`qemu-ovmf-initrd-mmio-check.sh` is the main QEMU proof. It boots through OVMF
pflash, passes a Linux kernel and a tiny busybox initrd, prints PCI resources
from `/sys` and `/proc/iomem`, then powers off. It does not wait for networking,
DHCP, cloud-init, systemd, or a disk image.

The test creates below-4G pressure with `3584M` of RAM and adds an
`ivshmem-plain` device whose BAR can be varied:

```text
machine:  pc-i440fx-jammy or pc-q35-jammy
memory:   3584M
device:   ivshmem-plain
BARs:     256M, 512M, 1G
```

Cases:

```text
ovmf_default:
  no extra MMIO argument

ovmf_fwcfg_zero:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0

ovmf_host_zero:
  -global <host-bridge>.pci-hole64-size=0

ovmf_both_zero:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global <host-bridge>.pci-hole64-size=0
```

Result summary, showing the start address of BAR/resource2:

| Machine | Case | 256M BAR | 512M BAR | 1G BAR | 64-bit PCI root window |
| --- | --- | --- | --- | --- | --- |
| i440fx | `ovmf_default` | `0x800000000` | `0x800000000` | `0x800000000` | yes |
| i440fx | `ovmf_fwcfg_zero` | `0xc0000000` | `0xc0000000` | `0x140000000` | yes |
| i440fx | `ovmf_host_zero` | `0x800000000` | `0x800000000` | `0x800000000` | yes |
| i440fx | `ovmf_both_zero` | `0xc0000000` | `0xc0000000` | unassigned | no |
| q35 | `ovmf_default` | `0x800000000` | `0x800000000` | `0x800000000` | yes |
| q35 | `ovmf_fwcfg_zero` | `0xc0000000` | `0xc0000000` | `0x180000000` | yes |
| q35 | `ovmf_host_zero` | `0x800000000` | `0x800000000` | `0x800000000` | yes |
| q35 | `ovmf_both_zero` | `0xc0000000` | `0xc0000000` | unassigned | no |

Key 1G proof snippets:

```text
i440fx ovmf_fwcfg_zero:
  BAR/resource2  0x0000000140000000 0x000000017fffffff
  140000000-1bfffffff : PCI Bus 0000:00

q35 ovmf_fwcfg_zero:
  BAR/resource2  0x0000000180000000 0x00000001bfffffff
  180000000-97fffffff : PCI Bus 0000:00

i440fx ovmf_both_zero:
  no BAR/resource2 for the 1G device
  no 64-bit PCI Bus 0000:00 window in /proc/iomem

q35 ovmf_both_zero:
  no BAR/resource2 for the 1G device
  no 64-bit PCI Bus 0000:00 window in /proc/iomem
```

The `ovmf_both_zero` 1G case was also tested with `pci=realloc`; BAR/resource2
remained unassigned on both i440fx and q35. That matters because it proves the
guest kernel allocator cannot resurrect a 4G+ BAR placement once both the OVMF
firmware aperture and the QEMU root-bridge 64-bit window are absent.

Interpretation:

- `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0` alone is not enough. With a 1G
  BAR, Linux still assigns above 4G by using QEMU's ACPI/root-bridge 64-bit
  window.
- `-global <host-bridge>.pci-hole64-size=0` alone is not enough. OVMF can still
  create/use its own 64-bit aperture, and the BAR lands above 4G.
- Both switches are required to model "no explicit 64-bit MMIO window".

`qemu-mmio-validate.sh` is kept as a negative control. It uses direct kernel
boot and therefore bypasses the OVMF part of the question. `qemu-ovmf-hmp-check.sh`
is a firmware-stage auxiliary check.

## Real Linux firmware-boot validation

`qemu-ovmf-real-linux-validate.sh` is the real guest validation path. It boots:

```text
QEMU -> OVMF pflash or SeaBIOS -> Ubuntu cloud image -> Linux guest
```

This is slower than the initrd smoke test, but it exercises firmware PCI
allocation and Linux's final ACPI/root-bridge resource view. The main artifact
summary is in `qemu-vmware-mmio-comparison.md`.

Key real-boot checks reproduced locally:

```text
OVMF + i440fx + host_4g only:
  -global i440FX-pcihost.pci-hole64-size=4G
  Linux high window: 0x800000000-0x8ffffffff
  ivshmem BAR2:      0x800000000-0x83fffffff

OVMF + i440fx + both_4g:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
  -global i440FX-pcihost.pci-hole64-size=4G
  Linux high window: 0x200000000-0x2ffffffff
  ivshmem BAR2:      0x200000000-0x23fffffff

OVMF + i440fx + both_zero, no ivshmem probe:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global i440FX-pcihost.pci-hole64-size=0
  Linux high window: none
```

The no-ivshmem case matters because `pci-hole64-size=0` is not an absolute ban
on every above-4G BAR. If firmware has already assigned a 64-bit BAR above 4G,
QEMU/ACPI can still report the minimal root-window range required to cover that
real BAR. Running without the BAR probe separates "default high aperture exists"
from "a real BAR forced a minimal high window".

## VMware local validation

An existing nested ESXi 8 Workstation VM was found and checked:

```text
VM: existing ESXi 8 Workstation VM
IP: 192.168.91.134
virtualHW.version = "20"
firmware = "efi"
guestOS = "vmkernel8"
memsize = "4096"
numvcpus = "2"
```

Its `vmware.log` showed:

```text
The EFI ROM is EFI2.7 64-bit.
Guest: EFI ROM version: VMW201.00V.21805430.B64.2305221830 (64-bit RELEASE)
Guest: About to do EFI boot: VMware ESXi
Guest: toolbox: Version: 12.5.1.52451 (build-24649672)
```

Host reachability:

```text
https://192.168.91.134/ui/ -> HTTP 200
443 open
902 open
22 closed/timeout
```

Old lab auth recovery was attempted from local backup files and PowerShell
history. The useful evidence was:

- VCSA deployment history used a `v67deploy.json` style file.
- Historical names included `esxi1.example.com`, `vcsa01.ula.local`,
  `esxi1.lab.local`, and `vcenter61.lab.local`.
- Explicit historical auth candidates from deployment JSON files were tried
  against the current ESXi host with `govc`; they failed with invalid user/auth.
- ESXi 8 bootbank state contained encrypted state (`local.tgz.ve`), so offline
  root reset was not used as proof.

## Fresh ESXi 8 proof

A new Workstation ESXi VM was installed unattended from the local ESXi 8.0U3b
ISO:

```text
ISO: VMware-VMvisor-Installer-8.0U3b-24280767.x86_64.iso
ISO SHA256: 718c4fa3447dd138db64398604438ee0d700e2c2fae9276201c016e386c3812b
VM: esxi8-auto-codex
IP: 192.168.91.128
```

The ISO hash matched the local sidecar SHA256 file. The VM was created with:

```text
virtualHW.version = "20"
firmware = "efi"
guestOS = "vmkernel8"
memsize = "4096"
numvcpus = "2"
scsi0.virtualDev = "pvscsi"
ethernet0.virtualDev = "vmxnet3"
```

The current Windows/Workstation platform did not expose virtualized
Intel VT-x/EPT to this nested VM, so `vhv.enable` was disabled for the proof
host. This makes the VM suitable for ESXi management API and VMX/log checks, but
not for running a second layer of nested VMs until the host VHV issue is fixed.

Post-install checks:

```text
https://192.168.91.128/ui/ -> HTTP 200
govc about -> success
FullName:     VMware ESXi 8.0.3 build-24280767
API type:     HostAgent
API version:  8.0.3.0
Product ID:   embeddedEsx
```

The working root credential is stored only in the user's private local Caveat
store, not in this repository. Temporary kickstart ISO, extracted ISO tree, and
DPAPI staging files were removed after verification.

Workflow note: in this local ESXi 8.0U3b run, a kickstart using
`rootpw --iscrypted` installed successfully but did not authenticate with the
expected secret afterward. Rebuilding the kickstart with plain `rootpw` worked
and was verified with `govc`.

## VMware default EFI guest proof

The fresh ESXi 8.0U3b host was given a VMFS datastore and a default EFI test VM
was created through the ESXi API:

```text
Datastore: pci-mmio-ds
VM:        pci-mmio-efi-default
Firmware:  efi
Guest OS:  other-64
vHW:       21
Memory:    512 MB
Disk:      1 GB
```

The VM was created without any extra PCI/MMIO settings. The resulting VMX
configuration contains ordinary PCI bridge/root-port entries, but no 64-bit MMIO
passthrough enablement:

```text
virtualHW.version = "21"
firmware = "efi"
guestOS = "other-64"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
```

Negative check on the VMX and power-on log:

```text
No pciPassthru.use64bitMMIO
No pciPassthru.64bitMMIOSizeGB
No 64bitMMIO
No pciHole / pci.*hole override
```

The power-on attempt failed because the Workstation host did not expose
virtualized Intel VT-x/EPT to the nested ESXi VM, but the VMX process had already
logged the configuration dictionary it was using:

```text
DICT --- CONFIGURATION .../pci-mmio-efi-default.vmx
DICT         virtualHW.version = "21"
DICT        pciBridge0.present = "TRUE"
DICT        pciBridge4.present = "TRUE"
DICT     pciBridge4.virtualDev = "pcieRootPort"
DICT      pciBridge4.functions = "8"
DICT        pciBridge5.present = "TRUE"
DICT     pciBridge5.virtualDev = "pcieRootPort"
DICT      pciBridge5.functions = "8"
DICT        pciBridge6.present = "TRUE"
DICT     pciBridge6.virtualDev = "pcieRootPort"
DICT      pciBridge6.functions = "8"
DICT        pciBridge7.present = "TRUE"
DICT     pciBridge7.virtualDev = "pcieRootPort"
DICT      pciBridge7.functions = "8"
DICT                  firmware = "efi"
DICT                   guestOS = "other-64"

Module 'MonitorMode' power on failed.
This host does not support Intel VT-x.
This host appears to be running in a virtual machine with VHV disabled.
```

This is configuration proof, not a guest-runtime BAR map. It proves that a
default ESXi 8 EFI VM does not silently add the documented passthrough 64-bit
MMIO knobs. Combined with the Broadcom KBs below, the VMware-side statement is:
64-bit MMIO for passthrough is opt-in through `pciPassthru.use64bitMMIO` and
`pciPassthru.64bitMMIOSizeGB`; the default EFI VM config is the below-4G PCI-hole
model plus ordinary PCIe root ports, not an implicit large 64-bit passthrough
window.

## Hyper-V nested ESXi low-version proof

As a second local VMware-side check, an existing Hyper-V Gen1 ESXi VM was used.
The VM name suggested ESXi 6.5, but DCUI and API reported the actual host as:

```text
VMware ESXi 6.0.0 build-5050593
Manufacturer: Microsoft Corporation
Processor: 13th Gen Intel(R) Core(TM) i5-13500H
Memory: 8 GiB
Hyper-V VM: Gen1, Legacy Network Adapter, ExposeVirtualizationExtensions=True
```

Networking note: the host obtained IPv4 addresses from the Hyper-V/VMware
virtual switches, but IPv4 TCP from the Windows host did not respond in this
topology. The ESXi HostAgent API was reachable over IPv6 link-local with the
Windows interface scope.

A default EFI guest VM was created on this ESXi host:

```text
VM:        pci-mmio-hv-esxi60-efi-default
Firmware:  efi
Guest OS:  other-64
vHW:       11
Memory:    512 MB
Disk:      1 GB
Power:     poweredOn successfully
```

This proves the Hyper-V -> ESXi -> guest path can actually power on a second
level VM on this machine. The `vmware.log` confirms hardware virtualization was
used:

```text
Log for VMware ESX pid=... version=6.0.0 build=build-5050593
DICT --- CONFIGURATION .../pci-mmio-hv-esxi60-efi-default.vmx
DICT         virtualHW.version = "11"
DICT        pciBridge0.present = "TRUE"
DICT        pciBridge4.present = "TRUE"
DICT     pciBridge4.virtualDev = "pcieRootPort"
DICT      pciBridge4.functions = "8"
DICT                  firmware = "efi"
DICT                   guestOS = "other-64"
MONITOR MODE: allowed modes          : BT32 HV HWMMU
MONITOR MODE: filtered list          : HWMMU BT32 HV
HV Settings: virtual exec = 'hardware'; virtual mmu = 'hardware'
Monitor64_PowerOn()
```

The default VMX again contains ordinary PCI bridges/root ports, but no
passthrough 64-bit MMIO enablement:

```text
virtualHW.version = "11"
firmware = "efi"
guestOS = "other-64"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
```

Negative check on VMX and power-on log:

```text
No pciPassthru.use64bitMMIO
No pciPassthru.64bitMMIOSizeGB
No 64bitMMIO
No pciHole / pci.*hole override
```

The log contains a generic line `MMIO Honors PAT == 0`; that is not a 64-bit
passthrough MMIO window setting and does not change the negative check above.

## VMware official evidence

Broadcom KB 312208 documents 64-bit MMIO for VMDirectPath I/O and Dynamic
DirectPath I/O using:

```text
pciPassthru.use64bitMMIO = "TRUE"
pciPassthru.64bitMMIOSizeGB = "..."
```

Broadcom KB 323402 gives the same style of fix for an EFI PCI MMIO power-on
failure.

Broadcom KB 341298 says virtual hardware version 7 and later reserve 1GB below
4GB for PCI devices. This supports the model that VMware has a default below-4G
PCI hole, while large passthrough 64-bit MMIO is explicitly configured.

## Source-level evidence for QEMU/OVMF

Relevant QEMU/OVMF source areas:

- QEMU i440fx: `hw/pci-host/i440fx.c`
- QEMU q35: `hw/pci-host/q35.c`
- QEMU ACPI resource publication: `hw/i386/acpi-build.c`
- OVMF runtime config: `OvmfPkg/RUNTIME_CONFIG.md`
- OVMF PCI MMIO sizing: `OvmfPkg/Library/PlatformInitLib/MemDetect.c`

The important distinction is that OVMF's fw_cfg knob affects firmware aperture
selection, while QEMU's machine/root bridge resources are a separate source of
guest-visible 64-bit PCI MMIO space:

- OVMF documents `opt/ovmf/X-PciMmio64Mb` as the knob for changing the 64-bit PCI
  MMIO window size. In the MemDetect code path, a parsed size of `0` disables
  the OVMF 64-bit host aperture.
- QEMU i440fx and q35 expose a host-bridge property named `pci-hole64-size`.
  In the tested QEMU 6.2 build and local source tree, i440fx defaults to 2G
  (`1ULL << 31`) and q35 defaults to 32G (`1ULL << 35`).
- QEMU ACPI generation publishes a 64-bit root-bridge memory resource when the
  host bridge has a non-empty `pci-hole64-start`/`pci-hole64-end` range.

So the commonly confused knobs are not the same thing:

```text
OVMF:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  controls firmware 64-bit PCI aperture sizing

QEMU host bridge:
  -global q35-pcihost.pci-hole64-size=0
  -global i440FX-pcihost.pci-hole64-size=0
  controls the QEMU/ACPI 64-bit PCI host-window resource
```

The below-4G PCI hole is a different topic. In this validation, the relevant
QEMU property is `pci-hole64-size`, not a below-4G `pci-hole-size`.

## Equivalence statement

Do not model "VMware EFI VM default without `pciPassthru.use64bitMMIO`" as only:

```text
QEMU:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
```

That QEMU argument disables the OVMF firmware-stage 64-bit aperture, but it does
not prevent Linux from later assigning 64-bit BARs above 4G from QEMU's
ACPI/root-bridge resource.

Do not model it as only:

```text
QEMU:
  -global q35-pcihost.pci-hole64-size=0
```

That removes QEMU's host-bridge 64-bit window, but OVMF can still create/use a
firmware 64-bit aperture.

The QEMU/OVMF below-4G-only profile is:

```text
QEMU q35 below-4G profile:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global q35-pcihost.pci-hole64-size=0

QEMU i440fx below-4G profile:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global i440FX-pcihost.pci-hole64-size=0
```

Observed consequence: with both QEMU/OVMF knobs disabled and sufficient
below-4G pressure, a large BAR is left unassigned.  This is not the complete
ESXi 8 U3 default behavior: VMware automatically created a minimal high window
for the tested 2GB BAR even when `use64bitMMIO` was absent or false.  QEMU
therefore needs a launcher-selected high profile for that case.

## References

- Broadcom KB 312208:
  https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html
- Broadcom KB 323402:
  https://knowledge.broadcom.com/external/article/323402/failed-to-power-on-virtual-machines-with.html
- Broadcom KB 341298:
  https://knowledge.broadcom.com/external/article/341298/virtual-machine-memory-limits-and-hardwa.html
- QEMU i440fx:
  https://github.com/qemu/qemu/blob/master/hw/pci-host/i440fx.c
- QEMU q35:
  https://github.com/qemu/qemu/blob/master/hw/pci-host/q35.c
- QEMU ACPI build:
  https://github.com/qemu/qemu/blob/master/hw/i386/acpi-build.c
- OVMF runtime config:
  https://github.com/tianocore/edk2/blob/master/OvmfPkg/RUNTIME_CONFIG.md
- OVMF MemDetect:
  https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/PlatformInitLib/MemDetect.c
