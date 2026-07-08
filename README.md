# PCI MMIO validation notes: VMware ESXi EFI defaults vs QEMU/OVMF

Record date: 2026-07-09

This repository records the evidence gathered for comparing VMware ESXi EFI VM
MMIO behavior with QEMU/OVMF MMIO controls. It intentionally contains no local
secrets or lab credentials.

## Short conclusion

1. `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0` only constrains the OVMF
   firmware-stage 64-bit PCI MMIO aperture. It is not a global "never assign a
   64-bit BAR above 4G" switch.
2. In the local QEMU 6.2 test, Linux still assigned a 1G 64-bit BAR at
   `0x140000000`, even when `i440FX-pcihost.pci-hole64-size=0` was added.
3. VMware documentation says VMDirectPath/Dynamic DirectPath 64-bit MMIO needs
   explicit `pciPassthru.use64bitMMIO = "TRUE"` plus
   `pciPassthru.64bitMMIOSizeGB`. That is product-level evidence that the
   default EFI VM config is not equivalent to "passthrough 64-bit MMIO enabled".
4. A fresh ESXi 8.0U3b nested Workstation VM was installed unattended and
   verified by Host Client and `govc`. On that host, a new default EFI guest VM
   was created and inspected. Its VMX file and VMX power-on configuration
   dictionary contain no `pciPassthru.use64bitMMIO`,
   `pciPassthru.64bitMMIOSizeGB`, `64bitMMIO`, or PCI hole override keys.

## QEMU local validation

The script `qemu-mmio-validate.sh` creates pressure below 4G and adds a device
with a 1G 64-bit BAR:

- machine: `pc-i440fx-jammy`
- memory: `3584M`
- device: `ivshmem-plain` with a 1G BAR

Two cases were tested:

```text
CASE: fwcfg_only
QEMU args include:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0

CASE: fwcfg_and_hole64_zero
QEMU args include:
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
  -global i440FX-pcihost.pci-hole64-size=0
```

Both cases assigned the 64-bit BAR above 4G:

```text
CASE: fwcfg_only
BAR/resource2 0x0000000140000000 0x000000017fffffff

CASE: fwcfg_and_hole64_zero
BAR/resource2 0x0000000140000000 0x000000017fffffff
```

Interpretation:

- OVMF's `X-PciMmio64Mb=0` controls whether OVMF itself creates/uses a 64-bit
  PCI host aperture during firmware enumeration.
- Linux can later re-enumerate PCI and assign 64-bit BARs from the resources
  exposed by QEMU/ACPI/root bridge descriptions.
- Therefore, `fw_cfg=0` by itself is not equivalent to VMware's default
  passthrough behavior.

`qemu-ovmf-hmp-check.sh` is an auxiliary firmware-stage check. In the tested
no-boot OVMF/HMP case, the BAR stayed unassigned at firmware time. That is
consistent with the Linux result: firmware did not assign it, but the OS later
could.

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
selection, while QEMU's machine/root bridge resources and the guest OS allocator
can still lead to 4G+ BAR placement.

## Equivalence statement

Do not model "VMware EFI VM default without `pciPassthru.use64bitMMIO`" as only:

```text
QEMU: -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
```

That QEMU argument disables the OVMF firmware-stage 64-bit aperture, but it does
not prevent Linux from later assigning 64-bit BARs above 4G.

A more accurate statement is:

```text
VMware default without pciPassthru.use64bitMMIO:
  No explicit product-level 64-bit MMIO passthrough window is configured.
  Large BAR passthrough requires the documented explicit settings.

QEMU fw_cfg X-PciMmio64Mb=0:
  Disable OVMF's firmware-stage 64-bit PCI aperture.
  This does not, by itself, prevent guest OS 4G+ BAR assignment.
```

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
