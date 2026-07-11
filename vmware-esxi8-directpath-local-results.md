# ESXi 8 VMDirectPath local black-box results

Date: 2026-07-11

This document supersedes the earlier assumption that an EFI VM without
`pciPassthru.use64bitMMIO` always behaves as a below-4G-only machine.  The
runtime tests below used active passthrough devices and a booted EFI Linux
guest, rather than inferring behavior from an ordinary VMX file.

## Lab shape

```text
WSL2 Linux / QEMU 6.2 / KVM
  -> ESXi 8.0.3 build 24280767
    -> vHW 20 EFI Linux guest
```

The outer QEMU machine used q35, split irqchip, virtual VT-d with interrupt
remapping, two multifunction QEMU e1000e functions, and an optional ivshmem
64-bit prefetchable BAR.  ESXi reported all three test functions as DirectPath
capable when they were below a PCIe root port.

The L3 VM originally failed with VM-entry error 7.  It booted reliably after
masking only VMX TSC scaling from the outer CPU:

```bash
-cpu host,+vmx,-vmx-tsc-scaling
```

A newer WSL kernel and QEMU remain useful for missing device models and event
injection, but were not required to boot the nested DirectPath guest.

## Default MMIO result

The decisive variable was the real BAR requirement, not the presence of the
historical VMX settings.

| BAR presented by outer QEMU | VMX setting | EFI guest result |
| --- | --- | --- |
| e1000e 32-bit BARs only | absent, false, true, true+Size4, or Size4 only | no above-4G window |
| 1GB 64-bit prefetchable BAR | same five variants | BAR at `0x80000000-0xbfffffff`; no above-4G window |
| 2GB 64-bit prefetchable BAR | same five variants | BAR and root window at `0x1fff80000000-0x1fffffffffff` |

For the 1GB case, the physical BAR reported by ESXi was
`0x800000000-0x83fffffff`, but VMware remapped it below 4G in the guest.  For
the 2GB case, VMware automatically created a high window even when:

```text
pciPassthru.use64bitMMIO = "FALSE"
```

It produced the same high address when the key was absent, true, true with
`64bitMMIOSizeGB=4`, or when only `64bitMMIOSizeGB=4` was present.  On this ESXi
8 U3 build and device path, those settings did not override the allocator's
placement decision or force a 4GB aperture.

This does not make the documented settings meaningless for every ESXi version,
device, or aggregate BAR size.  It proves that absence or false is not a
below-4G guarantee on the tested current build.

## QEMU comparison

The matching q35/OVMF 2GB BAR tests produced:

| QEMU profile | Guest result |
| --- | --- |
| QEMU/OVMF defaults | BAR at `0x800000000`; 32GB high root window |
| `X-PciMmio64Mb=0` plus `pci-hole64-size=0` | BAR2 unassigned; no high window |
| `X-PciMmio64Mb=2048` plus `pci-hole64-size=2G` | BAR and 2GB window at `0x180000000-0x1ffffffff` |

Therefore no single fixed pair of stock QEMU 6.2/OVMF knobs reproduces both
VMware default outcomes:

- A 1GB 64-bit BAR is placed below 4G without publishing a high window.
- A 2GB 64-bit BAR automatically receives a minimal high window.

The practical QEMU alignment is a launcher policy, not one unconditional
command line:

1. Inspect every assigned function's BAR size, type, alignment, and bridge
   dependency before starting QEMU.
2. If the complete layout fits the intended below-4G hole, set both OVMF and
   host-bridge high apertures to zero.
3. Otherwise choose a high aperture that covers the aligned aggregate BAR
   envelope, and set both controls to the same size.

For the tested 2GB case:

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=2048
-global q35-pcihost.pci-hole64-size=2G
```

This matches high/low classification and aperture size, but not VMware's exact
high address.  Stock q35 placed the window above RAM, while VMware placed it at
the top of the guest's 45-bit physical address space.  Exact base-address
equivalence requires allocator/firmware changes or a different machine model.

## Topology and eligibility

| Test | ESXi 8.0 U3 observation |
| --- | --- |
| PCIe root port baseline | e1000e and ivshmem capable; `Bridge reset` |
| Same-slot functions | ESXi managed functions independently on the normal PCIe path |
| Root-complex direct endpoint | `Reset Method=None`, `Passthru Capable=false` |
| Legacy PCI bridge | every endpoint used the bridge `01:00.0` as `Dependent Device` |
| Enable one legacy-bridge endpoint | ESXi automatically switched every endpoint behind the bridge to `VM Passthru` |
| Root port with ACS removed | ESXi logged `Bypassing non-ACS capable device in hierarchy` but still allowed passthrough |
| Outer link constrained to 8GT/s x4 | L1 endpoint was 2.5GT/s x1; VMware presented L2 as 5GT/s x32 |

The no-ACS result is a nested-platform exception, not a safe QEMU recipe.  This
ESXi boot had `enableACSCheckForRP=FALSE`; Broadcom KB 312208 still requires ACS
for production isolation.

The link test shows that VMware reconstructs guest-visible PCIe capability.  A
QEMU replacement that needs the same presentation must set the guest root-port
and/or VFIO capability policy explicitly; copying host link width is not enough.

## DMA, interrupts, reset, and lifecycle

The L3 initrd loaded e1000e, sent traffic, received traffic, and reported three
PCI-MSI vectors.  The outer trace captured all of the following in the same VM
run:

```text
vtd_iotlb_page_update ... sid 0x100 ... domain 0x2
vtd_dmar_translate dev 01:00.00 iova ... -> gpa ...
e1000e_irq_msix_notify_vec ...
vtd_ir_remap_msi ... -> ...
```

This is direct evidence that ESXi programmed DMA translation and interrupt
remapping for the assigned requester ID.  Power cycles also caused domain-2
IOTLB invalidations.

Reset evidence is intentionally narrower.  ESXi advertised `Bridge reset`, and
the device survived normal and forced power cycles, but QEMU emitted no
`qdev_reset*` or e1000e qdev-reset event during the tested L2 cycles.  Actual
bridge-reset execution is therefore not proven in this nested device model.

Lifecycle results:

| Operation | Result |
| --- | --- |
| Snapshot while powered on | rejected with `vim.fault.InvalidState` |
| Suspend while powered on | rejected with `vim.fault.InvalidState` |
| Forced power-off after real I/O | succeeded |
| Immediate restart after forced power-off | succeeded |
| Ten short start/forced-stop cycles | all ten passed on/off state checks |
| vMotion | not testable with one standalone host |

## Dynamic DirectPath

`HostAssignableHardwareManager.RetrieveDynamicPassthroughInfo()` returned one
candidate class for e1000e and one for ivshmem.  A VM was then configured
through the vSphere API with two identical e1000e `allowedDevice` entries and
one ivshmem entry.

Observed state transition:

```text
powered off:
  assignedId = null, null, null

powered on:
  assignedId = 0000:01:00.1, 0000:01:00.0, 0000:01:01.0

powered off again:
  assignedId = null, null, null
```

The persistent VMX contained only:

```text
pciPassthru0.allowedDevices = "0x8086:0x10d3"
pciPassthru1.allowedDevices = "0x8086:0x10d3"
pciPassthru2.allowedDevices = "0x1af4:0x1110"
```

QEMU has no equivalent internal BDF selector for ordinary VFIO.  Match this by
using an external launcher that selects distinct eligible BDFs, validates their
IOMMU/reset dependencies and BAR envelope, records the assignments, then emits
the final `vfio-pci,host=` devices.  Selection state belongs outside the guest
machine description.

## Other KB details

| KB topic | Local result |
| --- | --- |
| Expansion ROM default | outer e1000e had a ROM BAR; VMware did not expose a ROM BAR for the passthrough functions |
| Enabled option ROM execution | not run; requires `pcipSaveOPROM` reboot plus a validated ROM |
| PME virtualization | not run; stock endpoint path did not provide controlled PME injection |
| PCI/AER errors | QEMU correctable injection works, but this ESXi boot had PCI error reporting disabled; host-vs-guest ownership was not provable |
| P2P DMA | not run; requires two active peer-DMA endpoints |
| RMRR | not run; virtual DMAR had no controlled RMRR entry |
| SR-IOV PF/VF | not run; no SR-IOV endpoint in this topology |
| Physical reset and electrical isolation | requires bare metal and a real supported device |

These are platform-blocked or endpoint-blocked results, not inferred passes.

## Reproduction

The reusable lab scripts are under `vmware-esxi8-lab/`.  Generated ISO images,
VM disks, credentials, and multi-megabyte traces are deliberately not committed.
Local evidence was retained under `_artifacts/vmware-directpath-runs/` and
`_artifacts/mmio-tests/` in the source workspace.

Primary references:

- [Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [VirtualPCIPassthrough DynamicBackingInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html)
- [Host AssignableHardwareManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html)
