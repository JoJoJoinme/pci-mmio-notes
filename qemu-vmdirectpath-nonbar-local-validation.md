# QEMU VMDirectPath non-BAR local validation

Date: 2026-07-10

This note records what was locally verified for mapping Broadcom KB 312208
VMDirectPath behavior to QEMU/VFIO, beyond BAR sizing. It separates:

- QEMU/OVMF behavior that was actually boot-tested locally.
- QEMU device properties that were locally confirmed with `-device ...,help`.
- Real physical VFIO / ESXi passthrough behavior that this WSL2 host cannot
  prove.

Primary references:

- Broadcom KB 312208, "vSphere VMDirectPath I/O and Dynamic DirectPath I/O".
- QEMU system invocation documentation.
- Local artifacts under `_artifacts/mmio-tests/nonbar-local/`.

## Local environment

QEMU:

```text
QEMU emulator version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.30)
```

Host evidence from `host-vfio-limits.sh`:

```text
Linux helious 5.15.150.1-microsoft-standard-WSL2+
/dev/vfio/vfio exists
/sys/kernel/iommu_groups count: 0
```

The visible host PCI devices are only Hyper-V / virtio synthetic devices:

```text
4340:00:00.0 vendor=0x1414 device=0x008e class=0x030200
4c7b:00:00.0 vendor=0x1af4 device=0x105a class=0x088000
5582:00:00.0 vendor=0x1af4 device=0x1043 class=0x010000
```

Therefore this host can validate QEMU guest-visible PCIe, OVMF, ACPI, and
vIOMMU behavior, but it cannot validate real physical `vfio-pci,host=BDF`
assignment.

## Commands added for reproducibility

```bash
# Guest-visible PCIe/root-port/vIOMMU checks.
bash ./qemu-nonbar-local-validate.sh

# Host limitation proof.
bash ./host-vfio-limits.sh

# Device property inventory.
qemu-system-x86_64 -device vfio-pci,help
qemu-system-x86_64 -device pcie-root-port,help
qemu-system-x86_64 -device intel-iommu,help
```

The main full-matrix log was:

```text
_artifacts/mmio-tests/nonbar-local/qemu-nonbar-local-final.log
```

## Verified locally

### 1. q35 plus explicit root port gives the expected PCIe topology

The default case used:

```bash
-machine q35,accel=kvm:tcg
-device pcie-root-port,id=rp1,chassis=1,slot=1
-device e1000e,netdev=n0,bus=rp1,addr=00.0
```

Guest evidence:

```text
00:01.0 PCI bridge: Red Hat, Inc. QEMU PCIe Root port [1b36:000c]
01:00.0 Ethernet controller: Intel Corporation 82574L [8086:10d3]
```

This supports using `q35` plus explicit `pcie-root-port` as the QEMU baseline
for VMware EFI / PCIe DirectPath comparisons.

### 2. QEMU's default q35 high PCI MMIO root window is guest-visible

In the same default q35 case, Linux saw an above-4G root resource:

```text
pci_bus 0000:00: root bus resource [mem 0x100000000-0x8ffffffff window]
```

The root port also received an above-4G 64-bit prefetchable bridge window:

```text
pci 0000:00:01.0: BAR 15: assigned [mem 0x100000000-0x1001fffff 64bit pref]
```

This is consistent with the earlier OVMF BAR tests: setting only OVMF
`X-PciMmio64Mb=0` is not enough to model VMware's default "no explicit 64-bit
passthrough MMIO aperture" condition. QEMU's host bridge can still publish a
high root window unless `pci-hole64-size=0` is also set.

VMware-default-style QEMU/OVMF therefore remains:

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global q35-pcihost.pci-hole64-size=0
```

### 3. Guest-visible PCIe link capability is controllable

Default root port:

```text
LnkCap: Speed 16GT/s, Width x32
max_link_speed=16.0 GT/s PCIe
max_link_width=32
```

With:

```bash
-device pcie-root-port,id=rp1,chassis=1,slot=1,x-speed=8,x-width=4
```

Guest evidence changed to:

```text
LnkCap: Speed 8GT/s, Width x4
max_link_speed=8.0 GT/s PCIe
max_link_width=4
```

So if a VMware guest-visible PCIe link presentation matters for a comparison,
QEMU can model that at the root-port level. This is a presentation/topology
match; it does not prove physical link speed for a real VFIO device.

### 4. Guest-visible ACS capability is controllable on QEMU root ports

Default root port exposed ACS:

```text
ACSCap: SrcValid+ TransBlk+ ReqRedir+ CmpltRedir+ UpstreamFwd+ ...
ACSCtl: SrcValid- TransBlk- ReqRedir- CmpltRedir- UpstreamFwd- ...
```

With:

```bash
-device pcie-root-port,id=rp1,chassis=1,slot=1,disable-acs=on
```

The selected `lspci -vv` output no longer contained `ACSCap` / `ACSCtl` for
the QEMU root port.

Important boundary: this only validates guest-visible QEMU root-port ACS
presentation. It does not replace the real host ACS / IOMMU-group requirement
for physical passthrough.

### 5. Guest-visible virtual IOMMU and interrupt remapping work with split irqchip

The working QEMU shape was:

```bash
-machine q35,accel=kvm:tcg,kernel_irqchip=split
-device intel-iommu,intremap=on,caching-mode=on
```

The Linux guest also needs `intel_iommu=on` to populate IOMMU groups in this
test kernel.

Guest evidence:

```text
DMAR: IOMMU enabled
DMAR-IR: Queued invalidation will be enabled to support x2apic and Intr-remapping.
DMAR-IR: Enabled IRQ remapping in x2apic mode
pci 0000:00:01.0: Adding to iommu group 1
pci 0000:01:00.0: Adding to iommu group 3
```

Guest `/sys/kernel/iommu_groups` contained:

```text
/sys/kernel/iommu_groups/1/devices/0000:00:01.0
/sys/kernel/iommu_groups/3/devices/0000:01:00.0
```

Negative control:

```text
-device intel-iommu,intremap=on,caching-mode=on:
Interrupt Remapping cannot work with kernel-irqchip=on, please use 'split|off'.
```

Conclusion: guest vIOMMU exposure is a separate QEMU feature. It is not the same
thing as the host IOMMU isolation that makes VFIO safe.

### 6. MSI/MSI-X and reset inspection paths work in the guest

The emulated e1000e endpoint exposed MSI and MSI-X capabilities:

```text
Capabilities: [d0] MSI: Enable- Count=1/1 Maskable- 64bit+
Capabilities: [a0] MSI-X: Enable- Count=5 Masked-
```

The emulated endpoint also showed:

```text
reset_method=pm bus
```

This proves the inspection method, not physical-device reset safety. For real
VFIO, reset must be checked on the host at `/sys/bus/pci/devices/BDF/reset` and
`reset_method`, and then validated by repeated VM start/stop cycles.

### 7. Relevant QEMU knobs exist locally

Confirmed from local `-device ...,help`:

```text
vfio-pci:
  host=<str>
  sysfsdev=<str>
  rombar=<uint32>
  x-no-kvm-intx=<bool>
  x-no-kvm-msi=<bool>
  x-no-kvm-msix=<bool>
  x-nv-gpudirect-clique=<uint4>
  x-pcie-extcap-init=<bool>

pcie-root-port:
  disable-acs=<bool>
  hotplug=<bool>
  power_controller_present=<bool>
  x-native-hotplug=<bool>
  x-speed=<PCIELinkSpeed>
  x-width=<PCIELinkWidth>

intel-iommu:
  aw-bits=<uint8>
  caching-mode=<bool>
  device-iotlb=<bool>
  intremap=<OnOffAuto>
  pt=<bool>
```

This establishes that the proposed QEMU mapping uses actual local QEMU
properties, not invented flags.

## Not locally verifiable on this host

The current WSL2 host has no real IOMMU groups and no assignable physical PCI
device. These remain unverified locally:

- Real `-device vfio-pci,host=BB:DD.F` passthrough.
- Host IOMMU programming for physical DMA isolation.
- Physical ACS isolation and VFIO group correctness.
- FLR / PM reset / bus reset safety for a real device.
- RMRR or other firmware-reserved DMA region constraints.
- Physical MSI/MSI-X interrupt remapping security and delivery.
- SR-IOV VF/PF behavior.
- P2P DMA / GPUDirect behavior.
- Physical option ROM execution or suppression.
- PCI NUMA locality and DMA latency.
- Suspend, snapshot, live migration, and device state lifecycle behavior.

Those require a bare-metal Linux/VFIO host or a real ESXi host with an assignable
passthrough device.

## QEMU alignment for KB 312208 non-BAR details

The practical QEMU baseline for VMware default-style DirectPath is:

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

Use this unless the VMware case explicitly enables 64-bit passthrough MMIO. For
an explicit VMware `pciPassthru.64bitMMIOSizeGB=N` case, change both QEMU knobs:

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=$((N * 1024))
-global q35-pcihost.pci-hole64-size=${N}G
```

Do not add guest-visible vIOMMU unless the VMware comparison target exposes one.
If it does, add:

```bash
-machine q35,accel=kvm,kernel_irqchip=split
-device intel-iommu,intremap=on,caching-mode=on
```

Mapping summary:

| KB / VMware topic | QEMU alignment | Local status |
| --- | --- | --- |
| 64-bit MMIO aperture | Pair `X-PciMmio64Mb` with `q35-pcihost.pci-hole64-size` | Verified by earlier OVMF BAR tests; default q35 high window also observed here |
| PCIe topology | `q35` plus explicit `pcie-root-port` | Verified |
| Link presentation | `pcie-root-port,x-speed=...,x-width=...` | Verified |
| Guest-visible ACS capability | `pcie-root-port,disable-acs=on/off` | Verified for QEMU presentation only |
| Host ACS / IOMMU isolation | Real hardware grouping plus `vfio-pci` binding | Not verifiable on WSL2 |
| Guest virtual IOMMU | `intel-iommu,intremap=on,caching-mode=on` with split irqchip | Verified |
| Host interrupt remapping | BIOS/host IOMMU prerequisite; keep VFIO defaults | Not verifiable on WSL2 |
| Option ROM | Usually `rombar=0`; use `romfile=` only when modeling enabled ROM | Property confirmed; physical ROM not verified |
| Hotplug / PME / power controller | Root-port `hotplug=`, `x-native-hotplug=`, `power_controller_present=` | Properties confirmed; behavior not fully exercised |
| Reset | Host `/sys/.../reset_method`, assign all affected functions | Inspection path shown; physical reset not verified |
| SR-IOV | Prefer host-created VF BDFs assigned through `vfio-pci` | Not verifiable on WSL2 |
| NUMA locality | Pin memory/vCPU near PCI device NUMA node | Not verifiable on WSL2 |
| Lifecycle limitations | Treat ordinary VFIO like classic DirectPath: non-migratable unless proven | Not verifiable on WSL2 |

## Bottom line

For the VMware default DirectPath scenario described by KB 312208, QEMU should
not be modeled as "OVMF only". Use q35/OVMF plus both MMIO controls set to zero,
explicit PCIe root ports, and no guest vIOMMU unless that VMware VM setting is
also present.

The local machine verifies the QEMU side of this mapping for firmware/root-window
MMIO, PCIe topology, root-port ACS presentation, link presentation, and guest
vIOMMU. It does not verify real physical VFIO passthrough because the WSL2 host
has no real IOMMU groups.
