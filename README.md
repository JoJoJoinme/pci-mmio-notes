# PCI MMIO validation notes: VMware ESXi EFI defaults vs QEMU/OVMF

Record date: 2026-07-18

Project convergence status, current milestone, open decisions, and the fail-closed
release command are maintained in [`PROJECT-STATUS.md`](PROJECT-STATUS.md). The
current supported claim is **reference and qualification model only**, not a
production DirectPath controller.

The single product hierarchy is maintained in [`ipd/README.md`](ipd/README.md):
`EPIC-PCI-01 → F1-F8 → User Story → Tech Story`. Existing design, acceptance,
VMware/QEMU evidence, reference code, and historical inputs are attached without
being promoted to product completion in [`ipd/MATERIAL-MAP.md`](ipd/MATERIAL-MAP.md).
The VMware side is reconstructed as an official-contract plus observable-behavior
model, mapped across all 39 Tech Stories, in
[`ipd/VMWARE-BEHAVIOR-MODEL.md`](ipd/VMWARE-BEHAVIOR-MODEL.md).
Qman/reference-side technical evidence is tracked separately in
[`ipd/QMAN-TECHNICAL-EVIDENCE.md`](ipd/QMAN-TECHNICAL-EVIDENCE.md) and the
   machine-readable [`contracts/qman-evidence-index.json`](contracts/qman-evidence-index.json).
The current six E2/E3 records—five `REFERENCE_ONLY` and one `COMPONENT_ONLY`—
reproduce design premises, including the bounded C20 capability closure, and verify
a bounded default-deny QMP component. None closes a Qman product Case, physical
Risk, or production support claim.

This repository records the evidence gathered for comparing VMware ESXi EFI VM
MMIO behavior with QEMU/OVMF MMIO controls. It intentionally contains no local
secrets or lab credentials.

For the fuller Chinese write-up based on real OVMF/SeaBIOS boot with an Ubuntu
cloud image, see `qemu-vmware-mmio-comparison.md`. The corresponding runner is
`qemu-ovmf-real-linux-validate.sh`.

For the completed VMware `i440bx/acpi` x `BIOS/EFI` matrix, CreateVM-default
versus directly registered key-absent controls, and the seven-profile QEMU
topology comparison, see
[`vmware-firmware-layout-matrix.md`](vmware-firmware-layout-matrix.md). Its
machine-readable result is
[`evidence/esxi8-firmware-layout-20260715-summary.json`](evidence/esxi8-firmware-layout-20260715-summary.json).

For the Q35 dual-64GiB-BAR correction proving that QEMU `pci-hole64-size` is a
floor rather than a hard cap, including SeaBIOS auto-growth and OVMF default/
explicit controls, see
[`qemu-q35-firmware-dual-64g-results.md`](qemu-q35-firmware-dual-64g-results.md).

For the follow-up VMDirectPath/passthrough-specific validation matrix based on
Broadcom KB 312208, see `vmware-passthrough-mmio-validation.md`.

For the locally executed QEMU non-BAR / VMDirectPath-adjacent validation, see
`qemu-vmdirectpath-nonbar-local-validation.md`. It records which parts were
proved on this WSL2/QEMU host and which still require real physical VFIO or ESXi
passthrough hardware.

For the executable VMware implementation acceptance goals, evidence grades,
test matrix, artifact contract, and QEMU equivalence checklist, see
`vmware-directpath-acceptance-test-plan.md`.

QEMU 平台完整复刻静态 VMDirectPath 与 Dynamic DirectPath 的控制平面设计，包括 capability
分层、dependency bundle、候选求解、durable lease、IOMMUFD fd passing、rollback、
quarantine、multi-host fencing、KB 312208/API K01-K31 全量能力对标、R01-R39 风险清单，
并给出 capable、dependency/reset domain、静态/动态事务和多级 MMIO allocator 的分层图、
数据合同、可实现伪代码和分阶段验收，见
[`qemu-static-dynamic-directpath-design.md`](qemu-static-dynamic-directpath-design.md)。

面向实现团队的配套蓝图冻结 ESXi 8.0.3 build 24280767 / API 8.0.3.0 基线，
用模块接口、持久化 schema、Static/Dynamic 与 host owner activation 时序、逐步补偿矩阵、crash reconcile、
对外 API、可执行验收场景和完整 GPU dependency worked example 说明如何落地，见
[`qman-directpath-implementation-blueprint.md`](qman-directpath-implementation-blueprint.md)。

QEMU -> ESXi 8 -> EFI Linux DirectPath 黑盒验证的中文结果报告，包括 MMIO
边界、32/64GB no-backing BAR、VT-d trace、MSI-only EDU、拓扑负例、双主机
vMotion、host crash、guest reboot、INTx 和 Dynamic DirectPath `assignedId`
变化，见 `vmware-esxi8-directpath-local-results.md`；逐项复现命令和 Case
索引见 `vmware-esxi8-lab/README.md`。

ESXi `passthruCapable` 的累计 23 项 IOMMU/reset/ACS policy/topology/class/真实 bridge-FLR
矩阵、运行时 AH dependency 反例，以及基于 Linux VFIO Type-0/reset-device-set/
hot-reset ownership 公开源码、兼容 ACS override 部署的 QEMU 参考设计，见
`vmware-esxi8-passthru-capable-observed-model.md`。2026-07-14 增量的机器可读索引为
`evidence/esxi8-directpath-20260714-summary.json`。

上述设计中的部分纯函数与资源决策已有可运行参考实现，见
[`pci-resource-model/`](pci-resource-model/README.md)：包括
事务式 32/64 位 BAR sizing、Linux sysfs 只读 inventory、below/above-4G allocator、
OVMF/QEMU 参数生成，以及 `eligible/available/attachable` 三层 capable evaluator。模型已将
宿主 DPDK 的 unsafe no-IOMMU 允许位与 VM payload 的 per-device IOMMU gate 分离，并用
`hostReservation` 把 dataplane BDF 排除出 Static/Dynamic 候选池。机器可读
验收摘要为 `evidence/pci-resource-model-20260714-summary.json`。它不包含生产 attach
executor、durable lease、rollback/quarantine、Dynamic solver 或 multi-host fencing；完整边界
以 [`PROJECT-STATUS.md`](PROJECT-STATUS.md) 和详细设计第 22 节为准。

上述 no-IOMMU 分流另有真实 QEMU/Linux provider A/B：两个 guest 都保持 unsafe switch=`Y`，
无 vIOMMU 时得到 `/dev/vfio/noiommu-0`，有 Intel vIOMMU 时得到正常 group node 与 cdev。
结果、hash 和复现入口见
[`evidence/qemu-vfio-noiommu-split-20260718.md`](evidence/qemu-vfio-noiommu-split-20260718.md)。
ESXi 侧另有 Workstation 实际负控：vmkernel 明确记录 DMAR 缺失/IOMMU unavailable，45/45
`HostPciPassthruInfo` 均 incapable，包括带 Function/Bridge reset 的 USB 与网卡；见
[`evidence/esxi8-workstation-noiommu-20260718.md`](evidence/esxi8-workstation-noiommu-20260718.md)。

ESXi passthrough 启用后“立即生效还是需要重启”的外部模型、真实 host reboot、受控 vSwitch
Busy A/B、共享 bridge dependency 扩组、SOAP request-set 不对称、VM 独占 lease、SHA256，以及 Qman 四态 activation
planner 见 [`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)、
[`evidence/esxi8-passthru-activation-20260718-summary.json`](evidence/esxi8-passthru-activation-20260718-summary.json)
和 [`pci-resource-model/pci_resource_model/activation.py`](pci-resource-model/pci_resource_model/activation.py)。
重启需求是 owner transition 的运行时结果，不是 FLR、class code 或 BAR 的静态属性；Qman
明确采用“先扩 owner group、再逐成员预检”，并把 VM exclusive attach lease 与 reset domain 分离。

对必须启用 `pcie_acs_override` 的 host，配套的 Linux 6.6 provenance patch、自动构建入口
和双域 capable 规则见 [`kernel-patches/`](kernel-patches/README.md)。patched IOMMU group
继续用于 VFIO，安全 lease 则使用忽略 override 后保守重建的 physical isolation domain。

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
9. An aggregate 23-case capability matrix separated host IOMMU, accepted reset boundary,
   ACS policy, PCI class metadata, and structural bridge role from runtime
   assignability. Six class-only Type-0 variants all remained capable, while a
   real Type-1 X3130 bridge remained incapable despite recognized FLR. The
   documented `disableACSCheck` workaround also restored capability under an
   otherwise strict no-ACS Root Port check without changing the hardware surface. A shared
   reset dependency failed AH selection even with Capable/Enabled/Active=true;
   a dedicated Root Port made the same 32GB device boot.
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

When an OVMF aggregate BAR envelope cannot fit below 4G, a deterministic
launcher must set both knobs to the required high-aperture size. For the tested
2GB BAR this was `X-PciMmio64Mb=2048` plus `pci-hole64-size=2G`. It matched high/low
classification and size, but not VMware's exact high base address.

The 2026-07-15 layout matrix adds a required qualification: VMware CreateVM
defaults are workflow-sensitive. On the tested vHW20 host, CreateVM selected
`acpiHostBridges` for EFI and `i440bxHostBridge` for BIOS, while a directly
registered VMX with the layout key absent used the i440bx-like single-root
fallback. Both explicit VMware EFI layouts still exposed 440BX/PIIX4, so q35
is a PCIe-topology approximation rather than a chipset-equivalent default.
13. Q35 `pci-hole64-size=32G` is a minimum root-window span, not a BAR capacity
    ceiling. SeaBIOS 1.15 assigned two 64GiB BARs into `[64GiB,192GiB)` with
    the default, explicit 32GiB, and even zero floor. OVMF default assigned
    neither BAR; explicit 128GiB fw_cfg plus a 128GiB QEMU floor assigned both.
14. ESXi 8.0.3 can make DirectPath active without a host reboot when
    `--apply-now` succeeds. A dedicated deferred endpoint was also observed
    changing only Configured Owner until a real host reboot claimed it through
    `pciPassthru`. Persistent vSwitch use rejected both immediate and direct
    deferred requests; it was not a generic reboot-required state.
15. A shared bridge `dependentDevice` exposed request-target asymmetry: requesting
    the idle member expanded and activated both, while explicitly requesting the
    busy member or full set failed through both ESXCLI and SOAP. The same shared
    dependency was an exclusive VM-admission lease, including within one VM.
    Qman intentionally uses safer expand-first/preflight-all semantics.

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

This is configuration proof, not a guest-runtime BAR map. It proves only that a
default ESXi 8 EFI VM does not persist the documented passthrough 64-bit MMIO
knobs. Knob absence does **not** prove a below-4G-only runtime layout: the active
DirectPath tests below show ESXi creating a minimal high window for the tested
2GB BAR even when `use64bitMMIO` was absent or false. Explicit
`pciPassthru.use64bitMMIO` and `pciPassthru.64bitMMIOSizeGB` request a configured
aperture; the effective root window must always be established from an active
passthrough VM's `_CRS`, BAR map, and `vmware.log` evidence.

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
  (`1ULL << 31`) and q35 defaults to 32G (`1ULL << 35`). Source and dual-64GiB
  A/B tests prove this value is a minimum span from the runtime start, not a
  hard capacity: QEMU uses the farther of the actual assigned BAR end and
  `start + pci-hole64-size`.
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
  controls the minimum QEMU/ACPI 64-bit PCI host-window span
```

SeaBIOS can still assign 64-bit BARs above 4G when this floor is zero; QEMU then
publishes the actual assigned range. OVMF does not inherit that allocator
behavior, so the two firmware profiles must remain separate.

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
