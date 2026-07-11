# ESXi 8 VMDirectPath 本地黑盒验证结果报告

日期：2026-07-11
目标版本：VMware ESXi 8.0.3 build 24280767
外层平台：WSL2 + QEMU 6.2 + KVM
L3：vHW 20、EFI、Linux 5.15.0-185

本文是本仓库当前的 VMware DirectPath 主结果报告。它取代了早期仅根据普通 EFI VMX
中缺少 `pciPassthru.use64bitMMIO`，便推断“默认 MMIO 一定全部位于 4G 以下”的结论。
本轮证据来自真正启用的 passthrough endpoint、成功启动的 EFI Linux guest、ESXi
`vmware.log`，以及外层 QEMU VT-d/device trace。

复现命令和 Case ID 索引见 [`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。
机器可读摘要见 [`evidence/esxi8-directpath-summary.json`](evidence/esxi8-directpath-summary.json)。

## 1. 结论摘要

### 1.1 VMware 默认 MMIO 不是固定 below-4G 模型

在本机 ESXi 8.0 U3 上，真正决定 BAR 低置还是高置的是实际资源需求，而不是
`use64bitMMIO` 和 `64bitMMIOSizeGB` 是否存在。

| 受控 BAR | VMware VMX 变体 | L3 EFI Linux 结果 |
| --- | --- | --- |
| 只有 e1000e 32-bit BAR | absent、FALSE、TRUE、TRUE+Size4、仅 Size4 | 无 above-4G root window |
| 1GB 64-bit prefetchable BAR | 同上五种 | BAR 为 `0x80000000-0xbfffffff`，无 above-4G window |
| 2GB 64-bit prefetchable BAR | 同上五种 | BAR 和 root window 为 `0x1fff80000000-0x1fffffffffff` |

最硬的反例是：

```text
pciPassthru.use64bitMMIO = "FALSE"
```

并没有阻止 2GB BAR 被放到 4G 以上。参数 absent、FALSE、TRUE、TRUE+Size4、仅
Size4 的结果完全相同。反过来，1GB BAR 即使设置 TRUE+Size4，也仍然优先放在
4G 以下，没有无条件发布 4GB 高窗。

因此，在此版本和设备路径上：

- `use64bitMMIO` absent/false 不是“保证 4G 以下”的开关。
- `use64bitMMIO=TRUE` 不是“无条件创建 32GB 高窗”的开关。
- `64bitMMIOSizeGB=4` 被 VMX 接受，但没有强迫实际 `_CRS` 变成 4GB。
- VMware 会把 host BAR 重新映射到 guest 地址；host BAR 基址不能推导 guest BAR 基址。

该结论只绑定当前 ESXi build、vHW 和受控 endpoint，不能直接外推到所有旧版 ESXi、
GPU、ReBAR 或超大 aggregate BAR。

### 1.2 QEMU 没有一组固定参数能完整复制 VMware 默认策略

q35/OVMF 的 2GB 对照结果：

| QEMU profile | L3 结果 |
| --- | --- |
| QEMU/OVMF 默认 | BAR 在 `0x800000000`；发布 32GB high window |
| `X-PciMmio64Mb=0` + `pci-hole64-size=0` | BAR2 未分配；无 high window |
| `X-PciMmio64Mb=2048` + `pci-hole64-size=2G` | BAR 和 2GB window 为 `0x180000000-0x1ffffffff` |

所以 `both_zero` 只能表示 QEMU 的 below-4G-only profile，不能表示完整的 VMware
默认策略。QEMU 对标必须由启动器根据实际 BAR 包络动态选择 profile：

1. 启动前读取所有待分配 function 的 BAR size、类型、对齐、prefetchable 属性和
   reset/IOMMU dependency。
2. 如果完整布局能放进目标 below-4G hole，设置：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global q35-pcihost.pci-hole64-size=0
```

3. 如果不能低置，计算对齐后的 high BAR 包络 `N`，同时设置 OVMF 和 QEMU host
   bridge。例如本轮 2GB profile：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=2048
-global q35-pcihost.pci-hole64-size=2G
```

这种办法可以对齐“低置/高置分类”和 aperture 大小，但 stock QEMU 6.2/OVMF 的
高窗基址仍与 VMware 不同。VMware 把 2GB window 放在 guest 45-bit GPA 顶部，
q35 则把它放在 RAM 上方。若要求地址逐字一致，需要修改 OVMF/QEMU allocator 或
实现专用 machine type，不能仅靠现有两个 size knob。

## 2. 实验拓扑与证据边界

```text
Windows / WSL2
  -> QEMU q35 + KVM + virtual VT-d
    -> ESXi 8.0.3 build 24280767
      -> vHW 20 EFI Linux L3
```

外层 QEMU 提供：

- `q35`、`kernel-irqchip=split`。
- `intel-iommu,intremap=on,caching-mode=on,device-iotlb=on`。
- 同 slot 的 e1000e function 0/1。
- 可变大小的 `ivshmem-plain` 64-bit prefetchable BAR。
- 可切换 ACS、PCIe root port、root-complex 直挂、legacy bridge 和 link width/speed。
- VT-d、e1000e、MSI-X 和 qdev reset trace。

证据等级：

| 等级 | 本轮含义 |
| --- | --- |
| E1 | Broadcom KB、vSphere API、QEMU/OVMF 文档或源码契约 |
| E2 | 生效 VMX、`vmware.log`、ESXi API、L3 Linux 输出 |
| E3 | 外层 QEMU VT-d、DMA、中断和 reset trace |
| E4 | 裸机 ESXi + 真实 PCIe device；本轮没有 |

本报告可以对 VMware 黑盒决策和嵌套 IOMMU 行为给出 E2/E3 结论，但真实电气复位、
硬件 ACS、RMRR/P2P 和 vendor device 安全性仍需要 E4。

## 3. L3 启动阻塞与修复

最初 L3 在 VMX construction 和 IOMMU mapping 完成后失败：

```text
VM-entry failed; VMCS valid (error code 7)
```

不需要升级 WSL 内核或 QEMU。只屏蔽外层 VMX TSC scaling 后即可稳定启动：

```bash
-cpu host,+vmx,-vmx-tsc-scaling
```

修复后得到真正的 guest `lspci`、sysfs resource、e1000e I/O 和 MSI-X 证据。host
`01:00.0/.1` 在 guest 中为 `02:00.0/.1`，证明 guest 看到的是真正同 slot
multifunction，而不是只从 VMware `pciSlotNumber` 推算。

较新的 WSL 6.x 内核和 QEMU 仍有价值，但用途变成补齐 endpoint/event injection 和
新 tracing 能力，不再是“让 L3 能启动”的必要条件。

## 4. MMIO 与 BAR 详细结果

### 4.1 1GB BAR

外层 QEMU 给 ESXi 的物理 BAR 位于 4G 以上；`vmware.log` 记录：

```text
barIndex 2 type 3 realaddr 0x800000000 size 1073741824 flags 12
```

但 L3 guest 中 VMware 将它重映射为：

```text
root window: 0x80000000-0xbfffffff pref
ivshmem BAR2: 0x80000000-0xbfffffff 64bit pref
```

结论：设备 BAR 是 64-bit 并且 host 地址在 4G 以上，不代表 VMware 必须在 guest
中高置；只要资源可容纳，VMware 可以低置。

### 4.2 2GB BAR

默认、FALSE、TRUE、TRUE+Size4 和仅 Size4 均为：

```text
root window: 0x1fff80000000-0x1fffffffffff pref
ivshmem BAR2: 0x1fff80000000-0x1fffffffffff 64bit pref
```

这说明当前 VMware allocator 在低端布局无法容纳时会自动生成最小需求高窗，而不是
等待 `use64bitMMIO=TRUE` 才允许高置。

### 4.3 尚未覆盖的 MMIO 边界

本轮没有完成以下项：

- 单 BAR 4GB、8GB、32GB、64GB、128GB。
- 两个 1GB BAR 与单个 2GB BAR的对照。
- 多 endpoint 混合 256MB/1GB/2GB 的 aggregate alignment。
- ReBAR capability 与固定 effective BAR size 的交互。
- 不同 vHW、ESXi 6.x/7.x/8.x 的历史行为差异。

所以目前能实锤“1GB 低置、2GB 自动高置”，但还不能给出 VMware 通用 aperture
计算公式。

## 5. 拓扑、资格与 reset dependency

| Case | 结果 | 含义 |
| --- | --- | --- |
| A00 PCIe root port baseline | e1000e/ivshmem 均 capable，`Bridge reset` | 当前可用基线 |
| A02/A03 multifunction | 正常 PCIe 路径下两个 function 可独立切 owner | host function 管理独立于 guest BDF |
| A01 禁用 ACS | ESXi 记录 bypass，但仍允许 passthrough | 当前 nested host 关闭了 root-port ACS enforcement |
| A04 endpoint 直挂 root complex | `Reset Method=None`、`Passthru Capable=false` | 命中 KB 对 FLR/D3Hot 的要求 |
| A05 legacy bridge | 桥后所有 endpoint 的 dependency 都是 `01:00.0` | requester ID 被桥统一 |
| A05 只 enable 一个 endpoint | ESXi 自动把桥后全部 endpoint 切到 passthrough | 集体分配在 owner 阶段生效 |
| A06 外层限制 8GT/s x4 | L1 endpoint 为 2.5GT/s x1；L3 为 5GT/s x32 | VMware 重建 guest LinkCap |

A01 不是“ACS 不需要”的证据。该 ESXi 启动明确显示：

```text
enableACSCheckForRP = FALSE
Bypassing non-ACS capable device in hierarchy
```

因此它只能证明 VMware 存在 bypass 分支，不能作为生产安全配置。生产 VFIO/ESXi
对标仍应要求真实 ACS、正确 IOMMU group，禁止把 `pcie_acs_override` 当成通过条件。

## 6. DMA、中断与 reset

L3 initrd 加载 e1000e 后实际发送和接收报文，并看到三个 PCI-MSI vector。相同运行
区间内，外层 QEMU trace 出现：

```text
vtd_iotlb_page_update ... sid 0x100 ... domain 0x2
vtd_dmar_translate dev 01:00.00 iova ... -> gpa ...
e1000e_irq_msix_notify_vec ...
vtd_ir_remap_msi ... -> ...
```

这形成了 requester `01:00.0`、DMA translation、e1000e MSI-X 和 interrupt
remapping 的 E3 闭环。power cycle 还产生了 domain 2 的整域 IOTLB invalidation。

reset 证据较弱：

- ESXi API 报告 `Bridge reset`。
- 正常关机、forced-off 和下一次启动都成功。
- 十次快速 start/forced-stop 全部通过。
- 但即使启用 `qdev_reset*` 和 e1000e reset trace，也没有看到对应 QEMU qdev reset。

因此当前只能证明“设备可重复使用和 IOMMU invalidation”，不能声称 ESXi 每次都真实
执行了 Secondary Bus Reset。该项状态为 partial。

## 7. 生命周期

| 操作 | 结果 |
| --- | --- |
| powered-on snapshot | `vim.fault.InvalidState` |
| suspend | `vim.fault.InvalidState` |
| 实际 I/O 后 forced power-off | 成功 |
| forced-off 后立即重新开机 | 成功 |
| 十次快速 start/forced-stop | 10/10 通过 |
| vMotion | 单 standalone host，未测试 |
| L3 运行时强杀整个 ESXi | 未测试 |

snapshot 和 suspend 的拒绝与 Broadcom KB 312208 描述的 DirectPath 产品限制一致。

## 8. Dynamic DirectPath

`HostAssignableHardwareManager.RetrieveDynamicPassthroughInfo()` 返回一个 e1000e
candidate class 和一个 ivshmem candidate class。随后通过 vSphere API 给 VM 添加两个
相同 e1000e `allowedDevice` 和一个 ivshmem `allowedDevice`。

状态变化：

```text
关机：
  assignedId = null, null, null

开机：
  assignedId = 0000:01:00.1, 0000:01:00.0, 0000:01:01.0

再次关机：
  assignedId = null, null, null
```

持久 VMX 只保存：

```text
pciPassthru0.allowedDevices = "0x8086:0x10d3"
pciPassthru1.allowedDevices = "0x8086:0x10d3"
pciPassthru2.allowedDevices = "0x1af4:0x1110"
```

QEMU 普通 VFIO 没有 VMware 这种内建 candidate selector。对标实现应放在外部
launcher/orchestrator：

1. 按 VID:DID、subsystem、revision、custom label 发现候选。
2. 排除已占用 BDF，并展开 IOMMU/reset dependency。
3. 计算所有选中设备的 BAR/RMRR 包络。
4. 生成最终 `vfio-pci,host=BDF` 和 MMIO profile。
5. 记录运行时 BDF；停止后释放，不把 BDF 写成持久 VM 定义的一部分。

## 9. Case 与证据索引

所有复现入口见 [`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。关键
本地证据目录如下；这些目录包含多 MB trace、ISO 和 VM 日志，因此不提交 Git：

| 范围 | 本地证据目录 |
| --- | --- |
| 1GB BAR MMIO | `_artifacts/vmware-directpath-runs/20260711-largebar/` |
| 2GB BAR MMIO | `_artifacts/vmware-directpath-runs/20260711-largebar2g/` |
| ACS/root/legacy/link topology | `_artifacts/vmware-directpath-runs/20260711-topology/` |
| DMA/MSI-X/VT-d trace | `_artifacts/vmware-directpath-runs/20260711-trace-link/` |
| snapshot/suspend/forced-off/reset | `_artifacts/vmware-directpath-runs/20260711-lifecycle/` |
| 十次 stress | `_artifacts/vmware-directpath-runs/20260711-stress/` |
| Dynamic DirectPath | `_artifacts/vmware-directpath-runs/20260711-dynamic/` |
| QEMU 2GB profile 对照 | `_artifacts/mmio-tests/vmware-default-2g-q35.log` |

每个 MMIO case 至少保留：`case.json`、生效 VMX、ESXi PCI owner、`vmware.log`、
guest serial 和最终 power state。失败用例也保留，不能只归档成功样本。

## 10. Blocked 项：原因与解锁方法

`blocked` 不等于 VMware 不支持，也不等于 QEMU 无法实现。它表示当前平台、endpoint
或观测点不足以对该问题给出有效结论。

### 10.1 P0：建议优先补齐

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| M04/M07 | 只有 1GB/2GB 单大 BAR，无法归纳 aperture 公式 | 用多个独立 root port 挂 256MB/1GB/2GB/4GB ivshmem；再用 sparse `memory-backend-file` 做 32GB+；对比单 2GB 与双 1GB | guest `_CRS`、BAR 地址、失败边界、VMX 单变量矩阵 |
| X01 | 同类 Dynamic candidate 的 BAR/RMRR 包络相同 | 制作相同 VID:DID、不同 BAR size 的两个 instrumented endpoint；只配置一个 allowed class | `assignedId`、开机前预留窗口、选中设备与最大 candidate 包络对比 |
| X02 | 没有候选在 power-on 瞬间失效的注入点 | 配置后把一个候选分配给另一 VM，或在 power-on 前切回 VMkernel | fallback 到第二候选，或精确 task fault |
| R00 | ESXi 报 Bridge reset，但 QEMU 没有 qdev reset 事件 | 给 root port 和 endpoint reset callback 加定向 trace；endpoint 增加 generation counter；分别测 power-on/reboot/forced-off | reset 类型、顺序、影响的 function 集合、generation 变化 |
| R01 | 当前 initrd 自动关机，没有持久 reboot marker | 使用带小磁盘的 Linux guest；第一次 I/O 后写 marker 并 reboot，第二次再次 I/O 后关机 | 两次 driver 初始化、两次 I/O、reset trace、无 stale state |
| I01/I02 | 没有稳定强制 MSI-only/INTx-only 的 endpoint/driver 模式 | INTx 先做 `pci=nomsi` 负例；MSI-only 需要隐藏 MSI-X capability 或修改 endpoint/driver | guest `/proc/interrupts`、QEMU device IRQ trace、`vtd_ir_*` 对照 |

### 10.2 P1：需要定制 QEMU endpoint 或危险注入

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| S01 Option ROM enabled | 只验证了默认不暴露 ROM；没有安全、可识别的目标 ROM | 给 outer endpoint 挂已知 UEFI option ROM；设置 ESXi `pcipSaveOPROM=1` 并重启；VMX 设置 `pciPassthruN.opromEnabled=TRUE` | guest ROM BAR、OVMF 执行签名、restart 后可重复执行 |
| S02 PME | stock endpoint 没有受控 PME 注入命令 | 实现 endpoint PM capability 和“设置 PMCSR PME_Status + 发 PME message”的 monitor/QMP 命令；对比默认 `_OSC` 与 `acpi.osc.pcie` | host/guest PMCSR、guest 是否收到通知、ESXi 是否明确忽略 |
| S03 AER | **pass（Correctable + Non-Fatal）** | boot-only 启用 `enablePCIErrors`、关闭 `pcipDisablePciErrReporting`；QEMU 分别注入 Receiver Error 与 Unsupported Request | VMware 隐藏 guest AER header/ownership，但保留 raw status body；两类事件均为 status-only，详见 `vmware-aer-blackbox-results.md` |
| S04 P2P | 没有两个能做真实 peer DMA 的 endpoint | 实现两个可编程 DMA endpoint，让一端 DMA 到另一端 BAR；对比默认、`allowP2P`、`relaxACSforP2P` | peer BAR 内容、VT-d/ACS trace、host/guest 错误和性能计数 |
| S05 RMRR | QEMU 6.2 没有任意 RMRR command-line 注入 | 修改 QEMU DMAR table builder，为指定 SID 生成 RMRR，并保留对应 E820/UEFI range；endpoint 对该区域 DMA | ESXi memory map 调整、identity map 或精确 overlap fault；Dynamic candidate 包络 |

### 10.3 P2：需要第二台主机或真实硬件

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| L02 vMotion | 只有一台 standalone ESXi | 准备第二台同版 ESXi、vCenter、共享存储和迁移网络；classic 与 Dynamic DirectPath 分开测 | API task/fault、placement restriction、迁移前后 `assignedId` |
| L04 host crash | 本轮没有在 L3 DMA 时强杀整个 ESXi | 先备份 qcow2；L3 持续 DMA 时直接终止 outer QEMU，再重启 ESXi | datastore 一致性、owner 恢复、下一次 VM/I/O 成功 |
| E4 真实 reset/ACS | QEMU endpoint 不能证明电气行为和 vendor state 清除 | 裸机 ESXi + 支持的 NIC/NVMe/GPU，外加同设备裸机 Linux/VFIO 对照 | FLR/bus reset、IOMMU group、真实中断、十次以上压力和敏感状态清除 |
| SR-IOV | 当前没有 PF/VF endpoint | 使用真实 SR-IOV NIC，或升级/定制 QEMU endpoint 生成 PF/VF | ESXi PF/VF eligibility、VF 独立 assignment、PF capability 是否进入 guest |

### 10.4 升级 WSL 内核/QEMU 的定位

升级不再用于修复 L3 VM-entry。建议在以下情况才做：

- 需要更新的 QEMU device model、QMP/AER/PME trace 或自定义 endpoint 基线。
- 需要更完整的 nested KVM/VMX tracepoint。
- QEMU 6.2 的 ACPI/DMAR builder 难以维护目标 patch。
- 需要用较新内核验证 KVM nested regression，而不是规避当前已经找到的 TSC scaling 原因。

推荐先在独立目录编译新版 QEMU，保留 6.2 作为 A/B 基线；只有新版明确需要新 KVM
能力时，再编译自定义 WSL 6.x 内核。每次结果必须记录 QEMU commit、kernel config、
OVMF build/hash 和完整命令行。

## 11. 还需要加强的地方

按优先级排序：

1. **实现 BAR-aware QEMU launcher。** 当前只有策略和手工参数，还没有可复用程序。
   应读取 sysfs/VFIO resource，展开 dependency，计算 below-4G 和 high aperture，并输出
   manifest 与最终 QEMU 参数。
2. **补齐 4GB+ 与 aggregate BAR 边界。** 这是把“1GB/2GB 现象”提升为 allocator
   规则的必要条件。
3. **直接保存 ACPI `_CRS`。** 当前主要使用 Linux `root bus resource` 和 sysfs；应在
   L3 initrd 中加入 `acpidump`，保存并反编译 DSDT/SSDT。
4. **改善 trace 隔离。** 当前文本 trace 没有可靠时间戳，ESXi 管理网卡流量会混入。
   应在 L3 操作前后通过 QMP 动态开关事件，加入 case marker，并按 requester ID 分流。
5. **加强 reset 观测。** 增加 endpoint generation register 和 root-port callback trace，
   不能只依据 ESXi 的 `Reset Method` 字段。
6. **完成 Dynamic X01/X02。** 目前只证明相同 ID 的选择和 `assignedId` 生命周期，尚未
   证明异构 BAR/RMRR 包络和候选失效策略。
7. **做 ESXi 跨版本矩阵。** 至少比较 6.5/7.0/8.0 U2/U3，确认历史
   `use64bitMMIO`/SizeGB 语义何时发生变化。
8. **做真实硬件 E4。** 所有安全性、复位彻底性、P2P、RMRR 和 vendor driver 结论最终
   都必须回到裸机。
9. **规范化产物。** 每个 case 应生成固定 schema 的 `result.json`、输入 manifest、
   SHA256、版本信息和 pass/fail/blocked 原因，避免依赖人工 grep。
10. **增加破坏性用例保护。** AER uncorrectable、host crash、ROM 和 RMRR 测试必须使用
    disposable qcow2 snapshot、单独 run ID 和自动恢复步骤。

## 12. 当前可接受的 QEMU 对标基线

在 BAR-aware launcher 尚未实现前，建议明确区分两个 profile，不要再称某一个为
“VMware 默认固定参数”。

### below-4G profile

```bash
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=OVMF_VARS.fd \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
  -global q35-pcihost.pci-hole64-size=0 \
  -device pcie-root-port,id=rp1,chassis=1,slot=1 \
  -device vfio-pci,host=0000:65:00.0,bus=rp1,addr=00.0,rombar=0
```

### calculated high profile

```bash
# N 是考虑 BAR alignment 和 bridge window 后的高窗包络，单位 GB。
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=$((N * 1024))
-global q35-pcihost.pci-hole64-size=${N}G
```

另外：

- 不要把 guest vIOMMU 当成 host VFIO IOMMU isolation。
- 不要使用 unsafe interrupt 或 VFIO no-IOMMU 作为通过配置。
- multifunction/reset-dependent function 必须整体分配。
- ROM 默认对标使用 `rombar=0`，直到 S01 得到更强证据。
- Dynamic DirectPath 对标需要外部 selector，而不是静态写死 BDF。

## 13. 参考

- [Broadcom KB 312208：VMDirectPath/Dynamic DirectPath 平台与设备要求](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [vSphere API：VirtualPCIPassthrough DynamicBackingInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html)
- [vSphere API：Host AssignableHardwareManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html)
- [`vmware-directpath-acceptance-test-plan.md`](vmware-directpath-acceptance-test-plan.md)
- [`qemu-vmware-mmio-comparison.md`](qemu-vmware-mmio-comparison.md)
