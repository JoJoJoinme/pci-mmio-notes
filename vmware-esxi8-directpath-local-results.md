# ESXi 8 VMDirectPath 本地黑盒验证结果报告

日期：2026-07-11 至 2026-07-12
目标版本：VMware ESXi 8.0.3 build 24280767
外层平台：WSL2 + QEMU 6.2 + KVM，两台嵌套 ESXi + VCSA 8.0.3
L3：vHW 20、EFI、Linux 5.15.0-185

本文是本仓库当前的 VMware DirectPath 主结果报告。它取代了早期仅根据普通 EFI VMX
中缺少 `pciPassthru.use64bitMMIO`，便推断“默认 MMIO 一定全部位于 4G 以下”的结论。
本轮证据来自真正启用的 passthrough endpoint、成功启动的 EFI Linux guest、ESXi
`vmware.log`，以及外层 QEMU VT-d/device trace。双主机部分使用 VCSA
8.0.3 build 24674346、共享 NFS datastore 和两台同 build ESXi。

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

Dynamic X01 又给出一个同配置单变量闭环。两个 `1af4:1110` candidate 分别有 1GB
和 2GB BAR，并位于独立 root port/IOMMU dependency。VMX 中两个 64-bit MMIO key
均不存在：

| 运行 | `assignedId` | Guest BAR/root window |
| --- | --- | --- |
| target 单独启动 | `0000:01:01.0`，1GB | `0x80000000-0xbfffffff`，无高窗 |
| blocker 占用 1GB 后启动 target | `0000:02:00.0`，2GB | `0x1fff80000000-0x1fffffffffff`，2GB 高窗 |

两次均成功进入 Linux 并持续输出 heartbeat。这证明 ESXi 先解析具体 Dynamic
candidate，再按选中设备建立 guest MMIO envelope；它没有因为 allowed class 中存在
2GB candidate，就在选择 1GB candidate 时预留“所有候选最大值”高窗。

该结论只绑定当前 ESXi build、vHW 和受控 endpoint，不能直接外推到所有旧版 ESXi、
GPU、ReBAR 或超大 aggregate BAR。

### 1.2 QEMU 没有一组固定参数能完整复制 VMware 默认策略

新增的一键对照入口为：

```bash
./qemu-vmware-default-profile-validate.sh
```

它使用与 ESXi L3 相同的 EFI Linux 探针 ISO，不走 `-kernel/-initrd` 旁路。QEMU
6.2 + 当前 OVMF 的实测结果为：

| Case | 参数 | HMP/Guest 结果 |
| --- | --- | --- |
| i440fx、1GB RAM、1GB BAR | `X-PciMmio64Mb=0` + `i440FX-pcihost.pci-hole64-size=0` | BAR 精确为 `0x80000000-0xbfffffff`；无高窗；heartbeat |
| i440fx、1GB RAM、2GB BAR | `X-PciMmio64Mb=2048` + `i440FX-pcihost.pci-hole64-size=2G` | BAR/root window 为 `0x100000000-0x17fffffff`；heartbeat |
| q35、1GB RAM、1GB BAR | `X-PciMmio64Mb=0` + `q35-pcihost.pci-hole64-size=0` | BAR 保持未分配，EFI 不进入探针；负例通过 |

因此参数不能脱离 machine type、固件和完整低端布局单独解释。i440fx 低档在本轮
得到与 VMware 相同的 BAR 地址，但 QEMU root window/topology 仍不逐字相同；给
i440fx 增加 `pxb` 可以得到独立 ACPI root bus，却会多出可见 PCI bridge。

QEMU 对标启动器必须：

1. 读取待分配 function 的 BAR size/type/alignment/prefetchable，以及 IOMMU/reset
   dependency，并先选定 Dynamic candidate。
2. 用实际 machine/firmware 资源模型试算 below-4G 布局；只有试算和冷启动探针均
   通过时，才选择 OVMF `0` + host bridge `0` 的低档。
3. 若不能低置，计算对齐后的 high BAR envelope `N`，同时设置
   `X-PciMmio64Mb=N*1024` 和 `pci-hole64-size=NG`。
4. 把最终 BAR、ACPI root window 和启动结果作为验收值，不能把“QEMU 接受参数”
   当成通过。

高档可以对齐“高置分类”和 aperture 大小，但 stock QEMU 6.2/OVMF 的高窗基址仍
与 VMware 不同。VMware 将本轮 2GB window 放在 guest 45-bit GPA 顶部；i440fx
将其放在 4GB 紧上方。若要求地址与合成 root-bus 拓扑逐字一致，需要修改
OVMF/QEMU allocator 或实现专用 machine type。

## 2. 实验拓扑与证据边界

```text
Windows / WSL2
  -> QEMU q35 + KVM + virtual VT-d -> ESXi A 172.31.91.10
  -> QEMU q35 + KVM + virtual VT-d -> ESXi B 172.31.91.11
  -> shared NFS datastore + VCSA 8.0.3
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

### 4.3 aggregate BAR：不能只按总和计算

同一 VM 的实测对照为：

| BAR 集合 | Guest placement | 结果 |
| --- | --- | --- |
| 单 1GB | `0x80000000-0xbfffffff` | 低置 |
| 两个 1GB | `0x40000000-0x7fffffff`、`0x80000000-0xbfffffff` | 两个都低置 |
| 单 2GB | `0x1fff80000000-0x1fffffffffff` | 高置 |
| 1GB + 2GB | 连续 3GB DirectPath 高窗，另有 1GB main-root 高窗 | 高置 |

两个 1GB 与单个 2GB 的 aggregate 都是 2GB，却得到不同 placement。这实锤 allocator
必须按每个 BAR 的自然对齐、bridge packing 和低端碎片计算，不能只求和。1GB+2GB
用例中两个 BAR 位于连续 3GB DirectPath range，额外 1GB root range 使最终高端布局
按 4GB 边界收敛。

### 4.4 4GB gate 与 8GB 嵌套边界

单 4GB BAR 的单变量矩阵：

| VMX 参数 | 结果 |
| --- | --- |
| 两个 key 都缺省 | power-on 失败：`1048577 > 917504` pages |
| 仅 `64bitMMIOSizeGB=4` | 同样失败 |
| 仅 `use64bitMMIO=TRUE` | 通过；BAR/root=`0x1fff00000000-0x1fffffffffff` |
| TRUE + Size4 | 通过；地址与 TRUE-only 相同 |

因此在当前 build/device 上，`use64bitMMIO` 是进入 large-MMIO mapping path 的 gate；
`SizeGB` 不能单独开启该路径，且对恰好 4GB 的用例不是必要项。`917504` 个 4K page
等于 3.5GiB，是本 build 的外部可观察默认映射上限，不应外推成跨版本公式。

8GB 使用稀疏 regular-file backing，逻辑 8GB、初始实际占用 0，排除了 `/dev/shm`
容量不足：

- key 缺省时按预期失败：`2097153 > 917504` pages。
- TRUE-only 与 TRUE+Size8 均接受 8GB BAR并创建 IOMMU mapping。
- TRUE-only 进入 EFI runtime 后 600 秒无 guest serial；TRUE+Size8 也未得到 heartbeat，
  并令当前嵌套 ESXi 的 outer QEMU 长时间占满四个 vCPU。

所以 8GB 已证明“VMX mapping gate 能打开”，但没有形成 E2 guest-boot 通过证据。
32GB/64GB 没有继续盲跑；要验证 KB 的 `>32GB` SizeGB 规则，应改用 power-on-only
探针或不触发完整 guest enumeration 的定制 endpoint。仍未覆盖 ReBAR、32GB+、不同
vHW/ESXi 历史版本。

### 4.5 SeaBIOS 的定位

SeaBIOS 需要保留，但只作为固件边界控制，不是 VMware EFI 等价物。真实固件启动已证明：

- SeaBIOS 不读取 OVMF 的 `X-PciMmio64Mb`。
- 无 64-bit BAR 时，host bridge `pci-hole64-size=0` 会取消默认高窗。
- 有 present 64-bit BAR 时，SeaBIOS 仍可能先高置；即使 hole64=0，QEMU/ACPI 也会
  发布覆盖实际 BAR 的最小高窗。

因此 SeaBIOS 用来隔离“firmware allocator”与“QEMU ACPI host window”，不能拿它
代替 VMware EFI DirectPath profile。

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

R01 已用 UEFI variable 做跨重启 phase marker，避免额外磁盘改变 EFI 启动链。第一次
内核完成 e1000e I/O 后写 marker 并执行 `reboot -f`；第二次内核读取 marker、再次完成
I/O 后关机。两阶段均为 `tx=1`，运行中 `assignedId=0000:01:00.1`，最终
`poweredOff/assignedId=null`。所以 guest reboot 的功能路径为 pass；它仍不能替代
R00 对具体 FLR/bus reset callback 的直接观测。

I01 使用同一 EFI 探针加 `pci=nomsi`：

| 路径 | IRQ/流量结果 |
| --- | --- |
| ESXi Dynamic DirectPath | 成功回退到 `IO-APIC 17-fasteoi`，但 11 个样本 IRQ=0、`tx=0` |
| QEMU direct control | `IO-APIC 21-fasteoi` 从 13 增到 54，`tx` 从 9 增到 22 |

这说明 ESXi 向 guest 暴露了 legacy INTx route，但当前嵌套 DirectPath/e1000e 组合没有
功能 I/O。相同 QEMU endpoint 直接启动时通过，故失败范围收敛在嵌套 DirectPath 路径；
不能外推为物理 ESXi 不支持 INTx。QEMU 对标基线仍应使用已通过的 MSI-X/MSI，INTx
必须保留此负例并补 E4；MSI-only 仍需隐藏 MSI-X capability 的定制 endpoint。

## 7. 生命周期

| 操作 | 结果 |
| --- | --- |
| powered-on snapshot | `vim.fault.InvalidState` |
| suspend | `vim.fault.InvalidState` |
| 实际 I/O 后 forced power-off | 成功 |
| forced-off 后立即重新开机 | 成功 |
| 实际 I/O -> guest `reboot -f` -> 再次 I/O | 成功，efivar phase marker 闭环 |
| 十次快速 start/forced-stop | 10/10 通过 |
| 普通 VM live vMotion A -> B | 成功，迁移后保持 `poweredOn/connected` |
| Classic DirectPath live vMotion | 按预期拒绝：`vim.fault.InsufficientResourcesFault` |
| Dynamic DirectPath live vMotion | 按预期拒绝：同一 placement fault，缺少 `pciPassthru0` |
| Dynamic 关机后 relocate A -> B | 成功；B 开机时重新解析 `assignedId`，关机后再次清空 |
| DirectPath guest 有 DMA 流量时强杀外层 ESXi QEMU | 通过；host 重连、datastore/owner 恢复、同 VM 再启动成功 |

snapshot 和 suspend 的拒绝与 Broadcom KB 312208 描述的 DirectPath 产品限制一致。
普通 VM 成功迁移排除了 vCenter、共享存储、管理网络或目标主机本身不可用。Classic
与 Dynamic 的 live vMotion 均被同一个
`com.vmware.vim.vpxd.vmcheck.assignHwNotAvailable` placement check 拒绝；本轮没有
配置或声称支持带设备状态迁移的特殊硬件。Dynamic 的可移植路径是关机后 relocate，
再由目标主机按 allowed class 重新选 BDF。

L04 在 guest `rx=7/tx=10` 且持续 heartbeat 后，对 ESXi B 的 outer QEMU 发送
`SIGKILL`。vCenter 观察到 `connected -> notResponding -> connected`；重启后崩溃
VM 收敛为 `poweredOff/assignedId=null`，共享 datastore 与四个 passthrough owner
恢复 active。同一 VM 随后再次得到 `assignedId=0000:01:00.1`、DMA traffic 和
heartbeat，最终正常关机解绑。该结果证明当前嵌套镜像可从一次 abrupt host loss
恢复，但不替代真实设备对断电后寄存器/外部接口清零的 E4 检查。

## 8. Dynamic DirectPath

`HostAssignableHardwareManager.RetrieveDynamicPassthroughInfo()` 返回 e1000e 与
ivshmem candidate class。持久 VMX 只保存 `allowedDevices`，运行时 BDF 只出现在
`assignedId`/device hint 中。

| Case | 结果 | 外部可观察语义 |
| --- | --- | --- |
| X00 单主机生命周期 | `null -> 01:00.1/01:00.0/01:01.0 -> null` | 开机解析、关机解绑，不持久化 BDF |
| X01 异构 BAR candidate | 1GB 单独低置；被占用后改选 2GB 并自动高置 | 先选 candidate，再按选中设备定 MMIO envelope |
| X02 candidate 耗尽 | blocker 占一个 e1000e 后，要求两个设备的 VM 得到 `vim.fault.NoCompatibleHost`，nested missing=`pciPassthru1` | 不会重复分配同一设备，也不会静默少配 |
| X02 释放后恢复 | blocker 关机后 target 得到 `01:00.1` + `01:00.0`，guest heartbeat | 资源释放后无需改持久配置即可重试 |
| X03 关机跨主机 relocate | A/B 关机态 `assignedId=null`；B 开机解析 `01:00.1`；再关机清空 | allowed class 可移植，运行中设备状态不可直接 live migrate |

X01 的第一次错误拓扑也保留为负例：两个 candidate 同挂一个 outer root port 时，
blocker 占用其中一个后，另一个虽然被写入 device hint，VMX 最终报
`AH Failed to find a suitable device`。把两者移到独立 root port 后同一用例通过。
所以候选去重必须按完整 IOMMU/reset dependency，而不是只按 BDF。

QEMU 普通 VFIO 没有 VMware 这种内建 candidate selector。对标实现应放在外部
launcher/orchestrator：

1. 按 VID:DID、subsystem、revision、custom label 发现候选。
2. 按 IOMMU group/reset dependency 做原子占用，排除已被其他 VM 占用的整组。
3. 选定具体 BDF 后计算该组的 BAR/RMRR envelope；不能按 allowed class 最大值盲目预留。
4. 生成最终 `vfio-pci,host=BDF`、machine/firmware MMIO profile 和可审计 manifest。
5. 运行中记录等价于 `assignedId` 的租约；停止后释放，不把 BDF 写入持久 VM 定义。
6. live migration 默认拒绝；关机 relocate 后在目标 host 重新运行 1-5。

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
| 双 ESXi/vMotion/X02/X03 | `_artifacts/vmware-directpath-runs/20260711-vmotion/` |
| Dynamic 异构 BAR X01（通过） | `_artifacts/vmware-directpath-runs/20260711-dynamic-envelope-isolated/` |
| Dynamic 同 IOMMU 组负例 | `_artifacts/vmware-directpath-runs/20260711-dynamic-envelope/` |
| 2x1GB 与 1GB+2GB aggregate | `_artifacts/vmware-directpath-runs/20260711-dynamic-aggregate*/` |
| 4GB large-MMIO gate | `_artifacts/vmware-directpath-runs/20260711-single-4g*/` |
| 8GB sparse BAR 边界 | `_artifacts/vmware-directpath-runs/20260711-single-8g*/` |
| ESXi host crash/recovery L04 | `_artifacts/vmware-directpath-runs/20260711-host-crash/` |
| guest reboot R01 | `_artifacts/vmware-directpath-runs/20260712-r01-guest-reboot-efivar-v2/` |
| ESXi INTx I01 | `_artifacts/vmware-directpath-runs/20260712-i01-intx-v2/` |
| QEMU direct INTx control | `_artifacts/mmio-tests/qemu-intx-direct-20260712/` |
| QEMU 2GB profile 对照 | `_artifacts/mmio-tests/vmware-default-2g-q35.log` |
| QEMU i440fx 低/高档与 q35 负例 | `_artifacts/mmio-tests/qemu-vmware-default-profile-20260711/` |
| SeaBIOS i440fx/q35 | `_artifacts/mmio-tests/seabios-i440fx-1g-core/`、`seabios-q35-1g-core/` |

每个 MMIO case 至少保留：`case.json`、生效 VMX、ESXi PCI owner、`vmware.log`、
guest serial 和最终 power state。失败用例也保留，不能只归档成功样本。

Git 内可审计摘要：

- [`evidence/esxi8-vmotion-20260711-summary.json`](evidence/esxi8-vmotion-20260711-summary.json)
- [`evidence/esxi8-dynamic-envelope-20260711-summary.json`](evidence/esxi8-dynamic-envelope-20260711-summary.json)
- [`evidence/esxi8-bar-aggregate-20260711-summary.json`](evidence/esxi8-bar-aggregate-20260711-summary.json)
- [`evidence/esxi8-large-mmio-4g-20260711-summary.json`](evidence/esxi8-large-mmio-4g-20260711-summary.json)
- [`evidence/esxi8-large-mmio-8g-20260712-summary.json`](evidence/esxi8-large-mmio-8g-20260712-summary.json)
- [`evidence/esxi8-host-crash-20260711-summary.json`](evidence/esxi8-host-crash-20260711-summary.json)
- [`evidence/esxi8-reboot-intx-20260712-summary.json`](evidence/esxi8-reboot-intx-20260712-summary.json)
- [`evidence/qemu-vmware-default-profile-20260711-summary.json`](evidence/qemu-vmware-default-profile-20260711-summary.json)
- [`evidence/qemu-esxi-nfs-offload-20260712-summary.json`](evidence/qemu-esxi-nfs-offload-20260712-summary.json)

## 10. Blocked 项：原因与解锁方法

`blocked` 不等于 VMware 不支持，也不等于 QEMU 无法实现。它表示当前平台、endpoint
或观测点不足以对该问题给出有效结论。

### 10.1 P0：建议优先补齐

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| M04 32GB+ | sparse backing 已解决容量问题，但 8GB guest enumeration 已令当前 nested VMX/KVM 饱和 | 增加 power-on-only 模式，在 EFI/Linux 枚举前采集 VMX mapping；或实现只报告 BAR、不访问全部 range 的 endpoint，再测 32/64GB TRUE-only 与 TRUE+Size | power-on task、VMX mapping pages、guest `_CRS`（若可启动）、自动恢复 |
| R00 | ESXi 报 Bridge reset，但 QEMU 没有 qdev reset 事件 | 给 root port 和 endpoint reset callback 加定向 trace；endpoint 增加 generation counter；分别测 power-on/reboot/forced-off | reset 类型、顺序、影响的 function 集合、generation 变化 |
| I02 MSI-only | stock e1000e 总是优先 MSI-X，guest 参数不能表达“只隐藏 MSI-X、保留 MSI” | 给 endpoint 增加 capability mask，或用已知 MSI-only 设备模型 | `MSI-X` 不可见、`MSI Enable+`、流量与 interrupt-remap trace |

X01/X02、R01、L02、L04 已完成，不再列为 blocked。I01 也不是“未运行”：它是可重复的
nested functional fail，并已有 QEMU direct pass 对照；下一步是 E4，不是继续换文字参数。

### 10.2 P1：需要定制 QEMU endpoint 或危险注入

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| S01 Option ROM enabled | 只验证了默认不暴露 ROM；没有安全、可识别的目标 ROM | 给 outer endpoint 挂已知 UEFI option ROM；设置 ESXi `pcipSaveOPROM=1` 并重启；VMX 设置 `pciPassthruN.opromEnabled=TRUE` | guest ROM BAR、OVMF 执行签名、restart 后可重复执行 |
| S02 PME | stock endpoint 没有受控 PME 注入命令 | 实现 endpoint PM capability 和“设置 PMCSR PME_Status + 发 PME message”的 monitor/QMP 命令；对比默认 `_OSC` 与 `acpi.osc.pcie` | host/guest PMCSR、guest 是否收到通知、ESXi 是否明确忽略 |
| S04 P2P | 没有两个能做真实 peer DMA 的 endpoint | 实现两个可编程 DMA endpoint，让一端 DMA 到另一端 BAR；对比默认、`allowP2P`、`relaxACSforP2P` | peer BAR 内容、VT-d/ACS trace、host/guest 错误和性能计数 |
| S05 RMRR | QEMU 6.2 没有任意 RMRR command-line 注入 | 修改 QEMU DMAR table builder，为指定 SID 生成 RMRR，并保留对应 E820/UEFI range；endpoint 对该区域 DMA | ESXi memory map 调整、identity map 或精确 overlap fault；Dynamic candidate 包络 |

S03 AER Correctable/Non-Fatal 已通过三方采集，详见
[`vmware-aer-blackbox-results.md`](vmware-aer-blackbox-results.md)。

### 10.3 P2：真正需要真实硬件

| ID | 当前阻塞 | 怎么做 | 验收证据 |
| --- | --- | --- | --- |
| E4 真实 reset/ACS/INTx | QEMU endpoint 不能证明电气行为、vendor state 清除或物理 INTx 路由 | 裸机 ESXi + 支持的 NIC/NVMe/GPU，外加同设备裸机 Linux/VFIO 对照 | FLR/bus reset、IOMMU group、MSI-X/MSI/INTx、十次以上压力和敏感状态清除 |
| SR-IOV | 当前没有 PF/VF endpoint | 使用真实 SR-IOV NIC，或升级/定制 QEMU endpoint 生成 PF/VF | ESXi PF/VF eligibility、VF 独立 assignment、PF capability 是否进入 guest |

### 10.4 升级 WSL 内核/QEMU 的定位

升级不再用于修复普通 1/2/4GB 基线的 L3 VM-entry。建议在以下情况才做：

- 需要更新的 QEMU device model、QMP/AER/PME trace 或自定义 endpoint 基线。
- 需要更完整的 nested KVM/VMX tracepoint。
- QEMU 6.2 的 ACPI/DMAR builder 难以维护目标 patch。
- 需要判断 8GB BAR 下的四 vCPU 饱和是否为旧 KVM/QEMU nested regression，而不是
  规避普通基线中已经找到的 TSC scaling 原因。

推荐先在独立目录编译新版 QEMU，保留 6.2 作为 A/B 基线；只有新版明确需要新 KVM
能力时，再编译自定义 WSL 6.x 内核。每次结果必须记录 QEMU commit、kernel config、
OVMF build/hash 和完整命令行。

## 11. 还需要加强的地方

按优先级排序：

1. **实现 BAR-aware QEMU launcher。** 当前只有策略和手工参数，还没有可复用程序。
   应读取 sysfs/VFIO resource，展开 dependency，计算 below-4G 和 high aperture，并输出
   manifest 与最终 QEMU 参数。
2. **做 32GB+ power-on-only 探针。** 4GB gate、8GB mapping 与 aggregate packing 已有
   证据；剩余重点是隔离 guest enumeration，验证 KB 的 `>32GB` SizeGB 阈值。
3. **直接保存 ACPI `_CRS`。** 当前主要使用 Linux `root bus resource` 和 sysfs；应在
   L3 initrd 中加入 `acpidump`，保存并反编译 DSDT/SSDT。
4. **改善 trace 隔离。** 当前文本 trace 没有可靠时间戳，ESXi 管理网卡流量会混入。
   应在 L3 操作前后通过 QMP 动态开关事件，加入 case marker，并按 requester ID 分流。
5. **加强 reset 观测。** 增加 endpoint generation register 和 root-port callback trace，
   不能只依据 ESXi 的 `Reset Method` 字段。
6. **实现 MSI-only/PME/P2P/RMRR endpoint 控制。** 这些不是继续换 QEMU 参数就能得到的
   状态，需要 capability filter、QMP 注入或 DMAR builder patch。
7. **做 ESXi 跨版本矩阵。** 至少比较 6.5/7.0/8.0 U2/U3，确认历史
   `use64bitMMIO`/SizeGB 语义何时发生变化。
8. **做真实硬件 E4。** 所有安全性、复位彻底性、P2P、RMRR 和 vendor driver 结论最终
   都必须回到裸机。
9. **规范化产物。** 每个 case 应生成固定 schema 的 `result.json`、输入 manifest、
   SHA256、版本信息和 pass/fail/blocked 原因，避免依赖人工 grep。
10. **增加破坏性用例保护。** AER uncorrectable、host crash、ROM 和 RMRR 测试必须使用
    disposable qcow2 snapshot、单独 run ID 和自动恢复步骤。

## 12. 当前可接受的 QEMU 对标基线

不能再用一组固定 QEMU 参数代表“VMware 默认”。经过真实 EFI 探针验证，可接受的
实现是先选设备、再按 machine/firmware 试算资源：

```bash
# below-4G 候选档；本轮只有 i440fx + 1GB RAM + 1GB BAR 冷启动通过。
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global i440FX-pcihost.pci-hole64-size=0

# high 档：N 是逐 BAR 对齐、bridge packing 后的 envelope（GiB）。
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=$((N * 1024))
-global i440FX-pcihost.pci-hole64-size=${N}G
```

q35 的 zero/zero + 1GB BAR 是已验证负例，不能只把上面 property 名换成 q35 就宣称
等价。i440fx 的 2GB high 档得到 `0x100000000-0x17fffffff`，只对齐了高/低分类和
窗口大小；VMware 使用 45-bit GPA 顶部，精确基址/合成 root topology 需要 allocator
或 machine type patch。

### 12.1 KB 312208 到 QEMU 的核对表

| VMware 外部语义 | QEMU/VFIO 对齐办法 | 当前状态 |
| --- | --- | --- |
| UEFI 与 64-bit MMIO | OVMF 同时控制 fw_cfg aperture 与 host bridge hole64；launcher 按选中 BAR 计算 | 1/2/4GB、aggregate 已验证；8GB mapping-only |
| IOMMU isolation | 真实部署使用 host IOMMU + `vfio-pci`；nested 模型给 ESXi `intel-iommu,intremap=on` | VT-d DMA/MSI-X trace pass；禁止 no-IOMMU |
| ACS 与 dependency | 每组设备挂独立 `pcie-root-port`；按 host IOMMU group/reset dependency 原子租用 | PCIe/legacy/root/no-ACS 矩阵已跑 |
| reset 方法与总线依赖 | 让 VFIO 执行 FLR/bus reset；同 dependency 整组分配；endpoint generation register 记录回调 | 功能复用 pass，具体 reset 类型仍 partial |
| Dynamic candidate | orchestrator 按 allowed class 选 BDF，记录运行时 lease，关机释放；目标 host 重新选择 | X00-X03 pass；不能持久化固定 BDF |
| MSI-X/MSI/INTx | 保留 capability，启用 host interrupt remapping；禁止 unsafe interrupts | MSI-X E3 pass；INTx nested fail/direct pass；MSI-only 待 endpoint mask |
| PCIe AER ownership | host 侧注入/记录；guest config-space proxy 过滤 AER header/ownership，按目标策略镜像 status | Correctable/Non-Fatal surface 已验证；stock VFIO 不自动等价 |
| Option ROM | 默认 `rombar=0`；显式启用时固定 ROM hash，并分别验证 host 保存与 guest 执行 | 默认隐藏 pass；enabled 待安全 ROM |
| PME 与 `_OSC` | endpoint 提供可控 PME_Status/message，ACPI 层决定 native PME；host policy 可过滤 | 需要定制 endpoint/QMP |
| P2P 与 ACS relaxation | 两个真实 peer-DMA endpoint + ACS/IOMMU policy；不能把单个开关当成功 | 需要定制 peer DMA endpoint |
| RMRR | 修改 QEMU DMAR builder 发布 RMRR，并保留相同 guest physical range/identity map | stock QEMU 6.2 无通用 CLI |
| lifecycle/migration | 默认拒绝 save/snapshot/suspend/live migration；powered-off relocate 后重新选卡 | snapshot/suspend/vMotion/relocate/host-crash 已验证 |
| LinkCap/拓扑呈现 | 明确选择 synthetic guest topology，不把物理 speed/width 原样当合同 | 已观察 VMware 重建 LinkCap |

核心原则是：QEMU CLI 只能表达其中一部分。设备资格、Dynamic lease、依赖组、迁移拒绝
和恢复策略属于 launcher/orchestrator；PME/P2P/RMRR/AER filter 属于 device model 或
machine patch。把缺失语义硬塞成一个 `-global` 参数，会得到表面相似但行为不等价的配置。

## 13. 参考

- [Broadcom KB 312208：VMDirectPath/Dynamic DirectPath 平台与设备要求](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [vSphere API：VirtualPCIPassthrough DynamicBackingInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html)
- [vSphere API：Host AssignableHardwareManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html)
- [`vmware-directpath-acceptance-test-plan.md`](vmware-directpath-acceptance-test-plan.md)
- [`qemu-vmware-mmio-comparison.md`](qemu-vmware-mmio-comparison.md)
