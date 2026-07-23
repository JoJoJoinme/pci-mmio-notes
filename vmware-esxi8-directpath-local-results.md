# ESXi 8 VMDirectPath 本地黑盒验证结果报告

日期：2026-07-11 至 2026-07-23
目标版本：VMware ESXi 8.0.3 build 24280767
外层平台：WSL2 + QEMU 6.2/11.0.2 + KVM，两台嵌套 ESXi + VCSA 8.0.3
最新运行态：WSL 6.6.123.2 自编译 KVM 内核，QEMU 11.0.2 capability-lab build
L3：vHW 20、EFI、Linux 5.15.0-185

本文是本仓库当前的 VMware DirectPath 主结果报告。它取代了早期仅根据普通 EFI VMX
中缺少 `pciPassthru.use64bitMMIO`，便推断“默认 MMIO 一定全部位于 4G 以下”的结论。
本轮证据来自真正启用的 passthrough endpoint、成功启动的 EFI Linux guest、ESXi
`vmware.log`，以及外层 QEMU VT-d/device trace。双主机部分使用 VCSA
8.0.3 build 24674346、共享 NFS datastore 和两台同 build ESXi。

复现命令和 Case ID 索引见 [`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。
机器可读摘要见 [`evidence/esxi8-directpath-summary.json`](evidence/esxi8-directpath-summary.json)
和 [`evidence/esxi8-directpath-20260714-summary.json`](evidence/esxi8-directpath-20260714-summary.json)。
`passthruCapable` 专题模型见
[`vmware-esxi8-passthru-capable-observed-model.md`](vmware-esxi8-passthru-capable-observed-model.md)。
Host owner activation 的脱敏命令/输出与机器可读摘要见
[`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)
和 [`evidence/esxi8-passthru-activation-20260718-summary.json`](evidence/esxi8-passthru-activation-20260718-summary.json)。

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

### 1.2 8/32/64GB BAR 已闭环 gate、预算、IOMMU 与 guest runtime

`pci-testdev` 不需要为 BAR 建立等量 backing，因而可以把“宿主内存/稀疏文件容量不足”
从解释中排除。QEMU direct + OVMF 已分别启动 32GB、64GB BAR 并精确枚举；同一设备
交给 ESXi 后得到：

| BAR | absent/FALSE/Size-only | TRUE-only | TRUE + 足额 SizeGB | TRUE + 半额 SizeGB |
| --- | --- | --- | --- | --- |
| 8GB | 失败，limit=917504 pages | guest pass | guest pass | 失败，limit=1966080 pages |
| 32GB | 失败，limit=917504 pages | guest pass | guest pass | 失败，limit=5111808 pages |
| 64GB | 失败，limit=917504 pages | 失败，limit=9306112 pages | guest pass | 失败，limit=9306112 pages |

所需页数分别为 `8388609` 和 `16777217`。所有失败样本符合可观察预算模型：

```text
limitPages = 917504 + effectiveSizeGB * 262144
```

`SizeGB` 在 gate absent/FALSE 时不增加预算；`TRUE` 且 SizeGB absent 时的默认
`effectiveSizeGB` 为 32；显式 SizeGB 会替换这部分。故 32GB `TRUE-only` 能启动，
64GB `TRUE-only` 不能，而 `TRUE+Size64` 能启动。三种足额样本都完成 EFI Linux
heartbeat、目标 `1b36:0005` 枚举和 IOMMU mapping。Guest BAR 分别为：

```text
8GB:  0x1ffe00000000-0x1fffffffffff
32GB: 0x1ff800000000-0x1fffffffffff
64GB: 0x1ff000000000-0x1fffffffffff
```

运行态闭环还暴露了一个独立条件：大 BAR endpoint 与 e1000e 共用 Root Port 时，设备
虽为 `Capable/Enabled/Active=true`，VMX 仍报 `AH Failed to find a suitable device`；
把 endpoint 放到独占 Root Port 后，同一设备和 VMX 立即通过。QEMU 6.2/11.0.2 A/B
都复现共享组失败，因此根因是 dependency 无法独占，不是 QEMU 版本。规范化证据见
[`evidence/esxi8-directpath-20260714-summary.json`](evidence/esxi8-directpath-20260714-summary.json)。

### 1.3 QEMU 没有一组固定参数能完整复制 VMware 默认策略

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

### 1.4 启用 passthrough 后是否要重启是 owner transaction 结果

本地 `owner-toggle.txt` 保存了下面的正例：

```text
esxcli hardware pci pcipassthru set -d 0000:00:09.0 -e true -a
exit=0

Configured Owner: VM Passthru
Current Owner: VM Passthru
Module Name: pciPassthru
Passthru Capable: true
```

命令与读回之间没有 host reboot；同一运行随后由 vSphere API 读到
`passthruEnabled=true`、`passthruActive=true`。因此 Active 的外部含义是 effective owner 已经
匹配，不是“历史上一定重启过”。另一组样本则明确出现 Configured Owner=`VM Passthru`、
Current Owner=`VMkernel`、Module=`ne1000`，证明 desired/configured 与 effective/current 必须
分开保存。

2026-07-18 又在同一 ESXi 8.0.3 build 上补齐了 deferred、真实 host reboot 和受控 Busy A/B：

- 专用 `0000:01:00.1` 不带 `--apply-now` 时命令成功，Configured Owner 变为 passthrough，
  Current Owner/driver 保持 native；真实重启后 uptime 归零，同一 BDF 由 `pciPassthru` claim。
- 把同一类 endpoint 配为 `vmnic2 -> vSwitchBusy -> vmk1` 后，apply-now 和 direct deferred
  都返回明确的 vSwitch uplink 错误，desired/current 均不变；移除 consumer 后同一 BDF 立即成功。
- PCIe sibling 的 `dependentDevice` 不同时，空闲 function 可单独切换，忙 sibling 保持 native。
- legacy bridge 下两 function 共享 `dependentDevice` 时，仅请求空闲 function 会自动切换两者；
  显式请求 busy function 或完整 set 反而失败，SOAP 与 ESXCLI 一致。
- 共享 dependency 的 function 形成 VM admission 独占 lease：A 运行时 B 失败，A 释放后 B 成功；
  同一 VM 同时配置两者也在第二项 AH selection 失败。

因此 ESXCLI 合同中的 deferred 路径不能与任意 Busy 画等号，Broadcom busy-HBA 案例也不能泛化到
所有 host consumer。外部模型至少分开 request set、owner activation group、exclusive attach
group 和 reset contract：

```text
ALREADY_ACTIVE   complete dependency 的 current owner 已匹配
LIVE_APPLY       扩展后的 owner group 全员可 quiesce，可立即重绑
REBOOT_REQUIRED  request mode 显式允许 deferred，且完整 owner group 有精确 early-boot claim proof
DENIED           persistent host use、capability、identity、incomplete group、lease 或 policy 不成立
```

Qman 不复制 VMware 观测到的 request-target 不对称：先扩完整 owner group，再预检每个成员，
持久 network/storage/management consumer 一律拒绝；之后再按 exclusive attach group 获取 VM lease。
FLR/SBR 决定 attach/release/reset safety，但不证明 native driver 当前能否解绑；class code 与 BAR
也不能决定重启。没有 exact early-boot owner policy 时，单纯重启 Linux 只会让 native driver
再次绑定，不能承诺“重启后生效”。Qman 不支持 guest runtime PCI hotplug；这里的 live apply
发生在 VM power-on attach 之前，不改变运行中 guest PCI tree。完整证据、SHA256 和复现入口见
[`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)。

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

本报告可以对 VMware 黑盒决策和嵌套 IOMMU 行为给出 E2/E3 结论。RMRR 与 P2P 的
虚拟策略路径已验证；真实电气复位、硬件 ACS、vendor device 状态清除和真实 peer DMA
安全性仍需要 E4。

## 3. L3 启动阻塞与修复

最初 L3 在 VMX construction 和 IOMMU mapping 完成后失败：

```text
VM-entry failed; VMCS valid (error code 7)
```

对早期 1/2/4GB 基线，不需要升级 WSL 内核或 QEMU；只屏蔽外层 VMX TSC scaling
即可稳定启动：

```bash
-cpu host,+vmx,-vmx-tsc-scaling
```

修复后得到真正的 guest `lspci`、sysfs resource、e1000e I/O 和 MSI-X 证据。host
`01:00.0/.1` 在 guest 中为 `02:00.0/.1`，证明 guest 看到的是真正同 slot
multifunction，而不是只从 VMware `pciSlotNumber` 推算。

随后为 SR-IOV、PME、RMRR、FLR 和超大 BAR 编译了 WSL
`6.6.123.2-microsoft-standard-WSL2+` 与 QEMU 11.0.2。该组合已让 8/32/64GB 的
EFI guest runtime 全部通过；但本轮同时改变了 KVM 内核和 endpoint 拓扑，不能把
heartbeat 修复单独归因于新内核。可确定的单变量结论是：共享 dependency 在旧/新
QEMU 上都会触发 AH 拒绝，独占 Root Port 在新内核/QEMU 上通过。

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

### 4.4 4/8/32/64GB gate 与运行态边界

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

旧 8GB 稀疏 ivshmem 样本虽创建 mapping，却在共享 dependency 拓扑中没有 heartbeat。
2026-07-14 使用 no-backing `pci-testdev`、独占 Root Port 与同一 EFI 探针重跑 8GB
完整七项矩阵：TRUE-only 与 TRUE+Size8 均为 `guest-pass`，BAR 为
`0x1ffe00000000-0x1fffffffffff`；TRUE+Size4 按预期以
`2097153 > 1966080` pages 失败。

相同方法完成 32/64GB：32GB TRUE-only/TRUE+Size32 和 64GB TRUE+Size64 均形成
guest heartbeat、目标枚举及 IOMMU mapping；64GB TRUE-only 与 TRUE+Size32 均在
`9306112` 页上限处失败。8/32/64GB 的成功样本都使用与 BAR 同大小的 outer QEMU
hole64/OVMF aperture，外层 HMP、ESXi `vmware.log` 和 guest resource 三层地址均已保存。
尚未覆盖的是可变 ReBAR、不同 vHW/ESXi 历史版本和真实设备 pin/memlock 成本，而不是
这些固定大小 BAR 的 EFI runtime。

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

公开 [Broadcom KB 391460](https://knowledge.broadcom.com/external/article?articleNumber=391460)
还提供 `VMkernel.Boot.disableACSCheck=TRUE`，其语义是跳过 ESXi 8.0.3 过严的 ACS sanity
check，而不是关闭 ACS。本地将 `enableACSCheckForRP=TRUE` 保持开启，同时设置该全局
bypass 后，同一个无 ACS endpoint 从 `Capable=false` 恢复为 `Bridge reset`、
`Capable=true`；日志确认两个 boot option 均生效并打印 bypass，restore pass。
[Broadcom KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
还明确列出 `disableACSCheck`（绕过所有 PCIe ACS capability check）、
`enableACSCheckForRP`（启用 Root Port 检查）和 `enableACSDTP2P`（控制 ACS Direct
Translated P2P）。最后一项是独立的 P2P 策略开关，本轮没有把它冒充 ACS 检查绕过。
未显式传入 ACS boot option 的 baseline 在本 build 上记录为
`disableACSCheck=FALSE`、`enableACSCheckForRP=FALSE`；这是本环境观察值，不是跨版本
默认值承诺。

扩展后的累计 23 项 `passthruCapable` 单变量/对照矩阵进一步把资格判断收敛为外部可观察模型：

- 没有 IOMMU 时，即使 ESXi 能报告 `Bridge reset`，`passthruCapable=false`。
- Root Complex 直挂 endpoint 只有公开 FLR 时通过；PM-only、D3hot 状态位或 PME/D3
  广告都没有被本 build 接受为可用 reset 方法。
- Endpoint 自身没有 FLR/PM 时，只要位于可整体复位的 PCIe Root Port 或 legacy bridge
  后，仍可得到 `Bridge reset` 和 `passthruCapable=true`。
- Root Port 无 ACS 且当前 bypass policy 打开时仍 capable；开启严格 ACS 检查后，同一
  设备变为 incapable；再开启公开全局 `disableACSCheck` 后恢复 capable。
- 同一个 `1af4:1041` Type-0 FLR endpoint 只切换 class code 为 `0200/0500/0b02/0b40/
  0600/0604` 时，六轮均为 `Function reset`、`passthruCapable=true`；不存在这些 base
  class 的 blanket blacklist。
- 真正的 Type-1 X3130 upstream bridge 公开 FLR 后，ESXi 能报告 `Function reset`，但
  `passthruCapable=false`。因此 bridge 的结构角色是独立 gate，FLR 对真实 bridge 不充分。
- `passthruCapable` 只回答静态资格，不保证运行时可分配。共享 dependency 的大 BAR
  设备即使 `Capable/Enabled/Active=true`，仍可能被 AH 拒绝；独占 Root Port 后通过。

累计 23 项证据、白名单/quirk 边界、推理限制和 QEMU 核对表见
[`vmware-esxi8-passthru-capable-observed-model.md`](vmware-esxi8-passthru-capable-observed-model.md)。

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

e1000e reset 证据较弱：

- ESXi API 报告 `Bridge reset`。
- 正常关机、forced-off 和下一次启动都成功。
- 十次快速 start/forced-stop 全部通过。
- 但即使启用 `qdev_reset*` 和 e1000e reset trace，也没有看到对应 QEMU qdev reset。

因此该 endpoint 只能证明“设备可重复使用和 IOMMU invalidation”，不能声称 ESXi
每次都真实执行了 Secondary Bus Reset。

R00 的 Function Reset 路径已由 patched virtio endpoint 补齐。设备直挂 Root Complex、
公开 FLR 后，ESXi 报告 `Reset Method=Function reset` 和 `passthruCapable=true`；VM
power-on/power-off 两侧的 outer QEMU trace 都捕获到目标 `virtio-net-pci` 的
`qdev_reset_all/qdev_reset_tree/qdev_reset`，guest 同时启动成功。该结果证明本虚拟
端点的 FLR 回调链，不替代真实设备内部敏感状态清除的 E4，也没有把 SBR/D3 路径混写
成 FLR。

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
必须保留此负例并补 E4。

I02 的 MSI-only 缺口已用 QEMU EDU `1234:11e8` 补齐。该 endpoint 只有 INTx 和
MSI，没有 MSI-X；同一内核模块在 QEMU direct 和 ESXi DirectPath 下均强制申请一个
MSI vector，每阶段完成一次软件触发 IRQ 和两次 DMA-completion IRQ。ESXi 样本中：

- Guest 两阶段均为 `MSI: Enable+`，每阶段 IRQ count=3，256-byte 双向 DMA 比对通过。
- `vmware.log` 为该物理 function 记录 `physical MSI = Enabled (vmmInt = Enabled)`。
- 外层 VT-d 对 `dev 01:01.00` 记录四次 DMA translation；两个 Guest DMA IOVA 都落在
  `0x2a00000-0x2bfffff` 的 2MB translation range 内，且四次 DMA 后均紧邻同一
  IRTE 的 MSI remap；DMAR fault=0。

D01 的 teardown 已用 EDU 做同 requester、同 IOVA 的外层主动 DMA A/B。运行
`20260714-esxi8-edu-dma-teardown-v5` 在 L3 完成两阶段 DMA 后，读取第二阶段 IOVA
`0x2b00000`，再由 L0 QTest 只写公开 EDU DMA 寄存器：

- VM 运行中，SID `0x200` 使用 VT-d domain 2；`0x2b00000` 落在 2MB translation
  内，解析到 guest backing GPA `0x1c9100000`。
- VM 关机时，外层记录 `vtd_inv_desc_cc_global` 和
  `vtd_inv_desc_iotlb_global`。
- VM 显示 powered-off 后，同一 function 的 PCI Command/BAR 仍为
  `0x0406/0xc1000000`。再次发起同一 IOVA，SID `0x200` 已使用 domain 1，并恒等
  解析到 `0x2b00000`；没有继续命中旧 guest backing，也没有 DMAR fault。

所以本样本的“撤销 guest DMA translation”不是删除 context 后必然 fault，而是全局
失效后把 device 从 guest domain 2 切回 ESXi host identity domain 1。D01 的正确验收
条件是旧 guest backing 不再可达，并对删除、fault 或 host-domain rebound 分类；只找
IOTLB invalidation 或只等 fault 都会得出不完整结论。该探针只使用 QEMU 公开 trace、
PCI config 和 EDU 寄存器，不检查 VMware 私有实现。

reset sentinel 给出了更严格的语义边界。QEMU direct 的冷启动值为 reset，warm reboot
后为 persisted；ESXi 在 warm reboot 明确打印 `PCIPassthru: Resetting Device`，但第二
阶段 sentinel 仍为 persisted。故该日志证明 VMware 发起了 reset 流程，不证明没有
reset callback 的 EDU 内部状态已清零，也不能替代真实硬件 E4。复现入口为
`qemu-edu-direct-validate.sh` 与 `vmware-esxi8-lab/test_esxi_edu.py`。
KB 312208 要求合格设备在 reset 后不保留前一使用者的软件可读状态；因此该 EDU
结果应解释为“成功暴露了测试端点缺少 reset 语义”，不能把 EDU 标成生产兼容设备。

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

## 非 BAR 策略增量（2026-07-14）

### Option ROM

已知 UEFI ROM 先在 QEMU/OVMF 正控中通过：firmware 执行 marker、live counter、boot
target 和 Linux continuation 全部成立。ESXi 默认 DirectPath 样本按预期隐藏 ROM。
随后开启 host boot option `pcipSaveOPROM=TRUE`，并在有效 VMX 写入
`pciPassthru0.opromEnabled=TRUE`；guest 两个启动阶段和一次 restart 都成功，但 ROM
BAR、EFI variable/marker 和 outer counter delta 均为 0。结论是该 build/endpoint 的
enabled 路径“已测但未执行”，不是尚未运行，也不外推到所有受支持物理 adapter。

### PME

Patched e1000e endpoint 提供 PMCSR PME_Status 和 upstream PME status 注入。默认、
`acpi.osc.pcie=0x1f` 与拒绝 PME 的 `0x1b` 三项都完成。授予 native PME 的样本中，
guest 先将物理 function PME_Enable 置 1；注入后 endpoint/root status 均置位，guest raw
PMCSR 看到 `0x8100`，但没有 native PME IRQ delta。三种 `_OSC` grant 均与请求 mask
一致，结果符合 KB 描述的 tested ignored-PME 模型：status 可观察，不把物理 PME
无条件变成 guest native service。

### Correctable/Non-Fatal AER

Correctable AER 结果必须分成两个 profile，不能再概括为“ESXi 行的 CERE 全部为 0”：

| Profile | 已执行 | 外部结论 |
| --- | --- | --- |
| 历史 `e1000e/status-projection` | Correctable Receiver、Non-Fatal Unsupported Request、PassthruIdle 8 bit、PassthruActive Receiver/Advisory Non-Fatal 代表位 | endpoint/root CERE 与 Root COR_EN 均为 0；请求 CES 能沉积并投影到 guest raw body，guest AER header 为 0、`_OSC` 不授予 AER，owner 保持稳定。它只证明 surface/status projection，不能证明 ERR_COR delivery |
| `virtio/controlled-route` | PassthruIdle Receiver 完整 8 个 E/M/R tuple；PassthruActive `g100/g101` | Idle 8/8；只有 `g100/g101` 的 frozen snapshot 出现 Root `COR_RCV` 与 Source。Active guest 可发现 AER header `0x00020001` 且 raw CES `0→1`，但 Linux AER totals `0→0`、无 kernel event |

controlled-route result SHA-256 为
`655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1`。
这里的 E/M/R 分别是 Endpoint CERE、该 Correctable bit 的 Mask 与 Root COR_EN；辅助 Root
path 在八格中固定打开。`g100` 与 `g101` 都沉积 Root status，说明本 profile 下 R 不决定
Root status deposition；它是否触发 ESXi 可观察的 service/IRQ 必须单独验证。

关键证据边界是：frozen snapshot 在 ESXi vCPU 暂停时直接读取 outer QEMU fabric 配置空间，
证明的是 QEMU fabric 在 ESXi 已编程 gate 下的沉积和路由，不是 ESXi service、IRQ、日志清除
或 recovery。排除 SCP 路径和采集命令噪声后，恢复运行的有界 `vmkernel.log`/VM log
采集窗未观察到语义 AER/PCI error event，只能写成
“bounded log absence”，不能推出 no service。Stock QEMU 的 Root Port/e1000e/VFIO 默认
surface 也不能自动等价于 VMware；完整对标仍需要版本化 capability/body 读写、notification、
lifecycle clear 与 recovery policy。完整寄存器、run/hash 和限制见
[`vmware-aer-blackbox-results.md`](vmware-aer-blackbox-results.md) 与
[`vmware-aer-correctable-validation-plan.md`](vmware-aer-correctable-validation-plan.md)。

公开合同只到以下边界：

- [Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/) 规定
  DirectPath PCI error 由 ESXi 处理、而不是作为错误交给 guest；它没有要求每个 guest
  profile 都隐藏 capability/header/raw status，也没有公开 Correctable
  notification/service/clear/reset 算法。
- [Broadcom KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
  公开 `pcipDisablePciErrReporting` 的含义，但没有定义它对应哪些 AER gate。
- [Linux AER 文档](https://docs.kernel.org/PCI/pcieaer-howto.html)与
  [QEMU 11.0.2 `pcie_aer.c`](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
  只提供通用机制和 QEMU reference oracle，不能作为 VMware 内部实现证明。

### P2P

两个独立 Root Port 下的 EDU DMA source 与 ivshmem peer 执行真实 peer-BAR DMA：

| VMX policy | 结果 |
| --- | --- |
| 默认 | IOMMU fault type 5，地址 `0xff000000`，VM 被策略关闭 |
| 仅 `relaxACSforP2P=TRUE` | 与默认相同，不能单独放行 |
| 仅 `allowP2P=TRUE` | guest `P2P-PASS`，peer backing 匹配 DMA pattern |
| `allowP2P+relaxACSforP2P` | guest `P2P-PASS` |

有 ACS 和 no-ACS bypass 两组得到相同 policy 分叉；严格 ACS 检查则在更早的资格层拒绝。
因此 QEMU 对标必须把“设备可组成隔离组”和“VM 被允许 peer DMA”分成两个 gate。

### RMRR

QEMU DMAR patch 为指定 SID 发布 RMRR。`0x40000000-0x401fffff` 样本被 ESXi 识别为
一个 RMRR，`vmware.log` 明确记录 `Automatically adjusting PCI hole to 1024 MB`，
IOMMU mapping 与 guest boot 均成功，且该范围不与 guest System RAM 重叠。将 RMRR
移到 `0x01000000-0x011fffff` 的低 RAM overlap 后，outer QEMU 仍存活且有 ESXi boot
serial，但 ESXi 管理面在超时内不再 ready；该样本作为 host-boot-stage reject 通过。

### SR-IOV

QEMU NVMe/igb 可让 raw SR-IOV capability、VFE 和 ARI 状态出现，但 ESXi 的功能视图
把 PF Total/Initial VFs 置 0 或不枚举 raw VF。进一步把 igb 伪装为 I350 后，ESXi
`igbn` 已进入共享初始化代码，却以公开日志 `Invalid NVM Checksum` 停止。继续只改
VID:DID、subsystem 或 VF config ID 已不再是有效验证；需要受支持真实 PF，或实现完整
NVM/firmware/driver contract 的设备模型。

## 9. Case 与证据索引

所有复现入口见 [`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。关键
本地证据目录如下；路径以工作区 `E:\Code\PCI` 为根（从仓库根看等价于
`../_artifacts/...`）。这些目录包含多 MB trace、ISO 和 VM 日志，因此不提交 Git：

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
| 8GB sparse BAR 旧边界 | `_artifacts/vmware-directpath-runs/20260711-single-8g*/` |
| 8GB no-backing guest runtime | `_artifacts/vmware-directpath-runs/20260714-lb8-dedicated-full-v18/` |
| 32GB no-backing guest runtime/dependency A/B | `_artifacts/vmware-directpath-runs/20260714-lb32-*`、`20260714-esxi8-largebar-32g-dedicated-*` |
| 64GB no-backing guest runtime | `_artifacts/vmware-directpath-runs/20260714-lb64-dedicated-full-v17/` |
| QEMU direct 32/64GB control | `_artifacts/mmio-tests/qemu-pci-testdev-largebar-20260712/` |
| QEMU direct EDU MSI/DMA/reset | `_artifacts/mmio-tests/qemu-edu-direct-20260712-v2/` |
| ESXi EDU MSI/DMA/reset | `_artifacts/vmware-directpath-runs/20260712-esxi8-edu-msi-dma-reset-v4/` |
| ESXi EDU DMA power-off context A/B | `_artifacts/vmware-directpath-runs/20260714-esxi8-edu-dma-teardown-v5/` |
| ESXi host crash/recovery L04 | `_artifacts/vmware-directpath-runs/20260711-host-crash/` |
| guest reboot R01 | `_artifacts/vmware-directpath-runs/20260712-r01-guest-reboot-efivar-v2/` |
| ESXi INTx I01 | `_artifacts/vmware-directpath-runs/20260712-i01-intx-v2/` |
| QEMU direct INTx control | `_artifacts/mmio-tests/qemu-intx-direct-20260712/` |
| QEMU 2GB profile 对照 | `_artifacts/mmio-tests/vmware-default-2g-q35.log` |
| QEMU i440fx 低/高档与 q35 负例 | `_artifacts/mmio-tests/qemu-vmware-default-profile-20260711/` |
| SeaBIOS i440fx/q35 | `_artifacts/mmio-tests/seabios-i440fx-1g-core/`、`seabios-q35-1g-core/` |
| `passthruCapable` 15 项矩阵 | `_artifacts/vmware-directpath-runs/20260714-esxi8-passthru-capability-matrix-v4/` |
| ESXi ACS 全局 bypass 增量项 | `_artifacts/vmware-directpath-runs/20260714-esxi8-no-acs-global-bypass-v1/` |
| 虚拟 FLR callback | `_artifacts/vmware-directpath-runs/20260713-esxi8-flr-vm-power-v1/` |
| PME `_OSC`/status 注入 | `_artifacts/vmware-directpath-runs/20260714-esxi8-pme-v3/` |
| Correctable AER 历史 e1000e status/Active | `_artifacts/vmware-directpath-runs/20260723-aer-correctable/` |
| Correctable AER virtio PassthruIdle Receiver 8 EMR | `_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-idle-emr-v2/`；`result.json` SHA-256=`655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1` |
| Correctable AER virtio PassthruActive g100/g101 | `_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-emr-representative-v2/`、`20260723-esxi8-aer-virtio-active-g101-final-v1/` 与最终 parser smoke；按 case/result hash 区分有效观察和未注入的 harness 行 |
| P2P ACS/no-ACS policy | `_artifacts/vmware-directpath-runs/20260714-esxi8-p2p-*/` |
| RMRR 自动 hole/低 RAM 拒绝 | `_artifacts/vmware-directpath-runs/20260713-esxi8-rmrr-auto-v9-flr/`、`20260713-esxi8-rmrr-unsupported-v9-flr/` |
| Option ROM 正控与 ESXi 负例 | `_artifacts/vmware-directpath-runs/20260713-qemu-optionrom-minimal-compressed-padded-v33/`、`20260713-esxi8-optionrom-minimal-compressed-padded-v4/` |
| SR-IOV PF/VF surface | `_artifacts/vmware-directpath-runs/20260714-esxi8-sriov-*/` |
| owner `--apply-now`、API active 与 desired/effective A/B | `_artifacts/vmware-directpath-runs/20260713-capability-smoke-v5/`、`20260713-esxi8-flr-vm-power-v1/`、`20260711-largebar2g/` |
| Workstation ESXi 无 IOMMU 全量负控 | `_artifacts/vmware-directpath-runs/20260718-workstation-esxi8-noiommu-live-v4/` |
| QEMU/Linux VFIO IOMMU/no-IOMMU provider A/B | `_artifacts/vmware-directpath-runs/20260718-qemu-vfio-noiommu-split-v2/` |

每个 MMIO case 至少保留：`case.json`、生效 VMX、ESXi PCI owner、`vmware.log`、
guest serial 和最终 power state。失败用例也保留，不能只归档成功样本。

Git 内可审计摘要：

- [`evidence/esxi8-vmotion-20260711-summary.json`](evidence/esxi8-vmotion-20260711-summary.json)
- [`evidence/esxi8-dynamic-envelope-20260711-summary.json`](evidence/esxi8-dynamic-envelope-20260711-summary.json)
- [`evidence/esxi8-bar-aggregate-20260711-summary.json`](evidence/esxi8-bar-aggregate-20260711-summary.json)
- [`evidence/esxi8-large-mmio-4g-20260711-summary.json`](evidence/esxi8-large-mmio-4g-20260711-summary.json)
- [`evidence/esxi8-large-mmio-8g-20260712-summary.json`](evidence/esxi8-large-mmio-8g-20260712-summary.json)
- [`evidence/esxi8-large-mmio-32g-64g-20260712-summary.json`](evidence/esxi8-large-mmio-32g-64g-20260712-summary.json)
- [`evidence/qemu-edu-direct-20260712-summary.json`](evidence/qemu-edu-direct-20260712-summary.json)
- [`evidence/esxi8-edu-msi-dma-reset-20260712-summary.json`](evidence/esxi8-edu-msi-dma-reset-20260712-summary.json)
- [`evidence/esxi8-host-crash-20260711-summary.json`](evidence/esxi8-host-crash-20260711-summary.json)
- [`evidence/esxi8-reboot-intx-20260712-summary.json`](evidence/esxi8-reboot-intx-20260712-summary.json)
- [`evidence/qemu-vmware-default-profile-20260711-summary.json`](evidence/qemu-vmware-default-profile-20260711-summary.json)
- [`evidence/qemu-esxi-nfs-offload-20260712-summary.json`](evidence/qemu-esxi-nfs-offload-20260712-summary.json)
- [`evidence/esxi8-directpath-20260714-summary.json`](evidence/esxi8-directpath-20260714-summary.json)
- [`evidence/esxi8-edu-dma-teardown-20260714-summary.json`](evidence/esxi8-edu-dma-teardown-20260714-summary.json)
- [`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)
- [`evidence/esxi8-passthru-activation-20260718-summary.json`](evidence/esxi8-passthru-activation-20260718-summary.json)
- [`evidence/esxi8-workstation-noiommu-20260718.md`](evidence/esxi8-workstation-noiommu-20260718.md)
- [`evidence/esxi8-workstation-noiommu-20260718-summary.json`](evidence/esxi8-workstation-noiommu-20260718-summary.json)
- [`evidence/qemu-vfio-noiommu-split-20260718.md`](evidence/qemu-vfio-noiommu-split-20260718.md)
- [`evidence/esxi8-aer-correctable-20260723-result.json`](evidence/esxi8-aer-correctable-20260723-result.json)
- [`evidence/esxi8-aer-correctable-20260723-summary.json`](evidence/esxi8-aer-correctable-20260723-summary.json)

## 10. 剩余边界与解锁方法

`blocked` 只用于当前观测点确实不足的项目。2026-07-14 后，M04 8/32/64GB、R00
虚拟 FLR、D01 DMA teardown、S02 PME、S04 P2P 和 S05 RMRR 都已有可执行结果，不再
列为软件阻塞。

### 10.1 已完成但结果为负或有明确边界

| ID | 当前结论 | 证据边界 |
| --- | --- | --- |
| S01 Option ROM | 默认隐藏为 pass；已知 UEFI ROM 在 outer QEMU/OVMF 可重复执行，但 ESXi 设置 `pcipSaveOPROM=TRUE` 与 `opromEnabled=TRUE` 后仍未在 guest 执行 | 这是当前 build/endpoint 的可重复负结论，不等于所有支持设备都不能执行 ROM |
| I01 INTx | ESXi guest 有 legacy route 但无功能 IRQ/流量；同 ISO QEMU direct pass | 下一步是裸机 E4，不是继续改 VMX 文本参数 |
| R00 reset | 虚拟 FLR callback 在 VM power-on/off 可见；EDU 无 callback 时状态跨 warm reboot 保留 | SBR/D3 和真实设备内部状态清除仍未被 FLR 样本覆盖 |
| S05 RMRR | 自动 PCI-hole 范围被 ESXi 识别、调整并启动；低 RAM overlap 在 ESXi host boot 阶段拒绝 | 不把 guest 未公开 DMAR 当成 host 未处理 RMRR |

### 10.2 仍需更完整 endpoint 或真实硬件

| ID | 当前阻塞 | 怎么解锁 |
| --- | --- | --- |
| SR-IOV 功能 VF | QEMU NVMe/igb 的 raw SR-IOV capability/VFE 可构造，但 ESXi 将 PF Total/Initial VFs 视为 0 或不枚举 VF；igbn 在 I350 identity 下因 NVM checksum 拒绝 | 使用 ESXi HCL 支持的真实 PF，或实现足以让对应 ESXi driver 完成 NVM/firmware 初始化的完整模型 |
| 真实 reset/ACS/INTx | 虚拟 callback 不能证明电气行为、vendor state 清除或物理中断路由 | 裸机 ESXi + 同设备 Linux/VFIO A/B，记录 FLR/SBR、IOMMU group、IRQ 和敏感状态 |
| Option ROM 正向样本 | 当前仅得到 ESXi enabled-but-not-executed 负例 | 使用已知受支持且能被 ESXi 保存的物理 adapter ROM，再用同一 marker 协议复核 |
| 物理 owner-consumer qualification | nested ESXi 已完成同 BDF vSwitch Busy/idle、direct deferred、真实 reboot、shared dependency expansion 和 VM exclusive lease | 仍需在真实 HBA/GPU 上重放 storage path、multifunction coupling、boot ordering 与 vendor recovery；nested 结果不替代 E4 |
| 跨版本语义 | 当前主结论绑定 ESXi 8.0 U3；ESXi 6.5 仅作旁证 | 自动跑 6.5/7.0/8.0 U2/U3 同一 matrix，不跨版本外推默认 MMIO/资格规则 |

### 10.3 自定义 WSL 内核/QEMU 的定位

当前 WSL 内核为 `6.6.123.2-microsoft-standard-WSL2+`，`/dev/kvm` 可用且 nested=Y；
QEMU 11.0.2 lab binary SHA256 为
`021bda3344eadf7fd12cb66665351ef6d1e6734ab2c69ab8ab36441afc09b393`。
它用于 endpoint patch、新 trace 和大 BAR runtime。QEMU 6.2 仍保留为 A/B；共享
dependency 的 AH 失败在两版都复现，因此不能把拓扑问题归咎于新版 QEMU。

## 11. 还需要加强的地方

按优先级排序：

1. **实现 BAR/dependency-aware QEMU launcher。** 从 sysfs/VFIO resource 和 IOMMU
   group 生成 lease manifest，先原子占用 dependency，再计算 hole64/OVMF aperture。
2. **补真实硬件 E4。** 优先 SR-IOV PF/VF、INTx、FLR/SBR 状态清除和支持型 Option ROM；
   这些是当前无法用更换 QEMU 参数诚实替代的项目。
3. **直接保存 ACPI `_CRS`。** 当前已有 Linux root-bus resource 与 sysfs BAR；应在
   L3 initrd 中加入 `acpidump` 并保存反编译后的 DSDT/SSDT。
4. **改善 trace 隔离。** 在 L3 操作前后通过 QMP 开关事件，加入 case marker，并按
   requester ID 分流，减少管理网流量和旧 trace 混入。
5. **扩展 reset generation。** FLR callback 已通过；继续给 root-port SBR、D3hot 和
   multifunction dependency 增加 generation register，分清复位类型与影响集合。
6. **做 ESXi 跨版本矩阵。** 至少比较 6.5/7.0/8.0 U2/U3，确认
   `use64bitMMIO`、SizeGB、ACS 与 reset 判定何时变化。
7. **统一结果 schema。** 新脚本已有 `result.json`/`matrix-result.json`；仍需统一字段、
   SHA256、版本和 `pass|fail|partial|blocked` 原因，便于自动 diff。
8. **保留破坏性保护。** AER uncorrectable、host crash、P2P fault、ROM 和 RMRR 必须用
   disposable qcow2、独立 run ID 与自动 restore。
9. **实现 owner activation executor 与 attach lease coordinator。** planner/evaluator 已可执行，
   但产品还需要 owner-group durable journal、逐成员 consumer preflight、live rebind/rollback/
   quarantine、exclusive-attach multi-key CAS，以及按 exact identity/path/group 工作的 early-boot
   claim 和 boot reconcile；没有这条执行链时不能对外宣告 maintenance reboot activation。

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
| UEFI 与 64-bit MMIO | OVMF 同时控制 fw_cfg aperture 与 host bridge hole64；launcher 按选中 BAR 计算 | 1/2/4GB、aggregate 和 8/32/64GB guest runtime 已验证；大 BAR 必须独占 dependency |
| IOMMU isolation | VM payload 使用 host IOMMU + `vfio-pci`；nested 模型给 ESXi `intel-iommu,intremap=on`；宿主 DPDK 的全局 unsafe no-IOMMU 允许位独立 | e1000e MSI-X 与 EDU MSI/DMA 的 VT-d trace pass；D01 已证明关机从 guest domain 切回 host identity domain；VM fd 禁止 no-IOMMU，DPDK BDF 显式 host-reserved |
| Host DPDK/VM no-IOMMU 分流 | 两个 QEMU Ubuntu guest 均设置 unsafe=`Y`，只改变 Intel vIOMMU presence，再把同一 e1000e 绑定 `vfio-pci`；另跑 Workstation ESXi 无 DMAR 负控 | 无 IOMMU=`/dev/vfio/noiommu-0`，有 IOMMU=`/dev/vfio/7`+cdev；ESXi 45/45 incapable 且 reset-capable 网卡/USB 也不例外，证明全局允许位、class、reset 都不能替代 VM IOMMU gate |
| ACS 与 dependency | 每组设备挂独立 `pcie-root-port`；按 host IOMMU group/reset dependency 原子租用 | PCIe/legacy/root/no-ACS 矩阵已跑 |
| reset 方法与总线依赖 | 让 VFIO 执行 FLR/bus reset；同 dependency 整组分配；endpoint generation register 记录回调 | 虚拟 FLR power-on/off callback pass；bridge dependency pass；SBR/D3 与真实状态清除待 E4 |
| Dynamic candidate | orchestrator 按 allowed class 选 BDF，记录运行时 lease，关机释放；目标 host 重新选择 | X00-X03 pass；不能持久化固定 BDF |
| MSI-X/MSI/INTx | 保留 capability，启用 host interrupt remapping；禁止 unsafe interrupts | MSI-X E3 pass；EDU MSI-only E3 pass；INTx nested fail/direct pass，待 E4 |
| PCIe AER policy | synthetic endpoint status 注入/观察；guest config-space proxy 按 profile 过滤 capability 与 body read/write，host event/recovery 另证 | 双 profile：e1000e 完成 hidden-header/status projection；virtio Idle 8 EMR 已 8/8，Active 完成 visible-header/raw-CES/no-event 切片，只有 g100/g101 frozen Root `COR_RCV+Source`。frozen fabric 不代证 ESXi service/IRQ；guest write、notification 归因、T5 recovery 和物理 E4 未验证 |
| Option ROM | 默认 `rombar=0`；显式启用时固定 ROM hash，并分别验证 host 保存与 guest 执行 | 默认隐藏 pass；QEMU ROM 正控 pass；ESXi enabled 样本为可重复“不执行”负例 |
| PME 与 `_OSC` | endpoint 提供可控 PME_Status/message，ACPI 层决定 native PME；host policy 可过滤 | patched endpoint 三种 `_OSC` mask pass；PME status 可见但无 native PME IRQ，符合 KB ignored 模型 |
| P2P 与 ACS relaxation | 两个 peer-DMA endpoint + ACS/IOMMU policy；不能把单个开关当成功 | 默认/relax-only 被 IOMMU fault 阻断；`allowP2P=TRUE` 才成功，ACS/no-ACS A/B 已跑 |
| RMRR | 修改 QEMU DMAR builder 发布 RMRR，并保留相同 guest physical range/identity map | patched QEMU：自动 PCI-hole 调整 pass；低 RAM overlap 在 ESXi host boot 拒绝 |
| lifecycle/migration | 默认拒绝 save/snapshot/suspend/live migration；powered-off relocate 后重新选卡 | snapshot/suspend/vMotion/relocate/host-crash 已验证 |
| host owner activation | request set、owner activation group、exclusive attach group 分离；先扩组再预检；lease 后 live bind 或显式 exact early-boot claim | ESXi deferred/reboot、vSwitch Busy A/B、dependency expansion 与 VM lease 均本地 pass；Qman planner/evaluator 单测通过；executor/boot agent 待实现 |
| guest runtime PCI hotplug | API、scheduler、launcher、QMP 都拒绝；Dynamic 只在 power-on 选卡 | Qman 产品范围永久关闭，不把 VMware fixed-hotplug API 误当实现待办 |
| LinkCap/拓扑呈现 | 明确选择 synthetic guest topology，不把物理 speed/width 原样当合同 | 已观察 VMware 重建 LinkCap |

核心原则是：QEMU CLI 只能表达其中一部分。设备资格、Dynamic lease、依赖组、迁移拒绝
和恢复策略属于 launcher/orchestrator；PME/P2P/RMRR/AER filter 属于 device model 或
machine patch。把缺失语义硬塞成一个 `-global` 参数，会得到表面相似但行为不等价的配置。

## 13. 参考

- [Broadcom KB 312208：VMDirectPath/Dynamic DirectPath 平台与设备要求](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [Broadcom KB 424082：`pcipDisablePciErrReporting` 等 Advanced Settings 映射](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
- [Linux PCIe AER Driver Guide](https://docs.kernel.org/PCI/pcieaer-howto.html)
- [QEMU 11.0.2 `hw/pci/pcie_aer.c`](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
- [vSphere API：VirtualPCIPassthrough DynamicBackingInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html)
- [vSphere API：Host AssignableHardwareManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html)
- [ESXCLI 8.0.3：hardware pci pcipassthru set](https://developer.broadcom.com/xapis/esxcli-command-reference/8.0.3/namespace/esxcli_hardware.html)
- [Broadcom KB 434815：busy HBA native-driver detach](https://knowledge.broadcom.com/external/article/434815/hba-adapter-hba355i-registers-as-storage.html)
- [QEMU EDU 公开设备协议](https://www.qemu.org/docs/master/specs/edu.html)
- [`vmware-directpath-acceptance-test-plan.md`](vmware-directpath-acceptance-test-plan.md)
- [`qemu-vmware-mmio-comparison.md`](qemu-vmware-mmio-comparison.md)
