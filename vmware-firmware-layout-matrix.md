# VMware firmware / motherboardLayout 与 QEMU 对标实测

日期：2026-07-15

目标环境：VMware ESXi 8.0.3 build 24280767，vHW 20，三块 DirectPath
设备，其中 `1af4:1110` 带 2 GiB 64-bit prefetchable BAR。

本报告只描述公开 API、VMX、`vmware.log`、guest PCI/ACPI/sysfs 和 QEMU
日志的外部可观察行为，不推导 VMware 私有代码。

机器可读结论见
[`evidence/esxi8-firmware-layout-20260715-summary.json`](evidence/esxi8-firmware-layout-20260715-summary.json)。

## 1. 先把四个词拆开

VMware 的两个轴是：

1. firmware：`bios` 或 `efi`。
2. motherboard layout：`i440bx` 或 `acpi`，API 名称分别为
   `i440bxHostBridge` 和 `acpiHostBridges`。

SeaBIOS 和 OVMF 是 QEMU 侧固件，不是 VMware 固件名称。本文中的映射是：

| VMware | QEMU 对照 |
| --- | --- |
| `firmware=bios` | SeaBIOS 行为对照，不假定二者等价 |
| `firmware=efi` | OVMF 行为对照 |
| `i440bx` layout | `pc-i440fx` 是库存 QEMU 中较近的老式 PC machine，但 guest ID 仍不同 |
| `acpi` layout | i440fx + PXB 是库存 QEMU 中较近的多 ACPI root 模型 |

Broadcom API 将 layout 明确定义为“单 i440BX host bridge”或“多个 ACPI
host bridges”。`firmware` 和 `motherboardLayout` 是不同字段：

- [VirtualHardware.MotherboardLayout enum](https://developer.broadcom.com/xapis/vmware-storage-policy-api/latest/vim.vm.VirtualHardware.MotherboardLayout.html)
- [VirtualHardware JSON API，字段缺省说明](https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/VirtualHardware/)

## 2. “默认”有三层，不能只说一个默认

本地实测和 Broadcom KB 可以同时成立，因为它们描述的路径不同。

### 2.1 CreateVM 产品工作流

使用公开 vSphere CreateVM API，提交 `vmx-20`、firmware，故意不设置
`motherboardLayout`。创建后、上电后、关机后分别读
`config.hardware.motherboardLayout`，然后销毁临时 VM：

| CreateVM 请求 | afterCreate | afterPowerOn | afterPowerOff |
| --- | --- | --- | --- |
| EFI，layout unset | `acpiHostBridges` | `acpiHostBridges` | `acpiHostBridges` |
| BIOS，layout unset | `i440bxHostBridge` | `i440bxHostBridge` | `i440bxHostBridge` |

最终 v2 runner 对三阶段值自动断言，两个用例均为 `layoutAssertion=true`、`verdict=pass`，
并在 `finally` 路径确认临时 VM `cleanup=destroyed`。

这与 Broadcom 对 vHW20+EFI 新建 VM 使用 ACPI layout 的公开说明一致：

- [KB 407595：vHW20+ EFI 的 ACPI motherboard layout](https://knowledge.broadcom.com/external/article/407595/vm-pci-slot-and-network-interface-change.html)
- [KB 312026：ACPI layout 不能改用 BIOS](https://knowledge.broadcom.com/external/article?legacyId=91353)

### 2.2 直接注册、VMX 中 layout key 缺省

把手工 VMX 直接注册到 ESXi，VMX 中不写
`chipset.motherboardLayout`，但保留 VMware 常见 `pcieRootPort` 树，结果是：

| firmware | guest root | guest chipset | 2 GiB BAR2 |
| --- | --- | --- | --- |
| BIOS | 单根 `PCI0 [00-7f]` | 440BX/PIIX4 | 未分配 |
| EFI | 单根 `PCI0 [00-7f]` | 440BX/PIIX4 | `0x1fff80000000-0x1fffffffffff` |

因此，**VMX key 缺省 fallback** 在本实验中是 i440bx-like；它不等于
**CreateVM 工作流默认**。Qman 导入 VMX、API 新建、模板克隆时必须分别解析，最后把
resolved layout 显式持久化，不能每次启动重新猜。

Content Library 还可能改变或丢失该字段，Broadcom 已公开记录这类问题：

- [KB 396781：Content Library 可能把 i440bx 改为 acpi](https://knowledge.broadcom.com/external/article/396781/chipsetmotherboardlayout-is-automaticall.html)
- [KB 313466：vHW19 升级后 acpi layout 会改变 PCI slot](https://knowledge.broadcom.com/external/article?articleNumber=313466)

### 2.3 生效配置

无论配置来自 API、模板还是手工 VMX，验收对象都必须是：

1. 输入 VMX/API ConfigSpec。
2. ESXi 生效 VMX 和 `vmware.log` DICT。
3. guest ACPI root、`lspci -tv`、sysfs BAR。

只看创建界面或只看缺少某个 VMX key，都不能证明最终 layout/MMIO 行为。

## 3. VMware 四组合实测

四格统一使用 vHW20、三块 DirectPath 设备、2 GiB BAR、
`pciPassthru.use64bitMMIO` 缺省，以及四组八功能 VMware `pcieRootPort`
作为输入桥型。

| layout | firmware | 上电/guest | root topology | 2 GiB BAR2 | 结论 |
| --- | --- | --- | --- | --- | --- |
| i440bx | BIOS | 完成；端点、网卡 DMA/MSI 可用 | `PCI0 [00-7f]` + 32 个 VMware root port | 未分配 | 有限可用，不具备大 BAR 能力 |
| i440bx | EFI | 完成；IOMMU mapping 成功 | `PCI0 [00-7f]` + 32 个 VMware root port | `0x1fff80000000-0x1fffffffffff` | 通过 |
| acpi | EFI | 完成；IOMMU mapping 成功 | `PCI0 [00-01]`、`PC08 [02]`、`PC0G [03]` | `0x1fff80000000-0x1fffffffffff` | 通过 |
| acpi | BIOS | `DevicePowerOnEarly` 拒绝 | 无 guest | 无 | 固定负例 |

`acpi+BIOS` 的精确错误是：

```text
ACPI motherboard layout requires EFI.
```

因此用户所说的 `acpi+SeaBIOS` 不需要设计成 QEMU 正向 profile。VMware
对标 profile 应在启动前以稳定 reason code 拒绝该组合。

### 3.1 i440bx + BIOS 不是“大 BAR below-4G”

Linux 探测到目标 BAR2 的大小需求：

```text
pci 0000:13:00.0: reg 0x18: [mem 0x00000000-0x7fffffff 64bit pref]
```

但 root-port prefetch window 只有 1 MiB，目标 sysfs 只有 BAR0，BAR2 没有
非零 resource。端点仍可枚举，两块 e1000e 的 DMA、流量和 MSI 中断也成功。

所以需要分开报告：

- DirectPath endpoint 是否可见。
- 小 BAR/网卡功能是否可用。
- 大 BAR 是否真正分配。

“VM 上电”和“设备出现在 lspci”都不是大 BAR 通过条件。

### 3.2 acpi 不是 Q35

`i440bx+EFI` 和 `acpi+EFI` 的 guest 都呈现：

```text
8086:7190  Intel 440BX host bridge
8086:7191  440BX AGP bridge
8086:7110/7111/7113  PIIX4
```

`acpi` 改变的是 host-bridge/root-bus 组织。它没有把 guest 芯片组改成 Q35/ICH9。

在 `acpi+EFI` 案例中，输入的 `pcieRootPort` 集合被 ESXi 生效 VMX 归一化为
两个 `pciRootBridge`，并自动给三块 DirectPath 设备分配 slot 32/33/34。
这说明 layout 会参与桥拓扑合成，不能把它当成一个仅影响 ACPI 字符串的开关。

## 4. QEMU 真实固件启动矩阵

统一入口：

```bash
WORKDIR=/path/to/results \
BASE_IMAGE=/path/to/noble-server-cloudimg-amd64.img \
./qemu-firmware-layout-matrix-validate.sh
```

测试路径为 QEMU -> SeaBIOS/OVMF -> Ubuntu cloud image -> Linux 6.8，未使用
`-kernel/-initrd` 直启。矩阵 7/7 通过预期断言：

| QEMU profile | roots | 2 GiB BAR2 | 关键观察 |
| --- | ---: | --- | --- |
| i440fx + SeaBIOS + single root | 1 | `0x100000000-0x17fffffff` | SeaBIOS 仍把 BAR 高置 |
| i440fx + SeaBIOS + pci-bridge | 1 | `0x180000000-0x1ffffffff` | bridge high window 约 4 GiB |
| i440fx + OVMF + single root + exact 2G | 1 | `0x100000000-0x17fffffff` | MMIO 分类/大小匹配 VMware EFI |
| i440fx + OVMF + pci-bridge + exact 2G | 1 | 未分配 | 预期负例 |
| 同一 bridge + 4G control | 1 | `0x100000000-0x17fffffff` | 增大 aperture 后恢复 |
| i440fx + OVMF + PXB + exact 2G | 2 | `0x100000000-0x17fffffff` | 多 ACPI root 正例 |
| q35 + OVMF + PCIe root-port + exact 2G | 1 | `0x100000000-0x17fffffff` | PCIe 语义正例，芯片组不匹配 |

QEMU 版本为 6.2.0，OVMF 为 2022.02，SeaBIOS 为 1.15.0。精确 hash 已写入
机器可读摘要。

### 4.1 SeaBIOS 不能复刻 VMware BIOS 大 BAR 行为

本轮两个 SeaBIOS 案例都在 4 GiB 以上成功分配 2 GiB BAR。即使 QEMU 使用老式
i440fx machine 和传统 PCI bridge，它也不复现 VMware i440bx+BIOS 的“端点可见、
BAR2 未分配”。

因此不能用以下推理：

```text
VMware BIOS -> QEMU SeaBIOS -> 行为天然相同
```

若 Qman 的 VMware BIOS parity profile 要避免 silent partial device，应在预计算发现
mandatory BAR 无法分配时直接返回 `LEGACY_MMIO_UNASSIGNABLE`。只有实验兼容 profile
可以有意暴露未分配 BAR，并且必须标成 degraded，不应作为生产可用设备。

### 4.2 精确 2 GiB aperture 不等于能放一个 2 GiB BAR

普通 `pci-bridge` 精确 2 GiB OVMF 案例中，bridge 自身先占用了一个很小的 high
resource，剩余范围无法再满足 BAR2 的 2 GiB 对齐。扩大到 4 GiB 后，同一 BAR 立即成功。

因此 planner 必须对完整树自底向上计算：

```text
aperture = packed(endpoint BARs + bridge BARs + auxiliary BARs + alignment padding)
```

不能使用：

```text
aperture = sum(selected passthrough BAR sizes)
```

测试脚本还证明现代 virtio 辅助设备会消耗 high MMIO。精确 2 GiB profile 中，磁盘和
网络被切到 legacy virtio，让它们的 BAR 留在 4 GiB 以下；否则 OVMF 在 guest 入口前
就可能耗尽精确窗。

### 4.3 PXB 是 acpi layout 的最近库存近似，不是精确复制

i440fx + PXB 得到：

```text
PCI0 [bus 00-01]
PC02 [bus 02-03]
```

但 guest 还会看到：

```text
1b36:0009 QEMU PCI Expander bridge
1b36:0001 QEMU internal PCI bridge
```

VMware 实测为 `PCI0/PC08/PC0G` 三根，目标直接位于独立 ACPI root。PXB 在功能上
可以验证多根 ACPI `_CRS` 和独立 high window，却不能作为 guest ABI 逐字等价。

QEMU PXB 源码也明确会为传统 `pxb` 创建内部 `pci-bridge`：

- [QEMU pci_expander_bridge.c](https://gitlab.com/qemu-project/qemu/-/blob/master/hw/pci-bridge/pci_expander_bridge.c)

### 4.4 q35 root-port 是另一种近似

q35 + OVMF + `pcie-root-port` 保留 PCIe root-port 语义，但 guest 芯片组变为
Q35/ICH9，root port 变为 `1b36:000c`。VMware 两种 layout 都是 440BX/PIIX4。

因此库存 QEMU 的选择是：

| 方案 | 保留什么 | 丢失什么 |
| --- | --- | --- |
| i440fx + single root | 老式 PC、MMIO 行为简单 | VMware PCIe root-port 和多根拓扑 |
| i440fx + pci-bridge | 老式 PC、桥级 packing | PCIe root-port 语义；exact-2G 还会失败 |
| i440fx + PXB | 多 ACPI root、独立 high window | 多出 QEMU PXB/内部 bridge，root 数和 ID 不同 |
| q35 + pcie-root-port | PCIe root-port | 芯片组、ACPI layout 和设备 ID 不同 |

QEMU 官方文档也将 `pc-i440fx` 定义为 i440FX + PIIX3 machine，而不是 VMware
呈现的 440BX + PIIX4：

- [QEMU i440fx PC documentation](https://www.qemu.org/docs/master/system/i386/pc.html)

## 5. Qman 对标实现建议

### 5.1 profile 必须显式化

至少定义：

```text
vmware-esxi8u3-vhw20-create-bios-i440bx
vmware-esxi8u3-vhw20-create-efi-acpi
vmware-esxi8u3-vhw20-registered-efi-i440bx
vmware-esxi8u3-vhw20-explicit-efi-i440bx
```

每个 profile 固定：

- 创建来源和 resolved layout。
- firmware 及 hash。
- guest root topology、slot policy 和稳定设备 ABI。
- 所有虚拟设备和 passthrough BAR 集合。
- OVMF aperture 与 QEMU host `pci-hole64-size`。
- BIOS 下 mandatory BAR 失败策略。

### 5.2 创建时只解析一次默认

建议状态机：

```text
API CreateVM(vHW20, EFI, layout unset) -> acpi
API CreateVM(vHW20, BIOS, layout unset) -> i440bx
direct/import VMX with explicit layout  -> preserve explicit value
direct/import VMX with layout absent    -> import probe or i440bx-compatible fallback
resolved layout                         -> persist in VM definition and manifest
```

模板、克隆、恢复或版本升级后，输入与生效 layout 不同则拒绝自动启动，要求显式
ABI-change acknowledgement。这样可以消除 PCI slot 静默漂移风险。

### 5.3 启动门

```text
if layout == acpi and firmware != EFI:
    reject PROFILE_FIRMWARE_LAYOUT_MISMATCH

plan = pack_complete_bridge_tree(all_virtual_and_passthrough_bars)
if any mandatory BAR is unassigned:
    reject MMIO_RESOURCE_UNASSIGNABLE

if plan.high_aperture > 0:
    set X-PciMmio64Mb = plan.high_aperture / MiB
    set host_bridge.pci-hole64-size = plan.high_aperture
```

QEMU 接受命令行不是通过条件。冷启动后必须回读 guest `_CRS`、root resource 和每个
BAR，任何偏差都让 qualification 失效。

### 5.4 精确 guest ABI 的剩余风险

若 Qman 只要求能力等价，可用 i440fx/PXB/q35 三种库存近似并明确 profile 差异。

若要求 guest 看见与 VMware 相同的 7190/PIIX4、15ad root port、root ID、bus 范围和
45-bit 顶部 MMIO 基址，则库存参数无法完成，必须实现并维护专用 QEMU machine/ACPI/
bridge model。不能只修改 VID:DID 假装等价，必须重新验证 config space、PCIe services、
hotplug、reset、MSI/MSI-X、AER/PME 和 bridge window。

在该专用 machine 完成前，精确 ABI 能力必须标为 `BACKEND_TOPOLOGY_GAP`，不能宣告已消除。

## 6. 复现与证据索引

### VMware 四格和 key 缺省控制

```powershell
.\vmware-esxi8-lab\Test-EsxiFirmwareLayoutMatrix.ps1 `
  -HostName 172.31.91.10 `
  -RunId <run-id> `
  -BridgePolicy PcieRootPorts `
  -IncludeDefaultControls
```

只重建已有 artifact 摘要，不重启 VM：

```powershell
.\vmware-esxi8-lab\Test-EsxiFirmwareLayoutMatrix.ps1 `
  -RunId <run-id> `
  -BridgePolicy PcieRootPorts `
  -IncludeDefaultControls `
  -AnalyzeOnly
```

### CreateVM 默认值

```powershell
.\vmware-esxi8-lab\Test-EsxiCreateVmLayoutDefault.ps1 `
  -Firmware Efi -RunId <run-id> -PowerOn

.\vmware-esxi8-lab\Test-EsxiCreateVmLayoutDefault.ps1 `
  -Firmware Bios -RunId <run-id> -PowerOn
```

密码只从 Caveat 运行时读取，不进入脚本、artifact 或 Git。

### QEMU 七项矩阵

```bash
WORKDIR=/path/to/results \
BASE_IMAGE=/path/to/noble-server-cloudimg-amd64.img \
./qemu-firmware-layout-matrix-validate.sh
```

本轮本地 artifact：

```text
_artifacts/vmware-directpath-runs/20260715-esxi8-i440bx-pcie-rootports-v3/
_artifacts/vmware-directpath-runs/20260715-esxi8-acpi-efi-retry-v4/
_artifacts/vmware-directpath-runs/20260715-esxi8-layout-default-controls-v5/
_artifacts/vmware-directpath-runs/20260715-esxi8-api-createvm-assert-efi-v2-createvm-default/
_artifacts/vmware-directpath-runs/20260715-esxi8-api-createvm-assert-bios-v2-createvm-default/
_artifacts/mmio-tests/20260715-firmware-layout-matrix-final/results.tsv
```

原始日志和镜像保留在本地 `_artifacts`，Git 只提交脚本、报告和去敏机器摘要。
