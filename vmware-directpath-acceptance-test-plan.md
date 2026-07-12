# VMware VMDirectPath 实现细节验收目标与测试计划

日期：2026-07-11

## 1. 目的与范围

本文定义如何通过黑盒实验摸清 VMware ESXi 的 VMDirectPath I/O 和 Dynamic
DirectPath I/O 行为，并把已经实锤的 VMware 行为转化为 QEMU/OVMF/VFIO
侧的可执行核对表。

本项目不声称掌握 VMware 源码实现。只有同时记录输入、运行时观测和可重复结果，
才能把某项行为写成结论。

本地优先使用下面的实验拓扑：

```text
QEMU L0：可编程 PCIe 平台和底层 trace 观测点
  -> ESXi L1：被测 VMDirectPath 实现
    -> EFI Linux L2：观测 guest 可见 PCI/ACPI/资源分配
```

QEMU L0 可以逐项改变 PCIe 拓扑、ACS、multifunction、BAR 大小、Option ROM、
虚拟 VT-d 和 interrupt remapping，并从 ESXi 下方观察其 IOMMU、reset、DMA
和中断操作。这适合验证 VMware 的判定逻辑和虚拟硬件契约，但不能替代真实硬件上的
电气复位、ACS/P2P、RMRR、AER 和设备特有行为验证。

## 2. 验收目标

### 2.1 总体目标

最终应形成一份带版本的 VMware 行为画像，以及一份逐项对应的 QEMU 行为画像。
两边都必须有原始证据支持，而不是只比较参数名。

| 领域 | 必须回答的 VMware 问题 | 验收证据 |
| --- | --- | --- |
| 默认 MMIO 策略 | EFI + passthrough device，但没有 `pciPassthru.use64bitMMIO` 时，实际暴露哪些 below-4G/above-4G root window？ | VMX、`vmware.log`、guest ACPI `_CRS`、`/proc/iomem` 和 BAR 地址 |
| 显式 64-bit MMIO | 只有 `use64bitMMIO=TRUE` 时默认多大；显式 SizeGB 如何改变资源图？ | 同设备、单变量 A/B 测试和 guest 运行时证据 |
| 设备资格 | ACS、拓扑、multifunction、bridge 类型和 reset 能力如何影响 `passthruCapable`？ | vSphere API、host 日志和可控 QEMU 拓扑 |
| DMA 隔离 | ESXi 是否为被分配 requester ID 建立和撤销预期 IOMMU domain/translation？ | ESXi 日志加 QEMU L0 `vtd_*` trace，或裸机 IOMMU 证据 |
| 中断 | INTx、MSI、MSI-X 如何投递和重映射？ | guest 中断、ESXi 日志、L0 interrupt-remapping trace |
| Reset | power-on、reboot、power-off、crash 各使用什么 reset，影响哪些其他 function？ | reset trace、依赖关系和重复生命周期测试 |
| Expansion ROM | 默认只是禁止执行 ROM，还是连 guest 可见 ROM BAR 也不暴露？ | guest PCI config 和 firmware log 的前后对比 |
| PME/AER | 哪些事件由 ESXi 持有，哪些会进入 guest？ | 主动事件注入和 host/guest 成对日志 |
| Dynamic DirectPath | 如何选候选设备，何时设置 `assignedId`，多个 allowed device 如何计算资源包络？ | VM 开机前、运行中、关机后的 API 快照 |
| 生命周期 | snapshot、suspend、migration、hotplug、强制关机分别支持还是拒绝？ | API 结果、task fault 和操作后的设备状态 |

### 2.2 VMware 默认 MMIO 的最低验收条件

只有 `M00` 同时满足以下条件，才能接受“VMware 默认 EFI passthrough 没有显式
64-bit MMIO aperture”这个结论：

1. VM 中存在已经 active 的 passthrough device，而不是普通 EFI VM。
2. 生效 VMX 中 `pciPassthru.use64bitMMIO` 和
   `pciPassthru.64bitMMIOSizeGB` 确实 absent/false。
3. 已开机 guest 的 ACPI root bridge `_CRS` 和 `/proc/iomem` 明确显示是否存在
   above-4G PCI window。
4. 受控 64-bit BAR 的结果被记录为 below-4G、above-4G 或分配失败之一。
5. 三次干净 power cycle 得到相同分类。

现有普通 EFI VM 的 VMX 检查仍然是有价值的配置旁证，但因为当时没有 active
passthrough device，不能单独满足这项运行时验收。

### 2.3 QEMU 等价性的最低验收条件

QEMU profile 只有在以下可观测边界与 VMware 实测结果相符时，才能标记为等价：

1. Firmware 类型和 guest 可见 PCIe 拓扑。
2. ACPI root bridge 的 32-bit/64-bit memory window。
3. 相同 below-4G 压力下的 BAR 地址或失败边界。
4. Host DMA isolation 和 interrupt remapping 前提。
5. Multifunction 与 reset dependency 边界。
6. 场景涉及的 Option ROM、PME、AER 和生命周期策略。

“QEMU 成功启动”或“参数名字看起来对应”不算通过。

## 3. 证据等级与结论规则

| 等级 | 证据来源 | 允许得出的结论 |
| --- | --- | --- |
| E1 | Broadcom KB、vSphere API schema、QEMU/OVMF 文档或源码 | 官方契约或待验证假设 |
| E2 | 生效 VMX、`vmware.log`、ESXi API、`vmkernel.log`、L2 guest 输出 | VMware 黑盒运行行为 |
| E3 | QEMU L0 的 VT-d、PCI config、reset、DMA、中断 trace | ESXi 实际向底层平台发出的操作 |
| E4 | 裸机 ESXi + 真实 PCIe device | 真实复位、隔离、RMRR、P2P、AER 和硬件安全性 |

结论规则：

- 产品默认行为至少需要 E2。
- DMA、reset、中断机制尽量同时具备 E2 和 E3。
- “受支持等价”或硬件安全性结论必须有 E4。
- `pcie_acs_override`、VFIO no-IOMMU、unsafe interrupt 只能做反例，不能进入
  通过用例。
- 每项结论必须绑定 ESXi build、virtual hardware version、QEMU/OVMF build、
  device ID 和 host platform。

## 4. 测试产物契约

每次运行使用独立目录，并保存不可变的输入 manifest：

```text
results/<esxi-build>/<case-id>/<run-id>/
  case.json
  hashes.txt
  qemu-command.txt
  qemu-qmp.json
  qemu-trace.log
  esxi-about.json
  esxi-pci.txt
  esxi-passthru.json
  vm.vmx
  vmware.log
  vmkernel.log
  hostd.log
  guest-acpidump/
  guest-dmesg.txt
  guest-lspci-nnvvxxxx.txt
  guest-proc-iomem.txt
  guest-pci-resources.txt
  guest-interrupts.txt
  result.json
```

`case.json` 必须注明相对父用例唯一变化的变量。`result.json` 使用固定字段，方便自动
对比：

```json
{
  "passthruCapable": null,
  "passthruEnabled": null,
  "passthruActive": null,
  "dependentDevice": [],
  "assignedId": null,
  "rootWindow32": [],
  "rootWindow64": [],
  "bars": [],
  "iommuDomainObserved": null,
  "interruptRemappingObserved": null,
  "resetEvents": [],
  "powerResult": null,
  "failureId": null,
  "verdict": "not-run"
}
```

密码和实验室凭据只能从本地私有存储或进程环境读取，不得写入结果目录和 Git
仓库。失败用例的日志必须保留，不能只保留成功样本。

## 5. 入口门槛

| Gate | 必须达到的结果 | 未达到时如何处理 |
| --- | --- | --- |
| G0 ESXi 平台 | ESXi L1 启动、API 可用、检测到 virtual VT-d 和 interrupt remapping | 先修复 QEMU 平台，不进入 DirectPath 运行测试 |
| G1 设备资格 | 至少一个受控 endpoint 能变成 `passthruCapable` 和 `passthruActive` | 保留拒绝证据；改变 endpoint/reset capability，或实现小型 instrumented endpoint |
| G2 L2 枚举 | EFI L2 成功开机并枚举被分配 endpoint | 停止运行时等价结论，只保留 admission/configuration 结论 |
| G3 功能 I/O | L2 能制造已知 DMA 和中断 | DMA/interrupt 项保持未通过 |
| G4 可重复性 | 三次干净 cycle 和十次生命周期压力测试分类一致 | 排查 reset/state leakage |

Gate 失败本身是有效结论，不是丢弃日志的理由。

## 6. 受控 Endpoint 集合

| Endpoint | 用途 | 先确认的限制 |
| --- | --- | --- |
| QEMU e1000e | Multifunction、MSI/MSI-X、真实流量、DMA/interrupt trace | ESXi 资格和实际 reset capability |
| QEMU NVMe | PCIe endpoint、MSI-X、storage I/O 和 reset cycle | QEMU model 是否暴露 ESXi 要求的 reset |
| QEMU `edu` | MSI-only、双向 DMA、reset sentinel | 本地驱动和 direct/ESXi 两层验收已补齐；无 MSI-X、无可观测 reset callback |
| `ivshmem-plain` | 制造指定大小的 64-bit prefetchable BAR | ESXi eligibility 和 PCIe capability 必须实测 |
| Instrumented QEMU endpoint | 精确控制 FLR、D3hot、PME、AER、BAR、ROM | 需要单独维护 patch 和 build hash |
| 真实 NIC/NVMe/GPU/FPGA | E4 最终复核 | 需要裸机 ESXi 和安全的 device ownership |

## 7. 测试矩阵

### 7.1 平台与设备资格

| ID | 唯一变化变量 | 要回答的问题 | 通过证据 |
| --- | --- | --- | --- |
| A00 | ACS 正常的 root port 下放一个 endpoint | 基线设备能否 capable/active？ | API state、日志和 G1 结果 |
| A01 | 同一 root port 改为 `disable-acs=on` | 无 ACS 时 ESXi 拒绝还是扩大 dependency？ | `passthruCapable` 或 dependency delta |
| A02 | 同 slot function 0/1，只启用 function 0 | 是否自动发现 multifunction/reset dependency？ | `dependentDevice`、warning 或 power-on failure |
| A03 | A02 的两个 function 一起启用 | 集体分配是否满足 dependency？ | 两者同时 active 和 L2 topology |
| A04 | Endpoint 直接放在 root complex 下 | RCiEP-like 场景是否强制 FLR/D3hot？ | eligibility delta 和 reset 证据 |
| A05 | Endpoint 放到 conventional/legacy bridge 后 | 是否要求整个 requester-ID domain 集体分配？ | dependency list 和 collective assignment |
| A06 | 只改变 root-port `x-speed`/`x-width` | VMware 保留、屏蔽还是重建 L2 link capability？ | L1/L2 `LnkCap/LnkSta` 对比 |

### 7.2 MMIO 与 BAR 分配

固定 EFI L2 和 endpoint identity，只改变 BAR 大小、RAM 压力或指定 VMX 参数。

| ID | VMware 设置 | BAR 用例 | 必须得到的答案 |
| --- | --- | --- | --- |
| M00 | `use64bitMMIO` absent；SizeGB absent | 256M、512M、1G | 默认 root window 和实际 BAR 地址 |
| M01 | `use64bitMMIO=FALSE`；SizeGB absent | 同 M00 | 显式 false 是否不同于 absent |
| M02 | `use64bitMMIO=TRUE`；SizeGB absent | 1G、4G | 是否隐式得到 32G 或其他 high window |
| M03 | `use64bitMMIO=TRUE`；SizeGB=4 | 1G、4G | `_CRS` 大小、基址、对齐和失败边界 |
| M04 | `use64bitMMIO=TRUE`；SizeGB=32/64/128 | 大 aggregate BAR | Aperture 是否精确跟随 N，还是另有包络/对齐 |
| M05 | SizeGB=4；`use64bitMMIO` absent/false | 1G | SizeGB 被忽略、拒绝还是隐式启用 high MMIO |
| M06 | M00-M04 保持不变，仅增加 L2 below-4G 压力 | 256M、512M、1G | Legacy hole 耗尽时的 allocator 行为 |
| M07 | 多 endpoint 形成 aggregate BAR 压力 | 混合大小 | 单 BAR alignment 和总 aperture 计算 |

每个 M 用例都必须比较 VMX 输入和 `vmware.log` 中的生效配置，再比较 guest ACPI
`_CRS`、`/proc/iomem`、`lspci` 和 sysfs resource。Power-on failure 只有在同时
保存 VMware message ID、请求范围和可用范围时才算有效证据。

### 7.3 DMA、中断与 Reset

| ID | 操作 | 必须观察到的结果 |
| --- | --- | --- |
| D00 | L2 driver load 并持续 DMA | ESXi 启用 VT-d，为 endpoint requester ID 建立 context/domain，并发生 translation |
| D01 | 停止并关闭 L2 | Device 回到 host ownership 前，IOMMU translation 已撤销 |
| I00 | MSI-X 流量 | L2 vector 与 QEMU `vtd_ir_*`、device MSI-X trace 可以关联 |
| I01 | 支持时强制 INTx-only | 记录 shared-line 行为、延迟和 VMware warning |
| I02 | 设备/driver 支持时强制 MSI-only | MSI 保持 remapped 且功能正常 |
| R00 | 正常 L2 power-on/power-off | 记录 reset 类型和顺序 |
| R01 | L2 guest reboot | 判断是否 reset，以及 ROM/driver 能否再次初始化 |
| R02 | 强制 VM power-off 或 guest crash | Device quiescent，下一次开机成功 |
| R03 | 连续十次 start/stop | 无 stale DMA、stuck interrupt 或 wedged device |
| R04 | 只分配一个 function，但 reset 会影响同 bus 其他 function | VMware 检出或拒绝不安全 dependency |

不能只根据 PCI capability bit 推断 reset 方法。嵌套实验使用 QEMU config-space 和
device reset trace；裸机使用 `/reset_method`、设备日志和外部行为复核。

### 7.4 ROM、PME、AER、P2P、RMRR 与 Dynamic DirectPath

| ID | 测试 | 验收边界 |
| --- | --- | --- |
| S00 | 默认 passthrough device 带 Expansion ROM | 分别判断 ROM BAR 是否可见、firmware 是否执行 |
| S01 | `pcipSaveOPROM=TRUE` 加 `<device>.opromEnabled=TRUE` | OVMF 执行目标 ROM，restart 可重复 |
| S02 | Guest 启用 PME，endpoint 发出 PME | 判断 ESXi 是否忽略，以及是否要改 guest `_OSC` policy |
| S03 | 注入 Correctable Receiver Error 与 Non-Fatal Unsupported Request | 已执行；确认 guest AER header/ACPI ownership 被过滤，raw status body 保留，host/guest 日志均静默 |
| S04 | 两 endpoint 执行真实 peer DMA | 对比默认、`allowP2P`、`relaxACSforP2P`；只看 ACS bit 不算通过 |
| S05 | Endpoint 带关联 RMRR | 观察 memory-map 自动调整或精确 overlap failure |
| X00 | 两个相同 ID 的 Dynamic DirectPath candidate | 记录 allowed list、`assignedId` 和关机解绑 |
| X01 | Allowed candidate 有不同 BAR/RMRR 包络 | 判断 admission 为选中设备还是所有候选预留 |
| X02 | 开机时某 candidate 不可用 | 记录 selection fallback 和 task fault |

Stock QEMU 6.2 足以做第一批 ACS、topology、BAR、VT-d、interrupt、基本 reset 和
AER 注入。AER 已证明 stock QEMU 的 guest surface 不等价，完整过滤仍需 QEMU patch；
PME/RMRR/P2P 可能需要 instrumented endpoint、DMAR table patch 或真实硬件。

### 7.5 生命周期与产品限制

| ID | 操作 | 通过条件 |
| --- | --- | --- |
| L00 | 请求 snapshot | 结果和 task fault 符合目标 VMware 版本契约 |
| L01 | 请求 suspend/resume | 明确拒绝，或对精确 device/profile 证明安全 |
| L02 | 请求 live migration/vMotion | 保存结果、placement restriction 和 device state |
| L03 | L2 关机时重启 ESXi | Passthrough activation 和 ownership 可预测恢复 |
| L04 | L2 运行时强制关闭 ESXi | 下一次 host/VM boot 不保留不安全状态 |
| L05 | 删除并重新添加 passthrough 配置 | 记录 reboot/rebind 要求和 API state transition |

## 8. QEMU 侧核对表

本表必须由 VMware 实测输出回填。下列参数是当前候选，不是 VMware M 系列用例的
替代品。

| 项目 | QEMU/OVMF/VFIO 控制 | 验收方法 |
| --- | --- | --- |
| Machine/Firmware | q35 + OVMF + 显式 `pcie-root-port` | Guest topology 和 ACPI table 与 VMware profile 一致 |
| VMware 默认 high-MMIO 候选 | `X-PciMmio64Mb=0` + `q35-pcihost.pci-hole64-size=0` | 仅当 M00 证明没有 above-4G root window 时采用 |
| 显式 N-GB high MMIO | `X-PciMmio64Mb=N*1024` + `pci-hole64-size=NG` | 比较实际 `_CRS` 和 BAR 地址，不只比较配置 N |
| 只设置 OVMF knob | 禁止作为通过配置 | 本地已证明 QEMU host bridge 仍可暴露 above-4G space |
| 只设置 host-bridge knob | 禁止作为通过配置 | OVMF 仍可能把 BAR 放到 4G 以上并迫使 ACPI 覆盖 |
| Below-4G 压力 | 对齐 RAM 和其他 virtual device BAR 消耗 | BAR 地址或失败边界一致 |
| Host IOMMU | 裸机 VT-d/AMD-Vi、真实 IOMMU group、`vfio-pci` | 无 VFIO no-IOMMU 和 unsafe interrupt mode |
| Guest vIOMMU | 目标 VMware VM 未暴露时不添加 | Guest DMAR/IOMMU presence 与 VMware 一致 |
| ACS | Physical ACS + clean group；虚拟拓扑使用 q35 root-port ACS | 通过 profile 不使用 ACS override |
| Multifunction | 同 slot 不同 function，`multifunction=on`，分配所有 reset-dependent function | Group membership 和 L2 topology 一致 |
| Reset | Host `reset_method`；bus-wide reset 时集体分配 | 十次 lifecycle cycle，无 stale DMA/interrupt |
| MSI/MSI-X/INTx | VFIO 默认路径 + host interrupt remapping | Guest mode 和 host remapping 证据一致 |
| Resizable BAR | 固定 host BAR size，不依赖 guest 改 ReBAR | 记录 guest capability 和 effective BAR size |
| Expansion ROM | 暂以 `rombar=0` 为候选，等待 S00/S01 定案 | 分别匹配 ROM BAR visibility 和 firmware execution |
| PME/`_OSC` | Root-port hotplug 参数不等于 `acpi.osc.pcie` | 比较反编译 ACPI grant 和实际 PME 注入结果 |
| AER | stock QEMU 无完整等价参数；`vfio-pci` 需过滤 `PCI_EXT_CAP_ID_ERR`，Root Port 需 `aer=off` 类开关 | guest header/body、ACPI `_OSC`、host/guest log 三方比较 |
| P2P | 没有通用 QEMU 开关等价于 VMware policy | 实际 peer DMA 成功或按预期阻断 |
| RMRR | 优先使用无 host reserved-memory dependency 的设备 | 无 unsafe patch，attach 和 identity map 无异常 |
| Memory pinning | Prealloc/hugepage memory + 足够 memlock | 负载下无 VFIO mapping failure |
| NUMA | vCPU 和 memory 绑定 device 所在 NUMA node | Locality 和性能计数符合 profile |
| Dynamic DirectPath | 外部 launcher 按 ID/label 选择 BDF 后启动 QEMU | Selection log 对应 VMware `allowedDevice`/`assignedId` |
| Lifecycle | 普通 VFIO 默认视为不可迁移，除非证明 device-specific migration | 不支持操作明确失败且 device 仍可用 |

当前 VMware 默认 MMIO 候选命令：

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

只有 M00 提供 active-passthrough guest 证据后，这段命令才能从“候选”升级为
“已验收 VMware 默认 profile”。本地 QEMU 已经证明，只设置 `fw_cfg` 而保留默认
`pci-hole64-size` 时，Linux 仍可能把 BAR 分配到 4G 以上。

需要特别区分属性名：本项目讨论的是 above-4G 的 `pci-hole64-size`。本地 QEMU
6.2 中 i440fx 默认值为 2G，q35 默认值为 32G；它不是 below-4G `pci-hole-size`。

## 9. 推荐执行顺序

1. 固定 ESXi/QEMU/OVMF build，先实现产物自动采集。
2. 执行 G0，保存无 passthrough 的平台 baseline。
3. 执行 A00-A03，确认 synthetic endpoint 能否进入 active DirectPath，以及
   VMware 如何计算 dependency。
4. 使用 256M 和 1G BAR 执行 M00-M03，以最少用例回答主 MMIO 问题。
5. 打开 QEMU `vtd_*` 和 device trace，执行 D00、I00、R00-R03。
6. 扩展到 M04-M07、A04-A06 和 Dynamic DirectPath。
7. 只针对仍未回答的 reset/PME/RMRR 问题实现 instrumented endpoint；AER 转为实现并验证 config-space filter。
8. 在裸机 ESXi 上用至少一个真实 NIC/NVMe 重放已通过用例；只有 large BAR/P2P
   场景再引入 GPU/FPGA。

## 10. 完成标准

测试计划完成必须同时满足：

1. 每个适用测试项都有 `pass`、`fail` 或精确的 `blocked-by-platform`，没有静默省略。
2. M00 和选定的显式 MMIO 用例至少有三次可重复 E2 结果。
3. DMA、MSI-X 和 reset 有关联后的 E2/E3 证据。
4. 真实硬件结论有 E4，无法取得 E4 的项目明确标记未验证。
5. 最终 QEMU profile 通过与 VMware profile 相同的 guest resource 和 lifecycle 检查。
6. 所有脚本、规范化结果、非敏感日志和结论表都能从仓库复现。

## 11. 2026-07-11 本地执行状态

详细输出和推理见 `vmware-esxi8-directpath-local-results.md`。本轮使用两台 ESXi
8.0.3 build 24280767、VCSA 8.0.3、vHW 20 EFI L3、QEMU 6.2、virtual VT-d 与共享 NFS。

| 范围 | 状态 | 结论 |
| --- | --- | --- |
| G0-G4 | pass | L3 枚举、真实 e1000e I/O、三次以上干净运行和十次 start/stop 均完成 |
| A00/A02/A03 | pass | PCIe baseline 与 multifunction function 独立 owner 行为已记录 |
| A01 | nested-platform-only | 无 ACS 时 ESXi 明确记录 bypass；本机 `enableACSCheckForRP=FALSE`，不能外推生产安全性 |
| A04 | pass | root-complex 直挂设备为 `Reset=None`、`Capable=false` |
| A05 | pass | legacy bridge 后所有 endpoint 共用 bridge dependency，启用一个会自动启用全部 |
| A06 | pass | L1 2.5GT/s x1 被 VMware 在 L2 重建成 5GT/s x32 |
| M00-M03/M05/M06 | pass | 1GB 默认低置；2GB 在 absent/false/true/Size 变体下均自动高置 |
| M04 4GB | pass | absent/Size4-only 超过 917504-page limit；TRUE-only 与 TRUE+Size4 均通过 |
| M04 8GB | partial/platform-boundary | sparse 8GB mapping 可建立，但 EFI guest 无 heartbeat |
| M04 32/64GB | pass-mapping | no-backing `pci-testdev` 验证 gate/SizeGB/page budget；成功映射后 EFI guest 仍无 heartbeat，故不声称 runtime pass |
| M07 aggregate | pass | 2x1GB 低置；单 2GB 高置；1GB+2GB 形成 3GB DirectPath 高 range |
| D00/I00 | pass | requester `01:00.0` 的 VT-d translation 和 MSI-X interrupt remap 已关联 |
| D01 | partial | power cycle 有 domain IOTLB invalidation；完整 context teardown 未直接导出 |
| I01 | nested-functional-fail | `pci=nomsi` 得到 legacy IO-APIC，但 11 个样本 IRQ/tx 均为 0；同 ISO QEMU direct pass |
| I02 | pass | MSI-only EDU 两阶段各完成 1 个软件 IRQ、2 个 DMA completion IRQ；Guest IOVA、物理 MSI 和 VT-d/IR trace 已关联 |
| R00 | partial-observed | EDU sentinel 证明 ESXi 打印 reset 流程但 warm reboot 后端点状态 persisted；精确 FLR/SBR/D3 类型仍需有 reset callback 的 endpoint 或 E4 |
| R01 | pass | efivar phase marker 证明 reboot 前后各完成一次 e1000e I/O，最终正常解绑 |
| R02/R03 | pass | DMA 后 forced-off 可重启；十次快速 start/stop 全通过 |
| R04 | pass | legacy bridge requester-ID dependency 被 ESXi 自动集体启用 |
| S00 | pass | outer e1000e 有 ROM BAR，DirectPath guest 默认不见该 ROM BAR |
| S01/S02 | blocked-by-endpoint | 缺少已验证 OPROM 重启链和可控 PME 注入 |
| S03 | pass | boot-only 开启 ESXi PCI error reporting 后，Correctable 与 Non-Fatal 均完成 host/guest/config/log 三方采集 |
| S04/S05 | blocked-by-endpoint | 无 peer-DMA endpoint 和可控 RMRR |
| X00 | pass | 相同 allowed ID 获得不同 `assignedId`，关机后自动清空 |
| X01 | pass | 相同 VID:DID 的 1GB/2GB candidate 先选择再按实际 BAR 建 envelope |
| X02 | pass | candidate 耗尽得到 `NoCompatibleHost`；释放后同配置重试成功 |
| X03 | pass | powered-off relocate 后目标 host 重新解析 `assignedId` |
| L00/L01 | pass | snapshot 与 suspend 均按产品限制返回 `vim.fault.InvalidState` |
| L02 | pass | 普通 VM live vMotion 成功；Classic/Dynamic DirectPath live vMotion 按预期拒绝 |
| L03/L05 | pass | host 重启和 `--apply-now` owner 切换状态已记录 |
| L04 | pass | DMA/heartbeat 时 SIGKILL outer QEMU；host/datastore/owner 恢复且同 VM 再次 I/O 成功 |
| SeaBIOS boundary | pass | fw_cfg 被忽略；host hole64 控制默认窗，但 present BAR 可迫使最小高窗 |

## 12. 参考资料

- Broadcom KB 312208，VMDirectPath/Dynamic DirectPath requirements：
  https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html
- vSphere API `HostPciPassthruInfo`：
  https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PciPassthruInfo.html
- vSphere API `HostAssignableHardwareManager`：
  https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html
- vSphere API `VirtualPCIPassthroughDynamicBackingInfo`：
  https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html
- QEMU tracing documentation：
  https://www.qemu.org/docs/master/devel/tracing.html
- QEMU EDU device specification：
  https://www.qemu.org/docs/master/specs/edu.html
- 本地已执行 QEMU 证据：`qemu-vmdirectpath-nonbar-local-validation.md`
- 现有 VMware MMIO/QEMU 映射说明：`vmware-passthrough-mmio-validation.md`
