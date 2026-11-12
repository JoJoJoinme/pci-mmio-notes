# 5 Why：机制根因与对产品的意义

**本次路径的机制根因：设备登记的新旧判断按单个 PCI 地址进行，而 IOMMU 域切换按共享身份的桥子树生效。第一个设备的初始化已经改变了第二个设备的底层状态，后续注册却仍要求“新登记设备尚无客体域关联”。这个前提在该拓扑与执行顺序下不成立。**

相同 build 的静态控制流和此前运行采样相互支持这一解释。状态仍应分开：机制已定位；保留共享 DMA 身份的修复尚未验证；厂商是否将该路径归类为缺陷或平台支持限制尚未确认。

## 五次追问

| 层次 | 因果问题与答案 | 支持证据 |
| --- | --- | --- |
| Why 1 | 为什么双设备 VM 没启动？第二个 Function 注册失败，使整次开机回滚。 | 原始任务回执和 vmware.log |
| Why 2 | 为什么第二个注册失败？普通新登记路径要求域查询返回“无客体域”；返回 Success 会直接进入警告和清理分支。 | PCIPassthruRegisterDeviceInt 的比较、分支及运行日志第 5294 行 |
| Why 3 | 为什么第二个已经有客体域？给第一个设备切换域时，内核找到最上层别名桥并遍历其子树，更新了包括第二个设备在内的域状态。 | IOMMU_SwitchAddressDomain、IOMMUSwitchDeviceIterator 和整体映射切换 |
| Why 4 | 为什么另一设备仍被当作新资源？登记表按各自 SBDF 查找记录。两个不同 PCI 地址可以各自是新登记，但不是两个可独立切换的 DMA 单元。 | PCISbdfMap_Find 与两个不同设备地址的配置 |
| Why 5 | 为什么同一 VM 也没解决？依赖/owner 相容性与域初始化是两套检查；后者仍依赖“新地址意味着未分配”的前提，未在本次分支把同一 VM 的共享关联视作可复用状态。 | 依赖遍历中的相同 owner 继续分支，与后续仅比较域查询状态的失败分支 |

硬件共享身份解释“为什么必须成组”；上下层操作粒度没有协调，解释“为什么本次成组仍失败”。前一个事实不能代替后一个根因。

## 同 build 的静态证据

从原系统盘只读提取 bootbank，boot.cfg build 为 `8.0.3-0.35.24280767`。检查解压后的 vmkernel ELF 和 sb.v00 内包含精确警告的 PCIPassthru ELF，未修改或执行这些二进制。

| 层 | 控制流事实 | 位置 |
| --- | --- | --- |
| 登记 | 用 PCISbdfMap_Find 查登记记录，另行遍历设备依赖 | PCIPassthruRegisterDeviceInt，模块 .text `0x4ca7`、`0x4df6`、`0x4e41` |
| 前置条件 | 查询域，只在状态等于 `0x0bad0003` 时从该检查继续；否则警告并清理 | 模块 .text `0x53da`—`0x5437` |
| 查询语义 | 无域或仍为 VMkernel 域返回上述状态；其他已有域返回 Success | IOMMU_GetAddressDomain |
| 作用范围 | 找到最上层别名桥，再遍历设备子树 | IOMMU_SwitchAddressDomain |
| 状态传播 | 子树回调更新与查询读取相同的设备域字段 | IOMMUSwitchDeviceIterator、IOMMU_GetDeviceDomain |
| 共享能力 | 底层存在“已有域等于目标域”的分支及引用计数处理 | IOMMUSwitchDeviceIterator |

底层具有共享处理能力，不代表上层会以正确状态调用它。这里的新登记检查已经提前拒绝；不能据此说整个 ESXi 都没有域共享能力。

也不能把所有“已存在”错误当作成功。正确处理必须证明相同 owner、相容地址空间和正确清理次序；简单绕过检查可能放过跨 VM 冲突。

[静态核对回执](source-analysis/static-path-verification.json)固定两份 ELF 的 SHA-256，核对符号、调用重定位、分支目标、状态常量和域字段等 31 项事实。它证明选定静态事实；机制解释同时依赖已有运行证据，不代表修复后运行成功。

公开包不分发 VMware 二进制或完整反汇编。持有同 build 合法副本的人可运行[只读脚本](verify_static_paths.py)：

```console
python verify_static_paths.py --pcip-module <PCIPassthru-ELF> --kernel <decompressed-k.b00>
```

## 对我们的产品意味着什么

**界面里的两行设备，底层可能属于一份必须共同管理的资源。整组占用、共享映射的生命周期和各设备自己的初始化，必须协调。**

我们[现有蓝图](../../qman-directpath-implementation-blueprint.md)已区分 kernel IOMMU group、physical isolation、requester alias、reset affected set 和最终 DependencyBundle。本次应检验这套模型是否落实到目标 backend，而不是新增“一律拒绝传统桥”的规则。

Linux VFIO 以 IOMMU group 为所有权单位，文档包含桥后多个 Function 的处理方式。[VFIO 文档](https://docs.kernel.org/driver-api/vfio.html#groups-devices-and-iommus)

蓝图采用的 Legacy 路径中，stock QEMU 5.0 的 vfio_get_group 遇到已有 group 且 AddressSpace 相同会复用；地址空间不同则拒绝。vfio_put_group 在仍有设备时不释放组。这是源码依据，不等于私有目标产品已通过运行验收。[QEMU 5.0 实现](https://github.com/qemu/qemu/blob/v5.0.0/hw/vfio/common.c#L1353)

产品需要验证：

- **整组准入和占用。** 不同 VM 不得占用同一不可隔离组；同一 VM 的成员不能各自启动互不知情的资源接管事务。
- **正确复用和初始化次序。** 使用 backend 的组语义，同时完成各设备的 BAR、IRQ 和驱动初始化。仅在 UI 自动补选后逐个独立接管不够。
- **可靠释放和回滚。** 一个成员失败或移除，不能破坏其他成员仍需要的共享状态。不支持部分释放时应明确拒绝；整次失败必须完整回退或进入明确的隔离恢复状态。
- **地址空间相容。** VM ID 相同不是所有重复关联都安全的证明。本次失败与成功日志均加载 viommu-none；启用 guest vIOMMU 的产品场景仍需单独验证。

## 之前少覆盖的一类验收

| 场景 | 已有证据 | 尚未覆盖 |
| --- | --- | --- |
| PCIe 独立请求者、共同复位依赖 | 同 VM 双设备启动；分拆后启动者失败；启用/禁用联动 | 不能替代共享 DMA 身份场景 |
| 传统桥共享 DMA 身份 | 第二项注册失败的运行链和静态机制 | 保留共享身份后的成功运行、guest I/O 和恢复 |
| 我们的产品 backend | 蓝图的完整组模型、stock VFIO/QEMU 的复用机制 | 私有目标实现的绑定、I/O、释放和故障恢复 |

换 PCIe 是绕开共享 DMA 身份的失败路径，验证了另一类依赖，不能给原传统桥用例盖“已修复、已验收”的章。

关闭修复与产品验收，需要保留原共享身份，验证同组双设备同 VM 的启动和实际 I/O、跨 VM 冲突拒绝、交换顺序与重复请求、第二项失败回退、单成员释放和进程崩溃后的资源恢复。目标代码、合成实验和物理平台 qualification 的通过应分别记录。
