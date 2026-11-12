# 传统 PCI 桥下双设备注册失败的定位

本报告聚焦一个问题：A、B 已经同时配置给同一台 VM，为什么放在 `pcie-pci-bridge` 后面仍不能开机？

**机制根因已定位，修复尚未验证。** 同 build 静态检查进一步确认：登记的新旧判断按 SBDF，底层切域按别名桥子树生效；“新设备尚无客体域”的前提会被前一个成员的初始化破坏。厂商缺陷归类和物理平台适用范围仍未确认。完整 5 Why、静态核对与产品影响见[根因状态与产品意义](ROOT-CAUSE-STATUS.md)。

2026-11-13 后续已实际升级并复核 ESXi 8.0 U3k / 25595708 与 ESX 9.1.0.0100 / 25433460，二者仍复现；9.1 原生 PCI e1000 控制也复现。新版汇编条件、任务回执与软件侧归因见[问题归因与新版本复核](../vmware-passthrough-version-review-20261113/README.md)。最新 9.1.1.0100 未测试，不能据此判断其修复状态。

2026-11-12 的新控制实验把失败定位到 **ESXi 注册第二个 Function 时对已有 IOMMU 域的检查**。在第一个 Function 成功注册后，桥及两个 Function 的 VT-d context 已指向相同的域和页表；第二个 Function 随后反复报 `Expected no IOMMU domain ... got Success`，VM 开机回滚。这是本次 ESXi 8.0.3 build-24280767 与 QEMU 11.0.2 组合中的实际失败路径。

这不等于“传统桥从原理上不能把两个设备交给同一台 VM”。共享请求者 ID 要求共同分配，本来就应由共享域实现。Broadcom 也明确要求桥后的 Functions 共同分配，但不推荐这类拓扑，推荐 PCIe root port 或 switch downstream port。[官方要求 KB 312208](https://knowledge.broadcom.com/external/article/312208)

## 为什么桥改变了问题

两种拓扑的差异不只是多一个中间节点。

| 项目 | `pcie-pci-bridge` 下 | 直接挂在 `pcie-root-port` 下 |
| --- | --- | --- |
| Function 配置地址 | A=`02:01.0`，B=`02:01.1` | A=`01:00.0`，B=`01:00.1` |
| QEMU 给 IOMMU 的 DMA 请求者 ID | 两项都别名为 `02:00.0` | 保留各自 Function 的 BDF |
| Host API 的 dependentDevice | `0000:01:00.0` | 标记完整时均为 `0000:00:08.0` |
| 本次同 VM 双设备开机 | 第二个 Function 注册失败 | 成功 |

`dependentDevice` 是依赖信息，不能直接当作 DMA requester ID。QEMU 对真正的 PCIe-to-PCI bridge 使用“桥的 secondary bus + devfn 00.0”作为代理 ID，所以本例是 `02:00.0`，不是界面里的两个 Function 地址，也不是桥自身的配置地址 `01:00.0`。

QEMU 的 `pci_device_get_iommu_bus_devfn()` 明确实现这项别名处理。当前本地的 PCI 核心、VT-d 实现、VT-d 定义和桥设备源码均与官方 v11.0.2 对应文件逐字节相同；[源码比较回执](source-analysis/comparison.json)包含来源 URL 与 SHA-256。[官方 PCI 源码](https://github.com/qemu/qemu/blob/v11.0.2/hw/pci/pci.c#L2936)

## 新实验的直接观察

新建独立覆盖盘，保持传统桥、e1000e 和原 ESXi build，为两个 Function 都设置 `multifunction=on`。没有启动 vCenter。每次仅对实验 VM 执行配置和开机，完成后关机，再执行下一项。

| 控制项 | 结果 |
| --- | --- |
| 同 VM 先 A 后 B | A 注册成功，B 的域检查失败，VM 最终 poweredOff |
| 同 VM 先 B 后 A | B 注册成功，A 的域检查失败，VM 最终 poweredOff |
| 只给 VM 分配 A | poweredOn |
| 只给 VM 分配 B | poweredOn |

[完整任务矩阵](raw/native-mf-results.json)、[A+B 任务](raw/native-mf-power-both.json)、[B+A 任务](raw/native-mf-power-reverse.json)。两项 Header Type 均为 `0x80`，因此本轮失败不能归因于 Function 1 缺少多功能标记。

开机期间只读采样 VT-d 根表和 context 表。在 A+B 测试中，`01:00.0`、`02:00.0`、`02:01.0`、`02:01.1` 的 context 一起从基线 domain 1 / page table `0x10b25b000` 切到 domain 2 / page table `0x168ddb000`，失败后又回到基线。[采样原始值及解码](raw/native-mf-context-both.json)

反序测试同样出现四项一起切换到同一个域及页表，然后回退。只启动 A 或只启动 B 时，也会把这组 context 一起切换，但 VM 可以保持开机。这说明 ESXi 确实对桥后的地址作了整体映射；问题出现在继续注册第二个 Function 的阶段。[反序采样](raw/native-mf-context-reverse.json)、[A 单独启动](raw/native-mf-context-a.json)、[B 单独启动](raw/native-mf-context-b.json)

结合 vmware.log 和 vmkernel.log，失败过程可以表述为：

1. 第一个 Function 获得直通设备记录并注册成功。
2. 共享请求者所对应的 context 组已经关联到新域。
3. 初始化第二个 Function 时，检查期望没有已关联的 IOMMU 域，实际查询返回 Success。
4. 第二个 Function 的初始化记录被销毁，多次重试仍失败。
5. VM 返回 DevicePowerOn；第一个 Function 的域被禁用，映射回退。

这里的 Success 是域查询的返回结果，不是第二个设备启动成功。日志与表采样确定运行过程；同 build 静态控制流进一步确认：此新登记分支按“无客体域”状态继续，对已有域直接警告并清理。它没有在这个检查处比较已有域是否就是当前 VM 的目标域。解释依据是二进制控制流与运行证据，不是厂商源码或已验证的修复。

## 成功场景也共用同一个域

另建相同 ESXi build、相同 8 GiB / 4 vCPU、相同 e1000e 双 Function 的独立 PCIe 对照，两个多功能标记均开启，map 保持默认。A+B 和 B+A 都成功。读取成功后的 context，两个独立 RID 都指向同一个 domain 2 和同一张页表：正序为 `0x1a724d000`，反序为 `0x164e2a000`。[正序任务](raw/root-control/root-control-power-both.json)、[正序映射](raw/root-control/root-control-context-both.json)、[反序映射](raw/root-control/root-control-context-reverse.json)

所以，“ESXi 必须给同一 VM 的每个设备各建一个独立域”不符合本次实测。需要区分 **域对象可以共享** 与 **某个请求者 ID 是否已经关联过域**：

```text
PCIe：       RID 01:00.0 ─┐
                        ├─ 同一个 VM 的域 D     → 双设备注册成功
             RID 01:00.1 ─┘

传统桥：A、B ─→ 同一 RID 02:00.0 ─→ 域 D
                         第一个注册者建立关联
                         第二个注册者查到已有域 → 本次检查拒绝
```

这把实现层推断进一步缩小为：本路径没有把共享 DMA 身份的第二次关联当作“已属于同一 VM 的可复用关联”处理。不能将其描述为两个设备需要不同 VM 域、两个域相互争抢，或 IOMMU 不能把两个设备放入同一个域。域编号只是在本轮启动期间分配的值，不是固定 VM 编号。

单设备对照也直接显示了区别：PCIe 中只启动 A 时，A 切到 domain 2，B 保持基线 domain 1；只启动 B 时相反。传统桥下，只启动 A 或 B，四项 context 都一起切到新域。因此在 PCIe 中，注册第二项时仍有独立的请求者关联可建立；在传统桥中，第一个设备已经覆盖共享身份。[PCIe A 单独启动的映射](raw/root-control/root-single-context-a.json)、[PCIe B 单独启动的映射](raw/root-control/root-single-context-b.json)

## 排除项和仍待确认的内部机制

此前使用原生 conventional PCI 的 e1000 模型、交换设备顺序，也出现同样的第二项域检查错误，因此不能只用“e1000e 是 PCIe 模型，放到 PCI 桥下不合适”解释全部结果。本轮又排除了缺少多功能标记。单设备能启动、双设备失败阶段明确，也不支持把本次失败泛化成普通内存不足、guest 驱动失败或所有设备都不可用。

还写入 `8086 10d3 default false`，持久化并重启，确认两个 Function 的 VSI `fptShareable` 均为 `0`。正序和反序双设备仍失败，仍在第二项已有域检查处退出。这排除了“只因未声明不可跨上下文共享”的解释。[规则生效读回](raw/control-map-effective.json)、[规则生效后的任务矩阵](raw/nonshareable-results.json)

ESXCLI 在本例仍把两项的 FPT Sharable 显示为 true，与底层 VSI 不一致；生效判据使用持久化规则、变化后的启动时间和两个 VSI 读回，不用 ESXCLI 单字段反推未生效。规则也匹配管理网卡，因此变更前核对其原本已为不可直通、VMkernel owner、FPT false，没有对管理网卡切换 owner；试验后恢复了原始 map 并持久化。

静态检查已定位到新登记前置条件与整组切域作用范围的冲突；**仍没有厂商确认的缺陷编号，也没有在保留共享 DMA 身份下完成修复验证。** 本报告不把所有真实 PCIe-to-PCI 桥都判定为不可用，也不把同一 VM 配置成功视作运行正确性的保证。没有运行 guest OS 的设备 I/O，尚未验证真实 DMA、复位质量及物理平台兼容性。

## 对此前 PCIe 修复说明的澄清

此前两处改动应分别理解：

- 移除传统桥、让设备直接位于 PCIe root port 下，保留了独立的 DMA 请求者 ID，避开本次传统桥的共享域注册失败路径。原始 PCIe 基线在 Function 1 多功能位为 0 时，同 VM 双设备已经能启动。
- 再补 Function 1 的 `multifunction=on`，使本例 ESXi 将两项识别为共同复位依赖，形成“同 VM 成功，跨 VM 后启动者失败”的对照。它不是同 VM 启动成功的唯一原因，也不能修复本轮旧桥下的双设备注册失败。

参见[此前成功对照及单变量矩阵](../vmware-pci-multifunction-fix-20261111/README.md)。

## 采集范围

VT-d 采样通过 QEMU qtest 执行只读 `readl/readq`，未写 IOMMU 表，也未关闭隔离。每轮保存状态变化、采样次数和错误；单次多表项读取不是原子快照，时间线不得作亚毫秒级跨时钟排序。历史未启用这些采样的实验也有相同失败。

公开包保留任务回执、context 采样、选取的原日志行、源码哈希和实验脚本；不包含凭据、虚拟磁盘、完整宿主机日志或 VMware 二进制。脚本快照是最终采集版本；root-control 和 root-single 另保留实际执行时的脚本字节。

收尾恢复传统桥实验的原始 map，禁用目标设备，正常关闭两套 ESXi 实例并撤除专用 TAP。基础系统盘、数据盘和 OVMF 变量模板哈希未变；实验 VM 配置保留在独立覆盖盘中。为释放实验内存而保存的 `win10-home` 在结束后恢复运行，vCenter 本轮没有启动。

见 [逐文件 SHA-256 清单](manifest.json)、[机器摘要](summary.json)、[传统桥实例收尾](raw/finish-runtime.json)、[PCIe 实例收尾](raw/root-control/finish-runtime.json)和 [Hyper-V 状态恢复](raw/finish-hyperv-restoration.json)。离线核验：

```console
python evidence/vmware-legacy-bridge-cause-20261112/verify_bundle.py
```
