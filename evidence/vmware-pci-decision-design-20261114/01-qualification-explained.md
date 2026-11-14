# 资格判断中的三个容易混淆的条件

这三个条件分别问：**管理员是否关闭了直通功能、IOMMU 是否能管理这个设备、PCIe 路径是否满足隔离策略。** 它们不是三份设备型号白名单。

<a id="disable-switch"></a>
## 1. `disablePciPassthrough` 是功能总开关，不是设备黑名单

在已核对的 ESXi build `24280767` 中，`SetFromSBDF` 读取名为 `disablePciPassthrough` 的运行选项，将结果保存到每个管理设备对象的 `+0x77` 字节。`IsPassthruCapable` 随后读取这个保存值：

| 保存值 | 含义 | 此关的结果 |
| --- | --- | --- |
| `1` / 非零 | 禁止 PCI 直通功能 | 立即返回 false |
| `0` | 没有用这个开关禁止直通 | 继续检查 IOMMU、ACS 和依赖 |

**它没有在这一步拿设备的 vendor/device ID 去查黑名单。**“对象保存”只是说同一个运行选项被存入设备对象，并不使它变成每种网卡各自独立的策略。它与针对特定设备的 quirk、功能依赖规则、兼容性目录也不是同一机制。

`0` 不代表默认批准所有设备；它只让后续资格检查继续。对象什么时候刷新，以及谁在何时改变运行选项，需要调用者与选项管理代码证明，不能由这两处字段读写推定。这里不提供未经核验的生产修改命令。[A02 写入者](../vmware-pci-assembly-dossier-20261114/snippets/A02.asm) · [A01 读取者](../vmware-pci-assembly-dossier-20261114/snippets/A01.asm)

<a id="iommu-scope"></a>
## 2. `inIommuScope`：IOMMU 是否能管理这个设备的 DMA

IOMMU 管的是**设备访问内存的地址转换和访问权限**。CPU 开启普通虚拟化，不等于设备 DMA 已经能被 IOMMU 管理；主机有 IOMMU，也不能仅凭这一点认定任意 PCI 设备都受当前 IOMMU 实现支持。

已核对的实际调用链是：

```text
IsPassthruCapable
  → 读取 VSI.inIommuScope(device)
    → Hardware_PCIIsInIommuScope
      → IOMMU_IsIommuEnabled()
      → IOMMU_IsDeviceSupported(device.SBDF)
```

在设备查找成功的正常路径上，**两项都成立才输出 true**：IOMMU 已开启；该设备被 IOMMU 实现判定为受支持。`IsDeviceSupported` 的完整架构后端尚未逐项还原，因此不能把这里擅自翻译成一份 VMware 网卡 HCL、设备驱动名单，或者枚举所有具体拒绝原因。[A04 完整提供者](../vmware-pci-assembly-dossier-20261114/snippets/A04.asm)

它与 ACS 的区别可以这样记：

| 问题 | 由谁回答 |
| --- | --- |
| 这个设备的 DMA 能否纳入 IOMMU 的转换和保护体系？ | 本节的 IOMMU 条件 |
| 设备能否沿某些 PCIe 同级路径访问另一个设备，绕过预期的 IOMMU 检查？ | ACS、拓扑和 DMA alias 等隔离条件 |

所以 `inIommuScope=true` 仍不足以证明可以把设备 A、B 安全分给两个互不信任的 VM。后面的 ACS 与依赖检查并非重复劳动。

<a id="acs-comparison"></a>
## 3. VMware 与 Linux 的 ACS 策略有什么区别

ACS 是 PCIe 的访问控制机制。这里关注的作用包括验证请求身份、限制同级请求/完成包的直接重定向，以及让需要隔离的访问沿上游路径处理。需要检查的是**路径、节点类型及相应控制状态**，并不是只问“设备有没有一个叫 ACS 的 capability”。

下面固定比较 ESXi `24280767` 的 M07 与上游 Linux **v6.6** 的源代码；不把我们的 ACS override 补丁当成上游默认行为。

| 比较点 | VMware 已见实现 | Linux v6.6 上游实现 |
| --- | --- | --- |
| ACS 判断被用在哪里 | `PCIE_EnforceACS` 的结果进入 `meetsPassthruAcsReq`，再进入设备的 capable 布尔值 | `pci_acs_enabled` / `pci_acs_path_enabled` 的结果参与 PCI IOMMU group 的构造 |
| 对缺乏隔离的处理 | 该资格路径可能返回 false；还有按类型处理、quirk 和策略例外 | 沿拓扑和 DMA alias 合并无法分隔的设备；不等于把全部设备永久禁止交给 VFIO |
| 判断是否只靠 ACS bit | 否：读取 capability/control，结合节点类型、quirk，并缓存结果 | 否：含设备特例、类型规则；单功能 endpoint 可因没有内部同级通道而通过，并非必须有 ACS capability |
| 所要求的位 | M07 有 `0x0c`、`0x1d` 等掩码和类型分支，不能缩写为单一固定掩码 | group 路径请求 SV、RR、CR、UF；具体设备判断再按 capability 和类型规则处理 |
| 软件放宽 | 所见代码有 `disableACSCheck`、特定 root-port 的 `disableACSCheckForRP` | 本仓库的 `pcie_acs_override` 补丁可令部分原本不满足的 ACS 判断返回通过；不是上游 v6.6 的标准开关 |
| 是否同时解决复位/功能依赖 | 否 | 否；IOMMU group 也不能代替全部复位和功能依赖模型 |

VMware 依据：[M07 原始指令](../vmware-pci-assembly-dossier-20261114/snippets/M07.asm)。Linux 依据：[PCI ACS 判断](https://github.com/torvalds/linux/blob/v6.6/drivers/pci/pci.c#L3556-L3684)、[PCI IOMMU group 构造](https://github.com/torvalds/linux/blob/v6.6/drivers/iommu/iommu.c#L1521-L1707)。

### 一个具体例子

A、B 位于不能提供所需隔离的桥下。Linux 可能将二者放入同一个 IOMMU group：**不让 A、B 被不同 DMA owner 分开使用，但仍可能允许满足其他条件后由一个 owner 接管整个组。** VFIO 文档以 group 表达这种所有权边界；采用较新的 device cdev / IOMMUFD 接口也没有取消“一组一个 DMA owner”的要求。[Linux 6.6 VFIO 文档](https://docs.kernel.org/6.6/driver-api/vfio.html)

不能据此承诺所有这种拓扑在 Linux 都能开机或正常复位；该例只说明“合并组”与“设备资格返回 false”是不同的产品处理方式，也不能从两个布尔函数的名字推断 ESXi 在所有拓扑上更严格或更宽松。

### 对我们默认开启 ACS override 的影响

本仓库补丁保留原始判断 `pci_acs_native_enabled`，再由 `pci_acs_enabled` 返回有效判断：原始条件通过则直接通过，否则检查是否命中 override。这个补丁的代码能证明**软件判定被放宽**，不能证明 PCIe 交换路径因此获得新的硬件隔离能力。[仓库补丁](../../kernel-patches/0001-PCI-expose-ACS-override-provenance.patch)

因此必须分别记录：原始拓扑/ACS/quirk 依据、是否依赖 override、最终 kernel group，以及 DMA alias、复位和功能依赖。override 可能使组变小，但并不移除实际 DMA alias 或共享复位范围。这里核对的是仓库代码和既定部署要求，没有重新验证当前运行内核已加载哪一版补丁。

另需区别：较新上游文档中的 `pci=config_acs` / `pci=disable_acs_redir` 涉及控制实际 ACS 设置，不能把它们与 `pcie_acs_override` 混为同一参数。关闭重定向可能降低隔离、使 group 变大。[Linux 6.18 参数文档](https://www.kernel.org/doc/html/v6.18/admin-guide/kernel-parameters.html)

<a id="sources"></a>
## 版本与出处

外部资料于 2026-11-14 核对；Linux 源码固定为 `v6.6`，文件 blob 标识记录于 [external-sources.json](external-sources.json)。VMware 的资格与 ACS 结论固定于 build `24280767`。本章没有将 `meetsPassthruAcsReq=true`、native ACS 谓词返回 true，或 override 后的 group ID 直接当成完整硬件验收结果。

[返回主设计文档](README.md#capable) · [API 启用直通链路](02-host-api-enable.md)
