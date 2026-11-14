# VMware 的 ACS 检查：类型、quirk 和策略例外分别是什么

之前“可能返回 false；还有按类型处理、quirk 和策略例外”过于概括。具体说：**这一版 ESXi 沿上游 PCIe 路径检查，不同类型要求不同条件；特定 Intel 设备改用不同的控制寄存器偏移；遇到不合格条件时，软件 bypass 还可能将本次 ACS 判定改为通过。** 这三件事不是同一种“白名单”。

本章固定于 ESXi `24280767` 的 `PCIE_EnforceACS` 完整函数 M07，并补充 `PCIQuirks_GetAcsCtrlOffset` 的完整 83 字节函数 Q01。下面是代码重建，不代表所有版本完全一致，也不声称进行了新的硬件实验。

<a id="cap-control"></a>
## 1. 先区分“硬件声称支持”与“当前配置启用”

- **ACS Capability：**相关能力信息。
- **ACS Control：**当前的控制设置。

某项能力存在但没有按要求配置，仍可能不通过 ESXi 的检查。M07 先定位 extended capability `0x0d`，读取其 `+4` 能力寄存器，再通过 quirk 函数决定控制寄存器偏移并读取控制值。

本章用到的常规位如下，标准位名可由 [Linux v6.6 PCI 寄存器定义](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/pci_regs.h#L980-L991)复核：

| 位/掩码 | 含义 | 对隔离的作用 |
| --- | --- | --- |
| `0x01` / SV | Source Validation | 验证请求源身份 |
| `0x04` / RR | P2P Request Redirect | 控制同级请求的重定向路径 |
| `0x08` / CR | P2P Completion Redirect | 控制同级完成包的重定向路径 |
| `0x10` / UF | Upstream Forwarding | 控制向上游转发 |
| `0x0c` | RR + CR | 本函数中的成对重定向检查 |
| `0x1d` | SV + RR + CR + UF | 下游端口分支中的组合要求 |

不要只看一次 `lspci` 显示“有 ACS”，就认定路径检查一定通过。也不能把某个 capability bit 缺失一概解释为硬件不能隔离；具体类型的标准规则与软件判断还需分别阅读。

<a id="types"></a>
## 2. “按类型处理”具体检查了哪些类型

M07 从 PCIe 能力信息取 Device/Port Type，重点分支是 `0`（普通 endpoint）、`4`（root port）、`6`（downstream port）。这些是 PCIe 类型值，不是 PCI class code。[类型值定义](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/pci_regs.h#L471-L484)

以下条件假定配置读取成功，并且尚无可复用的缓存结果。`C` 表示能力值，`T` 表示控制值。

| 当前节点类型 | 没找到 ACS capability | 找到了 ACS capability |
| --- | --- | --- |
| 普通 endpoint，type 0 | 不因这一点单独拒绝，继续检查父级 | 若 `(C & 0x0c)==0x0c`，要求控制中的 RR/CR 都打开；随后继续父级。不能把这一分支概括成“任意 endpoint 都要求全套 ACS 位”。 |
| Root port，type 4 | 进入不合格处理，再看软件 bypass | 先做相同的 RR/CR 条件检查；再令 `required=0x01 + ((C << 2) & 0x10)`，要求能力和控制都包含 required。这是代码中的条件化要求，不是无条件检查固定 `0x1d`。 |
| Downstream port，type 6 | 进入不合格处理，再看软件 bypass | 要求能力和控制都包含 `0x1d`；不满足则进入不合格处理。 |
| 这段筛选未选中的其他类型，或没有该 PCIe 信息指针 | 本函数继续向父级检查 | 不能从本函数跳过它，推导整个直通系统忽略它的 DMA alias 或其他依赖。 |

Root port 的公式意味着：总要求 SV；当能力中的 RR 位为 1 时，额外要求 UF。它与前面的 RR/CR 成对检查是两段逻辑。这里按指令保留这个差别，不把它润色成一条更整齐但不真实的“所有端口四位必须全开”。

Root/downstream 的所示路径还检查扩展内存目标访问控制：当能力 bit 7 置位时，要求控制 bits 11:8 等于 `0xa`，否则记录 `ACS Memory Target Access Control not configured` 并进入不合格处理。本章保留这个数值条件和日志含义，没有把它扩展成所有 PCIe 代际的完整规范解释。

具体地址：类型筛选在 `0x4200000f5328`–`0x4200000f5344`；重定向分支在 `0x4200000f53bc`、`0x4200000f54a8`；root port 条件在 `0x4200000f53cb`；下游端口掩码在 `0x4200000f549e`。[M07 完整汇编](../vmware-pci-assembly-dossier-20261114/snippets/M07.asm)

读取失败时，所见代码有 `0xffff` 回退值；不能把上述成功读取条件直接改写成“任何读取失败都立即返回 false”。完整异常含义仍以原指令为准。

<a id="quirk"></a>
## 3. quirk 的具体例子：控制寄存器偏移从 +6 改为 +8

这次取得的 Q01 直接说明，`PCIQuirks_GetAcsCtrlOffset` 在这里并不是简单地“这家厂商免检”。它返回读取 ACS Control 所用的相对偏移：

| 匹配条件 | 返回偏移 |
| --- | --- |
| vendor 不是 `8086` | `6` |
| vendor=`8086`，device 在 `a110–a11f`、`9d10–9d1b`、`a290–a29f`、`9db0–9dbf` 之一 | `8` |
| 其余匹配不到的设备 | `6` |

M07 把这个偏移加到 ACS capability 起始地址，再读取控制寄存器，后续仍执行相应位检查。**这是按设备型号适配寄存器读取位置，不是把检查结果无条件改成 true。**

例子：一个匹配 `8086:a110` 的设备，控制值来自 ACS 起始位置 `+8`；普通路径则来自 `+6`。如果读错位置，后续位判断当然可能出错；但这个硬件为何采用该布局、对应哪条厂商勘误，不能只靠函数名编造解释。[Q01 原始指令和独立解码核对](acs-supplement/README.md)

<a id="bypass"></a>
## 4. “策略例外”在哪里改变结果

当本函数进入不合格处理后，依次看：

1. 内部 `disableACSCheck` 是否非零；是则记录 bypass 日志并令本次 ACS 判定通过。
2. 否则，当前失败节点是否为 root port，且内部 `disableACSCheckForRP` 非零；成立也允许 bypass。
3. 两项都不成立，保存 false 并返回。

注意这里的 bypass 会走向本次函数的成功返回，**不是仅跳过当前节点后必然继续检查剩余上游节点**。成功/失败结果保存在原始目标对象中；已有有效缓存时，入口直接返回缓存。缓存的完整失效协议尚未还原。

公开配置目录使用 `VMkernel.Boot.disableACSCheck` 和 `VMkernel.Boot.enableACSCheckForRP`；后者名称是“启用 root-port 检查”，而 M07 的内部变量名称是“禁用检查”。分别引用公开选项、内部字段与实验结果，不把名称相似当成已经追踪过赋值代码。[官方选项目录](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)

Broadcom KB 391460 记录过 ESXi 8.0.3 对 ACS 硬件配置检查过严的情况，并说明跳过这项检查时 ACS 本身仍保持启用。这支持“软件资格检查”和“硬件 ACS 是否工作”是两回事；不表示缺少 ACS 的硬件会因此得到隔离能力。[官方 KB](https://knowledge.broadcom.com/external/article?articleNumber=391460)

<a id="observed"></a>
## 5. 同一拓扑为什么能出现 true / false / true

已有实验：virtio endpoint 位于隐藏了 ACS capability 的 root port 下，ESXi `24280767`。

| 全局 bypass `disableACSCheck` | root-port 检查 `enableACSCheckForRP` | 已有观察 |
| --- | --- | --- |
| false | false | capable=true，有 bypass 日志 |
| false | true | capable=false，仍能识别 Bridge reset |
| true | true | capable=true，有 bypass 日志 |

这是既有三组控制的回读结果，不是本次重新运行。它说明 **capable 可以随检查策略改变，而复位能力和原本的硬件拓扑没有因此变成另一种能力**。这些值是该 build / 路径的观察，不推广为所有版本的默认值。[原始研究摘要](../esxi8-acs-check-bypass-20260714-summary.json)

<a id="group-meaning"></a>
## 6. 这为什么影响 VMware 与 Linux 的“分组”比较

Linux 通用 PCI 路径把 ACS 与 alias 判断用于形成 DMA groups；VMware 这里的 ACS 先产生一个资格判断，而依赖代表另由 alias、复位、功能约束计算。遇到不合格 ACS 条件时，不能假设 VMware 一定采取“扩大一组，然后整组允许直通”的路径；也不能将 bypass 通过直接解释成依赖范围被安全拆小。

[用三个场景详细比较两边的分组与操作范围](04-linux-groups-vs-vmware-dependencies.md) · [返回资格解释](01-qualification-explained.md#acs-comparison)
