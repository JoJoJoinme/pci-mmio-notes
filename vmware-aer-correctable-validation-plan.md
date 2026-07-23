# VMware ESXi DirectPath Correctable AER 黑盒验证计划

状态：`PARTIAL / EXECUTABLE`
日期：2026-07-23
关联风险：`R13`
关联 Case：`M06`、`M24`—`M29`

## 1. 目的与结论边界

本文把 PCIe Correctable AER 的待验证问题收敛为可执行实验。目标是回答 VMware ESXi 在不同设备所有权、AER 门控和 VM 生命周期下，**从外部能够观察到什么行为**，并把稳定行为转化为 Qman 的兼容 profile、控制面约束和验收 Case。

本文严格使用黑盒语言：只记录输入、外部状态、公开接口输出和时序，不推断 VMware 私有代码、内部数据结构或未公开算法。文中的 PCIe 路由关系是基于公开 PCIe/QEMU 模型提出的**判别假设**；只有实验结果可以把某个假设提升为“该 SUT profile 下的已观察行为”。

### 1.1 范围

- Correctable AER 的 8 个公开 status bit。
- endpoint Correctable Error Mask、endpoint Device Control.CERE、Root Error Command.COR_EN 三个门控变量。
- Native、passthrough 配置未生效、passthrough 空闲、guest 驱动前、guest 驱动活动、恢复 Native 等 owner phase。
- VM attach、reboot、clean/forced poweroff、重新分配和 owner restore 等生命周期边界。
- endpoint、upstream Root Port、ESXi、guest 四层证据的同时采集。
- hidden AER capability body 的 guest 读写边界。
- nested QEMU/ESXi 的行为验证，以及同一用例进入真实设备 E4 qualification 时的边界。
- Qman 应如何保存策略、阻断不安全写入、关联 owner lease、执行清理和触发 quarantine。

### 1.2 非范围

- VMware 私有实现、源码级调用链、内部线程或未公开 solver 算法。
- Uncorrectable Non-Fatal/Fatal 的全矩阵；既有 Non-Fatal 结果只作为 `M06` 基线背景。
- 用 synthetic QEMU 注入证明真实链路电气错误、真实设备内部状态或真实 reset 清除能力。
- 比较 FLR、SBR、D3hot/D3cold 的相对效果；本计划要求单个实验固定 reset 方法，比较实验另立 Case。
- HCL 设备型号选择、BMC、离线主机 HA 或跨集群 fencing。
- 由“没有日志”推断“ESXi 内部没有处理”。负日志只能说明指定日志源和观察窗口内未出现匹配项。

## 2. 四层外部可观察模型

实验结果必须同时绑定以下四层。任何一层缺失，都不能用相邻层的结果替代。

| 层 | 外部可观察对象 | 必采证据 | 不能推出的结论 |
| --- | --- | --- | --- |
| L0：刺激与运行来源 | outer QEMU/HMP 或物理注入器、QEMU/ESXi/firmware build、启动实例 | 注入命令、目标 qdev/BDF、注入 ACK、二进制与配置 hash、boot ID、单调时间戳 | HMP 返回 `OK` 只证明请求被注入器接受，不证明 endpoint 发出了 Error Message |
| L1：PCIe endpoint/fabric | endpoint config space、upstream Root Port config space | AER header、CES、CEM、Device Control/Status、Root Command/Status/Source ID，T0—T5 raw dump 与差异 | status 置位不等于 host 已产生日志、IRQ、health 事件或 quarantine |
| L2：ESXi owner 与 host policy | Current Owner、passthrough 配置、VM task/event、kernel policy、host 日志与存活性 | owner/readback、VMX 与 `vmware.log`、`vmkernel.log`、`vobd.log`、syslog marker、uptime | 未见日志不等于 ESXi 内部未消费；`host responsive` 不等于 Case 通过 |
| L3：VM/guest 表面 | guest PCI config、ACPI `_OSC`、driver、sysfs、dmesg、heartbeat、生命周期结果 | capability chain、raw body、Device Control/Status、`aer_dev_*`、driver bind、串口 marker、重启/复用结果 | guest 看不到 capability 或日志，不等于 guest 无法写 hidden body；必须单独验证写过滤 |

Qman 不是 VMware 黑盒实验的第五个测量层。Qman 的 admission、lease、health 和 quarantine 行为是由上述观察结果派生的产品设计，必须再由 Qman 自己的 E3/E4 Case 验证。

### 2.1 固定观测寄存器

每次运行先遍历 capability chain 发现实际 offset，不允许把一次运行的 offset 当成永久常量。

| 位置 | 字段 |
| --- | --- |
| endpoint AER | Extended Capability Header、Correctable Error Status（CES）、Correctable Error Mask（CEM） |
| endpoint PCIe capability | Device Control.CERE、Device Status.CED |
| upstream Root Port AER | Correctable Error Status/Mask、Root Error Command、Root Error Status、Error Source Identification |
| guest 对应 function | capability header/next pointer、raw CES/CEM、Device Control/Status |

所有 status 清除操作必须按 W1C 语义写入并立即 readback。一个寄存器清除成功，不得推定另一寄存器也已清除。

## 3. 输入维度

### 3.1 Correctable 8-bit 集合

| 代号 | Status | 输入值 |
| --- | --- | --- |
| B0 | Receiver Error | `0x00000001` |
| B1 | Bad TLP | `0x00000040` |
| B2 | Bad DLLP | `0x00000080` |
| B3 | Replay Number Rollover | `0x00000100` |
| B4 | Replay Timer Timeout | `0x00001000` |
| B5 | Advisory Non-Fatal | `0x00002000` |
| B6 | Corrected Internal Error | `0x00004000` |
| B7 | Header Log Overflow | `0x00008000` |

一次单变量运行只允许注入一个 bit。多 bit 累积只在 `M26` 的专门 sequence 中执行。

### 3.2 Owner phase

| 代号 | 外部前置状态 | 必须读回的事实 |
| --- | --- | --- |
| O0 | Native | `Current Owner=VMkernel`，无 guest 持有目标 function |
| O1 | 已配置 passthrough、尚未生效 | configured passthrough 与 Current Owner 仍为 Native 的差异 |
| O2 | PassthruIdle | `Current Owner=VM Passthru`，无 powered-on VM 占用 |
| O3 | AssignedPreDriver | VM 已 attach，guest 驱动尚未 bind；由 guest 串口 marker 定位 |
| O4 | GuestActive | VM 已 attach，guest 驱动已 bind 且 heartbeat 正常 |
| O5 | RestoredNative | 经过 detach/restore/reboot 后重新读到 Native owner |

`O1`、`O3` 不是现有 `Invoke-EsxiAerCase.ps1` 的可选值，需要新 runner。Owner phase 以有效状态 readback 为准，不以调用某个配置命令成功为准。

### 3.3 Gate tuple

定义 `G=(E,M,R)`：

- `E`：endpoint Device Control.CERE，`0=disabled`，`1=enabled`。
- `M`：当前注入 bit 在 Correctable Error Mask 中的值，`0=unmasked`，`1=masked`。
- `R`：Root Error Command.COR_EN，`0=disabled`，`1=enabled`。

对代表位 B0 完整执行 `000`—`111` 八种 gate tuple。对全部 8 bit 至少执行 `M=0/1` 成对测试，并固定 `E=1,R=1`。

公开 PCIe/QEMU 模型给出的判别假设是：

1. 注入被接受后，endpoint CES/CED 的沉积不由 `M/E/R` 决定。
2. 只有 `E=1,M=0` 时，endpoint 才可能向上游产生 Correctable Error Message。
3. Root Command 更可能控制 host notification/interrupt，而不是决定 Root Status 是否记录已经到达的消息。

这三条是预注册假设，不是 VMware 实现事实。若有效黑盒结果与其不同，结果记为 `DIVERGED`，保留原始证据并更新 VMware behavior profile，不能修改实验输出迎合假设。

### 3.4 Lifecycle transition

| 代号 | 转换 |
| --- | --- |
| L0 | fresh outer QEMU + cold ESXi boot，尚未 attach VM |
| L1 | PassthruIdle → VM power-on/attach → driver 前/后 |
| L2 | GuestActive → guest clean reboot → GuestActive |
| L3 | GuestActive → VM clean poweroff/detach → PassthruIdle |
| L4 | GuestActive → VM forced poweroff/detach → PassthruIdle 或显式故障态 |
| L5 | VM-A detach → 同一 function 分配给 VM-B |
| L6 | PassthruIdle → restore Native；需要 reboot 时把 reboot 作为转换的一部分记录 |

每一行固定 reset 方法及 host boot policy；不能在同一 Case 中同时改变 lifecycle 和 reset 类型。

### 3.5 Host policy 与 firmware 补充变量

现有结果只覆盖 `enablePCIErrors Runtime=TRUE`、`pcipDisablePciErrReporting Runtime=FALSE`。这不足以把 host 日志是否出现归因给 DirectPath 表面。`M25` 增加一个独立的 `P=(enablePCIErrors, pcipDisablePciErrReporting)` 2×2 boot-policy 矩阵：固定 B0、`G=101`、owner 和 lifecycle，每次改变 boot policy 后重启并 readback effective value。

Firmware 不进入 2688 个主组合。`M27` 增加 EFI/Legacy BIOS 的补充 A/B 行：固定 B0、O4、`G=101`、L1/L3，只比较 guest surface 与 lifecycle。若目标 ESXi/virtual hardware profile 不接受其中一种 firmware，该行记为 `BLOCKED`，不得用 QEMU OVMF/SeaBIOS 的结果代替 VMware 行为。

## 4. 8-bit × owner × gate × lifecycle 收敛矩阵

直接执行 `8 × 6 × 8 × 7 = 2688` 个组合既昂贵，又会把多个因果变量混在一起。本计划以全量单变量主轴覆盖每个值，再用边界 owner 和代表 bit 覆盖交互；任何未覆盖的高阶组合必须明确记为 limitation，不能声明“全组合等价”。

| 轨道 | Case | bit 覆盖 | owner 覆盖 | gate 覆盖 | lifecycle 覆盖 | 最小核心运行 |
| --- | --- | --- | --- | --- | --- | ---: |
| A：status 主轴 | M24 | B0—B7 | O0、O4 | 固定 `G=000`，隔离 status deposition | steady，注入后独立 clear | 16 |
| B1：mask 主轴 | M25 | B0—B7 | O0、O4 | `G=101` 与 `G=111` 成对，即只改变 M | steady | 32；与 B2 重复 tuple 可去重 |
| B2：route 主轴 | M25 | B0 | O0、O4 | `G=000`—`111` | steady | 16 |
| B3：host policy 主轴 | M25 | B0 | O0、O4 | 固定 `G=101`；host `P=00`—`11` | 每个 P 冷启动并 readback | 8 |
| C：root 状态机 | M26 | B0；另用 B1 做 OR 累积 | O0、O4 | 固定 `G=101`，再单独改变 R | first/repeat/clear/re-arm sequence | 每 owner 4 个独立 sequence，共 8 |
| D1：owner 主轴 | M27 | B0、B6 | O0—O5 | 固定 `G=101`，每阶段 readback | steady/owner transition | 12 |
| D2：lifecycle 主轴 | M27 | B0、B6 | transition 自带 owner phase | 固定 `G=101`，转换前后 readback | L0—L6 | 14；与 D1 可按相同 tuple 去重 |
| E：guest 写边界 | M28 | B0 | O4；O0 作为 host-side control | 分别写 CES/CEM/CERE | active、detach、reuse | 4 个操作序列 |
| F：物理复核 | M29 | 以设备可安全注入的 bit 为准，至少一个 unmasked 与一个 normally-masked bit | O0、O2、O4、O5 | 至少 `M=0/1` 和 `R=0/1` 边界 | L0、L3、L4、L5、L6 | 由物理设备注入能力生成，不得伪造固定数量 |

收敛规则：

1. 每个核心 tuple 至少重复 3 次，且至少有一次 A-B-A 恢复验证；三次必须绑定不同 run ID，不能复制 artifact。
2. B0 用于完整 gate 交互，因为现有证据已经有 B0 基线；B6 用于 owner/lifecycle 边界，因为它在既有 endpoint baseline 中处于 mask 范围。选择代表位不表示其他 bit 自动等价。
3. 如果某一主轴发现 owner-dependent 或 lifecycle-dependent 差异，把发生差异的 bit 提升为 D 轨道代表位，并扩展相邻组合。
4. 如果任一有效 run 出现额外 status bit、root source 不一致、guest write 穿透、host 不稳定或清理失败，停止后续复用，保存证据并进入隔离分支。
5. 执行计划器可以对完全相同的 `(SUT, boot, bit, owner, gate, lifecycle, reset, policy)` tuple 去重，但必须在 M24—M29 的 case manifest 中反向引用同一个 immutable run；不能用并集或笛卡尔聚合伪造覆盖。

## 5. T0—T5 证据协议

### 5.1 通用时间点

| 时间点 | 动作 | L0 | L1 | L2 | L3 |
| --- | --- | --- | --- | --- | --- |
| T0 | 建立 fresh baseline | QEMU/ESXi/firmware hash、boot ID、run nonce | endpoint/root 全寄存器 baseline；要求目标 status 为 0 | host policy、owner、passthrough inventory、日志起始游标 | guest 尚未启动或启动前 marker |
| T1 | 设置并验证唯一变量 | 控制命令及返回值 | 写入后的 CERE/CEM/Root Command readback | owner/readback、VM task 状态 | driver/attach phase marker |
| T2 | 注入前最后快照 | 注入目标与预注册 tuple | endpoint/root status 再次为预期 baseline | BEFORE syslog marker、日志游标 | raw config、`_OSC`、heartbeat |
| T3 | 注入与立即观测 | HMP/注入器 ACK 和单调时间 | endpoint CES/CED、root status/source 的立即快照 | owner 未漂移、host 存活 | guest raw config 和 heartbeat |
| T4 | 有界观察窗结束 | 观察窗时长 | endpoint/root 二次快照 | AFTER marker、按游标截取的 host logs/events | sysfs、dmesg、driver、heartbeat |
| T5 | clear 或 lifecycle 转换后 | clear/reset/transition 命令 | endpoint/root 独立 W1C readback、复用前快照 | owner/task/quarantine/health 外部状态 | reboot/detach/VM-B 的 raw config 与 heartbeat |

T0 不能使用上一 Case 的 after dump 代替。若无法 cold boot，每个相关 status 必须显式 W1C clear 并 readback 为 0；否则该 run 是 `INCONCLUSIVE`。

Host 负日志使用唯一 BEFORE/AFTER marker 与日志游标截取。`tail -n` 只能作为辅助文件，不能作为“指定窗口没有事件”的唯一证据。

### 5.2 四态 oracle

VMware 黑盒 Case 使用以下四态，不把“与假设不同”误写成“VMware 故障”：

| Oracle | 含义 | Case 处理 |
| --- | --- | --- |
| `MATCH` | 所有前置条件、证据链、重复性满足，观察结果与预注册外部行为假设一致 | 可冻结为该精确 SUT profile 的 `OBSERVED` 行为；映射到 Qman profile 后再做产品 PASS |
| `DIVERGED` | 前置条件和证据链有效，但一个或多个外部结果与假设不同 | 假设被反证；保留结果，更新行为 profile/ADR，不推断 VMware 内因 |
| `INCONCLUSIVE` | 实验运行了，但 baseline 脏、控制值未 readback、证据缺层、日志窗口不可靠、结果互相冲突或不可重复 | 不进入行为 profile，不关闭 Case/Risk；修复实验后重跑 |
| `BLOCKED` | 环境、runner、权限、物理注入能力或安全条件使实验无法执行 | 明确 blocker；不能用推测或别的 Case 替代 |

Qman conformance 使用同一输入 profile，但产品判定映射为 `PASS/FAIL/INCONCLUSIVE/BLOCKED`：只有 Qman 结果与已经冻结的 VMware 外部 profile 相符且满足 Qman 自身安全约束时才是 PASS。

## 6. M24—M29 Case 定义

建议的 registry 初始状态如下。它们是计划值；在 runner、Case contract 和依赖关系正式登记前，不代表 registry 已被修改。

| Case | 一句话验收目标 | 初始状态 | 依赖 | 风险 |
| --- | --- | --- | --- | --- |
| M24 | 8 个 Correctable status bit 在边界 owner 下得到完整、可重复的四层观察 | `IMPLEMENTATION_BLOCKED` | M06 | R13 |
| M25 | mask、CERE、Root Command 和 host policy 的单变量门控行为被区分 | `IMPLEMENTATION_BLOCKED` | M24 | R13 |
| M26 | Root Status/Source、multiple、独立 W1C 与 re-arm 行为被验证 | `IMPLEMENTATION_BLOCKED` | M25 | R13 |
| M27 | owner、VM lifecycle、firmware A/B 和重新分配不存在未建模残留 | `IMPLEMENTATION_BLOCKED` | M24、M25、M26 | R13 |
| M28 | guest 对 hidden AER body/route 字段的写边界被验证并进入过滤策略 | `IMPLEMENTATION_BLOCKED` | M24、M27 | R13 |
| M29 | exact 物理 tuple 的真实 AER、reset/clear、health/quarantine 和安全复用通过 qualification | `HARDWARE_BLOCKED` | M24—M28、C09 | R13 |

### 6.1 M24：全部 Correctable status bit

目的：在消息路由关闭的隔离条件下，确认 8 个 status bit 在 O0/O4 的 endpoint、host raw view 和 guest raw view 中如何沉积和清除。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | exact SUT hash/boot；endpoint CES、Device Status.CED、root status 全零；owner=O0 或 O4 |
| T1 | `G=000` 的三个实际值读回；除待注入 bit 外不改变其他控制 |
| T2 | host/guest raw CES 与 Device Status；O4 还需 capability header、`_OSC` 和 driver marker |
| T3 | 单 bit 注入 ACK；endpoint/host/guest/root 的立即差异 |
| T4 | 有界 host/guest 日志与 heartbeat；再次读取全部 status，排除瞬态误读 |
| T5 | 只清当前 endpoint CES，单独清 CED，再读回；下一 bit 必须重新 T0 |

Oracle：8 bit × 2 owner 的 required row 均有三次有效结果，且相同 tuple 可重复，才能为 `MATCH`。出现未预注册附带 bit 或 owner 表面差异为 `DIVERGED`；任何一行脏 baseline 为 `INCONCLUSIVE`。

### 6.2 M25：mask 与 route gate

目的：区分“status 沉积”“endpoint 发消息”“root 记录消息”和“host notification/log”四件事。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | endpoint/root status 全零；固定 owner、boot policy 和 observation window |
| T1 | 外层 lab 控制逐项设置 CERE、当前 bit mask、Root Command.COR_EN 或唯一 host policy 变量，并从物理/ESXi view 双重 readback；boot policy 行必须记录 reboot 与 effective value |
| T2 | 记录完整 `G`、非目标 mask bit、Root Correctable Mask 与 source baseline |
| T3 | 单 bit 注入；立即读取 endpoint CES/CED、Root Status/Source |
| T4 | host log/event/counter 与 root 二次快照；记录是否有 first/multiple 状态 |
| T5 | 分别清 endpoint 与 root；恢复原 gate，并做 A-B-A readback |

Oracle：每个 bit 的 mask A/B 只允许 M 改变；B0 的八个 gate tuple 只允许 E/M/R 改变。若 ESXi 在 T1 后重写 gate，记录有效值；无法保持目标 tuple 时是 `BLOCKED` 或 `INCONCLUSIVE`，不能按请求值判定。

Host policy 的 2×2 行与 gate 行分开执行；不能在改变 `P` 的同一行再改变 `G`。这组结果只回答四个公开配置组合的外部差异，不推断各参数在 ESXi 内部经过哪条路径。

### 6.3 M26：Root Status、Source、multiple 与 W1C

目的：摸清公开可观察的 root 状态机边界，不为 VMware 内部处理过程命名。

独立 sequence：

1. **First/Multiple**：全零 → B0 第一次注入 → 不 clear 再注入 B0。
2. **Endpoint/Root 独立 clear**：先只 clear endpoint CES/CED，再检查 root；重建状态后只 clear root，再检查 endpoint。
3. **OR 累积**：B0 → B1，不 clear endpoint，检查 CES 精确并集和 root source。
4. **Re-arm**：endpoint/root/CED 全部独立 clear 并 readback → 再注入 B0。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | root status/source 和 endpoint status 全零 |
| T1 | `G=101` readback；Root Correctable Mask、Root Command 全量保存 |
| T2 | sequence step 编号与精确 pre-state |
| T3 | 每次注入后的 endpoint/root immediate state 和 source ID |
| T4 | repeated injection 后的 multiple/log/counter 结果 |
| T5 | 每个 W1C 的写值、立即 readback、re-arm 结果 |

Oracle：sequence 的每一步必须可独立归因。一个早期步骤失败后，后续依赖步骤不得继续并汇总成 PASS；应终止该 sequence 并判为 `INCONCLUSIVE` 或 `DIVERGED`。

### 6.4 M27：owner phase 与 VM lifecycle

目的：确认 AER status、gate、surface 和 host 外部状态在 owner/VM 转换中的保留、清除或隔离行为。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | fresh boot、目标 function identity、owner 与零 status |
| T1 | 当前 owner phase 及实际 gate；VM-A lease/VMX/attach marker |
| T2 | 在转换前注入 B0 或 B6，并捕获完整 pre-transition state |
| T3 | 注入后立即寄存器与日志 marker |
| T4 | 执行 L1—L6 中唯一一个转换，记录 task/event、reset method、断电方式 |
| T5 | 转换后的 owner、gate、endpoint/root status；L5 必采 VM-B 第一次访问前后的 raw view，L6 必采 restored Native view |

Oracle：每个 lifecycle row 都必须明确观察到“保留”“已清除”“拒绝复用/隔离”三者之一。状态消失但没有 reset/clear/owner 证据，或 VM-B 在首访前缺快照，均为 `INCONCLUSIVE`。Forced poweroff 后出现清理失败时，测试停止复用并保留隔离状态。

### 6.5 M28：guest 对 hidden AER state 的写边界

目的：验证 AER header hidden、`_OSC` denied 时，guest 是否仍能改写物理/host-owned AER body 或路由控制。

独立操作序列：

1. guest 对已置位 CES 执行 W1C。
2. guest 翻转当前 bit 的 CEM。
3. guest 翻转 Device Control.CERE。
4. read-only control：仅读取相同 offset，验证探针本身不改变状态。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | O4、guest AER header/surface、host/physical CES/CEM/CERE baseline |
| T1 | host 设置唯一已知值并双视图 readback |
| T2 | guest 写入前 host/guest 同步快照和 write target/width/value |
| T3 | guest 单次 raw write 返回值；host/physical immediate readback |
| T4 | host/guest 日志、heartbeat、第二次 readback，排除延迟恢复 |
| T5 | detach/reuse 后状态；host 恢复原值并 readback |

Oracle：现阶段“guest write 被阻止”只是安全期望，不是 VMware 已知事实。若写穿透，结果是有效 `DIVERGED`，同时成为 Qman config-space write filter 的强制需求；不能删掉该结果来维持“host-owned”表述。

### 6.6 M29：真实物理 Correctable AER 与 health qualification

目的：在目标物理 host/device/firmware/guest/workload tuple 上，复核 synthetic 实验无法证明的真实链路、reset、telemetry、稳定性、health 和 quarantine 行为。

| 时间 | 必要证据/断言 |
| --- | --- |
| T0 | exact qualification key：host model/BIOS、IOMMU/interrupt remapping、kernel/QEMU/firmware、device identity/firmware、guest/workload；cold zero baseline |
| T1 | 安全且可审计的物理注入/设备自测能力、owner 与 gate readback |
| T2 | 注入前设备健康、链路计数、owner lease 与 host marker |
| T3 | 物理注入器/设备 ACK、endpoint/root/host immediate state |
| T4 | host telemetry、health transition、设备/guest workload 与持续时间 |
| T5 | clean/forced detach、reset/clear、VM-B 复用或 quarantine；再次验证设备功能 |

Oracle：没有安全的物理错误注入或等价设备自测能力时为 `BLOCKED`，不能用 synthetic bit injection 代替。`MATCH` 只对 exact qualification tuple 有效，不自动推广到其他设备类别、firmware 或平台。

## 7. 现有证据的保留与降级

### 7.1 可以保留的观察

现有 ESXi 8.0.3 build 24280767、nested QEMU `e1000e` 结果可以保留为特定 SUT profile 的基线观察：

- Native 与 PassthruActive 场景中，Correctable Receiver Error 注入后，目标 endpoint CES 可置位。
- 2026-07-23 的 PassthruIdle Correctable-only 矩阵中，8 个请求 bit 均从对应 bit clean 的
  baseline 独立沉积；PassthruActive 的 Receiver 与 Advisory Non-Fatal 代表位也投影到 guest
  raw body，且 owner 保持稳定。
- 被测 EFI DirectPath guest 中，AER Extended Capability header 被隐藏，guest `_OSC` 不获得 AER；raw capability body 可观察到物理 status 变化。
- 在既有观察窗口和日志源内，未发现对应 guest/ESXi AER log；这只是负观测，不证明内部未处理。
- QEMU VMware-profile 的 OVMF/SeaBIOS surface 结果可证明该自定义 QEMU profile 的 firmware 表面，不证明 VMware DirectPath SeaBIOS 行为。

### 7.2 必须降级或改写的结论

1. 既有 endpoint CERE 为 `0`；Receiver bit 虽 unmasked，也没有形成“消息路由已打开”的条件。因此既有结果不能证明 ESXi 收到 ERR_COR 后的 root service、notification、日志或 health 行为。
2. 既有 upstream Root Error Command 为 `0x00000006`，其中 COR_EN 为 `0`；必须通过 M25 分离 endpoint message 与 root notification。
3. C02d 前 Root Error Status 已为脏值 `0x00000024`，root Correctable Status 也已有 `0x1`。所以“Root Port unchanged”只能写为“相对该非零基线未观察到变化”，不能写为干净状态下无变化。
4. C03 继承了前一轮 CES=`1`，说明 Case 之间存在状态残留；C03 不能支持 Correctable clear/lifecycle 结论。
5. runner 的 `injected-and-host-responsive` 只表示注入器 ACK 且 host 可响应，不是语义 PASS。
6. 当前日志主要是 before/after tail，不能严格证明 marker 窗口内无事件。
7. VMware DirectPath guest 只验证了 EFI；“VMware 的 OVMF/SeaBIOS 行为相同”仍未验证。
8. 现有实验只有 guest read，没有 guest write；M28 完成前，“host-owned AER”只能表述为设计目标或部分可见性观察。
9. AER canonical result 与 summary 已 hash 固定，并由 `VMW-AER-COR-001` 登记到 VMware
   evidence index；raw run 位于 repo-sibling `_artifacts`，未随仓库提交。主矩阵绑定旧 runner
   hash，当前 runner 只完成 Receiver smoke，因此 runner bytes/逐 run 可重建性仍是明确 limitation。
   M06 只能消费这条 AER 证据，不能再用 firmware/MMIO/EDU 证据代替。

### 7.3 2026-07-23 实际运行账本

规范化结果见
[`evidence/esxi8-aer-correctable-20260723-result.json`](evidence/esxi8-aer-correctable-20260723-result.json)，
冻结摘要见
[`evidence/esxi8-aer-correctable-20260723-summary.json`](evidence/esxi8-aer-correctable-20260723-summary.json)。
两个文件由 `VMW-AER-COR-001` 登记；artifact locator 均相对仓库根，使用 `../_artifacts/...`。

| run | 覆盖 | result hash | manifest/hash 边界 | routing |
| --- | --- | --- | --- | --- |
| QEMU positive control | 8 bit × 3 gate，24/24 | `a0583d56…19c7` | result hash | QEMU route oracle PASS；非 VMware 证据 |
| `20260723T002305Z-76d79e36` | PassthruIdle 8 bit | `4681aaa5…33a8` | `SHA256SUMS=be517173…bcc6` | `NOT_TESTABLE_ENDPOINT_CERE_DISABLED` |
| `20260723T003751Z-16496a4c` | Active Receiver | `42368f80…ea8` | `SHA256SUMS=af691a6a…3d97` | `NOT_TESTABLE_ENDPOINT_CERE_DISABLED` |
| `20260723T001720Z-e19407a0` | Active Advisory Non-Fatal | `705b8118…e6a2` | `SHA256SUMS=e868e968…dd1` | `NOT_TESTABLE_ENDPOINT_CERE_DISABLED` |
| `20260723T004345Z-fae1a783` | final-runner Idle Receiver smoke | `4378ae1e…673b` | `SHA256SUMS=e69cd307…15eb` | `NOT_TESTABLE_ENDPOINT_CERE_DISABLED` |

完整 64-hex digest 保存在上述两个 JSON 中；表中缩写只用于阅读，不能作为验证输入。

现有 `M06` 建议收窄为：Receiver Correctable 与一个 Non-Fatal 基线、guest AER header/`_OSC` surface、raw body read，以及明确的上述 limitations。M24—M29 不得被现有 M06 自动关闭。

## 8. Qman 设计建议

### 8.1 明确 profile，不把推测写死在通用代码

建议给 platform/compatibility profile 增加显式 AER 策略，至少包含：

```text
aer.guestCapability          = hidden | visible
aer.guestOscOwnership        = denied | granted
aer.guestBodyRead            = passthrough | zero | synthesized
aer.guestBodyWrite           = deny | filtered-w1c | passthrough
aer.endpointReportingOwner   = host | guest | shared
aer.rootServiceOwner         = host | guest
aer.correctableHealthPolicy  = observe-only | threshold | quarantine
aer.lifecycleClearPolicy     = verified-reset | explicit-w1c | quarantine-on-unclean
```

profile 值只能来自已冻结的 VMware observation 或 Qman 自身安全决策。安全决策可以比 VMware 更严格，但必须标明是 Qman policy，不伪称 VMware 等价行为。

### 8.2 config-space 读写必须分别设计

- 隐藏 capability header/next pointer 不代表 body write 已隔离。
- 对 CES/CEM、Device Control.CERE、Root Command 等字段建立独立 read mask、write mask 与 side-effect contract。
- M28 完成前，Qman 的 VMware-compatible profile 应 fail-closed：guest 不得修改会改变 host AER 路由或清除 host 诊断证据的字段。
- 过滤必须覆盖 8/16/32-bit、unaligned/overlap write 以及 capability offset 变化，不能只拦一个固定 dword。

### 8.3 owner、assignedId 与事件关联

- 每次 AER 观察绑定稳定 `deviceUid`、当前 `assignedId`、lease generation/fencing token、VM ID、host boot ID 和 owner phase。
- `assignedId` 用于标识“本次设备分配实例”，而不是代替物理设备 identity。相同 BDF 在设备替换、host reboot 或重新分配后不得沿用旧事件归属。
- detach/attach 边界冻结事件游标；旧 lease generation 到达的异步 AER/health 事件不能污染新 owner。
- VM-B 首次访问前必须完成状态清理验证；失败则拒绝分配，而不是把 dirty state 交给新 VM。

### 8.4 health 与 quarantine

- Correctable status 置位本身不能直接推导 VMware 的 quarantine 算法；阈值、时间窗、去重和 bundle 粒度必须由 M29 或明确的 Qman 产品策略决定。
- 清理/reset 失败、guest 可改 host-owned gate、Root Source 与目标 function 不一致、host 状态不可读时，应 fail-closed 并隔离受影响 assignment scope。
- 是否 whole-bundle quarantine 不能从当前证据推出。Qman 至少要根据 IOMMU/reset/slot dependency graph 计算最小安全隔离域，并在证据不足时扩大而不是缩小隔离域。
- C09 的 candidate-pool 过滤应消费 health/quarantine 状态；M24—M28 只提供机制/行为证据，不直接关闭 C09。

### 8.5 backend 复用

- Legacy VFIO 与未来 cdev/iommufd backend 共享同一 AER policy、owner state machine、evidence schema 和 Case oracle。
- backend adapter 只负责实现 config-space filter、event source、reset/clear 和 readback；不得让 backend 差异改变控制面语义。
- 如果某 backend 无法保证 guest write filter、fresh owner readback 或 lifecycle clear，capability/admission 结果应为不支持，而不是静默降级。

## 9. E2/E4 边界

项目中存在两套历史同名等级，必须避免混用：

- 旧版 VMware 验证计划把生效 VMX、ESXi API/log、guest 输出称为“Legacy E2 黑盒行为”。本文保留这个词只用于解释旧报告。
- 当前 Qman canonical evidence 中，`E2` 是 deterministic model/source/unit/schema，`E3` 是跨真实 QEMU、firmware、guest kernel、VFIO 或 Qman component 的 instrumented virtual integration，`E4` 才是目标物理 qualification。reference/component subject 即使达到 E3 也不关闭产品 Case。新的 artifact 不应只写裸 `E2`，而应写完整 `subject + basisKind + observationStatus + sutProfile + limitations + hashes`。

Nested ESXi/QEMU 可以确认：

- 8-bit status deposition 的 synthetic 行为；
- capability/header/body 可见性；
- gate readback 与公开可观察的 root/host/guest差异；
- owner/lifecycle 下的虚拟表面和 guest write 边界；
- runner 与 oracle 是否具有判别力。

Nested 证据不能确认：

- 真实链路是否产生/传播对应错误；
- 真实 GPU/HBA/加速卡内部状态和 firmware side effect；
- FLR/SBR/D3 是否真正清除设备；
- 平台 Root Complex、interrupt remapping、IOMMU、errata 对行为的影响；
- 真实设备 health/quarantine、长期稳定性和安全复用。

因此 M24—M28 的 nested 结果属于 VMware reference/virtual integration 证据，不关闭 Qman 产品 qualification 和 R13；M29 必须是 exact target tuple 的 E4 physical qualification。E4 应复用相同 T0—T5 schema 和四层 oracle，但不能把 nested artifact 的结果字段复制为物理结果。

## 10. Runner 与可执行命令

### 10.1 QEMU 公开模型正控：8 bit × 3 gate

```bash
python3 vmware-esxi8-lab/test_qemu_aer_correctable_matrix.py \
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 \
  --output <EMPTY_OUTPUT_DIRECTORY>
```

该 runner 每个 tuple 启动 fresh QEMU，使用可写 CERE 的 `virtio-net-pci,aer=on`，覆盖 8 个 Correctable bit 与三类可判别 gate：`CERE=0`、`CERE=1/CEM=1`、`CERE=1/CEM=0/Root COR_EN=0`。它要求 endpoint/root UES 为 0、Device Status 不出现非 CED 位、Root Status 不出现 Uncorrectable 位，并校验 Correctable Source ID。它只证明 QEMU 的公开寄存器/消息路由模型，不是 VMware 行为，也不是物理链路证据。

QEMU firmware surface 对照仍由下列脚本执行：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc `
  'cd /mnt/e/Code/PCI/github-export && ./qemu-aer-surface-validate.sh'
```

### 10.2 ESXi Correctable-only 黑盒 runner

```bash
python3 vmware-esxi8-lab/test_esxi_aer_correctable_matrix.py \
  --host <ESXI_ADDRESS> \
  --owner-state PassthruIdle \
  --error-bits receiver_error,bad_tlp,bad_dllp,replay_number_rollover,replay_timer_timeout,advisory_nonfatal,corrected_internal_error,header_log_overflow \
  --qemu-monitor <HMP_SOCKET> \
  --qtest-socket <QTEST_SOCKET> \
  --qtest-clean-baseline \
  --qtest-baseline-policy status-routing \
  --outer-endpoint-bdf <OUTER_ENDPOINT_BDF> \
  --outer-root-bdf <OUTER_ROOT_BDF> \
  --esxi-bdf <ESXI_ENDPOINT_BDF> \
  --esxi-root-bdf <ESXI_ROOT_BDF> \
  --output <EMPTY_OUTPUT_DIRECTORY>
```

runner 只有 `-c` Correctable allow-list 注入表面。每个 case 记录请求 bit、effective CERE/CEM、root gates、Root Status/Source、owner、guest raw status 和有界日志窗口；输出把 endpoint deposition、message routing、日志观察与 guest projection 分开。`PASS` 只表示该 case 的冻结 observation oracle 满足，不自动表示 `ERR_COR` 已送达。若有效 CERE 为 0，routing conclusion 必须是 `NOT_TESTABLE_ENDPOINT_CERE_DISABLED`。

`status-routing` 基线策略只允许 QEMU `e1000e` 已观察到的 sticky `DevSta.CED`；endpoint CES、endpoint/root UES、root Device Status、Root Status、Source 和上游拓扑必须干净。Active owner 建立前后各做一次 clear/readback。任何 UES、非 CED Device Status 或 Root Uncorrectable 状态变化都产生 `FAIL_SAFETY` 并停止剩余注入。

当前 runner 已覆盖 PassthruIdle 8-bit deposition 和 PassthruActive 代表 bit；它尚未控制 ESXi 下的完整 2×2×2 gate tuple、host boot-policy 2×2、Native 全量、T5 lifecycle、guest write 和三次重复，因此不能宣告 M25—M29 完成。

### 10.3 新 runner 占位：root sequence

```powershell
# PLACEHOLDER: vmware-esxi8-lab/Invoke-EsxiAerRootSequence.ps1
& .\vmware-esxi8-lab\Invoke-EsxiAerRootSequence.ps1 `
  -Case M26 `
  -Sequences FirstMultiple,IndependentW1c,BitOr,Rearm `
  -Owners Native,GuestActive `
  -Repeat 3 `
  -RunId <RUN_ID>
```

### 10.4 新 runner 占位：owner/lifecycle 与 guest write

```powershell
# PLACEHOLDER: vmware-esxi8-lab/Invoke-EsxiAerLifecycleCase.ps1
& .\vmware-esxi8-lab\Invoke-EsxiAerLifecycleCase.ps1 `
  -Cases M27,M28 `
  -Bits 0x00000001,0x00004000 `
  -Lifecycle All `
  -Firmware EFI,LegacyBIOS `
  -GuestWritePlan CesW1c,CemToggle,CereToggle,ReadOnlyControl `
  -VmA <VM_A> `
  -VmB <VM_B> `
  -RunId <RUN_ID>
```

### 10.5 新 runner 占位：E4 physical qualification

```powershell
# PLACEHOLDER: vmware-esxi8-lab/Invoke-EsxiAerPhysicalQualification.ps1
& .\vmware-esxi8-lab\Invoke-EsxiAerPhysicalQualification.ps1 `
  -Case M29 `
  -QualificationRequest <SIGNED_REQUEST_JSON> `
  -PhysicalInjectorProfile <INJECTOR_PROFILE> `
  -DeviceProfile <EXACT_DEVICE_PROFILE> `
  -Lifecycle CleanPoweroff,ForcedPoweroff,Reuse,RestoreNative `
  -RunId <RUN_ID>
```

### 10.6 新 runner 最低输出合同

每个 row 至少生成：

```text
case.json
run-manifest.json
source-and-binary-hashes.json
t0-baseline/{outer,endpoint,root,esxi,guest}.*
t1-effective-controls/{requested,readback}.*
t2-pre-injection/*
t3-immediate/*
t4-window/{host-logs,guest-logs,registers,heartbeat}.*
t5-transition-or-clear/*
oracle.json
artifact-manifest.sha256
```

`oracle.json` 必须保存预注册假设、实际 observation、四态结果、limitations、重复 run 关联和判定器版本。任何 summary 都必须由 raw artifact manifest 可追溯重建。

## 11. 完成条件

本计划完成不等于 R13 或产品 qualification 完成。阶段完成条件如下：

1. M24—M28 runner 的每个请求值都有有效 readback，T0—T5 四层 artifact 完整并 hash 固定。
2. 收敛矩阵的 required row 三次可重复；差异已扩展验证并进入版本化 VMware behavior profile。
3. AER canonical result、summary、raw artifact digest、实验描述和 limitations 被正式登记到
   VMware evidence index。当前此项对聚合文件已满足；raw artifact 外置和旧 runner bytes 未归档
   仍阻止“任意环境可完整重建”的更强声明。
4. Qman profile 明确 guest read/write、host ownership、lifecycle clear 和 quarantine 边界，并有对应产品 Case，而不是只实现“隐藏 header”。
5. M29 在 exact physical tuple 上完成后，才允许对相应平台/设备 profile 宣告 E4 qualification；其他设备继续保持未验证。
