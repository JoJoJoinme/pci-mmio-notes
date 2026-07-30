# ESXi DirectPath PCIe AER 黑盒验证与 QEMU 对标

首次记录：2026-07-11
校正与增量验证：2026-07-26

## 1. 范围与结论

本报告只描述自有隔离实验环境中的公开接口、PCI config space、guest 输出和公开日志，
不推导 VMware 私有代码。

结论先行：在冻结的 nested profile（ESXi 8.0.3 build 24280767、vHW20、QEMU synthetic
endpoint）中，guest AER surface 是 **profile-specific**。历史 `e1000e` DirectPath profile
没有把 PCIe AER capability discovery 原样交给 guest：endpoint 的 AER Extended Capability
header 在 guest raw view 中为 0，guest ACPI 也不授予 AER ownership；但是 capability body
的 status 寄存器仍可通过 raw config read 观察。这个结论只属于该 profile 的
**surface/status projection**，不是所有 ESXi 8.0 U3 build 或 DirectPath 设备的通用规则。

2026-07-23 的历史门控读回把 `e1000e` profile 的结论进一步收窄：被测外层 `e1000e` 的 endpoint
`DeviceCtl.CERE=0`，upstream Root Port 的 `DeviceCtl.CERE=0`，Root Error Command 的
`COR_EN=0`；`Advisory Non-Fatal`、`Corrected Internal Error` 和 `Header Log Overflow`
还被默认 CEM `0x0000e000` 屏蔽。因此这组历史 ESXi 结果不能证明 `ERR_COR` 已送达 Root
Port、ESXi 已执行 Root service 或产生中断。公开日志只能写成“在采集窗口内未观察到
匹配项”，不能反推 VMware 内部没有处理。

同日新增的 `virtio-net-pci` profile 使用可读回的受控 gate lease：独立打开 upstream
`BridgeCtl.SERR` 与 Root `DeviceCtl.CERE`，再完整遍历 `G=(E,M,R)` 的八种组合。QEMU
公开模型完成 8 bit × 8 gate 的 64/64 正控；在 ESXi PassthruIdle owner 下，八种
ESXi-programmed effective gate tuple 完成 8/8 外部观察。outer QEMU 冻结期间，只有
`E=1,M=0` 的 `g100/g101` 使 outer-QEMU Root Port 沉积 `COR_RCV` 与 endpoint Source ID，
其余六种 gate 未沉积 Root reception。该冻结快照证明的是 **outer-QEMU fabric transport
在 ESXi 暂停时的状态沉积**，不是 ESXi Root service、IRQ 或私有实现证明。恢复 ESXi 后
的寄存器、owner 与日志只作为独立黑盒观察；未见匹配日志仍只是 bounded negative。

PassthruActive 的 `virtio-net-pci 1af4:1041` 则呈现另一种 guest surface：AER capability
可发现，header 为 `0x00020001`，Receiver Error 后 raw CES 从 `0x00000000` 变为
`0x00000001`；但 Linux `TOTAL_ERR_COR/FATAL/NONFATAL` 均保持 `0→0`，也没有真实
`PCIe Bus Error` 或 AER `severity=` 事件。因此 **capability/status visibility 不等于
guest AER service/event delivery**。这一 active 观察同样没有识别 ESXi 的中断或服务路径。

当前可证明与不可证明的边界为：

| 层次 | 历史 `e1000e` profile | 受控 `virtio-net-pci` profile |
| --- | --- | --- |
| endpoint status deposition | PassthruIdle 的 8 个 Correctable bit 均能独立沉积到 CES；Receiver 与 Advisory Non-Fatal 也在 PassthruActive 中观察到 | Idle Receiver 在八种 EMR gate 下均记录请求 CES/CED |
| message routing | `NOT_TESTABLE_ENDPOINT_CERE_DISABLED`；未证明 Root reception | frozen QEMU fabric 中仅 `g100/g101` 记录 Root reception/Source；不等价于 ESXi service/IRQ |
| guest surface 与 service | AER header 隐藏，raw CES 可投影；未观察到 guest AER event | Active profile 的 AER header 可发现且 raw CES 可投影；Linux AER totals `0→0`，无实际 kernel AER event |
| host log 或 service | 指定日志尾窗未观察到匹配项；不等价于未 service | 排除 SCP 路径和采集命令噪声后，指定窗口未观察到语义 AER/PCI error event；仍只是 bounded negative |
| recovery/health/quarantine | 未测试；synthetic status 注入不能代替真实设备与链路 qualification | gate/status 已恢复且 host 保持响应；设备 reset、health、quarantine 与安全复用仍未测试 |

在 QEMU surface A/B 中，这不是 OVMF/SeaBIOS 的差异：本次 Stock QEMU 6.2 的 Q35
Root Port 与 `e1000e` 会创建 AER；当 assigned function 的 extended-capability chain
本身含 AER 时，`vfio-pci` rebuild 默认也不会丢弃该 capability。
`x-pcie-extcap-init=off` 不会删除设备随后创建或从 backing function 保留的 AER capability。
VMware DirectPath 本轮只验证 EFI guest，不能由这组 QEMU A/B 外推 VMware SeaBIOS。
完整对标需要 opt-in config-space filter，并版本化虚拟 Root Port 的 AER
capability/service。

## 2. 环境与前置条件

| 层 | 版本/配置 |
| --- | --- |
| 历史 surface/基线 VMM | QEMU 6.2.0，Q35/KVM，显式 PCIe Root Port |
| 2026-07-23 验证 VMM | QEMU 11.0.2，SHA-256 `021bda3344eadf7fd12cb66665351ef6d1e6734ab2c69ab8ab36441afc09b393` |
| 被测 hypervisor | ESXi 8.0.3 build 24280767 |
| 历史 DirectPath endpoint | QEMU `e1000e` function `test_fn1`，`8086:10d3`，ESXi `0000:01:00.1` |
| 受控 route endpoint | QEMU `virtio-net-pci,aer=on` function `test_fn1`，`1af4:1041`，ESXi `0000:01:00.1` |
| upstream Root Port | outer/ESXi `0000:00:08.0`；virtio 实验把 `SERR` 与 Root `CERE` 作为独立、可恢复的 fixture lease |
| L3 guest | VMware EFI + Linux 5.15 initramfs |
| Correctable | Receiver Error，Correctable Status bit 0，`0x00000001` |
| Non-Fatal | Unsupported Request，Uncorrectable Status bit 20，`0x00100000` |

ESXi 使用本次启动参数，未修改持久默认值：

```text
enablePCIErrors:                 Configured=FALSE Runtime=TRUE
pcipDisablePciErrReporting:     Configured=TRUE  Runtime=FALSE
```

注意：第二个参数为 `FALSE` 只表示不强制关闭 passthrough error reporting，不表示 ESXi
会替 guest 把每个 endpoint 的 PCIe Device Control error-reporting bits 强制置 1。

## 3. 已执行矩阵

| Case | Owner/状态 | 注入 | 结果 |
| --- | --- | --- | --- |
| C00 | VMkernel owner | Correctable Receiver Error | 历史基线：QEMU `OK`；target CES=1；当时 Root baseline 不干净，不能作为 routing 负证据 |
| C01 | VM Passthru、未分配 | 状态检查 | 切 owner 不改变 endpoint/Root Port AER enable bits |
| C02d | VM Passthru、L3 活跃 | Correctable Receiver Error | host/guest CES 0->1；CERE/COR_EN 关闭，限定窗口未观察到 guest/ESXi AER log；不能推出 delivery suppression |
| C03 | VM Passthru、L3 活跃 | Non-Fatal Unsupported Request | host/guest UES 0->0x00100000；限定窗口未观察到 guest/ESXi AER log；该行继承 CES=1，不能证明 Correctable clear/lifecycle |
| Q-AER-0 | QEMU Q35+OVMF 默认 | surface probe | Root Port 与 endpoint 均公开 AER |
| Q-AER-1 | QEMU Q35+OVMF，`x-pcie-extcap-init=off` | surface probe | AER 仍公开，参数不能实现目标过滤 |
| Q-AER-2 | QEMU Q35+SeaBIOS 默认 | surface probe | AER 仍公开，和 OVMF 一致 |
| Q11-COR-24 | QEMU 11 fresh process | 8 bit × CERE blocked / endpoint masked / routed with Root COR_EN disabled | 24/24 PASS；证明 QEMU 公开模型的 status/gate/root-source 判别力，不是 VMware 证据 |
| Q11-COR-EMR-8 | QEMU 11 fresh process | Receiver Error × `g000`—`g111` | 8/8 PASS；验证完整 EMR gate oracle |
| Q11-COR-EMR-64 | QEMU 11 fresh process | 8 Correctable bit × `g000`—`g111` | 64/64 PASS；只有 `E=1,M=0` 路由到 Root，R 不抑制 Root Status 沉积 |
| Q11-COR-ROOT-12 | QEMU 11 fresh process | First/Multiple、独立 W1C、B0/B1 OR、re-arm × 3 | 12/12 `MATCH_TO_QEMU_PUBLIC_MODEL`；Root Source 在 Status W1C 后保留；仅为 QEMU root-state 正控，不关闭 ESXi M26 |
| ESX-COR-ROOT-O4-V17 | canonical ESXi O4/`g101` | 与 QEMU 相同的四个 sequence × 3 | 12/12 `MATCH`、`FULL_PLAN`；offline exact/`--require-complete` 通过；只授权 exact O4/`g101` 外部寄存器状态切片 |
| ESX-COR-ROOT-O0-V19 | canonical ESXi O0/`g101` | 与 QEMU 相同的四个 sequence × 3 | 12/12 `MATCH`、`FULL_PLAN`；与 V17 的 12 对 snapshot 逐字段 exact；`Module Name=None`，不证明 bound native driver |
| ESX-COR-I8 | VM Passthru、未分配 | 8 个 Correctable bit，逐例 W1C/readback | 8/8 status-projection oracle PASS；UES 与 root Uncorrectable surface 保持 0 |
| ESX-COR-A0 | VM Passthru、L3 活跃 | Receiver Error | host/guest CES 0→1，owner 稳定；routing 不可测 |
| ESX-COR-A5 | VM Passthru、L3 活跃 | Advisory Non-Fatal Correctable bit | host/guest CES 0→0x2000，owner 稳定；该位 CEM=1 且 CERE=0，routing 不可测 |
| ESX-VIRTIO-I-EMR8 | VM Passthru、未分配 | Receiver Error × `g000`—`g111`，Root path lease 打开 | 8/8 PASS；frozen transport 仅 `g100/g101` Root reception，八行均恢复 gate |
| ESX-VIRTIO-A-EMR2 | VM Passthru、L3 活跃 | Receiver Error × `g100/g101` | 两个 gate 均有独立 PASS：capability 可发现、raw CES `0→1`、AER totals `0→0`、无 kernel event；v2 聚合中的未注入 g101 只保留为 harness history |

`MATCH_TO_QEMU_PUBLIC_MODEL` 是本文展开后的 claim label；hash-bound raw
`oracle.json/result.json` 仍使用四态枚举 `MATCH`。这个展开只说明 comparator 是 QEMU
public model，不创建新的 runner verdict，也不表示与 ESXi 匹配。

C02d、C03 均由 `vmware.log` 中目标 `pciPassthru1` 的首次真实访问加 12 秒触发，
而不是猜测固定开机时间。QEMU HMP 均返回目标 function 的明确 `OK id`。

## 4. 四层外部可观察证据

每个新 case 分开保存：L0 注入 ACK 与运行来源、L1 endpoint/root config、L2 ESXi
owner 与有界日志、L3 guest raw config/ACPI/日志。四层不是四份独立物理证据：ESXi
`lspci` 与外层 QTest 读取同一 config space，guest raw body 也可能是该空间的投影；
它们不能相互代替来证明 message delivery。

### 4.1 Correctable Receiver Error

outer-QEMU backing endpoint / ESXi view：

```text
before: AER header=0x14020001, CES=0x00000000, Device Status=0x0000
after:  AER header=0x14020001, CES=0x00000001, Device Status=0x0001
```

L3 guest raw config view：

```text
before: AER header=0x00000000, CES=0x00000000, Device Status=0x0000
after:  AER header=0x00000000, CES=0x00000001, Device Status=0x0000
```

### 4.2 Non-Fatal Unsupported Request

outer-QEMU backing endpoint / ESXi view：

```text
before: UES=0x00000000, CES=0x00000001, Device Status=0x0001
after:  UES=0x00100000, CES=0x00000001, Device Status=0x000b
```

L3 guest raw config view：

```text
before: AER header=0x00000000, UES=0x00000000, CES=0x00000001
after:  AER header=0x00000000, UES=0x00100000, CES=0x00000001
```

两轮 guest 均报告：

```text
acpi PNP0A03:00: _OSC: platform does not support [AER LTR DPC]
```

guest 不生成 `aer_dev_correctable`/`aer_dev_nonfatal` sysfs 统计，采集的 `dmesg` 中未见
`PCIe Bus Error`。ESXi `vmkernel.log`/`vobd.log` 的指定采集窗口未见匹配事件。新 runner
在每次注入前把 endpoint CES、endpoint/root UES、Root Status/Source 清零并读回；
`DevSta.CED` 在 live `e1000e` 上不能经 QTest W1C 清除，故作为显式 sticky limitation
保存，且只允许 CED，任何 NFED/FED/URD 都会触发安全失败。

历史 `e1000e` profile 的**直接观察**是：

1. outer-QEMU backing endpoint/ESXi view 与 guest view 不同：guest AER header 和
   PCIe Device Status 为 0，而同一 raw body offset 的 CES 跟随 backing endpoint 从 0 变为 1。
2. guest `_OSC` 没有获得 AER ownership；未生成相应 `aer_dev_*` 统计，采集窗口内也未见
   Linux AER event。它们不能单独证明 guest 内部不存在任何 AER service。
3. guest driver 没有打开 endpoint Device Control 的 error-reporting bits；effective
   endpoint CERE、upstream CERE 与 Root COR_EN 均为 0。
4. 在该 effective gate 下，outer-QEMU Root Status/Source 相对基线没有新增 reception；
   这不是“ESXi 收到后静默”的证据。

基于公开参考模型的**可证伪解释**是：host/guest view 差异与 VMM 对 config-space surface
做 mediation、filter 或 synthesis 相容，但现有观察不能识别具体机制。QEMU 11.0.2
[`pcie_aer.c`](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
把 Correctable message 的上行资格置于 endpoint CERE 与当前 bit mask 之后；因此该
synthetic e1000e gate 不能正向检验 ESXi receipt/service。这个 source-derived oracle
不是 VMware 私有实现事实。

这些直接观察与 source-derived 解释都只属于历史 `e1000e` profile，不能被后续 virtio
fixture 原地覆盖。

### 4.3 `virtio-net-pci` route-enabled EMR

受控 profile 将 endpoint CERE、当前 bit 的 CEM 和 Root COR_EN 定义为
`G=(E,M,R)`，并把 upstream `BridgeCtl.SERR=1`、Root `DeviceCtl.CERE=1` 作为独立
root-path lease。每个 case 都在 outer QEMU 暂停后完成注入前快照、Correctable-only
HMP 注入和立即 QTest 快照，再恢复 ESXi、采集 post-resume timeline，最后恢复原 gate。

| Gate | endpoint CES/CED | frozen outer-QEMU Root deposition/source | QEMU public-model 解释 |
| --- | --- | --- | --- |
| `000`、`001` | 记录 Receiver | 无 | endpoint CERE 关闭 |
| `010`、`011` | 记录 Receiver | 无 | endpoint CERE 关闭且 bit masked |
| `100`、`101` | 记录 Receiver | 有；Source 匹配 `01:00.1` | `E=1,M=0` 允许 QEMU fabric reception |
| `110`、`111` | 记录 Receiver | 无 | 当前 bit 被 mask |

`g100` 与 `g101` 的 frozen Root Status/Source 相同，直接观察只支持“改变 R 没有改变
本次 outer-QEMU Root deposition”。QEMU 11.0.2
[`pcie_aer.c`](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
另行定义先沉积 Root Status、再由 Root Command 判断 notification eligibility；
[Linux PCIe AER Driver Guide](https://docs.kernel.org/PCI/pcieaer-howto.html)也把 Root
记录与 Root Error Command interrupt 分成不同步骤。因此“R 是 notification gate”是
公开参考机制解释，不是本次 IRQ 观察，也不能据此命名 VMware 内部处理路径。
八行均保持 Uncorrectable surface 为零并恢复受控 gate。ESXi 恢复后的日志未见匹配项只记为
`NOT_OBSERVED_IN_CAPTURED_TAIL_WINDOW`，不能升级成“未 service”或“无 IRQ”。

Active `g100/g101` 进一步表明：两种 R 值下都能在冻结 outer-QEMU fabric 中观察到同一类
Root deposition；恢复后 guest 可发现 AER header 并看到 raw CES `0→1`，owner 保持同一
VM，Uncorrectable surface 为零。guest Linux AER totals 没有增加且没有实际 AER event。
`R=0` 与 `R=1` 在当前公开观测面上没有形成可归因的 ESXi/guest service 差异；这只能写成
“notification/service effect 尚未识别”，不能写成 R 对 VMware 无效。

### 4.4 QEMU root-state 正控与 ESXi 现有证据的差异账本

这里的“差异”先区分“已观察到不同结果”和“某一侧尚未运行”。后者必须是
`INCONCLUSIVE`/open gap，不能写成 VMware 与 QEMU `DIVERGED`：

runner readiness 本身不是 observation；但 2026-07-29 的 canonical V17
`20260729-esxi8-aer-root-o4-v17-full1` 已形成独立 live observation：O4/`g101` 四个
sequence × 3 为 12/12 `MATCH`、`FULL_PLAN`，offline exact 与 `--require-complete` 通过。
冻结 [`campaign result`](evidence/esxi8-aer-root-o4-v17-full1-20260729-campaign-result.json)
SHA-256 为
`847a2500ae868a47d1abe8ae9765848085f8c31605afaa74b78cbc1923d40b7f`；canonical
[`result record`](evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json) 与
[`summary`](evidence/esxi8-aer-root-o4-v17-full1-20260729-summary.json) 固定边界。
2026-07-30 的 canonical V19 `20260730-esxi8-aer-root-o0-v19-full1` 在 O0/`g101`
完成相同 12 案，12/12 `MATCH`、`FULL_PLAN`；canonical
[`result record`](evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json)、
[`summary`](evidence/esxi8-aer-root-o0-v19-full1-20260730-summary.json) 与
[`campaign result`](evidence/esxi8-aer-root-o0-v19-full1-20260730-campaign-result.json)
SHA-256 分别为 `538aaf8c…310b`、`5a58f4de…dff`、`b2ab49a2…c6d6`。下表把 exact
O0+O4/`g101` profile 与 QEMU 正控逐面比较；其他 gate 保持 open gap。

| 可观察面 | QEMU 11.0.2 正控 | 当前 nested ESXi fixture 证据 | 判定 |
| --- | --- | --- | --- |
| first Root reception/source | B0 后 Root Status=`0x1`、Source=`0x0100` | V17/O4 与 V19/O0 均为 Root Status=`0x1`、Source=`0x0101`，各 3/3 | Source 分别绑定 requester BDF；ESXi 两 owner snapshot exact，不推成跨环境身份等同 |
| repeated same-bit / multiple | 未 clear 重复 B0 后 Root Status=`0x3`，3/3 | V17/O4 与 V19/O0 均为 Root Status=`0x3`，各 3/3 | exact O0+O4/`g101` 外部状态 `MATCH` |
| Endpoint/Root 独立 W1C | 两种方向均独立，3/3 | 两 owner 均为 Endpoint-only clear 保留 Root、Root-only clear 保留 Endpoint CES/CED，各 3/3 | exact O0+O4/`g101` 外部状态 `MATCH` |
| distinct-bit OR | B0→B1 得到 Endpoint CES=`0x41`、Root Status=`0x3`，3/3 | 两 owner 均得到 CES=`0x41`、Root Status=`0x3`、Source=`0x0101`，各 3/3 | exact O0+O4/`g101` 外部状态 `MATCH` |
| re-arm | clear 后重新得到 Root Status=`0x1`，3/3 | 两 owner 均重新得到 CES=`0x1`、Root Status=`0x1`、Source=`0x0101`，各 3/3 | exact O0+O4/`g101` 外部状态 `MATCH` |
| Root Source after Status W1C | QEMU raw view 保留 `0x0100` | V17/V19 在 Root Status=`0` 时把 Source 标为不具语义/`null`，未授权 raw clear/preserve 断言 | 观测合同不同，不能据此判定 `MATCH` 或 `DIVERGED` |
| owner/driver/service | 本 runner 无 ESXi owner/service | V17 为 O4 bound guest driver；V19 为 O0 VMkernel owner，但目标 `Module Name=None`；两者 bounded host log 均 `NOT_OBSERVED` | snapshot equality 不证明 bound native driver、owner-independent 私有机制或无 service/IRQ |

V19 与 V17 的 12 对 `evaluation-input.snapshots` 逐字段 exact；按 sequence 聚合的 SHA-256
为 `first-multiple=57f5d016add1da431dfe475818e80920cb35fbd766a85f8d422e1db75d26f772`、
`independent-w1c=21ee0c21d3a8b6e8a7429fb44599df97b72da3f79d48f843f42fff3a2d229df2`、
`bit-or=d121036d96f1c5fab9bdd0bc405058ae35b05065a0f3ca6b7ccc3a87b6e8ca90`、
`rearm=80370cc89885af9c70d982e4cec376ded05d4b3ea28f3c60c753f599c48625c4`。
它们形成
[`frozen observed profile`](contracts/vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json)
（SHA-256 `cafa083512697f5361d6e8385d2685b676ac896672439c36bd6e21574f531a6e`）与
[`promotion receipt`](evidence/esxi8-aer-root-g101-o0-o4-profile-promotion-20260730-summary.json)
（SHA-256 `fab09980f8f266e94640914df59833f640b66e063a1625333d9685031109812a`）。
该 promotion 的 closure authority 为 `NONE`：不关闭 Qman M26、M06、R13 或 G1-G6。

因此本轮推导出的最小实现原理是：Qman 应把 Endpoint status、Root first/multiple、
Endpoint/Root W1C、Source、notification/service、guest projection 和 recovery 建成可独立
版本化、可单独验收的状态面。它不是对 VMware 私有类、函数或控制流的还原。

## 5. QEMU 对标

### 5.1 Stock QEMU 参数边界

下面的参数不是解决方案：

```text
-device pcie-root-port,...,x-pcie-extcap-init=off
-device e1000e,...,x-pcie-extcap-init=off
-device vfio-pci,...,x-pcie-extcap-init=off
```

本地 guest 实测 AER 仍存在。QEMU 6.2 源码显示，该属性只影响 PCIe capability
初始化时 `0x100` NULL Extended Capability Header 的 writable mask；`e1000e` 随后仍
无条件调用 `pcie_aer_init()`。若 assigned backing function 的 extended-capability chain
含 AER，`vfio-pci` rebuild 默认会保留该 capability；其显式丢弃项是 capability ID 0、
SR-IOV、ARI 和 ReBAR。这个源码行为不表示每个 `vfio-pci` backing function 都实现 AER。

### 5.2 推荐实现

对 QEMU/VFIO 增加显式、版本化的 guest-surface profile；`x-vmware-hide-aer=on` 只能作为
历史 `e1000e` 兼容值，不能成为 VMware 对标的全局默认：

1. 在 `vfio_add_ext_cap()` 遍历中把 `PCI_EXT_CAP_ID_ERR` 从 guest capability chain
   跳过并保持 next pointer 正确；capability body 的读、W1C 和控制字段写入必须分别按
   profile 过滤，不能因隐藏 header 就假定 hidden body 不可写或可安全直通。
2. 给 generic PCIe Root Port 增加 `aer=off`，条件化跳过 `pcie_aer_init()` 和
   `pcie_aer_root_init()`。
3. 把 ACPI `_OSC` ownership、capability header 可见性、body read/write、raw status
   projection 与 service/event delivery 分成独立策略轴；不能由 header 可见或不可见推导
   guest 已经或没有获得 AER service。
4. Qman 必须显式定义物理 AER 的 owner、采集、guest write filter 与 recovery policy；
   当前 VMware surface 观察不能替 Qman 证明 Linux/VFIO host 路径已经收到事件，也
   不能支持把 AER IRQ 无条件转发给 guest。

对齐后的验收点必须按 profile 固定：历史 e1000e 可要求 guest AER header 为 0；
virtio profile 可公开 header 和 `aer_dev_*` 文件，但事件 totals 与 kernel event delivery
必须独立判定。两类 profile 的 raw body 读写边界都要明确定义；host 事件记录、
reset/clear、health 与 quarantine 必须由独立 E3/E4 Case 证明。

## 6. 复现

### 6.1 历史 `e1000e` canonical 运行账本

机器可读入口是
[`VMW-AER-COR-001 canonical result`](evidence/esxi8-aer-correctable-20260723-result.json)
和[冻结摘要](evidence/esxi8-aer-correctable-20260723-summary.json)。canonical result 通过
`contracts/vmware-experiment-result.schema.json`，并固定以下 repo-sibling artifact：

| 运行 | artifact（相对仓库根） | result SHA-256 | 结论 |
| --- | --- | --- | --- |
| QEMU 24-row 正控 | `../_artifacts/vmware-directpath-runs/20260723-aer-correctable/qemu-correctable-24-v2` | `a0583d56bbbb969aff5d65471a9e9c993c562f7e6d46022a6317ef39c1cc19c7` | 24/24 PASS；仅为 QEMU oracle 正控 |
| `20260723T002305Z-76d79e36` | `../_artifacts/vmware-directpath-runs/20260723-aer-correctable/esxi-idle-correctable-8-v2` | `4681aaa52669b2d47cada43b8e1984fd81c8b1a3f6c733a0cdb5874eaaba33a8` | Idle 8/8 deposition PASS；routing 不可测 |
| `20260723T003751Z-16496a4c` | `../_artifacts/vmware-directpath-runs/20260723-aer-correctable/esxi-active-receiver-v6` | `42368f80e066bcae72cbc29df5c39641ff6e650664f078c96bc0d3263e698ea8` | Active Receiver PASS；routing 不可测 |
| `20260723T001720Z-e19407a0` | `../_artifacts/vmware-directpath-runs/20260723-aer-correctable/esxi-active-advisory-v1` | `705b81181aaeb6a11472f82168761a73ce926f83aecf40c6befc2d8f0a2fe6a2` | Active masked representative PASS；routing 不可测 |
| `20260723T004345Z-fae1a783` | `../_artifacts/vmware-directpath-runs/20260723-aer-correctable/esxi-idle-receiver-final-smoke` | `4378ae1e16e41b2e4a2e7ef2ae83754594926ddc589849e89697fd06efac673b` | 当前 runner 修复后的 live smoke PASS |

主矩阵使用的 ESXi runner hash 为
`e12bf9a19e229f7df4006e62dd84e34f18f7d60f8af1578de33105c0d9f4048c`；当前提交版本为
`f5c7998fdfaefc8ba2fb82654ec4d7eefa5c1d3f76b64814756cf04ad5aa29fb`，后者只用 Idle
Receiver 做过 live smoke。旧 runner bytes 未归档、当前版本尚未重跑全部核心矩阵，因此这项
限制保留在 canonical result 中，不把一次 smoke 扩写为整套重验。

### 6.2 `virtio-net-pci` route-enabled 增量账本

下列 artifact 与旧 e1000e canonical 文件并列保留，不修改旧文件中的 endpoint、
effective gate 或结论。virtio profile 由
[`canonical result`](evidence/esxi8-aer-correctable-virtio-route-20260723-result.json) 和
[`hash summary`](evidence/esxi8-aer-correctable-virtio-route-20260723-summary.json) 登记到
同一个 `VMW-AER-COR-001`，并进入 VMware evidence index。

| 运行 | artifact（相对仓库根） | result SHA-256 | 结论 |
| --- | --- | --- | --- |
| QEMU Receiver × 8 EMR | `../_artifacts/vmware-directpath-runs/20260723-qemu11-aer-emr-control-v1/result.json` | `5e018ff1617c2d3bd85d935b7548d4e0248d6c8b3dffa46fc8d122ef011aab99` | 8/8 PASS；QEMU oracle |
| QEMU 8 bit × 8 EMR | `../_artifacts/vmware-directpath-runs/20260723-qemu11-aer-emr-allbits-v1/result.json` | `40880169d5a4deaf01019af7d0e4618886464256cd5513f1e6d06be14cff52a4` | 64/64 PASS；QEMU oracle |
| QEMU root sequence × 3 | `../_artifacts/vmware-directpath-runs/20260726-qemu11-aer-root-sequence-v1/result.json` | `59839df23f9711162f4d8548b7e258e355957bda23348f6acd727eb219decb5b` | 12/12 `MATCH_TO_QEMU_PUBLIC_MODEL`；276 个逐案 artifact hash 已校验；QEMU 正控，非 VMware 结果 |
| `20260729-esxi8-aer-root-o4-v17-full1` | [`campaign result`](evidence/esxi8-aer-root-o4-v17-full1-20260729-campaign-result.json) | `847a2500ae868a47d1abe8ae9765848085f8c31605afaa74b78cbc1923d40b7f` | O4/`g101` 四 sequence × 3，12/12 `MATCH`、`FULL_PLAN`，offline exact/`--require-complete` 通过；canonical [result record](evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json)；只闭合 exact 外部寄存器状态切片 |
| `20260730-esxi8-aer-root-o0-v19-full1` | [`canonical result`](evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json) | `538aaf8c5d44b42c7ceb7c2b985b3c059ef91be28902b805dac4eec117eb310b` | O0/`g101` 四 sequence × 3，12/12 `MATCH`、`FULL_PLAN`；summary `5a58f4de…dff`，campaign `b2ab49a2…c6d6`；`Module Name=None` |
| O0+O4 profile promotion | [`observed profile`](contracts/vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json) | `cafa083512697f5361d6e8385d2685b676ac896672439c36bd6e21574f531a6e` | 12 对 snapshot exact；[receipt](evidence/esxi8-aer-root-g101-o0-o4-profile-promotion-20260730-summary.json) SHA-256 `fab09980…12a`；closure authority `NONE` |
| `20260723-esxi8-aer-virtio-idle-emr-v2` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-idle-emr-v2/result.json` | `655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1` | Idle Receiver EMR 8/8 PASS；frozen QEMU fabric + ESXi post-resume black box |
| `20260723-esxi8-aer-virtio-active-emr-representative-v2` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-emr-representative-v2/result.json` | `4fe5e83789f8c509476e32630cc3b20960ca995e0637ccb53bcdde479089aaae` | aggregate INCONCLUSIVE：g100 PASS；g101 因观察窗不足未注入 |
| `20260723-esxi8-aer-virtio-active-g101-final-v1` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-g101-final-v1/result.json` | `c4511cb3514fd27b992a44af44c7dbdcf339c1a364730adcd06fb884ba700d72` | g101 PASS；guest parser 已修正，host SCP-path 假阳性由 raw log 重分类 |
| `20260723-esxi8-aer-virtio-active-g100-parser-final-v1` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-g100-parser-final-v1/result.json` | `bd455a4d9278e53687cf16dd2cfefe161bad78ec946249725a614dce2dd975c0` | g100 PASS；最终 guest/host semantic parser live smoke，实际 event 均为 0 |

当前四个 Python 入口：

```bash
python3 vmware-esxi8-lab/test_qemu_aer_correctable_matrix.py \
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 \
  --output <EMPTY_QEMU_OUTPUT_DIRECTORY>

python3 vmware-esxi8-lab/test_qemu_aer_root_sequence.py \
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 \
  --output <EMPTY_QEMU_ROOT_SEQUENCE_OUTPUT_DIRECTORY> \
  --gate g101 --repeat 3

python3 vmware-esxi8-lab/test_esxi_aer_correctable_matrix.py \
  --host <ESXI_ADDRESS> --owner-state PassthruIdle \
  --error-bits receiver_error --gate-tuples 000,001,010,011,100,101,110,111 \
  --enable-root-path \
  --qemu-monitor <HMP_SOCKET> --qtest-socket <QTEST_SOCKET> \
  --qtest-clean-baseline --qtest-baseline-policy strict \
  --outer-endpoint-bdf <OUTER_ENDPOINT_BDF> --outer-root-bdf <OUTER_ROOT_BDF> \
  --esxi-bdf <ESXI_ENDPOINT_BDF> --esxi-root-bdf <ESXI_ROOT_BDF> \
  --output <EMPTY_ESXI_OUTPUT_DIRECTORY>

python3 vmware-esxi8-lab/test_esxi_aer_root_sequence.py selftest
python3 vmware-esxi8-lab/test_esxi_aer_root_sequence_unit.py

python3 vmware-esxi8-lab/test_esxi_aer_root_sequence.py plan \
  --owner-phase O0 --gate g101 --repeat 3 \
  --output <EMPTY_ESXI_ROOT_PLAN_DIRECTORY>
```

QEMU root sequence 的 hash-bound 摘要见
[`qman-qemu-aer-root-sequence-20260726-summary.json`](evidence/qman-qemu-aer-root-sequence-20260726-summary.json)。
它得到 `MATCH_TO_QEMU_PUBLIC_MODEL`，验证 public-model first/multiple、独立 W1C、OR 与
re-arm oracle。ESXi 的 exact O4/`g101` 同序列三次重复已由
[`V17 result`](evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json) 和
[`summary`](evidence/esxi8-aer-root-o4-v17-full1-20260729-summary.json) 固定；exact
O0/`g101` 则由 [`V19 result`](evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json)
与 [`summary`](evidence/esxi8-aer-root-o0-v19-full1-20260730-summary.json) 固定。两 owner
的 12 对 snapshot exact；O0 `Module Name=None`，bound native driver、其他 gate、host
notification/service、guest write 与 lifecycle clear/reuse 仍未验证。

当前本地 AER guest fixture ISO SHA-256 为
`3DE27D166EE6881BFB60D8DA233A0B3E6871532108D01D5741C8A43BA91777DE`，
build attestation SHA-256 为
`103941485D8B1679D6DA18312025F5155F4A027F86EFA99E5BAD2FAA66FD67C1`。
离线冻结账本
[`20260726-esxi-aer-root-runner-offline-v3/result.json`](../_artifacts/vmware-directpath-runs/20260726-esxi-aer-root-runner-offline-v3/result.json)
的 SHA-256 为
`bae6e1e0d552a2d2859250a3ac61448c010df37f27903c774e79713f8f90cf23`。
ISO/attestation 与该账本分别只绑定 build 输入和离线 harness/source 回归，不构成 ESXi
行为证据。只有 V17/V19 live artifact 对 exact O0+O4/`g101` 外部寄存器状态授权
`MATCH`；不得把离线 78/78、ISO hash、plan 输出、跨 owner snapshot equality 或该单一
gate 外推为 bound native driver、owner-independent 私有机制、其他 gate、service/IRQ、
guest write、lifecycle、物理 qualification 或 VMware 私有实现结论。

M26 的目录级结果只有在 raw snapshot 先于解析保存、任何 sampler/parser/worker/cleanup
异常均 typed partial 并 fail-stop、T0/T1/T4/T5 coverage 与 raw host/guest evidence 可从
manifest 重算，且 `verify-run` 对 case/campaign/aggregate exact-match 后才具备权威性。

完整参数、T0—T5 协议和待补矩阵见
[`vmware-aer-correctable-validation-plan.md`](vmware-aer-correctable-validation-plan.md)。

### 6.3 2026-07-11 历史 runner

ESXi boot-only 参数注入：

```powershell
Start-Process -FilePath wsl.exe -WindowStyle Hidden -ArgumentList @(
  '-d','Ubuntu-22.04','--exec','python3',
  '/mnt/e/Code/PCI/_artifacts/qemu-esxi8-boot-options.py'
)
./_artifacts/Invoke-EsxiCaveatSsh.ps1 -RemoteCommand 'reboot'
```

构建并上传 AER guest：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "PROFILE=aer /mnt/e/Code/PCI/_artifacts/build-esxi-l3-probe-iso.sh"
./_artifacts/Copy-EsxiCaveatFile.ps1 -Direction ToEsxi `
  -Source /mnt/e/Code/PCI/_artifacts/esxi-l3-aer-probe.iso `
  -Destination /vmfs/volumes/pci-mmio-local/iso/esxi-l3-aer-probe.iso
```

执行：

```powershell
./_artifacts/Invoke-EsxiAerCase.ps1 `
  -CaseId C02-active-correctable -OwnerState PassthruActive `
  -ErrorClass Correctable -QemuDevice test_fn1 -EsxiBdf 0000:01:00.1 `
  -VmwarePassthruIndex 1 -RunId manual-aer

./_artifacts/Invoke-EsxiAerCase.ps1 `
  -CaseId C03-active-nonfatal -OwnerState PassthruActive `
  -ErrorClass NonFatal -AllowNonFatal -QemuDevice test_fn1 `
  -EsxiBdf 0000:01:00.1 -VmwarePassthruIndex 1 -RunId manual-aer
```

QEMU surface A/B：

```bash
./qemu-aer-surface-validate.sh
```

历史本地证据位于：

```text
_artifacts/vmware-directpath-runs/20260711-aer/C00-native-correctable/
_artifacts/vmware-directpath-runs/20260711-aer/C02d-active-correctable/
_artifacts/vmware-directpath-runs/20260711-aer/C03-active-nonfatal/
```

## 7. 公开依据

- [Broadcom KB 312208：VMDirectPath I/O and Dynamic DirectPath I/O](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [Broadcom KB 424082：`pcipDisablePciErrReporting` 等 Advanced Settings 映射](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
- [Linux PCIe AER Driver Guide](https://docs.kernel.org/PCI/pcieaer-howto.html)
- [QEMU 6.2 `pcie.c`：`x-pcie-extcap-init` 的实际作用](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/pci/pcie.c)
- [QEMU 6.2 `e1000e.c`：无条件初始化 AER](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/net/e1000e.c)
- [QEMU 6.2 `vfio/pci.c`：extended capability rebuild/filter](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/vfio/pci.c)
- [QEMU 6.2 `pcie_aer.c`：status、message 与 Root Error Command 模型](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/pci/pcie_aer.c)
- [QEMU 11.0.2 `pcie_aer.c`：本轮 EMR 正控使用的公开模型](https://gitlab.com/qemu-project/qemu/-/blob/v11.0.2/hw/pci/pcie_aer.c)
