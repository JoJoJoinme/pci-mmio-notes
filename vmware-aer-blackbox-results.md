# ESXi DirectPath PCIe AER 黑盒验证与 QEMU 对标

首次记录：2026-07-11
校正与增量验证：2026-07-23

## 1. 范围与结论

本报告只描述自有隔离实验环境中的公开接口、PCI config space、guest 输出和公开日志，
不推导 VMware 私有代码。

结论先行：ESXi 8.0 U3 的 guest AER surface 是 **profile-specific**。历史 `e1000e`
DirectPath profile 没有把 PCIe AER capability discovery 原样交给 guest：endpoint 的 AER
Extended Capability header 在 guest raw view 中为 0，guest ACPI 也不授予 AER ownership；
但是 capability body 的 status 寄存器仍可通过 raw config read 观察。这个结论只属于该
profile 的 **surface/status projection**，不是所有 DirectPath 设备的通用规则。

2026-07-23 的历史门控读回把 `e1000e` profile 的结论进一步收窄：被测外层 `e1000e` 的 endpoint
`DeviceCtl.CERE=0`，upstream Root Port 的 `DeviceCtl.CERE=0`，Root Error Command 的
`COR_EN=0`；`Advisory Non-Fatal`、`Corrected Internal Error` 和 `Header Log Overflow`
还被默认 CEM `0x0000e000` 屏蔽。因此这组历史 ESXi 结果不能证明 `ERR_COR` 已送达 Root
Port、ESXi 已执行 Root service 或产生中断。公开日志只能写成“在采集窗口内未观察到
匹配项”，不能反推 VMware 内部没有处理。

同日新增的 `virtio-net-pci` profile 使用可读回的受控 gate lease：独立打开 upstream
`BridgeCtl.SERR` 与 Root `DeviceCtl.CERE`，再完整遍历 `G=(E,M,R)` 的八种组合。QEMU
公开模型完成 8 bit × 8 gate 的 64/64 正控；ESXi PassthruIdle Receiver Error 完成
8/8。outer QEMU 冻结期间，只有 `E=1,M=0` 的 `g100/g101` 记录 Root Correctable reception
与 endpoint Source ID，其余六种 gate 均阻断 Root reception。该冻结快照证明的是
**QEMU fabric transport 在 ESXi 暂停时的状态沉积**，不是 ESXi Root service、IRQ 或私有
实现证明。恢复 ESXi 后的寄存器、owner 与日志只作为独立黑盒观察；未见匹配日志仍只是
bounded negative。

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

在 QEMU surface A/B 中，这不是 OVMF/SeaBIOS 的差异：Stock QEMU 6.2 的 Q35、Root
Port、`e1000e` 和 `vfio-pci` 默认会暴露 AER；`x-pcie-extcap-init=off` 也不会删除设备
随后创建的 AER capability。VMware DirectPath 本轮只验证 EFI guest，不能由这组 QEMU
A/B 外推 VMware SeaBIOS。完整对标需要 opt-in config-space filter，并版本化虚拟 Root
Port 的 AER capability/service。

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
| ESX-COR-I8 | VM Passthru、未分配 | 8 个 Correctable bit，逐例 W1C/readback | 8/8 status-projection oracle PASS；UES 与 root Uncorrectable surface 保持 0 |
| ESX-COR-A0 | VM Passthru、L3 活跃 | Receiver Error | host/guest CES 0→1，owner 稳定；routing 不可测 |
| ESX-COR-A5 | VM Passthru、L3 活跃 | Advisory Non-Fatal Correctable bit | host/guest CES 0→0x2000，owner 稳定；该位 CEM=1 且 CERE=0，routing 不可测 |
| ESX-VIRTIO-I-EMR8 | VM Passthru、未分配 | Receiver Error × `g000`—`g111`，Root path lease 打开 | 8/8 PASS；frozen transport 仅 `g100/g101` Root reception，八行均恢复 gate |
| ESX-VIRTIO-A-EMR2 | VM Passthru、L3 活跃 | Receiver Error × `g100/g101` | 两个 gate 均有独立 PASS：capability 可发现、raw CES `0→1`、AER totals `0→0`、无 kernel event；v2 聚合中的未注入 g101 只保留为 harness history |

C02d、C03 均由 `vmware.log` 中目标 `pciPassthru1` 的首次真实访问加 12 秒触发，
而不是猜测固定开机时间。QEMU HMP 均返回目标 function 的明确 `OK id`。

## 4. 四层外部可观察证据

每个新 case 分开保存：L0 注入 ACK 与运行来源、L1 endpoint/root config、L2 ESXi
owner 与有界日志、L3 guest raw config/ACPI/日志。四层不是四份独立物理证据：ESXi
`lspci` 与外层 QTest 读取同一 config space，guest raw body 也可能是该空间的投影；
它们不能相互代替来证明 message delivery。

### 4.1 Correctable Receiver Error

物理 endpoint / ESXi view：

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

物理 endpoint / ESXi view：

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

外部可观察模型因此是：

1. AER Extended Capability header 与 PCIe Device Status 可被 VMware 过滤或合成。
2. capability body 的 error status 可保留物理设备状态并由 raw config read 看见。
3. 在历史 `e1000e` profile 中，guest 没有 AER capability discovery 和 Root Port AER
   service，driver 也没有打开 endpoint Device Control 的 error-reporting bits；这不是
   `virtio-net-pci` profile 的通用结论。
4. 在本次 effective gate 下未观察到 Root reception；因为 CERE=0，这不是“ESXi 收到后
   静默”的证据。公开 QEMU 模型中只有 CERE=1 且目标 bit 未屏蔽时才形成可路由消息，
   该规则是实验判别正控，不是 VMware 私有实现推断。

以上四点是历史 `e1000e` profile 的观察，不能被后续 virtio fixture 原地覆盖。

### 4.3 `virtio-net-pci` route-enabled EMR

受控 profile 将 endpoint CERE、当前 bit 的 CEM 和 Root COR_EN 定义为
`G=(E,M,R)`，并把 upstream `BridgeCtl.SERR=1`、Root `DeviceCtl.CERE=1` 作为独立
root-path lease。每个 case 都在 outer QEMU 暂停后完成注入前快照、Correctable-only
HMP 注入和立即 QTest 快照，再恢复 ESXi、采集 post-resume timeline，最后恢复原 gate。

| Gate | endpoint CES/CED | frozen Root reception/source | 解释 |
| --- | --- | --- | --- |
| `000`、`001` | 记录 Receiver | 无 | endpoint CERE 关闭 |
| `010`、`011` | 记录 Receiver | 无 | endpoint CERE 关闭且 bit masked |
| `100`、`101` | 记录 Receiver | 有；Source 匹配 `01:00.1` | `E=1,M=0` 允许 QEMU fabric reception |
| `110`、`111` | 记录 Receiver | 无 | 当前 bit 被 mask |

`g100` 与 `g101` 的 frozen Root Status/Source 相同，说明在 QEMU 11 公开模型中，R 控制
notification eligibility，而不是决定已经到达的 Correctable message 是否沉积到 Root
Status。这个结论属于 QEMU 模型和本次虚拟 fabric；不能据此命名 VMware 内部处理路径。
八行均保持 Uncorrectable surface 为零并恢复受控 gate。ESXi 恢复后的日志未见匹配项只记为
`NOT_OBSERVED_IN_CAPTURED_TAIL_WINDOW`，不能升级成“未 service”或“无 IRQ”。

Active `g100/g101` 进一步表明：两种 R 值下都能在冻结 fabric 中观察到同一类 Root
reception；恢复后 guest 可发现 AER header 并看到 raw CES `0→1`，owner 保持同一 VM，
Uncorrectable surface 为零。guest Linux AER totals 没有增加且没有实际 AER event。
`R=0` 与 `R=1` 在当前公开观测面上没有形成可归因的 ESXi/guest service 差异；这只能写成
“notification/service effect 尚未识别”，不能写成 R 对 VMware 无效。

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
无条件调用 `pcie_aer_init()`。`vfio-pci` 的 extended-capability rebuild 也默认保留
AER，只显式丢弃 capability ID 0、SR-IOV、ARI 和 ReBAR。

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
| `20260723-esxi8-aer-virtio-idle-emr-v2` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-idle-emr-v2/result.json` | `655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1` | Idle Receiver EMR 8/8 PASS；frozen QEMU fabric + ESXi post-resume black box |
| `20260723-esxi8-aer-virtio-active-emr-representative-v2` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-emr-representative-v2/result.json` | `4fe5e83789f8c509476e32630cc3b20960ca995e0637ccb53bcdde479089aaae` | aggregate INCONCLUSIVE：g100 PASS；g101 因观察窗不足未注入 |
| `20260723-esxi8-aer-virtio-active-g101-final-v1` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-g101-final-v1/result.json` | `c4511cb3514fd27b992a44af44c7dbdcf339c1a364730adcd06fb884ba700d72` | g101 PASS；guest parser 已修正，host SCP-path 假阳性由 raw log 重分类 |
| `20260723-esxi8-aer-virtio-active-g100-parser-final-v1` | `../_artifacts/vmware-directpath-runs/20260723-esxi8-aer-virtio-active-g100-parser-final-v1/result.json` | `bd455a4d9278e53687cf16dd2cfefe161bad78ec946249725a614dce2dd975c0` | g100 PASS；最终 guest/host semantic parser live smoke，实际 event 均为 0 |

当前两个 Python 入口：

```bash
python3 vmware-esxi8-lab/test_qemu_aer_correctable_matrix.py \
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 \
  --output <EMPTY_QEMU_OUTPUT_DIRECTORY>

python3 vmware-esxi8-lab/test_esxi_aer_correctable_matrix.py \
  --host <ESXI_ADDRESS> --owner-state PassthruIdle \
  --error-bits receiver_error --gate-tuples 000,001,010,011,100,101,110,111 \
  --enable-root-path \
  --qemu-monitor <HMP_SOCKET> --qtest-socket <QTEST_SOCKET> \
  --qtest-clean-baseline --qtest-baseline-policy strict \
  --outer-endpoint-bdf <OUTER_ENDPOINT_BDF> --outer-root-bdf <OUTER_ROOT_BDF> \
  --esxi-bdf <ESXI_ENDPOINT_BDF> --esxi-root-bdf <ESXI_ROOT_BDF> \
  --output <EMPTY_ESXI_OUTPUT_DIRECTORY>
```

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
