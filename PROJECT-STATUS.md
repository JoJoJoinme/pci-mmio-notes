# Qman DirectPath 项目状态

状态日期：2026-07-21
当前里程碑：`G0-DESIGN-CONVERGENCE`
最终目标：`V3-FULL-DIRECTPATH`
当前可宣告范围：`REFERENCE_AND_QUALIFICATION_MODEL_ONLY`
生产发布状态：`BLOCKED`

本文件是项目进展的人类可读入口；机器可读状态位于
[`contracts/project-status.json`](contracts/project-status.json)，发布门由
[`tools/evaluate_release.py`](tools/evaluate_release.py)计算。若叙述性文档与发布门冲突，
以详细设计中的合同、机器状态和可复现证据为准，不以最近一次聊天结论为准。

产品范围和版本切片的唯一入口为 [`ipd/README.md`](ipd/README.md)，现有设计、验收、证据、
参考模型和历史材料的挂接规则见 [`ipd/MATERIAL-MAP.md`](ipd/MATERIAL-MAP.md)。产品树节点
存在只表示 `DEFINED`，不表示实现、验收或发布完成。
本轮 WSL/QEMU 技术结果、复现命令和关闭边界见
[`ipd/QMAN-TECHNICAL-EVIDENCE.md`](ipd/QMAN-TECHNICAL-EVIDENCE.md)。

## 1. 当前结论

仓库已经具备详细设计、VMware/QEMU 实验依据和可运行的 PCI 资源参考模型，但还不是
可上生产的 DirectPath 控制器。完整 V3 已冻结为唯一目标；G1-G6 是 Static、Managed Owner、
Dynamic、Cluster 和 qualification 的实现波次，不是多个独立产品版本。G0 内允许围绕 F1-F8
执行 VMware/QEMU 参考实验并收敛技术合同，但不得把参考实验冒充 Qman 产品实现或支持声明。

当前已确认的资产：

- K01-K31、R01-R39、C/O/S/D/M/F 验收矩阵已经写入详细设计。
- `pci-resource-model` 的 293 个收集用例在 2026-07-21 重跑：Windows 288 passed / 5 platform skips，WSL 293 passed；
  C20 固定点覆盖 22 个场景，VFIO provider 定向覆盖 27 个场景，Static lease/FSM 定向覆盖
  41 个场景；raw launch handle、QEMU render 与 launch envelope 分别定向覆盖 26、32、30 个场景；
  authoritative snapshot 与 QEMU authorization binding 另有 25 个定向测试和 21 个 subtests。
- VMware ESXi 8.0.3 和 QEMU/OVMF/SeaBIOS 已积累实验与规范化摘要。
- VMware F1-F8/39 Tech Story 可观察模型已建立：4 `VERIFIED`、26 `PARTIAL`、4 `UNKNOWN`、
  5 `NOT_APPLICABLE`；这些状态只描述 VMware reference coverage。
- owner activation 已有纯函数 planner 和 O09 可执行参考场景。
- Qman 技术证据索引已登记 10 条 hash 固定结果：2 条 E2、8 条 E3，覆盖 reference model、
  C20 capability closure、raw QMP/BDF、逐设备 DMA provider、双 64 GiB BAR/OVMF A/B 和最小
  default-deny QMP gate；其中 5 条为 `REFERENCE_ONLY`、5 条为 `COMPONENT_ONLY`。VFIO 组件在
  双 QEMU Guest 中稳定拒绝 no-IOMMU，并真实完成 VFIO cdev/IOMMUFD bind、IOAS attach 与清理；
  Static lease/FSM 组件在 WSL 原生文件系统上通过 7 个真实 subprocess/SIGKILL/SQLite 故障场景；
  Static launch-envelope 组件还把有效 lease、fresh raw fd、stock-QEMU、QMP/QOM 与 bind/IOAS/attach
  trace 串起来，并在无独立 DMA receipt 时不提交 `ATTACHED`、保留 claims 后 quarantine；
  bounded authoritative snapshot 组件已通过真实 subprocess hard-exit、并发 CAS、签名/载荷/重放/
  boot 负向门，并把 sealed authorization 保持到 VFIO/QEMU 启动边界；
  产品 Case/Risk 关闭数仍为 0。
- 101 个设计 Case 中已有 14 个机器定义：C20/O09 为 reference executable，C10/C15/C16/C18/C21/
  F00/F09/F10/S03/S04/S05/S15 为 `PRODUCT / IMPLEMENTATION_BLOCKED`；其余 87 个仍未分类。

当前仍不能宣告的能力：

- 把现有 bounded snapshot publisher 替换为生产 signer/trust root、qualification catalog、外部 rollback
  anchor、kernel atomic generation，并接入唯一产品 host-agent/controller 的生产 VFIO cdev/IOMMUFD 路径。
- 与真实 pidfd/clean-state provider 集成的生产 lease、rollback、quarantine 和 crash reconcile。
- Dynamic matcher/solver 与多级 bridge resource planner。
- host boot agent、multi-host fencing 和 production qualification DB。
- 生产 launcher/controller 与 QMP gate 的 privilege、lease、generation、VFIO 和全入口集成。
- 任何没有通过机器发布门的 supported capability。

## 2. G0 退出条件

| 条件 | 当前状态 | 完成信号 |
| --- | --- | --- |
| 权威入口和实现边界统一 | `DONE` | README、IPD 产品树、详细设计、蓝图均指向本状态页，并统一使用 reference model 表述 |
| ESXi 设备上限合同修正 | `DONE` | 上限由 ESXi build、virtual hardware version 和 Qman verified limit 共同决定 |
| 项目状态可机器检查 | `DONE` | `python tools/evaluate_release.py status` 返回结构有效的状态报告 |
| 产品/平台决策冻结 | `OPEN` | ADR-002/003/005/007/010 均有 owner、decision 和日期 |
| 风险库完成治理字段 | `OPEN` | R01-R39 均有 owner、containment/recovery、test IDs、证据等级与 artifact hash |
| 验收场景完成分类 | `OPEN` | 101 个 Case 均有 `EXECUTABLE`、`IMPLEMENTATION_BLOCKED`、`HARDWARE_BLOCKED` 或 `FEATURE_DISABLED` 定义；reference-only runner 不冒充 product gate |
| 结果证据 schema 统一 | `OPEN` | 现有 evidence JSON 迁移并通过统一 schema 检查 |

`OPEN` 是阻断状态，不允许用“风险已接受”或口头说明绕过。G0 未完成时可以继续做
验证、文档和必要的 reference-model 修正，但不得扩大产品能力声明。

## 3. 里程碑

| ID | 目标 | 状态 | 退出条件摘要 |
| --- | --- | --- | --- |
| G0 | 设计、事实、风险、验收和证据合同收敛 | `IN_PROGRESS` | 本节七项条件全部完成 |
| G1 | Host inventory 与 qualification 基线 | `NOT_STARTED` | authoritative snapshot、capability gate、reset/alias/ACS provenance 闭环 |
| G2 | Static 单机事务控制器 | `NOT_STARTED` | lease、bind/reset/fd/QEMU、rollback/quarantine 和 S00-S16 通过 |
| G3 | Owner activation 与 boot reconcile | `NOT_STARTED` | live/deferred owner executor、early boot claim、O00-O10 通过 |
| G4 | Dynamic 与完整资源规划 | `NOT_STARTED` | Dynamic solver、多级 MMIO planner、D/M 对应用例通过 |
| G5 | 故障恢复与多主机 | `NOT_STARTED` | crash reconcile、fencing、F00-F10 通过 |
| G6 | 生产 qualification 与发布 | `NOT_STARTED` | 风险门无阻断状态，所有对外能力均可追溯到限定 profile 和证据 hash |

已有实验或参考代码不自动推进里程碑。只有对应的产品实现、验收场景和证据同时满足
退出条件，状态才能改为 `DONE`。

## 4. 当前工作队列

按顺序只推进以下四件事：

1. 为 ADR-002/003/005/007/010 指定产品/平台 owner 并冻结决策。
2. 逐条治理 R01-R39；不能闭环的能力明确设为不可绕过的 `FEATURE_DISABLED`。
3. 将现有脚本和单测映射到 101 个 Case，并为剩余 87 个 Case 标明硬件阻塞或实现缺口。

4. 按依赖补证：C20 E2、最小 QMP gate E3、VFIO provider、Static lease/FSM fault 与
   authoritative snapshot fault 与 lease→fresh raw fd→stock-QEMU→QMP/trace→quarantine 的 component E3
   已完成；下一步把 production snapshot authority/catalog、真实 reset/driver restore、独立 DMA/IRQ
   clean-state、pidfd、QMP gate、generation 与唯一 product
   controller 接入同一事务，再执行 S03/S04/S05/F00 与完整 S15/F09 产品矩阵。并行保留
   `VMW-*` 缺口实验和首批 HCL 设备 qualification、reset、IOMMU/ACS、owner、cluster fencing E4。

完成前不新增与 V3 无关的设计主题。发现新事实时，先判断它修改哪个 ADR、risk 或 acceptance case；
如果三者都不属于，就先进入待分类队列，而不是直接展开实现。

## 5. 检查命令

```text
python tools/evaluate_release.py status
python tools/evaluate_release.py run-cases --case O09
python tools/evaluate_release.py release
python -m unittest discover -s tests
python -m unittest discover -s pci-resource-model/tests -t pci-resource-model
```

- `status` 检查合同结构并报告阻断项，当前应成功执行但显示 `BLOCKED`。
- `run-cases` 执行已经定义的场景。
- `release` 是 fail-closed 门；G0 和后续里程碑未闭环时必须返回非零。

## 6. AI 协作规则

任何 AI 任务开始前必须写明四件事：

1. 所属 milestone。
2. 要关闭的 ADR、risk ID 或 acceptance case ID。
3. 可执行的完成信号。
4. 明确不在本次范围内的内容。

任务结束时只允许根据证据更新状态。新增代码、文档篇幅、实验次数和聊天中的“看起来完成”
都不是 milestone 完成信号。
