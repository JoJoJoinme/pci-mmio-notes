# Qman DirectPath 项目状态

状态日期：2026-07-23
当前里程碑：`G1-HOST-INVENTORY-AND-QUALIFICATION-BASELINE`
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

面向内网私有 Qman 仓库的交接不以“先提供源码”为前置：
[`handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md`](handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md)
和 [`contracts/directpath-portable-control-contract.json`](contracts/directpath-portable-control-contract.json)
已经冻结 target-independent port、operation、FSM、CAS、backend、reason、配置/迁移/telemetry 与
parity obligation；[`contracts/qman-integration-map.template.json`](contracts/qman-integration-map.template.json)
保持全部项目 `UNMAPPED/NOT_STARTED`，等待内网 AI 对 exact private commit 做 symbol/interface、
storage/table/transaction 和 test/fixture 绑定。私有源码不需要离开内网，也不需要先提供给本仓库。
`PORTABLE_SPEC_READY` 与 `TARGET_CODE_MAPPED`、`PRODUCT_IMPLEMENTED`、`QUALIFIED` 是四条
独立状态轴，前者不会推进下面的产品 milestone 或 release claim。

## 1. 当前结论

仓库已经具备详细设计、VMware/QEMU 实验依据和可运行的 PCI 资源参考模型，但还不是
可上生产的 DirectPath 控制器。完整 V3 已冻结为唯一目标；G1-G6 是 Static、Managed Owner、
Dynamic、Cluster 和 qualification 的实现波次，不是多个独立产品版本。G0 的设计、决策、风险治理、
验收分类和证据合同已收敛；当前进入 G1，建设生产 Host inventory、capability gate 和首批
qualification profile。参考实验仍不得冒充 Qman 产品实现或支持声明。

当前已确认的资产：

- K01-K31、R01-R39、C/O/S/D/M/F 验收矩阵已经写入详细设计。
- `pci-resource-model` 的 294 个收集用例在 2026-07-23 重跑：Windows 289 passed / 5 platform skips，WSL 294 passed；
  C20 固定点覆盖 22 个场景，VFIO provider 定向覆盖 27 个场景，Static lease/FSM 定向覆盖
  41 个场景；raw launch handle、QEMU render 与 launch envelope 分别定向覆盖 26、32、30 个场景；
  authoritative snapshot 与 QEMU authorization binding 另有 25 个定向测试和 21 个 subtests。
- VMware ESXi 8.0.3 和 QEMU/OVMF/SeaBIOS 已积累实验与规范化摘要。
- VMware F1-F8/40 Tech Story 可观察模型已建立：4 `VERIFIED`、28 `PARTIAL`、3 `UNKNOWN`、
  5 `NOT_APPLICABLE`；这些状态只描述 VMware reference coverage。
- VMware 37 个实验已有 hash-checked machine index：29 项已执行记录绑定代表 run 和 evidence
  文件，6 项 planned 与 2 项 physical-blocked 显式保持 no-run；由 TS 派生的 acceptance 关联没有
  Qman Case、实现、qualification 或 release 关闭权限。`VMW-TRACE-001` 仅由 `PLANNED` 收敛为
  `PARTIAL`，因为历史 pyVmomi task/actor 链和统一 canonical run result 仍不完整。
- Correctable AER 现在必须按两个 profile 解读。历史 `e1000e/status-projection` profile
  的 effective endpoint/root CERE 与 Root COR_EN 均关闭，只证明 status deposition、guest
  projection 和安全负断言。新增 `virtio/controlled-route` profile 已完成 PassthruIdle
  Receiver 的 8 个 E/M/R tuple，8/8 通过：只有 `g100`、`g101` 在 outer QEMU 暂停期间的
  frozen snapshot 出现 Root `COR_RCV` 和 Source，其余六格分别被 endpoint reporting 或
  Correctable mask 阻断；结果 SHA-256 为
  `655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1`。该 frozen
  结果是 QEMU fabric 证据，不是 ESXi service/IRQ 证据；恢复运行后的有界日志窗未观察到匹配
  记录，也不能推出 ESXi 没有 service。Active `g100/g101` 中，virtio guest 可发现 AER
  capability（header `0x00020001`）并看到 raw CES `0→1`，但 Linux AER totals 保持
  `0→0` 且没有实际 kernel AER event；这证明 capability/status visibility 与
  service/event delivery 必须分开。guest write、lifecycle recovery、notification/IRQ
  归因和物理 qualification 仍保持未完成。公开边界以
  [Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/)、
  [KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)、
  [Linux AER 文档](https://docs.kernel.org/PCI/pcieaer-howto.html)和
  [QEMU 11.0.2 AER 源码](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
  为准；后两者只定义参考机制，不证明 VMware 私有实现。
- owner activation 已有纯函数 planner 和 O09 可执行参考场景。
- Qman 技术证据机器索引已登记 11 条 hash 固定结果：2 条 E2、9 条 E3，覆盖 reference model、
  C20 capability closure、raw QMP/BDF、逐设备 DMA provider、双 64 GiB BAR/OVMF A/B 和最小
  default-deny QMP gate，并新增 QEMU Correctable AER 64/64 reference；其中 6 条为
  `REFERENCE_ONLY`、5 条为 `COMPONENT_ONLY`。新增记录只作为 M06/R13 的参考前提，没有
  Case/Risk 关闭权限。VFIO 组件在
  双 QEMU Guest 中稳定拒绝 no-IOMMU，并真实完成 VFIO cdev/IOMMUFD bind、IOAS attach 与清理；
  Static lease/FSM 组件在 WSL 原生文件系统上通过 7 个真实 subprocess/SIGKILL/SQLite 故障场景；
  future-cdev Static launch-envelope 组件还把有效 lease、fresh raw fd、stock-QEMU、QMP/QOM
  与 bind/IOAS/attach trace 串起来，并在无独立 DMA receipt 时不提交 `ATTACHED`、
  保留 claims 后 quarantine；
  bounded authoritative snapshot 组件已通过真实 subprocess hard-exit、并发 CAS、签名/载荷/重放/
  boot 负向门，并把 sealed authorization 保持到 VFIO/QEMU 启动边界；
  产品 Case/Risk 关闭数仍为 0。
- 101 个设计 Case 已全部机器分类：1 个 `EXECUTABLE` reference Case（O09）、
  94 个 `IMPLEMENTATION_BLOCKED`（包括只有 E2 reference runner 的 PRODUCT C20）、
  6 个 `HARDWARE_BLOCKED`，未分类数为 0。
- portable revision `2026-07-23.11` 已冻结 295 个有序映射项，并把完整 Git tree、独立 BuildAttestation、
  六类互斥 runner control artifact、typed Measurement、双签 QualificationRunManifest、Case completion、
  trust history/live freshness 纳入 target-independent baseline；这只证明设计可交接，不证明私有实现。
- 35 个 operation 的 common envelope 已分别绑定 70 个 closed request/result payload profile；Scenario Step
  只能绑定 exact portable fragment 与 immutable request/result fixture；每个执行 iteration 还必须以
  `operationExchanges` 逐 step 保留 raw request/result envelope、digest、payload hash 和结果投影。
- qualification 判定已经拆成可重放的
  `WorkloadEvaluatorManifest → signed EvaluationContext → EvaluationReport → WorkloadResult`；设备类型已经拆成
  独立的 `DeviceTaxonomyDefinition → signed HostAuthority pointer receipt + ClassificationContext → DeviceClassificationRecord`。
  RunRequest/RunManifest/Measurement/Subject 全链固定 exact deviceUid/deviceRecordHash，identity/traits/classification
  必须引用同一 current-snapshot DeviceRecord。guest
  ABI/architecture/OS/kernel/driver 与 runtime platform/backend/IOMMU/machine/firmware 都按完整 tuple 匹配；
  vCPU/memory/capability 与
  runtime capability/provider prerequisite 都必须来自同一 qualification run 的 signed Measurement 并精确匹配，
  不能由配置、catalog、HCL 或结果对象回抄。
- ADR-002/003/005/007/010 均已 `ACCEPTED`；`openDecisions=0`。R01-R39 的 owner、containment/
  recovery、Case 和证据字段已补齐，但 39 条风险状态仍全部为 `OPEN`。

当前仍不能宣告的能力：

- 把现有 bounded snapshot publisher 收敛为生产 signer/trust root、qualification catalog、外部 rollback
  anchor 和 kernel atomic generation，并接入唯一产品 host-agent/controller。
- 在六个已冻结平台行上完成当前 Legacy TYPE1 profile 的 exact subtype、逐设备 IOMMU/IR、
  `AUTHORIZED_DEVICE_PATH` sandbox 与 post-spawn `/proc/<pid>/fd` + QMP/QOM receipt。现有 cdev/IOMMUFD
  结果只是未来独立 backend profile 的组件前提。
- 与真实 pidfd/clean-state provider 集成的生产 lease、rollback、quarantine 和 crash reconcile。
- Dynamic matcher/solver 与多级 bridge resource planner。
- host boot agent、production qualification DB，以及只面向源/目标均在线主机的计划性 cold-relocation
  coordinator。BMC/power fencing 和 host-failure 自动 HA restart 不在 V3 范围。
- 生产 launcher/controller 与 QMP gate 的 privilege、lease、generation、VFIO 和全入口集成。
- 任何没有通过机器发布门的 supported capability。

因此当前的准确结论是：portable contract 可以交给内网 AI 开始 exact mapping，但 target mapping 尚未完成，
产品实现和六平台/设备 qualification 均未证明；生产发布继续为 `BLOCKED`。

## 2. G0 退出条件（已完成）

| 条件 | 当前状态 | 完成信号 |
| --- | --- | --- |
| 权威入口和实现边界统一 | `DONE` | README、IPD 产品树、详细设计、蓝图均指向本状态页，并统一使用 reference model 表述 |
| ESXi 设备上限合同修正 | `DONE` | 上限由 ESXi build、virtual hardware version 和 Qman verified limit 共同决定 |
| 项目状态可机器检查 | `DONE` | `python tools/evaluate_release.py status` 返回结构有效的状态报告 |
| 产品/平台决策冻结 | `DONE` | ADR-002/003/005/007/010 均有 owner、decision 和日期；开放决策为 0 |
| 风险库完成治理字段 | `DONE` | R01-R39 均有 owner、containment/recovery、test IDs 和证据字段；状态仍为 `OPEN` |
| 验收场景完成分类 | `DONE` | 101/101 均为 `EXECUTABLE`、`IMPLEMENTATION_BLOCKED`、`HARDWARE_BLOCKED` 或 `FEATURE_DISABLED`；未分类为 0 |
| 结果证据 schema 统一 | `DONE` | VMware 与 Qman 按 subject-specific schema 统一必备语义；发布门只消费已注册且 hash 校验通过的 result |

G0 的 `DONE` 只表示治理合同收敛，不表示 39 条 `OPEN` 风险已接受，也不表示任何产品
Case 已关闭。风险、验收依赖、缺失证据与未完成里程仍由发布门 fail closed。

## 3. 里程碑

| ID | 目标 | 状态 | 退出条件摘要 |
| --- | --- | --- | --- |
| G0 | 设计、事实、风险、验收和证据合同收敛 | `DONE` | 本节七项条件全部完成 |
| G1 | Host inventory 与 qualification 基线 | `IN_PROGRESS` | authoritative snapshot、capability gate、reset/alias/ACS provenance 闭环 |
| G2 | Static 单机事务控制器 | `NOT_STARTED` | lease、bind/reset/fd/QEMU、rollback/quarantine 和 S00-S16 通过 |
| G3 | Owner activation 与 boot reconcile | `NOT_STARTED` | live/deferred owner executor、early boot claim、O00-O10 通过 |
| G4 | Dynamic 与完整资源规划 | `NOT_STARTED` | Dynamic solver、多级 MMIO planner、D/M 对应用例通过 |
| G5 | 在线主机间的计划性 cold relocation | `NOT_STARTED` | source clean release、target re-solve/attach、失联不接管负向门通过 |
| G6 | 生产 qualification 与发布 | `NOT_STARTED` | 风险门无阻断状态，所有对外能力均可追溯到限定 profile 和证据 hash |

已有实验或参考代码不自动推进里程碑。只有对应的产品实现、验收场景和证据同时满足
退出条件，状态才能改为 `DONE`。

## 4. 当前工作队列

当前只推进 G1 的以下关闭链：

1. 将 bounded snapshot component 接成唯一产品 publisher，补齐 production trust root、key lifecycle、
   external monotonic rollback anchor 和 kernel atomic generation。
2. 实现 backend-neutral 逐设备 capability gate；当前 Legacy profile 必须精确固定 TYPE1v2 或 TYPE1，
   不得 fallback，也不得用未来 cdev/IOMMUFD component PASS 关闭 Legacy 产品 Case。
3. 在六个平台行上建立第一批精确 qualification profile，补 reset/alias/ACS、IOMMU/IR、
   firmware/machine hash 与真实 GPU/HBA/加速卡 E4 证据。
4. 按 acceptance 依赖关闭 G1 对应 Case 和 Risk。VMware 缺口实验只更新 reference coverage；
   BMC、power fencing 和 host-failure 自动 HA 不是 G1/G5/V3 的验收前置。

完成前不新增与 V3 无关的设计主题。发现新事实时，先判断它修改哪个 ADR、risk 或 acceptance case；
如果三者都不属于，就先进入待分类队列，而不是直接展开实现。

## 5. 检查命令

```text
python tools/generate_directpath_portable_package.py --check
python tools/generate_directpath_case_contracts.py --check
python tools/validate_portable_handoff.py baseline --root .
python tools/evaluate_release.py status
python tools/evaluate_release.py run-cases --case O09
python tools/evaluate_release.py release
python -m unittest discover -s tests
python -m unittest discover -s pci-resource-model/tests -t pci-resource-model
```

- `generate... --check` 与 portable `baseline` 不需要私有代码，分别检查生成闭包漂移和 target-independent
  语义；两者当前必须返回 0。
- `status` 同时执行 portable baseline、检查全部项目合同并报告阻断项，当前应成功执行但显示 `BLOCKED`。
- `run-cases` 执行已经定义的场景。
- `release` 还要求 `--map` 指向四轴均提升的 detached final map，并从仓库外提供 trust-root/key-ring
  rollback/catalog rollback 状态；默认 UNMAPPED template、当前 G1-G6、39 条 `OPEN` 风险和未闭环 Case
  都使其必须返回非零。

## 6. AI 协作规则

任何 AI 任务开始前必须写明四件事：

1. 所属 milestone。
2. 要关闭的 ADR、risk ID 或 acceptance case ID。
3. 可执行的完成信号。
4. 明确不在本次范围内的内容。

任务结束时只允许根据证据更新状态。新增代码、文档篇幅、实验次数和聊天中的“看起来完成”
都不是 milestone 完成信号。
