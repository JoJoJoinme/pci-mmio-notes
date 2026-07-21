# IPD 产品树资料挂接图

本文档说明当前仓库中的设计、依据、验收和实验资料怎样补充
[`EPIC-PCI-01 → F1-F8 → User Story → Tech Story`](README.md)，以及哪些资料不能作为节点
完成证明。它是资料导航，不是第二棵需求树。

## 1. 资料在树外，关系挂在树上

```text
产品主干：Epic → Feature → User Story → Tech Story
                         │
                         ├─ Capability K01-K31
                         ├─ ADR / Risk R01-R39
                         ├─ Acceptance Case C/O/S/D/M/F
                         └─ Evidence artifact + hash
```

采用多对多附件而不是把文档塞进产品层级，原因是同一个设计章节或实验通常支撑多个故事；
反过来，一个故事也需要规范、实现、验收和真实硬件证据共同闭环。

### 资料类型

| `basis_kind` | 用途 | 能否单独关闭产品节点 |
| --- | --- | --- |
| `STATUS_GATE` | 当前 milestone、claim、阻断项和发布结果 | 否；它只裁决状态 |
| `NORMATIVE_DESIGN` | Qman 必须满足的技术语义和安全不变量 | 否 |
| `IMPLEMENTATION_BLUEPRINT` | 模块、schema、事务和提交顺序 | 否 |
| `ACCEPTANCE` | Case、runner、判据和负向门 | 只有产品 scope 且证据合格时参与关闭 |
| `OFFICIAL_CONTRACT` | Broadcom/QEMU/Linux/PCI 等官方资料 | 否；用于建立外部合同或假设 |
| `REFERENCE_OBSERVATION` | VMware/QEMU 黑盒或 trace 观察 | 否；说明被观察对象的行为 |
| `REFERENCE_MODEL` | 算法、schema、纯函数和单测参考实现 | 否 |
| `QMAN_VERIFICATION` | 对 Qman 产品实现的可复现验证 | 需与 Case/Risk/证据等级一起判断 |
| `QMAN_QUALIFICATION` | 指定真实平台/设备 profile 的资格证据 | 需通过发布门 |
| `HISTORICAL_INPUT` | 早期研究、聊天、旧副本、incident 报告 | 否 |

`basis_kind` 描述“这份材料是什么”，`subject` 描述“验证了谁”。Qman 技术结果再使用
[`qman-technical-evidence.schema.json`](../contracts/qman-technical-evidence.schema.json) 中明确冻结的
E2/E3/E4 表达证据强度；它不能代替 `basis_kind` 或 `subject`。旧文档中相互冲突、未带 schema
版本的裸 E1-E4 定义不再参与状态裁决。

## 2. 权威裁决顺序

| 问题 | 第一权威入口 | 补充入口 |
| --- | --- | --- |
| 产品要交付什么、版本边界是什么 | `ipd/README.md` | `contracts/ipd-tree.json` |
| 当前做到哪里、能宣告什么 | `PROJECT-STATUS.md` + `contracts/project-status.json` | `tools/evaluate_release.py` 输出 |
| 技术语义和安全不变量是什么 | `qemu-static-dynamic-directpath-design.md` | K01-K31、R01-R39 |
| 工程上怎样实现 | `qman-directpath-implementation-blueprint.md` | reference model、patch、lab harness |
| Qman 产品 Case ID 是什么 | 详细设计第 19 节 + `acceptance/cases/` | `contracts/acceptance-policy.json` |
| VMware 官方合同和当前观察覆盖 | `ipd/VMWARE-BEHAVIOR-MODEL.md` | `contracts/vmware-source-register.json`、`contracts/vmware-behavior-model.json`、专项报告与 evidence |
| Qman 技术证据能证明什么 | `ipd/QMAN-TECHNICAL-EVIDENCE.md` | `contracts/qman-evidence-index.json` + `contracts/qman-technical-evidence.schema.json` |
| 能否发布 | `tools/evaluate_release.py release` | 任何叙述性文档都不能覆盖该结果 |

详细设计和实现蓝图都覆盖全链路，但职责不同：前者是规范性 technical contract，后者是其
派生实现蓝图。它们都不再承担 Epic/Feature/User Story 的产品层定义。

### 外部官方依据现状

- 详细设计第 24 节把 Broadcom KB 312208/API 行为整理为 K01-K31 capability contract，
  第 26 节维护 Broadcom、QEMU、Linux/VFIO、UEFI/PCI 等公开依据。
- 实现蓝图第 20 节维护实现侧“规范与证据索引”。
- VMware 验收计划末尾维护面向黑盒实验的参考资料。

这些官方链接用于建立 external contract 或待验证假设；本地 ESXi/QEMU 报告用于记录实际
观察，两者不可互相替代。现已建立
[`contracts/vmware-source-register.json`](../contracts/vmware-source-register.json)，用
`source-id → claim → baseline/limitations → affected TS/Case` 管理 VMware 官方依据；详细设计
第 26 节继续作为跨 VMware/QEMU/Linux/PCI 的公开依据主索引。

## 3. 按 Feature 挂接当前资料

表中的“证据”均是当前可复用输入，不代表 Feature 已完成。
每个 Feature 下的 39 个 Tech Story 已统一映射到
[`VMWARE-BEHAVIOR-MODEL.md`](VMWARE-BEHAVIOR-MODEL.md)；该映射只更新 VMware reference
coverage，不更新 Qman implementation/qualification 状态。

| Feature | 规范/实现补充 | 验收入口 | 当前依据与证据 | 当前缺口 |
| --- | --- | --- | --- | --- |
| F1 设备可见性与支持资格 | 详细设计 inventory/capability/dependency；实现蓝图 snapshot/provider/qualification | 设计 C00-C21；C20 reference executable | `vmware-esxi8-passthru-capable-observed-model.md`、`evidence/esxi8-directpath-20260714-summary.json`、`QMAN-E2-REFERENCE-MODEL-001`、`QMAN-E2-CLOSURE-001`、`QMAN-E3-DMA-PROVIDER-001`、`QMAN-E3-VFIO-PROVIDER-GATE-001`、`kernel-patches/` | C20 仅为 E2 reference；VFIO provider 仅为 component，仍无权威产品 snapshot publisher 和首批真实设备 qualification profile |
| F2 设备池与宿主业务共存 | 详细设计 trust/owner；蓝图 owner activation/attach lease | 设计 O00-O10；当前仅 O09 已定义 | `evidence/esxi8-passthru-activation-20260718.md`、no-IOMMU A/B、activation reference model | O09 是 reference scope；live/deferred executor、boot reconcile 未实现 |
| F3 Static 固定设备分配 | 详细设计 Static；蓝图 Static transaction/compensation | 设计 S00-S16；S03/S04/S05/S15 product blocked | `vmware-esxi8-directpath-local-results.md`、DMA/reset/reboot summaries、`QMAN-QEMU-CONTROL-001` 威胁正控、`QMAN-E3-VFIO-PROVIDER-GATE-001`、`QMAN-E3-QMP-GATE-001` 与 `QMAN-E3-STATIC-LEASE-FAULT-001` 组件证据 | standalone durable lease/FSM 已有；仍缺 stock-QEMU fd-only 产品 attach、QMP gate/唯一 launcher 接线、真实 rollback/clean-state provider |
| F4 VM 准入与 Guest 兼容 | 详细设计 BAR/MMIO/Guest ABI；蓝图 planner/guest surface | 设计 M00-M23；复用 F09 bypass gate | firmware layout、MMIO comparison、`QMAN-E3-MMIO-OBSERVED-001`、`QMAN-QEMU-CONTROL-001`、`QMAN-E3-QMP-GATE-001` | 通用多级 planner、生产 API/CLI/storage/QMP 全入口 gate、版本化首批 profile 和产品 post-start verify 未实现 |
| F5 生命周期与故障恢复 | 详细设计 rollback/crash/quarantine；蓝图 compensation/reconcile | 设计 F00-F02/F09，并复用 S03-S12；F00 product blocked | host-crash、DMA teardown、MSI/reset、reboot/INTx summaries、`QMAN-E3-QMP-GATE-001`、`QMAN-E3-STATIC-LEASE-FAULT-001` | standalone journal/reconcile/quarantine 已有；仍缺真实 QEMU pidfd/owner、DMA/IRQ/reset cleanup、生产全入口 bypass matrix 和物理 clean-state 证明 |
| F6 Dynamic 动态分配 | 详细设计 Dynamic；蓝图 Dynamic transaction | 设计 D00-D14 | `vmware-esxi8-directpath-local-results.md`、dynamic-envelope/directpath summaries | matcher/global solver/atomic multi-reservation 未实现 |
| F7 跨主机放置与冷恢复 | 详细设计 multi-host；蓝图 cold relocate/fencing | 设计 F03-F08 | vMotion rejection、host-crash、Dynamic cold-relocate 观察 | consensus store、fencing token、BMC fence proof 和 Qman cluster 实现均缺失 |
| F8 可运维、审计、发布 | 详细设计 API/audit/risk/gate；蓝图 audit/evidence | F09-F10 + 全部 Case/Risk 的追踪和发布门 | `PROJECT-STATUS.md`、`contracts/qman-evidence-index.json`、`tools/evaluate_release.py`、8 条已登记 Qman E2/E3 结果 | US→Case→Evidence 尚未完整；92/101 Case 未分类；当前为 5 reference + 3 component，产品 closure 仍为 0 |

### 主要材料的具体定位

| 路径 | `basis_kind` | 使用边界 |
| --- | --- | --- |
| `qemu-static-dynamic-directpath-design.md` | `NORMATIVE_DESIGN` | 技术合同；不是产品树或完成状态 |
| `qman-directpath-implementation-blueprint.md` | `IMPLEMENTATION_BLUEPRINT` | 从技术合同派生；不能覆盖产品范围和状态 |
| `ipd/VMWARE-BEHAVIOR-MODEL.md` | `OFFICIAL_CONTRACT` + `REFERENCE_OBSERVATION` | VMware F1-F8/39 TS 的唯一可观察模型入口；不声称私有源码实现 |
| `contracts/vmware-source-register.json` | `OFFICIAL_CONTRACT` | 官方 source/claim/baseline/limitations 注册表 |
| `contracts/vmware-behavior-model.json` | `REFERENCE_OBSERVATION` | TS→VMW experiment→evidence 的机器覆盖合同 |
| `contracts/vmware-experiment-result.schema.json` | `ACCEPTANCE` | 新 VMware run 的统一环境、观察、限制和 artifact hash schema |
| `ipd/QMAN-TECHNICAL-EVIDENCE.md` | `QMAN_VERIFICATION` 导航 | Qman/参考 subject 的证据等级、结论、限制和复现入口；不直接改变 milestone |
| `contracts/qman-evidence-index.json` | `STATUS_GATE` | TS→Case→Risk→result/hash 机器索引；由 evaluator 检查关闭权限和 hash 漂移 |
| `contracts/qman-technical-evidence.schema.json` | `ACCEPTANCE` | Qman E2/E3/E4 result 的 subject、SUT、mapping、artifact、limitation 和 closure 合同 |
| `vmware-directpath-acceptance-test-plan.md` | `ACCEPTANCE` + `REFERENCE_OBSERVATION` | 旧实验计划；原 Case ID 只作 legacy alias，canonical ID 由 VMware 行为模型定义 |
| `vmware-esxi8-directpath-local-results.md` | `REFERENCE_OBSERVATION` | VMware 黑盒主报告；不是 Qman 产品证据 |
| `vmware-esxi8-passthru-capable-observed-model.md` | `REFERENCE_OBSERVATION` | 实验归纳；不是 qualification 算法合同 |
| `pci-resource-model/` | `REFERENCE_MODEL` + bounded component code | 纯函数/资源决策参考与 standalone VFIO/Static components；当前 165 个单测不等于生产 controller |
| `kernel-patches/` | `IMPLEMENTATION_BLUEPRINT` | ACS provenance 参考方案；构建成功不等于运行时验收 |
| `vmware-esxi8-lab/` | `ACCEPTANCE` | harness/复现入口；必须由 Case 引用 |
| `evidence/*.json`、`evidence/*.md` | 依 subject 分类 | 需携带 Case、Risk、环境和 hash，不能直接挂 Feature 宣告完成 |
| `_artifacts/` | 原始 artifact | 由规范化 summary/hash 间接引用，不直接挂产品节点 |

## 4. 资料冲突治理状态

这些都是工程治理项，不是需要用户选择两套错误定义的产品决策。

| ID | 冲突 | 状态 | 已采用规则 / 剩余工程动作 |
| --- | --- | --- | --- |
| MAT-CONFLICT-01 | VMware 旧 Case 与 Qman C/O/S/D/M/F、Risk R* 同名异义 | `RESOLVED_BY_NAMESPACE` | VMware canonical Case 统一为 `VMW-*`，旧 ID 只作 `legacyIds`；现有 artifact 不改名以保持 hash |
| MAT-CONFLICT-02 | 两份旧文档对 E1-E4 定义不同 | `RESOLVED_BY_SCHEMA` | VMware 模型使用 `subject + basisKind + observationStatus`；Qman 结果只按 versioned schema 使用 E2/E3/E4。旧裸等级不参与 gate；剩余任务是迁移旧 result |
| MAT-CONFLICT-03 | Static、owner、planner 的阶段顺序不同 | `PRODUCT_DECIDED / TOP_LEVEL_SYNCED` | 唯一目标为完整 V3，W1-W6 是实现波次；详细设计/蓝图中的 Phase 仅作为各波次内部技术子阶段，不再代表独立产品版本 |
| MAT-CONFLICT-04 | 详细设计和蓝图重复承担产品范围 | `GOVERNED` | IPD 管产品范围，详细设计管技术语义，蓝图管实现；后续用引用减少复制 |

截至当前，没有任何本地材料能证明 **Qman 产品在目标真实平台/设备上的生产 qualification**。
VMware E4 或 QEMU/参考模型结果都不能替代 Qman product subject 的资格证据。

## 5. 根目录历史材料如何保留

| `E:\Code\PCI` 根目录材料 | 挂接位置 | 规则 |
| --- | --- | --- |
| `acs-override-safe-iommu-groups.md` | F1/TS-F1-03 的 `HISTORICAL_INPUT` | 结论进入正式设计后才具规范性 |
| `dpdk-vfio-noiommu-behavior.md` | F1/TS-F1-02、F2 的 `HISTORICAL_INPUT` | 以仓库内新证据和正式设计为准 |
| `qemu-vmware-mmio-comparison.md` | F4 的旧输入 | `github-export/` 版本为维护副本，根目录副本不再演进 |
| `pci-passthrough-dpdk-vfio-summary.md` | Epic/F1/F2 背景 | 不代表当前实现状态 |
| `deep-research-report.md` | 历史研究草稿 | 含不可独立核验 citation token，不作规范依据 |
| `ChatGPT-ACS安全IOMMU组问题.md` | 聊天档案 | 不进入合同或发布证据 |
| `Emulex双口HBA直通Code10测试计划报告.docx` | F1/F4/F5 的 incident/test input | 映射到精确 profile、Case、Risk、环境和 hash 后才可进入 qualification |

## 6. 新资料的最小挂接合同

新增材料至少回答以下问题，答不全则先进入待分类队列：

1. 它支撑哪个 `US-*` 或 `TS-*`？
2. 它的 `basis_kind` 和 subject 是什么？
3. 若是验证材料，它执行哪个 Qman Case、覆盖哪些 Risk？
4. 环境、设备、固件、Guest、驱动和 workload 版本是什么？
5. 原始 artifact 在哪里，SHA-256 是什么？
6. 它能改变哪个 machine-readable 状态；如果不能，就只补充知识，不更新 milestone。

推荐的最终追踪链为：

```text
EPIC / Feature / User Story
        ↓
Tech Story / ADR / Risk
        ↓
Acceptance Case
        ↓
Evidence Artifact + Hash
        ↓
Milestone / Release Gate
```
