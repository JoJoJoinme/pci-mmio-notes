# Qman PCI DirectPath IPD 产品树

状态：`ACCEPTED PRODUCT DIRECTION / NOT IMPLEMENTED`
当前产品声明：`REFERENCE_AND_QUALIFICATION_MODEL_ONLY`
当前里程碑：`G0-DESIGN-CONVERGENCE`
最终目标：`V3-FULL-DIRECTPATH`

本文档是项目在 **Epic → Feature → User Story → Tech Story** 层级上的唯一产品树入口。
它回答“要交付什么、为什么、按什么波次实现”；当前进展、风险和证据是否足以发布，仍由
[`PROJECT-STATUS.md`](../PROJECT-STATUS.md) 和机器发布门决定。

当前节点只是完成了定义，并不表示实现完成或能力可对外宣告。现有设计、实验和参考模型
如何挂到树上，见 [`MATERIAL-MAP.md`](MATERIAL-MAP.md)；机器可读关系见
[`contracts/ipd-tree.json`](../contracts/ipd-tree.json)。
当前 Qman/reference-side 的 TS→Case→Risk→result/hash 证据链见
[`QMAN-TECHNICAL-EVIDENCE.md`](QMAN-TECHNICAL-EVIDENCE.md)；它补充树，不改变树节点状态。

## 1. 读树规则

```text
EPIC-PCI-01  产品目标
└─ F1-F8     可独立验收的产品能力
   └─ US-*   用户可感知的结果
      └─ TS-* 为结果提供实现能力的技术工作

ADR / Risk / Capability(K*) / Acceptance Case / Evidence
└─ 作为多对多附件挂到 TS 或 US，不成为第五层产品节点
```

- 每个 Feature、User Story 和 Tech Story 只有一个主父节点，以保证范围和责任不漂移。
- Tech Story 后的 `supports` 表示它还支撑哪些 User Story，不复制出第二个节点。
- 设计文档、代码、测试和实验报告只是树的补充材料；它们本身不能把节点变成 `DONE`。
- Feature 完成必须同时满足：对应 User Story 有可执行 Case、阻断风险闭环、证据 subject/grade
  符合发布合同、机器发布门通过。

### 通用机制与兼容性列表不是一回事

Qman 的技术目标是数据驱动、设备类型无关的 PCI DirectPath engine，不按 NIC/GPU/HBA
或某个 VID:DID 编写专用主流程；只要设备实例满足 DMA 隔离、dependency bundle、reset、
owner、MMIO/拓扑和 Guest 约束，引擎原则上都应能生成安全计划。

产品支持则采用 VMware 式兼容性列表，只对精确、版本化且通过真实硬件资格验证的 profile
承诺 `SUPPORTED`：

| 维度 | 判断对象 | 定义 |
| --- | --- | --- |
| `TECHNICALLY_ATTACHABLE` | 设备实例 + host snapshot | 通用引擎能生成不违反硬安全约束的 attach plan；QEMU 能启动本身不等于成立 |
| `ELIGIBLE` | 当前 VM 分配请求 | technically attachable，且设备此刻可用、健康、未被租用，owner/fence/资源和策略均满足 |
| `QUALIFIED` | 精确版本化 profile | platform/BIOS/kernel/QEMU/firmware/device firmware/Guest/driver/workload/feature 组合通过 Qman 真实硬件 Case，并绑定 evidence hash |
| `SUPPORTED` | 产品支持合同 | qualified profile 被当前 V3 compatibility catalog 正式纳入支持范围 |

必须保持以下不变量：

```text
PRODUCTION_ELIGIBLE  => SUPPORTED profile match
SUPPORTED            => QUALIFIED
ELIGIBLE             => TECHNICALLY_ATTACHABLE

TECHNICALLY_ATTACHABLE != QUALIFIED
VMware observation      != Qman QUALIFIED / SUPPORTED
```

非兼容性列表设备可以进入显式、隔离的 `UNQUALIFIED_LAB` 验证流程，以检验通用机制；它不能
进入生产调度、不能产生支持承诺，也不能用一次成功开机升级为 `SUPPORTED`。

## 2. 产品树

```text
EPIC-PCI-01  Qman 生产级 PCI DirectPath 服务
│  结果：在不破坏宿主 DPDK 的前提下，把合格 PCI 设备安全、可管理、可审计地交给 VM；
│        Static 与 Dynamic 共用同一套隔离、事务、恢复和资格体系。
│
├─ F1 设备可见性与支持资格
│  ├─ US-F1-01 运维人员能看到设备身份、拓扑、当前 owner 与用途
│  │  ├─ TS-F1-01 生成带 epoch/hash 的 immutable host snapshot
│  │  ├─ TS-F1-02 建立逐设备 DMA provider 证明并隔离 DPDK/no-IOMMU 语义
│  │  └─ TS-F1-03 忽略 ACS override 重建 physical isolation domain
│  ├─ US-F1-02 运维人员能得到 supported/conditional/unsupported 结论及原因
│  │  └─ TS-F1-04 计算 dependency bundle 与不可分割闭包
│  └─ US-F1-03 产品负责人能冻结精确平台、设备、固件、Guest、驱动和 workload 范围
│     └─ TS-F1-05 建立版本化 qualification profile 与支持矩阵
│
├─ F2 设备池与宿主业务共存
│  ├─ US-F2-01 运维人员能把设备标记为 host/DPDK 保留或 VM 可用池
│  │  ├─ TS-F2-01 实现 admin/desired/effective/pending owner 状态模型
│  │  └─ TS-F2-02 owner 切换前完成 bundle、占用和维护预检
│  ├─ US-F2-02 运维人员能看到期望 owner、实际 owner、待重启和维护状态
│  │  ├─ TS-F2-04 为必须抢占的设备生成精确 early-boot claim
│  │  └─ TS-F2-05 重启后按身份、驱动和 owner 进行 reconcile
│  └─ US-F2-03 设备被宿主业务占用时系统拒绝切换并说明原因
│     └─ TS-F2-03 bundle live rebind 必须全成或全量回滚
│
├─ F3 Static 固定设备分配
│  ├─ US-F3-01 管理员能把一个精确设备分配给指定 VM
│  │  └─ TS-F3-03 在 lease 内完成 bind、IOMMUFD、reset 和 fd-only QEMU attach
│  ├─ US-F3-02 VM 重启或重新开机后仍使用同一块物理设备
│  │  ├─ TS-F3-01 用 deviceUid + fingerprint 持久化身份而不是只保存 BDF
│  │  └─ TS-F3-04 同 BDF 身份变化时 fail closed
│  ├─ US-F3-03 同一设备不能被两个 VM 或宿主同时占用
│  │  └─ TS-F3-02 对 dependency bundle 获取 CAS durable lease
│  └─ US-F3-04 不可分割 function/dependency 必须作为一个 bundle 分配
│     └─ TS-F3-05 用单一事务 FSM 编排 Static 全生命周期
│
├─ F4 VM 启动准入与 Guest 兼容
│  ├─ US-F4-01 VM 启动前能校验设备、固件、内存、BAR/MMIO 和拓扑约束
│  │  ├─ TS-F4-01 规划完整 Guest PCI tree、bridge window、MMIO 与设备上限
│  │  └─ TS-F4-03 预留完整 Guest memory/address-space 资源
│  ├─ US-F4-02 不兼容时用户能获得稳定、具体、可行动的拒绝原因
│  │  └─ TS-F4-05 在 API、QMP 和进程边界阻止绕过准入的 raw QEMU 启动
│  └─ US-F4-03 成功启动后 Guest 获得稳定的 slot、BAR、IRQ/IOMMU 与驱动表面
│     ├─ TS-F4-02 冻结版本化 Q35/OVMF/QEMU 配置 profile
│     └─ TS-F4-04 启动后核验 BAR、bridge、IRQ 与 IOMMU 实际状态
│
├─ F5 设备生命周期与故障恢复
│  ├─ US-F5-01 VM 正常关机后设备能安全释放
│  │  └─ TS-F5-02 按 DMA/IRQ/map/reset/owner 顺序执行 teardown
│  ├─ US-F5-02 VM 被强制关闭后设备不会在状态不明时直接复用
│  │  └─ TS-F5-01 冻结 reset contract 并在执行前重检 affected set
│  ├─ US-F5-03 QEMU 或控制器崩溃后系统能恢复或给出确定隔离状态
│  │  └─ TS-F5-03 使用 durable journal 与 crash reconcile 恢复事务
│  └─ US-F5-04 无法证明设备干净时整个 bundle 被 quarantine
│     ├─ TS-F5-04 实现 whole-bundle quarantine 与人工恢复门
│     └─ TS-F5-05 在所有入口拒绝 snapshot、suspend、FT、live migration 和 runtime hotplug
│
├─ F6 Dynamic 动态设备分配
│  ├─ US-F6-01 用户能按型号、属性或标签申请兼容设备而非指定 BDF
│  │  └─ TS-F6-01 实现 selector 规范化与候选集生成
│  ├─ US-F6-02 VM 的多个设备需求必须整体可满足并原子获得
│  │  ├─ TS-F6-02 对依赖、隔离、MMIO 和策略进行全局求解
│  │  └─ TS-F6-03 对多个 bundle 执行原子预留与冲突处理
│  └─ US-F6-03 VM 关机后设备归还池，下次可选择另一块等价设备
│     ├─ TS-F6-04 assignedId 只在运行期存在并在 power-off 清除
│     └─ TS-F6-05 复用 Static attach/release/rollback/quarantine 核心
│
├─ F7 跨主机放置与冷恢复
│  ├─ US-F7-01 调度器能看到各主机限定 profile 的能力与可用量
│  │  └─ TS-F7-01 聚合 host capability、availability 与 qualification profile
│  ├─ US-F7-02 VM 能冷迁移到另一主机并重新选择兼容设备
│  │  └─ TS-F7-03 在目标主机重新求解，禁止复制源主机 BDF
│  ├─ US-F7-03 主机故障后 VM 能在已证明安全的主机上冷重启
│  │  └─ TS-F7-05 覆盖 partition、旧 agent、store failover 与 power-loss 故障测试
│  └─ US-F7-04 旧主机未被证明失效时系统阻止设备重新分配
│     ├─ TS-F7-02 使用 consensus store 与单调 fencing token
│     └─ TS-F7-04 重新分配前要求 BMC/电源 fence proof
│
└─ F8 可运维、可审计、可发布
   ├─ US-F8-01 运维人员能查看设备状态、owner、lease 与最近失败
   │  └─ TS-F8-01 建立 AssignmentManifest、状态事件与审计模型
   ├─ US-F8-02 审计人员能回答谁在何时把哪块设备分配给哪个 VM
   │  └─ TS-F8-02 收集并 hash snapshot、decision、lease、QEMU、Guest、reset 和 IOMMU 证据
   ├─ US-F8-03 发布人员能自动得到 supported/unsupported 能力报告
   │  └─ TS-F8-04 对 gap、open risk 和缺失 evidence 执行 fail-closed evaluator
   └─ US-F8-04 每个 User Story 都能追溯到可执行 Case 和证据
      └─ TS-F8-03 建立 US → Case → Evidence 的机器可读追踪
```

`TS-F*-*` 的完整多对多 `supports` 关系以机器合同为准。例如整体事务 FSM、审计和证据
收集会同时支撑同一 Feature 的多个 User Story；树中只显示其主归属。

## 3. 已冻结目标：V3 Full DirectPath

本项目只有一个目标产品：`V3-FULL-DIRECTPATH`，要求 F1-F8 全部完成。Static、Managed
Owner、Dynamic 和 Cluster 不是四个独立发布版本，而是降低实现风险的内部波次；中间波次
可以形成实验或工程演示，但不能对外宣告为完整产品发布。

V3 包含：Static、Dynamic、宿主 owner lifecycle、通用 PCI/MMIO planner、跨主机放置、
可靠 fencing、cold relocate、HA 冷恢复，以及完整 qualification/audit/release gate。

V3 明确不以 live migration、FT、snapshot/suspend 或 guest runtime PCI hotplug 为完成条件；
这些操作默认作为必须 fail-closed 的产品限制。未来若要支持，需要单独扩展 Feature、风险合同
和真实硬件 qualification，不能作为普通 policy override 打开。

### 实现波次与 milestone

| 波次 | Milestone | 主要树节点 | 波次退出信号 |
| --- | --- | --- | --- |
| W0 Contract Convergence | G0 | F8 + 全树 | 产品边界、ADR、Risk、Case、VMware 行为模型和 evidence schema 一致 |
| W1 Qualification Foundation | G1 | F1 + F8 | 通用 inventory/capability engine 和首批 profile qualification 基线 |
| W2 Static Core | G2 | F2 最小 reservation/bind-on-lease + F3/F4/F5/F8 | Static 单机事务、准入、释放、rollback/quarantine 可执行 |
| W3 Managed Owner | G3 | F2 + F8 | live/deferred activation、early-boot claim、boot reconcile 可恢复 |
| W4 Dynamic | G4 | F4 通用 planner + F6 + F8 | selector、全局求解、多设备原子 reservation 和归还池闭环 |
| W5 Cluster | G5 | F5 高阶恢复 + F7 + F8 | consensus、fencing、cold relocate、HA 冷恢复及故障注入通过 |
| W6 V3 Qualification/Release | G6 | F1-F8 | 首批 compatibility profile 的产品 Case、风险和真实硬件证据全部闭环 |

通用 planner 是 V3 必需能力，但允许先用首批 compatibility profile 驱动 W2/W3 的增量实现；
不能把阶段性 profile 限制固化成只支持某类设备的架构分支。

## 4. Epic 与 Feature 的完成定义

### Epic Outcome

只有当一个明确版本范围内的设备/平台 profile，能够在生产 Qman controller 上完成安全准入、
分配、启动、释放、故障恢复和审计，并通过发布门，`EPIC-PCI-01` 才能对该 profile 宣告完成。

### Feature Done

一个 Feature 只有同时满足以下条件才可标为 `DONE`：

1. 其 User Story 的适用范围和非目标已冻结。
2. 每个适用 User Story 至少映射一个产品级可执行 Acceptance Case。
3. 相关 ADR 已决，相关 Risk 处于发布合同允许的非阻断状态。
4. 证据明确标出 subject、环境、版本、Case、Risk 和 artifact hash。
5. VMware observation、QEMU reference 或 reference-model 结果没有冒充 Qman 产品结果。
6. `python tools/evaluate_release.py release` 对目标版本返回成功。

### 当前诚实状态

- 产品方向与树结构：`ACCEPTED`。
- 产品实现：未因本树新增而推进。
- 101 个设计 Case：当前 O09 为 `REFERENCE_MODEL` executable；C21 已标为
  `IMPLEMENTATION_BLOCKED`，并挂接 E3 QEMU/Guest/VFIO 参考证据。
- 风险：R01-R39 当前全部未达到发布闭环。
- 发布：`BLOCKED`。

## 5. 已决事项与仍需产品输入

已经根据本轮意见冻结，不再要求用户处理：

- 一个 Epic，F1-F8 共同组成完整 V3。
- Static、Owner、Dynamic、Cluster 是实现波次，不是独立产品版本。
- 底层机制追求通用安全 PCI 直通；生产支持只服务 compatibility catalog。
- Case 命名、证据 schema 和文档权威冲突属于工程治理，由项目直接修复。

当前 G0 发布门真正需要产品/平台 owner 提供事实或确认责任人的，是 5 个开放 ADR：

1. 首批受控 host/kernel/QEMU/firmware 基线（ADR-002）。
2. 现有 cluster control plane、状态存储、leader 与 host agent 的集成边界（ADR-003）。
3. 首批进入物理 qualification 的现实设备清单（ADR-005）。
4. host failure 的 RTO、BMC/电源 fencing 能力与 SLA（ADR-007）。
5. qualification profile 由谁签发、谁批准进入 `SUPPORTED` catalog（ADR-010）。

下面两项已有 fail-closed 默认值，不阻塞 G0；审核者只有不同意默认值时才需要改：

- `UNQUALIFIED_LAB` 默认不作为生产能力，只允许管理员在隔离实验环境显式开启。
- ESXi 8.0.1+ 的 `fixedPassthruHotPlugEnabled` 暂不进入 V3 基线；等独立实验和生命周期
  合同完成后，再作为扩展 Feature 审核。
