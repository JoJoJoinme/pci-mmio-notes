# Qman PCI DirectPath IPD 产品树

状态：`ACCEPTED PRODUCT DIRECTION / NOT IMPLEMENTED`
当前产品声明：`REFERENCE_AND_QUALIFICATION_MODEL_ONLY`
当前里程碑：`G1-HOST-INVENTORY-AND-QUALIFICATION-BASELINE`（G0 已 `DONE`）
最终目标：`V3-FULL-DIRECTPATH`

本文档是项目在 **Epic → Feature → User Story → Tech Story** 层级上的唯一产品树入口。
它回答“要交付什么、为什么、按什么波次实现”；当前进展、风险和证据是否足以发布，仍由
[`PROJECT-STATUS.md`](../PROJECT-STATUS.md) 和机器发布门决定。

当前节点只是完成了定义，并不表示实现完成或能力可对外宣告。现有设计、实验和参考模型
如何挂到树上，见 [`MATERIAL-MAP.md`](MATERIAL-MAP.md)；机器可读关系见
[`contracts/ipd-tree.json`](../contracts/ipd-tree.json)。
当前 Qman/reference-side 的 TS→Case→Risk→result/hash 证据链见
[`QMAN-TECHNICAL-EVIDENCE.md`](QMAN-TECHNICAL-EVIDENCE.md)；它补充树，不改变树节点状态。
将本设计交给未知私有 Qman 仓库实施时，使用
[`../handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md`](../handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md)
与 [`../contracts/directpath-portable-control-contract.json`](../contracts/directpath-portable-control-contract.json)；
内网代码绑定状态独立记录，不反向改变本树的 G1-G6 产品状态。

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
| `TECHNICALLY_ATTACHABLE` | 设备实例 + host snapshot + guest profile/VM resource context | 通用引擎能生成不违反硬安全约束的 attach plan；它不读取当前 owner/lease，也不等于 qualified/supported；QEMU 能启动本身不等于成立 |
| `ELIGIBLE` | 当前 VM 分配请求 | technically attachable，且设备此刻可用、健康、未被租用，owner/lease/资源和策略均满足 |
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

### 已冻结的平台、后端和控制面边界

完整机器合同见 [`compatibility-profile-policy.json`](../contracts/compatibility-profile-policy.json)，
正式决策见 [`decisions/`](../decisions/README.md)。这里给出产品树依赖的最小摘要：

| 交付线 | OS / arch | Kernel / QEMU | machine / firmware | VFIO backend |
| --- | --- | --- | --- | --- |
| 小规模测试 | Kylin V10 ARM | 4.19 / 5.0 | `virt + UEFI` | Legacy TYPE1 profile |
| 小规模测试 | Kylin V10 C86 | 4.19 / 5.0 | `q35/i440fx × UEFI/SeaBIOS` | Legacy TYPE1 profile |
| 小规模测试 | RH-family x86 | 4.18 / 5.0 | `q35/i440fx × UEFI/SeaBIOS` | Legacy TYPE1 profile |
| 主线 | Kylin V11 ARM | 6.6 / 10.2 | `virt + UEFI` | Legacy TYPE1 profile |
| 主线 | Kylin V11 C86 | 6.6 / 10.2 | `q35/i440fx × UEFI/SeaBIOS` | Legacy TYPE1 profile |
| 主线 | openEuler x86 | 6.6 / 10.2 | `q35/i440fx × UEFI/SeaBIOS` | Legacy TYPE1 profile |

每一行都以完整 V3 为能力目标。TYPE1v2/TYPE1 必须由精确 profile 固定，运行时不得静默
fallback；IOMMUFD/cdev 是未来可选 backend profile，不是当前产品依赖。Qman 不修改 BIOS 或
kernel boot args，而是在运行时探测逐设备 IOMMU 与中断隔离，无法证明即 fail closed。

控制面始终只有一套：Qman API → 单 active DirectPath Controller → 全局事务 repository →
逐主机 Host Agent → backend adapter → 非特权 QEMU。PostgreSQL 是全局 store 参考实现，Host
Agent 的 SQLite 仅作 journal/cache；Legacy 和未来 IOMMUFD 只允许 adapter、renderer、receipt 不同。

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
│  │  └─ TS-F3-03 在 lease 内完成 bind、reset、选定 VFIO backend 和 backend-specific QEMU attach
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
├─ F7 在线主机间的放置与计划性冷搬迁
│  ├─ US-F7-01 调度器能看到各主机限定 profile 的能力与可用量
│  │  └─ TS-F7-01 聚合 host capability、availability 与 qualification profile
│  ├─ US-F7-02 源、目标都在线时 VM 能冷搬迁并重新选择兼容设备
│  │  └─ TS-F7-03 在目标主机重新求解，禁止复制源主机 BDF
│  ├─ US-F7-03 目标 attach 前能证明源端已经 clean release
│  │  ├─ TS-F7-02 以全局 CAS、run generation 和 host epoch 串联搬迁事务
│  │  └─ TS-F7-05 覆盖 stop、release receipt、target solve/attach 的正负故障矩阵
│  └─ US-F7-04 源主机失联时 VM 保持停止且设备不在别处接管
│     └─ TS-F7-04 保留 lease，等待源主机返回并 reconcile；拒绝 stale mutation
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

V3 包含：Static、Dynamic、宿主 owner lifecycle、通用 PCI/MMIO planner、双在线主机的计划性
cold relocation，以及完整 qualification/audit/release gate。源主机失联时保留 lease、VM 保持
stopped 且不在目标接管；BMC/电源 fencing 与 host-failure 自动 HA restart 不属于 V3。

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
| W5 Online Cold Relocation | G5 | F5 clean release + F7 + F8 | 双在线主机 stop/release/re-solve/attach 与失联不接管负向门通过 |
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
- 101/101 个设计 Case 已机器分类：O09 为 1 个 reference-scope `EXECUTABLE`；
  94 个为 `IMPLEMENTATION_BLOCKED`，其中 C20 仅有 E2 reference runner、仍是 PRODUCT Case；
  C12、M08、M12、M13、S06、S08 为 6 个
  `HARDWARE_BLOCKED`；未分类数为 0。VFIO provider、QMP gate、authoritative snapshot、
  Static lease/FSM 与 future-cdev launch-envelope evidence 只是产品 Case 的组件前提，
  不构成产品关闭，也不推进 F1/F3/F5/F8 状态。
- 所有 Case 通过 `requiredTechStories` 挂回本树，并用 `dependsOnCaseIds` 固定关闭顺序；
  当前关键链由机器门约束为 `C10 + C20 → C21 → S03 → S04 → S05 → F00`，以及
  `C21 → S15 → F09`、`C10 → F10`；C20 是 `PRODUCT/IMPLEMENTATION_BLOCKED`，现有 E2
  reference runner 不能替代 C20 自身或 C21 的产品前置，任何 reference/component evidence
  都不能关闭产品依赖。
- 风险：R01-R39 的治理字段已补齐，但 39 条状态仍全部为 `OPEN`，产品关闭数为 0。
- 发布：`BLOCKED`。

## 5. 已决事项与后续可补事实

已经根据本轮意见冻结，不再要求用户处理：

- 一个 Epic，F1-F8 共同组成完整 V3。
- Static、Owner、Dynamic、Cluster 是实现波次，不是独立产品版本。
- 底层机制追求通用安全 PCI 直通；生产支持只服务 compatibility catalog。
- Case 命名、证据 schema 和文档权威冲突属于工程治理，由项目直接修复。
- ADR-002/003/005/007/010 已由用户输入或委托的 reference default 正式冻结，见
  [`product-decisions.json`](../contracts/product-decisions.json)。
- 当前产品 Legacy-first；IOMMUFD/cdev 只作为未来独立 profile，控制面代码不分叉。
- 集群只服务在线主机间的计划性 cold relocation；不依赖 BMC，也不承诺 host-failure HA。
- HCL 先按消费 GPU、专业 GPU、HBA、加速卡四类技术 trait 设计，精确 SKU 在 G6 补录。

后续允许补充且不回退已完成 G0 的事实包括：现有 Qman 服务名与 owner、实际数据库部署方式、
精确 versioned machine 名、开源 OVMF/SeaBIOS package/hash，以及首批物理 specimen。补充事实如改变
事务、安全或支持边界，必须新建 ADR，不能在实现中静默漂移。

下面两项已有 fail-closed 默认值，不重新打开 G0；审核者只有不同意默认值时才需要改：

- `UNQUALIFIED_LAB` 默认不作为生产能力，只允许管理员在隔离实验环境显式开启。
- ESXi 8.0.1+ 的 `fixedPassthruHotPlugEnabled` 不进入 V3；snapshot、suspend、FT、live migration
  和 guest runtime hotplug 均由产品负向 gate 拒绝，未来支持必须新建 Feature/ADR/qualification。
