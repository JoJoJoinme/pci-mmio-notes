# Qman DirectPath 可移植实现交接规范

状态日期：2026-07-22
VMware 冻结基线：ESXi 8.0.3 build 24280767 / API 8.0.3.0 / vHW 20
目标：在未知 Qman 私有仓库结构的前提下，把 V3 DirectPath 外部语义、事务与安全边界冻结到
可映射、可实现、可验收的程度。

## 1. 这份交接解决什么

本仓库不需要、也不等待 Qman 私有代码，也不要求把私有源码、目录或接口信息带出内网。它交付的
是一份 **target-code-independent portable specification**。进入内网后，工程 AI 先完成三类精确绑定：

1. **symbol mapping**：把 port、entity、operation、state machine、CAS rule、reason、configuration 和
   telemetry 绑定到 exact service/path/symbol/interface hash；
2. **storage mapping**：把 authority、key、version/generation、transaction/CAS、outbox、journal 与 migration
   绑定到 exact schema/table/field/transaction symbol；
3. **test mapping**：把每条 verification requirement、Case、fault point、oracle 和 operation fixture 绑定到
   exact test path/symbol/interface hash。

只有这三类 mapping 对 pinned target commit 完成并报告冲突后，内网 AI 才对缺失项按目标仓库既有风格
实现 adapter 或新模块。实现和 qualification 是后续状态轴，不是“找到一个相似目录”即可自动成立。

工程 AI 不得根据私有代码的现状反向削弱本规范，也不得为了“复用”现有入口而绕过 lease、
snapshot、qualification、reset、clean release 或 lifecycle deny gate。

这里对标的是 **VMware vSphere/ESXi DirectPath 的可观察外部能力与安全语义**，不是复制 VMware
私有源码。Qman 可使用不同 chipset、guest BDF、数据库、RPC 框架和 backend，只要
`MUST_MATCH` 语义、版本化 guest ABI 和验收结果等价。

## 2. 四条彼此独立的状态轴

| 状态轴 | 当前值 | 含义 |
| --- | --- | --- |
| `PORTABLE_SPEC_READY` | `READY` | 已冻结目标代码库无关的职责、事务、不变量、wire schema、验证矩阵和映射格式；可交给内网 AI 开始代码发现与绑定 |
| `TARGET_CODE_MAPPED` | `UNMAPPED` | 本仓库不知道私有 service/path/symbol；这不是 portable design 的阻塞 |
| `PRODUCT_IMPLEMENTED` | `NOT_PROVEN` | 未在目标仓库精确 commit 上完成实现和产品级 Case |
| `QUALIFIED` | `NOT_PROVEN` | 未在六个平台/HCL 精确组合上取得 E4、目录锚和发布门证据 |

`PORTABLE_SPEC_READY=READY` 不等于“代码已实现”，更不等于“产品可发布”。项目 G1-G6 与
`PROJECT-STATUS.md` 继续保持真实状态；不得因为交接规范完成而把 G1/G2/G3/G4/G5/G6 标为
`DONE`。

## 3. 权威资料与读取顺序

内网 AI 必须按以下顺序读取，后者只能细化前者，不能静默推翻前者：

1. `contracts/product-decisions.json`、`contracts/compatibility-profile-policy.json`：产品边界；
2. `contracts/vmware-behavior-model.json`：VMware parity 分类与证据边界；
3. `contracts/directpath-portable-control-contract.json`：机器可读实现合同；
4. `contracts/directpath-operation-envelope.schema.json`、
   `contracts/directpath-operation-payload.schema.json`、
   `contracts/directpath-authority-entities.schema.json`、
   `contracts/directpath-portable-entities.schema.json`：35 个 operation 的 common request/result envelope、
   35×2=70 个 operation-specific closed payload profile、17 个持久化 authority aggregate 和 4 个非 authority
   wire projection；
5. `contracts/directpath-identity-v1.schema.json` 与 golden vectors、portable hash subjects、trust/key-ring/
   rollback/catalog/qualification schemas：跨语言 canonical bytes、身份、签名和反回滚边界；
6. 本文件：target mapping 和停止条件；
7. `qman-directpath-implementation-blueprint.md`：模块、事务、持久化与伪代码；
8. `qemu-static-dynamic-directpath-design.md`：算法、风险和 101 个 Case 的需求来源；
9. `contracts/qman-integration-map.schema.json` 与
   `contracts/qman-integration-map.template.json`：私有代码绑定输出；
10. `contracts/directpath-integration-report.schema.json` 与
    `contracts/directpath-qualification-release-index.schema.json`：mapping/conflict/test 和逐 profile、逐 Case
    E4 的完成证据；
11. `contracts/directpath-acceptance-scenario.schema.json`：产品测试的可执行输入、故障注入、oracle、
   artifact 与清理证明格式；`handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json`
   是 `TEMPLATE` 示例，不是完成证据；`BOUND` 只表示已绑定可运行，只有 `EXECUTED_PASS` 才携带
   passing evidence，并且仍须通过产品发布门；
12. `contracts/directpath-acceptance-case-contracts.json` 与
    `contracts/directpath-case-completion-record.schema.json`：101 个 Case 的不可削弱谓词、依赖、
    trace/fault/artifact/repeat/duration，以及在同一 target/platform/backend/qualification tuple 上多 scenario
    的确定性完成聚合；
13. `contracts/directpath-case-evaluator-tool-manifest.schema.json` 与
    `contracts/directpath-build-attestation.schema.json`：Case 求值器自身的目标代码、接口、完整 source tree、
    builder/toolchain/dependency/environment/input/output 和 runtime 证明；它与任何 Scenario RunnerManifest
    相互独立；
14. `contracts/directpath-source-tree-manifest.schema.json`、
    `contracts/directpath-runner-manifest.schema.json` 与
    `contracts/directpath-execution-evidence-index.schema.json`：从目标 commit 的完整 Git tracked tree 固定
    runner/build/predicate，并形成六个互斥控制制品和逐 iteration 的 typed evidence DAG；dirty tree、一份
    通用日志或重复 hash 不能满足多个 oracle；
15. `contracts/directpath-qualification-workload-definition.schema.json`、
    `contracts/directpath-qualification-run-request.schema.json`、
    `contracts/directpath-workload-evaluator-manifest.schema.json`、
    `contracts/directpath-workload-evaluation-report.schema.json`、
    `contracts/directpath-qualification-workload-result.schema.json`、
    `contracts/directpath-device-taxonomy-definition.schema.json`、
    `contracts/directpath-device-classification-record.schema.json`、
    `contracts/directpath-qualification-measurement.schema.json`、
    `contracts/directpath-qualification-run-manifest.schema.json` 与
    `contracts/directpath-qualification-subject-manifest.schema.json`：固定 workload definition/assertion/metric、
    pre-run request、evaluator build/runtime、signed EvaluationContext、可重放 EvaluationReport 和 terminal result；
    taxonomy/classifier 与 current signed HostSnapshot 中的 exact DeviceRecord 独立形成 classification，再从
    inventory、firmware/provider、taxonomy、guest/workload 和
    scenario execution core 的独立 typed measurement，经 fresh nonce、host boot/epoch、起止时间和完整
    measurement/core 双签运行闭包后重算 E4 subject 与 exact qualification key，不能从待签发记录回抄；
16. `contracts/directpath-trust-key-ring-history.schema.json` 与
    `contracts/directpath-anchor-freshness-envelope.schema.json`：解析 genesis→current 信任链，并用
    verifier 外部 nonce 证明独立 anchor 的实时 freshness；
17. `contracts/qman-evidence-index.json`：已有参考/component 证据及其不得越权的边界。

如果叙述例子与 portable contract 的 enum/字段/FSM 冲突，以 machine contract 为准，同时在
目标 mapping 中登记 `CONFLICT`，不得自行选择一段实现。

## 4. VMware 对标边界

`contracts/vmware-behavior-model.json` 中的全部 `coreParity` 是权威清单：

- `MUST_MATCH`：capability/dependency、owner state 与 rollback、Static、Dynamic、guest profile
  admission、DMA/reset/clean release、lifecycle rejection、在线主机间 cold relocation、设备 trait、
  ops/audit；
- `ACCEPTABLE_DIFFERENCE`：exact chipset/address、VMware SKU/HCL 格式、backend/control-plane 私有
  实现；差异必须进入 versioned Qman profile，不能改变安全结果；
- `OUT_OF_SCOPE`：host-failure HA/BMC、Fault Tolerance、runtime PCI hotplug。所有入口必须稳定拒绝，
  不能简单“没有 UI”。

VMware reference 的 `VERIFIED/PARTIAL/UNKNOWN` 只说明冻结 ESXi subject 的证据覆盖。它不会关闭
Qman implementation、Case、Risk 或 qualification。未来 vSphere API（例如 9.1 新字段）只能作为
独立 version delta 登记，不能静默改写 8.0.3 baseline。

## 5. 必须映射的逻辑 ports

私有实现可以把多个 port 放进同一进程，也可以把一个 port 拆成多个模块；但 authority、调用方向
和不变量不能合并掉。

| Port | 唯一职责 | 禁止事项 |
| --- | --- | --- |
| `PORT-CONTROL-API` | 认证、RBAC、idempotency、expected version、operation 查询 | 直接 bind/reset/启动 QEMU |
| `PORT-ASSIGNMENT-ORCHESTRATOR` | 串联 plan/reserve/prepare/commit/rollback/release | 用内存或 TTL 充当 owner |
| `PORT-INVENTORY-SNAPSHOT` | 发布签名、原子、完整 host snapshot | evaluator 中零散重读 sysfs 并拼快照 |
| `PORT-QUALIFICATION-CATALOG` | 验证 profile/catalog/signature/revocation/sequence | wildcard HCL 或 unsigned override 进入生产 |
| `PORT-CAPABILITY-ENGINE` | 纯函数六层状态、dependency/reset/action closure、stable reason | owner side effect 或按 class whitelist 放行 |
| `PORT-OWNER-ACTIVATION` | planner、live executor、boot intent、read-back、rollback | operation lease 前 unbind/bind |
| `PORT-RESOURCE-PLANNER` | 完整 guest PCI tree、BAR/MMIO/RMRR/IRQ/ABI admission | 只累计 endpoint BAR 或把 QEMU floor 当 cap |
| `PORT-DYNAMIC-SOLVER` | selector、candidate equivalence、全局原子求解、unsat core | greedy first-match、仅 bundleId 去重 |
| `PORT-GLOBAL-REPOSITORY` | PostgreSQL global truth、CAS、generation、outbox | Host Agent SQLite 仲裁 owner |
| `PORT-HOST-AGENT` | lease 内本机 action journal、typed backend 调用、receipt | 无 lease 选卡或执行物理副作用 |
| `PORT-VFIO-BACKEND` | Legacy/current 与 cdev/future adapter | Legacy 静默 fallback 到 cdev/no-IOMMU |
| `PORT-QEMU-LAUNCHER` | typed plan/grant、唯一 spawn 入口、sandbox/QMP gate | raw argv、未授权 BDF/fd、runtime hotplug |
| `PORT-RUNTIME-VERIFIER` | QMP/QOM/guest/IOMMU/IRQ/observed-plan 独立核对 | 以 QEMU 存在或 QMP success 作为 commit |
| `PORT-RELEASE-RECOVERY` | ReleaseOwnershipGuard、clean release、reconcile、quarantine | QEMU exit/TTL 直接置 FREE |
| `PORT-RELOCATION-COORDINATOR` | source clean receipt、target re-solve、单 target attempt | source 不可达时接管或复制 assignedId |
| `PORT-AUDIT-EVIDENCE` | manifest/event/artifact/hash/trace correlation | 日志代替权威 lease 或伪造证据等级 |
| `PORT-LIFECYCLE-GATE` | snapshot/suspend/live-migration/FT/hotplug 四层 deny | 只在 UI 隐藏，其他入口仍可执行 |

## 6. 不得改变的总体事务顺序

### 6.1 所有物理副作用之前

```text
immutable snapshot
  -> pure capability/dependency/resource decision
  -> exact qualification/profile validation
  -> typed durable operation lease CAS
  -> host-side bind/reset/open/spawn side effects
```

`ENTITY-OPERATION-LEASE.leaseType` 的唯一枚举是 `OWNER_TRANSITION`、`ASSIGNMENT_PREPARE`、
`RELEASE`、`RELOCATION_HANDOFF`、`QUARANTINE_REMEDIATION`。它们共享同一 scope conflict key；
任何两个可能操作同一 physical/reset/exclusive domain 的事务不能并发。planner 无副作用。VM
power-on 使用 `ASSIGNMENT_PREPARE`，维护 owner 变更使用 `OWNER_TRANSITION`。`ENTITY-BUNDLE-LEASE`
是物理占用 authority，`ReleaseOwnershipGuard` 是 release deny guard；二者都不是 operation lease type，
maintenance/owner lease 也不能给 QEMU 签发授权。

### 6.2 Static/Dynamic 共享 attach core

```text
select exact Static identity OR solve complete Dynamic requirements
  -> reserve all bundle members atomically
  -> PREPARING + local durable journal
  -> revalidate identity/domain/generation
  -> owner activation under lease
  -> fresh reset affected-set discovery + qualified reset
  -> complete resource plan
  -> backend-specific launch grant
  -> unique QEMU spawn
  -> backend receipt + QMP/QOM + guest + DMA/IRQ + observed plan
  -> persist AssignmentManifest v2
  -> ATTACHED
```

任一步失败都按 journal 逆序补偿。只有完整 cleanup receipt 才能回 `FREE`；DMA、IRQ、reset、owner
或 identity 任一不确定都进入 whole-bundle `QUARANTINED`。

### 6.3 当前 Legacy 与未来 cdev 的唯一分叉

| 项 | 当前产品 `LEGACY_VFIO_TYPE1` | future `VFIO_CDEV_IOMMUFD` |
| --- | --- | --- |
| 资格 | 六个平台分别固定 TYPE1v2 或 TYPE1；不可用即拒绝 | 独立 profile、独立 Case/E4 后才启用 |
| grant | `AUTHORIZED_DEVICE_PATH` | `AUTHORIZED_FD_BUNDLE` |
| QEMU input | exact `host=BDF`，per-VM uid/mount/device ACL/read-only sysfs | inherited fresh cdev/IOMMUFD fds |
| backend proof | selected TYPE1、authorized group/proc-fd、QMP/QOM | QEMU bind、IOAS allocate/attach、fd identity |
| forbidden | preopened fd 伪装成 QEMU 5.0 Legacy；silent subtype/cdev fallback | 复用 standalone probe 的已 attach IOAS |

两条路径共享 API、repository、FSM、solver、manifest、reason 和 Case；只允许 adapter、renderer、
grant、receipt、DMA-domain identity 不同。

### 6.4 Release 的独占权连续

Stock QEMU 的 VFIO fd 随进程退出关闭，不假设能转交给 Host Agent。正确顺序是：

```text
ATTACHED -> RELEASING CAS
  -> acquire ReleaseOwnershipGuard and deny every new opener
  -> quiesce/stop/fence QEMU and prove pid/fds gone
  -> under the still-live guard acquire a fresh backend release context
  -> prove guest DMA/IRQ context destroyed
  -> verify fresh affected set; disable bus master/interrupt; release reset
  -> post-reset/health proof; close release context; restore/verify owner
  -> bump generation; clear binding; FREE lease; release guard
```

任何阶段不确定都保留 lease 与 deny guard 并 quarantine。禁止“先关 fd/释放 lease，再补 reset”；
也禁止把 driver 仍是 `vfio-pci`、QEMU exit、heartbeat timeout 或 lease TTL 单独解释为 clean release。

## 7. 状态与数据 authority

目标 repository 必须能够表达并 CAS 更新下列独立 FSM；不能把 owner、assignment、lease、
quarantine 和 relocation 混进一个 `state TEXT`：

| FSM | 最小状态 |
| --- | --- |
| Assignment | `REQUESTED, PLANNED, PREPARING, ATTACHED, ROLLING_BACK, RELEASING, FREE, FAILED, QUARANTINED` |
| Owner activation | `ENABLED, LIVE_APPLICABLE, PENDING_REBOOT, DENIED, APPLYING, ACTIVE, FAILED, QUARANTINED` |
| Relocation | `ATTACHED, RELOCATING_SOURCE_STOP, SOURCE_RELEASING, TARGET_SOLVE, TARGET_RESERVED, TARGET_ATTACHING, TARGET_ROLLING_BACK, STOPPED_UNSAT, HOST_UNREACHABLE, SOURCE_RECONCILE, QUARANTINED` |
| Quarantine remediation | `QUARANTINED, REMEDIATING, FREE` |

每个 transition 必须映射唯一 actor、expected state/version/generation、guard、同事务 DB writes、
side-effect journal entry、event/outbox、compensation 和失败 authoritative state。物理 side effect 前先
写 intent；结果提交与 outbox 同事务。目标数据库至少映射以下实体：controller/host authority、
inventory snapshot/device generation、qualification catalog/profile、VM request/version、assignment
run/member/binding/manifest、bundle lease/member、owner activation run、idempotency record、host action
journal cursor、quarantine/remediation、relocation/source-clean receipt、audit event/outbox。

typed operation lease 是独立 authority entity/CAS rule，不复制一台与 Assignment 相似的产品 FSM；
其 `leaseType + scopeHash + generations + resourceVersion` 在 covered side effect 前取得，并在结果
transition 中消费或转为 quarantine guard。`SOURCE_CLEAN` 是
`SOURCE_RELEASING -> TARGET_SOLVE` transition 的 signed receipt/lease-revocation 提交条件，不是
一个可被其他 actor 单独推进的中间 state。`STOPPED_UNSAT` 可在没有 active target lease、
source-clean fact 仍有效或重新验证后显式进入新的 `TARGET_SOLVE` attempt；target cleanup 不确定
则只能进入 `QUARANTINED`。

所有产品部署（即使只有一台 host）使用同一 PostgreSQL global truth contract。Host Agent SQLite
只保存本机补偿 journal/cache；其丢失会触发 reconcile/quarantine，不能使 global claim 自动消失。

## 8. Dynamic 的确定性合同

Dynamic request 只保存 selector、`requiredGuestAbiClass`、ordered guest slots 和 operations，不保存
BDF/deviceUid/assignedId。PCI ID 使用固定宽度小写 hex string。`guestSlots.length == count`。

candidate equivalence key 至少包括：bundle、payload、member actions、resource signature、guest ABI
class/signature。只按 bundleId 去重是错误实现。求解器必须：

1. 将 `(requirementId, ordinal, guestSlot)` 全部展开；
2. 同一 bundle member 不能被不同 slot 重复使用；
3. 同时满足完整 MMIO/RMRR/NUMA/IRQ/device-limit/ABI；
4. 搜索完整解而非第一个 greedy 解；
5. 用 portable contract 的 lexicographic tuple 选择 canonical solution；
6. timeout/UNSAT 返回稳定 reason、unsat core 和统计，不提交部分 reservation；
7. 一次 CAS 原子 reserve 所有 selected bundles。

`assignedId` 在 attach 全部验证后才生成，是 `(runId, requirementId, ordinal)` 对应的 opaque runtime
key。它与 BDF/deviceUid 一起写 manifest，但不能回写持久 VM request；powered-off 后清除。

## 9. Planned cold relocation

G5 只支持 source 和 target 都在线、可协作的 **Dynamic VM planned cold relocation**。Static
assignment host-affine，返回 `STATIC_DEVICE_HOST_AFFINITY`；source 不可达时保持 VM stopped、旧
claim/quarantine，不在 target 接管。无 BMC/power fence、无 host-failure automatic restart。

source clean receipt 必须绑定 relocation/run/source assignment、source host epoch、bundle/device
generations、QEMU pid/fd gone、DMA/IRQ teardown、release reset、owner result、evidence hash、nonce、
签名 key、issued/expiry 和 repository transition version。target 只能在 repository 原子接受
source clean receipt、撤销旧 lease 并转入 `TARGET_SOLVE` 后读取自己的 snapshot/catalog/profile
重新求解；receipt 不是 target device plan。

每个 relocation 同时只允许一个 active target reservation。target UNSAT 或 attach cleanup 已验证时，
可在同一 relocation generation 上选择另一个在线 target（包括重新选择 source）；target cleanup
不确定则该 target bundle quarantine 且不得继续。每个 crash window 都由 relocation FSM 和 global
CAS 恢复，不能靠重复 RPC 猜状态。

## 10. Qualification 与 support

通用 PCI engine 计算“原理上能否安全直通”；生产 `SUPPORTED` 仍要求 exact signed catalog match。
catalog 技术合同至少包括：

- `QualificationRecord`：platform/profile、PCI tuple/revision、device trait、firmware/ROM、kernel、
  QEMU、VFIO subtype、IOMMU/IRQ/reset provider、guest driver/workload、Case/E4 artifact hashes；
- Qualification Engineering 签名和 Product Release catalog/index 签名两级分离：必须是不同
  `keyId`、Ed25519 public key 和 immutable `principalId`，同一 principal/key 不得同时持有两个角色；
  target mapping 的 `TARGET_ARCHITECT`、`SECURITY`、`TEST` 也必须由三个不同
  key/public-key/principal 独立批准，approval.identity 必须等于 key-ring 中的 principalId；
- JCS + SHA-256 content digest、Ed25519 signature、`keyId`、monotonic catalog sequence、
  previous digest、validity、revocation、key rotation 和 external rollback anchor；
- `CONFIG-TRUST-ROOT-DIGEST` 与 rollback-anchor current state 必须由部署/发布环境在仓库外提供；
  integration map 或 target repository 不能用自己携带的 root/anchor 给自身建立信任；
- 默认 revocation 行为是 `DENY_NEW_AND_NEXT_POWER_ON`；安全级 critical 可要求显式 stop maintenance，
  但控制面不得未经产品 policy 静默杀 VM；
- catalog/profile/policy hash 在 plan、reserve、`PRE_GRANT/PRE_OPEN`、`PRE_SPAWN` 和 commit 前核对。
  无副作用时变化则重算；已有副作用时按 journal rollback/quarantine。

设备 archetype 也不是 catalog/HCL 的输入标签。`DeviceTaxonomyDefinition` 必须先固定五类 archetype、
classification profile、classifier 的 exact path/symbol/blob/semantic/interface、完整 source/build/runtime closure，
并由 Qualification Engineering 签名；预签名 `ClassificationContext` 先绑定 classification ID/time/signer 与
exact taxonomy/snapshot/device。`QualificationRunRequest` 在任何 collector 前冻结 `deviceUid + deviceRecordHash`；
Host Inventory authority 还必须在 `classifiedAt` 对完整 HostAuthority current-pointer state 生成签名 receipt，
证明该 snapshot 当时确为 current，而不只是历史签名有效。`DeviceClassificationRecord` 随后只允许消费这五个
显式输入，且 identity/traits/classification 三条链必须绑定同一 DeviceRecord descriptor，输出可重放
trace、archetype/profile，再由同一 authority 后填 `signedAt` 并签名，不得读取隐藏时钟或 signer 状态。
分类器不得读取 QualificationRecord、SupportedCatalog、HCL 或 support decision，防止循环证明。

WorkloadDefinition 的所有 prerequisite 都必须落到同一 qualification run 的实测投影：guest ABI、architecture、
OS/kernel/driver、vCPU、memory 与 required guest capabilities 只匹配 signed `guestDriverAndWorkload`
Measurement；required runtime capabilities 以及 platform/backend/IOMMU/machine/firmware/provider 只匹配 signed
platform-runtime/provider Measurement；device archetype/traits 只匹配上述独立 classification/trait Measurement。
集合条件使用 exact membership，资源下限使用定义中的 minimum；缺失、别名、未支持的笛卡尔组合、配置自报或
catalog 回抄一律拒绝 qualification。

`platformProfileHash` 不是目标实现自报值。它精确哈希 canonical projection
`{profileProjectionVersion:1, policySchemaVersion, capabilityTarget, platform, backendPolicy,
hostConfigurationPolicy}`；其中 `platform` 是由 record.platformProfileId 唯一选中的完整六平台 policy
行。qualification case matrix 由独立 digest 绑定。任何 OS/arch/kernel/QEMU/machine/firmware/backend、
Legacy no-fallback 或 IOMMU/interrupt probe policy 变化都会使旧 record 不再匹配。

HCL 的首批 SKU 后续填充，不影响上述技术 schema。consumer/professional GPU、HBA、accelerator
只是必须覆盖的 trait families，不能写成 class-code allowlist。当前 revision 没有签名 errata registry，
因此 `errataProfileId` 固定为 `NONE`；内网实现不得用任意字符串制造例外，未来非 `NONE` 必须另行版本化并签名。

## 11. API 与 operation 语义

私有 Qman 可以复用既有 REST/gRPC/event 模型，但必须映射下列语义：

- 35 个 operation 共用 closed envelope，但 operation-specific wire body 必须从
  `directpath-operation-payload.schema.json` 的 70 个唯一 `REQUEST/RESULT` profile 中选择；operationId、direction、
  profileId、schema fragment/hash 与 canonical payload digest 必须一致，不能用开放 map 或 target-local DTO
  代替 portable payload；
- 所有 mutation 携带 `schemaVersion, idempotencyKey, expectedResourceVersion,
  expectedSnapshotEpoch, profileId, request`；
- 同 key + 同 canonical request 返回同一 operation/result；同 key + 不同 request 返回
  `IDEMPOTENCY_KEY_REUSED`；
- 有物理副作用的调用返回可查询 `operationId/runId`。client timeout 后查询，不创建第二次事务；
- cancel 只在无物理副作用状态直接成功；进入 `PREPARING/APPLYING/RELEASING` 后只能请求受控
  rollback，不能删除 operation；
- reason registry 决定 retryability。只有 fresh snapshot/CAS conflict 等明确瞬态项可自动重算；
- RBAC 至少区分 read/evaluate、VM configure/power、host maintenance owner、quarantine remediation、
  qualification approve、release approve；
- raw QEMU/QMP/VFIO、scheduler、import/restore 和 admin debug 都必须经过同一 lifecycle/lease gate。

URL、proto service 名和 ORM 名是 target mapping 输出，不是 portable contract 的开放语义。

Scenario Step 也不能只写“调用某 operation”。`TEMPLATE` 必须绑定 request/result 的 operation、direction、
portable schema fragment 和 canonical profile；`BOUND/EXECUTED_PASS` 还必须绑定仓库内 immutable request/result
fixture path 与 canonical payload digest，并验证内部 profileId、operationId 以及 expected status/reason/retryable。
evidence commit 固定 presentation bytes，payload digest 固定语义 canonical bytes。这样 target test
只能实现已冻结的 70 个 profile，不能通过叙述性 intent 或 ad-hoc JSON 改写接口。每次执行 iteration 还要形成
与 Step 完全一一对应的 `operationExchanges`：读取 evidence commit 中 raw request/result envelope，验证固定
schema fragment/hash、requestHash/resultHash、payloadHash、共同 command/correlation 以及结果投影。

## 12. 内网 AI 的精确映射流程

1. 冻结目标 repository、branch、commit、build/test/migration 命令；禁止映射漂移中的工作树。
2. 发现现有 Controller/scheduler/VM lifecycle/Host Agent/DB/QEMU launcher/QMP/audit/qualification
   入口和 authority；同时定位 exact storage table/field/transaction/CAS/outbox/journal/migration 与 test
   path/symbol/fixture；不要先写新代码。
3. 复制 `contracts/qman-integration-map.template.json`，按 schema 填 target metadata。
4. 每个 contract item 选择 `REUSE | EXTEND | NEW | CONFLICT`，绑定 exact service/path/symbol、
   interface/schema hash、storage authority 和 test symbol/fixture；一个 item 不得靠“见某模块”模糊关闭。
5. 对 `CONFLICT` 先生成差异报告：现状、违反的不变量、最小 adapter/migration、影响 Case/Risk；
   未消歧前停止相关实现。
6. 生成目标代码变更和 versioned DB/config/API migration；实现与 mapping 绑定同一 commit。
7. 每项只有在 exact target commit 上通过关联 Case、fault point、artifact oracle 后，才从
   `IMPLEMENTED` 变为 `VERIFIED`。
8. 重新运行产品 release gate；不得手工修改状态绕过证据。

映射与证据必须按下列无环顺序构造，字母是内容身份，不是某个服务名：

```text
C  exact target-code revision
  -> M  detached mapping-core digest（不含 E、A、test result、approval）
  -> qualification/evidence content + SupportedCatalog（只绑定 C+M）
  -> A  独立单调 catalog rollback anchor（先验 catalog，再 CAS 推进）
  -> E  evidence repository revision（blob 可镜像 A，但绝不嵌入 E 自身）
  -> detached final integration map + approvals（绑定 C+M+E+A）
```

`M` 的 canonical projection 必须把 `evidenceRepository`、completion evidence、approval、
`trustPolicy.catalogRollbackAnchor` 和最终 digest 置空。root-set/key-ring rollback 的既有信任身份仍进入
`M`，post-catalog 的 `A` 不进入。否则会产生无法构造的
`M -> QualificationRecord/E4 -> SupportedCatalog -> A -> M` 固定点。final map 不得存进 `C` 或 `E`；
任何位于 `E` 的 blob 都不得写入包含自己的 Git revision。

portable contract 当前导出 **293 个有序 mapping item**，并为每个 item 固定一条
`verificationMatrix` 记录。每条记录独立绑定 test obligation、101 Case 的适用并集、八类 oracle 和
`verificationRequirementDigest`。integration map 中同一 item 必须携带该 digest；目标 test/scenario
只能满足它，不能通过自报少测、改序、合并 item 或扩大无关 Case 来改变要求。场景的每次 iteration 和
每个 fault point 都要有自己的 run identity、完整 oracle 结果、artifact correlation 与 cleanup proof；
复用另一次 iteration 的日志或 receipt 视为失败。

三个提升条件是机器合同，不是人工标签：

- `TARGET_CODE_MAPPED=true`：按 pinned portable contract 的 `mappingSurface.derivation` 动态导出的全部有序
  item 一个不少，portable contract hash 与完整 target commit 已固定，无 `UNMAPPED`，coverage/conflict report
  可复算，且 `TARGET_ARCHITECT` 批准；
- `PRODUCT_IMPLEMENTED=true`：所有 `CURRENT_RELEASE_REQUIRED` item 必须为 `BOUND + VERIFIED`，每项至少
  一个 exact test binding，不允许 `CONFLICT/REJECT`；`FUTURE_SEPARATELY_QUALIFIED` item 只有在具备
  portable normative-source closure 中 hash-bound 的 `ADR-002` deferDecision 时才可保持
  `DEFERRED/NOT_APPLICABLE_CURRENT_RELEASE`；该决定只划分 current/future track，不授予 target 实现或发布
  权限，并在 M 提升时由 `TARGET_ARCHITECT` 对完整 mapping core 覆盖签名；整个
  `PRODUCT_IMPLEMENTED` 轴仍须 `TARGET_ARCHITECT + SECURITY + TEST` 三方独立批准；
- `QUALIFIED=true`：在上一条件上增加目标平台/HCL 的 qualification evidence index 与
  `PRODUCT_RELEASE` 批准。schema、hash 和 release evaluator 任一失败都保持 false。

产品测试场景同样有三态：`TEMPLATE` 只定义 oracle；`BOUND` 固定完整 commit、test symbol/interface
hash、integration map、真实 fixture 与 profile，但没有完成权限；`EXECUTED_PASS` 还必须逐条给出
step/final-state/write/physical/idempotency/cleanup oracle 的 PASS 结果、实际 artifact hash、runner、
evidence-index record 和 Ed25519 signature。只有最后一态可提交发布门，仍不能绕过 Case 依赖、E3/E4、
Risk 和审批检查。

Case 完成不是“某个测试名叫 Case ID”。`generate_directpath_case_contracts.py` 从第 19 节、101 个 Case
定义和 portable contract 独立生成 Case contract digest。单个 scenario 绑定全部 Case assertion，但只覆盖
一段合法 operation/transition/fault 子集；`CaseCompletionRecord` 必须在同一 C/M/target commit 上聚合一个
或多个 `EXECUTED_PASS`，精确求 union/sum，覆盖 Case 要求的完整 trace、fault、artifact、八类 oracle、
repeat、duration 和 dependency；它还直接签入 `platformProfileId`、`platformProfileDigest`、
`backendProfileDigest` 和 `exactQualificationKey`。E3 的 exact key 必须为 null，E4 必须从 measured Subject
的九字段资格键重算；
dependency completion 必须使用相同完整 tuple，外层报告不得改写。每个 scenarioEvidence 同时固定
scenario/index/runner 的 repo-relative
path、raw file hash 与内部签名 digest，使 detached completion record 可以递归重验。Runner 的
sourceTreeSha256 由目标 C 的完整 Git tracked-tree manifest 重建，不接受 working tree 标签。Qualification
的七类运行时/分类观察和每个 scenario core 先分别形成 typed signed measurement，再按
`execution core → measurement → dual-attested run manifest → subject → index → final result → qualification record → Case completion`
构造无环证据；索引不得嵌入自己的 digest，measurement/subject 也不得反向嵌入包含它的对象。
Case 求值器另有签名的 `CaseEvaluatorToolManifest`，固定其 target blob/interface、完整 source tree 以及
runtime binary、dependency lock、environment manifest 和 build log。不得借用 Scenario RunnerManifest、
任意 transitive `TOOL_MANIFEST` 或环境中的可变解释器来证明求值器。

Runner 和 Case evaluator 的源码树标签本身也不证明实际执行字节。两者必须递归验证独立
`BuildAttestation`：精确 argv/cwd/env allowlist、builder/toolchain/dependency/environment、外部输入闭包、
output 和 build log 全部 hash-bound；Hermetic 声明还必须有不同 principal 在独立 clean environment 中产生
byte-identical output 的签名 replay receipt。产品 Scenario runner 必须是 produced binary；Case evaluator
可用明确的 `INTERPRETED_NO_BUILD` tuple，但须固定 source blob、interpreter 和 dependency lock。

E4 的每条 Measurement 还签入同一 `qualificationRunId/hostId/hostEpoch/bootId`；device archetype 不是自报
标签，而是由 signed `DeviceTaxonomyDefinition` 与 exact current HostSnapshot/DeviceRecord 导出的
`DeviceClassificationRecord`，再由 `QUALIFICATION_ENGINEERING` 形成独立 Measurement。taxonomy/classifier
artifact 的 source、build、runtime 和 trace 可重放，且不得消费 qualification/catalog/HCL 结果。

`QualificationWorkloadDefinition` 先固定 binary/config、无 shell invocation、minimum duration、完整
`supportedQualificationTuples`（每行同时包含 guest+runtime，禁止两半独立命中或笛卡尔组合）、mandatory
assertion/oracle/evidence role、metric projection 与 pinned
`WorkloadEvaluatorManifest`；带 fresh nonce 的 signed RunRequest 在任何执行前固定它。signed
`EvaluationContext` 在 evaluator 运行前固定 evaluationId/evaluatedAt/key-ring/signer；evaluator 只消费 Definition、
RunRequest、RFC8785 canonical observation descriptor array、descriptor path/hash 精确绑定的 read-only raw
observation closure 与该 Context，按 manifest 固定的 source/build/runtime、
path/symbol/blob/interface 和精确 decimal/rounding/percentile/rate 语义生成 `WorkloadEvaluationReport`。签名报告
的 artifact/assertion/metric/outcome 必须被 terminal `QualificationWorkloadResult` 原样复制；exit code、日志行或
可变脚本没有判定权限。`EVALUATION_ERROR` 只能保留已验证的 canonical prefix，不能伪装成 workload failure。

evaluator/classifier 重放禁止 validator 在宿主上裸执行 evidence binary。内网须提供 verifier 独立配置的
target-architecture isolation runner：完整 closure 只读挂载、仅声明输入与一个 bounded output、
observation raw blobs 以 exact descriptor set 挂载到独立 evidence root、
no-new-privileges、deny-all network、禁止宿主文件/设备/凭据与未声明子进程，并限制
CPU/memory/process/file/time。无 runner、架构不符、隔离证明不可验证或 direct-exec fallback 时，E4/
qualification fail closed；空 portable baseline 不因此伪装已验证。

E4 Scenario input/core/index 都写入相同 runId、request digest 和 nonce digest，禁止 RunManifest 事后收养无关
core。全部 Measurement 和 scenario core 随当前 snapshot、wall/monotonic 起止和 signed terminal workload
result 进入 `QualificationRunManifest`，由 HOST_INVENTORY_EVIDENCE 与 TEST_EVIDENCE 两个不同 principal
双签；Subject 只能消费该 COMPLETE/PASSED 闭包，并精确核对 measured guest/runtime prerequisite。snapshot
descriptor 的 `sha256` 是最终签名 JSON 的 raw file hash，而 `inventorySnapshotDigest` 是解析后的
`HostSnapshot.contentHash` 和 authority current pointer；两个 hash domain 不得互换。

Host Agent 的 `CleanReleaseReceipt` 只是物理清理证据输入。`FREE`、旧 lease 消失、relocation
`TARGET_SOLVE` 还要求 global repository 在同一 serializable transaction 中比较完整旧 lease/version，写入
`ENTITY-CLEAN-RELEASE-ACCEPTANCE`，递增 authority resourceVersion，并由独立
`CONTROL_REPOSITORY_EVIDENCE` key 签名。没有该 acceptance，日志、TTL、QEMU exit 或 host receipt 都不能
声明资源已可复用。

推荐映射粒度是 symbol/API/table/transition，而不是整个目录。目标已有接口优先引用其 canonical
IDL/schema hash；缺失时才新建，避免维护两套 wire contract。

## 13. 内网 AI 必须停止并上报的情况

出现以下任一项，不允许“按最接近的实现”继续：

- 目标系统没有可做全局 CAS 的 owner authority，或准备以 TTL/heartbeat 自动释放 DMA 设备；
- owner bind/unbind、reset、QEMU spawn 发生在 durable operation lease 前；
- Legacy 路径只有 raw `host=BDF`，无法建立 per-VM device/sysfs/entrypoint 强制隔离和 receipt；
- 目标要求当前 Legacy 静默 fallback 到 TYPE1 另一 subtype、no-IOMMU 或 cdev；
- target VM lifecycle 有绕过 DirectPath gate 的 snapshot/suspend/migration/hotplug/raw QMP 入口；
- source 不可达却要求 target 自动接管，或要求 BMC/HA 进入本 V3 设计；
- 无法得到 physical isolation/requester alias/interrupt/reset 的 authoritative provider；
- catalog/profile/signature/sequence 无法绑定到 plan 与 launch；
- 目标 build 不能从 exact commit 的 Git object database 重建完整 tracked-tree，或 runner/predicate/decoder
  依赖 dirty、untracked、未解析 submodule 输入；
- qualification collector 只能从 proposed QualificationRecord/Subject 回抄字段，不能输出带 raw observation、
  pinned tool、typed projection 和独立签名的 measurement；
- 目标 schema 无法表达多 requirement/multi-bundle manifest 或独立 FSM/generation；
- 两份现有设计对同一 item 仍给出不同字段/顺序/失败 authoritative state。

上报内容必须含 contract item ID、target symbol、冲突证据、受影响 Case/Risk 和建议最小决策，不能
只写“代码不支持”。

## 14. 交接完成条件

### Portable spec（本仓库责任）

- VMware baseline、parity classification、产品边界和 backend policy 已版本化；
- required ports、canonical objects、FSM、CAS、reason、configuration、telemetry、migration 与 Case
  mapping 可机器检查；
- 35 个 operation envelope 与 70 个逐 operation/direction closed payload profile、17 个 authority aggregate、
  4 个 portable projection、identity golden vectors、trust/catalog anti-rollback 和 qualification index 都有
  closed schema；Scenario fixture 与 70 个 profile 精确绑定，执行时 `operationExchanges` 证明实际 envelope；
- 101 个 Case 有生成式 predicate/coverage 合同与 typed completion record；runner、execution index、
  `WorkloadEvaluatorManifest → signed EvaluationContext → EvaluationReport → WorkloadResult` 可重放链、
  `DeviceTaxonomyDefinition → signed ClassificationContext → DeviceClassificationRecord` 独立分类链、
  guest/runtime 完整 tuple prerequisite 实测匹配、
  qualification subject、完整 key-ring history 和 live anchor freshness 均有 closed schema；
- 293 个 mapping item 与 293 条 verification requirement 一一对应，Case/oracle 由合同派生而非由目标
  scenario 自报；
- Legacy attach、release ownership continuity、owner lease ordering、Dynamic solver 和 cold
  relocation 没有相互矛盾的规范分支；
- C→M→catalog/evidence content→A→E→detached final map 无自引用；mapping schema/template 完整且默认
  不冒充目标实现。

### Target mapping（内网 AI 责任）

- 目标 commit/build/test/migration 信息已冻结；
- schema 与语义校验器从 pinned contract 动态导出的全部有序 contract item 都存在；当前 release item
  为 `BOUND` 或显式 `CONFLICT`，未来独立 qualification track 仅可为 authority-backed `DEFERRED`，无
  silent omission/duplicate/reorder；
- 每个绑定都有 exact target path/symbol/interface hash、storage/table/field/transaction authority、test
  path/symbol/fixture、Case/Risk 和 disposition；
- 所有 `CONFLICT` 在实施前获得解决。

### Product implementation/qualification（内网产品责任）

- exact commit 上所有适用 mapping item `VERIFIED`；
- 所有产品 Case 由 `EXECUTED_PASS` 场景及已注册 evidence index 支撑，不能用 `TEMPLATE/BOUND` 关闭；
- DB/API/config upgrade、N/N-1、rollback、crash window、concurrency、negative lifecycle 和 bypass Case
  通过；
- 六个平台与支持 catalog 的设备取得要求的 E3/E4；
- Risk、Case、milestone 和 release gate 按证据更新。

因此，当前不需要用户提供 Qman 源码或仓库位置。等文档进入内网后，目标仓库本身就是 mapping
阶段的输入；内网 AI 应先按第 12 节自动发现并提交 integration map，再进入实现。
