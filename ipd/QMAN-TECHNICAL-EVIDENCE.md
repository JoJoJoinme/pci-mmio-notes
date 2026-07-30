# Qman 技术证据树与 WSL/QEMU 验证结果

状态：`TECHNICAL EVIDENCE / PRODUCT NOT IMPLEMENTED`
项目 claim：`REFERENCE_AND_QUALIFICATION_MODEL_ONLY`
治理快照：G0 `DONE`；G1 `IN_PROGRESS`；G2-G6 `NOT_STARTED`；Acceptance `101/101` 已分类
（1 `EXECUTABLE` reference、94 `IMPLEMENTATION_BLOCKED`、6 `HARDWARE_BLOCKED`）；C20 的 E2
reference runner 只证明算法，不关闭 PRODUCT Case；R01-R39 全部 `OPEN`
实验日期：`2026-07-21—2026-07-30 Asia/Shanghai`
环境：`WSL2 Ubuntu-22.04 + KVM + QEMU 11.0.2 + OVMF 2022.02`

本文把 [`ipd/README.md`](README.md) 中的 Tech Story 接到 Qman 自身证据链。机器索引位于
[`contracts/qman-evidence-index.json`](../contracts/qman-evidence-index.json)，单次结果必须满足
[`contracts/qman-technical-evidence.schema.json`](../contracts/qman-technical-evidence.schema.json)。

这里的“Qman 技术证据”包括 Qman reference model、QEMU control reference、QEMU/Guest/VFIO
集成和后续 Qman component/end-to-end 结果。它不意味着仓库里已经存在完整 Qman controller。

## 1. 证据等级与关闭权限

| 等级 | 含义 | 可以支持 | 不能关闭 |
| --- | --- | --- | --- |
| E2 | 单元、纯函数、schema、源码或模型证据 | 算法语义与 fail-closed 规则 | 产品 Case、物理 Risk、qualification |
| E3 | 实际 QEMU、firmware、Guest、VFIO 或 Qman component 的虚拟集成 | control/backend 行为与故障前提 | E4 硬件 Risk、HCL、`SUPPORTED` |
| E4 | 目标 server/device/firmware/Guest/driver/workload 的物理证据 | qualification review 输入 | 未通过产品 gate 的 release claim |

在独立、签名的 qualification approval contract 落地前，E4 仅是评审输入；单份 result
不得自授 Case、Risk 或状态关闭权限。

强制不变量：

```text
VMware observation != Qman evidence
QEMU/Guest reference != Qman product Case pass
Qman component result != end-to-end product closure
E2/E3 != physical qualification
SUPPORTED => E4 qualification + Qman product gate
artifact hash drift => evidence invalidated
```

## 2. 本轮结论

| Evidence | 等级 | 已实锤 | 影响的 TS / Case 前提 | 本轮没有宣告 |
| --- | --- | --- | --- | --- |
| `QMAN-E2-REFERENCE-MODEL-001` | E2 | WSL 下历史基线 87/87 reference-model tests pass | TS-F1-02/03/04、F2-01/02、F4-01；C05/C06/O09/M22 | controller、provider、lease store；不追认后续 C20 |
| `QMAN-E2-CLOSURE-001` | E2 | C20 定向 22/22、全量 112/112；四格固定点、严格 fact verifier、有界 closure、immutable inventory、owner-independent/decision hash A/B 与零副作用均通过 | TS-F1-01/04、F5-01；C20 / R38 前提 | 产品 inventory/evidence provider、controller/lease/attach、C20 产品 Case、R38、E4 |
| `QMAN-E2-C16-TOPOLOGY-LOCALIZATION-001` | E2 / `REFERENCE_ONLY` | C16 定向 15/15、全量 294 passed + 5 platform skips；parent/group/alias/anchor 组成的受影响组件局部 fail closed，互不相交完整组件的 device projection 在 16 种输入顺序下不变；`software_topology_estimate` 明确不受信 | TS-F1-01/03/04；C16 / R01/R35 前提 | 产品 kernel-native shadow-domain ABI、签名 HostSnapshot publisher、完整 capability/snapshot hash、target mapping、E3/E4；不关闭 C16/Risk/G1 |
| `QMAN-E2-C00-HOST-SNAPSHOT-ANCHOR-BINDING-001` | E2 / `COMPONENT_ONLY` | 只接受 `COMMITTED` HostSnapshot rollback anchor；逐层校验 candidate/prepare/anchor/final/freshness/binding digest 与 root quorum，精确绑定 8 个 inventory 坐标、path、nonce、schema/raw bytes、结构性 CAS 和时序；6 个 current-vector 字段进入 guarded read，并由 query-trace verifier 约束其观察来源 | TS-F1-01/04、F5-01；C00 / R38 前提 | 外部 authority 的直接 fetch、nonce transport、线性 CAS/耐久 publisher、产品 adapter、产品 raw-config collector/provider、E3/E4；不关闭 C00/R38/G1 |
| `QMAN-E2-C00-PCI-STRUCTURE-FLR-PREMISE-001` | E2 / `COMPONENT_ONLY` | 对调用方保留的精确 256-byte 配置空间执行有界 capability-chain 重放；Header Type 与 class code 正交，PCIe Device Capabilities bit 28 是唯一 FLR capability 来源；DeviceRecord V3、provider capture interval/digest、HostSnapshot V2 语义投影、完整 closure owner scope、factory-only hardware/technical/admin/owner gate 与 schema-bound guest-plan hash 逐层精确复算 | TS-F1-01/04、F5-01；C00-C03 / R03/R29/R38 前提 | 产品 sysfs/kernel collector、签名 publisher/CAS、target mapping、真实 planner/solver、reset safe/clean/affected-set、E3/E4；不关闭 Case/Risk/G1 |
| `QMAN-E2-C00-HOST-SNAPSHOT-CAPTURE-CLOSURE-001` | E2 / `COMPONENT_ONLY` | 精确保留 capture batch、freshness policy、DeviceRecord V3 与 provider raw/semantic envelopes；V2 algorithm identity 绑定五份有序 transitive schema digest 和十个 validation stage；从 record provenance 重建非空 coverage，要求完整 host PCI UID/BDF 双射，重放 raw config/closed failure、PCI structure/FLR、topology/provider/no-change projection、mandatory-fact freshness，并在 schema walk 前执行闭合预算 | TS-F1-01/04、F5-01；C00-C03 / R03/R29/R38 前提 | caller-stamped candidate coordinates、trusted publication evaluation time、target decoder/build、collector/publisher、capability-policy authority CAS、完整 publication transaction、SERIALIZABLE repository、rollback/visibility receipt、E3/E4；不关闭 Case/Risk/G1 |
| `QMAN-E2-C00-HOST-SNAPSHOT-PUBLICATION-CLOSURE-001` | E2 / `COMPONENT_ONLY` | 从 factory-only capture 继续重放 exact 四 authority read set 和五类 decision；以 publication/recovery 双 trust 验证 PREPARED/COMMITTED rollback、nonce/CAS/恢复窗口与前向 key-ring lineage，并分别绑定独立配置的 trust path、freshness receipt digest 和验证窗口；再确定性生成 `N+6` mutation DAG、五类 projection、四 authority resolved vector 和 audit/outbox/commit self-digest，`NO_CHANGE` 严格零写 | TS-F1-01/04、F5-01；C00 / R38 前提 | 认证 operation/result schema、trust authority direct path/nonce transport、产品 repository transaction/CAS/commit clock、atomic visibility、post-anchor delivery、target mapping/build/runner、E3/E4；不关闭 C00/R38/G1 |
| `QMAN-QEMU-CONTROL-001` | E3 | 建机后可通过 QMP 向 QEMU device tree 加入 PCI endpoint（本次在 machine 暂停态）；同 guest BDF 可换 VID:DID；`device_del` reply 后设备仍存在 | TS-F3-01/04、F4-05、F5-05；S01/S15/F09 前提 | Guest 在线热插、Qman QMP ACL 已实现、S15/F09 已通过 |
| `QMAN-E3-QMP-GATE-001` | E3 | 最小 gate 本地处理 capability，只转发五类只读 query；17 类拒绝均未被独立 backend recorder 观察到，PCI tree、QEMU/gate fd 基线不变 | TS-F4-05、F5-05；S15/F09 与 R17/R26/R37 前提 | production launcher/lease/generation/VFIO 或全入口绕过已封堵；S15/F09 与三项 Risk 均未关闭 |
| `QMAN-E3-DMA-PROVIDER-001` | E3 | unsafe=`Y` 时，no-IOMMU 与 IOMMU-backed device 仍呈现不同 provider node | TS-F1-02、F3-03；C21 前提 | 物理 IOMMU/IR/errata、IOMMUFD IOAS attach、DPDK workload |
| `QMAN-E3-VFIO-PROVIDER-GATE-001` | E3 | Qman component 对 no-IOMMU 稳定拒绝；对 cdev 真实执行 IOMMUFD bind、IOAS allocate/attach、身份/完整 group 复核与逆序清理 | TS-F1-02、F3-03；C21 / R27 前提 | 权威产品 snapshot、durable lease、stock-QEMU handoff、物理 E4；C21/R27 均未关闭 |
| `QMAN-E3-STATIC-LEASE-FAULT-001` | E3 | WSL 原生 ext4 上 7/7 subprocess/SQLite 故障场景通过：begin/release commit 前硬退出无部分状态，重叠 bundle 双进程仅一胜，未知 cleanup 与 SIGKILL 后 reconcile 保留 whole-bundle quarantine | TS-F3-02/05、F5-03/04；S03/S04/S05/F00 与 R04/R05/R11 前提 | bind/reset/QEMU/cleanup 真实执行、pidfd/DMA/IRQ/owner clean state、产品 Case/Risk；四个 Case 仍 blocked |
| `QMAN-E3-AUTHORITATIVE-SNAPSHOT-FAULT-001` | E3 | host-local SQLite snapshot component 的未提交 epoch 不可见、并发 CAS 单胜与严格递增 epoch 已通过真实 subprocess/并发故障注入；signature/payload/stale/minimum-epoch/boot drift 均 fail closed；删除最新行后 earlier-valid 状态仍可被接受，实验证实外部单调锚是必要边界 | TS-F1-01、F8-02；R04 前提 | G1 产品 publisher、生产 trust root、外部单调防回滚锚、power-loss durability；不关闭 Case/R04/G1 |
| `QMAN-E3-STATIC-LAUNCH-ENVELOPE-001` | E3 | v5 将 sealed capture provider、签名 full-host snapshot、完整 group 授权范围、6 次一致的 live full scan、lease authorization、production-provenance raw cdev/IOMMUFD 与 fd-only stock QEMU 串成一条链；QMP/QOM 看到 realized `vfio-pci`，trace 中 bind、IOAS allocate、attach 均返回 0；无独立 DMA receipt 时不提交 `ATTACHED`，保留 claims 并 quarantine | TS-F1-01、F3-02/03/05、F5-04、F8-02；C21/S05 与 R04/R05/R26/R27 前提 | 该结果只是未来 cdev backend 前提；当前 Legacy path grant/sandbox/receipt、生产 G1 authority/trust/rollback anchor、真实 reset/driver restore、独立 DMA/IRQ observer、pidfd/产品 controller、物理 E4 仍缺；Case/Risk/G1/G2 均未关闭 |
| `QMAN-E3-MMIO-OBSERVED-001` | E3 | QEMU floor 与 OVMF aperture 必须配对；双 64 GiB BAR 默认失败、128 GiB 配对成功 | TS-F4-01/02/04；M23 前提 | Qman observedPlan commit/rollback、物理 BAR qualification |
| `QMAN-E3-AER-QEMU-REFERENCE-001` | E3 / `REFERENCE_ONLY` | stock QEMU 11.0.2 的 8 个 Correctable bit × 8 个 E/M/R tuple 共 64/64 通过；Endpoint status deposition、report/mask gate、Root Status/Source 与 Root Command state 可由 oracle 分离 | TS-F4-06；M06/R13 的 reference 前提，不关闭二者 | ESXi service/IRQ、Qman `aerPolicy`/host agent、lifecycle recovery、物理 E4 与任何 support/release claim |
| `QMAN-E3-AER-QEMU-ROOT-SEQUENCE-001` | E3 / `REFERENCE_ONLY` | first/multiple、Endpoint/Root 独立 W1C、B0/B1 OR 与 re-arm 各三次 fresh QEMU，12/12 MATCH；276 个逐案 artifact hash 通过 | TS-F4-06；M06/R13 的 root-state reference 前提，不关闭二者 | ESXi 同序列、Root notification/service、Qman 实现、guest write、lifecycle、物理 E4 |
| `QMAN-E2-AER-VMWARE-G101-PARITY-001` | E2 / `COMPONENT_ONLY` | 同一 Correctable-only 纯模型 trace 分别与 frozen ESXi O0/O4 `g101` 的四序列逐字段比较；2 branch × 8 checkpoint × 8 field 共 128 项一致，实际 action 顺序与 checkpoint 位置被记录并校验，非法 sequence/requester fail closed | TS-F4-06；M06/R13 的 component 前提，不关闭二者 | owner 不是模型输入；exact target Qman adapter、guest-write authorization、其他 E/M/R gate、IRQ/service、lifecycle、物理 E4；O0 `Module Name=None`，不证明 VMware 私有 owner-independent 机制 |

当前 Acceptance 已 `101/101` 分类，所有 Risk 仍为 `OPEN`。这些结果增加
“为什么要这样设计”的技术证据，不改变 G0 `DONE`、G1 `IN_PROGRESS`、G2-G6 `NOT_STARTED`、claim
`REFERENCE_AND_QUALIFICATION_MODEL_ONLY` 和 release `BLOCKED` 状态。

## 3. 被实验修正或强化的设计判断

### 3.1 不能把 VMware 默认配置翻译成固定的 QEMU `0/0`

历史任务早期猜测“VMware 默认 EFI 大致等价于 OVMF aperture=0、QEMU floor=0”，后续
ESXi 与 QEMU 实验都推翻了这种单值翻译。本轮在 QEMU 11.0.2/`pc-q35-11.0` 重跑双
64 GiB BAR：

- 默认 32 GiB QOM floor 下，OVMF 没有为两个 BAR 分配地址，Guest probe 无 heartbeat。
- `X-PciMmio64Mb=131072` 与 `pci-hole64-size=128G` 配对后，两个 BAR 分别位于
  `0x2000000000:0x3000000000` 和 `0x3000000000:0x4000000000`，Guest heartbeat 成功。
- Qman 必须保存 required span、firmware aperture、QEMU floor 和 observed runtime window
  四个事实，不能把 `pci-hole64-size` 当成 hard cap。

证据：[`qman-qemu-mmio-observed-20260721-summary.json`](../evidence/qman-qemu-mmio-observed-20260721-summary.json)。

### 3.2 全局 unsafe no-IOMMU 开关不是逐设备结论

两个 Guest 都把 `enable_unsafe_noiommu_mode` 设为 `Y` 并把相同 e1000e bind 到
`vfio-pci`：

- 无 vIOMMU：bind 前无 group，bind 后是 `/dev/vfio/noiommu-0`。
- 有 Intel vIOMMU：bind 前后存在正常 group，并出现 `/dev/vfio/N` 与 VFIO cdev。

因此 Qman 可以允许宿主为受信 DPDK workload 打开全局 unsafe switch，但 VM 目标设备必须
在 attach 时独立证明 IOMMU-backed provider；`noiommu-*` 必须拒绝。

证据：[`qman-vfio-dma-provider-20260721-summary.json`](../evidence/qman-vfio-dma-provider-20260721-summary.json)。

### 3.3 Qman provider 已执行真实 IOMMUFD attach，但只是组件闭环

在 provider-node A/B 之上，`QMAN-E3-VFIO-PROVIDER-GATE-001` 把 C21 的关键判定变成了
Qman component 代码和真实 Guest UAPI 调用：

- 两个 QEMU Guest 使用相同 e1000e 和 `unsafe=Y`；独立 Guest sysfs reader 生成 canonical
  identity/完整 IOMMU group preimage 与 SHA256，runner 又逐字固定实际执行的 provider 源码；
- 无 vIOMMU 的 Guest 出现 `/dev/vfio/noiommu-0`，provider 在打开任何 DMA context 前以
  `DEVICE_NO_IOMMU_DMA_ISOLATION`、exit 2 稳定拒绝；
- Intel vIOMMU Guest 的 cdev 路径真实得到 `ioasId=1`、`deviceId=2`、`hwptId=3`，说明完成了
  IOMMUFD IOAS allocate、`VFIO_DEVICE_BIND_IOMMUFD` 和 IOAS attach；attach 后再次复核身份、
  driver、完整 group 与 node，standalone probe 最后逆序清理并报告 `ACQUIRED_AND_CLOSED`；
- Windows/WSL 全量 resource-model 均为 139/139，provider 定向 27/27；identity/group stale、
  no-IOMMU 竞态、node substitution、未知 ABI、所有 ioctl 失败和 cleanup 生命周期均 fail closed。

这仍不是产品 C21。实验中的 `snapshotEpoch/topologyHash` 明确只有
`CALLER_CORRELATION_ONLY`，独立 reader 不是 G1 权威 inventory publisher；CLI 也在验证后关闭 fd，
没有把活 session 交给 QEMU。尤其 stock QEMU 会自行执行 VFIO cdev bind/attach，所以“agent 先
attach，再把同一 session 直接交给 stock QEMU”不是可用的产品路径。后续必须按已冻结
backend profile 验证唯一 launcher 协议：当前 Legacy TYPE1 路径从 sealed authorization
生成 `AUTHORIZED_DEVICE_PATH`，用受限 namespace/cgroup/LSM 和 `host=<BDF>` 启动，再以
`/proc/<pid>/fd` + QMP/QOM 收据提交；未来 cdev/IOMMUFD profile 才通过 fd-only 参数由
stock QEMU 自行 bind/attach。物理 IOMMU/IR/errata/reset/workload 仍需 E4，故 C21 与 R27 不更新状态。

证据：[`qman-vfio-provider-gate-20260721-summary.json`](../evidence/qman-vfio-provider-gate-20260721-summary.json)。

### 3.4 BDF 不是稳定身份，raw QMP 是真实绕过面

同一 QEMU machine address `0000:01:00.0` 在两次启动中分别承载：

```text
8086:10d3  QEMU e1000e
1b36:0005  QEMU pci-testdev
```

另一个 run 在建机后先暂停 machine，再通过 raw QMP 成功把 e1000e 加到原本为空的
`01:00.0`。它证明 QMP 能越过仅发生在冷启动前的设备规划边界，但不宣称 Guest 在线热插已
完成。这支持以下设计要求：

1. Static manifest 不能只保存 BDF，必须保存并重验稳定 fingerprint。
2. 冷启动 admission 不能只靠 launcher；QMP proxy/ACL、sandbox 和 backend-specific attach
   authorization（当前 Legacy path、未来 cdev fd）都是安全边界。
3. `device_del` 返回成功后，设备一秒后仍在 `query-pci`，所以 teardown 必须等待 Guest/backend/
   IOMMU/reset 的完成证据，不能以 QMP reply 提交 lease release。

证据：[`qman-qemu-control-20260721-summary.json`](../evidence/qman-qemu-control-20260721-summary.json)。

### 3.5 C20 必须把依赖闭包放在 availability 之前

`QMAN-E2-CLOSURE-001` 把实现蓝图中的 C20 四格变成可执行 reference runner：dependency
qualified/free 与同一 bundle busy 拥有完全相同的 snapshot/bundle/capability/policy hash，仅
availability 与 `decisionHash` 改变；dependency reset missing 或 action unknown 则在 capable gate
直接失败。补充反例还验证了：

- 无显式 verifier、伪造 evidence hash、旧 epoch/topology 和 BDF key/identity 替换全部 fail closed；
- verifier 必须返回严格布尔 `True`，inventory devices/leases 构造后不可变；
- 20,000-member 恶意 dependency domain 在加入 member/edge 前受限，拒绝结果不复制超大全集；
- reason message 本地化不改变语义 hash，attach/activation group 与 MMIO 只绑定到最终 decision hash；
- 查询不执行 bind、reset 或 lease write。

这里使用的 `REFERENCE_FACT_VERIFIER` 是可重算的确定性 E2 fixture verifier，只证明字段绑定，
不证明签名真实性。生产 Qman 必须注入版本化 trust-root/policy verifier，且其 identifier/digest 必须
进入 policy hash；因此本结果不关闭 C20 产品 Case 或 R38。

证据：[`qman-capability-closure-20260721-summary.json`](../evidence/qman-capability-closure-20260721-summary.json)。

### 3.6 QMP component 已证明“受控端点默认拒绝”，尚未证明产品无旁路

`QMAN-QEMU-CONTROL-001` 是 raw QMP 能越过冷启动规划的威胁正控；本轮新增的
`QMAN-E3-QMP-GATE-001` 是一个最小 Qman component 负控：

- gate 解析后重建 JSON，客户端 `qmp_capabilities` 在本地处理；进入 backend 的业务命令只可能是
  `query-version/status/kvm/name/pci`，客户端 ID 不进入 backend namespace；
- 27 个客户端请求产生 34 条精确审计事件：3 个 local capability、7 个 forward attempt、
  7 个 success outcome 和 17 个 deny；每条都绑定连接、顺序、peer credential、policy hash 与
  request digest，未知命令字符串不写入 audit；
- 位于 gate 之外的 test-only recorder 实际只看到 3 个内部 capability 协商和 7 个只读 query，
  `device_add/device_del`、HMP、QOM、fd、畸形 JSON、OOB、超长帧和 SCM_RIGHTS 共 17 类负例中，
  进入 QEMU backend 的数量为 0；
- 拒绝矩阵前后 PCI tree hash 相同，QEMU fd multiset 无变化；SCM_RIGHTS 后 gate 自身 fd multiset
  回到基线，socket 权限为 `0600`、私有目录为 `0700`，非授权用户得到 `EACCES`，gate 正常退出。

这只证明一个 emulated QEMU 进程的受控 monitor 端点。实验中的 observer monitor 和 recorder 是
测试专用旁路；生产还没有把 gate 与 controller、durable lease/generation、当前 Legacy
path-authorized launcher、
API/CLI/storage/alternate-monitor 封锁集成起来。因此结果是 `QMAN_COMPONENT / COMPONENT_ONLY`，
不能关闭 S15/F09 或 R17/R26/R37。

证据：[`qman-qmp-gate-20260721-summary.json`](../evidence/qman-qmp-gate-20260721-summary.json)。

### 3.7 Static lease/FSM 已有真实进程故障证据，但外部设备动作仍是边界

`QMAN-E3-STATIC-LEASE-FAULT-001` 把 host-local persistence、CAS 和 recovery 语义从普通单测推进到
WSL 原生 ext4 上的真实进程故障：

- schema-v4 store 把 `local_host_id`、单一 `trusted_authority_id` 与 `store_instance_id` 固定进 metadata；bundle、每个 device
  generation 和 transaction 必须来自同一 authority namespace，同 epoch ABA、stale VM/device generation
  与跨 authority publisher 都 fail closed；
- child 在 `BEGIN_BEFORE_COMMIT` 调用 `os._exit(91)` 后，transaction、journal、member/bundle claim 与
  VM generation 均无残留；在 `RELEASE_CLEAN_BEFORE_COMMIT` 调用 `os._exit(92)` 后，原 state、claim、
  journal 和 device generation 全部保留；
- 两个独立进程同时争抢重叠 bundle，SQLite `BEGIN IMMEDIATE` + member CAS 只允许一个 transaction
  commit，另一方稳定得到 `MEMBER_BUSY`；
- 一个独立 Python owner 持久化到 `ATTACHED` 后被真实 `SIGKILL`；重开 store 时进程消失没有被当成
  cleanup 证据，`UNSAFE_OR_UNKNOWN` 只会把完整 bundle 置为 `QUARANTINED` 并保留 claims；
- 37 个留存 artifact hash 全部复算一致，7 个 checkpoint SQLite DB 均 `integrity_check=ok`；live DB
  从不放在 `/mnt/e`，DrvFS 只保存 checkpoint 后的证据副本。

S03/S04/S05/F00 在 runner 中只是产品场景的组件前提名称。bind/reset/QEMU 均为模拟阶段标签，
S03 的 `cleanup_verified` 是受信测试断言，F00 杀死的是 Python 代理而不是真实 QEMU；因此该记录是
`QMAN_COMPONENT / COMPONENT_ONLY`，不关闭 Case、Risk、G2，也不证明 power-loss、多主机 fencing、
DMA/IRQ teardown、driver restoration 或物理设备 clean state。

证据：[`qman-static-lease-fault-20260721-summary.json`](../evidence/qman-static-lease-fault-20260721-summary.json)。

### 3.8 Authoritative snapshot 已有 bounded publisher 与故障门，但不是 G1 产品权威

`QMAN-E3-AUTHORITATIVE-SNAPSHOT-FAULT-001` 把 snapshot 从 caller supplied correlation 推进为
host-local component authority：完整 HostInventory 与精确 PCI identity/IOMMU group facts 被 canonicalize，
以 boot identity、单调 epoch、full-topology hash 和 HMAC-SHA256 envelope 一起持久化到 WSL 原生文件系统。
发布使用双次稳定 full scan、SQLite `BEGIN IMMEDIATE`/CAS 与 WAL/FULL；launch authorization 只接受
当前 boot、当前 snapshot、满足 minimum epoch 且签名/内容/hash 一致的记录。

真实故障实验验证了：

- child 在 insert 后、commit 前 `os._exit(91)`，重开后只看见旧的 epoch 1，SQLite
  `integrity_check=ok`，未提交 epoch 不可见；
- 两个独立 publisher 对同一 current hash 并发 CAS，严格只有一个 winner；提交序列为 epoch 1、2，
  loser 得到 `PUBLISH_CONFLICT`；
- signature tamper、payload tamper、旧 snapshot、minimum epoch 与 boot drift 分别以稳定 reason
  fail closed；
- 删除最新 epoch 2 后，同一 inode/store instance 中正确签名的 epoch 1 仍会被 `current()` 接受为
  当前 authority state；重开进程没有 process-local sealed capture provider，不能据此签发 launch
  authorization。该 L01 反例明确验证了外部单调 rollback anchor 的必要性，而不是把 inode/store UUID
  误当作防回滚证明。

这只是 `QMAN_COMPONENT / COMPONENT_ONLY`。HMAC signer/verifier 共享组件 key，不是 TPM/HSM-backed
生产 trust root；没有外部单调锚时，任何 earlier-valid SQLite 状态回放（含同 key 下原位/块级恢复或
删除最新行）都可能被接受，inode/store UUID 不是 anti-rollback 证明；WAL/FULL
也不等于端到端 power-loss durability。它不完成 G1，不关闭 R04 或任何 Case。

证据：[`qman-authoritative-snapshot-fault-20260721-summary.json`](../evidence/qman-authoritative-snapshot-fault-20260721-summary.json)。

### 3.9 Static launch 已接上 signed snapshot，但故意没有越过 DMA 证据门

`QMAN-E3-STATIC-LAUNCH-ENVELOPE-001` 在 WSL2/KVM 外层 QEMU 11 中启动 Ubuntu + Intel vIOMMU，
把虚拟 e1000e bind 到真实 `/dev/vfio/devices/vfio0`。v5 先在 WSL 原生文件系统用同一个
`COMPONENT_CAPTURE_PROVIDER` 双扫描并发布 HMAC 签名的 full-host snapshot，再由 sealed snapshot
authorization 派生完整 IOMMU group request；只有 snapshot
authorization 与 schema-v4 lease authorization 同时有效时，Qman component 才打开 fresh raw cdev 与
`/dev/iommu`，typed renderer 才生成 `env={}`、`cwd=/`、`shell=false` 的 fd-only stock-QEMU spawn。
这条链明确是未来 cdev/IOMMUFD backend 的 component evidence，不是当前 Legacy 产品路径：

```text
signed full snapshot (double stable scan, epoch 1)
  -> sealed snapshot authorization
lease RESERVED -> PREPARING
  -> PRE_OPEN full scan -> raw VFIO bundle -> POST_OPEN full scan
envelope INTENT_PERSISTED -> LEASE_PREPARED -> HANDLES_OPEN -> QEMU_RUNNING
  -> validate_before_spawn full scan -> popen_kwargs full scan -> Popen
QMP/QOM realized vfio-pci -> QMP_RECEIPT_VERIFIED
independent DMA receipt absent
  -> CLEANING -> stop QEMU -> close raw fds
  -> lease QUARANTINED (claims retained)
  -> envelope QUARANTINED
ATTACHED was never committed
```

本次观测到：

- publisher 的 2 次 publish scan，加上 PRE_OPEN、POST_OPEN、`validate_before_spawn` 和
  `popen_kwargs` 的 4 次 live revalidation，共 6 次 full-host scan；12 个 PCI device 的 boot/host、
  device count 与 full-topology hash 全部一致；
- snapshot authority/store/key/boot/epoch/hash/authorization 与 capture-provider binding 被绑定进
  raw-handle metadata、fd binding 与 launch plan；plan BDF 集合等于 `authorized_bdfs` 并覆盖完整
  IOMMU group；snapshot authorization 和 lease authorization 在最终 Popen 时仍处于 active；
- QMP 为 `prelaunch/running=false`，KVM enabled/present，`/machine/peripheral` 中存在
  `dp0 child<vfio-pci>` 且 `realized=true`；
- tracefs 将 255 个 QEMU ioctl 配对，其中 `VFIO_DEVICE_BIND_IOMMUFD (0x3b76)`、
  `IOMMU_IOAS_ALLOC (0x3b81)`、`VFIO_DEVICE_ATTACH_IOMMUFD_PT (0x3b77)` 都返回 0；
- QMP receipt 只具有 component authenticity；它与内核 syscall trace都不是独立 DMA/IRQ
  isolation 证明，因此 DMA receipt 保持缺失，最终 lease/envelope 都是 `QUARANTINED`，raw fd 已关闭，
  bundle/member claims 仍保留；
- 现有 bundle opener 还通过单测固定“每个涉及的 IOMMU group 必须完整、多个 cdev 共享一个
  IOMMUFD、任一 child close 关闭整个 ownership unit”的合同；正式 nested run 只有单成员 group，
  不能冒充多设备或物理平台验证。

正式登记的仍是 v5 provider/snapshot 语义，最新 raw 目录为
`E:/Code/PCI/_artifacts/qman-wsl-qemu/20260722-static-launch-envelope-framed-115200`，summary verdict 为
`pass`，22/22 个保留工件哈希独立复核一致。证据回传使用独立 `ttyS1` 和
`BEGIN/CHUNK/END` framing；7 个 artifact、328 个 chunk 均通过连续序号、声明长度和 raw SHA-256
校验，并明确确认 115200、`RC=0` 与 completion marker。此前一次显式 `--timeout 420` 的复验虽然
guest 已 PASS，却在 ioctl trace 回传中途被外层超时终止；该不完整结果未登记，也没有被解释成
VFIO/Qman 功能失败。v1-v3 保留为历史工程反馈：v1 暴露 QEMU greeting 后
3 秒 command timeout 的误判，v2 的 guest 已 PASS 但长 Base64 证据与 ttyS0 systemd 日志交织，v3
修复 transport，却仍是 snapshot caller correlation；v4 接入 bounded signed publisher 与 6 次 full
scan；v5 再封存 capture provider 并强制 authorization/QEMU plan 的完整 group 范围一致。

v5 的 snapshot authenticity 仍只是 component HMAC，不是生产 trust root；没有外部单调 rollback
anchor，无法检测任意 earlier-valid SQLite 状态回放，也没有证明真实 power-loss、物理设备 DMA/IRQ
isolation。因此
结果仍是 `QMAN_COMPONENT / COMPONENT_ONLY`，不关闭 C21/S05、任何 Risk、G1/G2 或 HCL。

证据：[`qman-static-launch-envelope-20260721-summary.json`](../evidence/qman-static-launch-envelope-20260721-summary.json)。

### 3.10 C16 已把 provenance 缺口局部化，但没有制造受信的物理域

`QMAN-E2-C16-TOPOLOGY-LOCALIZATION-001` 将拓扑连通性与 provenance 完整性拆开：

- 先用 parent、kernel IOMMU group、multifunction alias、shared anchor 和 shared legacy bus
  保守构造 topology component，再判定每个 component 的 ACS provenance 是否完整；
- dangling parent、parent cycle、缺失/不对称/集合不等价的 group 或 alias，以及 ACS
  缺失或冲突，只把受影响 component 置为 `UNKNOWN`；输出携带稳定排序的 affected members
  和精确 reason；
- 向完整 inventory 加入互不相交的坏 component，不改变原完整 component 的 device
  projection；16 种固定随机输入顺序也得到相同结果；
- 用户态重建来源固定为 `software_topology_estimate`，且 capability gate 明确拒绝该来源和
  已废弃的旧标签。只有未来产品 kernel-native shadow-domain ABI 的输出才可进入受信来源。

C16 定向测试 15/15、26 个 subtest 通过；resource model 全量为 294 passed、5 个平台限定
skip、137 个 subtest 通过。机器记录见
[`qman-c16-topology-localization-20260730-summary.json`](../evidence/qman-c16-topology-localization-20260730-summary.json)。
该结果只固定 device/component semantic projection，不证明完整 `capabilityHash` 或签名
`snapshotHash` 稳定；产品 kernel ABI、HostSnapshot publisher、trust root/rollback anchor、
target mapping 和 E3/E4 均缺失。因此 C16、R01、R35 与 G1 继续保持 blocked/open。

### 3.11 C00 已消费外部 HostSnapshot 回滚锚，但仍不是产品 authority

`QMAN-E2-C00-HOST-SNAPSHOT-ANCHOR-BINDING-001` 把此前仅被识别为必要条件的外部单调锚，
推进为可执行的 component gate：

- factory-only verifier 只接受 `COMMITTED` 记录，逐层重放 candidate、prepare、anchor、
  final receipt、freshness receipt 和 binding 的 canonical bytes、digest、签名与测试 root quorum；
- genesis、同 incarnation successor 和新 incarnation genesis 分别执行结构性 CAS 检查，
  并精确绑定 HostSnapshot 的 8 个 inventory 坐标；这只能验证输入形状和前后链，不能证明
  authority 端真实线性化、掉电耐久或外部单调存储；
- freshness receipt 精确绑定配置 path、verifier nonce、schema hash 和 anchor 原始字节；
  `checkedAt` 使用半开区间，anchor expiry 进入 guarded-read 的 exact evidence horizon；
- `CurrentAuthorityVector` 新增 6 个 anchor/freshness/binding 字段；当调用方提交的 after-vector
  显示任一字段已推进时，旧授权会被拒绝。query-trace verifier 必须观察同一组字段，并要求
  component/reference observation 显式为 `productAuthorized=false`。

本条 hash 闭包内的 anchor 定向链测试为 85 passed、111 subtests；authority/operation
序列化定向链为 32 passed、49 subtests；另行执行的 portable core 全量
回归为 294 passed、302 subtests。
机器记录见
[`qman-c00-host-snapshot-anchor-binding-20260730-summary.json`](../evidence/qman-c00-host-snapshot-anchor-binding-20260730-summary.json)。
该记录固定为 `LOCAL_RAW / COMPONENT_ONLY`：anchor/freshness/path/nonce/trust context 仍由调用方
提供。raw PCI structure/FLR 已由另一条 component-only E2 记录覆盖，但目标 Qman repository
mapping、产品 direct-fetch/CAS/publisher、产品 raw-config collector/provider、E3/E4 和
CaseCompletionRecord 仍缺失。因此 C00 仍为 `IMPLEMENTATION_BLOCKED`，
R38 仍为 `OPEN`，G1 与 release 状态不变。

### 3.12 C00 已有 raw PCI structure/FLR 可重放前提，但仍没有产品 collector

`QMAN-E2-C00-PCI-STRUCTURE-FLR-PREMISE-001` 将 G1 inventory 中最容易被调用方“口头声明”的
两组硬件事实改为同源、可重放的 component chain：

- 输入只能是调用方保留的精确 256-byte conventional PCI configuration space，或带稳定失败码的
  `UNAVAILABLE`；全零、全一、长度错误、越界/未对齐 capability pointer、环和重复 PCIe capability
  均 fail closed；
- class code 只与 immutable identity 交叉校验；结构角色独立读取 offset `0x0e` 的 Header Type，
  bit 7 单独表示 multifunction。`ENDPOINT_PAYLOAD` 必须是已知 Type-0 PCIe endpoint，不能由
  network/display/storage class code 代替；
- FLR 只从 PCIe capability ID `0x10` 的 Device Capabilities dword bit 28 重放。
  `selectedMethodOrNull=PCI_FLR` 还必须绑定同一次 capture 的 provider fact、Type-0 endpoint 与
  FLR=true；它没有推导 reset clean、reset safe 或完整 affected set；
- DeviceRecord 硬切到 V3。portable inventory verifier V2 绑定 7 个 closed schema、执行 12 个
  有序 stage，并要求每个 provider fact 的 `observedAt` 落在
  `captureStartedAt..capturedAt` 闭区间内；逐设备重算 provider fact-set digest，再从完整 DeviceRecord 集重算
  HostSnapshot topology/provider semantic digest；
- publication V2 要求每个通用 provider capture 至少覆盖一个已发布 DeviceRecord，覆盖集合与各
  DeviceRecord provenance 精确双向对应；只有 PCI provider 还要求 PCI-specific fact binding 的并集
  与 DeviceRecord 一一对应。证据字节与语义事实分开：保留区 raw byte 或 evidence hash 的单独变化不制造
  topology change；Header Type 从 Type-0 变 Type-1、或 FLR bit 28 丢失则必须改变 device、
  topology 与 no-change projection；
- inventory closure factory 产生不可公开构造的 hardware premise。admin gate 逐个约束请求 root，
  owner gate 则覆盖完整 `ownerActivationGroup`，要求每个成员均为 active、
  desired/effective owner=`PASSTHROUGH` 且 transition=`ALREADY_ACTIVE`。static/read guard 精确重放并
  比较 factory hardware/technical/admin/owner gate，调用方把真实 `NO` 自报为 `YES` 会在 evaluator 前被拒绝；
  `UNKNOWN`/`CONFLICT` reset 也保持空 affected set 和 fail closed。
- 同一 Static admission 还精确绑定 canonical、schema/hash 固定且有大小/节点/深度/条目预算的 guest
  resource-plan 原始字节。该 verifier 只检查结构、上游坐标和基础 window 顺序/对齐/区间算术；不发现 BAR
  demand，不运行或证明 MMIO/BAR/RMRR/IRQ solver，不证明
  `allMandatoryResourcesAssigned`，也不观察 QEMU/firmware 实际布局。
- guarded capability 到 operation-admission 的序列化始终携带各 component premise digest、边界、
  blocker 和 `productAuthorized=false`，因此“eligible/attachable”组件判定不能被洗成产品授权。

上述定向链为 110 passed、114 subtests；portable core 全量为 294 passed、302 subtests。
机器记录见
[`qman-c00-pci-structure-flr-premise-20260730-summary.json`](../evidence/qman-c00-pci-structure-flr-premise-20260730-summary.json)。
其 authority boundary 明确是 `COMPONENT_CALLER_SUPPLIED_RAW_CONFIG_BYTES_ONLY`，不是产品
sysfs/kernel collector、签名 HostSnapshot publisher、外部 CAS 或 target-Qman adapter。没有目标
repository mapping、E3/E4 和 CaseCompletionRecord，故 C00-C03、R03/R29/R38、G1 与 release
状态均不变。

### 3.13 C00 capture closure 已可执行重放，但仍只是调用方字节前提

`QMAN-E2-C00-HOST-SNAPSHOT-CAPTURE-CLOSURE-001` 把 publication capture 阶段的跨字段规则从
schema/prose 断言推进为 factory-only verifier：

- capture batch、freshness policy、DeviceRecord artifact 与 provider raw/semantic envelope 都保留
  exact canonical bytes、schema state 和 domain-separated digest。V2 algorithm identity 固定
  capability-policy、publication-trace、identity-v1、portable-entities、portable-hash-subjects 五份
  有序 transitive schema digest 与十个 validation stage；替代 schema 验证出的 policy 不能混入当前
  closure；
- base64 padding、artifact/decoded bytes、nodes/depth/count、mandatory selectors、provider facts 和
  dependency edges 均有调用方只能收紧的硬上限；shape/count/budget 先于 schema walk，canonical
  uniqueness、mandatory freshness 与 dependency reciprocity 采用索引，避免二次/三次全表扫描；
- candidate DeviceRecord set 逐项重放 V3 hash、identity、PCI、generation、capture interval、顺序、
  唯一性、引用完整性、IOMMU 与 physical-function reciprocity。provider 集和非空 coverage 只能从
  record provenance 推导，完整 host 的 PCI-specific UID/BDF binding 必须形成精确双射；
- raw envelope 独立保留精确 256-byte conventional config 或 closed failure；semantic envelope
  独立保留 normalized PCI structure/FLR。PCI 行必须从 raw bytes 重新解析并与 semantic facts 和
  DeviceRecord 同源相等；generic provider 行只能证明 raw/semantic byte equality，仍明确等待
  target-commit decoder/build attestation；
- verifier 重算 topology、provider 与 no-change projection，校验 capability policy 在 capture 时刻
  自哈希/有效，并按整数微秒检查 mandatory fact presence 与 freshness。nonsemantic raw 变化会推进
  evidence/record/batch hash，但不伪造 topology change；Header Type 或 FLR 变化必须推进语义投影；
- candidate set 只证明每条 `deviceGeneration == candidateSnapshotEpoch` 且共享一个
  `candidateResourceVersion`；两坐标仍是 caller-stamped，必须由 product repository 从 current
  HostAuthority 派生并 CAS。freshness 只使用 caller-supplied `captureCompletedAt`，不等于 trusted
  transaction `evaluatedAt`；
- replay receipt 固定为 `COMPONENT_CALLER_SUPPLIED_CAPTURE_BYTES_ONLY`、
  `COMPONENT_PREMISE_ONLY`、`productAuthorized=false`，并保留 target decoder/build、
  collector/publisher、trusted publication evaluation time、repository、capability-policy authority
  CAS、外部 rollback、independent visibility 和 target mapping/build/runner 八类 blocker。

capture verifier 的正向与对抗矩阵为 34 passed，root publication contract 为 14 passed；
本 checkpoint 的固定源码 portable core 全量为 414 passed、305 subtests。机器记录见
[`qman-c00-host-snapshot-capture-closure-20260730-summary.json`](../evidence/qman-c00-host-snapshot-capture-closure-20260730-summary.json)。

这条 capture 记录自身没有验证五个 publication decision、historical/current trust lineage、
operation envelopes、四类 authority transition、PREPARED/COMMITTED rollback、`N+6` mutation DAG、
audit/outbox/commit、独立可见性、delivery gate 或 final trace digest。后续 component stage 已结构
绑定 capability/freshness policy authority 与 CAS expectation，但真实产品 CAS 仍未证明。full
publication 与 inventory receipt 的共同硬上限现已统一为 4,096，不再存在 65,536/4,096 合同分叉。
candidate epoch/resourceVersion 仍需从 repository-current HostAuthority 派生并 CAS；caller
capture-completion time 仍需由 trusted transaction evaluation time 替代。因此 C00-C03、
R03/R29/R38、G1-G6 与 release 状态均不变。

### 3.14 C00 publication decision、rollback 与 mutation 已闭合字节关系，尚未证明产品事务

`QMAN-E2-C00-HOST-SNAPSHOT-PUBLICATION-CLOSURE-001` 在 capture closure 之后增加三个
factory-only stage：

- decision 从 exact HostAuthority、全局 AvailabilityAuthority、capability/freshness policy
  authority、current inventory、predecessor anchor/freshness、zero-unresolved preflight 和
  structural SERIALIZABLE-read receipt 重算四 authority expectation，只从 retained facts 派生
  `GENESIS`、`INCARNATION_GENESIS`、`SUCCESSOR`、`REFRESH`、`NO_CHANGE`。preflight root
  signature 不得晚于 `beganAt`；predecessor/preflight nonce 必须分离；新 incarnation 的
  hostEpoch/agentGeneration 分别不得回退且至少一项严格推进；
- rollback 把 publication/commit-time trust 与 recovery-time live trust 分开。前者在
  `beganAt` 验证 committed after inventory，后者在 recovery `verifiedAt` 验证 finalized
  anchor/freshness；两者必须保持同 root、同 key-ring/anchor namespace、exact key-ring history
  prefix 和单调 trust-anchor version。这样旧 committed snapshot 无需重签即可跨合法 ring
  `sequence 1→2` 恢复，同时拒绝替换 root/ring/anchor-authority namespace、history fork 和
  anchor rollback。两阶段还必须匹配 adapter 独立配置的 trust-anchor path，序列化 context
  分别固定 freshness receipt digest、`verifiedAt`、expiry 与 path；`NO_CHANGE` 复用 exact
  retained current inventory；
- mutation 消费 exact caller-supplied repository transaction 与 Availability/audit/pending-outbox/
  durable-commit rows，生成一个 DeviceRecord INSERT/record 加六个固定行的 `N+6` mutation set，
  重算五种 projection、无环 fixed point、DeviceRecord-set digest、四 authority resolved vector、
  payload/audit/outbox/commit self-digest；`NO_CHANGE` 四个 after artifact 必须全空且零写。完整
  CAS result 进入 context digest 并在 replay 时逐字节固定。

这些 stage 的无公开构造器 context 均固定 `productAuthorized=false`。它们没有认证 operation
request/result schema/envelope，也没有产品 repository port、可信 commit clock、真实
SERIALIZABLE/CAS receipt、atomic visibility probe、trust authority direct path/nonce transport、
post-anchor delivery witness 或 target Qman mapping/build/runner。因此该记录只增加 C00/R38
的 E2 component 前提，
不关闭 Case/Risk，不推进 G1，也不构成 VMware 私有代码还原或产品行为声明。

### 3.15 QEMU Correctable AER gate 与 root sequence 只固定 reference oracle

`QMAN-E3-AER-QEMU-REFERENCE-001` 使用 stock QEMU 11.0.2 的公开
`pcie_aer_inject_error` HMP 路径和 QTest 配置空间读写，在无 Guest 的受控拓扑中执行
8 个 Correctable bit 与全部 8 个 E/M/R tuple：

- E=Endpoint CERE，M=当前 Correctable bit 的 mask，R=Root COR_EN；Root path 的其他门固定打开。
- 64/64 均满足 Endpoint CES/CED deposition；只有 E=1、M=0 的 `g100/g101` 把
  Root `COR_RCV` 和 Source 沉积到 Root Port。
- QEMU 公开源码显示 R 控制 Root notification eligibility，而不是已经发生的 Root status
  deposition；因此 `g100/g101` 的 Root status 相同不是“R 无效”。
- raw result 位于
  `E:/Code/PCI/_artifacts/vmware-directpath-runs/20260723-qemu11-aer-emr-allbits-v1/result.json`，
  SHA-256=`40880169d5a4deaf01019af7d0e4618886464256cd5513f1e6d06be14cff52a4`。

该条目只有 `REFERENCE_ONLY` 语义：它固定 QEMU oracle，不证明 ESXi 的 service/IRQ，也不证明
Qman 已实现 config filter、host service、审计、clear/reset 或 recovery。ESXi
`virtio/controlled-route` 的 PassthruIdle Receiver 8/8 和 Active
visible-header/raw-CES/no-event 都是 VMware observation，不能转授给这条 Qman evidence；
本次也没有关闭任何产品 Case/Risk。机器索引
[`qman-evidence-index.json`](../contracts/qman-evidence-index.json) 只把 QEMU 64/64 登记为
`REFERENCE_ONLY`，对应 result 是
[`qman-qemu-aer-emr-20260723-summary.json`](../evidence/qman-qemu-aer-emr-20260723-summary.json)。

`QMAN-E3-AER-QEMU-ROOT-SEQUENCE-001` 在相同 public-model topology 上补充了四个
root-state sequence，每项三次 fresh-process：

- 首次 B0 产生 Endpoint CES=`0x1`、Root Status=`0x1`，重复 B0 后 Root Status=`0x3`；
- Endpoint CES/CED 与 Root Correctable Status 的 W1C 互不代清；
- B0 后接 B1 得到 Endpoint CES=`0x41` 与 Root Status=`0x3`；
- CES、CED、Root Status 分别清零后再注入，重新得到 first-message 的 Root Status=`0x1`；
- 该 QEMU build 在 Root Status W1C 后保留 Correctable Source=`0x0100`，oracle 不把
  Source 清零当作通用 PCIe/ESXi 规则。

正式结果 12/12 `MATCH`，聚合 SHA-256 为
`59839df23f9711162f4d8548b7e258e355957bda23348f6acd727eb219decb5b`；机器记录见
[`qman-qemu-aer-root-sequence-20260726-summary.json`](../evidence/qman-qemu-aer-root-sequence-20260726-summary.json)。
它仍是 `REFERENCE_ONLY`，不关闭 ESXi M26、Qman M06、R13 或任何产品状态。

`QMAN-E2-AER-VMWARE-G101-PARITY-001` 进一步把 canonical V17 O4 与 V19 O0 提升出的
frozen observed profile 接入 `qman-directpath-core`。纯模拟器没有 owner 输入，也不校验
runtime owner envelope；conformance test 将同一条 pure-model trace 分别与 O0 和 O4
artifact branch 比较。`first-multiple`、`independent-w1c`、`bit-or` 和 `rearm` 的实际
transition 由单一 dispatcher 执行并记录，checkpoint 在执行当下绑定 action position。
2 个 branch × 每 branch 8 个 checkpoint × 8 个字段共 128 项与冻结 profile 逐字段一致，
Source 仅在 `COR_RCV` 为 1 时赋予 Requester 语义；51 个定向 test 与 73 个 subtest 通过。
机器记录见
[`qman-aer-vmware-g101-parity-20260730-summary.json`](../evidence/qman-aer-vmware-g101-parity-20260730-summary.json)。
这是 E2 `COMPONENT_ONLY` 证据；它不是 guest-write authorization，不证明 VMware 私有
owner 机制，也不关闭 M06/R13。

公开边界：

- [Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/)：规定
  DirectPath PCI error 由 ESXi 处理、而不是作为错误交给 guest；没有公开
  notification/service/recovery 实现，也不规定所有 guest profile 的
  capability/header/raw status 都必须隐藏。
- [Broadcom KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)：
  公开 `pcipDisablePciErrReporting` 的配置含义，不公开 E/M/R 实现。
- [Linux PCIe AER Driver Guide](https://docs.kernel.org/PCI/pcieaer-howto.html)：通用 AER
  status、Requester ID 与 notification 模型。
- [QEMU 11.0.2 `pcie_aer.c`](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)：
  本条 reference oracle 的源码依据，不是 VMware 实现证据。

## 4. 可复现入口

实验复用了本地历史任务中沉淀的 WSL/QEMU 环境；可提交、可复现的权威环境说明为
[`vmware-esxi8-lab/README.md`](../vmware-esxi8-lab/README.md)。QEMU 11 必须显式指定，不能
误用 PATH 中的 QEMU 6.2。

```powershell
# QMP/BDF control reference
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_qemu_control_boundary.py `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-qmp

# Qman default-deny QMP component
wsl -d Ubuntu-22.04 -- env `
  QMAN_QEMU_BINARY=/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  bash /mnt/e/Code/PCI/github-export/qman-lab/run_qmp_gate.sh `
  /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-qmp-gate

# VFIO no-IOMMU / IOMMU provider A/B
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_vfio_noiommu_split.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-vfio

# Qman per-device VFIO/IOMMUFD provider component
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_qman_vfio_provider.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-vfio-provider

# Qman Static lease/FSM subprocess fault component
# Live SQLite state stays under WSL-native /root; --output-dir may be retained on DrvFS.
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_static_lease_faults.py `
  --state-root /root/.qman-static-lease-fault-state `
  --output-dir /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-static-lease-fault

# Qman authoritative snapshot publish/CAS/replay fault component
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_authoritative_snapshot_faults.py `
  --output-dir /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-authoritative-snapshot-fault

# Qman lease -> fresh raw VFIO fd -> stock-QEMU -> receipt/quarantine component
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_qman_static_launch.py `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-static-launch `
  --timeout 600

# QEMU 11 + OVMF dual-64GiB BAR
wsl -d Ubuntu-22.04 -- env `
  WORKDIR=/root/pci-evidence/RUN-ID-mmio `
  QEMU_BIN=/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  MACHINE=pc-q35-11.0 `
  bash /mnt/e/Code/PCI/github-export/qemu-q35-ovmf-dual-64g-validate.sh

# QEMU 11 Correctable AER: 8 bits x 8 E/M/R tuples
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_aer_correctable_matrix.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID-qemu-aer-emr-allbits

# QEMU 11 Correctable AER: first/multiple, independent W1C, OR, re-arm x3
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_aer_root_sequence.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID-qemu-aer-root-sequence `
  --gate g101 --repeat 3

# Qman reference model
wsl -d Ubuntu-22.04 -- bash `
  /mnt/e/Code/PCI/github-export/qman-lab/run_reference_model_tests.sh `
  /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-model/unittest.log

# C20 bounded capability closure
wsl -d Ubuntu-22.04 -- bash `
  /mnt/e/Code/PCI/github-export/qman-lab/run_c20_capability_closure.sh `
  /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-c20/unittest.log
```

原始 Unix socket 必须放在 WSL 原生文件系统。把 monitor socket 放在 `/mnt/e` 会返回
`Operation not supported`；该 preflight failure 不能作为 QEMU/MMIO 结论。

## 5. 下一批 Qman 证据

按依赖顺序继续：

1. G0 合同已冻结，当前 G1 `IN_PROGRESS`；把现有带 boot identity、epoch、full-topology
   hash 的 bounded snapshot component 收敛为 G1 产品 publisher，补齐生产 trust root、key lifecycle、
   外部单调防回滚锚、power-loss durability 与唯一 product controller 接线。
2. 未来 cdev backend 的 stock-QEMU fd-only bind/attach 与 fail-closed envelope 前提已可执行；
   当前产品优先实现 Legacy exact TYPE1 profile、`AUTHORIZED_DEVICE_PATH` sandbox 与
   post-spawn proc-fd/QMP receipt，然后加入真实 reset/driver restore、pidfd owner 和独立
   DMA/IRQ/clean-state observer，执行产品级 S03/S04/S05/F00。
3. 将已验证的 QMP component 接入 production launcher/controller/durable lease/generation/VFIO，
   并执行覆盖 API、CLI、storage、alternate monitor、fd injection、并发和 replay 的完整 S15/F09
   产品 bypass matrix。
4. E4：真实 NIC/GPU/HBA 上的 IOMMU/IR、ACS/RID alias、reset/state、INTx、P2P、RMRR、
   SR-IOV、errata 和 workload qualification。

Dynamic solver 完成后再推进双在线主机的计划性 cold relocation：必须有 global CAS、
source clean-release receipt、target re-solve/attach 和失联不接管负向门。BMC/power fencing、
host-failure 自动 HA restart 不在 V3 范围，不再作为 Qman 证据缺口。
