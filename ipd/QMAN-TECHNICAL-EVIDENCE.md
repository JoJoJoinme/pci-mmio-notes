# Qman 技术证据树与 WSL/QEMU 验证结果

状态：`TECHNICAL EVIDENCE / PRODUCT NOT IMPLEMENTED`
项目 claim：`REFERENCE_AND_QUALIFICATION_MODEL_ONLY`
治理快照：G0 `DONE`；G1 `IN_PROGRESS`；G2-G6 `NOT_STARTED`；Acceptance `101/101` 已分类
（1 `EXECUTABLE` reference、94 `IMPLEMENTATION_BLOCKED`、6 `HARDWARE_BLOCKED`）；C20 的 E2
reference runner 只证明算法，不关闭 PRODUCT Case；R01-R39 全部 `OPEN`
实验日期：`2026-07-21 Asia/Shanghai`
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
| `QMAN-QEMU-CONTROL-001` | E3 | 建机后可通过 QMP 向 QEMU device tree 加入 PCI endpoint（本次在 machine 暂停态）；同 guest BDF 可换 VID:DID；`device_del` reply 后设备仍存在 | TS-F3-01/04、F4-05、F5-05；S01/S15/F09 前提 | Guest 在线热插、Qman QMP ACL 已实现、S15/F09 已通过 |
| `QMAN-E3-QMP-GATE-001` | E3 | 最小 gate 本地处理 capability，只转发五类只读 query；17 类拒绝均未被独立 backend recorder 观察到，PCI tree、QEMU/gate fd 基线不变 | TS-F4-05、F5-05；S15/F09 与 R17/R26/R37 前提 | production launcher/lease/generation/VFIO 或全入口绕过已封堵；S15/F09 与三项 Risk 均未关闭 |
| `QMAN-E3-DMA-PROVIDER-001` | E3 | unsafe=`Y` 时，no-IOMMU 与 IOMMU-backed device 仍呈现不同 provider node | TS-F1-02、F3-03；C21 前提 | 物理 IOMMU/IR/errata、IOMMUFD IOAS attach、DPDK workload |
| `QMAN-E3-VFIO-PROVIDER-GATE-001` | E3 | Qman component 对 no-IOMMU 稳定拒绝；对 cdev 真实执行 IOMMUFD bind、IOAS allocate/attach、身份/完整 group 复核与逆序清理 | TS-F1-02、F3-03；C21 / R27 前提 | 权威产品 snapshot、durable lease、stock-QEMU handoff、物理 E4；C21/R27 均未关闭 |
| `QMAN-E3-STATIC-LEASE-FAULT-001` | E3 | WSL 原生 ext4 上 7/7 subprocess/SQLite 故障场景通过：begin/release commit 前硬退出无部分状态，重叠 bundle 双进程仅一胜，未知 cleanup 与 SIGKILL 后 reconcile 保留 whole-bundle quarantine | TS-F3-02/05、F5-03/04；S03/S04/S05/F00 与 R04/R05/R11 前提 | bind/reset/QEMU/cleanup 真实执行、pidfd/DMA/IRQ/owner clean state、产品 Case/Risk；四个 Case 仍 blocked |
| `QMAN-E3-AUTHORITATIVE-SNAPSHOT-FAULT-001` | E3 | host-local SQLite snapshot component 的未提交 epoch 不可见、并发 CAS 单胜与严格递增 epoch 已通过真实 subprocess/并发故障注入；signature/payload/stale/minimum-epoch/boot drift 均 fail closed；删除最新行后 earlier-valid 状态仍可被接受，实验证实外部单调锚是必要边界 | TS-F1-01、F8-02；R04 前提 | G1 产品 publisher、生产 trust root、外部单调防回滚锚、power-loss durability；不关闭 Case/R04/G1 |
| `QMAN-E3-STATIC-LAUNCH-ENVELOPE-001` | E3 | v5 将 sealed capture provider、签名 full-host snapshot、完整 group 授权范围、6 次一致的 live full scan、lease authorization、production-provenance raw cdev/IOMMUFD 与 fd-only stock QEMU 串成一条链；QMP/QOM 看到 realized `vfio-pci`，trace 中 bind、IOAS allocate、attach 均返回 0；无独立 DMA receipt 时不提交 `ATTACHED`，保留 claims 并 quarantine | TS-F1-01、F3-02/03/05、F5-04、F8-02；C21/S05 与 R04/R05/R26/R27 前提 | 该结果只是未来 cdev backend 前提；当前 Legacy path grant/sandbox/receipt、生产 G1 authority/trust/rollback anchor、真实 reset/driver restore、独立 DMA/IRQ observer、pidfd/产品 controller、物理 E4 仍缺；Case/Risk/G1/G2 均未关闭 |
| `QMAN-E3-MMIO-OBSERVED-001` | E3 | QEMU floor 与 OVMF aperture 必须配对；双 64 GiB BAR 默认失败、128 GiB 配对成功 | TS-F4-01/02/04；M23 前提 | Qman observedPlan commit/rollback、物理 BAR qualification |

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
