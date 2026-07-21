# PCI BAR/MMIO 与 passthrough capable 参考实现

这个目录把本仓库的 VMware/QEMU 黑盒结论实现为可执行的 host-side reference model：

```text
config/sysfs inventory
        |
        +--> BAR size/type requirements --> transactional MMIO allocator
        |
        +--> IOMMU/ACS/reset/topology --> eligible
                    + dependency owners --> available
                    + MMIO/RMRR admission --> attachable
        |
        +--> desired/effective owner + quiesce --> activation disposition
```

实现只依赖 Python 3.10+ 标准库。它适合放在 libvirt 上层、自有 host service 或
launcher preflight 中；不是 Linux PCI core、OVMF 或 QEMU firmware allocator 的替代品。

## 1. BAR 探测

[`bar_probe.py`](pci_resource_model/bar_probe.py) 实现标准 Type-0/Type-1 BAR sizing：

1. 读取 Header Type；Type-0 探测 6 个 slot，Type-1 探测 2 个 slot。
2. 保存全部 BAR dword 和 `PCI_COMMAND`。
3. 临时清除 I/O decode、memory decode 和 bus master。
4. 对 BAR 写全 1并读回 mask；64 位 BAR原子处理低/高两个 dword。
5. 使用 mask 最低有效位计算 power-of-two decode size。
6. 在所有成功/异常路径恢复全部 BAR和原始 `PCI_COMMAND`；恢复失败单独报
   `CONFIG_RESTORE_FAILED`。

`probe_standard_bars()` 使用抽象 `ConfigSpace` protocol，便于接到 hypervisor 配置空间
后端。它会改写配置空间，只能在调用方已独占、解绑并 quiesce 设备后使用。
`LinuxSysfsConfigSpace` 和 `probe_unbound_linux_device()` 提供实际 Linux `pread/pwrite`
后端；后者要求 `acknowledge_live_writes=True`、root 且设备没有绑定 driver，并且故意不
暴露为普通 CLI 子命令。调用方仍必须持有防止 driver/VM 并发 claim 的外部 device lease。

日常 inventory 不走危险写探测。[`linux_sysfs.py`](pci_resource_model/linux_sysfs.py)
只读 Linux 已探测好的 `/sys/bus/pci/devices/*/{config,resource}`，同时收集 driver、
IOMMU group、reset method、父拓扑和原始 ACS capability/control。

## 2. MMIO allocator

[`allocator.py`](pci_resource_model/allocator.py) 接受半开区间 `START:END`：

- 所有 BAR按自身 size 对齐。
- 32 位和 below-1M BAR先分配，保护不可替代的低地址空间。
- 64 位 BAR默认 demand-driven：低窗能放则低置，否则进入高窗。
- `--prefer-high` 或 `--force-high` 可以改变 64 位 BAR策略。
- reserved range 会先从 free list 中扣除。
- 任一 BAR失败时返回空 allocation set，不暴露半提交布局。
- high BAR必须能由一个连续 root aperture 覆盖。
- high aperture 默认按最大 BAR对齐并向上取 power-of-two。

成功结果同时生成：

```text
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=N_MB
-global q35-pcihost.pci-hole64-size=NG
```

没有 high BAR时两项均为 0。SeaBIOS 模式只生成 host bridge 属性，因为 SeaBIOS 不读取
OVMF fw_cfg。

字段语义必须分开：`requiredHighSpanBytes` 是 planner 求出的连续 high demand，
`qemuPciHole64FloorBytes` 是渲染到 QEMU 的最小 root-window 跨度。兼容字段
`highApertureBytes` 当前与二者取相同值，但不能解释为 QEMU hard cap。QEMU 会用实际已分配
BAR 的最高 end 与 `runtimeStart + floor` 中更大的一个作为 runtime end。
`project_qemu_hole64_window()` 实现并测试了这一公开行为：两块 64GiB BAR 位于
`[64GiB,192GiB)` 时，32GiB 或 0 floor 都不会缩小实际 128GiB window；没有已分配 BAR 时，
32GiB floor 才单独表现为 `[fallbackStart,fallbackStart+32GiB)`。

SeaBIOS 1.15 能按探测到的 BAR demand 自动生成比 floor 更大的窗口；OVMF 默认对同一双
64GiB 用例没有分配 BAR，显式 128GiB fw_cfg + floor 后才通过。因此 renderer 仍为 production
profile 显式输出已求解的 floor，并要求启动后核对 QOM start/end、bridge windows 和 BAR。
复现实验见 [`../qemu-q35-firmware-dual-64g-results.md`](../qemu-q35-firmware-dual-64g-results.md)。

## 3. capable 模型

[`capability.py`](pci_resource_model/capability.py) 不返回含糊的单一布尔值：

```text
eligible   = per-device IOMMU-backed DMA + interrupt-remap + assignable Type-0 role
           + fixed-point dependency action/reset closure + exact action qualification
           + accepted reset path + trustworthy isolation
           + no platform reservation or errata deny

available  = eligible + complete dependency lease is present and free
           + no dependency member is host-reserved

attachable = available + BAR allocation + RMRR admission
```

关键策略：

- PCI class code 只作为元数据，不做 CPU/memory/bridge class blanket blacklist。
- Type-1 或实际承载 subordinate bus 的 function 是 fabric node，不作为 payload。
- `host.unsafeNoIommuModeEnabled=true` 只表示内核为宿主可信 DPDK 允许 unsafe VFIO；它产生
  warning，不会否决同一 host 上有真实 IOMMU backing 的 VM 设备。旧输入字段
  `host.noIommuMode` 仍可读取，但新 inventory 只输出语义明确的新字段。
- 每个 VM payload 必须是 `dmaIsolationMode=iommu`；`no-iommu` 与 `unknown` 均硬拒绝。
  scanner 会把 `/dev/vfio/noiommu-$GROUP` 标为反例，最终生产 proof 仍需 host agent 成功
  使用 VFIO cdev/IOMMUFD，或 legacy TYPE1/TYPE1v2 backend。
- 宿主 DPDK BDF 必须由编排配置覆盖 `hostReservation=dataplane-dpdk`。它不改写稳定的硬件
  `eligible` 事实，但会让完整 dependency bundle 的 `available=false`，因此永不进入
  Static/Dynamic VM candidate pool；sysfs 无法仅凭 driver 名称可靠推断业务 owner。
- FLR 是 function reset；bus reset 必须携带完整 affected set。
- sysfs 父拓扑只能估算 bus reset domain，默认报 `RESET_DOMAIN_UNVERIFIED`。生产路径应接
  `VFIO_DEVICE_GET_PCI_HOT_RESET_INFO` 或资格测试保存的 affected set。
- 未启用 ACS override 时，平台原子租用完整 stock-kernel IOMMU group。
- 启用 override 后，kernel group 只作为 VFIO 操作单位。默认策略允许 mandatory override，
  但必须从可信 provenance 重建 `physicalIsolationDomain` 并整域租用；可用
  `--deny-acs-override` 切回全拒绝策略。
- dependency 中任何 BDF 未进入 inventory 时，报 `DEPENDENCY_NOT_IN_INVENTORY`，不会
  默认为空闲，也不会把目标先标成 capable。
- capability 查询先对 dependency action 与 reset affected set 求 owner-independent 固定点。
  被提升为 `assign-to-guest` 的 dependency 必须拥有自己的 reset contract；action 为
  `unknown`、reset 缺失或 action qualification 缺失分别以
  `DEPENDENCY_ACTION_UNKNOWN`、`RESET_NOT_SUPPORTED`、`QUALIFICATION_MISSING` fail closed。
- inventory 中的 `dependencyAction` 是 dependency 被闭包拉入时的保守 action fact，
  `qualifiedActions` 是已解析的精确 member/action qualification；scanner 无法自行证明二者，
  因而保持 `unknown`/空集合，必须由可信 policy/qualification snapshot 补齐。
- inventory schema 已升级为 v2；v1 不会被静默按新语义解释，而是要求显式迁移。v2 的 host
  snapshot 必须携带 `hostId/kernelBootId/inventoryEpoch/topologyHash`，action、qualification、
  reset contract 必须各自携带 source、rule、subject hash 与 evidence hash。缺失、来源不可信、
  未经外部 verifier 认证、identity/generation 漂移或任一 fact 的 epoch/topology 不一致，均在
  capable gate fail closed。普通 JSON 不能靠自报 64 位十六进制 hash 进入可信边界。
- dependency closure 同时受 `maxDependencyMembers/maxDependencyEdges` 约束，并在加入每个 member/edge
  前增量检查，拒绝结果也不会携带超大依赖全集；初始 payload 被其他
  dependency edge 再次引用时仍执行 action merge，不能跳过 `QUIESCE_HOST` 等冲突。
- scanner 对 IOMMU、physical isolation、reset、multifunction 和 platform dependency 求传递闭包，
  生成保守的 `ownerActivationGroup`/`exclusiveAttachGroup`；外部 inventory 缺 group 时
  `attachable=false`，不会默认为 singleton。
- BAR/MMIO 失败只让 `attachable=false`，不会篡改前面的静态 `eligible` 结论。
- 结果输出 `snapshotHash`、`bundleHash`、`capabilityHash`、`policyHash` 与 `decisionHash`。
  snapshot/bundle/capability hash 不读取
  lease owner；同一闭包的 free/busy A/B 只改变 `available` 及其下游 `attachable`，不会改变
  capable、member action、selected reset 或前四个 hash。`decisionHash` 单独绑定 lease/driver、
  exact attach/activation group、
  MMIO 输入、allocator policy/result 与最终 available/attachable，避免用 capability hash 冒充
  一次可执行 attach decision。hash 只包含 reason code/details，不包含可本地化 message。
- evaluator 仍是纯函数，不执行 bind、reset 或 lease write。C20 fixture 会重复查询并验证
  inventory、driver、reset fact 与 lease/counter snapshot 完全不变。

## 4. Host owner activation

[`activation.py`](pci_resource_model/activation.py) 纯函数从显式 BDF request 扩展完整
`ownerActivationGroup` 后规划宿主 owner 切换，不执行 unbind、reset、lease 或 reboot；
`exclusiveAttachGroup`、reset domain 和 physical isolation domain 分别保存：
每个 `ActivationMember` 必须显式携带 group ID 和 completeness proof；unknown 不得退化为 singleton。

```text
ALREADY_ACTIVE   effective owner 已全部匹配
LIVE_APPLY       当前可 quiesce，可在 durable bundle lease 后执行 live transition
REBOOT_REQUIRED  request mode 显式允许 deferred，且完整 owner group 有精确 early-boot claim
DENIED           persistent host use、identity/owner/action 未知、host-critical、foreign lease 或无 boot claim
```

planner 故意不接收 FLR bit、class code 或 BAR size。它们分别属于 reset safety、payload role 和
resource admission，不能证明 native driver 当前可安全解绑。`REBOOT_REQUIRED` 也不是自动重启
指令；controller 只有在显式 maintenance workflow 已持久化 exact identity/path/owner-group boot
claim 后才可接受该结果。Capability evaluator 默认拒绝一个 VM payload 中重复的
`exclusiveAttachGroup`；实验性放宽必须通过
`--qualified-shared-attach-group <exact-group-id>` 精确列出，不存在全局 allow 开关。运行中 guest
PCI hotplug 永久不在此模型范围内。

## 5. 有界 VFIO 与 Static components

[`vfio_provider.py`](pci_resource_model/vfio_provider.py) 是独立的逐设备 provider gate：它对
no-IOMMU node 稳定拒绝，并可在 lab/component 模式真实执行 VFIO cdev + IOMMUFD bind、IOAS
attach 与逆序 cleanup。它不是产品 launcher；CLI probe 完成后会关闭 fd，pre-attached session
也不能直接交给 stock QEMU。

[`authoritative_snapshot.py`](pci_resource_model/authoritative_snapshot.py) 提供 host-local、
component 范围的权威快照发布与 launch authorization。它执行两次完整 host capture，并要求
host/boot identity、设备数量、full-host safety topology 与所有可分组设备的精确 launch facts 在两次采集间
稳定；随后在同一个 SQLite 事务中分配单调 `inventoryEpoch`、写入 canonical payload、
`topologyHash`、HMAC envelope 和 current record。数据库是 authority，导出的 JSON 只是 cache/evidence。
持久层使用 WAL + `synchronous=FULL`，校验固定 schema、store instance、文件系统 provenance 和
数据库文件 identity；[`../contracts/authoritative-snapshot.schema.json`](../contracts/authoritative-snapshot.schema.json)
给出跨组件 envelope contract。

发布成功时，store 把执行双扫描的同一个 capture provider 封存为
`COMPONENT_CAPTURE_PROVIDER` capability，并将其 binding hash 写入 launch authorization；后续
`PRE_OPEN/POST_OPEN/PRE_SPAWN` 只能调用该 capability，launch caller 不能替换采集函数。
`AuthoritativeSnapshotStore.authorize_launch()` 签发不可自行构造、不可复制、不可 pickle 的 sealed
authorization，并在 context 生命周期内持有 `BEGIN IMMEDIATE`。进入 context 时，它要求 snapshot
仍是 current、boot ID 仍有效、请求恰好覆盖完整且互相一致的 IOMMU group；退出 context 后
authorization 立即失效。该读锁的目的，是防止最终校验与 QEMU spawn 之间被并发 publisher 切换
current snapshot，而不是把任意较旧 snapshot 重新解释为可启动依据。

component launch 的强制顺序是：

```text
stable full-host capture x2
  -> atomic signed snapshot publish
  -> sealed snapshot authorization + capture provider capability (outer lock)
  -> lease authorization
  -> PRE_OPEN full-host revalidation
  -> open complete VFIO group with fresh fds
  -> POST_OPEN full-host revalidation
  -> authoritative VFIO result -> QEMU fd/plan binding
  -> PRE_SPAWN revalidation at validate_before_spawn()
  -> PRE_SPAWN revalidation again at popen_kwargs()
  -> Popen while snapshot/lease authorizations remain active
```

因此，QEMU 适配器不是从 caller JSON 重建可信事实：
`open_authorized_vfio_launch_bundle()` 只从 sealed authorization 派生请求和完整 group，且 QEMU plan
中的 BDF 集合必须等于 authorization 的 `authorized_bdfs` 并覆盖每个 group member，
`device_binding_from_authorized_vfio_launch_result()` 要求 live、production-provenance 的 VFIO result，
并把 snapshot authority/store/key、boot/epoch、topology、identity/group/device generation 与 fd/plan hash
一起绑定。任一阶段发现 current snapshot、完整拓扑、launch facts、lease scope 或 generation 漂移，都会
在 spawn 前 fail closed；VFIO open/revalidation 的失败路径会按整个 bundle 逆序关闭已打开句柄。锁顺序
固定为 snapshot -> lease -> launch envelope，避免把持有关系倒置成另一条隐式 authority。

[`vfio_launch_handles.py`](pci_resource_model/vfio_launch_handles.py) 在 spawn 前重新采集 identity、
完整 IOMMU group 与字符设备 inode，打开 fresh raw cdev/IOMMUFD，并在全部 fd 打开后再次复核。
`open_vfio_launch_bundle()` 要求每个涉及的 IOMMU group 成员完整，使用一个共享 IOMMUFD，并把
全组 fd 作为单一 close unit；[`qemu_launch_contract.py`](pci_resource_model/qemu_launch_contract.py)
只渲染 fd-only stock-QEMU argv，不接收预绑定 session 或 caller 拼接的额外参数。

[`static_lease.py`](pci_resource_model/static_lease.py) 是 schema-v4 host-local SQLite lease/CAS/FSM
component。数据库固定 `local_host_id` 与单一 `trusted_authority_id`，完整 bundle、member claim、
VM/device generation、transaction 和 journal 使用 `BEGIN IMMEDIATE` 原子更新；只有上层声明
`cleanup_verified=True` 并提供下一代 generation/authority epoch 时才释放，否则保留 whole-bundle
quarantine。默认只接受 allowlist 中的本地文件系统；`/mnt/e`/9p、tmpfs、overlay、FUSE、NFS/CIFS
等不作为 normal durable boundary。

[`static_launch_envelope.py`](pci_resource_model/static_launch_envelope.py) 是 schema-v4 的 launch
ordering component：它把 envelope 数据库、权威 lease store、进程 identity、fd/plan hash、QMP
与 DMA 两个相互独立的签名 observer 固定在同一状态机中。只有 QMP 与 DMA receipt 都验证并持久化
commit intent 后才能确认 `ATTACHED`；任一证据缺失只能清理或保留 claims 后 quarantine。

这些 component 已能组成可执行的单机 Static launch 前提，并补上了 component-level snapshot
publisher -> VFIO -> QEMU 的可验证链路，但仍不是 production controller 或 production authority；
还缺生产 key/catalog/rotation、外部 rollback anchor、真实 reset/driver restore、独立 DMA/IRQ
clean-state observer、pidfd owner、产品入口接线和多主机 fencing。故它们不表示 Feature/Milestone
完成，也不能关闭 C10/C15/C16/C18/C21、S03/S04/S05/F00 或任何 Risk。

## 6. CLI

只读扫描当前 Linux host：

```bash
PYTHONPATH=pci-resource-model \
python3 -m pci_resource_model scan \
  --interrupt-remapping true \
  --output inventory.json
```

scanner 输出 schema v2、host/boot identity 与 topology hash，但故意不伪造 monotonic
`inventoryEpoch`，也不签发 action/qualification/reset evidence。publisher/qualification provider
补齐这些事实并原子发布前，`capable` 会以 `SNAPSHOT_IDENTITY_INCOMPLETE` 或 provenance reason
拒绝；不能把裸 sysfs scan 当成生产 capability snapshot。

必须启用 ACS override 的 host 应使用
[`../kernel-patches/`](../kernel-patches/README.md) 中的 provenance patch。scanner 会读取
`acs_native_isolation`、`acs_effective_isolation`、`acs_override_source`，把 patched
`kernelIommuGroup` 与保守重建的 `physicalIsolationDomain` 同时写入 inventory。接口缺失或
任一 function 证据不自洽时保持 fail-closed，不会退回相信拆分后的 group。

对样例中的 2 GiB BAR做 demand-driven placement：

```bash
PYTHONPATH=pci-resource-model \
python3 -m pci_resource_model allocate \
  --inventory pci-resource-model/examples/two-gib-endpoint.json \
  --device 0000:65:00.0 \
  --mmio32 0x80000000:0xc0000000 \
  --mmio64 0x100000000:0x200000000
```

1 GiB 低窗放不下 2 GiB BAR，因此结果为 high placement，并生成
`X-PciMmio64Mb=2048` 与 `pci-hole64-size=2G`。

运行完整 capable preflight：

```bash
PYTHONPATH=pci-resource-model \
python3 -m pci_resource_model capable \
  --inventory pci-resource-model/examples/two-gib-endpoint.json \
  --target 0000:65:00.0 \
  --mmio32 0x80000000:0xc0000000 \
  --mmio64 0x100000000:0x200000000 \
  --accept-reference-fixture-evidence
```

mandatory override 的整域租用样例：

```bash
PYTHONPATH=pci-resource-model \
python3 -m pci_resource_model capable \
  --inventory pci-resource-model/examples/mandatory-acs-override.json \
  --target 0000:01:00.0 \
  --mmio32 0x80000000:0xc0000000 \
  --accept-reference-fixture-evidence
```

`--accept-reference-fixture-evidence` 只用于本仓库的确定性 E2 样例。它验证 envelope 与字段绑定，
不提供签名、MAC 或 trust store，绝不能进入 Qman 产品启动路径。生产调用方必须注入真实的
`FactEvidenceVerifier`，验证已留存的 policy/qualification/reset evidence；不提供 verifier 时默认拒绝。

该例的 patched groups 都是 singleton，但输出为 `verdict=conditional`，且
`requiredLease` 包含 non-isolating root port 与两个 endpoint。使用
`--deny-acs-override` 可验证全拒绝策略。

所有地址范围的 `END` 都是 exclusive。对真实 QEMU VM，应从 machine/firmware 已保留的
PCI root windows 构造这些输入，而不是把示例地址硬编码进生产。

## 7. 测试

```bash
PYTHONPATH=pci-resource-model \
python3 -m unittest discover -v -s pci-resource-model/tests
```

测试覆盖：

- 32/64 位 BAR mask、Type-1 slot 数、I/O BAR、异常恢复。
- low/high placement、32 位优先、reserved range、对齐和事务失败。
- Type-0 class A/B、Type-1+FLR 负例、IOMMU/reset/ACS override/dependency。
- `eligible=true` 但 dependency busy 或 MMIO admission 失败的分层结果。
- C20 四格：dependency qualified/free、同 bundle busy、dependency reset missing、dependency
  action unknown；同时覆盖 qualification missing、初始 payload action conflict、closure 上限、
  schema-v2 round-trip、identity/provenance/stale 反例、golden/扰动 hash、decision hash 与查询零副作用。
- Linux resource、PCIe type、ACS extended capability 与 mandatory-override shadow domain。
- desired/effective owner 分离、request-to-owner-group expansion、idle/transient/persistent busy A/B、
  shared attach collision、stale identity、foreign lease、host-critical、early-boot claim 和
  disable/rebind activation。
- Static schema-v4 host/authority/store-instance scope、bundle/member/VM/device generation CAS、同 epoch ABA、并发
  winner、commit 前崩溃原子性、精确 replay、reconcile、whole-bundle quarantine 和 filesystem gate。
- authoritative snapshot 的双采集稳定性、完整 host/boot/topology/launch-fact hash、单调 epoch 与 CAS、
  HMAC/envelope/row 交叉校验、重复 JSON key/临时 schema object/数据库篡改拒绝、发布中途崩溃回滚、
  并发 publisher 唯一 winner、boot/minimum-epoch/stale snapshot gate、导出 cache 原子替换，以及 sealed
  authorization 的不可复制/不可 pickle/context 失效语义。
- raw launch handle 的 before/open/after identity/group/node gate、完整 group 共享 IOMMUFD、原子逆序
  cleanup、production provenance、PRE_OPEN/POST_OPEN/PRE_SPAWN 全量复核；同时覆盖 authoritative
  VFIO result 到 QEMU admission/fd/plan hash 的绑定、snapshot/lease scope 或 generation 漂移拒绝，以及
  envelope 的 lease/store/process/receipt/commit ordering。

完整测试当前收集 293 项；2026-07-21 Windows 为 288 passed / 5 platform skips，WSL 为 293 passed。
平台相关用例在运行条件不满足时保持显式 skip。真实
subprocess/`os._exit`/`SIGKILL` fault runner 位于
[`../qman-lab/test_static_lease_faults.py`](../qman-lab/test_static_lease_faults.py)；它在 WSL 原生
文件系统创建 live DB，并明确把 bind/reset/QEMU 标为模拟阶段标签。真实 nested-QEMU component
runner 位于 [`../qman-lab/test_qman_static_launch.py`](../qman-lab/test_qman_static_launch.py)；snapshot
publisher 的真实 subprocess crash/concurrency/tamper runner 位于
[`../qman-lab/test_authoritative_snapshot_faults.py`](../qman-lab/test_authoritative_snapshot_faults.py)。

## 8. 当前边界

- 直接探测只覆盖 standard BAR0-BAR5，不含 ROM、SR-IOV VF BAR和 Resizable BAR支持集合。
- sysfs scanner 不执行 VFIO hot-reset ioctl；override physical domain 依赖定制内核 provenance，
  并采用可能过度合并的保守父拓扑算法。
- `seal_reference_device_facts()` 与 `REFERENCE_FACT_VERIFIER` 只生成、验证确定性的 E2 fixture
  envelope，不验证生产签名，也不能进入 Qman 产品路径；生产 provider 必须从签名
  qualification/policy store 发布 evidence object，并由产品 verifier 验证。
- allocator 计算 root-level aperture demand，不复刻 OVMF 的完整多级 bridge window算法。
- QEMU 参数是启动前需求；启动后仍必须核对 guest BAR、ACPI `_CRS`、IOMMU map 和中断。
- activation 目前只有无副作用 planner；Static component 有独立 durable journal，但 live driver
  transition、exact early-boot claim、可信 cleanup provider 和 boot reconcile 尚未接入 Qman host agent。
- `ComponentHmacAuthenticator` 只证明 payload 对当前配置 component key 的真实性与完整性，明确标记为
  `COMPONENT_AUTHENTICITY_ONLY`；它不是 TPM/HSM-backed production trust root，也没有 production
  key catalog/rotation/revocation。SQLite 内部 epoch 只能发现仍可见的 stale snapshot；缺少外部单调
  anchor 时，任何 earlier-valid 数据库状态回放——包括同 key 下原位/块级恢复或删除最新行——都可能被
  接受，inode/store UUID 不是 anti-rollback 证明；多主机 consensus/fencing 也不在
  该 authority 范围。因此该实现只能提供 component evidence，不能据此宣告产品发布或关闭 Case/Risk。
- 本环境只有 WSL synthetic PCI，可验证只读扫描和算法，不能替代真实设备写全 1 sizing、
  电气 reset 或物理 ACS 验收。
