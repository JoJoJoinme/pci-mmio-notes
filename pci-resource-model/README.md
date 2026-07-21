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

## 5. CLI

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

## 6. 测试

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

## 7. 当前边界

- 直接探测只覆盖 standard BAR0-BAR5，不含 ROM、SR-IOV VF BAR和 Resizable BAR支持集合。
- sysfs scanner 不执行 VFIO hot-reset ioctl；override physical domain 依赖定制内核 provenance，
  并采用可能过度合并的保守父拓扑算法。
- `seal_reference_device_facts()` 与 `REFERENCE_FACT_VERIFIER` 只生成、验证确定性的 E2 fixture
  envelope，不验证生产签名，也不能进入 Qman 产品路径；生产 provider 必须从签名
  qualification/policy store 发布 evidence object，并由产品 verifier 验证。
- allocator 计算 root-level aperture demand，不复刻 OVMF 的完整多级 bridge window算法。
- QEMU 参数是启动前需求；启动后仍必须核对 guest BAR、ACPI `_CRS`、IOMMU map 和中断。
- activation 目前只有无副作用 planner；durable journal、live driver transition、exact early-boot
  claim 和 boot reconcile 属于 Qman host agent 实现，不由本 reference model 执行。
- 本环境只有 WSL synthetic PCI，可验证只读扫描和算法，不能替代真实设备写全 1 sizing、
  电气 reset 或物理 ACS 验收。
