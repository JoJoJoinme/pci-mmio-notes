# QEMU 静态与动态 PCI 直通对标设计

状态：架构基线 1.0

目标基线：VMware ESXi 8.0 U3、virtual hardware 20、EFI guest

范围：公开接口、公开文档和本仓库黑盒结果所能观察的外部行为
非目标：推导 VMware 私有代码、复制未公开算法或把实验绕过描述成硬件安全能力

## 1. 结论先行

QEMU 本体只能完成设备呈现、MMIO 映射、中断和 DMA 等运行时工作，不能单独提供
VMware Assignable Hardware 的候选发现、跨 VM 排他租约、跨主机选择、故障 fencing 和
审计状态。完整实现必须是一个 QEMU 平台：

```text
QEMU + OVMF/SeaBIOS + VFIO/IOMMUFD
     + host inventory/capability agent
     + durable lease and placement service
     + lifecycle controller
     + versioned policy and qualification database
```

本设计采用以下核心原则：

1. 静态直通持久绑定一个明确 host device；动态直通持久保存匹配条件，只在 VM 启动事务中
   产生临时 `assignedId`。
2. Dynamic DirectPath 表示 power-on selection，不表示运行中 PCI hot-add/hot-remove。
3. `capable`、管理员启用、host 激活、当前可租用、对某个 VM 可启动和某项生命周期操作可用
   是六种不同状态。
4. 候选单位不是单个 BDF，而是 IOMMU、物理隔离、reset、RID alias、multifunction 和功能
   互连依赖的闭包。
5. ACS override 后的 kernel IOMMU group 只用于 VFIO 操作，不能缩小平台安全租约。
6. 多设备分配、bind、reset、QEMU 启动和释放必须是可回滚事务；清理失败进入 quarantine，
   不得直接回到 free pool。
7. VMware 对标 profile 默认拒绝 snapshot、suspend、live migration 和 runtime hotplug；QEMU
   原生 VFIO migration 或 hotplug 只能作为单独扩展 profile，经能力证明后启用。

## 2. 设计目标与边界

### 2.1 目标

- 对齐 VMware 静态 VMDirectPath 的 `Capable/Enabled/Active`、固定 backing 和 dependency 行为。
- 对齐 Dynamic DirectPath 的 allowed-device matcher、power-on selection、运行时 binding、关机
  清空、candidate exhaustion 和 powered-off relocate。
- 在 QEMU 启动前完成 BAR、MMIO、RMRR、IOMMU、ACS、reset、interrupt 和 lifecycle admission。
- 对所有拒绝给出稳定 reason code、具体依赖 BDF、证据 provenance 和恢复建议。
- host crash、QEMU crash、部分 bind 失败和 reset 失败后，不产生双重分配或未受控 DMA。
- 允许同一实现提供严格 VMware parity profile 和显式扩展的 QEMU-native profile。

### 2.2 非目标

- 不保证复刻 VMware 未公开的 candidate 排序；保证匹配集合、排他性和外部状态语义。
- 不把 VID:DID、class code、FLR bit 或 patched IOMMU group 单独当成 capable 结论。
- 不允许 VFIO no-IOMMU、unsafe interrupts 或未审计的 ACS override 进入生产通过路径。
- 不承诺任意 PCI 设备可迁移、可热拔或可安全复用；这些都是独立的设备能力。
- 不在 guest 运行期间把一个 Dynamic backing 静默切换成另一个物理设备。

### 2.3 对标 profile

版本差异必须进入 profile，不能形成一个永久不变的“VMware 默认值”：

```text
vmware-esxi8u3-vhw20-efi       # 本仓库主要实测基线
vmware-esxi8u3-vhw20-bios      # 仅在 SeaBIOS/legacy BIOS 用例中启用
qemu-vfio-native               # 允许经过证明的 VFIO migration/hotplug 扩展
lab-unsafe                     # 只用于实验，输出永远带 unsafe 标记
```

profile 至少固定 QEMU、kernel、firmware、machine type、guest firmware、vHW 对标版本、
capability filter、MMIO policy、migration policy 和 policy database hash。

## 3. VMware 公开状态到 QEMU 平台状态的映射

Broadcom API 将静态设备状态分成 `passthruCapable`、`passthruEnabled` 和
`passthruActive`；其中 Active 明确定义为 enabled 且 host 已重启。Dynamic backing 则保存
`allowedDevice`、可选 `customLabel` 和仅在 VM powered-on 时设置的 `assignedId`。

| VMware 可观察状态 | QEMU 平台等价状态 | 说明 |
| --- | --- | --- |
| `passthruCapable` | `hardwareCapable && policyEligible` | 不受当前 owner 和 VM MMIO 布局影响 |
| `passthruEnabled` | `adminEnabled` | 管理员允许该设备进入直通池 |
| `passthruActive` | `hostActive` | Linux 可按策略安全 bind/open；不伪造“必须重启”语义 |
| `dependentDevice` | `requiredLease` | 完整 dependency closure，不只返回一个 bridge |
| static backing BDF | `StaticRequest.deviceUid` | BDF 和身份都必须匹配，禁止静默替换 |
| `allowedDevice` | `DynamicRequirement.matcher` | VID:DID，加可选 subsystem/revision |
| `customLabel` | `labels` exact matcher | 标签是调度条件，不是安全证明 |
| `assignedId` | `RuntimeBinding.hostBdf` | 只存在于当前 run；power-off 后清空 |
| AH binding | `LeaseRecord + RuntimeBinding` | durable lease 是权威 owner，QEMU manifest 是运行证据 |

Linux 不需要为了外观对标而强制 host reboot。平台应输出实际激活模式：

```text
activationMode = persistent-vfio | bind-on-lease | reboot-required
```

`hostActive=true` 的含义是该模式已经满足，而不是谎称走过 ESXi 的实现路径。

## 4. 总体架构

```mermaid
flowchart LR
    API["VM API / Scheduler"] --> COORD["Placement and Lease Coordinator"]
    COORD --> AGENT["Host DirectPath Agent"]
    AGENT --> INV["Inventory and Capability Engine"]
    INV --> SYSFS["PCI sysfs / config / ACPI / policy DB"]
    AGENT --> VFIO["VFIO cdev + IOMMUFD or legacy group"]
    AGENT --> PLAN["BAR / MMIO / RMRR Planner"]
    PLAN --> LAUNCH["QEMU Launch Adapter"]
    VFIO --> LAUNCH
    LAUNCH --> QEMU["QEMU + OVMF / SeaBIOS"]
    QEMU --> VERIFY["QMP / guest / IOMMU verification"]
    VERIFY --> COORD
    COORD --> AUDIT["Durable manifest and evidence"]
```

### 4.1 组件职责

| 组件 | 必须负责 | 禁止负责 |
| --- | --- | --- |
| Inventory agent | 全量 PCI 拓扑、资源、provenance、health 和 generation | 根据 VM 需要篡改硬件事实 |
| Capability engine | 静态 capable、dependency closure、reason code | 获取或释放实际 owner |
| Lease coordinator | 原子多 bundle 租约、epoch/CAS、fencing | 直接操作 PCI config space |
| Host agent | bind/reset/open、fd passing、rollback、quarantine | 无 durable lease 自行选卡 |
| MMIO planner | selected BAR 布局、profile RMRR envelope、QEMU/firmware参数 | 把示例 hole 固定为生产默认 |
| QEMU adapter | 生成稳定 guest topology、启动和 QMP 验证 | 运行中重新选择 Dynamic backing |
| QEMU/VFIO | config/MMIO/IRQ/DMA 和可选 device migration | 分布式调度和跨进程租约 |
| Policy DB | HCL、errata、override、trust-domain 规则 | 用整个 class code 代替精确证据 |

## 5. 信任与安全模型

### 5.1 owner 和 trust domain

VM、DPDK 进程和其他 userspace driver 都是能够直接发起 DMA 的 owner。安全边界来自 IOMMU、
interrupt remapping、物理拓扑和租约，不来自进程名称。生产至少区分：

```text
untrusted-vm
trusted-vm
trusted-dpdk
host-kernel
qualification-lab
```

不同 trust domain 不能共享同一 `physicalIsolationDomain`、reset domain 或未证明安全的 P2P
互连。`uio_pci_generic`/`igb_uio` 不提供 VFIO/IOMMU 强制，不能用于 `untrusted-vm`。

### 5.2 ACS override 的强制约束

长期启用 `pcie_acs_override` 时必须同时保存：

```text
kernelIommuGroup          # 当前 kernel 的 VFIO 操作单位
physicalIsolationDomain  # 忽略 override 后保守重建的安全域
acsNativeIsolation
acsEffectiveIsolation
acsOverrideSource
```

租约闭包使用 physical domain，VFIO open/bind 使用 kernel group。缺少或矛盾 provenance 时
所有 override-dependent candidate fail-closed。本仓库的
[`kernel-patches/`](kernel-patches/README.md) 提供对应 Linux 6.6 接口和已构建验证。

### 5.3 DMA 和中断底线

- Host IOMMU 必须存在并启用 translation；禁止 no-IOMMU。
- Interrupt remapping 对 untrusted VM 必须为 true；禁止 unsafe interrupts。
- VFIO cdev/IOMMUFD 是优先后端，legacy group/container 是兼容后端。
- IOMMUFD 的 device-centric fd 不改变 IOMMU group 单一 DMA owner 约束。
- ATS、PRI、PASID 默认不暴露；启用前必须证明 bind、invalidate、teardown 和 reset 语义。
- P2P 必须显式声明 peer set。当前 QEMU IOMMUFD 文档仍列出 PCI BAR P2P mapping caveat，
  未通过 backend-specific 验收时直接拒绝。

## 6. 规范化 inventory

inventory 是事实快照，不是调度结果。每次 PCI add/remove、driver bind、link change、reset
失败、kernel reboot 或 policy 更新都递增 `inventoryEpoch`。

### 6.1 DeviceRecord

```json
{
  "deviceUid": "host-uuid/physical-slot-or-bdf/function",
  "hostBdf": "0000:65:00.0",
  "identity": {
    "vendorId": 4318,
    "deviceId": 9860,
    "subVendorId": 4318,
    "subDeviceId": 5192,
    "revisionId": 161,
    "classCode": 197120
  },
  "structure": {
    "headerType": 0,
    "pcieType": 0,
    "parent": "0000:64:00.0",
    "physicalSlot": "slot-3",
    "numaNode": 1
  },
  "resources": {
    "bars": [],
    "rom": null,
    "rmrr": [],
    "interruptModes": ["msix", "msi"],
    "maxVectors": 129,
    "dmaAddressBits": 48
  },
  "domains": {
    "kernelIommuGroup": ["0000:65:00.0"],
    "physicalIsolationDomain": ["0000:65:00.0"],
    "resetDomain": ["0000:65:00.0"],
    "requesterAliasSet": ["0000:65:00.0"],
    "multifunctionSet": ["0000:65:00.0"],
    "functionalGroup": []
  },
  "reset": {
    "methods": ["flr"],
    "selectedMethod": "flr",
    "domainSource": "vfio-hot-reset-info"
  },
  "isolation": {
    "provenance": "native-acs",
    "overrideSource": "none"
  },
  "activation": {
    "adminEnabled": true,
    "hostActive": true,
    "driver": "vfio-pci",
    "activationMode": "persistent-vfio"
  },
  "health": {
    "state": "healthy",
    "generation": 12,
    "lastResetResult": "pass"
  },
  "policy": {
    "eligible": true,
    "policyHash": "sha256:...",
    "qualificationLevel": "software-plus-vendor"
  }
}
```

### 6.2 必收集字段

| 类别 | 字段 |
| --- | --- |
| 身份 | VID:DID、subsystem、revision、class、VPD/serial hash（可用时） |
| 结构 | Header Type、PCIe type、parent、subordinate bus、physical slot、NUMA |
| BAR | index、size、I/O 或 memory、32/64-bit、prefetch、当前地址、ROM、VF BAR、ReBAR effective size |
| 隔离 | IOMMU group、physical domain、ACS native/effective/source、RID alias |
| Reset | sysfs methods、VFIO hot-reset affected set、method provenance |
| 功能依赖 | multifunction、PF/VF、NVLink/NVSwitch、vendor-declared group、platform dependency |
| DMA/IRQ | address width、MSI/MSI-X/INTx、vector count、ATS/PRI/PASID、interrupt remap |
| Reserved | RMRR/IVMD、reserved memory、ROM hash |
| 生命周期 | driver、admin state、health、generation、quarantine reason |
| 策略 | HCL/errata rule、override approval、profile compatibility、evidence level |

### 6.3 BAR 探测

正常 inventory 优先读取 kernel 已探测的 sysfs resource。write-all-ones sizing 只能在设备已经
解绑、quiesced、bus master/decode 已关闭且持有外部独占租约时执行；所有成功和异常路径恢复
BAR 与 `PCI_COMMAND`。本仓库 [`pci-resource-model/`](pci-resource-model/README.md) 已实现该
事务模型，但真实硬件写探测仍需单独资格验收。

## 7. Capability 分层

### 7.1 输出模型

```text
hardwareCapable = assignable function role
               && host IOMMU/interrupt prerequisites
               && accepted reset path
               && trustworthy isolation
               && no structural/platform exclusion

policyEligible = hardwareCapable
              && HCL/errata/trust-domain policy permits

adminEnabled = policyEligible && administrator admitted device to pool

hostActive = adminEnabled && activation mode is ready

available = hostActive
         && complete dependency bundle is healthy and free

attachable = available
          && selected VM BAR/MMIO/RMRR/NUMA/IRQ admission passes

operationSupported(op) = attachable
                      && every selected device supports op
                      && target profile permits op
```

这些状态都必须返回，不能再压缩成一个 `passthroughCapable` 布尔值。

### 7.2 设备 role

- Type-0 endpoint 和经过证明的 VF 可以作为 payload。
- Type-1 bridge、root port、switch port、host bridge 和实际承载 subordinate bus 的 function
  是 fabric node，只能作为 lease dependency，不能作为普通 payload。
- class code 是 metadata，不做 CPU/memory/bridge class blanket blacklist。
- 精确 denylist 只用于已知 errata，必须带 source、affected IDs/revisions、kernel/profile range、
  reason 和审计 override。

### 7.3 reason code

所有 reason 至少带 `stage`、`devices`、`details`、`source`：

```text
HARDWARE_ROLE_NOT_ASSIGNABLE
HOST_IOMMU_MISSING
INTERRUPT_REMAP_MISSING
IOMMU_GROUP_NOT_VIABLE
PHYSICAL_ISOLATION_DOMAIN_UNKNOWN
ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN
RESET_NOT_SUPPORTED
RESET_DOMAIN_UNVERIFIED
PLATFORM_RESERVED
DEVICE_ERRATA_DENY
ADMIN_DISABLED
HOST_ACTIVATION_REQUIRED
DEVICE_QUARANTINED
DEPENDENCY_BUSY
PROFILE_NO_MATCH
PROFILE_ABI_MISMATCH
RMRR_PROFILE_CONFLICT
MMIO_APERTURE_EXHAUSTED
NUMA_POLICY_UNSATISFIED
MIGRATION_UNSUPPORTED
HOTPLUG_UNSUPPORTED
HOST_FENCE_PENDING
INVENTORY_EPOCH_CHANGED
```

## 8. Dependency bundle

### 8.1 闭包规则

对每个 payload seed 迭代求固定点：

```text
leaseDomain = closure(
    payload
  U kernelIommuGroup
  U physicalIsolationDomain
  U resetAffectedSet
  U requesterAliasSet
  U multifunctionSet
  U PF/VFDependencies
  U functionalGroup
  U platformDependencies
)
```

一个 bundle 可以包含不可直通的 fabric function。它们不进入 guest，但其 owner 必须被平台
锁定，必要时保持 host driver 状态不变。两个候选的 lease domain 有任意交集，就不是两个
可独立分配的资源。

### 8.2 reset domain

优先级为 device-specific、ACPI、FLR、AF FLR、PM function reset，再到已验证的 bus/link/slot
reset。bus-level reset 必须通过 `VFIO_DEVICE_GET_PCI_HOT_RESET_INFO` 或资格快照取得 affected
set；仅按 sysfs parent 猜测的集合默认拒绝。reset 日志不是内部状态已清除的证明。

### 8.3 functional group

functional group 覆盖 IOMMU 无法表达的设备关系，例如：

- vendor 声明必须共同分配的 multifunction functions；
- PF/VF 管理依赖；
- NVLink/NVSwitch 或其他 fabric-connected accelerators；
- 共享 firmware、doorbell、sideband management 或安全状态的 function；
- 允许 P2P 时的完整 peer set。

来源优先级为 vendor/HCL signed rule、host firmware/topology、qualification snapshot、人工审核。
不能从相同 VID:DID 自动推断功能依赖。

## 9. 静态直通设计

### 9.1 持久配置

```json
{
  "mode": "static",
  "deviceUid": "host-a/slot-3/function-0",
  "expectedHostBdf": "0000:65:00.0",
  "expectedIdentity": {
    "vendorId": 4318,
    "deviceId": 9860,
    "subVendorId": 4318,
    "subDeviceId": 5192,
    "revisionId": 161
  },
  "guestSlot": "rp-dp0/00.0",
  "profile": "vmware-esxi8u3-vhw20-efi"
}
```

BDF 改变、板卡被替换或 subsystem/revision 不符时必须拒绝并要求管理员确认，不能像 Dynamic
模式一样自动换卡。

### 9.2 状态机

```mermaid
stateDiagram-v2
    [*] --> Disabled
    Disabled --> Enabled: admin enable
    Enabled --> Active: activation ready
    Active --> Reserved: lease CAS
    Reserved --> Preparing: bind/open/reset
    Preparing --> Attached: QEMU verified
    Attached --> Releasing: VM stop/crash
    Releasing --> Active: teardown/reset verified
    Preparing --> Quarantined: rollback failed
    Releasing --> Quarantined: teardown/reset failed
    Quarantined --> Active: explicit recovery and qualification
    Active --> Disabled: admin disable
```

### 9.3 启动事务

1. 读取 inventory 和 policy epoch，确认 exact device identity。
2. 计算 dependency bundle，执行 durable compare-and-swap lease。
3. 再次读取 udev generation、BDF identity 和 group membership，防止 TOCTOU。
4. quiesce host workload，设置 `driver_override`，解绑 host driver 并 bind `vfio-pci`。
5. 打开全部 VFIO cdev/group fd，绑定 IOMMUFD/IOAS，确认单一 DMA owner。
6. 执行选定 reset，重新读取 config/link/health，失败则 rollback 或 quarantine。
7. 根据最终 bundle 计算 BAR/MMIO/RMRR、NUMA、IRQ 和 guest ABI plan。
8. 通过继承 fd 启动 QEMU，避免 QEMU 按字符串 BDF 重新解析到另一设备。
9. QMP、guest 和 IOMMU 三方验证通过后，将 lease 从 `PREPARING` 提交为 `ATTACHED`。

### 9.4 释放事务

1. 停止 guest DMA，等待 QEMU 退出或完成 device detach。
2. 撤销 IRQ eventfd、DMA map、IOAS attachment 和 device fd。
3. 关闭 bus master/interrupt，执行 release reset 并验证 link/config/health。
4. 按 policy 重新绑定 host driver，或保持 persistent-vfio active。
5. 清除 runtime binding，递增 device generation。
6. 仅在所有步骤成功后释放 lease；否则进入 quarantine。

## 10. Dynamic DirectPath 设计

### 10.1 持久请求

每个 virtual passthrough slot 是一个 requirement。持久配置保存 predicate，不保存 BDF：

```json
{
  "mode": "dynamic",
  "requirements": [
    {
      "requestKey": "pciPassthru0",
      "allowedDevices": [
        {
          "vendorId": 32902,
          "deviceId": 4110,
          "subVendorId": 6900,
          "subDeviceId": 1,
          "revisionId": 2
        }
      ],
      "customLabel": "storage-tier-a",
      "count": 1,
      "guestSlot": "rp-dp0/00.0",
      "guestAbiClass": "nvme-tier-a-v1"
    }
  ],
  "profile": "vmware-esxi8u3-vhw20-efi"
}
```

`vendorId/deviceId` 必须匹配；subsystem/revision 只有在 request 中存在时才参与 exact match。
`customLabel` 存在时也必须 exact match。class code、display name 和驱动名不能替代这些字段。

### 10.2 candidate 构造

对每个匹配 function：

1. 运行静态 `policyEligible` evaluator。
2. 展开完整 dependency bundle。
3. 计算 `resourceSignature`、`guestAbiClass`、NUMA 和 health。
4. 去重相同 lease domain；同一物理 bundle 不能伪装成多个 candidate。
5. 排除与 request 的 trust domain、firmware 或 operation policy 不兼容者。

### 10.3 多设备原子求解

输入是 requirement 到 candidate bundle 的二部图。求解结果必须满足：

```text
每个 requirement 达到 count
每个 selected bundle 满足 matcher 和 ABI class
任意 selected leaseDomain 两两不相交
同一 functional group 的 collective assignment 规则满足
host MMIO/RMRR/NUMA/IRQ/VM device-count 限制满足
```

实现使用确定性 backtracking/constraint solver，不使用逐 requirement 贪心。排序只影响可重复性：

1. candidate 数量最少的 requirement 优先；
2. exact subsystem/revision/label 优先；
3. 满足 VM NUMA locality 的 bundle 优先；
4. resource waste 较小者优先；
5. 最后按稳定 `deviceUid` 排序。

这不是声称 VMware 使用同一排序，而是提供稳定、可审计且满足相同外部约束的选择。

### 10.4 事务和 `assignedId`

```mermaid
sequenceDiagram
    participant C as Coordinator
    participant H as Host Agent
    participant L as Lease Store
    participant Q as QEMU
    C->>H: Plan dynamic request at inventoryEpoch E
    H-->>C: Candidate bundles and constraints
    C->>L: CAS reserve all bundles at E
    L-->>C: leaseId + generations
    C->>H: Prepare selected bundles
    H->>H: Revalidate, bind, reset, open fds
    H->>Q: Start with selected fds and resource plan
    Q-->>H: QMP ready and device realized
    H-->>C: Commit runtime bindings/assignedIds
    C->>L: PREPARING -> ATTACHED
```

任何 requirement 无候选或任何准备步骤失败，整组回滚，不允许少配后启动。运行时 binding
包含 `leaseId`、`runId`、selected BDF、device generation 和 guest slot；VM powered-off 后清空。

### 10.5 Dynamic 不是 runtime hotplug

baseline profile 在 QEMU 启动前就选定并 realize `vfio-pci`。QMP `device_add/device_del` 是独立
扩展，`device_del` 只发起 guest eject，必须等待 `DEVICE_DELETED` 才能继续 teardown。未证明
guest cooperation、reset 和 driver recovery 时，runtime hotplug capability 为 false。

## 11. Durable lease 与并发控制

### 11.1 LeaseRecord

```json
{
  "leaseId": "uuid",
  "hostId": "host-a",
  "ownerVmId": "vm-42",
  "runId": "run-77",
  "state": "ATTACHED",
  "bundleIds": ["bundle/0000:65:00.0"],
  "members": ["0000:64:00.0", "0000:65:00.0"],
  "inventoryEpoch": 1042,
  "deviceGenerations": {
    "0000:65:00.0": 12
  },
  "fencingToken": 981,
  "policyHash": "sha256:...",
  "expiresAt": null
}
```

### 11.2 状态

```text
FREE -> RESERVED -> PREPARING -> ATTACHED -> RELEASING -> FREE
                         |             |             |
                         +-------------+-------------+-> QUARANTINED
```

- 单 host 可用 SQLite WAL 加 host-local file lock，但 API 必须保留 CAS/epoch 语义。
- 多 host 使用有共识的 durable store；QEMU pidfile、VM config 和进程列表都不是权威租约。
- 使用 pidfd/systemd scope 或等价进程身份，禁止仅按 PID 判断 owner，避免 PID reuse。
- TTL 只触发调查/回收流程，不能直接把 DMA-capable device 置为 FREE。
- 每次 bind/reset/release 增加 generation；旧 generation 的回调不能释放新 lease。

### 11.3 TOCTOU 防护

租约提交前后都核对：

```text
inventoryEpoch
device generation
BDF -> deviceUid mapping
VID:DID/subsystem/revision
IOMMU group and physical domain
driver owner
PCI link presence
```

发生变化返回 `INVENTORY_EPOCH_CHANGED` 并从头求解，不在旧计划上局部修补。

## 12. BAR、MMIO、RMRR 与 firmware

### 12.1 两阶段 admission

本地实测显示 Dynamic BAR 布局在选定具体 candidate 后生成；Broadcom KB 对 RMRR 则要求
Dynamic VM 的 memory map 尝试兼容 allowable devices。因此设计分开处理：

```text
BAR/MMIO plan       = selected bundles 的实际 BAR
RMRR profile plan   = 当前 host 上所有匹配且可允许 candidate 的 RMRR union
```

如果 selector-wide RMRR union 无法避开 guest RAM，拒绝整个 profile 或要求管理员缩小
allowed set，不能只因为当前选中的一张卡暂时可用就接受。

### 12.2 MMIO planner

1. 固定不可替代的 32-bit/below-1M BAR。
2. 按 size/alignment 进行 below-4G packing。
3. 不能低置的 64-bit BAR 进入 high aperture。
4. 以实际 bridge tree 自底向上聚合 window，不只计算 root-level 总和。
5. high aperture 同时设置 OVMF `X-PciMmio64Mb` 和 QEMU host bridge
   `pci-hole64-size`，不允许只设置一侧。
6. 记录 guest RAM、firmware reserved ranges、其他 virtual device BAR 和 RMRR。
7. plan 是事务结果；任何 BAR 失败时不返回部分布局。

### 12.3 firmware profile

- EFI 基线使用 OVMF，并固定 CODE/VARS hash。
- Legacy BIOS 是独立 profile，使用 SeaBIOS 重新验证 below-4G hole、ROM 和设备数量限制。
- 默认 `rombar=0` 对齐当前 VMware 默认隐藏样本。
- 显式 Option ROM 必须固定 hash、来源和执行 policy；未知 ROM 不进入 guest firmware。
- VMware parity profile 固定 effective BAR size，不允许 guest 改 Resizable BAR。

### 12.4 启动参数模板

优先由 host agent 打开 IOMMUFD 和 VFIO cdev，再把 fd 传给 QEMU：

```bash
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -object iommufd,id=iommufd0,fd=22 \
  -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=OVMF_VARS.fd \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=2048 \
  -global q35-pcihost.pci-hole64-size=2G \
  -device pcie-root-port,id=rp-dp0,chassis=1,slot=1 \
  -device vfio-pci,id=dp0,fd=23,iommufd=iommufd0,bus=rp-dp0,addr=00.0,rombar=0
```

精确参数由启动时探测的 QEMU build capability 决定。旧 kernel/QEMU 可退回 legacy
group/container，但仍必须持有完整 platform lease；禁止退回 no-IOMMU。

## 13. Guest ABI 与 QEMU surface policy

### 13.1 稳定和可变字段

Dynamic 冷启动允许在显式 allowed set 内更换物理 identity，但必须满足 guest contract：

| 必须稳定 | 可在显式 allowed set 内变化 |
| --- | --- |
| virtual slot/function、boot order、profile operation policy | VID:DID/subsystem/revision |
| firmware 类型和 ACPI ownership | BAR size/address（关机重启后） |
| 是否存在 guest vIOMMU | link speed/width 的 profile 化呈现 |
| capability filter 规则 | MSI-X vector 上限（ABI class 允许时） |

每个 candidate 生成 `guestAbiSignature`。request 的 `guestAbiClass` 声明允许的 signature 集合；
未在集合内时返回 `PROFILE_ABI_MISMATCH`，不能寄希望于 guest driver 恰好兼容。

### 13.2 VMware parity surface

基于当前实测，QEMU/VFIO 至少需要以下 policy：

| Surface | 基线行为 |
| --- | --- |
| PCIe topology/LinkCap | 按 profile 重建，不把 host link 原样当合同 |
| AER | host ownership；过滤 guest AER header/ownership，保留经验证的 status body 语义 |
| PME | ACPI `_OSC` 按 profile；默认不向 guest 提交 native PME IRQ |
| Option ROM | 默认隐藏；显式路径固定 ROM hash |
| MSI/MSI-X | 保留并要求 interrupt remapping；记录 vector budget |
| INTx | 仅在物理验收通过的 profile 中允许 |
| ATS/PRI/PASID | 默认过滤；启用需 IOMMUFD/vendor qualification |
| guest vIOMMU | VMware target 未暴露时不添加 |
| P2P | 默认拒绝；显式 peer-set profile 才允许 |
| ReBAR | parity profile 不允许运行时 resize |

不能由标准参数表达的 AER/config capability 过滤，应在 `vfio-pci` config-space policy 或
等价 proxy 中实现，并绑定 profile/version。实验补丁见
[`vmware-esxi8-lab/qemu-patches/`](vmware-esxi8-lab/qemu-patches/)，生产实现需要重写成通用、
有测试的 property/object，而不是保留 lab-only 开关。

## 14. Lifecycle capability

### 14.1 baseline 矩阵

| Operation | 静态 parity | 动态 parity | 条件 |
| --- | --- | --- | --- |
| guest reboot | 允许 | 允许 | 同一 assigned device；reset/driver 功能验证 |
| VM power cycle | 允许 | 允许 | Dynamic 每次重新求解并产生新 binding |
| forced VM off | 允许但强制 cleanup | 同左 | cleanup 失败 quarantine |
| snapshot | 拒绝 | 拒绝 | 当前 ESXi 对标合同 |
| suspend/resume | 拒绝 | 拒绝 | 当前 ESXi 对标合同 |
| live migration | 拒绝 | 拒绝 | 当前实测 `assignHwNotAvailable` |
| powered-off relocate | 固定设备通常 host-bound | 允许 | 目标 host 重新求解 Dynamic request |
| HA restart | 条件允许 | 条件允许 | 原 host fenced，目标有完整 candidate bundle |
| runtime hot-add/remove | 拒绝 | 拒绝 | Dynamic 不等于 hotplug |
| host maintenance evacuation | 关机/应用层处理 | 关机后 relocate | 不能伪装成 live migration |

### 14.2 QEMU-native migration 扩展

只有 device/vendor VFIO driver 报告 migration feature，destination ABI 匹配，DMA dirty
tracking 可用，且全部 P2P devices 支持 P2P migration/quiescent state 时，才可启用
`qemu-vfio-native` live migration。该能力必须显示为 VMware parity 之外的 extension。

迁移失败或取消必须把 device state 恢复为 RUNNING；源端 lease 在 destination commit 前不可
释放。多设备 migration 的 stop/start 不是天然原子操作，必须遵守 VFIO P2P quiescent 规则。

### 14.3 runtime hotplug 扩展

可选实现必须：

1. 预留稳定 PCIe root port 和 firmware hotplug aperture。
2. 在 `device_add` 前完成完整 lease、bind、reset 和 admission。
3. `device_del` 后等待 `DEVICE_DELETED`，不能把 QMP command success 当成已拔除。
4. 再执行 unmap/reset/rebind/release；guest 不合作时保持 lease 并进入 recovery。

## 15. Crash、rollback 与 quarantine

### 15.1 rollback 栈

每个 side effect 入栈对应补偿动作：

```text
lease reserved          -> release lease
host driver unbound     -> rebind original driver
vfio bound              -> unbind vfio
device fd opened        -> close fd
IOMMUFD attached        -> detach IOAS
DMA mapped              -> unmap DMA
QEMU spawned            -> stop/fence QEMU
device reset            -> verify or quarantine
runtime binding stored  -> clear binding with generation check
```

补偿按逆序执行。任何 reset、IOMMU detach、driver restore 或 identity revalidation 失败都禁止
释放成 FREE。

### 15.2 QEMU crash

- host agent 使用 pidfd/systemd scope 收到确定退出事件；
- 先撤销 DMA/IRQ，再 reset；
- config/link/health probe 通过后释放；
- QEMU process 消失但 fd ownership 不清楚时，确认 kernel owner 后再继续；
- lease record 保存 crash reason 和 cleanup evidence。

### 15.3 host crash 和 fencing

cluster 看到 agent heartbeat 丢失时只能标记 `HOST_UNREACHABLE`，不能释放其设备。HA 在其他
host 启动 VM 前必须完成原 host power fencing；原 host 恢复后以更高 fencing token 启动
agent，旧 token 的回调全部拒绝。host reboot 后重新 inventory、reset/health check，再把设备
加入 pool。

### 15.4 quarantine

进入 quarantine 的条件包括：

```text
RESET_FAILED
RESET_STATE_VERIFY_FAILED
DMA_TEARDOWN_UNVERIFIED
IOMMU_DETACH_FAILED
LINK_OR_DEVICE_DISAPPEARED
AER_FATAL_OR_DPC_TRIGGERED
HOST_DRIVER_REBIND_FAILED
IDENTITY_CHANGED
VENDOR_HEALTH_CHECK_FAILED
```

退出 quarantine 必须是显式、审计的 recovery workflow，可要求 slot power cycle 或 host reboot。

## 16. 多主机 placement、cold relocate 与 HA

### 16.1 两阶段 placement

1. Coordinator 向每个 host 请求基于 snapshot 的 `CanSatisfy`，用于筛选和评分。
2. 选中 host 后必须重新执行原子 lease；`CanSatisfy=true` 不是 reservation。
3. 若 inventory epoch 或 owner 变化，返回可重试 conflict，而不是继续使用旧 plan。
4. 所有 requirements 成功后才启动 VM。

### 16.2 cold relocate

- VM powered-off 且 runtime binding 为空才能迁移 Dynamic request。
- 持久 VM config 只移动 matcher/profile，不移动 BDF。
- 目标 host 重新匹配、租约和 MMIO/RMRR plan。
- static request 默认 host-affine；只有管理员将其转换为 Dynamic request 才可自动换卡。

### 16.3 HA restart

HA 成功条件是目标 host 存在完整、健康、互不重叠的 candidate bundles。原 host 未 fenced、
profile RMRR 不兼容、guest ABI class 不满足或 candidate exhaustion 时，保持 VM stopped 并给出
结构化 reason，不能降级为少配设备启动。

## 17. API 与审计 manifest

### 17.1 建议 API

```text
GET  /hosts/{host}/directpath/devices
POST /hosts/{host}/directpath/evaluate-static
POST /hosts/{host}/directpath/plan-dynamic
POST /hosts/{host}/directpath/reservations
POST /reservations/{id}/prepare
POST /reservations/{id}/attach
POST /reservations/{id}/release
POST /devices/{uid}/recover
GET  /vms/{vm}/directpath/runtime-bindings
```

所有变更 API 接受 idempotency key 和 expected epoch；所有响应带 policy/profile hash。

### 17.2 AssignmentManifest

```json
{
  "schemaVersion": 1,
  "vmId": "vm-42",
  "runId": "run-77",
  "mode": "dynamic",
  "profile": "vmware-esxi8u3-vhw20-efi",
  "inventoryEpoch": 1042,
  "policyHash": "sha256:...",
  "riskRegisterHash": "sha256:...",
  "qualificationBundleHash": "sha256:...",
  "leaseId": "uuid",
  "fencingToken": 981,
  "bindings": [
    {
      "requestKey": "pciPassthru0",
      "assignedId": "0000:65:00.0",
      "deviceUid": "host-a/slot-3/function-0",
      "deviceGeneration": 12,
      "leaseMembers": ["0000:64:00.0", "0000:65:00.0"],
      "guestSlot": "rp-dp0/00.0",
      "guestAbiSignature": "sha256:..."
    }
  ],
  "resourcePlan": {
    "mmio32": [],
    "mmio64": [],
    "rmrrEnvelope": [],
    "ovmfPciMmio64Mb": 2048,
    "qemuPciHole64Size": 2147483648
  },
  "artifacts": {
    "qemuHash": "sha256:...",
    "firmwareCodeHash": "sha256:...",
    "firmwareVarsBaseHash": "sha256:...",
    "argvHash": "sha256:..."
  },
  "verification": {
    "qmpRealized": true,
    "guestEnumerated": true,
    "iommuMapped": true,
    "interruptRemapped": true
  }
}
```

manifest 可以记录本次 Dynamic BDF，但不能回写成下一次启动的持久 backing。

## 18. 关键风险与控制

| 风险 | 后果 | 强制控制 | 验收证据 |
| --- | --- | --- | --- |
| ACS override 缩小 group | P2P 绕过 IOMMU | 双域模型，整租 physical domain | provenance + peer-DMA negative/positive control |
| reset 影响旁路 function | 破坏 host/其他 VM | VFIO affected set 闭包和原子 lease | hot-reset info + callback/真实硬件 |
| reset 未清敏感状态 | 跨租户泄漏 | 双端 reset、state probe、失败 quarantine | generation register/vendor test |
| 双重分配/TOCTOU | 两个 owner 同时 DMA | durable CAS、epoch、fd passing | 并发 race 测试 |
| 多设备部分成功 | guest 少配或依赖拆分 | constraint solver、all-or-nothing rollback | 中途 bind/reset fault injection |
| stale DMA/IOTLB/IRQ | power-off 后写 guest/host | unmap/invalidate/IRQ teardown 后才释放 | IOMMU trace 和 sentinel |
| RMRR 与 guest RAM 重叠 | identity DMA 错址 | selector-wide RMRR envelope | synthetic DMAR overlap A/B |
| 异构 candidate ABI 不兼容 | guest driver/firmware 失败 | guestAbiClass 和 per-candidate validation | cold restart across candidates |
| MMIO 只配 firmware 一侧 | BAR 未分配或隐式高置 | OVMF/QEMU 联动 planner | guest `_CRS`、BAR、HMP |
| host crash 后误释放 | split brain | power fencing 和 fencing token | kill/restart/old-token test |
| QEMU crash 清理失败 | device 带旧状态回池 | pidfd cleanup + quarantine | SIGKILL fault injection |
| Option ROM 不可信 | firmware supply-chain 风险 | 默认隐藏，显式 hash allowlist | ROM marker 和 hash |
| AER/DPC fatal | host/设备失稳 | host ownership、health/quarantine | host/guest paired logs |
| ATS/PRI/PASID 残留 | translation/cache 跨 owner | 默认过滤，vendor/IOMMUFD qualification | invalidate/reset/teardown trace |
| P2P backend 不支持 | mapping fail 或越界 DMA | 默认拒绝，backend/profile gate | peer DMA + IOMMU trace |
| live migration 能力误判 | 丢设备状态或脏页 | baseline blocker，VFIO feature 全量检查 | migration FSM/failure rollback |
| runtime eject 未完成 | 提前释放仍在用设备 | 等 `DEVICE_DELETED` 和 fd teardown | guest cooperation timeout test |
| NUMA 远端放置 | 性能与中断抖动 | hard/soft NUMA policy 分离 | locality 和性能 counter |
| HCL/errata 变化 | 已知硬件缺陷进入生产 | signed versioned policy DB | policy hash 和 qualification report |

### 18.1 风险清零发布门

“消除所有技术风险”在本设计中的可执行定义是：**支持范围内零已知未缓解风险**。
不宣称无法证明的“绝对零风险”；无法闭环的风险必须通过禁用设备、关闭功能、
缩小 profile 或拒绝启动来消除暴露，不能以“已接受”代替控制。

每一条 risk record 必须包含 risk ID、影响范围、owner、预防控制、检测、隔离/恢复、
测试 ID、证据等级、artifact hash 和以下唯一状态之一：

```text
OPEN                 # 已识别，未实现完整控制；阻断发布
CONTROL_IMPLEMENTED   # 控制已实现但证据未闭环；阻断发布
VERIFIED              # 控制与正/负/故障注入证据都通过；可在限定 profile 中暴露
FEATURE_DISABLED      # 对应功能在 API、调度和 QEMU 三层都 fail-closed；不属于支持范围
INVALIDATED           # 依赖变更使旧证据失效；立即撤销能力并阻断发布
```

发布和运行时强制规则：

1. 只有 `VERIFIED` 能进入 supported capability；`FEATURE_DISABLED` 必须在三层负例中证明无法绕过。
2. isolation、DMA/IOTLB/IRQ teardown、reset/state leakage、lease/fencing、identity 和 firmware
   integrity 不接受 waiver；只能 `VERIFIED` 或 `FEATURE_DISABLED`。
3. 硬件相关风险不能用 synthetic/QEMU 证据提升为物理硬件 `VERIFIED`；未验收的
   VID:DID/revision/topology 自动落入 deny-by-default。
4. 每个风险都必须同时拥有 prevention、detection、containment 和 recovery；只有日志或只有
   rollback 不算闭环。
5. QEMU、kernel、firmware、policy DB、host platform class 或 device revision 变更时，按依赖图
   自动将相关 `VERIFIED` 置为 `INVALIDATED`，重新验收前不可用。
6. CI/release controller 要求 risk register 无 `OPEN`、`CONTROL_IMPLEMENTED`、`INVALIDATED` 和
   `accepted-risk` 类状态；manifest 固定 risk/qualification hash，运行时 hash 不符立即拒绝。
7. 新发现严重风险时先撤销 capability 并 quarantine 已影响设备，再进行根因分析；
   不等待下一个常规版本。

## 19. 验收矩阵

### 19.1 Inventory 与 capable

| ID | 用例 | 通过条件 | 当前状态 |
| --- | --- | --- | --- |
| C00 | Type-0 FLR endpoint | capable=true，完整 domain | 已有 QEMU/ESXi |
| C01 | Type-1 bridge + FLR | role gate 拒绝 payload | 已有 ESXi |
| C02 | class code A/B | class 不改变 Type-0 结论 | 已有 ESXi |
| C03 | RC endpoint 无 FLR/D3 | reset gate 拒绝 | 已有 ESXi |
| C04 | bridge reset dependency | affected set 整租 | 已有 ESXi；VFIO ioctl 待接入 |
| C05 | no-ACS strict/bypass | strict reject；bypass 仅 conditional | 已有 ESXi |
| C06 | mandatory ACS override | patched group 与 physical domain 分离 | 已有单元/内核构建；运行态待启动新 kernel |
| C07 | RID alias/legacy bridge | alias domain 集体分配 | 已有 ESXi legacy；物理待验收 |
| C08 | narrow errata deny | 精确 ID/revision 和 reason | 待实现 |
| C09 | health/quarantine | 不健康设备不进入 candidate pool | 待实现 |

### 19.2 静态 lifecycle

| ID | 用例 | 通过条件 | 当前状态 |
| --- | --- | --- | --- |
| S00 | exact identity start/stop | 固定 backing、完整 lease、clean release | 部分已有 |
| S01 | BDF 相同但 identity 变化 | fail-closed | 待实现 |
| S02 | dependency busy | available=false，不改变 capable | 已有 evaluator |
| S03 | bind 中途失败 | 原 driver/lease 全回滚 | 待实现 |
| S04 | reset 失败 | quarantine，不回 free | 待实现 |
| S05 | QEMU 启动失败 | fd/IOMMU/driver/lease 逆序清理 | 待实现 |
| S06 | guest reboot traffic | 同设备继续工作 | 已有 ESXi |
| S07 | forced VM off | DMA/IRQ 清理后可复用 | 已有嵌套；controller 待实现 |
| S08 | 十次复用 | 无 stale DMA/interrupt/state | 已有嵌套；物理待验收 |
| S09 | snapshot/suspend | 明确拒绝且设备保持可用 | 已有 ESXi；QEMU gate 待实现 |

### 19.3 Dynamic matcher 与 solver

| ID | 用例 | 通过条件 | 当前状态 |
| --- | --- | --- | --- |
| D00 | VID:DID match | 开机选卡、关机清空 binding | 已有 ESXi |
| D01 | subsystem/revision A/B | 可选字段 exact match | 待实现 |
| D02 | customLabel A/B | label exact；非法 label 有 reason | ESXi API 已见；QEMU 待实现 |
| D03 | 同 BDF domain 的多个 candidate | 去重为一个 bundle | 已有 ESXi 负例 |
| D04 | heterogeneous BAR | selected candidate 后生成 BAR plan | 已有 ESXi |
| D05 | heterogeneous RMRR | allowed-set envelope 或明确冲突 | synthetic 单设备已有；动态集合待实现 |
| D06 | candidate exhaustion | all-or-nothing `PROFILE_NO_MATCH` | 已有 ESXi |
| D07 | 两 requirement 多解 | 确定性无交集 matching | 待实现 |
| D08 | 贪心失败但全局有解 | backtracking 找到合法解 | 待实现 |
| D09 | 两 VM 同时争抢 | 只一个 CAS 成功 | 待实现 |
| D10 | prepare 后 inventory 改变 | epoch conflict，完整重算 | 待实现 |
| D11 | 部分 bind/reset fault | 全组 rollback 或 quarantine | 待实现 |
| D12 | powered-off relocate | 目标 host 新 assignedId | 已有 ESXi |
| D13 | guest ABI class mismatch | candidate 被排除 | 待实现 |
| D14 | functional device group | 全组共同分配 | 待实现；真实 GPU 待验收 |

### 19.4 资源与 guest surface

| ID | 用例 | 通过条件 | 当前状态 |
| --- | --- | --- | --- |
| M00 | 1/2/4/8/32/64GB BAR | placement/failure 与 profile 一致 | 已有 |
| M01 | aggregate/alignment | bridge/root windows 正确 | root-level 已有；多级 planner 待实现 |
| M02 | OVMF-only/host-hole-only | 两种不完整配置均为负例 | 已有 |
| M03 | SeaBIOS profile | below-4G、ROM、device count 独立结论 | 部分已有 |
| M04 | RMRR compatible/overlap | 自动 hole 或精确拒绝 | 已有 synthetic ESXi |
| M05 | ROM default/explicit | 默认隐藏；显式 hash/marker | 已有默认与 QEMU 正控 |
| M06 | AER correctable/nonfatal | host/guest surface 符合 profile | 已有 |
| M07 | PME `_OSC` | ownership 和 IRQ 行为符合 profile | 已有 |
| M08 | MSI-X/MSI/INTx | remap 和功能证据 | MSI-X/MSI 已有；物理 INTx 待验收 |
| M09 | ATS/PRI/PASID | 默认隐藏；显式 profile 完整清理 | 待真实支持设备 |
| M10 | P2P | 默认拒绝；允许 profile 才成功 | ESXi synthetic 已有；QEMU backend gate 待实现 |

### 19.5 故障与多主机

| ID | 用例 | 通过条件 | 当前状态 |
| --- | --- | --- | --- |
| F00 | QEMU SIGKILL | cleanup 后复用或 quarantine | 待 controller；嵌套 host crash 已有 |
| F01 | host agent SIGKILL | lease 保留，重启 reconcile | 待实现 |
| F02 | lease store 短时不可用 | 不产生无租约 attach | 待实现 |
| F03 | host power loss | 未 fence 不在其他 host 重启 | 待实现 |
| F04 | stale fencing token | 旧 agent 无法提交/释放 | 待实现 |
| F05 | cold relocate | Dynamic 重新选卡，static 保持 host-affine | Dynamic 已有 |
| F06 | HA candidate exhaustion | VM 保持 stopped，reason 完整 | 待实现 |
| F07 | live migration request | parity profile 明确拒绝 | 已有 ESXi；QEMU gate 待实现 |
| F08 | optional VFIO migration | feature/P2P/dirty tracking 全满足才通过 | 待支持硬件 |

## 20. 实施路线

### Phase 0：规范冻结

- 固定本文 schema、reason code、profile 和 evidence contract。
- 将现有 `pci-resource-model` 输出升级为 versioned inventory/plan。
- 验收：旧 46 项测试迁移，JSON schema 和 golden files 稳定。

### Phase 1：单 host 静态控制器

- 实现 host agent、activation state、durable local lease、VFIO fd passing。
- 接入 hot-reset affected set、rollback stack、health/quarantine。
- 将 MMIO planner 从 root aperture 扩展到多级 bridge windows。
- 验收：S00-S09、M00-M08 自动化，QEMU crash fault injection 通过。

### Phase 2：单 host Dynamic

- 实现 matcher、bundle dedup、constraint solver、runtime binding。
- 实现 heterogeneous BAR 和 selector-wide RMRR admission。
- 实现 guest ABI class、两 VM race 和多 requirement all-or-nothing。
- 验收：D00-D14，且持久 VM 定义不包含 selected BDF。

### Phase 3：多 host 与 HA

- 实现 cluster placement、consensus lease、fencing token、host reconcile。
- 支持 powered-off relocate 和经 fencing 的 HA restart。
- 验收：F01-F07，两 host 并发/断网/崩溃矩阵无双重 owner。

### Phase 4：QEMU parity surface

- 把 AER/PME/ROM/LinkCap/ATS capability policy 从 lab patch 产品化。
- 实现 versioned `directpath-profile` QOM object/property 和 QMP 状态查询。
- 验收：guest config、ACPI、BAR、IRQ 和 host logs 与目标 VMware profile 比较。

### Phase 5：可选扩展

- 仅对明确支持的 vendor VFIO device 启用 migration。
- 仅对通过 guest cooperation 和 reset 验收的设备启用 runtime hotplug。
- 支持 SR-IOV PF/VF lifecycle、device groups 和 ATS/PRI/PASID advanced profile。
- 扩展能力不得改变 VMware parity profile 的默认拒绝结果。

## 21. 完成标准

实现完成必须同时满足：

1. 静态和 Dynamic 请求都经过同一个 capability、bundle、lease、resource 和 lifecycle 核心。
2. Dynamic 持久配置没有 BDF，运行时 `assignedId` 在 power-off 后清空。
3. 多设备和依赖 bundle 只有全成功或全回滚，不存在部分 guest 启动。
4. ACS override、bus reset、RID alias、functional group 都不能被拆给不同 trust domain。
5. attach 前后都有 IOMMU/IRQ/reset 证据；cleanup 未验证的设备进入 quarantine。
6. host/QEMU/agent/store 故障注入不产生双重 owner 或未授权 DMA。
7. BAR/MMIO、RMRR、firmware、guest ABI 和 operation capability 都进入 manifest。
8. 每个拒绝有稳定 reason code、具体 devices、provenance 和 policy/profile hash。
9. VMware parity 与 QEMU-native extension 分 profile，测试和 API 不混淆。
10. 所有纯软件用例自动执行；真实硬件缺口明确标记，不用 synthetic 结果冒充 E4。
11. risk register 中没有 `OPEN`、`CONTROL_IMPLEMENTED`、`INVALIDATED` 或风险接受项；
    所有暴露能力均为 `VERIFIED`，其余均为不可绕过的 `FEATURE_DISABLED`。

## 22. 当前实现与缺口

| 模块 | 当前状态 |
| --- | --- |
| BAR sizing、root MMIO allocator | 已实现并测试 |
| 静态 `eligible/available/attachable` | 已实现并测试 |
| Linux sysfs inventory | 已实现只读版本 |
| mandatory ACS override provenance | kernel patch 已完整构建；运行新 kernel 待验收 |
| reset affected set | 模型支持，真实 VFIO ioctl 尚未接入 scanner |
| Dynamic matcher/solver | 设计完成，尚未实现 |
| durable lease/host agent | 尚未实现 |
| bind/reset rollback/quarantine | 尚未实现 |
| 多级 bridge resource planner | 尚未实现 |
| multi-host coordinator/fencing | 尚未实现 |
| AER/PME/ROM QEMU parity | lab patch/验证已有，尚未产品化 |
| VFIO migration/hotplug extension | 尚未实现，baseline 明确拒绝 |

在 Phase 1-4 和对应风险闭环完成前，本仓库的产物是 reference/qualification model，
不是可上生产的 DirectPath 控制器。未实现或仅 synthetic 验证的能力必须在对外
capability 中视为 `FEATURE_DISABLED`，不得从命令行、API 或手工 QMP 路径绕过。

当前可执行参考实现为 [`pci-resource-model/`](pci-resource-model/README.md)，现有 VMware
黑盒结论和 Case 索引分别见
[`vmware-esxi8-directpath-local-results.md`](vmware-esxi8-directpath-local-results.md) 和
[`vmware-directpath-acceptance-test-plan.md`](vmware-directpath-acceptance-test-plan.md)。

## 23. 仍需真实硬件完成的项目

- 真实 FLR/SBR/D3/link reset 对敏感状态、外部接口和 DMA 的清除。
- 物理 ACS、PCIe switch P2P、requester-ID alias 和 ACS override 风险边界。
- 支持 ATS/PRI/PASID 的真实设备在 claim/release/migration 时的 cache 和 request teardown。
- 真实 INTx shared-line、interrupt remapping 和压力行为。
- ESXi HCL 支持的 SR-IOV PF/VF、VF reset、PF 管理依赖和 ARI。
- vendor Option ROM 正样本、firmware reinitialization 和安全审核。
- GPU/NVLink/NVSwitch 等 device group 的完整分配与故障恢复。
- vendor driver/HCL/errata policy 和裸机 NUMA/性能验收。

这些项目之外，matcher、solver、lease、rollback、quarantine、RMRR/MMIO、双 host 调度和
绝大多数 lifecycle failure 都应先用 QEMU/instrumented endpoint 完成，不应等待物理硬件。

## 24. 公开依据

- [Broadcom KB 312208：VMDirectPath/Dynamic DirectPath 平台和设备要求](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [vSphere API：HostPciPassthruInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PciPassthruInfo.html)
- [vSphere API：HostAssignableHardwareManager](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.AssignableHardwareManager.html)
- [vSphere API：DynamicBackingInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo.html)
- [vSphere API：AllowedDevice](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.device.VirtualPCIPassthrough.AllowedDevice.html)
- [Linux kernel：VFIO](https://docs.kernel.org/driver-api/vfio.html)
- [QEMU：IOMMUFD backend with VFIO](https://www.qemu.org/docs/master/devel/vfio-iommufd.html)
- [QEMU：VFIO device migration](https://www.qemu.org/docs/master/devel/migration/vfio.html)
- [QEMU：QMP device_add/device_del](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
