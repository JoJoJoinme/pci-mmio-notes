# Qman Static/Dynamic DirectPath 实现蓝图

状态：详细设计 1.4（产品范围、平台矩阵、Legacy-first backend 与在线冷搬迁边界已冻结）
项目快照：G0 `DONE`；当前 G1 `IN_PROGRESS`；Acceptance `101/101` 已分类；
R01-R39 仍全部 `OPEN`；release `BLOCKED`。
目标读者：Qman 架构、host agent、QEMU/VFIO、调度、测试和安全评审人员
规范正文：[`qemu-static-dynamic-directpath-design.md`](qemu-static-dynamic-directpath-design.md)

本文回答“工程师拿到设计后具体怎么实现”。规范正文仍是 capability、domain、allocator、
风险和验收编号的权威来源；产品范围、平台/backend、控制面和集群边界以已接受 decision/policy
合同为准。本文给出阅读路径、模块接口、持久化模型、事务补偿、端到端样例和这些冻结决策的
实现含义。出现未覆盖冲突时 fail closed，不得用旧实现描述覆盖已接受产品合同。
当前 milestone 和发布阻断项见 [`PROJECT-STATUS.md`](PROJECT-STATUS.md)；产品决策与平台/backend
机器合同分别见 [`product-decisions.json`](contracts/product-decisions.json) 和
[`compatibility-profile-policy.json`](contracts/compatibility-profile-policy.json)。

本蓝图不等待、也不假设任何私有 Qman service 名或仓库结构。实现接口、wire entity、FSM/CAS、
verification matrix 和交接停止条件由
[`directpath-portable-control-contract.json`](contracts/directpath-portable-control-contract.json) 与
[`handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md`](handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md)
冻结；内网 AI 只需在 exact target commit 上填写 integration map。portable 合同自身可独立闭环，
而目标 mapping、代码实现、六平台/HCL qualification 必须继续以证据分别提升，不能因为文档完成而
改写为已实现或可发布。

产品范围以 [`ipd/README.md`](ipd/README.md) 为准：唯一目标是 F1-F8 全部完成的
`V3-FULL-DIRECTPATH`。本文 Phase 0-5 是 W1-W6 内部的工程子阶段，不是独立产品版本。
实现不得按 NIC/GPU/HBA 或具体 VID:DID 分叉主流程；通用技术准入由隔离、dependency、reset、
owner、MMIO 和 Guest 约束决定，生产支持则只对 compatibility catalog 中的精确 qualification
profile 生效。VMware 参考模型和实验缺口见
[`ipd/VMWARE-BEHAVIOR-MODEL.md`](ipd/VMWARE-BEHAVIOR-MODEL.md)。
当前 Qman/reference-side 的 WSL/QEMU 结果、runner/hash、E2/E3/E4 边界见
[`ipd/QMAN-TECHNICAL-EVIDENCE.md`](ipd/QMAN-TECHNICAL-EVIDENCE.md)。这些结果用于冻结实现约束，
最小 default-deny QMP、逐设备 VFIO provider 与 host-local Static lease/FSM components 已验证。
现有 bounded snapshot→lease→fresh cdev/IOMMUFD fd→stock-QEMU bind/attach 链只证明未来
`VFIO_CDEV_IOMMUFD` backend 的组件授权连续性；它不证明当前 Legacy TYPE1 产品路径，更不证明
stock QEMU 5.0 支持 passed VFIO fd。下述 production Controller/launcher、生产信任根、物理
DMA/IRQ clean-state、reset/cleanup 或 recovery 仍未因此存在。

## 0. 五分钟读懂系统

### 0.1 先看当前平台的矛盾

Qman 宿主同时承担两类直接设备访问：可信宿主 DPDK dataplane 必须在没有 IOMMU 时仍能
接管指定网卡；不受信任 VM 的 PCI passthrough 则必须保证设备 DMA 只能访问该 VM 的内存。
此外，宿主因 DPDK 独占约束常开 ACS override，VM 又可能一次直通多张大 BAR GPU。

如果把这些需求压成一个全局 `no-IOMMU=false` 或一个 `capable=true`，会出现两个相反错误：

| 错误模型 | 直接后果 |
| --- | --- |
| 看到全局 unsafe no-IOMMU 开关就拒绝整台 host | IOMMU-backed GPU 也无法给 VM，DPDK 与虚拟化不能共存 |
| 因宿主允许 DPDK no-IOMMU，就允许任意 VFIO device 进入 VM | guest 可驱动设备 DMA 到任意 host memory |
| 把 DPDK 网卡和空闲设备放进同一 Dynamic candidate pool | VM 启动可抢占 dataplane，造成宿主业务中断 |
| capable 时不计算 dependency/reset domain | sibling 或 bridge 被另一 owner 使用，attach/release 破坏其他设备 |
| 只按 BAR 总和设置 `pci-hole64-size` | 多级桥窗、对齐和 firmware placement 仍可能失败 |
| live detach 失败统一建议重启 | persistent host consumer 重启后仍会抢回设备，形成维护事故 |

所以 Qman 对标的不是一条 QEMU 命令，而是 ESXi 8.0.3 在设备资格、资源规划、排他占有、
host owner 激活、生命周期和失败恢复上的公开外部语义。PCI 基础术语和 VFIO 原理先读规范
正文第 0.4 节；本蓝图从工程模块和数据合同继续。

### 0.2 先给出解决办法

| 问题 | VMware 可观察语义 | Qman 设计落点 |
| --- | --- | --- |
| 设备是否可直通 | `passthruCapable` | role + per-device IOMMU + isolation + reset + qualification |
| 管理员是否启用 | `passthruEnabled` | durable desired owner，不与 capable 混合 |
| 何时重启生效 | `passthruActive`、Configured/Current Owner、apply-now | activation planner 输出 live/reboot/deny，并在 boot 后 reconcile |
| 共同切换谁 | `dependentDevice` | 显式 owner activation group；reset/isolation/attach 各自建模 |
| 大 BAR 如何放置 | `use64bitMMIO` 与 firmware/layout | 完整 guest PCI tree allocator，统一渲染 QEMU/firmware 参数 |
| Static/Dynamic | fixed backing 与 `allowedDevice/assignedId` | 固定 identity 或开机求解；都复用同一 capability/lease/attach core |

no-IOMMU 使用 **按 owner 和设备分流**，而不是全局二选一：

```text
host unsafe-noiommu capability = enabled for explicitly reserved DPDK devices
VM passthrough policy          = every payload must prove IOMMU-backed DMA
DPDK BDF                       = hostReservation=dataplane-dpdk, never a VM candidate
VM current product backend     = Legacy VFIO TYPE1v2 or TYPE1, exactly pinned by profile
VM future backend              = VFIO cdev + IOMMUFD, independently qualified profile only
runtime backend fallback       = forbidden; configured backend unavailable => fail closed
```

这一分流已由 QEMU/Linux 双 guest 实测：两边全局 unsafe switch 都为 `Y`，无 vIOMMU 的设备
生成 `/dev/vfio/noiommu-0`，有 vIOMMU 的设备生成正常 `/dev/vfio/7` 和 cdev。该结果证明
no-IOMMU 与 IOMMU-backed 设备可以逐设备区分，并保留为未来 cdev backend 的组件证据；它不能
替代 Legacy TYPE1 产品 profile 在六个平台上的 qualification。证据与复现见
[`evidence/qemu-vfio-noiommu-split-20260718.md`](evidence/qemu-vfio-noiommu-split-20260718.md)。

### 0.3 端到端链路

```mermaid
flowchart LR
    REQ["VM Static/Dynamic request"] --> SNAP["Immutable host snapshot"]
    SNAP --> CAP["Capability gates"]
    CAP --> BUNDLE["Dependency bundle"]
    BUNDLE --> PLAN["Guest resource plan"]
    PLAN --> LEASE["Durable lease"]
    LEASE --> ATTACH["Bind, reset, VFIO, QEMU"]
    ATTACH --> VERIFY["QMP, guest, IOMMU proof"]
    VERIFY --> COMMIT["Assignment manifest"]
    COMMIT --> RELEASE["Teardown, reset, verify, free"]

    VERIFY -. failure .-> ROLLBACK["Rollback or quarantine"]
    RELEASE -. uncertain .-> QUAR["Quarantine"]
```

一句话区分 Static 和 Dynamic：

| 模式 | VM 持久配置保存什么 | 每次开机做什么 | 关机后什么仍然存在 |
| --- | --- | --- | --- |
| Static DirectPath | 精确设备 identity 与 host affinity | 验证原设备仍是同一设备并占用完整 bundle | 固定设备请求仍在，运行 lease 释放 |
| Dynamic DirectPath | allowed-device 条件，不保存 BDF | 在目标 host 构造候选、全局求解并生成临时 `assignedId` | allowed-device 条件仍在，`assignedId` 清空 |

最容易混淆的四个集合必须始终分开：

```mermaid
flowchart TB
    KG["Kernel IOMMU group<br/>VFIO operation unit"]
    PD["Physical isolation domain<br/>security lease boundary"]
    RD["Reset affected set<br/>reset atomicity boundary"]
    LB["Dependency bundle<br/>final ownership unit"]

    KG --> LB
    PD --> LB
    RD --> LB
    MF["Multifunction / PF-VF / vendor dependency"] --> LB
    RA["Requester-ID alias / legacy subtree"] --> LB
```

`pcie_acs_override` 可以改变第一个集合，不能证明第二个集合变小。Qman 必须对最终
`DependencyBundle` 做租约和分配，不能对用户请求的单个 BDF 做租约。

## 1. 冻结的对标合同

### 1.1 唯一 VMware 基线

| 项目 | 冻结值 |
| --- | --- |
| ESXi | 8.0.3 / 8.0 U3 |
| 被测 build | 24280767 |
| vSphere API | 8.0.3.0 |
| virtual hardware | 20 |
| 外部依据 | Broadcom KB 312208、8.0 U3 API、仓库黑盒证据 |
| 对标方法 | 只比较公开接口、PCI/ACPI surface、日志和生命周期结果 |
| 明确排除 | vSphere 9.0/9.1 DirectPath Profile Manager、新 API 字段和未公开实现 |

版本不能被“latest”链接暗中升级。qualification manifest 必须保存上述版本、build、
证据 hash 和采集日期；将来支持其他 ESXi 版本时创建新 profile，不能改写本 profile。

### 1.2 对标层级

本设计默认追求 **外部行为与安全语义对齐**，不追求 VMware 私有实现或逐字节复制所有
虚拟芯片组细节。能力分三级：

| 层级 | 含义 | 本设计默认 |
| --- | --- | --- |
| Semantic parity | 状态、资格、资源、错误、生命周期和失败结果等价 | 必须 |
| Guest ABI parity | guest PCI 路径、ACPI root、slot、BAR 与 capability surface 稳定 | 必须稳定；允许明确记录的 topology approximation |
| Strict topology parity | chipset/root bridge/ACPI namespace 与 VMware golden 完全一致 | 不支持；不是产品目标 |

这里的 guest topology 只指 VM 内看到的虚拟 PCI/ACPI root、root port/bridge、BDF 路径、
桥窗口、`_CRS` 和 BAR，不是宿主机物理拓扑或 ACS 安全 domain。Qman 不伪装成 VMware
芯片组，但必须把自己的 machine profile、guest slot 和 ACPI/资源 ABI 做成跨重启与升级稳定
的合同。因此 stock Q35/PXB 可进入 semantic profile；manifest 记录其 profile identity，产品
不提供 `strict VMware topology` 开关。

### 1.3 Firmware/layout profile

VMware 8.0 U3 黑盒矩阵与 QEMU qualification profile 分开表达：

| VMware firmware/layout | VMware 结论 | QEMU qualification 对照 | 产品含义 |
| --- | --- | --- | --- |
| BIOS + i440bx | 有效 | i440fx + SeaBIOS | legacy/below-4G profile；mandatory large BAR 预拒绝 |
| EFI + i440bx | 有效 | i440fx + UEFI | legacy root topology + UEFI profile |
| EFI + acpi | 有效 | q35/PXB + UEFI | 语义近似并冻结 Qman guest ABI；不宣称 VMware chipset identity 等价 |
| BIOS + acpi | ESXi 启动前拒绝 | q35 + SeaBIOS | Qman 可作为独立产品 profile qualification；标记 VMware reference divergence，不冒充 parity |

Q35 + SeaBIOS 的双 64GiB BAR 结果用于理解 QEMU allocator，不会把 VMware 明确拒绝的
`acpi+bios` 组合改写为 VMware parity。Qman 是否支持由自身精确 platform/profile qualification
决定；当前 x86/C86 产品矩阵明确包含 q35 + SeaBIOS。

### 1.4 已冻结产品平台矩阵

以下六行都交付同一个 `V3_FULL_DIRECTPATH` 能力语义；测试线不是删减版产品。x86/C86 每行都
覆盖 `q35/i440fx × UEFI/SeaBIOS` 四组合，ARM 每行只覆盖 `virt + UEFI`。machine、firmware
package、binary 和配置的精确版本/hash 由 qualification 自动采集并写入 profile，不能用表中的
家族名代替运行时精确匹配。

| 交付线 | Platform ID | OS / arch | Kernel / QEMU | machine / firmware | 当前 backend |
| --- | --- | --- | --- | --- | --- |
| 小规模测试 | `TEST-KYLIN-V10-ARM` | Kylin V10 / ARM64 | 4.19 / 5.0 | `virt + UEFI` | Legacy VFIO TYPE1 family |
| 小规模测试 | `TEST-KYLIN-V10-C86` | Kylin V10 / C86 | 4.19 / 5.0 | `q35/i440fx × UEFI/SeaBIOS` | Legacy VFIO TYPE1 family |
| 小规模测试 | `TEST-RH-X86` | RH-family / x86_64 | 4.18 / 5.0 | `q35/i440fx × UEFI/SeaBIOS` | Legacy VFIO TYPE1 family |
| 主线 | `MAIN-KYLIN-V11-ARM` | Kylin V11 / ARM64 | 6.6 / 10.2 | `virt + UEFI` | Legacy VFIO TYPE1 family |
| 主线 | `MAIN-KYLIN-V11-C86` | Kylin V11 / C86 | 6.6 / 10.2 | `q35/i440fx × UEFI/SeaBIOS` | Legacy VFIO TYPE1 family |
| 主线 | `MAIN-OPENEULER-X86` | openEuler / x86_64 | 6.6 / 10.2 | `q35/i440fx × UEFI/SeaBIOS` | Legacy VFIO TYPE1 family |

Qman 不修改 BIOS 或 kernel command line。Host Agent 在运行时逐设备探测 IOMMU 与中断隔离；
缺失、未知或出现 `/dev/vfio/noiommu-*` 反证时直接拒绝 VM 直通。ACS override 永远不能作为
物理隔离缩组证明。

### 1.5 支持范围默认值

在 qualification 完成前，以下默认值是设计合同，不是临时建议：

```text
host unsafe no-IOMMU switch      = enabled/allowed for trusted DPDK
host DPDK device reservation     = explicit, excluded from VM candidates
VM per-device IOMMU backing      = required, no-IOMMU/unknown hard reject
VM current product backend       = Legacy VFIO TYPE1 family
Legacy configured IOMMU type     = exact profile pin: TYPE1v2 or TYPE1; no fallback
VM future backend                = cdev/IOMMUFD in a separate qualification profile
interrupt remapping             = required
ACS override                    = allowed only with whole physical-domain lease
ReBAR guest resize              = false
guest SR-IOV VF creation        = false
P2P                             = false
ATS/PRI/PASID                   = false
INTx                            = false unless exact hardware is qualified
real RMRR device                = false unless exact identity mapping is qualified
snapshot/suspend/FT/vMotion     = false
Dynamic runtime device switch   = false
fixed passthru hotplug          = false, permanently unsupported
maximum passthrough functions   = min(documentedPairLimit, runtimeOptionLimit,
                                      qmanVerifiedLimit); any unknown => not advertised
host-failure automatic HA       = false
BMC/power fencing integration   = false
```

未实现能力必须同时在 API、scheduler/host agent 和 QEMU/QMP 三层返回
`FEATURE_DISABLED`，不能只隐藏 UI。

## 2. 设计目标、非目标与完成定义

### 2.1 设计目标

1. Static 与 Dynamic 共用 inventory、capability、dependency、allocator、lease 和 attach core。
2. 所有决策使用同一个 immutable snapshot；决策阶段不 bind、不 reset、不打开独占 VFIO fd。
3. 所有副作用在 durable lease 后发生，并进入显式 rollback stack。
4. 多设备、多 dependency、多个 Dynamic requirement 只有全成功或全失败。
5. attach 和 release 都以可验证的硬件状态结束；不确定状态进入 quarantine。
6. 每个结论都可追到 policy/profile/snapshot/证据 hash 和验收编号。

### 2.2 非目标

- 不还原 VMware 私有 capable、candidate 排序或 MMIO allocator。
- 不保证任意 PCI endpoint 都能安全直通；默认 deny-by-default。
- 不把 QEMU synthetic callback 当成物理隔离、reset 清理或 vendor 支持证明。
- 不实现 guest runtime PCI hot-add/hot-remove；ESXi 8.0.3 的 fixed hotplug API 只作为产品差异
  记录，Qman 永久返回 `FEATURE_DISABLED`。host owner 的 live activation 不属于 guest hotplug。
- 不允许运维人员用 raw QEMU CLI 绕开 Qman 的 lease 和 admission。

### 2.3 Definition of Done

某个对外 capability 只有同时满足以下条件才可标记 supported：

```text
implementation present
AND all applicable K rows verified
AND all referenced R rows are VERIFIED
AND positive, negative and fault-injection tests pass
AND qualification hashes match runtime
AND management bypass tests fail as expected
AND cleanup/recovery evidence is complete
```

其余状态只能是 `FEATURE_DISABLED`。不存在“功能能跑但风险先接受”的生产状态。

## 3. 组件与权限边界

### 3.1 进程分层

```mermaid
flowchart TB
    subgraph CONTROL["Backend-neutral Qman control plane"]
        API["Qman API"]
        CTRL["DirectPath Controller<br/>single active + standby"]
        SCHED["placement / Dynamic solver"]
        STORE["PostgreSQL transaction + CAS repository"]
        API --> CTRL
        CTRL --> SCHED
        CTRL <--> STORE
    end

    subgraph HOST["Host privileged plane"]
        INV["inventory publisher"]
        AGENT["DirectPath Host Agent"]
        POLICY["qualification cache"]
        JOURNAL["local SQLite journal/cache<br/>not global authority"]
        ADAPTER["VFIO backend adapter"]
        INV --> AGENT
        POLICY --> AGENT
        AGENT <--> JOURNAL
        AGENT --> ADAPTER
    end

    subgraph RUNTIME["Unprivileged runtime"]
        QEMU["QEMU process"]
        FW["UEFI / SeaBIOS"]
        QEMU --> FW
    end

    KERNEL["Linux PCI/VFIO<br/>current TYPE1; future cdev/IOMMUFD"]
    DEVICE["Physical dependency bundle"]

    CTRL --> AGENT
    STORE <--> AGENT
    ADAPTER -->|"Legacy: AUTHORIZED_DEVICE_PATH<br/>Future cdev: passed fds"| QEMU
    ADAPTER <--> KERNEL
    KERNEL <--> DEVICE
```

全系统只有这一套 API、Controller、inventory、qualification、selector、FSM、错误码、审计和
repository schema。Legacy 与未来 cdev/IOMMUFD 只允许在 Host Agent 的 backend adapter、QEMU
renderer、`launchGrant` 和 `attachReceipt` 上分叉，禁止复制一套“Legacy Controller”。

### 3.2 组件责任

| 组件 | 必须负责 | 绝不能负责 |
| --- | --- | --- |
| Qman API | 验证请求、profile、idempotency key；返回稳定状态/reason | 直接操作 sysfs、VFIO 或 QMP |
| DirectPath Controller | single-active 编排 FSM、调用 solver/Host Agent、提交全局事务；standby 只接管控制职责 | 绕过 CAS、把本地 journal 当全局 owner 或按 backend 复制业务流程 |
| placement solver | Static host affinity；Dynamic candidate/global solve | bind/reset 或信任 stale inventory |
| PostgreSQL repository | 全局 CAS、assignedId、bundle lease、run generation、host epoch 与持久 owner | 推断硬件 capability 或因 TTL 到期宣告硬件已释放 |
| inventory publisher | 原子采集 host/device/provider facts | 为了让设备通过而补默认值 |
| Host Agent + SQLite journal/cache | lease 内 bind/reset、生成 backend-specific grant、launch/verify/release，并记录可重放的本机补偿步骤 | 在 lease 前产生设备副作用，或用 SQLite 仲裁跨主机 lease |
| VFIO backend adapter | 按精确 profile 生成 Legacy path grant 或未来 cdev fd grant，返回 typed receipt | 静默 fallback，或改变上层 lease/FSM 语义 |
| qualification DB | 精确 host/device/profile allow/deny 与证据依赖 | 用宽泛 class code 代替设备规则 |
| QEMU renderer | 渲染稳定 topology 与 backend grant、限制 QMP、读回 observed plan/receipt | 选择 Dynamic backing 或成为 owner 权威 |
| QEMU | config/MMIO/IRQ/DMA runtime | durable ownership、跨 VM/host CAS 或失联接管决策 |

### 3.3 最小权限

- API/scheduler 不以 root 运行，不拥有 `/dev/vfio/*`、PCI sysfs 写权限或 QMP unrestricted socket。
- Host Agent 是唯一允许 bind driver、执行 reset、创建 launch sandbox/grant 并验证 attach receipt 的进程。
- 当前 Legacy 路径必须把 exact BDF 作为 stock QEMU 5.0 `vfio-pci,host=` selector，但该值只能来自
  sealed authorization；QEMU 运行在 per-VM transient uid、mount namespace、device cgroup/LSM 和
  read-only sysfs view 中，只能解析授权 BDF 与 `/dev/vfio/$GROUP`。
- 只有未来 cdev/IOMMUFD profile 可以向 QEMU 传预打开 device/IOMMU fd；不能为 Legacy 伪造
  `vfio-pci,fd=` 能力。
- QMP 使用 allowlist；parity profile 拒绝 `device_add`、`device_del`、migration 和绕过 profile 的属性修改。
- policy、firmware、ROM 和 QEMU binary 都按 digest 固定；digest 改变使旧 qualification 失效。

## 4. 核心对象与版本规则

### 4.1 标识符

```text
hostId              stable host UUID
deviceUid           IDENTITY-V1 host-scoped immutable/slot-bound fingerprint; never raw BDF
snapshotEpoch       host-local monotonically increasing uint64
topologyHash        canonical PCI topology and domain hash
profileHash         resolved firmware/machine/surface policy hash
policyHash          qualification/risk database hash
bundleId            canonical hash of dependency members and edge provenance
planHash            canonical guest resource plan hash
leaseId             UUID for one ownership attempt
runId               UUID for one VM power-on generation
runGeneration       monotonic generation for one VM assignment lineage
hostEpoch           monotonic epoch for one Host Agent authority session
assignmentId        UUID for committed runtime assignment
```

所有跨进程 hash 使用 `CANONICAL-JSON-V1`：UTF-8、RFC 8785 JCS、禁止 duplicate key/float/NaN、
枚举和 PCI ID 使用 schema 指定的小写定宽字符串（VID/DID/SVID/SDID 为 4 位、revision 为 2 位，
均不带 `0x`）、缺省字段省略而不是写 `null`、set 先按每个元素的 `CANONICAL-JSON-V1` bytes
排序成 array；时间使用 `TIMESTAMP-UTC-US-V1`，即 UTC RFC 3339、固定 6 位小数和 `Z`。digest 表示为
`sha256:<64 lowercase hex>`，签名输入是完整 canonical bytes，不对解析后的局部对象二次拼接。
schema version 或 canonicalization version 改变必须产生新 hash namespace，不能原地解释旧值。

`IDENTITY-V1` 的输入只有两种，均先按 `CANONICAL-JSON-V1` 规范化：

```text
STRONG_SERIAL = {schemaVersion=1, identityVariant, hostStableId, pciIds,
                 serialProvider, serialValueHash}
SLOT_BOUND    = {schemaVersion=1, identityVariant, hostStableId, pciIds, physicalPath}
deviceUid     = "urn:qman:directpath:device:v1:" + hostStableId + ":" + identityFingerprint
```

`pciIds` 是 closed object，字段固定为 `vendorId/deviceId/subsystemVendorId/subsystemDeviceId/
revisionId/functionRole`；`serialProvider` 只允许经过
qualification 的 VPD/DSN/设备唯一序列号 provider，原始序列号不进入普通日志。无可信序列号时必须
使用 firmware/physical-slot provider 给出的稳定 `physicalPath`；若两者都缺失，设备不能成为
Static target。`SLOT_BOUND` 只有在 compatibility profile 显式
`allowSlotBoundStatic=true` 且管理员完成 enrollment 时才可用于 Static，默认只允许 Dynamic。

`BDF` 不是设备身份，也不进入 `deviceUid`。Static selector member 另外固定
`expectedPhysicalPathProvider/expectedPhysicalPath/expectedCurrentBdf/identityFingerprint/enrolledHostId`；任一变化返回
`ACTIVATION_IDENTITY_MISMATCH`（details 区分 `fingerprint|physicalPath|hostBdf`）并要求显式
re-enroll，不能静默直通替代设备。即使同型号设备
占用原 BDF，STRONG serial 改变也必须使 `deviceUid` 改变；SLOT_BOUND 无法区分同型号同槽替换的
固有限制必须进入该 HCL/profile 的 risk acceptance，而不能被文档隐藏。

上述对象的字段、variant、PCI lexical form、禁止字段、digest 与两个 golden vector 以
[`contracts/directpath-identity-v1.schema.json`](contracts/directpath-identity-v1.schema.json) 为权威；
任何旧的 `hostId/physicalLocationId/subVendorId` 拼法只能作为输入适配层字段，必须在进入 hash 前显式
转换，不能直接参与 `IDENTITY-V1`。

### 4.2 不可变快照

```python
record HostSnapshotWire:                    # exact portable hash subject
    subjectType: const("HOST_SNAPSHOT")
    schemaVersion: const(1)
    hostId: UUID
    kernelBootId: UUID
    hostEpoch: uint64
    agentGeneration: uint64
    hostAuthorityResourceVersion: uint64
    snapshotEpoch: uint64
    previousSnapshotContentHashOrNull: SHA256 | null
    capturedAt: Timestamp
    topologyDigest: SHA256
    deviceRecordDigests: CanonicalSet[SHA256]
    providerFactsDigest: SHA256
    policyHash: SHA256
    keyRingVersion: uint64
    signerKeyId: Id
    signature: Ed25519Signature | null
    contentHash: SHA256 | null

record DeviceRecordWire:                    # exact ENTITY-DEVICE-RECORD
    subjectType: const("DEVICE_RECORD")
    schemaVersion: const(2)
    hostId: Id
    deviceUid: IdentityV1DeviceUid
    immutableIdentity: IdentityV1
    identityFingerprint: SHA256
    currentBdf: CanonicalBdf
    physicalPathProvider: PhysicalPathProvider
    physicalPath: ProviderBoundPhysicalPath
    role: DeviceRole
    iommuProvider: IommuProvider
    physicalIsolationDomain: PhysicalIsolationDomainFact
    dependencyDomains: ExactCanonicalSeven[DependencyDomain{
        kind, state, provenanceDigest,
        edges: CanonicalSet[DependencyDomainEdge{
            targetDeviceUid, actionState, requiredActionOrNull,
            provenanceDigest
        }]
    }]
    dependencyActions: CanonicalSet[DependencyAction]
    resetContract: ResetContractProjection
    owner: OwnerState
    bars: CanonicalSet[BarFact]
    interrupts: InterruptFacts
    health: DeviceHealth
    technicalTraits: CanonicalSet[Id]
    generations: DeviceGenerations
    provenance: DeviceProvenance
    deviceRecordHash: SHA256

record SnapshotEvaluationView:              # internal read model; not wire/hash
    wire: HostSnapshotWire
    hostFacts: HostFacts
    devices: Map[BDF, DeviceEvaluationView]
    resetContracts: Map[BDF, List[ResetContract]]

record HostFacts:
    identity: HostIdentity
    iommuPresent: Fact[bool]
    interruptRemapping: Fact[bool | unknown]
    unsafeNoIommuModeEnabled: Fact[bool]
    acsOverrideActive: Fact[bool]

record Fact[T]:
    value: T
    source: enum(kernel_uapi, patched_kernel_abi, acpi,
                 config_space, qualification_db, manual_audited)
    sourceVersion: string
    observedAt: Timestamp
    evidenceHash: SHA256
```

`HostSnapshotWire` 严格等于
[`directpath-portable-hash-subjects.schema.json#/$defs/hostSnapshot`](contracts/directpath-portable-hash-subjects.schema.json)，
`DeviceRecordWire` 严格等于
[`directpath-portable-entities.schema.json#/$defs/ENTITY-DEVICE-RECORD`](contracts/directpath-portable-entities.schema.json)；
两者均 `additionalProperties=false`。HostSnapshot wire 只携带 `deviceRecordDigests`，不内嵌 BDF map。
DeviceRecord V3 先从同一 256-byte raw PCI config capture 重放 Header Type、multifunction、
PCIe port type 与 FLR bit 28；其 `dependencyDomains` 再按 canonical kind order 精确且仅包含 `FUNCTIONAL`、
`IOMMU`、`MULTIFUNCTION`、`PF_VF`、`PHYSICAL_ISOLATION`、`PLATFORM`、`REQUESTER_ALIAS`；
每条 typed edge 自带 target deviceUid、action state、required action 与 provenance，
UNKNOWN/CONFLICT 不得携带猜测 edge。扁平 `dependencyActions` 仅是 compatibility projection，
不能用来恢复 domain kind 或 edge provenance。
读取端必须解析并校验 digest 指向的 closed DeviceRecord 与 provider facts，才可物化
`SnapshotEvaluationView/DeviceEvaluationView`。旧 `identity/roleFacts/dmaIsolationMode/hostReservation/...`
分组只能是该 internal view 的便利 accessor，不得作为另一套持久化、签名或 API projection。下文的
`snapshot.devices/snapshot.hostFacts/snapshot.resetContracts` 均指这个已校验 view，而
`snapshot.hostId/snapshotEpoch/topologyDigest/policyHash` 代理到 `snapshot.wire`。

HostSnapshot publication 必须把 `hostAuthorityResourceVersion` 当 committed post-CAS version：

```python
function publishCurrentSnapshot(candidateFacts):
    transaction SERIALIZABLE:
        predecessor = readHostAuthorityForUpdate(candidateFacts.hostId)
        r = predecessor.resourceVersion
        candidate = buildAndSignHostSnapshot(
            candidateFacts,
            hostAuthorityResourceVersion=r + 1,
            previousSnapshotContentHashOrNull=
                predecessor.currentSnapshotContentHash)
        insertImmutable(candidate)
        require updateHostAuthority(
            set resourceVersion=r + 1,
                lastSnapshotEpoch=candidate.snapshotEpoch,
                currentSnapshotContentHash=candidate.contentHash
            where resourceVersion=r) changed exactly one row
        commit candidate and authority pointer once
```

提交成功后的不可分割等式为：

```text
current HostAuthority.resourceVersion
  == HostSnapshot.hostAuthorityResourceVersion
  == PINNED_CURRENT_SNAPSHOT.hostAuthorityResourceVersion
  == InventoryVerificationReceipt.observedHostAuthorityResourceVersion
  == InventoryVerificationReceipt.snapshotHostAuthorityResourceVersion
  == r + 1
```

CAS 失败则候选 snapshot 与 pointer 一起回滚，不能被 current/pinned/receipt 任何一条路径消费。

portable verifier 的
[`inventory algorithm identity`](contracts/directpath-inventory-verifier-algorithm.schema.json)
绑定 exact schema bytes 与验证阶段，不是 executable/build attestation；
[`inventory verification receipt`](contracts/directpath-inventory-verification-receipt.schema.json)
绑定 exact trust/current pointer/signed snapshot/complete DeviceRecord set/time，但不是签名、独立/线性化
repository read 证明、publication CAS 或 product admission authority。`RequestReadSet` 固定 exact current
Static request row；`AvailabilityReadSet` 固定 closure member 的 device generation/resourceVersion 与
blocking lease/quarantine predicate。`read_guard` 仅比较调用方提供的 before/after
`CurrentAuthorityVector`、绑定这些 read set 与 inventory/policy/closure artifacts，并从 verified facts、
roots、limits 确定性重放 closure。线性化读取、可信时钟、durable operation lease 与 side-effect fence
仍是 Qman product adapter 的责任。vector 还必须携带
`policyAuthorityId/policyId/policyVersion/policyDigest/policyAuthorityResourceVersion`；只拿到一个
self-hashed policy blob 不等于读到了 repository-current policy pointer。availability 的 V3 P0
正确性基线是每 cluster 一个 `GLOBAL_DIRECTPATH_AVAILABILITY` authority row：所有会改变 availability
predicate 的 insert/update/delete 都在同一个 serializable transaction 中锁定并递增它。该全局 fence
会牺牲并发度，但能封住 absence/phantom；在有闭合 overlap-vector schema 与原子 multi-scope locking
证明前，不允许用 caller-selected device/bundle fence 替代。

portable core 另有一个严格更窄的 publication **capture-closure** stage。它从固定
`providerCaptureOutputEnvelope`/`providerCaptureSemanticFactsEnvelope` 的 exact retained bytes 出发，
按 DeviceRecord provenance 重建每个 provider 的非空 coverage，要求 complete-host PCI binding 双射，
从 raw 256-byte config 或 closed failure 独立重放 structure/FLR，再重算 topology/provider/no-change、
独立 capability-policy hash 与 mandatory-evidence freshness。它输出 schema-valid、自哈希、
factory-only receipt。V2 algorithm identity 精确绑定五份有序 transitive schema digest 和十个
validation stage，policy 必须在同一 schema identity 下重放；shape/count/byte/node/depth/aggregate
budget 先于昂贵 schema walk，freshness 与 dependency reciprocity 使用预建索引。候选记录只证明
`deviceGeneration == candidateSnapshotEpoch` 且共享一个 `candidateResourceVersion`，两个坐标仍是
caller-stamped，不能满足上文 HostAuthority post-CAS 等式。其 freshness 只以 caller-supplied
`captureCompletedAt` 为基准，不是 repository trusted `evaluatedAt`。authority 永远固定为
`COMPONENT_PREMISE_ONLY`、`productAuthorized=false`，并保留包括
`TRUSTED_PUBLICATION_EVALUATION_TIME_REQUIRED` 在内的八个 blocker。这一步消除了
“只有 x-qman prose、没有 executable capture replay”的缺口，
却不证明 target provider decoder/build、真实 collector/publisher、capability-policy authority/CAS、
SERIALIZABLE repository、external rollback 或独立 visibility；完整 publication transaction 仍必须按
上面的 post-CAS 等式和产品证据门实现。

在 capture-closure 之后，portable core 还提供三个顺序不可交换的 factory-only stage：

1. **decision** 从 exact 四 authority read set、current inventory、predecessor
   anchor/freshness 和 zero-unresolved preflight 重算 CAS expectation，并确定性派生
   `GENESIS/INCARNATION_GENESIS/SUCCESSOR/REFRESH/NO_CHANGE`；preflight root signatures 必须
   在 `beganAt` 前完成，predecessor/preflight nonce 必须不同，incarnation 的
   hostEpoch/agentGeneration 分别不得回退且至少一项严格推进；
2. **rollback closure** 对历史 predecessor 使用原 decision trust，对当前 recovery artifacts
   使用 recovery 时点仍 live、同 root/key-ring/trust-anchor namespace、exact key-ring history
   prefix 且 trust-anchor 单调推进的 trust，验证 exact PREPARED/COMMITTED reservation、after
   inventory、finalized anchor 和 fresh nonce；合法前向 ring rotation 不重签旧 committed
   snapshot。两阶段必须匹配 adapter 独立配置的 trust-anchor path，序列化 context 分别固定
   freshness receipt digest、`verifiedAt`、expiry 和 path。该 stage 输出 repository commit 的
   inclusive validity window，没有 caller `committedAt` 参数；
3. **mutation closure** 接受 exact caller-supplied transaction 与 Availability/audit/outbox/commit
   rows，生成一个 DeviceRecord INSERT/record 加 HostSnapshot、HostAuthority、
   AvailabilityAuthority、audit、outbox、commit 的 `N+6` 写集，重算五种 projection、无环
   mutation fixed point、所有 self-digest 和 four-authority resolved vector；`NO_CHANGE` 是严格
   零写。

这三个 stage 仍只验证字节关系。目标 adapter 必须额外证明 raw operation exchange 的来源、
operation result schema/envelope identity、aggregate/event-ID/createdAt/commit-clock 语义、
trusted transaction clock、四 authority SERIALIZABLE CAS、真实原子写入/可见性、anchor finalize
后的 outbox delivery、trust authority 的 direct path/nonce transport，以及 target
commit/build/runner 映射；否则不得把 component context 转成
side-effect authorization。

扫描流程必须读取一次 topology generation，在完整扫描后再次读取；发生变化则丢弃整轮，
不发布拼接快照。所有 evaluator 只接收已发布对象，不允许中途零散重读 sysfs。

`unsafeNoIommuModeEnabled` 是宿主 kernel capability，不是某个设备的运行 backend；它为 true
只产生审计 warning。`dmaIsolationMode` 才进入 VM hardware gate。仅由 sysfs 推断时，
`/dev/vfio/noiommu-$GROUP` 是明确的 `NO_IOMMU` 反证。当前产品 profile 必须在完整 group 上成功
选择 profile 精确固定的 `VFIO_TYPE1v2_IOMMU` 或 `VFIO_TYPE1_IOMMU`，选择值不可用即 fail closed，
不得尝试另一个值；运行时 receipt 还必须证明 QEMU 只打开了授权 group。cdev 绑定
IOMMUFD/IOAS 的结果只属于未来独立 backend profile 和既有 E3 component evidence，不能反向关闭
Legacy 产品 Case。DPDK 编排配置必须在快照发布前覆盖 `hostReservation`，无法关联到准确
BDF/identity 时拒绝发布候选快照。

当前 [`authoritative_snapshot.py`](pci-resource-model/pci_resource_model/authoritative_snapshot.py)
已经把上述合同实现为一个 **bounded component authority**：全 host 采集必须返回精确
`scannedDeviceCount == returnedDeviceCount`，连续两次采集的 boot/topology 完全相同后，才以
CAS 递增 epoch 并在 Linux 本地 filesystem 上用 SQLite WAL/FULL 原子提交；canonical envelope
覆盖 host/boot/epoch、完整 topology、每个 BDF 的精确 VID:DID/subsystem/revision、完整 IOMMU
group、identity/group hash 和 device generation。读取侧拒绝重复 JSON key、额外/缺失字段、
非预期 schema/TEMP object、签名或内容 hash 漂移、旧 boot、旧 epoch 和非 current snapshot。

publisher 成功提交时还会把执行双扫描的同一 capture provider 封存为
`COMPONENT_CAPTURE_PROVIDER` capability；`authorize_launch()` 返回不可复制、不可 pickle 的 sealed
authorization，并在其存活期保留 snapshot store 的一致性边界。该 v5 cdev component 的 VFIO/QEMU
链只能从 authorization 派生 launch facts 和 live capture capability，launch caller 不能替换采集函数；完整 host
分别在 `PRE_OPEN`、`POST_OPEN`、`validate_before_spawn()` 和最终 `popen_kwargs()` 前重新采集，
任一 identity/group/generation/boot/topology 漂移都关闭整个 raw-handle bundle。QEMU plan 的 BDF
集合必须等于 `authorized_bdfs` 并覆盖每个 IOMMU group member。v5 nested-QEMU run 实际记录了
2 次 publish scan 与 4 次 live scan，六次均为相同 12-device topology。

上述 raw-handle/PRE_OPEN 名称是既有 cdev component 证据合同。当前 Legacy 产品实现复用 sealed
facts 和 capture provider，但派生 `AUTHORIZED_DEVICE_PATH`，使用 `PRE_GRANT/PRE_SPAWN`，不把
raw VFIO device fd 传给 QEMU。

这仍只是 `COMPONENT_AUTHENTICITY_ONLY`：HMAC signer/verifier 共用组件 key，不是 production
trust root。当前没有 external monotonic rollback anchor；任何 earlier-valid SQLite 状态回放，包括同
key 下原位/块级恢复或删除最新行，都可能无法检出，inode/store UUID 也不是 anti-rollback 证明；
也没有 production key rotation/revocation、compatibility catalog approval、kernel atomic topology/
device-generation provider 或 authoritative reset provider。因此它不关闭 C10/C15/C16/C18/F10，
也不能把 G1 标记为完成。

### 4.3 运行对象关系

```mermaid
erDiagram
    VM_REQUEST ||--o{ ASSIGNMENT_RUN : starts
    INVENTORY_SNAPSHOT ||--o{ CAPABILITY_DECISION : feeds
    CAPABILITY_DECISION ||--|| DEPENDENCY_BUNDLE : selects
    DEPENDENCY_BUNDLE ||--|| RESOURCE_PLAN : constrains
    ASSIGNMENT_RUN ||--|| LEASE : owns
    ASSIGNMENT_RUN ||--o{ ASSIGNMENT_MEMBER : contains
    ASSIGNMENT_RUN ||--o| ASSIGNMENT_MANIFEST : commits
    ASSIGNMENT_MEMBER }o--|| DEVICE_RECORD : references
    ASSIGNMENT_RUN ||--o{ EVIDENCE_ARTIFACT : proves
```

任何对象引用的 `snapshotEpoch/policyHash/profileHash` 不一致时，旧 plan/decision/lease
不能被“修补后继续”，必须作废并从无副作用阶段重新计算。

## 5. Capability 详细设计

### 5.1 状态分层

| 层 | 回答的问题 | 典型失败 |
| --- | --- | --- |
| `hardwareCapable` | 结构、IOMMU、物理隔离和 reset 是否可证明 | Type-1 payload、IOMMU missing、domain unknown |
| `technicallyAttachable` | 给定 guest profile/VM resource context，通用引擎是否能形成安全完整 plan；不读 owner/lease/catalog | MMIO/RMRR/ABI/operation hard constraint |
| `qualified` | 精确 platform/device/software/guest/workload 是否有有效 E4 qualification record | record missing/revoked/dependency drift |
| `supported` | qualified record 是否被当前 signed compatibility catalog 纳入产品支持 | catalog missing/revoked/expired |
| `policyEligible` | 当前运行模式是否允许该技术结果进入候选；生产必须 `supported`，隔离 lab 必须显式 lab policy | errata deny、unsupported production profile |
| `adminEnabled` | 管理员是否把设备放入直通池 | disabled |
| `hostActive` | complete bundle 的 effective owner/provider 是否已读回为目标状态 | desired/current mismatch |
| `activationDisposition` | 本次 owner transition 是已生效、可 live apply、需维护重启还是拒绝 | driver busy、identity stale、host-critical |
| `available` | 完整 bundle 此刻是否健康且未被占用 | dependency busy、quarantine |
| `attachable` | 对这个 VM/profile 的资源和操作是否可行 | MMIO UNSAT、RMRR overlap、ABI mismatch |
| `eligible` | IPD 对外状态；等于当前 request 的 `attachable=true`，且绝不反向表示 qualified/supported | 任一当前 owner/lease/resource/policy gate 失败 |

对标 VMware 的 `passthruCapable` 是 owner-independent 的 `policyEligible`，不是 `available`。
设备被其他 VM 使用时
capable 不应抖动，只改变 availability。

### 5.2 Gate 顺序

```python
function evaluate(snapshot, target, vmContext, profile, policy):
    require snapshot is published and immutable

    if snapshot.hostFacts.unsafeNoIommuModeEnabled:
        warnings += HOST_UNSAFE_NOIOMMU_MODE_ENABLED
    if not snapshot.hostFacts.iommuPresent:
        reasons += HOST_IOMMU_MISSING

    closure = resolveCapabilityClosure(snapshot, {target}, profile, policy)
    hardwareCapable = closure.success
    for bdf in closure.payload:
        d = snapshot.devices[bdf]
        if d.dmaIsolationMode == NO_IOMMU:
            reasons += DEVICE_NO_IOMMU_DMA_ISOLATION(bdf)
        if d.dmaIsolationMode == UNKNOWN:
            reasons += DEVICE_IOMMU_BACKING_UNKNOWN(bdf)
        reasons += evaluateRoleIsolationResetAndPlatformGates(
            snapshot, d, closure.selectedReset[bdf], policy)
    hardwareCapable = hardwareCapable and noHardwareBlockingReason(reasons)

    qualification = QualificationResult.notEvaluated()
    if closure.success:
        qualification = matchExactQualificationForEveryMemberAction(
            host=snapshot.hostFacts.identity,
            members=closure.actions,
            kernel=snapshot.hostFacts.kernel,
            qemu=profile.qemu,
            firmware=profile.firmware,
            profileHash=profile.hash)
    qualified = hardwareCapable and qualification.allAllowed
    supported = qualified and supportedCatalog.containsExact(qualification.recordHash)
    policyEligible = hardwareCapable and (
        supported if policy.evaluationMode == PRODUCTION
        else explicitUnqualifiedLabPolicyAllows(profile, qualification))

    technicalPlan = null
    technicallyAttachable = null
    if vmContext exists and hardwareCapable:
        technicalPlan = planVmResources(snapshot, {closure.bundle}, vmContext, profile)
        technicallyAttachable = technicalPlan.success and \
                                hardOperationConstraintAllows(vmContext.operation)

    adminEnabled = policyEligible and activationDb.allEnabled(closure.payload)
    activationPlan = null
    hostActive = false
    if adminEnabled:
        activationPlan = planHostActivation(
            snapshot, closure.bundle, desiredOwner=PASSTHROUGH,
            requestMode=vmContext.activationRequestMode or LIVE_ONLY)
        hostActive = activationPlan.disposition == ALREADY_ACTIVE

    bundle = closure.bundle if closure.success else null
    available = false
    if bundle is not null:
        for bdf in bundle.members:
            if snapshot.devices[bdf].hostReservation is not null:
                reasons += HOST_DEVICE_RESERVED(
                    bdf, snapshot.devices[bdf].hostReservation,
                    stage=AVAILABILITY)
    if activationPlan exists and \
            activationPlan.disposition in {ALREADY_ACTIVE, LIVE_APPLY}:
        available = bundle.complete and healthyAndUnowned(bundle) and \
                    noHostReservations(bundle, snapshot)

    plan = technicalPlan
    attachable = null
    if vmContext exists and available:
        attachable = technicallyAttachable and policyEligible and adminEnabled and \
                     operationAllowed(vmContext.operation)
    eligible = (attachable == true)

    return finalizeClosedCapabilityDecision(
        evaluationContext=(VM_REQUEST if vmContext exists else HOST_ONLY),
        admissionMode=policy.evaluationMode,
        requestHash=canonicalRequestHashOrHostOnlyContextHash(vmContext),
        snapshotEpoch=snapshot.snapshotEpoch,
        policyHash=policy.hash,
        profileHash=profile.hash,
        bundleHashOrNull=hashOrNull(bundle),
        resourcePlanHashOrNull=hashOrNull(plan),
        attachable=(attachable == true),
        eligible=(attachable == true),
        reasons=canonicalReasons(reasons), ...)
```

closure、hardware、qualification/catalog 和 technical plan 不得读取 VM owner/lease/admin/当前健康
状态；availability/attachability
不得反向改写 capable。查询 API 重复执行时，
driver、reset generation、lease 和设备寄存器必须完全不变。

因此一张结构、IOMMU、隔离和 reset 均合格、但被宿主 DPDK 保留的网卡可以保持
`hardwareCapable=true`、`policyEligible=true`，同时必须是 `available=false`。这是刻意的分层：
前两个字段允许资格缓存稳定复用，后一个字段和 activation planner 才负责防止 VM 抢占宿主
dataplane；planner 还必须把该情况硬拒绝为 `HOST_DEVICE_RESERVED`，不能建议重启。

### 5.3 Role 不是 class whitelist

判断顺序是 Type-1/header/PCIe port/subordinate bus/platform ownership 等结构证据，class code
只作一致性检查。Type-0 endpoint 改成 bridge class 仍可 capable；真实 Type-1 bridge 即使改成
display class 仍应因结构角色拒绝。精确 VID:DID/revision denylist 只承载已知 errata，必须带来源、
影响版本和 evidence hash。

### 5.4 输出合同

```python
record CapabilityDecisionWire:              # exact closed hash subject
    subjectType: const("CAPABILITY_DECISION")
    schemaVersion: const(1)
    evaluationContext: enum(HOST_ONLY, VM_REQUEST)
    admissionMode: enum(PRODUCTION, ISOLATED_UNQUALIFIED_LAB)
    requestHash: SHA256
    snapshotEpoch: uint64
    policyHash: SHA256
    profileHash: SHA256
    bundleHashOrNull: SHA256 | null
    resourcePlanHashOrNull: SHA256 | null
    hardwareCapable: bool
    technicallyAttachable: bool | null
    qualified: bool
    supported: bool
    policyEligible: bool
    adminEnabled: bool
    hostActive: bool
    available: bool
    attachable: bool
    eligible: bool
    reasons: CanonicalSet[Reason]
    warnings: CanonicalSet[Reason]
    decisionHash: SHA256 | null

record Reason:
    code: ClosedReasonCode
    stage: ClosedReasonStage
    devices: CanonicalSet[DeviceUid]
    details: CanonicalSet[ReasonDetail]
    provenance: CanonicalSet[ReasonProvenance]
```

该 projection 严格等于
[`directpath-portable-hash-subjects.schema.json#/$defs/capabilityDecision`](contracts/directpath-portable-hash-subjects.schema.json)，
Reason 严格等于 operation envelope 的 closed `reason`。`target/payload/activationDisposition/desiredOwner/
effectiveOwner/operation matrix` 是内部 evaluation view 或独立 artifact，不是 decision wire；bundle/plan
只通过 digest 绑定。HOST_ONLY 的 `technicallyAttachable=null`，但 `attachable=false/eligible=false`；
VM_REQUEST 的 `technicallyAttachable` 必须为 bool。API 文案位于签名对象之外；
`code/devices/details/provenance/hash` 必须稳定并参与回归 golden。
控制器内部 `evaluate` 返回 `CapabilityEvaluationResult{wire, bundle, activationPlan, selectedReset,
resourcePlan, payload}`；后五项只是同事务内的已验证 artifact/view。下文 `decision.attachable` 等布尔
快捷访问代理到 `decision.wire`，只有 `decision.wire` 可以跨进程、落库、签名或缓存。

## 6. Domain 与 DependencyBundle

### 6.1 边类型

| 边 | 权威来源 | 默认动作 |
| --- | --- | --- |
| kernel IOMMU group | kernel VFIO/IOMMU | 同一 ownership transaction |
| physical isolation domain | patched-kernel shadow ABI | 同 trust domain、通常同 DMA domain/lease |
| reset affected set | VFIO hot-reset UAPI/qualified FLR | 原子租约与 reset |
| requester alias | kernel PCI/IOMMU alias facts | 同 DMA domain/owner |
| multifunction | PCI identity/topology | 默认整租，精确 qualification 可放宽 |
| PF/VF | SR-IOV topology/provider | PF 管理依赖与 reset closure |
| functional group | signed vendor/platform rule | 按 rule 整租或同 VM |
| platform dependency | RMRR/firmware/platform rule | 特定 action 或拒绝 |

同一张 dependency graph 投影为不同用途的 key，不能输出一个万能 `bundleId`：

```python
function buildAssignmentGroups(snapshot):
    safetyEdges = IOMMU | PHYSICAL | RESET | REQUESTER_ALIAS |
                  MULTIFUNCTION | PF_VF | FUNCTIONAL | PLATFORM

    for connectedComponent in transitiveClosure(snapshot.devices, safetyEdges):
        conservativeId = canonicalId(connectedComponent.members)
        for device in connectedComponent.members:
            # 没有 VMware dependentDevice 等更精确、已 qualification 的事实时，
            # owner/attach 都使用同一保守超集，而不是猜 singleton。
            device.ownerActivationGroup = conservativeId
            device.exclusiveAttachGroup = conservativeId

    applySignedExactRulesThatMayOnlySplitQualifiedEdges()
    require every payload has complete owner/attach group provenance
```

reference scanner 已实现 IOMMU、physical isolation、reset、multifunction 和 platform dependency
的保守传递闭包。缺 `exclusiveAttachGroup` 的外部 inventory 只能到 `available`，不得成为
`attachable`；精确放宽只接受 exact group ID，不提供 host-wide boolean。

### 6.2 CapabilityClosure 固定点

closure 是 `hardwareCapable/policyEligible` 的输入，必须在读取 admin、owner、health 之前求出。
不能先把单 function 标成 capable，再在 attach 时才发现其依赖 function 不可 reset/qualification。
member action 和 reset affected set 相互依赖，因此两者在同一个单调固定点中求解：

```python
function resolveCapabilityClosure(snapshot, requestedPayload, profile, policy):
    members = Set(requestedPayload)
    actions = Map(default=NONE)
    selectedReset = Map[BDF, ResetContract]()
    edges = Set[DependencyEdge]()

    for bdf in requestedPayload:
        actions[bdf] = mergeAction(actions[bdf], ASSIGN_TO_GUEST)

    repeat:
        before = hashCanonical(members, actions, selectedReset, edges)

        # Domain edges may add ownership members. The signed rule maps each edge
        # to a conservative action; an unknown/conflicting mapping is a rejection.
        for bdf in sorted(members):
            d = requireDevice(snapshot, bdf)
            domains = [
                (IOMMU, d.kernelIommuGroup),
                (PHYSICAL, d.physicalIsolationDomain),
                (REQUESTER_ALIAS, d.requesterAliasSet),
                (MULTIFUNCTION, d.multifunctionSet),
                (PF_VF, d.pfVfDependencies),
                (FUNCTIONAL, d.functionalGroup),
                (PLATFORM, d.platformDependencies),
            ]
            for kind, peers in domains:
                require trustedProvenance(kind, d)
                for peer in peers:
                    require peer in snapshot.devices
                    edge = canonicalEdge(bdf, peer, kind, provenanceOf(kind, d))
                    edges.add(edge)
                    members.add(peer)
                    required = conservativeRequiredMemberAction(
                        edge, snapshot.dependencyFacts,
                        requestedPayload, profile.dependencyPolicy,
                        currentActions=actions)
                    actions[peer] = mergeActionOrReject(actions[peer], required)

        # Only members that must be independently presented/reset need their own
        # reset contract. A peer merely held because it is affected by SBR does
        # not recursively acquire an unrelated reset method.
        resetTargets = sorted(bdf for bdf in members
                              if actionRequiresTargetReset(actions[bdf]))
        for bdf in resetTargets:
            contract = selectPublishedResetContract(snapshot, bdf, policy.resetPolicy)
            require contract.accepted
            selectedReset[bdf] = contract
            for peer in contract.affectedDevices:
                require peer in snapshot.devices
                edges.add(canonicalResetEdge(bdf, peer, contract.provenance))
                members.add(peer)
                holdAction = resetOwnershipAction(contract, bdf, peer)
                actions[peer] = mergeActionOrReject(actions[peer], holdAction)

        # A dependency rule may promote a newly found member into guest payload;
        # promotion is monotonic and causes its reset/domain facts to be solved.
        requestedPayload = requestedPayload union {
            bdf for bdf in members if actions[bdf] == ASSIGN_TO_GUEST
        }
    until hashCanonical(members, actions, selectedReset, edges) == before

    require no action is NONE or UNKNOWN
    require every reset contract matches snapshot epoch/topology/rule hash
    require actionCompatibilityIsSafe(actions, selectedReset)

    bundle = canonicalBundle(
        members=members,
        payload={bdf where actions[bdf] == ASSIGN_TO_GUEST},
        edges=edges,
        actions=actions,
        snapshotEpoch=snapshot.snapshotEpoch,
        policyHash=policy.hash)
    resetContractSet = ResetContractSet(
        contracts=canonicalUniqueByDigest(selectedReset.values))
    return CapabilityClosure(
        bundle=bundle,
        selectedReset=selectedReset,
        resetContractSet=resetContractSet,
        resetContractSetDigest=hashCanonical(resetContractSet),
        success=true)
```

`mergeActionOrReject` 不是随意的 enum `max`：允许的提升关系由 policy schema 固定，例如
`LOCK_ONLY -> VFIO_HOLD_IN_SAME_DMA_DOMAIN -> ASSIGN_TO_GUEST`。DeviceRecord wire 的精确映射为
`LEASE_ONLY=LOCK_ONLY`、`DETACH=VFIO_HOLD_IN_SAME_DMA_DOMAIN`、`PAYLOAD=ASSIGN_TO_GUEST`；
`DETACH` 绝不等于 `QUIESCE_HOST`。provider fact 要求 quiesce 或其他未建模 action 时必须
unknown/conflict/deny，不能改标为 `DETACH`；`RESET_WITH/RESTORE_OWNER` 是 additive action，
`DENY_IF_PRESENT` fail closed。固定点实现还要有 `|devices| + |edges|` 上界和 cycle-safe set，超界返回
`DEPENDENCY_CLOSURE_LIMIT`，不能截断后继续。

这里的 action resolver 只能使用内置保守映射和 snapshot 中带可信 provenance 的 dependency
fact，不能读取 owner/admin，也不能用 allowlist 把 bundle 缩小。签名 qualification 在下一 gate
确认“该精确 member/action 是否受支持”；任何允许缩小物理/reset closure 的未来规则都必须形成
新 profile 和 E4 证据，不能作为普通 policy override。

闭包必须确定性排序，`bundleId` 包含 member、edge type、provenance、action、snapshot epoch 和
policy hash。只记录 member 而不记录“为什么加入”会使审计和后续安全放宽不可行。成功结果还必须输出
严格等于
[`directpath-reset-contract-set.schema.json`](contracts/directpath-reset-contract-set.schema.json) 的 exact
`RESET_CONTRACT_SET`，并与 DependencyBundle 一起 hash-bound，调用方不能另选或省略。

### 6.3 ACS override 的 kernel 合同

production 不能依赖 userspace 从被 override 后的 group 反推原始安全边界。内核需要发布：

```python
record KernelPhysicalDomainFact:
    abiVersion: "native-shadow-domain-v1"
    pciTopologyGeneration: uint64
    domainId: uint64
    members: SortedSet[BDF]
    constraints: List[enum(native_missing_acs, requester_alias,
                           legacy_subtree, platform_quirk)]
    memberProvenance: Map[BDF, BitSet]
```

构建器复用 stock IOMMU group formation 的 ACS、alias 和 architecture quirk 事实，但忽略
override 造成的“允许拆组”结果。任一 topology component provenance 不完整时，只把该
component 标成 unknown；不得让无关 component 一起失效，也不得把 unknown 当单设备 domain。

#### 6.3.1 六个平台共用的 provider ABI

4.18/4.19/6.6 不允许各自发明 userspace heuristic。三条 kernel line backport 同一个 versioned
Generic Netlink family `qman_pci_isolation` v1；实现代码可以因内核 API 不同而分支，wire/result
语义必须一致：

```text
QMAN_PCI_ISO_PROBE_V1    -> abi/features/architecture/kernel-instance-nonce
QMAN_PCI_ISO_CAPTURE_V1  -> immutable snapshotHandle, topologyGeneration,
                            deviceCount, snapshotHash, expiresAt
QMAN_PCI_ISO_DUMP_V1     -> multipart dump from that immutable handle
QMAN_PCI_ISO_RELEASE_V1  -> invalidate handle
```

`CAPTURE` 在 PCI/IOMMU topology protection 下先构造完整 immutable kernel snapshot，再返回 handle；
`DUMP` 只读该副本，不能一边遍历一边读取 live sysfs。handle 绑定调用者 credential/net namespace、
kernel instance nonce 和短 TTL；过期、boot 变化、缺 chunk、deviceCount/hash 不符均使整轮失败。
`topologyGeneration` 在 add/remove/rescan、IOMMU/alias/domain 变化、ACS override/provenance 变化时
递增，uint64 wrap 触发 provider unavailable，不能归零继续。

每个 dump item 至少包含：segment/bus/devfn、native/effective IOMMU group、physical domain ID 与
完整 members、requester alias set、legacy subtree、platform quirk、每级 ACS native/effective/source、
constraint provenance 和 architecture provider。unknown alias、无法遍历的桥或缺少 native/effective
区分时，该 connected component 输出 `UNKNOWN` 并在 capability gate fail closed。

DMA 与 interrupt provider 分 architecture 映射到同一个上层合同：

| Architecture | DMA isolation proof | Interrupt isolation proof |
| --- | --- | --- |
| x86/C86 | Intel VT-d/AMD-IOMMU translation domain、requester alias 和 exact group | DMAR interrupt-remapping 或 AMD interrupt-remap effective+enabled；仅有 MSI/MSI-X capability 不足 |
| ARM64 | SMMU stream ID/context domain、alias/endpoint→stream mapping | GICv3 ITS/LPI isolation；legacy INTx 需精确 route ownership 的独立 profile |

“未做特殊设置”只表示产品不主动改 BIOS/kernel 参数，不能把 proof 省略。provider 必须读取当前
effective state；IOMMU、IR/ITS 任一未知或 disabled 都产生稳定拒绝。现有逐 function ACS sysfs patch
可作 provenance 调试输入，但在没有上述 atomic snapshot/generation ABI 时不得升级为 production
physical-domain authority。

### 6.4 Reset provider 合同

reset discovery 是 qualification/inventory 操作，不是普通 capable 查询的副作用：

```python
function discoverResetContract(snapshot, bdf, provider):
    require maintenance lease or persistent provider ownership
    methods = provider.readResetMethods(bdf)

    for method in policyPreference(methods):
        if method == FLR:
            affected = {bdf}
        else:
            affected = provider.queryHotResetAffectedSetTwoPass(bdf)

        contract = ResetContract(
            method=method,
            affectedDevices=affected,
            snapshotEpoch=snapshot.snapshotEpoch,
            topologyHash=hashResetTopology(snapshot, affected),
            ownershipMode=provider.mode,
            qualificationRule=exactRuleId(bdf))
        if qualificationAccepts(contract):
            publish(contract)
```

执行前再次 query affected set；和 plan 不一致时返回 `RESET_DOMAIN_CHANGED`，不 reset、不启动
QEMU。ioctl 成功只证明命令执行，不证明敏感状态已清；后者由设备级 state probe 和真机
qualification 决定。

## 7. MMIO/firmware planner

### 7.1 输入与输出

planner 输入不是 BAR size 总和，而是完整 guest tree：

```text
selected dependency bundles
resolved machine/firmware profile
guest RAM and fixed reservations
every endpoint BAR: size, alignment, 32/64-bit, prefetchable, mandatory
root port and bridge window capability
ROM and emulated-device demand
RMRR/IVMD identity ranges
device/bus/IRQ/fd limits
```

输出 `VmResourcePlan` 至少包含每个 BAR 地址、每级 bridge window、root low/high aperture、
firmware aperture、QEMU `pci-hole64-size` floor、RMRR hole、guest topology、rendered profile 和
预期 observed assertions。

### 7.2 求解流程

```mermaid
flowchart LR
    INPUT["Snapshot + bundles + VM profile"] --> TREE["Build complete guest PCI tree"]
    TREE --> DEMAND["Normalize BAR and fixed demand"]
    DEMAND --> PACK["Bottom-up bridge packing"]
    PACK --> ROOT["Solve root low/high windows"]
    ROOT --> FW["Derive firmware aperture and QEMU floor"]
    FW --> RENDER["Render versioned QEMU profile"]
    RENDER --> ASSERT["Generate observed-plan assertions"]
```

每个 pool 使用 half-open interval `[start,end)`；size 和 alignment 使用 checked unsigned 64-bit
运算。求解 timeout 返回非重试 `MMIO_PLANNER_TIMEOUT`，不得退回可能给出错误成功的 greedy。

### 7.3 QEMU floor 与实际窗口

`pci-hole64-size` 是 floor，不是 hard cap：

```python
function projectQemuHole64(configuredFloor, actualW64, fallbackStart):
    if actualW64 exists:
        start = actualW64.start
        actualEnd = actualW64.end
    else:
        start = fallbackStart
        actualEnd = start

    floorEnd = alignUp(start + configuredFloor, 1GiB)
    return [start, max(actualEnd, floorEnd))
```

Schema 必须分开保存：

```text
requiredHighSpanBytes       selected tree 的真实需求
firmwareApertureBytes       OVMF/firmware 可分配范围
qemuPciHole64FloorBytes     QEMU host-bridge floor
observedRuntimeStart/End    QOM/HMP 实际 root window
```

### 7.4 双 64GiB BAR worked example

输入：Q35、两个独立 Root Port、每个 endpoint 一个 mandatory 64-bit prefetchable 64GiB BAR。

| Profile | 请求 | 预期 |
| --- | --- | --- |
| SeaBIOS qualification | QEMU floor 默认 32GiB | SeaBIOS 分配 `[64G,128G)`、`[128G,192G)`；runtime window `[64G,192G)` |
| OVMF negative | OVMF aperture 默认、floor 32GiB | 两个 mandatory BAR 均未分配；启动验证失败 |
| OVMF positive | `X-PciMmio64Mb=131072`、floor 128GiB | BAR `[128G,192G)`、`[192G,256G)`；runtime window `[128G,256G)` |

产品 renderer 不依赖 SeaBIOS auto-grow 兜底。它显式渲染 planner 解出的 aperture/floor，启动后
再读取 QOM `pci-hole64-start/end/size`、HMP `info pci/mtree`、guest BAR 和 `_CRS`。任何 mandatory
BAR 为 0 或 observed plan 偏离均在 assignment commit 前失败并回滚。

## 8. 持久化与并发模型

### 8.1 全局 repository 与本机 journal

- 参考控制面固定为 single-active DirectPath Controller + standby；任何时刻只有 active Controller
  推进 assignment FSM，standby 接管时必须先取得新的 controller generation。
- PostgreSQL transaction/CAS repository 是 assignedId、bundle lease、run generation、host epoch 和
  持久 owner 的唯一全局真相源；单 host 和多 host 使用同一 repository，不存在产品级“SQLite 模式”。
- 每个 Host Agent 的 SQLite WAL 只保存补偿 journal、receipt 缓存和重放游标。它可以帮助恢复，
  不能分配 bundle、推进全局 state、释放 lease 或覆盖 PostgreSQL CAS 结论。
- repository interface 与上层 FSM backend-neutral；Legacy 与未来 cdev/IOMMUFD 不得各建一套表。

### 8.2 逻辑表

```sql
CREATE TABLE assignment_run (
    run_id              TEXT PRIMARY KEY,
    vm_id               TEXT NOT NULL,
    request_type        TEXT NOT NULL,
    operation           TEXT NOT NULL,
    state               TEXT NOT NULL,
    host_id             TEXT,
    snapshot_epoch      INTEGER NOT NULL,
    policy_hash         TEXT NOT NULL,
    profile_hash        TEXT NOT NULL,
    decision_hash       TEXT NOT NULL,
    plan_hash           TEXT NOT NULL,
    run_generation      INTEGER NOT NULL,
    host_epoch          INTEGER NOT NULL,
    version             INTEGER NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE bundle_lease (
    bundle_id           TEXT PRIMARY KEY,
    lease_id            TEXT NOT NULL UNIQUE,
    run_id               TEXT NOT NULL,
    owner_vm_id         TEXT NOT NULL,
    state               TEXT NOT NULL,
    run_generation      INTEGER NOT NULL,
    host_epoch          INTEGER NOT NULL,
    expected_generations TEXT NOT NULL,
    expires_at          TEXT,
    version             INTEGER NOT NULL
);

CREATE TABLE assignment_member (
    run_id              TEXT NOT NULL,
    device_uid          TEXT NOT NULL,
    bdf                 TEXT NOT NULL,
    action              TEXT NOT NULL,
    owner_group_id      TEXT NOT NULL,
    attach_group_id     TEXT NOT NULL,
    original_driver     TEXT,
    reset_contract_hash TEXT,
    vfio_device_id      TEXT,
    PRIMARY KEY (run_id, device_uid)
);

CREATE TABLE host_activation_intent (
    intent_id               TEXT PRIMARY KEY,
    desired_owner           TEXT NOT NULL,
    request_mode            TEXT NOT NULL,
    state                   TEXT NOT NULL,
    identity_manifest_hash  TEXT NOT NULL,
    requested_set_hash      TEXT NOT NULL,
    owner_group_hash        TEXT NOT NULL,
    expected_snapshot_epoch INTEGER NOT NULL,
    applied_boot_id         TEXT,
    observed_state_hash     TEXT,
    reason_code             TEXT,
    version                 INTEGER NOT NULL,
    updated_at              TEXT NOT NULL
);

CREATE TABLE quarantine_record (
    device_uid          TEXT PRIMARY KEY,
    bundle_id           TEXT NOT NULL,
    reason_code         TEXT NOT NULL,
    evidence_hash       TEXT NOT NULL,
    generation          INTEGER NOT NULL,
    cleared_by          TEXT,
    cleared_at          TEXT,
    version             INTEGER NOT NULL
);

CREATE TABLE idempotency_record (
    scope               TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    request_hash        TEXT NOT NULL,
    response_json       TEXT,
    state               TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    PRIMARY KEY (operation_id, idempotency_scope_hash, idempotency_key)
);
```

上面的 SQL 是早期关系示意，不是可直接执行的最终 migration。目标实现不得只创建这六张表。
可变 authority、非 authority read/config projection、immutable signed/hash artifact 必须分开；不能把
Catalog、HostSnapshot 或 receipt 当成可以原地覆写的 owner 表。19 个可变持久 authority aggregate
由 [`contracts/directpath-authority-entities.schema.json`](contracts/directpath-authority-entities.schema.json)
逐字段封闭，目标 repository 至少必须一一映射：

| Authority/entity | 必须可查询/CAS 的内容 |
| --- | --- |
| `ENTITY-CONTROLLER-AUTHORITY` | active controller identity/generation、lease/fencing、last committed event；旧 generation mutation 拒绝 |
| `ENTITY-HOST-AUTHORITY` | host/boot/Agent generation、cooperation state、resourceVersion，以及当前 signed HostSnapshot 的 epoch/content-hash 原子 pointer |
| `ENTITY-OWNER-ACTIVATION-RUN` | 独立 Owner FSM、request/owner group、typed operation lease、boot intent、read-back、rollback evidence |
| `ENTITY-ASSIGNMENT-RUN` | 独立 Assignment FSM、operation、run/host/controller generation、snapshot/profile/decision/plan hash 与 failure authority |
| `ENTITY-ASSIGNMENT-BINDING` | requirement/ordinal/guest slot→assignedId→deviceUid/current BDF 的 runtime-only 绑定与 manifest/grant identity |
| `ENTITY-BUNDLE-LEASE` | 物理占用 authority、完整 members、scope conflict、expected generations、fencing token、lease state/version |
| `ENTITY-HOST-ACTION-JOURNAL` | global intent 与本机 durable action journal 的 sequence、step、attempt、ack/result/receipt；不保存 global owner |
| `ENTITY-RESERVATION-CANCEL-RECEIPT` | 未发生物理副作用时释放 reservation 的 exact lease/member/version proof；不能伪装 clean release |
| `ENTITY-QUARANTINE-RECORD` | whole-bundle affected set、deny reason、retained leases/guards、evidence 与 clear eligibility |
| `ENTITY-REMEDIATION-RUN` | 独立 remediation FSM、expected quarantine generation、lease/guard、probe/action/cleanup result |
| `ENTITY-RELOCATION-RUN` | source/target attempts、source assignment、signed clean receipt、active target generation 与独立 relocation FSM |
| `ENTITY-IDEMPOTENCY-RECORD` | operation ID/scope hash/key/canonical request hash/run/result、状态、resourceVersion 和 retention；同一自然键异请求拒绝 |
| `ENTITY-OPERATION-LEASE` | `OWNER_TRANSITION/ASSIGNMENT_PREPARE/RELEASE/RELOCATION_HANDOFF/QUARANTINE_REMEDIATION` typed lease 与 covered side-effect fence |
| `ENTITY-RELEASE-OWNERSHIP-GUARD` | 精确 leaseBindings、QEMU pid/starttime 或 never-created/exit proof、backend context、deny-new-opener 与 consumed state |
| `ENTITY-CLEAN-RELEASE-ACCEPTANCE` | repository 对 clean-release receipt 的不可变接受事实；精确绑定 receipt、lease set、assignment/run/generation、expected/committed authority version、事务与幂等键，并由同一 FREE CAS 事务提交 |
| `ENTITY-AUDIT-EVENT` | actor/correlation/causation、operation/run/transition、before/after version、artifact/evidence hashes |
| `ENTITY-OUTBOX-EVENT` | 与 authority transition 同事务写入的 event payload hash、delivery attempt/status 和 monotonic sequence |

以下四个 closed projection 由
[`contracts/directpath-portable-entities.schema.json`](contracts/directpath-portable-entities.schema.json)
定义，但不创造第二份可变 owner：`ENTITY-DEVICE-RECORD` 是某一 HostSnapshot 的 current fact；
`ENTITY-QUALIFICATION-PROFILE` 是已验证 catalog/record 的 resolved read model；
`ENTITY-VM-DIRECTPATH-REQUEST` 是 versioned Static/Dynamic configuration；
`ENTITY-DEPENDENCY-BUNDLE` 是某一 snapshot 下的 canonical closure。HostSnapshot、AssignmentManifest、
clean-release/source-clean receipt、QualificationRecord、SupportedCatalog、trust/key-ring/anchor 和 integration
reports 是 immutable signed/hash artifact；更新产生新 digest/sequence，不在原记录上修补字段。

每张状态表必须使用 enum/check constraint 或等价的 domain type，所有引用有 FK，generation/version
非负且单调；live conflict key 上建立唯一约束，保证同一 physical/reset/exclusive domain 最多一个
active operation lease。transition 通过 repository method 或 DB procedure 同时比较
`state + version + controllerGeneration + hostEpoch + runGeneration + memberGenerations`，不能只比较
state 字符串。intent mutation、outbox event 和 version 增量在同一 transaction 中提交。

lease/reservation/relocation target-attempt 使用 PostgreSQL `SERIALIZABLE` 或能证明等价的 predicate
locking；serialization failure 返回稳定 CAS conflict 并从 fresh snapshot 重算。普通读模型可用较低
隔离级别，但不得据此提交 owner。versioned DB migration 必须支持 N/N-1 control-plane 混部的显式
compatibility window、forward/backward validation 和 rollback；无法无损回滚的 migration 必须在
升级前阻断新 assignment 并 drain，而不是运行中猜测 schema。

JSON 字段使用 `CANONICAL-JSON-V1` 的 versioned schema；不可查询 blob 只能保存 immutable artifact，
不能替代 lease member、generation、transition guard 等关系约束。

`host_activation_intent` 只保存显式 maintenance owner 变更；普通 `bind-on-lease` 不制造
desired/current 长期分离。`PENDING_REBOOT` 必须同时固定 exact device identity、physical path、
显式 request set、扩展后的 owner activation group 和 snapshot epoch；boot 后只有该 owner group 的
observed owner/provider hash 全匹配才转
`ACTIVE`。BDF 或 identity 漂移时转 `FAILED`，禁止按同 VID:DID 猜设备。

### 8.3 CAS 不变量

```python
function acquireBundleLease(request, bundle, snapshot):
    require request.expectedSnapshotEpoch == snapshot.snapshotEpoch
    require request.expectedHostEpoch == store.currentHostEpoch(snapshot.hostId)
    require request.expectedRunGeneration == store.currentRunGeneration(request.vmId) + 1
    require no member has active lease or quarantine

    success = store.transactionCompareAndSwap(
        expectedVmRunGeneration=request.expectedRunGeneration - 1,
        bundleKey=bundle.bundleId,
        expectedBundleVersion=currentVersion,
        new=PREPARING(runId=request.runId,
                      members=bundle.members,
                      runGeneration=request.expectedRunGeneration,
                      hostEpoch=request.expectedHostEpoch,
                      expectedGenerations=currentGenerations(bundle)))
    if not success:
        return conflict(DEPENDENCY_BUSY, retryable=true)
    return lease
```

同一物理 domain 的所有可租元素必须在一个原子 key/transaction 中竞争。按单 BDF 分别 CAS
再补偿会产生短暂双 owner，设计上禁止。

`runGeneration`、`hostEpoch` 和 CAS version 只拒绝 stale Controller/Host Agent mutation；它们不是
物理 clean-release proof，不能在源主机失联时把 lease 变为 FREE。

### 8.4 Host owner activation 与 reboot decision

#### 8.4.1 外部状态合同

ESXi 8.0.3 的公开接口和本地证据要求 Qman 分开保存：

```text
adminEnabled             管理员允许进入直通池
desiredOwner             maintenance 持久意图
effectiveOwner           当前实际 driver/provider owner
requestSet               本次 API/CLI 明确请求的 BDF
ownerActivationGroup     实际必须共同切换宿主 owner 的闭包
exclusiveAttachGroup     VM admission 必须独占的 lease key
hostActive               完整 ownerActivationGroup 的 effective owner 已读回匹配
activationDisposition    ALREADY_ACTIVE | LIVE_APPLY | REBOOT_REQUIRED | DENIED
```

官方 ESXCLI 8.0.3 明确规定：`--apply-now` 会立即在 native driver 与 `pciPassthru` 间重绑；
不带该参数则请求重启后生效。本地 `20260713-capability-smoke-v5` 和
`20260713-esxi8-flr-vm-power-v1` 进一步证明 `-a` 后无 host reboot 即可得到 Current Owner=
`VM Passthru` 和 API `passthruActive=true`。相反，`20260711-largebar2g/M00` 保存了 Configured
Owner=`VM Passthru`、Current Owner=`VMkernel` 的分离态。脱敏命令/输出摘录见
[`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)，机器可读索引见
[`evidence/esxi8-passthru-activation-20260718-summary.json`](evidence/esxi8-passthru-activation-20260718-summary.json)。

2026-07-18 的新增实测关闭了此前的两个缺口：专用 endpoint deferred 后经过真实 host reboot
成功由 `pciPassthru` claim；持久 vSwitch uplink 对 apply-now 和 direct deferred 都原子拒绝，
移除 consumer 后同一 BDF 立即成功。共享 bridge dependency 还出现 request-target 不对称：仅请求
空闲 member 会自动切换整个组，而显式请求 busy member 或完整组会失败；SOAP 与 ESXCLI 一致。
VM power-on A/B 则证明同一 dependency 形成 exclusive attach lease，且同 VM 双 member 也不合并。

因此 reboot requirement 是一次 ownership transaction 的结果，不是 device 的 FLR/class/BAR
静态属性。FLR/SBR 仍属于 attach/release reset gate；它不能证明 native driver、storage path 或
host service 当前可解绑。Qman 对 VMware 的 request-target 不对称采取安全分歧：**先扩完整
owner group，再逐成员预检**，绝不借由请求另一个 sibling 静默拆除 network/storage/management
consumer。

```mermaid
flowchart LR
    REQ["requestSet"] --> EXPAND["expand ownerActivationGroup"]
    EXPAND --> PREFLIGHT["preflight every host consumer"]
    PREFLIGHT --> OPLEASE["acquire typed durable operation lease"]
    OPLEASE --> OWNER["bind/read back effective owner"]
    OWNER --> LEASEKIND{"lease kind"}
    LEASEKIND -->|"VM power-on"| ATTACHLEASE["assignment lease stays PREPARING"]
    LEASEKIND -->|"maintenance"| MAINTLEASE["activation lease commits intent/result"]
    ATTACHLEASE --> ADMIT["MMIO/IRQ/DMA/guest ABI admission"]
    RESET["resetDomain/recovery contract"] -. independent input .-> PREFLIGHT
    RESET -. independent input .-> ADMIT
```

`typed durable operation lease` 的唯一枚举是 `OWNER_TRANSITION`、`ASSIGNMENT_PREPARE`、
`RELEASE`、`RELOCATION_HANDOFF`、`QUARANTINE_REMEDIATION`。VM power-on 使用覆盖完整
`exclusiveAttachGroup` 的 `ASSIGNMENT_PREPARE`；显式 maintenance owner 变更使用同一全局
repository 中互斥的 `OWNER_TRANSITION`。所有类型共享 scope conflict key，不能并发。planner 始终
无副作用；unbind/bind/early-boot intent 的第一项前置条件必须是 operation lease 已 CAS 成功。
`BundleLease` 与 `ReleaseOwnershipGuard` 分别是物理占用 authority 和 release deny guard，不是新的
operation lease type。
maintenance lease 不得伪装成 VM assignment，也不能给 QEMU 签发 launch authorization；它只在
owner 结果和 journal 已提交或已验证回滚后释放。这样既支持 VMware 的 enabled/active 分离，
又禁止“先改 owner、再补租约”的无保护窗口。

```mermaid
stateDiagram-v2
    [*] --> ENABLED
    ENABLED --> ACTIVE: effective owner already matches
    ENABLED --> LIVE_APPLICABLE: expanded owner group can quiesce now
    ENABLED --> PENDING_REBOOT: explicit maintenance intent
    ENABLED --> DENIED: persistent host use or incomplete group
    LIVE_APPLICABLE --> APPLYING: durable bundle lease
    APPLYING --> ACTIVE: all owners/providers read back
    APPLYING --> ENABLED: rollback verified
    APPLYING --> QUARANTINED: partial transition or rollback uncertain
    PENDING_REBOOT --> ACTIVE: early-boot claim and observation pass
    PENDING_REBOOT --> FAILED: identity/bundle/owner observation mismatch
```

#### 8.4.2 无副作用 planner

wire enum 固定如下；不得用自由字符串或本地 driver error 代替：

```text
requestMode       LIVE_ONLY | DEFER_TO_REBOOT | LIVE_OR_REBOOT
desiredOwner      HOST | PASSTHROUGH
quiesceState      IDLE | TRANSIENT_BUSY | PERSISTENT_HOST_USE |
                  HOST_CRITICAL | UNKNOWN
liveSupport       SUPPORTED | UNSUPPORTED | UNKNOWN
activationAction  QUIESCE_CONSUMER | UNBIND_NATIVE | SET_OVERRIDE |
                  BIND_VFIO | READ_BACK | RESTORE
```

owner provider 必须先探测 network/storage/DPDK/boot-root/management consumer，返回 provider ID、
consumer identity、状态、provenance、observation generation 和 deadline capability。`IDLE` 必须是
积极证明，不能由“没找到进程”推导；storage path、root filesystem、管理 uplink、host reservation
等 persistent/critical consumer 不允许 reboot fallback 偷偷拆除。每个可 quiesce consumer 返回
single-use `quiesceToken`，token 绑定 member、consumer generation、operation lease 与 deadline；
restore 只接受原 token。

`exactEarlyBootClaimProof` 不是 bool，而是 `{providerId, providerVersion, platformProfileId,
bootOwnerManifestSchema, exactIdentityFields, ownerGroupHash, nativeDriverProbeOrderHash,
secureBootPolicyHash, qualificationRecordHash}`。任一字段缺失即 `BOOT_CLAIM_UNSUPPORTED`。
Host Agent 对每个 member/action 在 side effect 前写 local journal intent，完成后写 read-back receipt；
deadline、retry 次数与 rollback deadline 来自 resolved profile，不能在 executor 中使用无限重试。

```python
function planHostActivation(snapshot, requestedBdfs, desiredOwner, requestMode):
    requested = resolveExactIdentity(snapshot, requestedBdfs)
    ownerGroup = expandOwnerActivationGroups(snapshot, requested)
    require ownerGroup.complete
    require ownerGroup.hash and every identity/action fact match snapshot

    if any ownerGroup member.identity/path mismatches persisted deviceUid:
        return DENIED(ACTIVATION_IDENTITY_MISMATCH)
    if any ownerGroup member.currentOwner is UNKNOWN:
        return DENIED(CURRENT_OWNER_UNKNOWN)
    if any ownerGroup member.quiesceState is UNKNOWN:
        return DENIED(QUIESCE_STATE_UNKNOWN)
    if any ownerGroup member is hostCritical, policyDenied, quarantined,
           or leasedByOther:
        return DENIED(exactReasonAndMembers)
    if desiredOwner == PASSTHROUGH and
           any ownerGroup member.hostReservation is not null:
        return DENIED(HOST_DEVICE_RESERVED)
    if any ownerGroup member.quiesceState == PERSISTENT_HOST_USE:
        return DENIED(PERSISTENT_HOST_USE)
    if all ownerGroup member.currentOwner == desiredOwner:
        return ALREADY_ACTIVE

    changing = ownerGroup members where currentOwner != desiredOwner
    if requestMode != DEFER_TO_REBOOT and
           all changing members are IDLE and liveTransitionSupported:
        return LIVE_APPLY(changing)

    # Reboot is recommended only when an implementation can claim this exact
    # owner group before native drivers/services make it busy.
    if requestMode explicitly permits reboot fallback and
           all changing members have exactEarlyBootClaimProof:
        return REBOOT_REQUIRED(changing, liveBlockers)
    return DENIED(BOOT_CLAIM_UNSUPPORTED)
```

该函数不得 bind、unbind、reset、写 config space 或持久化 desired owner。参考实现
[`activation.py`](pci-resource-model/pci_resource_model/activation.py) 以 inventory + request set 为输入，测试
证明 owner-group expansion 和 incomplete-group fail-closed；idle 返回 `LIVE_APPLY`，persistent
host use 返回 `DENIED`；主动 deferred 的 idle device，或 `LIVE_OR_REBOOT` 下有 transient blocker
的 device，只有完整 owner group 具备 exact boot proof 才返回 `REBOOT_REQUIRED`。这些运行态变化
不改变硬件 capable。

`hostReservation=dataplane-dpdk` 必须在 owner-group 扩展后逐成员检查。它代表平台明确保留，
不是“当前进程 busy”：目标或 sibling 被 DPDK 保留时，即使进程暂时退出且具备 boot claim，
VM 方向仍返回 `DENIED(HOST_DEVICE_RESERVED)`，绝不能建议重启；从 passthrough 归还 host 则允许。

#### 8.4.3 VM admission 的独占 attach lease

Host owner 已激活不等于设备对某个 VM 可分配。调度器必须把已选 payload 展开为
`exclusiveAttachGroup`，并在任何 QEMU fd、IOMMU mapping 或 guest resource 分配前原子加锁：

```python
function acquireAttachLeases(vm, selectedDevices, snapshot):
    groups = expandExclusiveAttachGroups(snapshot, selectedDevices)
    require every group is complete and generation-current

    # ESXi 8.0.3 shared-dependent 实测中，同 VM 双 function 仍冲突；
    # 因此默认不以 vmId 相同为由合并重复 group。
    if count(groups) != count(unique(groups)):
        require exactQualificationAllowsSharedAttach(selectedDevices)
        otherwise return DENIED(EXCLUSIVE_ATTACH_GROUP_COLLISION)

    return store.atomicMultiKeyLease(
        keys=sort(unique(groups)), owner=vm.runId,
        expectedSnapshotEpoch=snapshot.snapshotEpoch,
        expectedHostEpoch=store.currentHostEpoch(snapshot.hostId),
        expectedRunGeneration=store.currentRunGeneration(vm.id) + 1)
```

qualification 若要放宽，必须精确绑定 VID:DID/subsystem/revision/firmware、reset contract、DMA
isolation、错误恢复和 teardown 证据；不能按 class、vendor 或“同 VM”全局放宽。

#### 8.4.4 Lease 后的 live executor

```python
function executeLiveActivation(plan, ownerGroup, activationLease):
    require plan.disposition in {ALREADY_ACTIVE, LIVE_APPLY}
    require activationLease atomically owns every ownerGroup member
    require activationLease also covers required isolation/reset safety closures
    require current epoch/generation/identity/ownerGroup hash == plan inputs

    if plan.disposition == ALREADY_ACTIVE:
        observed = readEffectiveOwnersAndProviders(ownerGroup)
        require observed exactly matches plan.desiredOwner
        return observed

    journal = durableJournal(PREPARING_ACTIVATION, plan, activationLease)
    rollback = RollbackStack()
    try:
        for member in ownerGroup.hostQuiesceOrder:
            token = quiesceHostConsumers(member, deadline)
            rollback.push(restoreHostConsumers(member, token))

        for member in ownerGroup.unbindOrder:
            original = readDriverAndOverride(member)
            unbindNativeDriver(member)
            rollback.push(restoreDriverAndOverride(member, original))

        for member in ownerGroup.vfioHoldOrAssignMembers:
            setDriverOverride(member, "vfio-pci")
            bindVfio(member)
            rollback.push(unbindVfioAndRestoreOverride(member))

        observed = readEffectiveOwnersProvidersGroups(ownerGroup)
        require every expected member has target owner/provider
        require no unexpected member changed owner
        require kernel group viability and physical-domain lease still hold
        journal.commit(ACTIVE, observedHash=hash(observed))
        rollback.disarm()
        return observed
    except error:
        failures = rollback.runReverse()
        if failures or effectiveOwnerCannotBeProved(ownerGroup):
            quarantine(ownerGroup, ACTIVATION_ROLLBACK_UNCERTAIN, evidence())
        else:
            journal.commit(ROLLED_BACK, observedHash=hashCurrent(ownerGroup))
        raise stableActivationError(error, failures)
```

默认 `bind-on-lease` 使用这条路径。live apply 因 Busy 失败时，Qman 先完成 rollback；只有另一个
显式 maintenance 请求才可写 `PENDING_REBOOT`，不能像 UI 便利逻辑一样悄悄留下 desired/current
分离。disable 走同一事务的反向路径，但必须先证明无 VM lease、QEMU/VFIO fd、DMA mapping 和
IRQ owner。

#### 8.4.5 Early-boot claim

“重启可能解决”必须对应真实实现。仅执行 Linux reboot 而没有 boot-time owner policy，native
driver 会再次先绑定，结果仍然 Busy。生产实现优先采用一个小型 kernel early-owner hook：

```python
function pciDeviceAddedEarly(dev, signedBootOwnerManifest):
    entry = exactMatch(dev.firmwarePath, dev.physicalSlot,
                       dev.vendorDeviceSubsystemRevision,
                       signedBootOwnerManifest)
    if entry is null:
        return NORMAL_DRIVER_PROBE
    if entry.ownerGroupManifestIncompleteOrHashMismatch:
        markActivationFailed(entry.ownerGroupId)
        return NORMAL_DRIVER_PROBE
    dev.driver_override = "vfio-pci"
    recordEarlyClaimCandidate(entry.ownerGroupId, dev)

function reconcileBootActivation(ownerIntent, currentBootId):
    observed = readOwnerGroupOwnersProviders(ownerIntent)
    if identityAndOwnerGroupMatch(ownerIntent, observed) and allBoundToVfio(observed):
        casIntent(PENDING_REBOOT, ACTIVE,
                  appliedBootId=currentBootId,
                  observedStateHash=hash(observed))
    else:
        casIntent(PENDING_REBOOT, FAILED,
                  reason=ACTIVATION_OBSERVED_STATE_MISMATCH)
        quarantineAnyPartiallyClaimedMembers(observed)
```

boot manifest 必须在 PCI driver probe 前可用并经过签名/secure-boot policy 校验；只用
`vfio-pci.ids=VID:DID` 不合格，因为会抢走同型号 host-critical device。initramfs/udev 方案只有在
所有相关 native driver 都是 module、且 probe ordering 已逐 build 验收时才可作为 profile；存在
built-in driver 或 ordering unknown 时必须使用 kernel hook 或返回 `BOOT_CLAIM_UNSUPPORTED`。
Qman 永不自动 reboot；maintenance orchestrator 负责 host drain、显式批准、reboot 和 O07
reconcile，失败后不启动任何 DirectPath VM。

## 9. Static DirectPath 事务

### 9.1 持久请求

持久 wire 只有
[`directpath-portable-entities.schema.json#/$defs/ENTITY-VM-DIRECTPATH-REQUEST`](contracts/directpath-portable-entities.schema.json)
这一种 closed projection：

```python
record VmDirectPathRequestWire:
    subjectType: const("VM_DIRECTPATH_REQUEST")
    schemaVersion: const(1)
    vmId: Id
    requestVersion: uint64
    requestType: enum(STATIC, DYNAMIC)
    canonicalRequest: StaticCanonicalRequest | DynamicCanonicalRequest
    requestHash: SHA256
    requiredGuestAbiClass: Id
    lifecyclePolicy: StaticLifecyclePolicy | DynamicLifecyclePolicy
    requestedBy: Id
    createdAt: Timestamp
    resourceVersion: uint64

record StaticCanonicalRequest:
    schemaVersion: const(1)
    vmId: Id
    requestVersion: uint64
    requestType: const(STATIC)
    selector: {
        selectorType: const(STATIC_FIXED_IDENTITY_SET),
        members: CanonicalSet[{
            requirementId, deviceUid, identityFingerprint, enrolledHostId,
            expectedPhysicalPathProvider, expectedPhysicalPath,
            expectedCurrentBdf, guestSlot
        }]
    }
    hostAffinity: {mode: const(EXACT_HOST), hostId: Id}
    requiredGuestAbiClass: Id
    lifecyclePolicy: StaticLifecyclePolicy
    profileBinding: ProfileBinding
    snapshotConstraint: ResolveCurrentAtOperation | PinnedCurrentSnapshot
    policyBinding: PolicyBinding
    mutationPrecondition: MutationPrecondition
    idempotency: IdempotencyBinding
    requestedBy: Id
    issuedAt: Timestamp
```

外层 `vmId/requestVersion/requestType/requiredGuestAbiClass/lifecyclePolicy/requestedBy` 必须与
`canonicalRequest` byte-equal，`createdAt=issuedAt`，`requestHash` 只覆盖 canonical request；这些是
索引 projection，不是可单独修补的第二份输入。`snapshotConstraint` 只能是
`RESOLVE_CURRENT_AT_OPERATION(maximumAgeMicros)` 或携带完整 HostSnapshot binding 的
`PINNED_CURRENT_SNAPSHOT`。前者由 repository 解析当时唯一 current pointer，后者要求
`hostId/kernelBootId/hostEpoch/agentGeneration/hostAuthorityResourceVersion/snapshotEpoch/snapshotContentHash`
全部 byte-equal current pointer；二者均检查最大年龄并签发同一种 sealed binding，不接受 loose
minimum-epoch/boot/hash/BDF tuple。`deviceUid` 包含按 `IDENTITY-V1` 生成的 host-scoped immutable identity fingerprint；BDF 只用于
定位，location/BDF 变化也必须显式 re-enroll。Static request 默认 host-affine，离开原 host时返回
`STATIC_DEVICE_HOST_AFFINITY`，不会在目标 host 找一张“看起来一样”的卡。

Static admission 先分别验证 closed request 与 self-hashed
[`CapabilityPolicy`](contracts/directpath-capability-policy.schema.json)，并要求 request 的完整
`policyBinding` byte-equal policy 导出的 binding。唯一 typed constructor 从 verified Static selector
派生 `ClosureRequest.payloadDeviceUids` roots、从 verified policy 派生 `maxDevices/maxEdges` limits，
并分别绑定 requestHash/policyHash provenance；调用方不能自传 roots 或放宽 limits。ClosureRequest
严格等于
[`directpath-dependency-closure-request.schema.json`](contracts/directpath-dependency-closure-request.schema.json)，
成功求值必须一起返回 exact DependencyBundle 和 `RESET_CONTRACT_SET`。policy currentness、trusted time、
approval 和 persisted request row currentness 由 read guard 与 product authority 证明；该 typed 链目前只
覆盖 verified Static request，不能把 Dynamic selector 当成已实现。

最终 `read_guard` 只接受 factory 生成的 `VerifiedStaticCapabilityContext`；它不可分地组合
`VerifiedStaticInventoryClosureContext` 与同一 admission 派生的
`VerifiedStaticQualificationBindingContext`，不得再分别传 admission、facts、roots/limits、closure
result 或一个调用者自报的 profile hash。它重放两个 factory，校验同一 request/policy admission，
从 retained verified inventory/request/policy 重新投影七类 facts 并重跑 resolver，再绑定 committed
HostAuthority resourceVersion、current policy pointer、trust root/ring、catalog/anchor、qualification
record/signer/profile/receipt、inventory receipt/verifier、request/availability read set 和 before/after
current vector。所有 verifier-produced Python context 均无公开构造器且不支持
`dataclasses.replace`；这是进程内误用防护，不替代 repository 的 linearizable read、OperationLease
或 CAS。

`OP-QUERY-DIRECTPATH` 的产品适配器还必须生成 closed
[`QueryReadTrace`](contracts/directpath-query-read-trace.schema.json)：在数据库强制只读 transaction
中保存 actual canonical row bytes 与九类 exact predicate observation，分别覆盖 current authority、
完整 snapshot/device scope、overlapping lease、uncleared quarantine、host journal head、side-effect
counter 和 reset occurrence。before/after state 必须逐字节相同，repository commit clock、journal
head 与 counter/reset vector 不变，write/affected rows 为零；query output 固定四个 canonical set
顺序并返回 decision/semantic/query-state hashes，但不携带 `traceDigest`，从而没有 output/trace hash
固定点。decoder、SQL/API log、fake provider 或 digest-only 引用均不能替代 observed instance。该
contract 和 reference verifier 只是 C15 的 component premise，不改变其
`PRODUCT/IMPLEMENTATION_BLOCKED` 状态。

Qualification Profile 必须沿单一无固定点流水线构造：递归 E4 已验证且属于 current catalog 的 exact
QualificationRecord → 不含 receipt/profile hash 的
[`directpath-qualification-profile-projection.schema.json`](contracts/directpath-qualification-profile-projection.schema.json)
→ 绑定 verifier/schema、E4、catalog/anchor/freshness、trust/root-ring 与 validity horizon 的
[`directpath-qualification-verification-receipt.schema.json`](contracts/directpath-qualification-verification-receipt.schema.json)
→ `verificationReceiptHash=receiptDigest` → `profileHash=null` 最终重放。request 的
`profileId/profileHash/verificationReceiptHash/requiredSupportStatus`、`requiredGuestAbiClass` 与 policy
catalog/ring tuple 必须从同一个 factory-only qualification binding 校验；catalog freshness receipt、
context/dependency digest 或 exact key 不能被重命名成 Profile receipt/hash。projection schema 的
`x-qmanProfileSemanticProjection` 另行固定 `profileSemanticDigest`：它包含 profileId 与完整 runtime、
ABI、workload、revocation/support semantics，但排除 record/catalog/receipt/profile hash 等
currentness coordinates。语义缓存可在内容等价时复用计算，旧 admission authorization 仍因任何
current vector 变化而失效。

产品 adapter 的 public admission API 严格接收
[`StaticAdmissionCommand`](contracts/directpath-static-admission-command.schema.json) 的业务命令：
`commandId/vmId/runId/idempotencyKey/actor/deadline/requestReference/commandHash`。它不接收 caller
自报的 read set、current vector、CAS expectation、lease、binding、decision 或 resourceVersion。
adapter 在一个 `SERIALIZABLE READ-WRITE` transaction 内读取并验证 current authority，先锁
`GLOBAL_DIRECTPATH_AVAILABILITY` row，再做 availability absence read，运行 portable core，重读
before/after vector，然后用真实逐行 expectation 原子创建
`ASSIGNMENT_PREPARE OperationLease`、单一 guarded bundle reservation、
[`directpath-operation-admission-binding.schema.json`](contracts/directpath-operation-admission-binding.schema.json)、
AssignmentRun、versioned idempotency record、audit 和 outbox，并递增 availability authority。
`OperationAdmissionBinding` 保存 exact immutable blob references 与 exclusive validity window，但明确
不是 transaction/CAS proof；repository 必须对 `operationLeaseSpec.operationLeaseId` 建 UNIQUE
一对一约束，并把最终 `bindingHash` 写入 live OperationLease 的非空
`admissionBindingHashOrNull`。commit 后只返回
[`CommittedStaticAdmission`](contracts/directpath-committed-static-admission.schema.json)，其 lease
capability 可以逐字段投影到 operation envelope，且 idempotency natural key 为
`[operationId,idempotencyScopeHash,idempotencyKey]`。commit 后第一项 host side effect 前仍须重读
live lease/binding、要求 capability/binding hash 完全一致、检查版本/时间并 fsync journal INTENT；
任一步失败时副作用次数为零。

`qman-directpath-reference` 的 SQLite WAL/FULL 实现只用于
`REFERENCE_SQLITE_TRANSACTION_COMPONENT_ONLY`：它可执行验证 command-only boundary、单文件 writer
serialization、global phantom fence、idempotency replay 和进程崩溃原子性，但不证明 Qman 私有
repository、PostgreSQL `SERIALIZABLE`/SSI、分布式 leader fencing、断电耐久或任何真实 host side
effect，因此不得关闭 PRODUCT Case 或推进产品状态轴。

### 9.2 状态机

```mermaid
stateDiagram-v2
    [*] --> REQUESTED
    REQUESTED --> PLANNED: decision + bundle + plan
    PLANNED --> PREPARING: durable lease acquired
    PREPARING --> ATTACHED: QEMU and observed plan committed
    ATTACHED --> RELEASING: power-off / crash cleanup
    RELEASING --> FREE: teardown and post-reset verified

    PLANNED --> FAILED: admission rejected
    PREPARING --> ROLLING_BACK: attach step failed
    ROLLING_BACK --> FREE: compensation verified
    ROLLING_BACK --> QUARANTINED: cleanup uncertain
    RELEASING --> QUARANTINED: cleanup uncertain
    QUARANTINED --> FREE: audited remediation
```

`ATTACHED` 是唯一对 VM runtime 宣告设备可用的提交状态；QEMU 进程存在、QMP 返回 success、
VFIO fd 已打开都不是提交点。

### 9.3 Power-on 时序

```mermaid
sequenceDiagram
    participant API as Qman API
    participant S as scheduler
    participant P as snapshot authority
    participant L as PostgreSQL repository
    participant H as Host Agent
    participant V as VFIO backend adapter
    participant Q as QEMU
    participant G as guest probe

    API->>S: StartStatic(vm, deviceUid, profile, epoch)
    S->>P: read current signed full-host snapshot
    P-->>S: boot + epoch + topology + exact launch facts
    S->>S: evaluate + bundle + resource plan
    S->>P: authorize exact snapshot members/generations
    P-->>S: sealed launch authorization
    S->>L: CAS acquire complete bundle
    L-->>S: lease + run generation + host epoch
    S->>H: Prepare(run manifest hashes, lease)
    H->>H: verify snapshot, identity, run generation, host epoch
    H->>H: execute/verify complete-bundle owner activation
    H->>V: open scoped reset-provider handles
    H->>V: re-query reset set and execute reset
    H->>H: re-plan after reset
    H->>P: PRE_GRANT full-host revalidation
    H->>V: prepare exact-profile launchGrant
    H->>P: PRE_SPAWN revalidation
    alt current Legacy TYPE1
        V-->>H: AUTHORIZED_DEVICE_PATH(BDF/group/type)
        H->>H: create uid/mount/cgroup/LSM/sysfs sandbox
        H->>Q: launch vfio-pci,host=exact BDF
    else future cdev/IOMMUFD profile
        V-->>H: AUTHORIZED_FD_BUNDLE(cdev/IOMMUFD fds)
        H->>Q: pass fds and launch frozen profile
    end
    Q-->>H: QMP ready and devices realized
    H->>V: collect /proc fd + QMP backend receipt
    H->>G: collect BAR, ACPI, IRQ heartbeat
    H->>V: verify DMA-domain/IRQ ownership
    G-->>H: observed plan evidence
    H->>L: commit ATTACHED manifest
    L-->>API: assignmentId
```

### 9.4 Attach step 与补偿

| 顺序 | 动作 | 成功证据 | 失败补偿 | 补偿不确定时 |
| --- | --- | --- | --- | --- |
| 0 | CAS lease 完整 bundle | version/run generation/host epoch/members | 删除未产生副作用的 lease | 保留 lease，人工审计 store |
| 1 | 获取 sealed snapshot launch authorization，核对 boot/epoch/topology/identity/group/generation | current signed snapshot；完整 group/member facts；authorization hash | 释放 lease，重新规划 | inventory/auth unknown 时保留 lease |
| 2 | 执行完整 bundle owner activation | 每个成员 current owner/driver 读回匹配 | 按 journal 恢复原 owner | quarantine bundle |
| 3 | 执行精确 profile backend admission | identity/group hash、完整 members 与 `noiommu-*` 反证匹配；当前 Legacy 的 group node/viability 和 profile-pinned TYPE1 值成立，未来 cdev 的 devt 成立；禁止 fallback | 恢复 owner | quarantine |
| 4 | re-query 并执行 reset | affected set 相同、reset + state probe | release-side reset/rebind | quarantine affected set |
| 5 | reset 后重新探测 BAR/plan | plan/ABI hash 与 admission 相容 | 逆序清理 | quarantine if BAR identity unstable |
| 6 | backend adapter 从 sealed authorization 生成 typed `launchGrant` | Legacy=`AUTHORIZED_DEVICE_PATH`，绑定 exact BDF/group/TYPE1 和 sandbox policy；未来 cdev=`AUTHORIZED_FD_BUNDLE`，绑定精确 devt/fd；authority/boot/epoch/identity/generation 全绑定 | 撤销 grant、关闭 fd/namespace | quarantine |
| 7 | `PRE_SPAWN` 复核后启动 stock QEMU | Legacy QEMU 5.0 运行于 transient uid + mount namespace + device cgroup/LSM + read-only sysfs，只能打开授权 group；未来 cdev 才继承 fd；pidfd 与唯一 QMP 成立 | kill QEMU、等待 VFIO fd teardown、销毁 sandbox | quarantine |
| 8 | backend receipt + observed plan/guest heartbeat | receipt 绑定 pid/starttime、argv hash、授权 BDF/group、`/proc/$pid/fd` device identity、QMP/QOM identity、lease/run generation；另有 ACPI+BAR+IRQ/DMA assertions | kill QEMU、逆序清理 | quarantine |
| 9 | commit manifest | store state `ATTACHED` | reconcile 依据 pidfd/fd state 决定 | 保持 PREPARING，禁止重分配 |

当前 Legacy grant 的 canonical 最小合同如下；它是 authorization，不是可复用 raw argv：

```text
LegacyLaunchGrant(kind=AUTHORIZED_DEVICE_PATH)
  authorizedBdfs[]             exact segment:BDF set from sealed snapshot
  authorizedGroups[]           exact group id, members and /dev/vfio/<group> identity
  configuredIommuType          exactly TYPE1v2 or TYPE1 from profile
  preopenedDeviceFdPassing     false
  transientIdentity            per-run uid/gid + run generation
  vfioMountView                /dev/vfio/vfio + authorized group nodes only
  deviceCgroupOrLsmAllowlist   QEMU base devices + authorized VFIO device identities
  readOnlySysfsView            authorized BDF/group facts only
  ioctlPolicy                  VFIO_SET_IOMMU permits configuredIommuType only
  monitorPolicy                one controlled QMP endpoint; no alternate/raw entrypoint

LegacyAttachReceipt
  qemuPidStarttime + canonicalArgvHash
  authorizedBdfAndGroup + procFdDeviceIdentity
  qmpQomDeviceIdentity + selectedLegacyIommuType
  leaseId + runGeneration + hostEpoch + snapshot/profile/plan hashes
```

未来 `AUTHORIZED_FD_BUNDLE` 复用相同外层字段，但用 cdev/IOMMUFD fd identity 替代 path/sandbox
选择器；两种 grant 不能互相转换或在同一 run 中 fallback。

补偿动作必须在执行正向动作前压入 rollback stack，并携带 deadline。不能在 catch block 里根据
“通常做过哪些步骤”临时猜测。

### 9.5 Attach 伪代码

```python
function attachStatic(vm, request):
    validateClosedEntity(request, ENTITY_VM_DIRECTPATH_REQUEST)
    require request.requestType == STATIC
    canonical = request.canonicalRequest
    require canonical.requestType == STATIC
    require canonical.selector.selectorType == STATIC_FIXED_IDENTITY_SET
    require canonical.hostAffinity.mode == EXACT_HOST
    require indexedProjectionByteEqualsCanonical(request)
    require hashCanonical(canonical) == request.requestHash
    replay = idempotency.lookup(
        canonical.idempotency.idempotencyScopeHash,
        canonical.idempotency.idempotencyKey,
        request.requestHash)
    if replay exists:
        return replay

    profile = resolveExactProfileBinding(canonical.profileBinding)
    snapshotAuthorization = inventory.authorizeLaunch(
        hostId=canonical.hostAffinity.hostId,
        snapshotConstraint=canonical.snapshotConstraint,
        requestedDeviceUids=sorted(m.deviceUid for m in canonical.selector.members))
    # authorization 必须一直存活到 Popen；它只暴露 sealed snapshot facts。
    snapshot = snapshotAuthorization.snapshot
    selected = resolveStaticMembersExact(
        snapshot, canonical.selector.members,
        requireIdentityFingerprint=true,
        requireEnrolledHostAndPhysicalPath=true,
        requireExpectedCurrentBdf=true)
    decision = evaluateStaticSet(
        snapshot, selected.currentBdfs,
        vm.context.withRequestHash(request.requestHash), profile, policy)
    require decision.attachable == true
    require decision.activationDisposition in {ALREADY_ACTIVE, LIVE_APPLY}

    runRequest = newRunRequest(
        runId=newRunId(),
        vmId=vm.id,
        expectedRunGeneration=store.currentRunGeneration(vm.id) + 1,
        expectedHostEpoch=store.currentHostEpoch(snapshot.hostId),
        expectedSnapshotEpoch=snapshot.snapshotEpoch)
    lease = acquireBundleLease(runRequest, decision.bundle, snapshot)
    leaseAuthorization = authorizeLeaseForLaunch(lease)
    # leaseAuthorization 与 snapshotAuthorization 都必须贯穿 grant/render/Popen/receipt。
    rollback = RollbackStack()
    rollback.push(releaseLeaseIfNoSideEffects(lease))

    try:
        assertFresh(lease, snapshot, decision)
        assertRunGenerationAndHostEpoch(lease)

        activation = executeLiveActivation(
            decision.activationPlan, decision.bundle, lease)
        rollback.push(restoreActivationOrQuarantine(activation, lease))
        require activation.everyEffectiveOwnerMatches

        providerAdmission = vfio.validateConfiguredBackendReadOnly(
            decision.bundle,
            backendKind=profile.backendKind,
            configuredIommuType=profile.configuredIommuType,
            expectedIdentityHashes=decision.identityHashes,
            expectedGroupHashes=decision.groupHashes,
            snapshotEpoch=snapshot.snapshotEpoch,
            topologyDigest=snapshot.topologyDigest)
        require providerAdmission.noNoiommuNode
        require providerAdmission.backendExactlyMatchesProfile
        require providerAdmission.silentFallback == false

        with resetProvider.openScopedHandles(decision.bundle, lease) as resetHandles:
            freshReset = resetProvider.requeryAll(
                decision.resetContracts, resetHandles)
            require sameAffectedSets(freshReset, decision.resetContracts)
            executeAndProbe(freshReset, lease, resetHandles)

        postReset = inventory.refreshBundle(decision.bundle)
        require noIdentityOrGenerationViolation(postReset, lease)
        finalPlan = planner.plan(postReset, decision.bundle, vm, profile)
        require finalPlan.success
        require finalPlan.guestAbiSignature == decision.plan.guestAbiSignature

        launchGrant = backendAdapter.prepareLaunchGrant(
            snapshotAuthorization=snapshotAuthorization,
            leaseAuthorization=leaseAuthorization,
            requestedBdfs=decision.payload,
            backendKind=profile.backendKind,
            configuredIommuType=profile.configuredIommuType)
        require launchGrant.snapshotBinding == snapshotAuthorization.binding
        require launchGrant.members == completeAuthorizedIommuGroups(
            snapshotAuthorization, decision.payload)
        rollback.push(revokeGrantAndCloseResources(launchGrant))

        match launchGrant.kind:
            case AUTHORIZED_DEVICE_PATH:
                require profile.backendFamily == LEGACY_VFIO_TYPE1
                require launchGrant.preopenedDeviceFdPassing == false
                sandbox = launcher.createLegacySandbox(
                    transientUid=newPerVmUid(),
                    vfioNodesVisible=["/dev/vfio/vfio", launchGrant.groupNodes],
                    deviceCgroupOrLsmAllowlist=(
                        profile.qemuBaseDevices union launchGrant.deviceIdentities),
                    readOnlySysfsBdfs=launchGrant.authorizedBdfs,
                    allowedVfioSetIommu=profile.configuredIommuType,
                    noAlternateQmpOrRawLaunch=true)
                rollback.push(destroySandbox(sandbox))
                qemuSpec = launcher.renderStockQemuAuthorizedDevicePath(
                    vm, finalPlan, launchGrant, sandbox,
                    exactHostBdfs=launchGrant.authorizedBdfs)
            case AUTHORIZED_FD_BUNDLE:
                require profile.backendFamily == VFIO_CDEV_IOMMUFD
                require profile.isIndependentlyQualifiedFutureProfile
                qemuSpec = launcher.renderStockQemuFdOnly(
                    vm, finalPlan, launchGrant)

        qemuSpec.disableRootPortHotplugAndNativeHotplug()
        qemuSpec.validateBeforeSpawn()  # PRE_SPAWN full-host capture
        qemu = launcher.spawn(qemuSpec)  # 内部再次 PRE_SPAWN 并使用唯一受控入口
        rollback.push(killAndWaitFdTeardown(qemu))

        receipt = backendAdapter.collectAttachReceipt(
            qemuPid=qemu.pid,
            grant=launchGrant,
            required=[QEMU_PID_STARTTIME, QEMU_ARGV_HASH,
                      AUTHORIZED_BDF_AND_GROUP,
                      PROC_FD_DEVICE_IDENTITY, QMP_QOM_DEVICE_IDENTITY,
                      LEASE_AND_RUN_GENERATION, HOST_EPOCH])
        require receipt.matches(launchGrant, lease.runGeneration, lease.hostEpoch)
        require receipt.hasNoUnauthorizedVfioFdOrBdf
        if launchGrant.kind == AUTHORIZED_DEVICE_PATH:
            require receipt.selectedLegacyIommuType == profile.configuredIommuType
        observed = verifier.collectAndVerify(qemu, vm, finalPlan, receipt)
        if launchGrant.kind == AUTHORIZED_FD_BUNDLE:
            require observed.qemuPerformedIommufdBindAndIoasAttachForEveryPayload
        manifest = buildManifest(
            lease, decision, activation, finalPlan, launchGrant.kind, receipt, observed)
        store.commitAttached(lease, manifest, expectedState=PREPARING)
        rollback.disarm()
        return manifest.assignmentId
    except error:
        failures = rollback.runReverse(deadlines=policy.rollbackDeadlines)
        if failures or cleanupCannotBeProved(decision.bundle):
            quarantine(decision.bundle, error, failures,
                       lease.runGeneration, lease.hostEpoch)
        else:
            store.release(lease,
                          expectedRunGeneration=lease.runGeneration,
                          expectedHostEpoch=lease.hostEpoch)
        raise stableAssignmentError(error, failures)
    finally:
        leaseAuthorization.close()
        snapshotAuthorization.close()
```

VM provider 不能根据宿主全局 `unsafeNoIommuModeEnabled` 猜测结果。当前 Legacy 路径必须验证
exact group node、profile-pinned TYPE1 配置，以及 QEMU 启动后的 `/proc/$pid/fd` + QMP receipt；
未来 cdev 路径还必须验证本次打开并传递的 fd。下面是已经由 E3 runner 执行的 C21
component/probe 顺序；它记录当时对 cdev 和显式 Legacy lab branch 的 A/B，不由上面的
`attachStatic` 产品热路径先执行。函数中的 `allowLegacyLab` 是历史 runner 合同，不能据此推导
当前产品仍沿用该 branch 当时的实验定位：

```python
function acquireAuthoritativeProbe(request, allowLegacyLab=false):
    before = captureExactBdfIdentityAndCompleteIommuGroup(request.bdf)
    require hashIdentity(before) == request.expectedIdentityHash
    require hashGroup(before) == request.expectedGroupHash
    if exists("/dev/vfio/noiommu-" + before.groupId):
        reject(DEVICE_NO_IOMMU_DMA_ISOLATION)

    if before.hasVfioCdev:
        iommufd = openVerifiedCharDevice("/dev/iommu")
        ioas = ioctl(iommufd, IOMMU_IOAS_ALLOC)
        device = openCdevAfterDevtAndInodeCheck(before.cdev)
        deviceId = ioctl(device, VFIO_DEVICE_BIND_IOMMUFD, iommufd)
        hwptId = ioctl(device, VFIO_DEVICE_ATTACH_IOMMUFD_PT, ioas)
        after = captureExactBdfIdentityAndCompleteIommuGroup(request.bdf)
        require sameIdentityGroupOwnerAndNode(before, after)
        return LiveProbeSession(device, iommufd, ioas, deviceId, hwptId)
        # close: DETACH -> DESTROY IOAS -> close device/iommufd；全部 fd 都尝试关闭。

    require allowLegacyLab == true
    group = openVerifiedCharDevice("/dev/vfio/" + before.groupId)
    require ioctl(group, VFIO_GROUP_GET_STATUS).viable
    container = openVerifiedCharDevice("/dev/vfio/vfio")
    require ioctl(container, VFIO_GET_API_VERSION) == VFIO_API_VERSION
    ioctl(group, VFIO_GROUP_SET_CONTAINER, container)
    selected = firstSupported(container, [VFIO_TYPE1v2_IOMMU,
                                           VFIO_TYPE1_IOMMU])
    require selected not in {VFIO_NOIOMMU_IOMMU, UNKNOWN}
    ioctl(container, VFIO_SET_IOMMU, selected)
    device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, request.bdf)
    require sameIdentityGroupOwnerAndNode(before, captureAgain(request.bdf))
    return LabOnlyLegacySession(device, group, container, selected)
    # close: device -> UNSET_CONTAINER -> group/container；不进入产品 launcher。
```

`snapshotEpoch` 和 `topologyHash` 在该 component 中是 `CALLER_CORRELATION_ONLY`：provider 会原样
绑定到 proof，但不会据此宣告 kernel boot、ACS provenance 或整机 topology 已复核。真正的 stale
gate 是 caller 必须提供的 canonical `expectedIdentityHash` 与 `expectedGroupHash`，二者在任何
open/ioctl 前与当前 BDF identity、group ID 和排序后的完整 members 比较，attach 后再采集一次。
standalone CLI 成功只表示本进程完成 acquire/recheck/cleanup，输出
`lifecycle=ACQUIRED_AND_CLOSED`；其中的 IOAS/HWPT/device ID 已失效，不能交给 launcher。
runner 中 `firstSupported(TYPE1v2, TYPE1)` 只用于当时的 A/B 探测；产品 adapter 必须改为 exact
profile pin，并用 sandbox ioctl policy 和 receipt 证明没有选择另一个 TYPE1 值。

上段描述的是 `QMAN-E3-VFIO-PROVIDER-GATE-001` 的历史 standalone proof，必须原样保留，不能
把后续结果追写成它当时已经拥有 authoritative snapshot，也不能把 cdev PASS 改写成 Legacy
产品 proof。另一个独立结果
`QMAN-E3-STATIC-LAUNCH-ENVELOPE-001` 的 v5 run 才使用
`AUTHORITATIVE_COMPONENT_SNAPSHOT_V1`：signed full-host snapshot authorization 在 lease
authorization 外层保持 active，`open_authorized_vfio_launch_bundle()` 仅从 sealed facts 派生完整
IOMMU-group raw handles，并复用 authorization 中的 sealed capture provider；QEMU adapter 又把
snapshot authority/store/key/boot/epoch/hash、capture-provider binding 与 lease
host/authority/member/generation 同时绑定到 fd/plan hash。`PRE_OPEN`、`POST_OPEN` 和两次
`PRE_SPAWN` 全部通过后，stock QEMU 才完成 bind、IOAS allocate 与 attach。

v5 没有 independent DMA receipt，所以没有进入 `ATTACHED`；inner QEMU return code 为 0 后，
raw handles 关闭，lease/envelope 都以 claims retained 收敛到 `QUARANTINED`。这个结果证明的是
未来 cdev/IOMMUFD backend 的组件间授权连续性与 fail-closed 顺序，不是 production Controller、
production snapshot trust root、Legacy `AUTHORIZED_DEVICE_PATH` sandbox/receipt、reset/driver restore、
DMA/IRQ clean-state 或 compatibility support。

还必须区分 component probe、当前 Legacy 产品路径和未来 cdev 产品路径。E3 使用的 stock QEMU 11
`iommufd` object 和
`vfio-pci,fd=` 会在 QEMU 内部执行 bind、IOAS 分配和 attach；一个已经 pre-attach 的 live probe
session 不是可直接传给 stock QEMU 的产品接口，也不应为每次启动先做一次 bind/attach 再关闭。
未来 cdev launcher 必须在 durable lease 内重新核对 identity/group/node，打开新的 raw
cdev/IOMMUFD fd，以唯一、typed argv 继承给 QEMU，并在 QEMU 完成内部 bind/attach 和
observed-plan 验证后才提交 `ATTACHED`。

当前 Legacy 路径不同：stock QEMU 5.0 legacy `vfio-pci` 没有 passed group/device fd property，QEMU
10.2 的 `fd=` 也属于 IOMMUFD/cdev 路径，不能用于 TYPE1。Host Agent 因此生成
`AUTHORIZED_DEVICE_PATH`，只渲染授权 exact BDF/group，并在 per-VM transient uid、只挂载授权
VFIO group node 的 mount namespace、device cgroup/LSM allowlist、绑定授权 BDF 的 read-only sysfs
view 下启动 QEMU。versioned sandbox policy 还要通过 seccomp user-notification/ioctl broker（或等价
可审计机制）只允许 `VFIO_SET_IOMMU` 使用 profile 固定的 TYPE1v2/TYPE1 值；stock QEMU 尝试另一
类型时 syscall 被拒绝，不能静默降级。启动后必须用 pid/starttime、argv hash、
`/proc/$pid/fd` char-device identity、QMP/QOM device identity、实际选择的 TYPE1 值、lease/run
generation/host epoch 形成 receipt；任一额外 group/BDF/fd 或 backend type 都回滚或
quarantine。这个 path grant 不是“信任 BDF 字符串”，而是把 BDF 限定在 sealed authorization 和
OS 强制隔离中。

若未来坚持由 Host Agent 预先 attach 后再移交，只能新增 QEMU/provider ABI 并单独验收，不能把
当前 component proof 当作该能力。
当前手写 `_IO` UAPI 编码只在 `x86_64/amd64/aarch64/arm64` 开放；其他架构必须先由目标 Linux
headers 生成并验收 ioctl ABI，否则在读取 sysfs 或打开 fd 前返回 `UNSUPPORTED_IOCTL_ABI`。

host DPDK 走另一个受限 service/provider API；Qman VM launcher 不接受它产生的 group fd、UIO
fd 或 `/dev/vfio/noiommu-*`。二者还应使用不同 Unix 用户、device cgroup/SELinux policy 和
fd-passing socket，避免“scheduler 拒绝了，但运维把 DPDK fd 塞给 QEMU”的旁路。

### 9.6 Release 伪代码

```python
function releaseAssignment(assignmentId, reason):
    manifest = store.requireAssignmentManifestV2(assignmentId)
    bindings = canonicalOrderedBindings(manifest.bindings)
    leaseSet = store.requireCanonicalLeaseSet(bindings, state=ATTACHED)
    scope = canonicalReleaseScope(leaseSet, bindings,
                                  manifest.resetAffectedSets)

    # 一个 global transaction 在停止 QEMU 前取得 RELEASE typed capability、
    # 完整 lease-set guard，并把 Assignment ATTACHED -> RELEASING。
    capability, guard = store.beginReleaseTransition(
        assignmentId, leaseSet, scope,
        expectedControllerGeneration=currentControllerGeneration(),
        expectedRunGeneration=manifest.runGeneration,
        expectedHostEpoch=manifest.hostEpoch)
    require guard.leaseSetHash == canonicalHash(leaseSet)
    require guard.coversEvery(scope.bundleIds, scope.memberDeviceUids)

    stopResult = stopGuestAndQemu(manifest, deadline=profile.qemuStopDeadline)
    processGone = provePidfdStarttimeAndAllQemuVfioFdsGone(manifest)
    if not stopResult.verified or not processGone:
        store.atomicQuarantineScopeAndRetainEveryClaim(
            scope, leaseSet, QEMU_EXIT_UNVERIFIED, evidence())
        backendAdapter.retainDenyGuardForQuarantine(guard)
        return QUARANTINED

    # Stock QEMU 的 guest DMA context 随进程/fd 关闭销毁；不能假设旧 fd 可跨进程移交。
    # 在 durable guard 未释放期间获取 fresh release context，因此不存在可被第三方打开的窗口。
    releaseContexts = []
    teardownResult = []
    for binding in bindings:
        ctx = backendAdapter(binding.backendKind).acquireReleaseContext(
            capability=capability, guard=guard, binding=binding,
            exactConfiguredIommuType=binding.configuredIommuType)
        require ctx.ownerAndAffectedSetMatchManifest
        releaseContexts += ctx
        teardownResult += backendAdapter(binding.backendKind).verifyGuestDmaIrqContextDestroyed(
            binding, ctx)

    disableBusMasterAndInterrupts(scope.memberDeviceUids, releaseContexts)
    resetResult = executeQualifiedReleaseReset(
        scope.resetContracts, leaseSet, releaseContexts)
    stateResult = probePostResetState(scope.memberDeviceUids)
    irqResult = verifyNoStaleInterruptOwnership(scope.memberDeviceUids)
    closeResult = closeEveryReleaseContext(releaseContexts)

    if not allVerified(teardownResult, resetResult, stateResult,
                       irqResult, closeResult):
        store.atomicQuarantineScopeAndRetainEveryClaim(
            scope, leaseSet, RELEASE_CLEANUP_UNCERTAIN, evidence())
        backendAdapter.retainDenyGuardForQuarantine(guard)
        return QUARANTINED

    if manifest.activationMode == BIND_ON_LEASE:
        rebindOriginalDrivers(scope.memberDeviceUids)
    else:
        verifyPersistentVfioOwner(scope.memberDeviceUids)
    publishNewDeviceGenerations(scope.memberDeviceUids)
    receipt = signFullAssignmentCleanReleaseReceipt(
        guard, leaseSet, bindings, scope, evidence())
    store.atomicAcceptReceiptRevokeLeaseSetAndFreeAssignment(
        receipt, leaseSet,
        expectedControllerGeneration=currentControllerGeneration())
    backendAdapter.releaseOwnershipGuard(guard)
    return FREE
```

backend 只在 `acquireReleaseContext` 和 receipt 分叉：Legacy 必须在 `vfio-pci` owner 与 ACL 不变
时重新打开 exact group/container/device，并固定 assignment manifest 中的 TYPE1 subtype；future
cdev 重新打开 exact cdev/reset handles，但永不复用已销毁的 guest IOAS。任何失败都保持 lease 与
deny guard，并把整个 affected set 置为 quarantine；TTL、QEMU exit 或 driver 仍为 `vfio-pci`
都不能单独产生 clean-release receipt。

guest reboot 不经过 release：设备仍由同一 VM、runId 和 DMA domain（当前 TYPE1 container；未来
cdev IOAS）占有，但必须验证 reboot 后 functional heartbeat，并按 profile 执行允许的 reset/ROM 语义。

### 9.7 Guest runtime PCI hotplug 永久关闭

vSphere 8.0 U3 的 `fixedPassthruHotPlugEnabled` 是 VMware 的独立能力事实，不是 Qman 的待办。
Qman 的 `fixedPassthruHotplug`、`dynamicRuntimeHotplug` 和 `qemuNativeRuntimeHotplug` 永久为
false。API 设置该字段返回 `FEATURE_DISABLED/HOTPLUG_UNSUPPORTED`；scheduler 不创建 hotplug
capacity；launcher 不创建可热拔 slot；QMP proxy 和 sandbox 无条件拒绝
`device_add/device_del`。

对 q35/PCIe profile，仅拒绝 QMP 还不够。每个承载 DirectPath endpoint 的 root-port 都必须由
typed renderer 显式生成 `hotplug=off,x-do-not-expose-native-hotplug-cap=on`；缺少任一属性都使
launch spec fail-closed，且不能由 raw argv 覆盖。

S13-S16/F09 必须证明拒绝前后 VM definition、assignment、lease、VFIO fd、guest PCI tree、BAR
window、DMA/IRQ owner 均不变。host owner 的 `LIVE_APPLY` 发生在 VM power-on 前，不改变运行中
guest topology，因此不属于本节禁止的 device hotplug。

## 10. Dynamic DirectPath 事务

### 10.1 持久请求

```python
record DynamicCanonicalRequest:
    schemaVersion: const(1)
    vmId: Id
    requestVersion: uint64
    requestType: const(DYNAMIC)
    selector: {
        selectorType: const(DYNAMIC_ALLOWED_DEVICE_REQUIREMENTS),
        requirements: CanonicalSet[{
            requirementId,
            allowedDevices: CanonicalSet[{
                vendorId, deviceId,
                subsystemVendorId?, subsystemDeviceId?, revisionId?
            }],
            customLabelOrNull,
            requiredGuestAbiClass,
            count,
            guestSlots,
            equivalencePolicyHash
        }]
    }
    hostAffinity: AnyOnlineCooperativeHost | AllowedOnlineCooperativeHostSet
    requiredGuestAbiClass: Id
    lifecyclePolicy: DynamicLifecyclePolicy
    profileBinding: ProfileBinding
    snapshotConstraint: ResolveCurrentAtOperation | PinnedCurrentSnapshot
    policyBinding: PolicyBinding
    mutationPrecondition: MutationPrecondition
    idempotency: IdempotencyBinding
    requestedBy: Id
    issuedAt: Timestamp
```

持久对象没有 BDF、`deviceUid` 或 `assignedId`。`assignedId` 只存在于一次 `AssignmentRun`，
powered-off 后清空；下一次可以在另一 host 选择不同 BDF，但必须满足同一 ABI/resource contract。

字段语义对齐 vSphere 8.0 U3 API，但 wire 以本项目 closed schema 为准：`vendorId/deviceId` 必填，
`subsystemVendorId/subsystemDeviceId/revisionId` 是每个 `AllowedDevice` tuple 的可选精确约束；`customLabelOrNull` 是
`DynamicBackingInfo` 的同级字段，不属于某个 tuple。Qman schema 使用十六进制字符串避免 JSON
有符号数和前导零歧义，canonicalizer 校验范围后再转成 API 整数。省略可选 ID 表示该维度不约束，
不表示用 class code、名称或近似设备替代。
`guestSlots` 是有序数组且长度必须等于 `count`；展开后的 slot key 固定为
`(requirementId, ordinal, guestSlot)`，solver 不得依赖数据库或 hash-map 顺序分配 guest address。

### 10.2 Candidate 构造

```python
function buildCandidates(snapshot, requirement, vm, profile, policy):
    byEquivalence = Map[CandidateEquivalenceKey, Candidate]()

    for device in snapshot.devices.sorted():
        if not exactAllowedDeviceMatch(device, requirement.allowedDevices):
            continue
        if requirement.customLabelOrNull is not null and \
                not exactLabelMatch(device.labels, requirement.customLabelOrNull):
            continue

        decision = evaluate(snapshot, device.uid, vm.withoutMmio(), profile, policy)
        if decision.activationDisposition not in {ALREADY_ACTIVE, LIVE_APPLY}:
            continue
        if decision.bundle has blocking availability reason:
            continue
        if not abiCompatible(device, requirement.requiredGuestAbiClass):
            continue

        candidate = Candidate(
            payload=decision.payload,
            bundle=decision.bundle,
            resourceSignature=barsRmrrIrqSignature(decision.bundle),
            guestAbiClass=qualifiedAbiClass(device),
            guestAbiSignature=qualifiedAbiSignature(device, profile),
            numaNode=effectiveNumaNode(decision.bundle),
            decisionHash=decision.wire.decisionHash)
        key = CandidateEquivalenceKey(
            bundleId=candidate.bundle.id,
            payloadHash=hashCanonical(candidate.payload),
            memberActionHash=hashCanonical(candidate.bundle.memberActions),
            resourceSignatureHash=hashCanonical(candidate.resourceSignature),
            guestAbiClass=candidate.guestAbiClass,
            guestAbiSignature=candidate.guestAbiSignature)
        byEquivalence[key] = chooseStableRepresentative(
            byEquivalence.get(key), candidate,
            orderedBy=(device.uid, candidate.decisionHash))

    return stableSort(byEquivalence.values(), canonicalCandidatePreferenceKey)
```

多个 BDF 只有在 bundle、payload、member action、resource signature 和 guest ABI 全等时才去重；
仅按 bundleId 去重会丢掉 multifunction bundle 中不同合法 payload。`canonicalCandidatePreferenceKey`
固定为 exact-match specificity、NUMA rank、resource-waste tuple、deviceUid、bundleId、ABI signature、
decisionHash 的字典序，不允许 `putIfAbsent`、BDF 枚举顺序或数据库默认排序决定结果。

### 10.3 全局求解

```python
function solveDynamic(snapshot, requirements, vm, profile):
    candidates = {r.requirementId: buildCandidates(snapshot, r, vm, profile, policy)
                  for r in requirements}
    if any candidates[r.requirementId].size < r.count:
        return failure(PROFILE_NO_MATCH)

    slots = expandCountsToOrderedGuestSlots(requirements)
    slots.sortBy(fewestCandidatesThenStableId)

    function search(index, selected, usedMembers):
        if deadlineExceeded():
            return TIMEOUT
        if index == slots.size:
            plan = planner.plan(snapshot, bundles(selected), vm, profile)
            return scoredCanonicalSolution(selected, plan) if plan.success else UNSAT

        slot = slots[index]
        for candidate in candidates[slot.requirementId]:
            if intersects(candidate.bundle.members, usedMembers):
                continue
            if violatesLowerBound(candidate, selected, vm, profile):
                continue
            result = search(index + 1,
                            selected + [(slot, candidate)],
                            usedMembers union candidate.bundle.members)
            recordSolutionOrContinueSearching(result)
        return UNSAT

    search(0, [], set())
    return lexicographicallyBestRecordedSolutionOrUnsatCore()
```

完整解的 score 是所有 slot 的 canonical candidate key 拼接，再加精确 resource plan 的
`(below4GBytes, highMmioBytes, bridgeWindowBytes, virtualSlotCost)` waste tuple；不能在遇到第一个
solution 时返回。任何 greedy 结果只可作为 search 顺序提示，不能单独宣告 success。timeout 是确定性失败，保存
候选计数、剪枝统计和资源 lower bound，但不保存可能暴露其他租户 identity 的详细 owner 信息。

### 10.4 多 requirement 原子 reservation

```mermaid
sequenceDiagram
    participant S as scheduler
    participant H1 as host A agent
    participant H2 as host B agent
    participant L as PostgreSQL repository

    S->>H1: Get snapshot/candidate summary
    S->>H2: Get snapshot/candidate summary
    S->>S: solve each host, rank complete solutions
    S->>L: CAS reserve all bundles on chosen host
    alt CAS success
        L-->>S: runId + run generation + host epoch
        S->>H1: Attach selected solution
        H1-->>S: committed assignedIds
    else conflict or epoch changed
        L-->>S: conflict reason
        S->>S: discard whole solution and recompute
    end
```

多 bundle reservation 必须由一个 store transaction 或一个 canonical composite lease key 原子提交。
不允许先拿 GPU lease、再拿 NIC lease；否则失败窗口会让其他 VM 永久饥饿并产生复杂补偿。

### 10.5 双在线主机的计划性 cold relocation

该流程只在源、目标 Host Agent 都在线且 Controller 能与二者完成新鲜 host-epoch handshake 时
进入；它不是 host-failure HA：

1. Controller 在 PostgreSQL 全局事务中把 relocation 从 `ATTACHED` CAS 到
   `RELOCATING_SOURCE_STOP`，固定源 Assignment run、完整 lease set、
   source/target host epoch、run generation、profile、selector 和 guest ABI；目标端此时不能 reserve。
2. 源 Host Agent 按正常 release core 推进 `RELOCATING_SOURCE_STOP -> SOURCE_RELEASING`：先取得覆盖完整
   lease/bundle set 的 `ReleaseOwnershipGuard`，并原子推进源 Assignment `ATTACHED -> RELEASING`；
   停止 QEMU 并证明 pid/fd 消失，再在 guard 下为全部 binding 获取 fresh release context，
   完成 DMA/IRQ teardown receipt、reset/state probe 和原 owner/driver restore。
3. 源端只有在上述动作全部可证明后，才签发
   `SourceCleanReleaseReceipt`。receipt 至少绑定 source host/epoch、旧 Assignment/run generation、
   canonical lease-set hash、每个 leaseId/version/bundle/member、QEMU exit、DMA/IRQ teardown、reset、
   owner restore、证据 hash 与 `SIGNED-ENVELOPE-V1` trust chain。
4. Controller 在一个 repository transaction 中校验 receipt 签名/hash、source host epoch 和旧
   lease set 全部版本；随后一次性撤销所有旧 lease、推进源 Assignment `RELEASING -> FREE`、清除旧
   assignedId/runtime binding，并把 receipt 接受为 relocation 的 durable `sourceCleanFactVersion`，再从
   `SOURCE_RELEASING` 转入 `TARGET_SOLVE`。任一不匹配全部不提交。
5. 目标 Host Agent 读取自己的 current snapshot，重新构造 candidate 和完整 guest resource plan；
   不能复制源 BDF。新 solution 必须满足相同 `guestAbiClass`、profile 和 selector-wide RMRR contract。
6. 每个串行 target attempt 都创建新的 `targetAttemptId/targetRunId/targetRunGeneration`；目标 bundle
   lease set 与新 Assignment `PLANNED -> PREPARING` 原子提交后才执行 attach。新 `assignedId` 只写入
   新 Assignment/manifest，VM 持久 Dynamic selector 不保存源 BDF。

```mermaid
stateDiagram-v2
    [*] --> ATTACHED
    ATTACHED --> RELOCATING_SOURCE_STOP: source/target handshake committed
    RELOCATING_SOURCE_STOP --> SOURCE_RELEASING: guarded QEMU stop verified
    SOURCE_RELEASING --> TARGET_SOLVE: clean receipt plus old-lease revoke CAS
    RELOCATING_SOURCE_STOP --> HOST_UNREACHABLE: source handshake lost before clean release
    SOURCE_RELEASING --> QUARANTINED: cleanup uncertain
    TARGET_SOLVE --> TARGET_RESERVED: complete solution CAS
    TARGET_SOLVE --> STOPPED_UNSAT: no complete solution
    TARGET_RESERVED --> STOPPED_UNSAT: no host INTENT; cancel complete reservation
    TARGET_RESERVED --> TARGET_ATTACHING: Host Agent accepts generation
    TARGET_ATTACHING --> ATTACHED: manifest v2 committed
    TARGET_ATTACHING --> TARGET_ROLLING_BACK: guard plus rollback intent committed
    TARGET_ROLLING_BACK --> STOPPED_UNSAT: target clean release plus lease-set revoke
    TARGET_ATTACHING --> QUARANTINED: target cleanup uncertain
    STOPPED_UNSAT --> TARGET_SOLVE: explicit next online target attempt
```

receipt canonical shape：

```json
{
  "schemaVersion": 1,
  "receiptId": "uuid",
  "relocationIdOrNull": "relocation-uuid",
  "relocationGenerationOrNull": 4,
  "receiptNonce": "base64url-128bit",
  "sourceHostId": "host-a",
  "sourceHostEpoch": 37,
  "assignmentId": "uuid",
  "runId": "uuid",
  "oldRunGeneration": 901,
  "leaseSetHash": "sha256:...",
  "leaseBindings": [
    {
      "leaseId": "uuid",
      "leaseVersion": 19,
      "bundleId": "sha256:...",
      "memberDeviceUids": ["urn:qman:directpath:device:v1:host-a:sha256:identity"],
      "oldDeviceGenerations": {"urn:qman:directpath:device:v1:host-a:sha256:identity": 12}
    }
  ],
  "bindingsHash": "sha256:...",
  "bundleIds": ["sha256:..."],
  "bundleMembers": ["urn:qman:directpath:device:v1:host-a:sha256:identity"],
  "newDeviceGenerations": {"urn:qman:directpath:device:v1:host-a:sha256:identity": 13},
  "qemuExitProof": "sha256:...",
  "dmaIrqTeardownProof": "sha256:...",
  "iommuInvalidateProof": "sha256:...",
  "resetStateProof": "sha256:...",
  "ownerRestoreProof": "sha256:...",
  "policyHash": "sha256:...",
  "profileHash": "sha256:...",
  "evidenceHash": "sha256:...",
  "issuedAt": "2026-07-22T10:00:00.000000Z",
  "expiresAt": "2026-07-22T10:10:00.000000Z",
  "keyRingVersion": 7,
  "signerKeyId": "host-agent-key-v3",
  "receiptDigest": "sha256:...",
  "signature": "ed25519:base64url-without-padding"
}
```

`relocationIdOrNull` 与 `relocationGenerationOrNull` 必须同时为 null（普通 power-off/release）或同时
非 null（cold relocation source clean）；不得省略、混用旧字段名或只填其中一个。非 null 时
`receiptNonce` 在该 relocation generation 下唯一；digest、签名 projection、domain
separator、key role/revocation/rollback-anchor 检查全部使用 portable contract 的
`SIGNED-ENVELOPE-V1`。它证明 source assignment 已 clean，不授权任何
target device。repository 允许 receipt 在同一 relocation 中支持多个**串行** target attempt，但
唯一约束保证任何时刻只有一个 `TARGET_RESERVED/TARGET_ATTACHING`；每次 retry 递增
`targetAttemptGeneration`。target cleanup verified 后可选择另一在线 host；cleanup uncertain 则完整
target scope quarantine 且 relocation 终止。receipt 只在首次接受时检查有效期；接受后的
`sourceCleanFactVersion` 是 durable repository fact，后续 attempt 只校验该 fact/relocation generation，
不重复消费、重新签发或“复活”旧 source assignment。

完整 required fields、canonical set order、hash/null projection 与 cross-field rules 仅以
[`directpath-clean-release-receipt.schema.json`](contracts/directpath-clean-release-receipt.schema.json)
为准；本段 JSON 是字段阅读示例，不另建 receipt wire。

源 clean receipt 被接受**之前**失联、断电或网络分区时，Controller 置 `HOST_UNREACHABLE`，保留
完整源 lease set 与旧 Assignment claims，且不允许目标 reserve/attach。该状态不声称已物理停止
失联源上的 QEMU 或 DMA；源主机返回后先进入 `SOURCE_RECONCILE`，根据持久 guard/journal/物理事实
回到源 `ATTACHED`、继续 `SOURCE_RELEASING` 或 quarantine。sourceCleanFact 已接受之后源 lease 已
不存在，目标失联则撤销尚无 side effect 的完整 reservation，或对已有 side effect 的 target attempt
执行正常 rollback/quarantine；不能重新创建源 claim。V3 不调用 BMC/Redfish/IPMI，不做电源 fencing，
也不自动 HA restart。

Static 请求不执行 target re-solve；目标 host 无原 deviceUid 时保持 stopped。

## 11. Crash、reconcile 与失联不接管

### 11.1 启动时 reconcile

host agent 每次启动都先 reconcile，完成前 host 不进入 candidate pool：

```python
function reconcileHost(hostId, kernelBootId):
    runs = store.listNonTerminalRuns(hostId)
    processes = pidfdScanner.listManagedQemu()
    vfioOwners = provider.listOwnedDevices()
    hostEpoch = store.beginHostReconcile(hostId, kernelBootId)

    for run in runs:
        if run.runGeneration != store.currentRunGeneration(run.vmId):
            revokeLocalControlMutations(run)
            quarantine(run.bundle, STALE_RUN_GENERATION, evidence())
            continue

        observed = correlate(run, processes, vfioOwners)
        match (run.state, observed):
            case (ATTACHED, qemuAliveAndFdsMatch):
                verifyRuntimeOrQuarantine(run)
            case (ATTACHED, qemuMissing):
                releaseAssignment(run.assignmentId, QEMU_CRASH)
            case (PREPARING, noSideEffects):
                store.release(run.lease)
            case (PREPARING, partialSideEffects):
                rollbackFromPersistedJournal(run)
            case (RELEASING, any):
                resumeReleaseFromPersistedJournal(run)
            case (_, uncorrelatedOwnership):
                quarantine(run.bundle, OWNERSHIP_UNCERTAIN, evidence())

    store.completeHostReconcile(hostId, hostEpoch, evidenceHash())
    publishHostReadyOnlyAfterAllRunsResolved(hostEpoch)
```

### 11.2 故障矩阵

| 故障点 | 权威 owner 结论 | 自动动作 | 重新进入 pool 条件 |
| --- | --- | --- | --- |
| QEMU SIGKILL | lease 仍有效，设备不 free | pidfd 触发 release/reset | DMA/IRQ/fd/reset 全验证 |
| Host Agent SIGKILL | PostgreSQL lease 不变 | 新 Agent 取得 host epoch 后按本地 SQLite journal + 全局 run 状态 reconcile | 同上 |
| active Controller 失败 | 全局事务和 lease 不变 | standby 取得新 controller generation 后恢复 FSM；旧 Controller mutation 被 CAS 拒绝 | 新 active 与 PostgreSQL 状态一致 |
| PostgreSQL repository 短时不可用 | 不产生新 attach/release commit | 保持设备和 lease，停止调度 | store 恢复并校验 CAS version/generation/epoch |
| 源 host 网络隔离 | 原 host 可能仍运行或 DMA，lease 保留 | 标记 `HOST_UNREACHABLE`，VM 产品状态 stopped，目标不 reserve/attach | 源返回并完成 host/owner/release reconcile |
| 源 host 断电 | owner/clean release 未证明，lease 保留 | 标记 `HOST_UNREACHABLE`，不在目标重启 | 源返回，以新 boot/host epoch 完成 reconcile |
| source clean-release receipt 缺失或 stale | 源 claim 未安全关闭 | cold relocation 保持 stopped，不进入 `TARGET_SOLVE` | 新鲜完整 receipt 经全局 CAS 接受 |
| reset affected set 改变 | 原 plan 作废 | 不执行 reset，rollback | 新 snapshot/plan/lease |
| QEMU 启动后 BAR 漂移 | 未提交 assignment | kill、teardown、profile invalidated | 新 qualification 通过 |
| live owner transition 部分完成 | bundle owner 不确定，禁止启动 QEMU | 按 journal 回滚；回滚不完整则 quarantine | 所有成员 effective owner/driver 与目标状态一致并有读回证据 |
| boot claim 与运行时 identity 不匹配 | 设备仍归原 host owner，不可分配 | 拒绝激活并报警，不按 VID:DID 猜测 | exact identity/path/bundle 重新发现并生成新 intent |
| release reset/state probe 失败 | bundle 仍归旧 run/quarantine | 禁止 rebind/重分配 | 人工或自动 remediation 证明 clean |

### 11.3 Generation、lease 与失联底线

- PostgreSQL CAS version、run generation、controller generation 和 host epoch 进入 Controller/Host Agent
  RPC、launch grant、receipt、lease 与 manifest，用于拒绝 stale control mutation。
- 这些逻辑 epoch 不会物理停止 QEMU 或 DMA，不能当作 clean release receipt。
- 源主机失联时必须保持 `HOST_UNREACHABLE`、保留 lease 和 stopped/no-reassignment 状态；V3 没有
  BMC/power fence 或 host-failure automatic HA 的旁路。
- store 中的 lease expiration 不是硬件释放证明；TTL 到期只能触发 reconcile，不能直接 free。
- 源主机返回后必须先用新 boot ID/host epoch 完成 inventory、process、VFIO owner、journal 和全局
  run 的关联；只有 clean release CAS 成功，设备才可重新进入 pool。

## 12. QEMU、firmware 与 guest surface

### 12.1 Renderer 输入

QEMU renderer 只接受已签名/哈希的
`ResolvedDirectPathProfile + VmResourcePlan + backend-specific launchGrant`。
它不重新计算 capability、bundle 或 Dynamic candidate。关键输出：

```text
machine type and compatibility version
stable root ports/PXB topology and guest slots
OVMF/SeaBIOS image digest
OVMF X-PciMmio64Mb where applicable
host-bridge pci-hole64-size floor
IOMMU model and interrupt-remapping policy
Legacy: exact authorized vfio-pci host BDF + sandbox manifest, no passed VFIO fd
Future cdev/IOMMUFD: typed inherited fd references, no host BDF fallback
ROM policy and digest
AER/PME/ReBAR/SR-IOV/ATS surface policy
QMP command allowlist and migration blockers
```

不同 QEMU 版本的具体 property 名由 versioned adapter 映射；profile 保存渲染后的 canonical
argv/QOM manifest，升级不能静默改变 property 默认值。stock QEMU 5.0 Legacy 固定使用
`vfio-pci,host=<authorized-BDF>`，当前 QEMU 10.2 Legacy profile 也使用同一路径；`fd=` 只允许
出现在未来 cdev/IOMMUFD profile，不能按 property 探测结果在运行时切换 backend。

### 12.2 AER parity profile

ESXi 8.0 U3 的被测外部模型必须按两个 profile 实现和验收：

| Profile | 已验证边界 | 禁止外推 |
| --- | --- | --- |
| 历史 `e1000e/status-projection` | guest 不发现 endpoint AER capability，ACPI 不授予 AER ownership，raw body 可看到部分 status；endpoint/Root Port CERE 与 Root COR_EN 均为 0 | ERR_COR delivery、Root service、IRQ、clear 与 health handling |
| `virtio/controlled-route` | PassthruIdle Receiver 的 8 个 E/M/R tuple 8/8；只有 `g100/g101` 的 frozen outer-QEMU snapshot 出现 Root `COR_RCV+Source`。Active guest 可发现 AER header `0x00020001` 且 raw CES `0→1`，但 Linux AER totals `0→0`、无 kernel event | ESXi service/IRQ 归因、bounded log 之外的处理、guest write、lifecycle recovery 与物理设备行为 |

controlled-route result SHA-256 为
`655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1`。
frozen snapshot 是 ESXi vCPU 暂停时读取的 QEMU fabric 状态，不是 ESXi service/IRQ receipt；
恢复运行后的有界日志窗没有语义 AER/PCI error event，也不能解释成 no service。capability
可发现、raw status 可见和 service/event delivery 是三个独立观察面。

2026-07-26 的 QEMU 11.0.2 root-state public-model 正控又完成 First/Multiple、
Endpoint/Root 独立 W1C、B0/B1 OR 与 re-arm，每项三次 fresh-process，形成 12/12
formal evidence；聚合 result SHA-256 为
`59839df23f9711162f4d8548b7e258e355957bda23348f6acd727eb219decb5b`。
2026-07-29 的 canonical V17 `20260729-esxi8-aer-root-o4-v17-full1` 已在 O4/`g101`
完成相同四个 sequence 各 3 次，得到 12/12 `MATCH`、`FULL_PLAN`；离线 exact 与
`--require-complete` 校验均通过。冻结
[`campaign result`](evidence/esxi8-aer-root-o4-v17-full1-20260729-campaign-result.json)
SHA-256 为
`847a2500ae868a47d1abe8ae9765848085f8c31605afaa74b78cbc1923d40b7f`，并由 canonical
[`result record`](evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json) 与
[`summary`](evidence/esxi8-aer-root-o4-v17-full1-20260729-summary.json) 登记。
2026-07-30 的 canonical V19 `20260730-esxi8-aer-root-o0-v19-full1` 又在 O0/`g101`
完成相同四个 sequence × 3，得到 12/12 `MATCH`、`FULL_PLAN`。canonical
[`result record`](evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json)、
[`summary`](evidence/esxi8-aer-root-o0-v19-full1-20260730-summary.json) 与
[`campaign result`](evidence/esxi8-aer-root-o0-v19-full1-20260730-campaign-result.json)
SHA-256 分别为 `538aaf8c…310b`、`5a58f4de…dff`、`b2ab49a2…c6d6`。V19 与 V17 的
12 对 `evaluation-input.snapshots` 逐字段 exact，并冻结为
[`O0+O4 observed profile`](contracts/vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json)
（SHA-256 `cafa0835…1a6e`）及
[`promotion receipt`](evidence/esxi8-aer-root-g101-o0-o4-profile-promotion-20260730-summary.json)
（SHA-256 `fab09980…12a`）。
该闭环只授权 exact build/device/QEMU/`g101` 的 O0+O4 外部寄存器状态。O0 目标
`Module Name=None`，未证明 bound native driver，也不证明 owner-independent VMware
私有机制、service/IRQ、其他 gate、guest write、lifecycle 或物理 qualification。它不关闭
M26、M06、R13、G1-G6。
当前本地 AER guest fixture ISO SHA-256 为
`3DE27D166EE6881BFB60D8DA233A0B3E6871532108D01D5741C8A43BA91777DE`，
build attestation SHA-256 为
`103941485D8B1679D6DA18312025F5155F4A027F86EFA99E5BAD2FAA66FD67C1`；
离线冻结账本 SHA-256 为
`bae6e1e0d552a2d2859250a3ac61448c010df37f27903c774e79713f8f90cf23`。
ISO/attestation 与该账本分别只绑定 build 输入和离线 harness/source 回归，不构成 ESXi
行为证据。

[Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/)规定
DirectPath PCI error 由 ESXi 处理、而不是作为错误交给 guest；它没有公开
notification/service/recovery 实现，也不要求所有 profile 都隐藏 guest AER header 或 raw
status；
[KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
只公开 `pcipDisablePciErrReporting` 的配置含义。
[Linux AER](https://docs.kernel.org/PCI/pcieaer-howto.html)和
[QEMU 11.0.2 AER 源码](https://gitlab.com/qemu-project/qemu/-/raw/v11.0.2/hw/pci/pcie_aer.c)
只作为通用/reference oracle，不能反推 VMware 私有 service 实现。

产品化需要同时实现：

1. 使用 versioned `aerPolicy`，分别声明 guest capability、`_OSC` ownership、body read、body
   write、endpoint reporting owner、Root service owner、Correctable threshold 与 lifecycle
   clear policy；不允许用一个 `hideAer=true` 代替这些语义。
2. 只在 profile 要求隐藏时，VFIO extended-capability chain 才跳过 AER header并保持 next
   pointer 正确；CES/CEM/CERE、Root Command 等字段的 read mask、write mask 和 side effect
   分别定义。隐藏 header 不代表 hidden body 的 guest write 已隔离，公开 header 也不代表
   guest 已获得 service。
3. synthetic Root Port 是否创建 AER Root service、`_OSC` 是否授予 AER，必须与 endpoint
   surface 一起由 profile 固定；不能只改 config space 或 ACPI 一侧。
4. host agent 分开采集 `STATUS_DEPOSITED`、`MESSAGE_RECEIVED`、`LOG/COUNTER_OBSERVED`、
   `HEALTH_TRANSITION` 与 `RECOVERY_RESULT`，并关联 `deviceUid`、`assignedId`、lease
   generation/fencing token、VM、bundle、host boot ID 和有效 owner phase。`assignedId` 标识
   本次 assignment 实例，不能代替物理 identity，也不能让旧 lease 事件污染新 owner。
5. 每次 reuse 前独立验证 endpoint/root W1C、reset 与 readback；清理不完整时拒绝重新分配。
   Correctable status 单次置位不自动等于 unhealthy/quarantine；阈值和时间窗属于显式 Qman
   策略。fatal/DPC/uncorrectable 或 clear/reset 失败进入 health/quarantine/no-reassignment，
   不承诺软件一定可恢复。
6. Legacy VFIO 与未来 cdev/IOMMUFD 复用同一 `aerPolicy`、owner state machine、审计 schema
   和 oracle；backend adapter 只提供 config filter、event source、clear/reset 与 readback。

建议的最小合同：

```text
aer.guestCapability          = hidden | visible
aer.guestOscOwnership        = denied | granted
aer.guestBodyRead            = passthrough | zero | synthesized
aer.guestBodyWrite           = deny | filtered-w1c | passthrough
aer.endpointReportingOwner   = host | guest | shared
aer.rootServiceOwner         = host | guest
aer.correctableHealthPolicy  = observe-only | threshold | quarantine
aer.lifecycleClearPolicy     = verified-reset | explicit-w1c | quarantine-on-unclean
```

M24—M29 的详细 tuple、T0—T5 artifact 和四态 oracle 见
[`vmware-aer-correctable-validation-plan.md`](vmware-aer-correctable-validation-plan.md)。Nested
QEMU/ESXi 只能形成 reference/virtual-integration 证据；真实 GPU/HBA/加速卡的链路、reset、
health 与安全复用仍须 exact tuple 的 E4 qualification。

### 12.3 其他 surface 默认值

| Surface | ESXi 8.0.3 parity 默认 | Qman/QEMU 控制 |
| --- | --- | --- |
| ReBAR | guest resize 不支持 | capability 过滤/只读；effective size 固定进 plan |
| PF SR-IOV | guest 不创建 VF | 隐藏/只读 VF Enable、NumVFs，或拒绝 PF |
| PME | host-owned，不通知 guest | `_OSC` + PM config + message path 联合过滤 |
| Expansion ROM | 默认不执行 | `rombar=0`；显式 profile 要求 digest/签名和 reboot marker |
| P2P | 默认拒绝 | backend/profile gate；单独 allow 不足以通过 |
| ATS/PRI/PASID | parity 不承诺 | 默认隐藏；独立 native profile 才可 qualification |
| migration | 不支持 vMotion | QEMU migration blocker + API/QMP ACL |
| Dynamic runtime hotplug | Dynamic 只在 power-on 选卡 | baseline/Dynamic profile 拒绝 `device_add/device_del` |
| fixed passthru hotplug | ESXi 8.0 U3 存在该可选能力 | Qman 永久不支持；API、scheduler、launcher、QMP 四层稳定拒绝；见 9.7 |

### 12.4 Observed plan verifier

assignment commit 前必须同时核对：

```python
function verifyObservedPlan(plan, qemu, guest, iommu):
    assert qemu.machineAndTopology == plan.resolvedTopology
    assert qemu.qomHole64Floor == plan.qemuPciHole64FloorBytes
    assert qemu.runtimeRootWindows contain plan.mandatoryWindows
    assert every mandatory guest BAR equals planned address/size/type
    assert every bridge window contains all child resources
    assert guest.rootCrs contains planned root windows and excludes RAM/RMRR
    assert guest.irqMode in plan.allowedIrqModes
    assert iommu.attachedDevices == plan.bundleMembersRequiringDmaDomain
    assert iommu.noUnexpectedMappingsOrFaults
    return hashCanonical(allEvidence)
```

guest probe 不可用时不允许静默跳过。可定义不需要完整 guest OS 的 firmware qualification profile，
但它只能产生 firmware 证据，不能提交生产 VM assignment。

## 13. 对外 API

### 13.1 API 集合

| API | 副作用 | 主要输出 |
| --- | --- | --- |
| `GET /hosts/{id}/directpath/devices` | 无 | 六层状态、domain/bundle summary、reasons |
| `POST /directpath/evaluate` | 无 | decision、plan 或 unsat reason |
| `POST /vms/{id}/directpath/static` | 持久配置 | Static request version |
| `POST /vms/{id}/directpath/dynamic` | 持久配置 | Dynamic requirements version |
| `POST /hosts/{id}/directpath/activation-plan` | 无 | bundle 的 desired/effective owner、disposition、reason |
| `PUT /hosts/{id}/directpath/bundles/{bundleId}/desired-owner` | 维护配置 | exact boot claim、intent version、是否要求维护重启 |
| `POST /hosts/{id}/directpath/bundles/{bundleId}/apply-activation` | owner transition | 读回后的 effective owner 或 rollback/quarantine |
| `POST /vms/{id}/power-on-plan` | reservation | runId、host、selected bundle、plan summary |
| `POST /assignment-runs/{runId}/commit` | attach | assignmentId、manifest hash |
| `POST /assignments/{id}/release` | release | FREE 或 QUARANTINED |
| `GET /assignments/{id}` | 无 | binding、lease、evidence、health |
| `POST /quarantine/{bundleId}/remediate` | 高权限 | remediation run，不直接 clear |

内部 RPC 可以是 gRPC；外部 REST 名称不是强制，但语义、idempotency 和 expected version 必须保留。
上表中的 `power-on-plan/assignment-runs/commit` 是 Controller 内部 port，不得直接暴露给普通 API
caller；外部 caller 只能请求 Qman 既有 VM lifecycle operation并查询 operation。`commit` 仅由
orchestrator 在 attach receipt、runtime verifier 和 manifest v2 全部通过后调用，RBAC 不能授予
operator 手工跳过前置。

有物理副作用的 mutation 返回 `operationId` 和可选 `runId`，状态为
`ACCEPTED/RUNNING/SUCCEEDED/FAILED/QUARANTINED`；client timeout 后必须查询同一 operation。同一
idempotency key + canonical request hash 返回同一 operation；不同 hash 稳定拒绝。cancel 只在
`REQUESTED/PLANNED` 无副作用状态直接终止；进入 `PREPARING/APPLYING/RELEASING` 后 cancel 变成
受控 rollback request并保留 operation/audit，不允许删除记录。canonical operation ID、port、
request/response/reason/FSM mapping 以
[`contracts/directpath-portable-control-contract.json`](contracts/directpath-portable-control-contract.json)
为权威；内网 AI 用 integration map 绑定现有 REST/gRPC/event symbol。

### 13.2 Mutation request envelope

```json
{
  "schemaVersion": 1,
  "idempotencyKey": "client-generated-uuid",
  "expectedResourceVersion": 17,
  "expectedSnapshotEpoch": 1842,
  "profileId": "qman-x86-q35-uefi-v1",
  "request": {}
}
```

同一 idempotency key 携带不同 request hash 返回 `IDEMPOTENCY_KEY_REUSED`。超时重试返回原结果或
同一 in-progress runId，不能创建第二个 lease。

### 13.3 Error envelope

```json
{
  "status": "rejected",
  "retryable": false,
  "reason": {
    "code": "RESET_DOMAIN_CHANGED",
    "stage": "transaction",
    "devices": ["0000:65:00.0", "0000:65:00.1"],
    "details": {
      "plannedContract": "sha256:...",
      "observedContract": "sha256:..."
    },
    "provenance": "linux-vfio-uapi"
  },
  "snapshotEpoch": 1843,
  "policyHash": "sha256:...",
  "profileHash": "sha256:..."
}
```

只有明确瞬态冲突可以 `retryable=true`，例如 epoch/CAS conflict。MMIO UNSAT、qualification missing、
unsafe isolation 和 planner timeout 默认不可盲重试。

## 14. 审计、指标与证据

### 14.1 AssignmentManifest

```json
{
  "schemaVersion": 2,
  "assignmentId": "assignment-uuid",
  "runId": "run-77",
  "vmId": "vm-77",
  "requestType": "DYNAMIC",
  "hostId": "host-a",
  "profileId": "qman-x86-q35-uefi-v1",
  "snapshotEpoch": 1842,
  "topologyHash": "sha256:...",
  "policyHash": "sha256:...",
  "profileHash": "sha256:...",
  "riskRegisterHash": "sha256:...",
  "qualificationBundleHash": "sha256:...",
  "authority": {
    "leaseSetHash": "sha256:...",
    "leaseBindings": [
      {"bindingId": "binding-uuid", "bundleId": "sha256:...", "leaseId": "lease-uuid", "leaseVersion": 19}
    ],
    "fencingToken": 981,
    "controllerGeneration": 204,
    "hostEpoch": 37,
    "runGeneration": 901
  },
  "backend": {
    "kind": "LEGACY_VFIO_TYPE1",
    "configuredIommuType": "VFIO_TYPE1V2_IOMMU",
    "launchGrantKind": "AUTHORIZED_DEVICE_PATH",
    "attachReceiptHash": "sha256:..."
  },
  "activation": {
    "plannedDisposition": "LIVE_APPLY",
    "mode": "BIND_ON_LEASE",
    "desiredOwner": "PASSTHROUGH",
    "effectiveOwnerBefore": "HOST",
    "effectiveOwnerAfter": "VFIO",
    "activationPlanHash": "sha256:...",
    "observedStateHash": "sha256:..."
  },
  "bindings": [
    {
      "bindingId": "binding-uuid",
      "requirementId": "gpu0",
      "ordinal": 0,
      "assignedId": "dp-assigned/run-77/gpu0/0",
      "deviceUid": "urn:qman:directpath:device:v1:host-a:sha256:identity",
      "hostBdf": "0000:65:00.0",
      "deviceGeneration": 12,
      "bundleId": "sha256:...",
      "bundleMembers": ["0000:65:00.0", "0000:65:00.1"],
      "payloadMembers": ["0000:65:00.0"],
      "memberActionsHash": "sha256:...",
      "guestSlot": "rp-dp0/00.0",
      "guestAbiClass": "cuda-gpu-v1",
      "guestAbiSignature": "sha256:...",
      "backendKind": "LEGACY_VFIO_TYPE1",
      "launchGrantKind": "AUTHORIZED_DEVICE_PATH",
      "attachReceiptHash": "sha256:...",
      "resourcePlanSliceHash": "sha256:..."
    }
  ],
  "decisionHash": "sha256:...",
  "planHash": "sha256:...",
  "observedPlanHash": "sha256:...",
  "resetContractsHash": "sha256:...",
  "artifacts": {
    "qemuBinaryHash": "sha256:...",
    "firmwareCodeHash": "sha256:...",
    "firmwareVarsBaseHashOrNull": "sha256:...",
    "argvHash": "sha256:...",
    "observedEvidenceHash": "sha256:..."
  },
  "verification": {
    "qmpRealized": true,
    "guestEnumerated": true,
    "iommuMapped": true,
    "interruptRemapped": true
  },
  "manifestDigest": "sha256:..."
}
```

Static 固定 `requirementId=static-0, ordinal=0`；Dynamic 可包含多个 requirement、bundle 和 guest
slot，禁止退化为单 `bundleId` 或 flat `assignedIds`。manifest 是审计记录，不替代 lease store；
manifest 不完整时 assignment 不能 commit。`assignedId` 是 run-scoped opaque key，不是持久 BDF。
完整字段、nullability、枚举、数组 canonical order 和 digest projection 以
[`contracts/directpath-assignment-manifest-v2.schema.json`](contracts/directpath-assignment-manifest-v2.schema.json)
为权威。

### 14.2 必要指标

```text
directpath_capability_decisions_total{result,reason,profile}
directpath_activation_plans_total{disposition,reason,mode}
directpath_activation_transitions_total{direction,result,stage}
directpath_candidate_count{host,requirement}
directpath_solver_duration_seconds{result}
directpath_lease_conflicts_total{bundle}
directpath_attach_duration_seconds{stage,result}
directpath_release_duration_seconds{stage,result}
directpath_quarantined_bundles{reason}
directpath_iommu_faults_total{assignment,device}
directpath_aer_events_total{severity,assignment,device}
directpath_plan_drift_total{profile,qemu_version}
directpath_reconcile_runs_total{result}
```

高基数 identity 只进入受控审计标签或日志，不直接进入公共 metrics label。

### 14.3 Artifact contract

每个验收 run 保存：request、resolved profile、outer/inner argv、snapshot、decision、bundle、plan、
lease journal、QMP/HMP、guest serial、ACPI、BAR、IOMMU/IRQ/reset trace、ESXi/QEMU 日志、restore
verdict、文件 SHA256 和工具版本。只保存“最终 pass”不足以复核失败边界。

AER M26 root-sequence 还必须满足 raw-first 和目录级 authority 合同：

1. endpoint/root/ESXi/guest raw snapshot 先于 parser/oracle 落盘；解析失败仍保留可重算的
   partial numeric safety observation。
2. sampler、parser、monitored worker、apply/restore 或 cleanup 任一异常都产生 typed
   partial/safety result、触发幂等 safe-stop，并停止后续注入；不完整尾窗不能形成 clean PASS。
3. T0/T1/T4/T5 的 artifact path、采样时间、最大间隔、numeric safety surface、cleanup boundary
   和 stop-tail 必须从 manifest-bound raw artifact 重算。host raw logs 与 guest serial 必须重新
   解析，不能信任 summary 自报字段。
4. campaign/case manifest、artifact closure、oracle/result 和 aggregate sidecar 只有通过
   `verify-run` exact-match 才能成为 authoritative result。离线 suite 与 ISO/build attestation
   只证明 harness/build readiness，不得提升 VMware observation 或 Qman product evidence。

## 15. 安全模型与绕过防护

| 威胁 | 强制控制 | 负例 |
| --- | --- | --- |
| ACS override 伪造安全 group | kernel shadow domain + whole-domain lease | 尝试把原生同域成员分给两个 VM 必须拒绝 |
| raw CLI 直通未租设备 | 唯一 launcher；Legacy QEMU 的 transient uid/mount namespace/device cgroup/LSM/read-only sysfs 只暴露授权 BDF/group；未来 cdev 只接收授权 fd | 未授权 `-device vfio-pci,host=` 无对应 sysfs/VFIO node 且入口被拒绝 |
| QMP runtime 添加/删除设备 | 所有 DirectPath profile 永久阻断，宿主 owner live activation 不经过 QMP | raw `device_add/device_del` 返回稳定拒绝 |
| stale Agent/Controller 提交旧 lease | PostgreSQL CAS + run generation + host epoch | 旧 generation/epoch 的 commit/release 均失败，且不改变物理 owner |
| reset 影响旁路 function | authoritative affected set + closure | 少一个 owner fd 时 hot reset 失败且不执行 |
| BAR/ReBAR 改变已批准 plan | config filter + post-boot verifier | guest resize/write 不改变 effective plan |
| release 后 stale DMA/IRQ | unmap/invalidate/IRQ teardown + sentinel | teardown 后 DMA/IRQ 触发 quarantine |
| policy/firmware/QEMU 升级沿用旧证明 | dependency hash invalidation | hash 改变后 capability 自动关闭 |

`QMAN-QEMU-CONTROL-001` 已在未受控 QEMU 的 machine 暂停态证明 raw `device_add` 可以越过
冷启动设备规划，且 `device_del` 成功 reply 后设备仍可能存在。它不证明 Guest 在线热插已
成功；它是上述控制面威胁的 E3 正控，不是“阻断已实现”的负例。
`QMAN-E3-QMP-GATE-001` 又在最小 Qman component 上证明：客户端 capability 可在本地处理，
独立 backend recorder 只观察到内部 capability 与五类只读 query，17 类拒绝未进入 backend，
且 PCI tree、QEMU fd 与 SCM_RIGHTS 后的 gate fd 基线不变。实验 observer/recorder 是 test-only
旁路，也没有 assignment、lease、generation 或 VFIO，因此它只验证一个受控端点，不是产品闭环。
只有 Qman QMP proxy/ACL 上相同命令稳定拒绝，并同时证明 device tree、fd、generation 和 lease
均未改变后，S15/F09 才能进入产品关闭评审。

## 16. 验收与双向追踪

### 16.1 模块到场景

| 实现单元 | 首批必须通过的场景 | 发布阻断风险 |
| --- | --- | --- |
| snapshot/provenance | C10、C15、C16、C18、F10 | R19、R27、R35 |
| capability closure | C00-C04、C13、C17-C20、D14 | R02、R28、R29、R38 |
| shadow-domain ABI | C05、C06、C07、C19 | R01、R28、R35 |
| VFIO reset provider | C03、C04、C17、C18、S11、S12 | R02、R03、R29 |
| full resource planner | M00-M04、M11、M18-M23 | R07、R09、R21、R22、R33、R34、R36 |
| host owner activation | O00-O09 | R03、R06、R11、R39 |
| Static transaction | S00-S16、F00、F09 | R03-R06、R11、R17、R26、R37、R39 |
| Dynamic solver | D00-D14 | R04、R05、R08、R23、R29 |
| online cold relocation / source-unreachable no-takeover | F01-F07 | R04、R10 |
| parity surface | M05-M10、M14-M17、M24-M29 | R12-R17、R22-R24、R30-R32 |

acceptance inventory 的已定义/未分类数量和各 Case 当前状态由
`python tools/evaluate_release.py status` 生成，不在蓝图中复制易漂移计数。只有 O09 是 executable
reference scope；C20 虽有可执行 E2 reference runner，本身仍是 PRODUCT/IMPLEMENTATION_BLOCKED。
C10/C15/C16/C18/C21、Static/Fault/QMP 等 product Case 的组件前提不等于
产品关闭。`C16` 的局部 provenance 约束也只是 reference premise；产品 Case/Risk closure 必须读取
机器合同，不能由本段叙述推断。

### 16.2 场景格式

每个 acceptance case 必须可执行，而不是只有表格一行：

```yaml
id: S05-qemu-start-failure-cleanup
given:
  profile: qman-x86-q35-uefi-v1
  qualified_bundle: bundle-gpu-0
  injected_fault: qemu-exit-before-qmp-ready
when:
  operation: static-power-on
then:
  assignment_state: failed
  lease_state: free
  vfio_fds: 0
  iommu_mappings: 0
  original_drivers_restored: true
  device_generation_incremented: true
  quarantine: false
artifacts:
  required: [request, decision, plan, journal, qemu-log, iommu-trace, restore-verdict]
```

capable closure 的最小差分场景必须同时证明资格稳定和依赖 fail-closed：

```yaml
id: C20-capability-closure-before-availability
matrix:
  - name: dependency-qualified-and-free
    dependency_reset_contract: valid
    dependency_action_fact: valid
    dependency_owner: free
    expect: {capable: true, available: true}
  - name: same-bundle-busy
    dependency_reset_contract: valid
    dependency_action_fact: valid
    dependency_owner: other-vm
    expect: {capable: true, available: false}
  - name: dependency-reset-missing
    dependency_reset_contract: missing
    dependency_action_fact: valid
    dependency_owner: free
    expect: {capable: false, available: false, reason: RESET_NOT_SUPPORTED}
  - name: dependency-action-unknown
    dependency_reset_contract: valid
    dependency_action_fact: unknown
    dependency_owner: free
    expect: {capable: false, available: false, reason: DEPENDENCY_ACTION_UNKNOWN}
invariants:
  - first_two_cases_have_identical_bundle_hash
  - first_two_cases_have_identical_capable_and_policy_hash
  - query_has_no_bind_reset_or_lease_side_effect
```

当前 executable reference fixture 位于
[`pci-resource-model/tests/fixtures/c20-capability-closure.json`](pci-resource-model/tests/fixtures/c20-capability-closure.json)，
runner 为 [`qman-lab/run_c20_capability_closure.sh`](qman-lab/run_c20_capability_closure.sh)。
`QMAN-E2-CLOSURE-001` 已在 Windows/WSL 通过 22 个 C20 定向测试和 112 个全量测试，并增加
unauthenticated/stale fact、BDF identity substitution、immutable inventory、20,000-member bounded
closure 与 decision-hash 扰动反例。该结果只完成 reference evaluator，不替代生产
inventory publisher、签名 verifier、controller/lease/attach executor，也不关闭 C20 产品 Case 或 R38。

无法稳定自动断言的场景不能标记 `VERIFIED`；它只能是 `CONTROL_IMPLEMENTED` 或对应功能
`FEATURE_DISABLED`。

### 16.3 Qman Evidence 等级与机器合同

| 等级 | 含义 | 可证明什么 |
| --- | --- | --- |
| E2 | 单元/模型测试 | 算法与 schema |
| E3 | QEMU/instrumented endpoint | 软件路径和外部 surface |
| E4 | 指定真实平台/设备 | 物理 isolation/reset/IRQ/vendor behavior |

文档/源码推理作为 `OFFICIAL_CONTRACT`、`NORMATIVE_DESIGN` 或其他 `basis_kind` 管理，不伪装成
运行结果。每条 Qman result 必须满足
[`qman-technical-evidence.schema.json`](contracts/qman-technical-evidence.schema.json)，并登记到
[`qman-evidence-index.json`](contracts/qman-evidence-index.json)；发布门检查 result/runner hash、
TS/Case/Risk 引用和 `closureEffect`。reference/component subject 与 E2 不关闭产品状态，E3 不得把
R01/R03/R20/R27 等硬件风险提升为 E4。qualification key 至少包含 host model/BIOS、IOMMU、
device VID:DID/revision/firmware、kernel/QEMU/firmware 和 guest driver/workload。

截至 2026-07-21，索引中有 2 条 E2、8 条 E3：5 条为 `REFERENCE_ONLY`，5 条为
`QMAN_COMPONENT / COMPONENT_ONLY`。它们固定 reference model、C20 closure、raw QMP/BDF、
VFIO provider split、QEMU/OVMF MMIO、最小 QMP default-deny component，以及
`QMAN-E3-VFIO-PROVIDER-GATE-001` 的真实 cdev/IOMMUFD/no-IOMMU A/B 和
`QMAN-E3-STATIC-LEASE-FAULT-001` 的 subprocess/SQLite crash/CAS 前提。
`QMAN-E3-AUTHORITATIVE-SNAPSHOT-FAULT-001` 又证明 component SQLite publisher 在 insert 后硬退出
不会暴露部分 epoch、相同 CAS 只有一个 winner，以及 signature/payload/stale/minimum-epoch/boot
负门；L01 删除最新 row 后 earlier-valid epoch 仍会被 `current()` 接受为当前 authority state，但重开
进程没有 process-local sealed capture provider，不能签发 launch authorization。该结果直接证明外部
rollback anchor 仍缺失，而非证明 inode/store UUID 能防回滚；它也不证明生产密钥治理。更新后的
`QMAN-E3-STATIC-LAUNCH-ENVELOPE-001` v5 把 sealed capture provider、signed full-host snapshot authorization、lease
authorization、fresh cdev/IOMMUFD raw fd、四次 live revalidation、stock-QEMU bind/IOAS/attach
observation 与无 independent DMA receipt 时的 claims-retaining quarantine 串成同一个组件链。
它是未来 cdev backend component evidence，不覆盖当前 Legacy path grant、QEMU 5.0 sandbox 或
post-spawn receipt。
所有 `closureEffect` 仍为空，
产品 Case/Risk 关闭数为 0；新增 component evidence 不改变 C21 或 S03/S04/S05/F00 的产品阻断状态。

### 16.4 Case completion 与证据服务的实现端口

内网实现不得把 `caseId`、测试函数名或一份 CI 日志直接写成完成状态。建议在现有系统中映射以下逻辑
组件；可以合并进既有服务进程，但 wire schema、authority 和签名角色必须保留：

| 逻辑组件 | 输入 | 权威输出 | 禁止替代 |
| --- | --- | --- | --- |
| Test build pipeline | exact C/M、Git object database、toolchain | 完整 tracked-tree `SourceTreeManifest`、`BuildAttestation`、`RunnerManifest`、六个 role-exclusive control artifacts | dirty working tree、bare runner SHA、无 replay receipt 的 hermetic 标签或可变 latest image |
| Scenario runner | bound scenario、fixture、runner manifest | per-iteration result 与 role-exclusive artifacts | 一个 aggregate log 复用为所有 oracle |
| Evidence indexer | execution core、artifact bytes | signed `ExecutionEvidenceIndex` | index 嵌入自身 hash 或 final result digest |
| Case evaluator | generated CaseContract、同 C/M/target/platform/backend/qualification tuple 的 passing indexes、专用 `CaseEvaluatorToolManifest` | signed `CaseCompletionRecord` | blocked/reference Case、scenario 自报 coverage、借用 RunnerManifest/TOOL_MANIFEST |
| Qualification collector | signed WorkloadDefinition/RunRequest、inventory、taxonomy、firmware/provider/guest readback、scenario core | signed WorkloadResult、每字段独立 `QualificationMeasurement`、双签 `QualificationRunManifest` 与聚合 Subject | 自报 assertion/metric、RunManifest 事后收养 core、旧 runId/boot measurement replay |
| Trust verifier | root set、完整 ring history、外部 nonce response | verified history/freshness decision | repository 旁置 anchor 快照 |

`CaseCompletionRecord.observedCoverage` 必须由 evidence index 集合确定性重算；其 port/operation/transition/
fault/schema/oracle/assertion union、每 fault repeat、总 duration 和 dependency completion digest 都不能由 API
调用者提供。E3 使用 `TEST_EVIDENCE` 签名，E4 还要求 exact measured subject 与
`QUALIFICATION_ENGINEERING` 独立批准。

完成记录的复用身份是 `(platformProfileId, platformProfileDigest, backendProfileDigest,
exactQualificationKey, caseId)`，同时继续绑定 C/M/target commit。E3 的 exact key 必须为 null；E4 从
QualificationSubjectManifest 的九字段输入独立重算。依赖 Case 必须匹配同一完整 tuple；若 detached record
存在非空依赖但调用者未提供可解析的 dependency descriptor set，结果只能是
`UNRESOLVED_DEPENDENCY_CLOSURE`。Integration/qualification 外层 descriptor 只定位并校验原记录，无权重标。

Case evaluator 必须提供独立签名的 `CaseEvaluatorToolManifest`：固定 evaluator target blob/interface、由 C
重建的完整 SourceTreeManifest，以及 role-exclusive runtime binary、dependency lock、environment manifest
和 build log。Scenario RunnerManifest 或任意 scenario `TOOL_MANIFEST` 均不能替代它。

Build pipeline 必须从 target commit 的 Git object database 生成全 tracked-tree manifest；文件 path/mode/
object/raw content hash、symlink 和递归 submodule 一个不少，且 build 不得读取未声明的 dirty/untracked 输入。
`BuildAttestation` 进一步固定 canonical argv/cwd/空环境 allowlist、builder/toolchain/dependency/environment、
所有外部读取、output 和 build log。`HERMETIC_REPRODUCIBLE` 还要由不同 principal 在独立 clean environment
重放并生成 byte-identical output receipt；没有 receipt 只能选择 pinned non-hermetic，不能靠标签升级。
Scenario runner 只接受 produced binary；Case evaluator 可使用 `INTERPRETED_NO_BUILD`，但 runtime identity
必须由 source blob、interpreter artifact 和 dependency lock 确定性生成。

Qualification collector 先解析 signed WorkloadDefinition（binary/config、invocation、duration、assertion/oracle/
evidence-role 和 metric projection），再原子消费 signed RunRequest 的 fresh nonce；RunRequest 在任何 collector
前同时冻结 current snapshot 下唯一的 `deviceUid/deviceRecordHash`。每个 E4 Scenario input、
execution core 和 EvidenceIndex 固定相同 runId、request digest 与 nonce digest，防止事后收养无关 core。
collector/tool manifest 生成 identity、archetype taxonomy、traits、firmware、runtime、provider、guest/workload
七类 measurement，并为每个 core 生成 caseExecution measurement；signed WorkloadResult 必须与 definition 的
assertion 精确双射且 PASS，metric 只能从允许的 raw artifacts 重算。所有记录签入相同 run/host/epoch/boot；
还必须继承相同 deviceUid/deviceRecordHash。identity/traits 同时绑定 current HostSnapshot 与其中的 exact
DeviceRecord；classification 复用同一 descriptor，并在 classifiedAt 嵌入 Host Inventory authority 对完整
HostAuthority current-pointer state 的签名 receipt，禁止同一 host 内跨设备拼接。
RunManifest 再固定当前 snapshot、wall/monotonic interval、完整 measurement/core/workload 集合，由 Host
Inventory 与 Test 两个不同 principal 双签。Subject 只做 COMPLETE/PASSED RunManifest 及这些签名记录的
精确投影和双射聚合，不具有凭空声明测量值、archetype、workload 结果或时间窗口的权限。

release 数据库还需持久化 `ENTITY-CLEAN-RELEASE-ACCEPTANCE`。它和 complete old lease revocation、
Assignment/Relocation authority version advance、audit、outbox 属于一个 transaction。唯一约束至少覆盖
`receiptDigest`、`idempotencyKey` 和 `repositoryTransactionId`；相同输入 replay 返回 byte-identical
acceptance，不同 scope/version/generation 复用任一 key 必须冲突。Host Agent 的 receipt signer 与
repository acceptance signer 使用不同 principal/key role。

目标代码 discovery 完成后，integration map 应分别绑定 runner builder、scenario executor、artifact store、
case evaluator、qualification collector、trust verifier 和 repository transaction symbol；如果当前 Qman 把其中
多个职责放在同一 service，可以绑定到同一 path，但不能省略 contract item 或把独立证据角色合并为同一 key。

## 17. 实施计划与提交边界

### Phase 0：合同与 schema

交付：baseline/profile ADR、canonical snapshot/decision/bundle/plan/manifest schema、stable reasons、
risk evaluator、owner-independent action/reset closure、golden fixtures。完成门：
C10、C15、C16、C18、C20、F10。

### Phase 1A：事实 provider

交付：kernel native shadow-domain ABI、当前 Legacy TYPE1 group/type provider、backend-neutral
adapter contract、per-component provenance、health/generation；未来 cdev/IOMMUFD adapter 作为独立
profile 保留。完成门：C03-C07、C17-C19。

现有逐设备 DMA provider E3 已覆盖真实 cdev/IOMMUFD 与一个显式 Legacy lab branch；bounded HMAC
snapshot/authorization 到 fresh cdev fd 和 stock-QEMU attach observation 的 v5 链也已通过。它们只
关闭组件内 provider 分流/cleanup 与未来 cdev 授权连续性，不证明六个平台的 Legacy TYPE1 选择、
QEMU 5.0 `AUTHORIZED_DEVICE_PATH`、sandbox/receipt 或 E4 IOMMU/interrupt-remapping/errata。production
trust root、external rollback anchor、key rotation/revocation/catalog、kernel atomic generation/reset
provider 和产品 Controller 仍缺失，C21 因此仍为 `IMPLEMENTATION_BLOCKED`。

### Phase 1B：完整资源 planner

交付：完整 guest tree、逐桥精确求解、firmware/QEMU renderer、observed verifier。完成门：
M00-M04、M11、M18-M23。

### Phase 1C：单 host owner activation 与 Static

交付：desired/effective 四态 planner、完整 bundle live executor、exact early-boot claim/reconcile、
PostgreSQL global CAS/lease/run generation/host epoch、Host Agent SQLite journal/cache、backend-neutral
launch grant、Legacy path sandbox+receipt、future cdev fd renderer、rollback/release/quarantine/reconcile
和 API/QMP bypass gate。完成门：O00-O09、S00-S16、F00、F09。

standalone schema-v4 `StaticLeaseStore` 与 component fault runner 已证明固定 host/authority/store-instance
namespace、VM/device generation CAS、whole-bundle claim、journal、commit 前进程死亡原子性、双进程冲突
和 unknown cleanup quarantine。新增加的 raw-handle、fd-only render 与 launch-envelope components 已把
bounded signed full-host snapshot authorization、lease authorization、fresh cdev/IOMMUFD、四次 live
revalidation、stock-QEMU spawn、QMP receipt 和 fail-closed quarantine 串成未来 backend 的可执行
前提；它没有实现当前 Legacy path sandbox/receipt，也没有实现 PostgreSQL 全局真相源。除此之外，
production snapshot authority、真实 reset/driver restore 与独立 DMA/IRQ clean-state observer 仍缺失，
因此 Phase 1C 不完成，也不推进 G2 或后续产品 milestone。原 fault runner 中的 bind/reset/QEMU 仍只是模拟阶段标签，
`cleanup_verified` 仍是受信上层断言。

治理状态保持：产品声明只能是 `REFERENCE_AND_QUALIFICATION_MODEL_ONLY`。acceptance 当前定义数、
milestone 与 blocker 以 `python tools/evaluate_release.py status` 的机器结果为准；既有 component PASS
不产生产品 Case/Risk closure，也不把 E3 提升为 E4。

Phase 1A/1C 的关闭顺序不是并列清单，而是严格依赖链：

```text
C21 component/provider
  -> bounded authoritative component snapshot premise
  -> production snapshot trust root + rollback/key/catalog/generation controls
  -> standalone durable lease/FSM component premise
  -> integrated bind/reset/cleanup + backend-specific launch-grant Static transaction
  -> S15 production QMP boundary
  -> F09 all-entry bypass matrix
```

S15 必须先在一个由产品 launcher 创建、只有唯一受控 monitor 的真实 Static run 上证明 QMP
mutation 不改变 lease/generation/VFIO/topology；F09 才能在此基础上扩展到 API、raw CLI、storage、
alternate monitor 和 fd injection。前一项未关闭时，不允许用后一项的局部负例反向追认。

### Phase 2：单 host Dynamic

交付：allowed-device matcher、bundle dedup、global solver、multi-bundle atomic reservation、runtime
`assignedId`。完成门：D00-D14。

### Phase 3：双在线主机的计划性 cold relocation

交付：PostgreSQL 全局 relocation transaction、source stop、DMA/IRQ teardown、reset/owner restore、
`SourceCleanReleaseReceipt`、target re-solve/attach、run generation/host epoch stale-mutation gate，以及
source-unreachable 保留 lease/stopped/no-reassignment 负向门。完成门：F01-F07 中属于计划性在线
cold relocation 的 Case；BMC/power fencing 和 host-failure automatic HA 不属于完成条件。

### Phase 4：parity surface 与硬件 qualification

交付：AER/PME/ROM/ReBAR/SR-IOV filters、versioned QOM profile，以及六个平台矩阵上的真实硬件
E4 qualification。HCL trait 至少覆盖消费 GPU、专业 GPU、HBA、加速卡四类 archetype；具体
VID:DID/firmware/Guest driver/workload 由 G6 profile 产生。只有签名、版本化并经 Product Release
纳入 catalog 的精确组合对外开启；其余保持 `FEATURE_DISABLED` 或隔离的 `UNQUALIFIED_LAB`。

AER 子门按 M24-M29 关闭：M24-M28 的 nested ESXi/QEMU 结果只形成 versioned VMware
reference/virtual-integration 输入，仍须由独立 Qman product Case 证明每个 backend、architecture
与 firmware profile；M29 的 exact physical tuple、真实链路/reset/clear、health/quarantine 和
安全复用才可形成对应 G6 E4 qualification。QEMU 12/12、ESXi runner 离线 78/78、
ISO/attestation 以及 V17+V19 的 exact O0/O4 `g101` 外部寄存器状态切片，都不能替代
bound native driver、其他 gate/service/lifecycle/physical profile，更不能单独推进 G6。

`platformProfileHash` 必须由 active compatibility policy 独立复算，而不是由 QualificationRecord
自报：哈希对象精确为 `{profileProjectionVersion:1, policySchemaVersion, capabilityTarget, platform,
backendPolicy, hostConfigurationPolicy}`，其中 `platform` 是 record 指定的唯一完整平台行；case matrix
另有独立 digest。trust root/key ring 的每个 key 除 `keyId/publicKey` 外还绑定 immutable
`principalId`。QE、Product Release、Target Architect、Security、Test 的分离同时检查 principal、keyId
和 key material，approval identity 必须回指 principal；同一人换多个 key 不会产生额外 quorum vote。

### Phase 5：发布闭环与长期故障注入

交付：升级/回滚兼容矩阵、长时间 DMA/IRQ soak、Host Agent/Controller/boot/store/source-unreachable 故障注入、所有风险和
capability 的机器可执行 release evaluator。重复 O00-O09、S13-S16/F09，证明 owner activation
在 crash 后可 reconcile，且所有 DirectPath profile 均无法绕过 API、scheduler、launcher 或 QMP
进行 guest runtime hotplug。

每个提交只开放其已闭环能力。禁止先提供 raw VFIO/QEMU escape hatch，再等待未来补控制面。

## 18. 已冻结架构决策与后续 qualification 输入

正式产品决策以 [`product-decisions.json`](contracts/product-decisions.json) 为机器真相源，
ADR-002/003/005/007/010 均已 `ACCEPTED`，不再作为开放问题。其余行记录本蓝图沿用的局部设计
baseline；任何改变安全、事务或支持边界的答案都必须新增 versioned ADR，不能在实现中静默漂移。

| ADR | 状态 | 已冻结结论 | 实现影响 |
| --- | --- | --- | --- |
| ADR-001 | DESIGN_BASELINE | 语义对标 + 稳定 Qman guest ABI；不严格复制 VMware topology | guest ABI 变化必须新增 versioned machine profile，不能原地漂移 |
| ADR-002 | ACCEPTED | 六个平台都交付完整 V3；当前 backend 为 profile 精确固定的 Legacy TYPE1v2/TYPE1，禁止 fallback；cdev/IOMMUFD 是未来独立 profile | QEMU 5.0 Legacy 使用 path grant；现有 cdev E3 不关闭 Legacy 产品 Case |
| ADR-003 | ACCEPTED | 一套 backend-neutral Qman API、single-active Controller + standby、PostgreSQL global repository、Host Agent SQLite journal/cache | backend 差异只在 adapter/renderer/grant/receipt；SQLite 不仲裁全局 owner |
| ADR-004 | DESIGN_BASELINE | 按强多租户设计，不接受 ACS override 缩组 | 单租户也不能放宽 reset/DMA 清理，只可简化调度 policy |
| ADR-005 | ACCEPTED | 设备类型无关的通用 PCI 引擎；生产只支持精确 compatibility catalog；首批 archetype 为消费 GPU、专业 GPU、HBA、加速卡 | 设备特例进入 profile/rule/provider，禁止在主 FSM 按设备类分叉；精确 SKU 在 G6 产生 |
| ADR-006 | IMPLEMENTATION_ORDER | 先关闭 Static core，再复用同一事务 core 实现 Dynamic | 这是内部 wave 顺序，不是删减产品版本 |
| ADR-007 | ACCEPTED | 只支持双在线主机计划性 cold relocation；source clean-release receipt 后目标才 re-solve/attach；源失联保留 lease/stopped/no reassignment | 不集成 BMC/power fencing，不承诺 host-failure HA；logical epoch 只拒绝 stale mutation |
| ADR-008 | DESIGN_BASELINE | 首版只宣告 exact profile 实际通过的设备数量；其他 vHW/limit 建独立 profile | 禁止把 VMware release、vHW、runtime option 与 Qman verified limit 压成一个常量 |
| ADR-009 | DESIGN_BASELINE | P2P/RMRR/INTx/SR-IOV 默认关闭，逐项 qualification | 任一开启都要求独立真实硬件证据和 backend/profile gate |
| ADR-010 | ACCEPTED | Qualification Engineering 签发 `QUALIFIED`；Product Release 审批进入 `SUPPORTED` catalog | 签发与发布责任分离；catalog 签名、版本化、可撤销、hash-bound |
| ADR-011 | DESIGN_BASELINE | guest runtime PCI hotplug 永久不支持，所有 DirectPath profile 四层拒绝 | 将来改变必须新 ADR、新 profile 和独立安全审计 |
| ADR-012 | DESIGN_BASELINE | bind-on-lease 默认；显式 maintenance 才持久 early-boot VFIO claim；先扩 owner group 再预检；产品不自动重启 host | 禁止全局 VID:DID claim 或未经授权的 reboot fallback |
| ADR-013 | DESIGN_BASELINE | ownerActivationGroup、resetDomain、exclusiveAttachGroup、physicalIsolationDomain 分开持久化，事务按需取闭包并集 | 避免漏租、同 VM 双占、无关 sibling 误解绑或过度拒绝 |
| ADR-014 | DESIGN_BASELINE | 宿主可为显式 DPDK reservation 开 unsafe switch；VM 仍逐设备要求 IOMMU；当前产品走 exact Legacy TYPE1，未来 cdev 独立 qualification | no-IOMMU 对 VM hard reject；DPDK node/fd 不得进入 VM launcher；backend 不得静默 fallback |

以下是允许后补的 integration/qualification 事实，不重新打开上述产品边界，也不阻断按本蓝图
推进实现；缺少它们会阻断相应精确 profile 的 G6 发布或现场部署：

1. 现有 Qman 服务名、进程 owner 和部署拓扑到参考 `Qman API / Controller / Host Agent` 的映射。
2. PostgreSQL 的实际集群/备份/凭据部署方式，以及 Host Agent SQLite journal 的磁盘位置和保留策略。
3. 六个平台中 exact machine version、UEFI/SeaBIOS package、binary/config hash；由 qualification 自动采集。
4. 四类 archetype 的首批物理 specimen：VID:DID/subsystem/revision、device firmware、host 型号、
   Guest、driver 和 workload。
5. Qualification Engineering 与 Product Release 的实际人员/组织映射，以及 catalog 签名密钥治理。
6. 显式 host maintenance 工作流与允许的 initramfs/Secure Boot 更新、人工 reboot 编排细节。

这些事实可以改变 adapter 参数、部署或验收规模，但不能改变安全不变量：先扩 owner group 再全员
预检、whole-domain lease、权威 reset affected set、durable ownership、清理不确定即 quarantine。

## 19. 一个完整 Dynamic 例子

假设 VM 请求一张 `cuda-gpu-v1`，目标 host 开启 ACS override：

1. snapshot 发现 `65:00.0` GPU 和 `65:00.1` audio 被 patched kernel 拆成两个 IOMMU group。
2. native shadow-domain ABI 表明两者仍属于 physical domain `pd-17`。
3. VFIO reset provider 表明选择 SBR 时 affected set 也是两者；multifunction 默认规则再次加入
   同样成员，最终 bundle 为 `{65:00.0,65:00.1}`。
4. matcher 只把这个 bundle 计为一个 candidate；不会把两个 function 当两张 GPU。
5. planner 读取 GPU 64GiB BAR、audio 小 BAR、Root Port window、OVMF profile 和 VM RAM，生成
   root/bridge aperture、guest slot 和 plan hash。
6. store 对整个 bundle CAS；另一台 VM 同时选择 `65:00.1` 会因同一 bundle key 失败。
7. Host Agent 重新核对 identity/generation/affected set，bind 两个 function 到 vfio-pci，按当前
   Legacy profile 生成覆盖 exact BDF/group 的 `AUTHORIZED_DEVICE_PATH`；reset 后重新规划，在
   transient uid + mount namespace + device cgroup/LSM + read-only sysfs sandbox 中启动 QEMU。
8. `/proc/$pid/fd` + QMP/QOM receipt、guest BAR/ACPI heartbeat 和 TYPE1 DMA-domain ownership 全通过后
   才提交 `assignedId`。未来 cdev profile 可在同一步生成 fd grant，但不能运行时 fallback。
9. power-off 时先停止 QEMU，再关 bus master/IRQ、unmap/invalidate、reset/state probe、rebind；所有
   证据通过后 lease 才变 FREE，Dynamic 持久配置中没有留下 `65:00.0`。
10. 任一步不确定，整个 `{65:00.0,65:00.1}` quarantine；不会只隔离报错的 function。

这个例子同时解释了为什么 class code、单个 FLR bit、patched IOMMU group、BAR 总和或 QMP success
都不能独立构成 `passthruCapable`/attach success。

## 20. 规范与证据索引

- 已接受产品决策、六平台/Legacy-first/backend launch policy 与集群边界：
  [`contracts/product-decisions.json`](contracts/product-decisions.json)、
  [`contracts/compatibility-profile-policy.json`](contracts/compatibility-profile-policy.json)
- IPD 人类树与机器树：[`ipd/README.md`](ipd/README.md)、
  [`contracts/ipd-tree.json`](contracts/ipd-tree.json)
- 完整算法、风险 R01-R39、验收 C/S/D/M/F/O：
  [`qemu-static-dynamic-directpath-design.md`](qemu-static-dynamic-directpath-design.md)
- ESXi 8.0 U3 黑盒结果与 case 索引：
  [`vmware-esxi8-directpath-local-results.md`](vmware-esxi8-directpath-local-results.md)
- `passthruCapable` 外部模型：
  [`vmware-esxi8-passthru-capable-observed-model.md`](vmware-esxi8-passthru-capable-observed-model.md)
- AER 外部模型：[`vmware-aer-blackbox-results.md`](vmware-aer-blackbox-results.md)
- firmware/layout 矩阵：[`vmware-firmware-layout-matrix.md`](vmware-firmware-layout-matrix.md)
- 可执行验收目标：[`vmware-directpath-acceptance-test-plan.md`](vmware-directpath-acceptance-test-plan.md)
- Qman 技术证据、复现命令与关闭边界：
  [`ipd/QMAN-TECHNICAL-EVIDENCE.md`](ipd/QMAN-TECHNICAL-EVIDENCE.md)
- Qman 机器证据索引与 result schema：
  [`contracts/qman-evidence-index.json`](contracts/qman-evidence-index.json)、
  [`contracts/qman-technical-evidence.schema.json`](contracts/qman-technical-evidence.schema.json)
- Authoritative snapshot 组件 schema、fault evidence 与 v5 Static chain evidence：
  [`contracts/authoritative-snapshot.schema.json`](contracts/authoritative-snapshot.schema.json)、
  [`evidence/qman-authoritative-snapshot-fault-20260721-summary.json`](evidence/qman-authoritative-snapshot-fault-20260721-summary.json)、
  [`evidence/qman-static-launch-envelope-20260721-summary.json`](evidence/qman-static-launch-envelope-20260721-summary.json)
- 当前 reference model：[`pci-resource-model/`](pci-resource-model/README.md)
- VFIO unsafe switch 与逐设备 DMA backend 的 QEMU/Linux 实测：
  [`evidence/qemu-vfio-noiommu-split-20260718.md`](evidence/qemu-vfio-noiommu-split-20260718.md)
- ESXi 无 IOMMU 全量负控：
  [`evidence/esxi8-workstation-noiommu-20260718.md`](evidence/esxi8-workstation-noiommu-20260718.md)
- Host owner activation 证据与 SHA256：
  [`evidence/esxi8-passthru-activation-20260718.md`](evidence/esxi8-passthru-activation-20260718.md)、
  [`evidence/esxi8-passthru-activation-20260718-summary.json`](evidence/esxi8-passthru-activation-20260718-summary.json)
- ESXCLI 8.0.3 `--apply-now` 合同：
  [`hardware pci pcipassthru set`](https://developer.broadcom.com/xapis/esxcli-command-reference/8.0.3/namespace/esxcli_hardware.html)
- Broadcom busy-driver 重启边界：
  [KB 434815](https://knowledge.broadcom.com/external/article/434815/hba-adapter-hba355i-registers-as-storage.html)
- vSphere 8.0 U3 fixed passthrough hotplug API：
  [`VirtualMachineConfigSpec.fixedPassthruHotPlugEnabled`](https://developer.broadcom.com/xapis/vsphere-web-services-api/8.0U3/vim.vm.ConfigSpec.html#fixedPassthruHotPlugEnabled)
