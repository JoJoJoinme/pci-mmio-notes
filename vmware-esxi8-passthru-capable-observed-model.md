# ESXi 8 DirectPath `passthruCapable` 外部可观察模型

记录日期：2026-07-14
目标：VMware ESXi 8.0.3 build 24280767
范围：公开 vSphere API、`esxcli`、PCI config、VMX/host 日志与 QEMU trace；不推导 VMware 私有代码。

## 1. 结论

本地原 15 项 IOMMU/reset/ACS/topology 矩阵，加上 1 项公开 ACS bypass 组合、6 项
class-code A/B 和 1 项真实 Type-1 bridge FLR 对照表明，
`HostPciPassthruInfo.passthruCapable` 不是“设备 ID 或 class
在白名单”的同义词，也不是“当前 VM 一定能分配该设备”。对本轮受控设备，最小外部
模型是：

```text
staticCapable = hostIommuPresent
             && functionIsAssignablePayload
             && acceptedResetBoundaryExists
             && acsPolicyPasses
             && deviceIsNotPlatformReserved

assignableNow = staticCapable
             && passthruEnabled
             && passthruActive
             && wholeDependencyIsExclusivelyLeased
             && assignableHardwareSelectionMatches
             && mmioAndRmrrAdmissionPasses
```

`functionIsAssignablePayload` 表示该 function 不是维持宿主 PCI fabric 的 Type-1 bridge
等结构节点；它描述外部现象，不声称 VMware 内部字段或检查顺序。以上判别式由实验
归纳，不是 VMware 内部实现声明。累计 23 个资格样本全部符合；
共享 dependency 的大 BAR 负例又证明第二个判别式不能省略。

## 2. 16 项基础资格/ACS 矩阵

| Case | 唯一变量 | ESXi 观察 | 结果 |
| --- | --- | --- | --- |
| `pcie-no-iommu` | 关闭 outer virtual VT-d | 可报告 `Bridge reset`，但 `Capable=false` | pass |
| `pcie-edu-bridge-reset` | EDU 位于 PCIe Root Port 后 | `Bridge reset`、`Capable=true` | pass |
| `root-e1000e-no-function-reset` | e1000e 直挂 Root Complex，无 FLR | `Reset=None`、`Capable=false` | pass |
| `root-virtio-flr-pm` | 直挂 virtio，同时有 FLR/PM | `Function reset`、`Capable=true` | pass |
| `root-virtio-flr-only` | 只保留 FLR | `Function reset`、`Capable=true` | pass |
| `root-virtio-pm-only` | 去掉 FLR，只保留 PM capability | `Reset=None`、`Capable=false` | pass |
| `root-virtio-d3hot-reset` | device model 实现 D3hot reset | ESXi 仍报 `Reset=None`、`Capable=false` | pass |
| `root-virtio-pme-d3hot-advertised-only` | 只广告 PME/D3 state bits | `Reset=None`、`Capable=false` | pass |
| `root-virtio-d3hot-reset-advertised` | D3hot callback 加能力广告 | `Reset=None`、`Capable=false` | pass |
| `root-virtio-no-flr-no-pm` | 无 FLR/PM，直挂 Root Complex | `Reset=None`、`Capable=false` | pass |
| `root-i82559-native-pm` | 换成带原生 PM 的 i82559 | `Reset=None`、`Capable=false` | pass |
| `pcie-virtio-no-flr-no-pm` | 同设备移到 Root Port 后 | `Bridge reset`、`Capable=true` | pass |
| `pcie-virtio-no-acs` | Root Port 隐藏 ACS，ESXi bypass policy | `Bridge reset`、`Capable=true` | pass |
| `pcie-virtio-no-acs-strict` | 同拓扑，只开启严格 ACS 检查 | `Bridge reset` 仍可见，但 `Capable=false` | pass |
| `pcie-virtio-no-acs-global-bypass` | 严格 Root Port 检查保持开启，同时设置公开 `disableACSCheck=TRUE` | `Bridge reset`、`Capable=true` | pass |
| `legacy-virtio-no-flr-no-pm` | 同设备移到 conventional bridge 后 | `Bridge reset`、`Capable=true` | pass |

原始结果：

```text
_artifacts/vmware-directpath-runs/
  20260714-esxi8-passthru-capability-matrix-v4/matrix-result.json
  20260714-esxi8-no-acs-global-bypass-v1/matrix-result.json
```

原 15 项矩阵和新增 ACS bypass 单项的 verdict/restore verdict 均为 `pass`。累计 23 个
capability 案例的 `result.json` 均记录 QEMU 6.2.0；各子矩阵使用 system build 或带实验
扩展的 6.2.0 build。新增 bypass 单项的 system binary SHA256 为
`7d1e85a29e09c49f6a1c60a18713d80a72ef3b8932c4183cc100bce3a01fa64e`。聚合报告中的
QEMU 11.0.2 用于大 BAR 等其他运行，不代表本资格矩阵。

### 2.1 六项 class-code 单变量矩阵

六轮均使用同一个 QEMU `virtio-net-pci` function：VID:DID `1af4:1041`、Type-0
`Header Type=0x00`、Root Complex 位置、FLR、IOMMU 和其余 capabilities 完全相同，
只覆盖 PCI base/subclass：

| Class | ESXi class name | FLR | ESXi 观察 | 结果 |
| --- | --- | --- | --- | --- |
| `0x0200` | Ethernet controller | true | `Function reset`、`Capable=true` | pass |
| `0x0500` | RAM memory | true | `Function reset`、`Capable=true` | pass |
| `0x0b02` | Pentium | true | `Function reset`、`Capable=true` | pass |
| `0x0b40` | Co-processor | true | `Function reset`、`Capable=true` | pass |
| `0x0600` | Host bridge | true | `Function reset`、`Capable=true` | pass |
| `0x0604` | PCI bridge | true | `Function reset`、`Capable=true` | pass |

原始结果位于
`20260714-esxi8-class-gate-v1/matrix-result.json`，matrix 与 restore verdict 均为
`pass`。实验 QEMU 6.2 binary SHA256 为
`26bef9b942dcaee8c4f10cf1b9b5837671acaadb3bdd466f5655e41056e0387d`。

这组结果只证明 class code 本身不是 blanket gate。特别是 `0x0604` 样本仍是 Type-0
endpoint，并不冒充一个实际产生 subordinate bus 的 Type-1 bridge。本组验收对象是
host 静态 `passthruCapable`，没有把 class/header 不一致的实验 function 分配给 L3 guest；
它足以否定 class-only 资格模型，但不是这种畸形设备组合的生产可用性证明。

### 2.2 真实 Type-1 bridge 的 FLR 对照

同一次 ESXi 启动中加入 QEMU TI X3130 upstream port。该模型是真实 Type-1 bridge，
QEMU 原生调用 `pcie_cap_flr_init()` 并实现 FLR config write；其上游 QEMU Root Port 是
同启动对照：

| Function | Header/PCIe type | FLR | Reset Method | Capable |
| --- | --- | --- | --- | --- |
| X3130 upstream `104c:8232` | Type-1 / Upstream Port | true | `Function reset` | false |
| QEMU Root Port `1b36:000c` | Type-1 / Root Port | false | `None` | false |

原始结果位于 `20260714-esxi8-real-bridge-flr-v2/matrix-result.json`，matrix 与 restore
verdict 均为 `pass`。X3130 负例最关键：ESXi 已接受其 FLR 并报告 `Function reset`，
却仍判 `passthruCapable=false`。所以对真实 bridge，FLR 是不充分条件；结构角色 gate
独立于 reset gate。结合上节 Type-0 `class=0604` 正例，也可排除“只按 0604 class
拒绝”的模型。

## 3. 可成立的推理

### 3.1 IOMMU 是资格门槛，不只是运行时优化

关闭 virtual VT-d 后，设备仍有可识别拓扑和 bridge reset，但 ESXi 将其判为 incapable。
因此 QEMU/VFIO 对标不能使用 no-IOMMU mode，也不能把“QEMU 能启动设备”当成 DirectPath
资格等价证据。

### 3.2 ESXi 关心可隔离的 reset boundary

在 Root Complex 直挂路径中，公开 FLR 是本矩阵唯一得到 `Function reset` 和 capable 的
条件。PM capability、D3hot callback 或 PME/D3 能力位都没有被该 ESXi build 接受。

同一无 FLR/PM endpoint 放到可整体 reset 的 Root Port/legacy bridge 后会变为 capable，
并把上游桥记录为 parent/dependency。这说明 reset 可用性是“endpoint 或其隔离边界”属性，
不能只检查 endpoint 的 Device Capabilities FLR bit。

### 3.3 ACS policy 与 reset method 是两个独立 gate

无 ACS 且 `enableACSCheckForRP=FALSE` 时，日志显示 bypass，设备仍 capable；开启严格检查
后，同一设备仍能报告 `Bridge reset`，但 capability 变为 false。由此可见 reset path
成立并不足以绕过 ACS policy。生产实现应默认要求真实 ACS/干净 IOMMU group，不应把
实验 bypass 或 Linux `pcie_acs_override` 当成隔离证明。

VMware 也有公开的检查绕过选项。[Broadcom KB 391460](https://knowledge.broadcom.com/external/article?articleNumber=391460)
针对 ESXi 8.0.3 ACS hardware configuration sanity check 过严的问题，给出的 workaround 是
`VMkernel.Boot.disableACSCheck=TRUE`，并明确说明 ACS 本身仍保持启用，只跳过过严检查。
[Broadcom 高级设置目录 KB 424082](https://knowledge.broadcom.com/external/article/424082/esxi-advanced-system-settings-mapping-to.html)
又公开区分了三个选项：`disableACSCheck` 是绕过所有 PCIe 设备的 ACS capability check，
`enableACSCheckForRP` 是启用 Root Port 的 ACS capability check，`enableACSDTP2P` 则是控制
ACS Direct Translated P2P。第三项属于 P2P 路由策略，不是 capable 检查绕过，也不是给硬件
伪造 ACS capability。
第一项没有显式传入 ACS boot option；测试 build 的启动日志观察到
`disableACSCheck=FALSE`、`enableACSCheckForRP=FALSE`。这只是 ESXi 8.0.3 build-24280767
和本 Root Port 路径的 baseline，不外推为所有 ESXi 版本、平台或升级后的固定默认值。
本地同拓扑三项 A/B/C 为：

| `disableACSCheck` | `enableACSCheckForRP` | 无 ACS endpoint |
| --- | --- | --- |
| `FALSE` | `FALSE` | bypass，`Capable=true` |
| `FALSE` | `TRUE` | `Capable=false` |
| `TRUE` | `TRUE` | bypass，`Capable=true` |

第三项日志同时确认两个 boot option 均为 `TRUE`，并打印
`Bypassing non-ACS capable device in hierarchy`；结果为 `Bridge reset`、
`Capable=true`，restore pass。证据索引为
[`evidence/esxi8-acs-check-bypass-20260714-summary.json`](evidence/esxi8-acs-check-bypass-20260714-summary.json)。
因此在本 build/路径上，全局 `disableACSCheck` 的 bypass 优先于 Root Port 严格检查。
这证明的是 admission policy，不证明 ESXi 伪造 ACS capability、改变硬件 P2P 路由或创建
了新的物理隔离边界。

### 3.4 `Capable/Enabled/Active` 仍不等于 AH 可分配

32G `pci-testdev` 与两个 e1000e 共用 Root Port 时：

- API：目标 `Capable/Enabled/Active=true`；
- VMX：静态 BDF、VID:DID、systemId 和 `ah.deviceHints` 均正确；
- 结果：BAR 枚举前报 `AH Failed to find a suitable device for pciPassthru0`。

QEMU 6.2 与 11.0.2 都复现。将大 BAR endpoint 移到独占 Root Port 后，只改变
dependency，VM 立即完成 IOMMU mapping 和 EFI Linux heartbeat。证据：

```text
20260714-lb32-qemu62-kvm-vcsa-v12/                 # shared dependency, fail
20260714-esxi8-largebar-32g-dedicated-after-enable/ # owner/dependency proof
20260714-lb32-dedicated-qemu11-kvm-v13/            # mapping + guest pass
```

所以 AH 的运行时选择至少还检查完整 dependency 的独占性/可租用性。Basic capability、
owner state、AH selection 和 VM MMIO admission 必须分别记录。

### 3.5 class code、FLR 与结构角色不是同一个 gate

- `0x0500 RAM memory`、`0x0b02 Pentium`、`0x0b40 Co-processor` 均可 capable，故
  CPU/memory base class 不构成 blanket blacklist。物理 CPU 本身通常也不是一个可移交
  PCI function；PCI class `0x0b` 只是 PCI function 的分类元数据。
- Type-0 endpoint 即使写成 `0x0600/0x0604` 仍 capable，故 bridge class code 本身不
  构成 blanket blacklist。
- 真正 Type-1 X3130 bridge 即使有 FLR 且 ESXi 报告 `Function reset`，仍 incapable，
  证明“有 FLR”对 host-fabric 结构节点不充分。
- 普通 endpoint 自身无 FLR 时，可借上游 bridge reset 变为 capable；此时 bridge 是
  parent/dependency/reset boundary，而不是作为 payload 暴露给 guest。

因此“CPU、内存、桥不能直通”必须拆开理解：独立 PCI memory/coprocessor endpoint 可以
通过；宿主 host bridge、root port、switch port、集成内存控制器等平台 fabric/resource
通常不能作为独立 payload 移交。当前证据支持按 header/PCIe port type、spawned bus、
拓扑职责和平台保留状态综合判断，但不推导 VMware 私有实现的具体检查顺序。

### 3.6 VMware 是否有白名单或黑名单

公开证据显示至少有三种不同概念，不能混称为一个 blacklist：

1. [Broadcom KB 312208](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
   要求生产支持组合位于 Compatibility Guide，并公开 IOMMU、ACS、reset 与 bridge
   dependency 约束。这是支持/HCL 边界，不等于运行时 `passthruCapable` 白名单；本地
   非 HCL 的 QEMU VID:DID 仍可得到 `Capable=true`。
2. [`/etc/vmware/passthru.map` 的公开格式](https://knowledge.broadcom.com/external/article/416531/esxi-host-experience-psod-hpe-proliant-x.html)
   是 `vendor-id device-id resetMethod fptShareable`，VID/DID 可用 `ffff` 通配。它是按
   设备 identity 覆盖 reset/shareability 的 quirk map，能间接改变资格或运行行为，
   但公开格式没有通用 `deny` 动作，不能直接称为黑名单。
3. [HostPciPassthruInfo API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.PciPassthruInfo.html)
   只说明 `passthruCapable` 由 vmkctl 决定，并暴露可能为 bridge 的 `dependentDevice`；
   它不公开 reason code 或完整算法。

所以可以实锤“不是纯 VID:DID/class 白名单，也不是 FLR 单条件”；不能实锤“VMware
内部绝不存在任何设备 deny/quirk”。公开可见、最接近设备策略表的是 `passthru.map`
和 HCL，而平台结构排除是另一层资格 gate。

## 4. QEMU/VFIO 对齐核对表

### 4.1 class-code 结果为什么不矛盾

PCI class code 适合描述 function 提供什么服务，不足以证明该 function 在宿主 PCI
fabric 中承担什么职责。`class=0604` 的 Type-0 endpoint 没有 secondary bus；真正的
Type-1 bridge 则会生成下游总线并成为其他 requester 的 parent/reset boundary。因此本轮
结果更适合解释为：ESXi 对“可分配 payload”的识别优先于 class label，随后再检查
IOMMU、reset、ACS 和平台保留条件。当前证据不能证明 ESXi 的内部检查顺序，但已经排除
class-only 和 FLR-only 两种模型。

Type 是 PCI configuration header 在 offset `0x0e` 的 `Header Type` 低 7 位；bit 7 仅表示
multifunction。它与 offset `0x09..0x0b` 的 programming-interface/subclass/base-class
相互独立：

| Header type | 结构意义 | 关键配置字段 | 作为 VFIO payload |
| --- | --- | --- | --- |
| Type-0 (`0x00`) | 普通 function/endpoint 的配置头 | 6 个 BAR、Subsystem ID、ROM BAR | 只是候选形状，仍需 isolation/reset/platform gate |
| Type-1 (`0x01`) | PCI-to-PCI/PCIe bridge 的配置头 | primary/secondary/subordinate bus、桥窗口、Bridge Control/SBR | fabric node，不作为普通 `vfio-pci` payload |
| Type-2 (`0x02`) | CardBus bridge | CardBus bus/window 字段 | 非本项目目标 |

因此 `Header Type=0x80` 仍是 multifunction Type-0，`0x81` 才是 multifunction Type-1。
真实 host bridge 也可能使用 Type-0 header，所以“Type-0”只是必要的结构候选，不等于
充分条件；平台保留、IOMMU group 和 reset gate 仍会排除宿主 root-complex 资源。

这个外部现象与 Linux VFIO 的公开实现高度同构：

- [`vfio_pci_core_register_device()`](https://github.com/torvalds/linux/blob/master/drivers/vfio/pci/vfio_pci_core.c)
  明确要求 `pdev->hdr_type == PCI_HEADER_TYPE_NORMAL`；Type-1 bridge 在注册为
  `vfio-pci` 设备前即被拒绝，而代码没有用 PCI class 做这一结构 gate。
- 同一函数按 reset 影响范围建立 device set：root-bus endpoint/SR-IOV VF 使用自身，
  可 slot reset 时使用 slot，否则使用整条 bus。也就是说 reset 是一个集合属性，不是
  endpoint 上的一位布尔属性。
- [VFIO UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/vfio.h)
  的 `VFIO_DEVICE_GET_PCI_HOT_RESET_INFO` 返回 hot reset 会影响的全部 function；执行
  `VFIO_DEVICE_PCI_HOT_RESET` 前必须证明拥有整个 affected set。
- [QEMU `hw/vfio/pci.c`](https://gitlab.com/qemu-project/qemu/-/blob/master/hw/vfio/pci.c)
  正是先查询该 affected set，再区分单个和多个在用 VFIO device 的 hot reset。

这不是 VMware 私有实现的源码旁证，只是一个公开、可审计且能解释相同外部现象的参考
架构。QEMU 平台无需仿造一个 class 白名单；Linux/VFIO 已经给出了更合适的结构和
reset-domain 原语。

### 4.2 推荐的 QEMU 平台判定模型

不要把 stock QEMU 能否启动作为唯一的 `passthroughCapable`。QEMU 是 attach 执行端，
Linux VFIO 是安全强制层；与 ESXi host inventory/AH 最接近的准入和调度逻辑应位于
libvirt 上层或自有 host service。推荐把一个 BDF 的依赖单元定义为：

```text
dependency(BDF) = closure(
    iommuIsolationGroup
  U resetAffectedSet
  U vfioDeviceSet
  U multifunctionAndRequesterAliasSet
  U platformReservedDependencies
)

eligible = vfioType0Bindable
        && hostIommuAndInterruptRemapReady
        && acceptedResetPathExists
        && acsAndRequesterIsolationPass
        && noPlatformReservation
        && noApplicableErrataDeny

availableNow = eligible
            && every(dependency(BDF)) is exclusively leasable

attachableToVM = availableNow
              && guestMmioAndRmrrAdmissionPass
              && requestedMigrationModeSupported
```

这里的 `vfioType0Bindable` 是 Linux `vfio-pci` 当前结构边界，不是建议自行按 class
重写一遍。`acceptedResetPathExists` 应同时检查 device reset 和
`VFIO_DEVICE_GET_PCI_HOT_RESET_INFO`，并把 affected set 纳入同一原子 lease。stock QEMU
即使只打印 reset warning 仍可能继续的场景，平台若要对标 ESXi，应在 preflight 阶段
转成明确拒绝。

Linux `vfio-pci` 确实还有一个很窄的
[VID:DID denylist](https://github.com/torvalds/linux/blob/master/drivers/vfio/pci/vfio_pci.c)：
它针对已知会造成可利用稳定性或安全问题的硬件 errata，默认阻止 probe，并提供带风险
告警的 `disable_denylist` 模块参数。这是 QEMU 平台值得参考的“黑名单”形态：只用于有
证据的设备例外，带 reason/source/kernel-range 和审计过的 override；不要把 CPU、memory、
bridge 等整个 class 当 denylist。

建议 API 不只返回一个布尔值，而返回 `eligible/available/attachable` 三层状态、完整
dependency BDF 列表、所选 reset method/affected set，以及稳定 reason code。这样既不会
把“硬件原则上可直通”和“此刻可租用”混在一起，也能准确解释 MMIO、RMRR、迁移或同组
占用造成的晚期失败。

### 4.3 启用 ACS override 时的 capable 模型

`pcie_acs_override` 一类补丁只让 Linux 的 ACS 判定/IOMMU group 构造相信设备之间可以
隔离；它不会给硬件增加 ACS redirect，也不能阻止 TLP 在无 ACS 的 switch/bridge 内做
P2P、绕过 root-port/IOMMU。[Linux VFIO 文档](https://docs.kernel.org/driver-api/vfio.html)
也明确把“无 ACS bridge 允许重定向而不经过 IOMMU”和 multifunction 内部 backdoor
列为 group 粒度变粗的原因；[PCI P2P 文档](https://docs.kernel.org/driver-api/pci/p2pdma.html)
进一步说明 switch 内路由能否绕过 root port 取决于 ACS 设置。因此启用补丁后，
`/sys/.../iommu_group` 只能作为 VFIO 的操作分组，不能单独作为安全边界。

VMware 的 `disableACSCheck=TRUE` 与 Linux override 不是完全相同的机制：公开 KB 将前者
定义为跳过 ESXi admission sanity check，Linux 补丁则会影响内核 ACS 判定和 IOMMU group
构造。VMware 的 `enableACSDTP2P` 又是单独的 Direct Translated P2P 开关，不能当作两者中
任何一个的同义词。但对平台 capable 模型，所有依赖软件绕过的路径都只能提供 `bypass`
provenance，不能替代真实 ACS 证据；调度器都必须按独立重建的物理隔离域租用设备。

平台 inventory 必须同时保留：

```text
kernelIommuGroup       # 当前 patched kernel 暴露的组，供 VFIO open/bind 使用
physicalIsolationDomain # 忽略 override 后，按真实 ACS、拓扑、RID alias 得到的隔离域
resetDomain            # FLR/slot reset/SBR/hot reset 实际影响的 function 集合

leaseDomain = closure(
    physicalIsolationDomain
  U resetDomain
  U multifunctionAndRequesterAliasSet
  U platformDependencies
)
```

`physicalIsolationDomain` 的首选证据是在同一硬件上用未启用 override 的 qualification
kernel 启动一次并保存原始 IOMMU group/topology；在线重建则必须读取真实 PCI config 中
每一级 port 的 ACS capability/control 和拓扑，不能调用已被 override 改写的
`pci_acs_enabled()` 结果。还应记录 `/proc/cmdline`、启动期 ACS override warning、kernel
build/source hash 和 override 匹配范围。仅仅“内核编入补丁但本次未激活”不应降级设备。

推荐按目标信任域给 verdict，而不是全局一个 capable：

| Policy | ACS override-dependent split | Verdict |
| --- | --- | --- |
| `untrusted-vm` | 不允许把同一 `physicalIsolationDomain` 拆给 VM/host/其他 VM | 拆分即 `false`；整域原子租给同一 VM 才可继续 |
| `trusted-dpdk` | 可以按显式风险策略运行，但不能宣称硬件隔离等价 | 默认 `conditional`；整域租给同一 DPDK trust domain 可提升为 `true` |
| `lab` | 可用于功能实验 | `unsafe-override`，不得进入生产 capability 数据 |

DPDK 与 VM 对 VFIO 来说都是能直接驱动 DMA 的 userspace owner，安全区别来自 trust
domain，而不是“DPDK”这个名字。如果 DPDK 使用 `uio_pci_generic/igb_uio` 而非
`vfio-pci`，则没有 VFIO/IOMMU 安全强制，生产 `untrusted-vm` 模型应直接判
`NO_IOMMU_ENFORCEMENT`。

建议输出至少包含以下 reason/provenance：

```json
{
  "headerType": "type0",
  "kernelIommuGroup": ["0000:41:00.0"],
  "physicalIsolationDomain": ["0000:41:00.0", "0000:42:00.0"],
  "isolationProvenance": "acs-override",
  "resetDomain": ["0000:41:00.0", "0000:42:00.0"],
  "requiredLease": ["0000:41:00.0", "0000:42:00.0"],
  "verdict": "conditional",
  "reason": "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN"
}
```

这里最重要的规则是：ACS override 可以改变“内核允许怎样打开设备”，不能缩小平台
自己的安全 lease。即使 patched group 已是 singleton，调度器仍必须用
`physicalIsolationDomain` 和 `resetDomain` 的并集加锁。

| VMware 可观察层 | QEMU/VFIO 实现要求 | 验收值 |
| --- | --- | --- |
| Host IOMMU gate | 启用 VT-d/AMD-Vi；禁止 no-IOMMU/unsafe interrupts | IOMMU group、map/unmap 和 interrupt remap 可审计 |
| Reset boundary | 读取 host `reset_method`；FLR 优先，bus reset 时租用整组 | callback trace、影响 function 集合、十次复用 |
| Function role | 区分 assignable endpoint 与 host bridge/root/switch port 等 fabric node；不可只按 class code | header type、PCIe port type、subordinate bus、parent/dependency 一致 |
| ACS policy | 要求真实 ACS 或天然隔离拓扑 | 不依赖 ACS override；group 与拓扑一致 |
| Dependency | 将 IOMMU group、reset domain、multifunction/bridge dependency 合并成原子 lease | 同组不能拆给不同 VM；失败指出具体 dependency |
| Owner state | 分离 `eligible`、`bound-to-vfio`、`leased`、`attached` | 状态机与恢复日志，不用一个布尔值代替 |
| Dynamic candidate | 先按 ID/label 选具体 BDF，再展开 dependency | manifest 记录候选、拒绝原因和最终 BDF |
| MMIO/RMRR | 在选卡之后按整组 BAR/RMRR 计算 OVMF aperture 和 host hole64 | guest BAR/root window 与失败 budget |
| Migration | 默认拒绝运行态迁移；关机 relocate 后重新选卡 | lease 释放、目标主机重新解析、无持久 BDF |

推荐的 QEMU launcher 顺序：

1. 枚举候选及 host IOMMU group、ACS、`reset_method`、BAR、ROM、RMRR。
2. 合并完整 dependency，原子加锁；任何成员被占用则拒绝或选择下一候选。
3. 对最终候选计算 below-4G packing；不能容纳时计算对齐后的 high aperture。
4. 同时生成 `vfio-pci,host=BDF`、OVMF `X-PciMmio64Mb`、host bridge
   `pci-hole64-size` 和 machine-readable manifest。
5. 启动后验证 guest BAR/root window、IOMMU map 和中断；停止后先 detach/unmap 再释放 lease。

## 5. 复现

完整矩阵会逐案重启 outer ESXi，并在结束时恢复基线：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

只复现本次 class/bridge 机制：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID `
  --cases root-virtio-class-network root-virtio-class-memory `
    root-virtio-class-pentium root-virtio-class-coprocessor `
    root-virtio-class-host-bridge root-virtio-class-pci-bridge `
    pcie-x3130-upstream-flr
```

只复现 ACS policy 与公开 global bypass：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID `
  --cases pcie-virtio-no-acs pcie-virtio-no-acs-strict `
    pcie-virtio-no-acs-global-bypass
```

大 BAR dependency A/B 复现见
[`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。每次结论至少保存 outer QEMU
argv/HMP、ESXi API `pciPassthruInfo`、`esxcli hardware pci list`、有效 VMX、
`vmware.log`、guest serial 和 restore verdict。

## 6. 仍需真实硬件回答的问题

- HCL/vendor driver 是否在 basic capability 之外增加设备级 policy。
- 真实 FLR/SBR 是否清除设备内部、链路外设或固件保留的敏感状态。
- 真实 ACS、root complex requester-ID alias 和平台 RMRR 的电气/固件边界。
- SR-IOV PF/VF 的 driver/NVM/firmware 初始化与 VF 独立 reset。

这些问题不应由虚拟 endpoint 的通过结果外推。
