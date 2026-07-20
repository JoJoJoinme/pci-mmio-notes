# VMware DirectPath 可观察实现模型与实验矩阵

状态：`REFERENCE MODEL / EXPERIMENT DRIVEN`
基线：`ESXi 8.0.3 build 24280767 / API 8.0.3.0 / vHW20`
覆盖：`EPIC-PCI-01 / F1-F8 / 39 Tech Stories`

本文所说“补齐 VMware 实现”，指补齐 VMware 的 **官方外部合同、可观察行为和带明确标签的
机制推断**，不是声称拿到了 VMware 私有源码。机器可读覆盖矩阵位于
[`contracts/vmware-behavior-model.json`](../contracts/vmware-behavior-model.json)，官方来源位于
[`contracts/vmware-source-register.json`](../contracts/vmware-source-register.json)，每次新实验的
结果合同位于
[`contracts/vmware-experiment-result.schema.json`](../contracts/vmware-experiment-result.schema.json)。

## 1. 事实边界

每条结论必须属于以下一种类型：

| 字段 | 含义 | 可以证明什么 |
| --- | --- | --- |
| `OFFICIAL_CONTRACT` | Broadcom KB、Compatibility Guide、vSphere API schema | 官方承诺的字段、要求、限制；不能证明内部算法 |
| `OBSERVED_BEHAVIOR` | VMX、API、task/event、vmkernel/vmware.log、Guest、L0 trace | 冻结环境中的实际输入输出；不能直接外推所有设备/版本 |
| `INFERRED_MECHANISM` | 为解释多组观察而建立的最小机制模型 | 可生成新实验假设；反例出现时必须修改 |
| `QMAN_DECISION` | Qman 为安全性、可运维性或通用性选择的实现 | 只能由 Qman 自身 Case 证明，不能借 VMware 黑盒关闭 |

旧文档中两套互相冲突的 E1-E4 不再作为主分类。新实验至少记录：

```text
caseId / legacyIds / subject / sutProfile / techStories
basisKind / observationStatus / sourceIds
input / expected / observed / limitations
artifactPaths / SHA-256 / run timestamp
```

## 2. VMware 可观察控制链

现有官方接口和实验共同支持下面这条外部行为链；方框之间怎样编码属于未知内部实现：

```text
Host PCI inventory
  → passthruCapable + dependentDevice
  → configured(enabled) / effective(active) owner
  → Static exact backing 或 Dynamic allowedDevice selector
  → host placement + VM memory/PCI/MMIO admission
  → power-on assignedId / IOMMU / reset / Guest PCI surface
  → power-off cleanup / owner state / lifecycle restrictions
  → powered-off relocate 或 HA cold restart
```

官方 API 的 `passthruCapable` 只表示 vmkctl 判断“可能直通”；Compatibility Guide 则单独规定
生产支持只覆盖列表设备。官方材料没有证明 HCL 参与 `passthruCapable` 算法。因此 Qman 采用
“通用 technical attachability + 精确 compatibility support”两轴模型，不复制一个混合布尔值。

当前 39 个 Tech Story 的 VMware 观察覆盖为：

```text
VERIFIED       4   当前冻结 nested profile 已直接观察到完整外部语义
PARTIAL       26   有观察，但缺物理设备、并发、故障或更广 profile
UNKNOWN        4   尚无直接 VMware 实验
NOT_APPLICABLE 5   Qman 内部机制，不能由 VMware 黑盒证明
```

`VERIFIED` 不是 Qman implementation done，也不是物理硬件 qualification。

## 3. F1-F8 / Tech Story 映射

### F1 设备可见性与支持资格

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F1-01 immutable snapshot | API 暴露 HostPciDevice 与 passthru info；未承诺跨接口原子快照、epoch 或 hash | `PARTIAL` | `VMW-CAP00..22`、`VMW-O00`；增加 inventory 变化期间三阶段一致性实验 |
| TS-F1-02 DMA provider proof | IOMMU 是必要条件；已有 VT-d requester/domain trace 与无 DMAR 负控 | `PARTIAL` | `VMW-D00/D01/D06`；补裸机 IOMMU/IR 和真实 DPDK PMD + VM 共存 |
| TS-F1-03 physical isolation domain | ACS 是必要条件；8.0.3 `disableACSCheck` 仅跳过过严检查，不能证明隔离 | `PARTIAL` | `VMW-A01`、`VMW-S04`；补物理 ACS/RID alias 和 Linux override shadow-domain 对照 |
| TS-F1-04 dependency closure | dependentDevice、multifunction 与 legacy bridge 集体分配可观察 | `PARTIAL` | `VMW-A02..A05`、`VMW-O05A/B/O10`；补真实 GPU/HBA、PF/VF 和任意拓扑闭包 |
| TS-F1-05 qualification profile | Compatibility Guide 定义支持清单，运行 capability 与 HCL 是两轴 | `PARTIAL` | CAP/LF/MMIO 已有；补服务器×BIOS×设备固件×Guest×驱动×workload 的物理矩阵 |

### F2 设备池与宿主业务共存

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F2-01 owner state model | configured/enabled 与 effective/active 分离，支持 live/deferred/reboot 状态 | `VERIFIED` | `VMW-O00..O03/O07`；该状态机仍需 Qman 自己实现 |
| TS-F2-02 owner preflight | native consumer Busy、dependentDevice 和 exclusive assignment 影响转换 | `PARTIAL` | `VMW-O04/O05A/O05B/O10`；补物理 HBA/GPU/boot-critical consumer 与并发维护 |
| TS-F2-03 all-or-rollback rebind | 成功整组切换和 Busy 原子拒绝已观察，但中途失败未知 | `PARTIAL` | `VMW-O01/O04/O05`；注入第 N 个 member rebind 失败 |
| TS-F2-04 early-boot claim | persisted owner intent 可在真实 host reboot 后按同 BDF 生效 | `PARTIAL` | `VMW-O03/O07`；补换卡、换槽、stale claim 与 fingerprint |
| TS-F2-05 post-reboot reconcile | reboot 后 owner/module/BDF 可读回 | `PARTIAL` | `VMW-O07/L03/L05`；补 mismatch→failed/quarantine 分支 |

### F3 Static 固定设备分配

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F3-01 stable identity | Static backing 保存 id/vendor/device/systemId；未公开更强物理 fingerprint | `PARTIAL` | 同 BDF reboot 已有；增加同 BDF 换设备和 physical-path 漂移 |
| TS-F3-02 durable exclusive lease | 跨 VM 排他、释放后复用和不重复分配可观察；CAS/epoch 未公开 | `PARTIAL` | `VMW-O10`、`VMW-X02`；补并发 power-on、lease persistence 与 stale owner |
| TS-F3-03 IOMMUFD/fd-only attach | IOMMU/DMA/reset 外部语义可参考；IOMMUFD 与 fd-only 是 Qman 技术选择 | `NOT_APPLICABLE` | 由 Qman attach/launcher Case 自证 |
| TS-F3-04 same-BDF replacement | VMware 如何检测同 BDF 身份替换尚无直接证据 | `UNKNOWN` | 新建 `VMW-STATIC-IDENTITY-001`，替换 outer endpoint 身份但保留 BDF |
| TS-F3-05 Static transaction FSM | start/stop/forced-off 外部生命周期已覆盖，内部 FSM/补偿不可见 | `PARTIAL` | O/R/L 系列；补每个外部阶段的 crash/fault injection |

### F4 VM 启动准入与 Guest 兼容

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F4-01 PCI/MMIO planner | firmware、BAR、RMRR、device count 和 root layout 参与 power-on admission | `PARTIAL` | `VMW-LF00..06`、`VMW-M00..07`、X01；补多级桥 exact solver、ReBAR、sub-4K 和上限探测 |
| TS-F4-02 versioned Guest profile | vHW/firmware/motherboardLayout/MMIO knobs 形成稳定配置表面 | `PARTIAL` | LF 与 QEMU 对照已有；冻结 Qman Q35/OVMF/QEMU profile 并量化 ABI gap |
| TS-F4-03 full reservation | 全 VM 内存 reservation 是官方要求，page budget/RMRR 会影响 admission | `PARTIAL` | M04/M07/S05；补多桥、RAM pressure、ROM/aux BAR/RMRR 组合 |
| TS-F4-04 post-start verification | Guest BAR/root window、bridge、IRQ 与 VT-d mapping 已在每轮关联 | `VERIFIED` | LF/M/D/I 当前 profile 已闭环；物理 HCL profile 仍须单独 qualification |
| TS-F4-05 raw QEMU/QMP gate | VMware task/API 负例可参考，QMP/launcher ACL 是 Qman 自身安全边界 | `NOT_APPLICABLE` | 由 Qman API/launcher/QMP 攻击 Case 自证 |

### F5 设备生命周期与故障恢复

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F5-01 reset contract | reset/dependency capability 可观察；执行前 affected-set 重检未公开 | `PARTIAL` | CAP、`VMW-R00/R04`；补物理 FLR/SBR/D3、vendor state 和 affected-set race |
| TS-F5-02 ordered teardown | guest translation 在关机后失效并切回 host domain，虚拟 FLR callback 已见 | `PARTIAL` | `VMW-D01/R00`；补完整 DMA→IRQ→map→reset→owner 顺序和 stale DMA 负控 |
| TS-F5-03 crash reconcile | outer host SIGKILL 后 host/owner/VM 可恢复；journal 内部不可见 | `PARTIAL` | `VMW-L04`；补 hostd/vCenter/agent 各阶段 crash |
| TS-F5-04 whole-bundle quarantine | 没有 reset-failure 后 quarantine 的直接 VMware 观察 | `UNKNOWN` | 新建 `VMW-QUARANTINE-001`，覆盖 reset/state-probe/半组故障和人工恢复 |
| TS-F5-05 lifecycle restriction | snapshot、suspend、Classic/Dynamic live vMotion 均被拒绝 | `PARTIAL` | `VMW-L00/L01/L02`；补 FT；Qman runtime hotplug 另由自身负向门验证 |

注意：vSphere API 8.0.1 起出现 `fixedPassthruHotPlugEnabled`。它是 fixed passthrough 的独立
runtime hot-plug 能力，不等于 Dynamic DirectPath 的 power-on 选卡。当前实验尚未验证其设备
范围、Guest 表面、reset/rollback 和失败恢复，因此 Qman V3 暂时保持 runtime hotplug
fail-closed，并把是否对标该能力保留为单独产品决策。

### F6 Dynamic 动态设备分配

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F6-01 selector builder | allowedDevice 支持 VID:DID 和可选 subsystem/revision，customLabel 要求匹配 | `PARTIAL` | `VMW-X00/X01`；补 subsystem/revision/customLabel 与非法 selector A/B |
| TS-F6-02 global solver | 已观察选候选、资源 envelope 和耗尽；全局优化算法未公开 | `PARTIAL` | `VMW-X01/X02/M07`；补 greedy-fail/global-success、异构 RMRR 与多 requirement |
| TS-F6-03 atomic multi-reservation | 多需求失败不降级和排他行为有部分证据，事务原子性未知 | `PARTIAL` | X02/O10；补双 VM 竞争、部分 reservation fault、inventory epoch 改变 |
| TS-F6-04 runtime assignedId | assignedId 开机设置、关机清空、目标 host 重新选择已官方定义并观察 | `VERIFIED` | `VMW-X00/X03`；Qman 仍需实现等价 manifest/lease |
| TS-F6-05 reuse Static core | VMware 私有代码是否复用不可观察 | `NOT_APPLICABLE` | 用 Qman 单一 attach/release core 的代码和测试证明 |

### F7 跨主机放置与冷恢复

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F7-01 host capability aggregate | vCenter 可读取各 host Dynamic candidates 并进行 initial placement | `PARTIAL` | 双主机/X02/X03 已有；补异构 HCL/profile、容量变化和 scheduler snapshot |
| TS-F7-02 consensus/fencing token | VMware 内部 store/token 无公开可观察合同 | `NOT_APPLICABLE` | Qman 自测 linearizability、generation 与 stale token |
| TS-F7-03 target-host re-solve | powered-off relocate 后在目标 host 重新产生 assignedId，而非复制源 BDF | `VERIFIED` | `VMW-X03`；当前仅同构两主机 |
| TS-F7-04 BMC/power fence proof | VMware 对旧 host 的 fencing 条件没有当前直接实验 | `UNKNOWN` | 新建 `VMW-CLUSTER-FENCE-001`：真实 BMC power-off 与未 fence 拒绝 A/B |
| TS-F7-05 failure matrix | 已有一次 outer host SIGKILL 和 reconnect，分区/store/真实断电未覆盖 | `PARTIAL` | `VMW-L04`；补 management partition、old agent、store failover、HA cold restart |

### F8 可运维、可审计、可发布

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F8-01 manifest/events/audit | API/task/log/ESXCLI 提供分散状态；没有统一 assignment manifest/lease timeline | `PARTIAL` | activation/Dynamic runners；增加 actor+task+VM+host+device 关联实验 |
| TS-F8-02 evidence/hash | 部分 summary 已有 artifact hash，但 schema 和覆盖不统一 | `PARTIAL` | 迁移所有 `VMW-*` 到统一 result schema，缺 hash 时不升级状态 |
| TS-F8-03 US→Case→Evidence | 旧资料只有人工索引且 Case ID 与 Qman 冲突 | `UNKNOWN` | 本矩阵先建立 TS→VMW Case；下一步为每次 run 生成机器 result/index |
| TS-F8-04 Qman fail-closed evaluator | VMware 观察不能证明 Qman release gate | `NOT_APPLICABLE` | 由 Qman risk/case/evidence evaluator 自证 |

## 4. 独立实验命名空间

VMware 观察用例统一使用 `VMW-*`；旧 ID 仅作为 `legacyIds` 保留，不能再与 Qman 产品
C/O/S/D/M/F Case 共用权威命名空间。

| 旧范围 | Canonical VMware ID | 说明 |
| --- | --- | --- |
| G00-G04 | `VMW-G00..G04` | 实验入口门 |
| A00-A06、CAP00-CAP22 | `VMW-A*`、`VMW-CAP*` | capability/topology/dependency |
| LF00-LF06、M00-M07 | `VMW-LF*`、`VMW-M*` | firmware/layout/MMIO |
| D00-D01/D06、I00-I02、R00-R04 | `VMW-D*`、`VMW-I*`、`VMW-R*` | VMware DMA/IRQ/reset |
| S00-S05 | `VMW-S*` | ROM/PME/AER/P2P/RMRR；lab C00-C03 是 `VMW-S03` 子变体 |
| X00-X03 | `VMW-X*` | Dynamic/cold relocate |
| L00-L05 | `VMW-L*` | VMware lifecycle |
| O00-O08/O10 | `VMW-O*` | owner activation；O09 仍是 Qman reference-model Case |

不能机械加前缀的旧 Case：

- D02/D03 是 QEMU/VFIO A/B，迁为 `QEMU-CTL-D02/D03`。
- D04/D05 是 Qman qualification/policy Case，不属于 VMware。
- L06-L09 是 Qman runtime-hotplug 负向门，映射到 Qman S13-S16。
- Q00-Q06 是 QEMU firmware 对照，迁为 `QEMU-CTL-Q00..Q06`。

现有 artifact 不重命名；canonical result 通过 `legacyIds` 指向旧路径，避免破坏 hash 和复现脚本。

## 5. 实验优先级

### P0：建立 compatibility catalog 的物理 qualification

1. `VMW-PHY-QUAL-*`：选 HCL 内 NIC、NVMe/HBA、GPU，冻结 server/BIOS/device firmware/
   ESXi/Guest/driver/workload。
2. `VMW-PHY-RESET-*`：FLR、SBR、D3 在正常关机、forced-off、VM crash、host power loss 后的
   寄存器、队列、DMA、IRQ 和外部链路清理。
3. `VMW-PHY-IOMMU-*`：真实 ACS、RID alias、IOMMU/interrupt remapping、P2P 与 strict/bypass。
4. `VMW-PHY-OWNER-*`：HBA storage path、NIC vSwitch、GPU/multifunction busy，外加换卡、换槽、
   同 BDF 身份变化。
5. `VMW-PHY-PROFILE-*`：INTx、可执行 Option ROM、SR-IOV PF/VF、RMRR、ReBAR 负例。

### P1：补全 Dynamic 与通用 PCI 语义

- subsystem/revision/customLabel 精确 selector。
- 两 requirement 的 greedy-fail/global-success 与双 VM 并发竞争。
- reservation 后 inventory/identity 变化和中途 fault。
- 异构 RMRR/BAR/reset dependency candidate。
- 多级桥、辅助 BAR、sub-4KB、ReBAR 和运行时设备上限。
- reset/owner 中途故障与 whole-bundle quarantine。

### P2：补齐 V3 Cluster

- 异构主机 capability/profile 聚合和 initial placement。
- 真实 host 断电后的 HA cold restart。
- 未完成 power fence 时保持 stopped 的负例。
- candidate exhaustion、management partition、old agent、vCenter/store failover。
- Static host-affine 与 Dynamic target-host re-solve 对照。

## 6. 实验关闭规则

一个 VMware 观察从 `UNKNOWN/PARTIAL` 升级为 `VERIFIED`，必须同时满足：

1. Canonical `VMW-*` Case 有冻结输入、明确预期和自动/半自动 runner。
2. 记录精确 ESXi build、API、vHW、server/BIOS、device/firmware、Guest/driver/workload。
3. 保存 API/task/log/Guest/L0 trace 中适用的原始 artifact 和 SHA-256。
4. 至少一个负向或边界对照，证明不是“VM 恰好开机”。
5. `limitations` 明确 nested、synthetic、single-build 或缺物理设备等外推边界。
6. 结果只更新 VMware reference coverage，不更新 Qman milestone、qualification 或 support state。
