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

四层事实不得相互冒充。特别是：

- `OFFICIAL_CONTRACT` 与 `OBSERVED_BEHAVIOR` 的 subject 是 VMware；它们可以定义对标输入，不能把
  Qman Case、Risk、milestone 或 compatibility 状态改成完成。
- `OBSERVED_BEHAVIOR=VERIFIED` 只表示冻结的 ESXi nested profile 已直接观察到该外部切片；不能外推
  到真实 GPU/HBA/加速卡、其他 ESXi build、Qman legacy/modern backend 或 ARM。
- `INFERRED_MECHANISM` 只产生可证伪假设，不能当作 VMware 私有实现说明。
- `QMAN_DECISION` 必须由 Qman 自己的可执行 Case 和证据关闭；VMware E3、官方 KB 或 API schema
  都不能转授为 Qman implementation、E4 qualification 或 `SUPPORTED`。

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
  → powered-off relocate / target-host re-solve
```

官方 API 的 `passthruCapable` 只表示 vmkctl 判断“可能直通”；Compatibility Guide 则单独规定
VMware 的 SKU 支持列表。官方材料没有证明 HCL 参与 `passthruCapable` 算法。因此 Qman 保留
“通用 technical attachability + support policy”两轴模型，但不复制 VMware SKU HCL：Qman 支持
策略按消费 GPU、专业 GPU、HBA 和加速卡的技术 trait 定义。真实实验仍必须记录准确 specimen、
firmware、host 和 Guest/driver/workload 以便复现；这些字段是证据元数据，不自动成为公开 HCL key。

当前 39 个 Tech Story 的 VMware 观察覆盖为：

```text
VERIFIED       4   当前冻结 nested profile 已直接观察到完整外部语义
PARTIAL       27   有观察，但缺物理设备、并发、故障或更广 profile
UNKNOWN        3   尚无直接 VMware 实验
NOT_APPLICABLE 5   Qman 内部机制，不能由 VMware 黑盒证明
```

`VERIFIED` 不是 Qman implementation done，也不是物理硬件 qualification。

### 2.1 Qman V3 core parity 分类

Qman V3 的平台范围是：legacy-first、单一控制面合同，所有受支持软件线均提供完整 V3；x86
使用 versioned q35/i440fx + UEFI/SeaBIOS profile，ARM 使用 versioned virt + UEFI profile。
VMware 只提供外部语义参考，不能证明这些 Qman profile。

| Core parity | 分类 | VMware reference 覆盖 | 最小未闭环实验 / Qman 自证 |
| --- | --- | --- | --- |
| capability、IOMMU/ACS、dependency 与保守 reason | `MUST_MATCH` | `PARTIAL` | `VMW-CAP-001`、`VMW-DMA-001`、`VMW-ACS-001`、`VMW-DEP-001`、`VMW-QUAL-001` |
| configured/effective owner 分离 | `MUST_MATCH` | `VERIFIED` | Qman `QMAN-BACKEND-CONFORMANCE-001` 自证两后端 |
| owner rollback、boot reconcile | `MUST_MATCH` | `PARTIAL` | `VMW-OWNER-003`、`VMW-OWNER-005` |
| Static identity、排他与 release-before-reuse | `MUST_MATCH` | `PARTIAL` | `VMW-STATIC-IDENTITY-001`、`VMW-STATIC-002` |
| Dynamic selector、全量求解、原子 reservation、runtime assignedId | `MUST_MATCH` | 整体 `PARTIAL`；assignedId 切片 `VERIFIED` | `VMW-DYNAMIC-001`、`VMW-DYNAMIC-003`、`VMW-DYNAMIC-004` |
| firmware/MMIO/full reservation/post-start verify | `MUST_MATCH` | 整体 `PARTIAL`；冻结 profile 的 post-start 切片 `VERIFIED` | `VMW-ADMISSION-001/002`、`VMW-GUEST-VERIFY-001`；ARM 由 `QMAN-ARM-VIRT-UEFI-001` 自证 |
| VMware 与 Qman 的精确 chipset、bridge identity、BAR 地址相同 | `ACCEPTABLE_DIFFERENCE` | `NOT_APPLICABLE` | Qman 只需冻结自身 guest ABI 并证明等价准入结果 |
| legacy group/container、IOMMUFD/cdev、fd handoff 与单控制面内部实现 | `ACCEPTABLE_DIFFERENCE` | `NOT_APPLICABLE` | `QMAN-BACKEND-CONFORMANCE-001` |
| DMA/IRQ teardown、reset 与 clean release | `MUST_MATCH` | `PARTIAL` | `VMW-TEARDOWN-001`、`VMW-QUARANTINE-001` |
| snapshot、suspend/resume、live migration 拒绝 | `MUST_MATCH` | 适用拒绝切片 `VERIFIED` | Qman `QMAN-LIFECYCLE-DENY-001`；VMware 结果不转授 |
| source/target 在线、source clean release 后 cold relocation | `MUST_MATCH` | `PARTIAL`；仅 target re-solve `VERIFIED` | `VMW-COLD-CLEAN-001`、`VMW-COLD-NOCLEAN-001`、`VMW-COLD-EXHAUST-001` |
| 消费 GPU、专业 GPU、HBA、加速卡技术 trait | `MUST_MATCH` | `UNKNOWN`，仅有 synthetic 前提 | `VMW-QUAL-001`；四类 specimen 作为其物理 qualification 子矩阵 |
| 复制 VMware SKU HCL | `ACCEPTABLE_DIFFERENCE` | `PARTIAL` | Qman 使用 trait policy；不宣称继承 VMware 支持合同 |
| owner/VM/source-target/device/assignedId 的可审计关联 | `MUST_MATCH` | `PARTIAL` | `VMW-TRACE-001`；Qman manifest 另行自证 |
| host-failure HA restart、BMC/power fencing | `OUT_OF_SCOPE` | Qman `NOT_APPLICABLE` | 不进入 V3 release gate；失联 source 永不视为 clean release |
| Fault Tolerance capability | `OUT_OF_SCOPE` | Qman `NOT_APPLICABLE` | 未做本地 FT 实验不是 V3 缺口 |
| fixed/Dynamic runtime PCI hotplug capability | `OUT_OF_SCOPE` | Qman `NOT_APPLICABLE` | Qman 所有 mutation 入口仍须稳定拒绝 |

这里的 `MUST_MATCH` 指外部安全/生命周期语义，不要求复制 VMware 私有算法、API 形状或 guest
chipset identity。`OUT_OF_SCOPE` 指 Qman 不提供该能力；对于 runtime hotplug 等入口，仍需要 Qman
负向 Case 证明请求被拒绝，但不需要实现正向能力。

## 3. F1-F8 / Tech Story 映射

### F1 设备可见性与支持资格

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F1-01 immutable snapshot | API 暴露 HostPciDevice 与 passthru info；未承诺跨接口原子快照、epoch 或 hash | `PARTIAL` | `VMW-CAP00..22`、`VMW-O00`；增加 inventory 变化期间三阶段一致性实验 |
| TS-F1-02 DMA provider proof | IOMMU 是必要条件；已有 VT-d requester/domain trace 与无 DMAR 负控 | `PARTIAL` | `VMW-D00/D01/D06`；补裸机 IOMMU/IR 和真实 DPDK PMD + VM 共存 |
| TS-F1-03 physical isolation domain | ACS 是必要条件；8.0.3 `disableACSCheck` 仅跳过过严检查，不能证明隔离 | `PARTIAL` | `VMW-A01`、`VMW-S04`；补物理 ACS/RID alias 和 Linux override shadow-domain 对照 |
| TS-F1-04 dependency closure | dependentDevice、multifunction 与 legacy bridge 集体分配可观察 | `PARTIAL` | `VMW-A02..A05`、`VMW-O05A/B/O10`；补真实 GPU/HBA、PF/VF 和任意拓扑闭包 |
| TS-F1-05 qualification profile | Compatibility Guide 定义 VMware SKU 支持清单，运行 capability 与支持策略是两轴 | `PARTIAL` | Qman 不复制 SKU HCL；按消费/专业 GPU、HBA、加速卡 trait 建 Case，run 中仍冻结 specimen/firmware/host/Guest/driver/workload |

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
| TS-F3-03 backend attach | IOMMU/DMA/reset 外部语义可参考；legacy group/container、IOMMUFD/cdev 与 fd handoff 都是 Qman 技术选择 | `NOT_APPLICABLE` | `QMAN-BACKEND-CONFORMANCE-001` 由 Qman 在 legacy/modern 两条产品线自证，VMware 不能代证 |
| TS-F3-04 same-BDF replacement | VMware 如何检测同 BDF 身份替换尚无直接证据 | `UNKNOWN` | 新建 `VMW-STATIC-IDENTITY-001`，替换 outer endpoint 身份但保留 BDF |
| TS-F3-05 Static transaction FSM | start/stop/forced-off 外部生命周期已覆盖，内部 FSM/补偿不可见 | `PARTIAL` | O/R/L 系列；补每个外部阶段的 crash/fault injection |

### F4 VM 启动准入与 Guest 兼容

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F4-01 PCI/MMIO planner | firmware、BAR、RMRR、device count 和 root layout 参与 power-on admission | `PARTIAL` | `VMW-LF00..06`、`VMW-M00..07`、X01；补多级桥 exact solver、ReBAR、sub-4K 和上限探测 |
| TS-F4-02 versioned Guest profile | vHW/firmware/motherboardLayout/MMIO knobs 形成稳定配置表面 | `PARTIAL` | LF 与 QEMU 对照已有；Qman 分别冻结 x86 q35/i440fx + UEFI/SeaBIOS 与 ARM virt + UEFI，精确 chipset identity 属可接受差异 |
| TS-F4-03 full reservation | 全 VM 内存 reservation 是官方要求，page budget/RMRR 会影响 admission | `PARTIAL` | M04/M07/S05；补多桥、RAM pressure、ROM/aux BAR/RMRR 组合 |
| TS-F4-04 post-start verification | Guest BAR/root window、bridge、IRQ 与 VT-d mapping 已在每轮关联 | `VERIFIED` | LF/M/D/I 当前 nested profile 已闭环；物理 device-trait profile 仍须单独 qualification |
| TS-F4-05 raw QEMU/QMP gate | VMware task/API 负例可参考，QMP/launcher ACL 是 Qman 自身安全边界 | `NOT_APPLICABLE` | 由 Qman API/launcher/QMP 攻击 Case 自证 |

### F5 设备生命周期与故障恢复

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F5-01 reset contract | reset/dependency capability 可观察；执行前 affected-set 重检未公开 | `PARTIAL` | CAP、`VMW-R00/R04`；补物理 FLR/SBR/D3、vendor state 和 affected-set race |
| TS-F5-02 ordered teardown | guest translation 在关机后失效并切回 host domain，虚拟 FLR callback 已见 | `PARTIAL` | `VMW-D01/R00`；补完整 DMA→IRQ→map→reset→owner 顺序和 stale DMA 负控 |
| TS-F5-03 crash reconcile | outer host SIGKILL 后 host/owner/VM 可恢复；journal 内部不可见 | `PARTIAL` | `VMW-L04`；补 hostd/vCenter/agent 各阶段 crash |
| TS-F5-04 whole-bundle quarantine | 没有 reset-failure 后 quarantine 的直接 VMware 观察 | `UNKNOWN` | 新建 `VMW-QUARANTINE-001`，覆盖 reset/state-probe/半组故障和人工恢复 |
| TS-F5-05 lifecycle restriction | snapshot、suspend/resume、Classic/Dynamic live vMotion 拒绝切片已观察；FT 与 runtime hotplug 正向能力不在 Qman V3 | VMware composite=`PARTIAL`；Qman 适用参考切片=`VERIFIED` | `VMW-L00/L01/L02`；不再以 FT/hotplug 正向实验阻塞 V3；Qman 仍由 `QMAN-LIFECYCLE-DENY-001` 自证所有入口拒绝 |

注意：vSphere API 8.0.1 起出现 `fixedPassthruHotPlugEnabled`。它是 fixed passthrough 的独立
runtime hot-plug 能力，不等于 Dynamic DirectPath 的 power-on 选卡。Qman V3 已将其正向能力标为
`OUT_OF_SCOPE/NOT_APPLICABLE`；这不会取消负向安全门，API、scheduler、launcher 与 QMP 仍须稳定
拒绝运行中 PCI add/remove。

### F6 Dynamic 动态设备分配

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F6-01 selector builder | allowedDevice 支持 VID:DID 和可选 subsystem/revision，customLabel 要求匹配 | `PARTIAL` | `VMW-X00/X01`；补 subsystem/revision/customLabel 与非法 selector A/B |
| TS-F6-02 global solver | 已观察选候选、资源 envelope 和耗尽；全局优化算法未公开 | `PARTIAL` | `VMW-X01/X02/M07`；补 greedy-fail/global-success、异构 RMRR 与多 requirement |
| TS-F6-03 atomic multi-reservation | 多需求失败不降级和排他行为有部分证据，事务原子性未知 | `PARTIAL` | X02/O10；补双 VM 竞争、部分 reservation fault、inventory epoch 改变 |
| TS-F6-04 runtime assignedId | assignedId 开机设置、关机清空、目标 host 重新选择已官方定义并观察 | `VERIFIED` | `VMW-X00/X03`；Qman 仍需实现等价 manifest/lease |
| TS-F6-05 reuse Static core | VMware 私有代码是否复用不可观察 | `NOT_APPLICABLE` | 用 Qman 单一 attach/release core 的代码和测试证明 |

### F7 跨主机放置与在线 clean-release 冷迁移

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F7-01 host capability aggregate | vCenter 可读取各 host Dynamic candidates 并进行 initial placement | `PARTIAL` | 双主机/X02/X03 已有；补异构 trait/profile、容量变化和 scheduler snapshot |
| TS-F7-02 control-plane generation/backend reuse | VMware 内部 store、token 与代码复用无公开可观察合同 | `NOT_APPLICABLE` | 由 Qman 单控制面和 `QMAN-BACKEND-CONFORMANCE-001` 自证；host-failure fencing 不在范围 |
| TS-F7-03 target-host re-solve | powered-off relocate 后在目标 host 重新产生 assignedId，而非复制源 BDF | VMware target re-solve=`VERIFIED`；完整 Qman contract=`PARTIAL` | `VMW-X03` 仅覆盖同构双主机；尚未把 source clean release 与 target attach 串成一次事务 |
| TS-F7-04 BMC/host-failure HA | VMware 可能支持 HA cold restart，但当前无 power-fence 直接实验 | Qman=`OUT_OF_SCOPE / NOT_APPLICABLE` | `VMW-CLUSTER-FENCE-001` 不再是 Qman V3 缺口；source 失联时保持 VM stopped |
| TS-F7-05 online relocation failure matrix | Qman 只要求 source/target 在线协作；无 source clean release 时 target 不得启动，候选耗尽不得少配 | `PARTIAL` | `VMW-COLD-CLEAN-001`、`VMW-COLD-NOCLEAN-001`、`VMW-COLD-EXHAUST-001` |

`VMW-X03` 已证明关机态 `assignedId=null`、迁到目标后重新选择并成功运行；`VMW-D01` 已独立
证明旧 Guest DMA translation 在关机后不再可达。两份分离的结果不能自动合并成 source clean
release gate。完整 Case 必须在同一个 run 中关联：source stop、assignedId clear、DMA/IRQ teardown、
reset/owner readback、durable run revocation，然后才允许 target re-solve/attach。任一步未知都保持
VM stopped。host crash、unreachable source、BMC/power fence 和 HA restart 不进入该 Case。

### F8 可运维、可审计、可发布

| Tech Story | VMware 官方/可观察模型 | 覆盖 | 现有实验与下一缺口 |
| --- | --- | --- | --- |
| TS-F8-01 manifest/events/audit | API/task/log/ESXCLI 提供分散状态；没有统一 assignment manifest/lease timeline | `PARTIAL` | activation/Dynamic runners；增加 actor+task+VM+host+device 关联实验 |
| TS-F8-02 evidence/hash | 部分 summary 已有 artifact hash，但 schema 和覆盖不统一 | `PARTIAL` | 迁移所有 `VMW-*` 到统一 result schema，缺 hash 时不升级状态 |
| TS-F8-03 US→Case→Evidence | 36 个实验已有 hash-checked TS→experiment→代表 run→artifact 索引；acceptance Case 只从 `requiredTechStories` 派生且无关闭权限 | `PARTIAL` | 历史 pyVmomi task ID/actor 链和统一 canonical run result 尚未补齐，不能升级为 `VERIFIED` |
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

## 5. 最小未闭环实验与优先级

### P0：先关闭 V3 事务语义

| ID | 最小输入与断言 | 当前 WSL/QEMU nested ESXi |
| --- | --- | --- |
| `VMW-COLD-CLEAN-001` | A/B 在线；A 上运行 DMA/IRQ，关机后在同一 run 证明 assignedId clear、旧 IOVA 不可达、IRQ/reset/owner clean，再迁移并由 B 重新选卡启动 | 可扩展 `test_esxi_vmotion_matrix.py` + `test_esxi_edu.py`；尚未串成一次 run |
| `VMW-COLD-NOCLEAN-001` | A 在线但 teardown/reset 注入失败；B power-on 必须拒绝且 VM stopped | 需要新增 outer endpoint fault hook |
| `VMW-COLD-EXHAUST-001` | A clean release 后 B 候选不足；不得少配或留下 partial assignedId | 可扩展现有 X02/X03 runner |
| `VMW-DYN-ATOMIC-001` | 两 VM 并发申请同一多设备集合；exactly one 完整成功，loser 全空，释放后可重试 | 当前 synthetic 多 endpoint 环境可做 |
| `VMW-OWNER-003` | 两成员 owner transition 在第 N 个 member 失败；不得留下 partial active | 需要新增可控 mid-transition fault |
| `VMW-QUARANTINE-001` | reset/clean-state 失败后完整 dependency bundle 不得被复用，显式 recovery 后才恢复 | 需要新增 reset/state-probe fault |

Qman 同时必须优先执行 `QMAN-BACKEND-CONFORMANCE-001`：同一 API、selector、plan、FSM、reason
与 manifest 分别跑 legacy 与 modern backend，只允许 adapter/evidence 字段不同。该 Case 是 Qman
自证，不属于 `VMW-*`，也不能用 nested ESXi 代替。

### P1：设备技术 trait 与 identity

物理 run 选择可获得的准确 specimen 并记录全部版本，但 support key 使用技术 trait，不使用具体 SKU：

1. `VMW-TYPE-CGPU-001`：display/boot owner、multifunction audio、ROM、large/ReBAR BAR、reset 和
   Guest workload。
2. `VMW-TYPE-PGPU-001`：large BAR、MSI-X、vendor reset、多 function；ATS/P2P 默认关闭仍能工作，
   否则明确拒绝。
3. `VMW-TYPE-HBA-001`：active storage path 必须 Busy 拒绝；drain 后 assign、Guest I/O、clean
   release，SBR affected set 不影响其他 path。
4. `VMW-TYPE-ACCEL-001`：vendor class、大 BAR、DMA/MSI、firmware/reset sentinel；未 qualification
   的 ATS/PRI/PASID/P2P 依赖稳定拒绝。
5. `VMW-STATIC-IDENTITY-001`：保留 BDF 并改变 device/subsystem/ROM/identity，观察 Static backing
   是否明确拒绝或审计重绑定，禁止静默替换。
6. `VMW-STATIC-CONCURRENT-001`：两个 VM 并发 power-on 同一 backing，exactly one 成功且释放后复用。

当前 nested synthetic endpoint 可提供 trait 逻辑的前置正负对照，不能把它升级为四类真实设备的
物理 qualification。

### P2：profile、通用 PCI 与证据治理

- `VMW-CAP-TRAIT-001`、`VMW-DEP-MIXED-001`：IOMMU/ACS/reset/dependency 正负 A/B 和整组 Busy。
- `VMW-DYN-SELECTOR-001`：subsystem/revision/customLabel 与非法 selector A/B。
- `VMW-MMIO-TOPO-001`：多级桥、辅助 BAR、sub-4KB、ReBAR、alignment 与 limit+1。
- `QMAN-ARM-VIRT-UEFI-001`：ARM virt/UEFI 的 PCIe、BAR/window、MSI/ITS、DMA/IOMMU、reset 与
  clean release；这是 Qman E3/E4，不是 VMware 实验。
- `VMW-TRACE-001` 已通过 `contracts/vmware-evidence-index.json` 完成 36/36 实验登记，并固定已执行
  reference evidence 的文件 hash；当前仍是 `PARTIAL`。下一步把 actor、pyVmomi task、VM、
  source/target host、device、assignedId 与 canonical result 串成同一次 run，不能用现有派生索引
  冒充完整审计链。

不再为 Qman V3 安排 BMC、真实 host 断电 HA restart、unreachable-source recovery、FT 正向能力或
runtime hotplug 正向能力实验。若未来产品范围改变，必须新增 ADR/core parity 项，不能复用本轮
`NOT_APPLICABLE` 结论静默开启。

## 6. 实验关闭规则

一个 VMware 观察从 `UNKNOWN/PARTIAL` 升级为 `VERIFIED`，必须同时满足：

1. Canonical `VMW-*` Case 有冻结输入、明确预期和自动/半自动 runner。
2. 记录精确 ESXi build、API、vHW、server/BIOS、device/firmware、Guest/driver/workload。
3. 保存 API/task/log/Guest/L0 trace 中适用的原始 artifact 和 SHA-256。
4. 至少一个负向或边界对照，证明不是“VM 恰好开机”。
5. `limitations` 明确 nested、synthetic、single-build 或缺物理设备等外推边界。
6. 结果只更新 VMware reference coverage，不更新 Qman milestone、qualification 或 support state。
7. `MUST_MATCH` 的 VMware reference 即使升级为 `VERIFIED`，仍须由独立的 Qman Case 证明每个
   versioned backend、architecture 与 firmware profile；禁止证据转授。
