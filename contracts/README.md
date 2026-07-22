# Governance contracts

该目录保存项目治理的机器可读合同：

- `ipd-tree.json`：唯一的 Epic → Feature → User Story → Tech Story 层级、主归属、
  多对多 `supports`、V3 单一目标、实现波次和通用机制/HCL 支持边界；人类可读入口为
  `ipd/README.md`。
- `product-decisions.json`：ADR-002/003/005/007/010 的 owner、日期、正式决定、后果和
  TS/Case/Risk 影响映射；人类解释位于 `decisions/`。
- `compatibility-profile-policy.json`：六个平台基线、Legacy-first/no-fallback、单一控制面、
  HCL archetype/审批生命周期和双在线主机 cold relocation 边界。
- `directpath-portable-control-contract.json`：不依赖私有 Qman 目录结构的实现合同；冻结 VMware
  8.0.3 baseline、17 个 port、35 个 backend-neutral operation、独立 FSM/CAS、Canonical JSON/identity、
  Legacy/cdev adapter、stable reason、配置/迁移/telemetry、17 项 parity 与全部 TS/Case 追踪；其
  `mappingSurface` 当前确定性导出 293 个 item 和逐项 hash-bound verification requirement。
- `directpath-operation-envelope.schema.json`：35 个 operation 的 closed common request/result envelope、typed
  lease、ReleaseOwnershipGuard、CAS、reason 和 FSM 投影；每个 operation/direction 还必须指向唯一的
  portable payload profile，不能把 target-local object 塞进开放字段。
- `directpath-operation-payload.schema.json`：为 35 个 operation 分别定义 `REQUEST` 与 `RESULT`，共 70 个
  `additionalProperties:false` 的 closed profile；`x-operationProfileIndex`、operation envelope 中的
  request/result binding 与 profile fragment 一一对应，内网实现只能映射这些 wire objects，不能改写字段集。
  `EXECUTED_PASS` 的每次 iteration 还必须用 `operationExchanges` 对每个 Step 绑定 raw request/result envelope、
  schema/digest、payload hash 与 status/reason/retryable 投影；普通日志不能替代实际 wire evidence。
- `directpath-authority-entities.schema.json`：17 个必须持久化的 authority aggregate；字段集合、key、
  resourceVersion/generation、lease/guard 与 current HostSnapshot pointer 不再依赖文字猜测。
- `directpath-portable-entities.schema.json`：DeviceRecord、QualificationProfile、VM DirectPath Request、
  DependencyBundle 四个非 authority wire projection；Static/Dynamic request 是封闭 union，Dynamic 不持久化
  BDF、deviceUid 或 assignedId。
- `directpath-identity-v1.schema.json` 与 `directpath-identity-v1.golden-vectors.json`：固定 serial/slot
  provider、原始字节、endianness、physical-path grammar、domain-separated hash 和跨语言 golden vector。
- `directpath-portable-hash-subjects.schema.json`、assignment manifest、clean-release receipt、
  qualification record、supported catalog：固定计划、授权、运行、释放和 support 的 canonical hash subject。
- `directpath-trust-root-set.schema.json`、trust key ring、trust/catalog rollback anchor：离线 N-of-M root、
  immutable principalId、按不同 principal/key material 计数的 quorum/role separation、key/catalog
  monotonic CAS 和 out-of-band bootstrap；候选签名对象不包含接收自己的 anchor receipt，避免 digest
  fixed point。
- `directpath-qualification-release-index.schema.json`：精确绑定目标代码 C、mapping core M、由完整
  platform row/backend/host-policy canonical projection 复算的 platformProfileHash、case-matrix digest、
  每份 QualificationRecord 的 derived Case 和逐 Case E4 artifact，以及 anchor-after-catalog receipt；
  禁止把 evidence revision E 或 final map digest 写入位于 E 的 blob。
- `directpath-integration-report.schema.json`：mapping coverage、conflict register、implementation test 三类
  signed report；完整覆盖 C+M，不能用空报告或自报摘要提升状态。
- `qman-integration-map.schema.json`：内网 AI 把 portable item 绑定到 exact target repository
  commit、service/path/symbol/interface hash、test 和 authority 的 closed schema；强制
  C→M→catalog/evidence content→外部 anchor A→evidence revision E→detached final map 的无环构造。
- `qman-integration-map.template.json`：完整 mapping surface 的初始模板；所有项目默认
  `UNMAPPED/NOT_STARTED`，因此不会因文档完成而冒充私有实现。人类交接入口为
  `handoff/QMAN-DIRECTPATH-IMPLEMENTATION-HANDOFF.md`。
- `directpath-acceptance-scenario.schema.json`：内网产品测试的 closed scenario/oracle 合同；
  `TEMPLATE` 只定义预期，`BOUND` 固定真实 fixture/target test 但仍不是完成证据；只有带完整
  artifact/oracle/signature 的 `EXECUTED_PASS` 才有资格进入 Case/Risk/milestone 发布门复核。示例位于
  `handoff/examples/S05-legacy-qemu-start-failure-clean-rollback.json`。每个 Step 的 request 与 expected result
  都精确绑定 operation、direction、portable schema fragment、schema/raw fixture hash 和 profileId；叙述性
  intent、开放 ad-hoc object 或 target-local payload schema 都不能成为可执行 fixture。
- `directpath-acceptance-case-contract.schema.json`、`directpath-acceptance-case-contracts.json` 与
  `directpath-case-completion-record.schema.json`：把 101 个设计 Case 的 pass condition、断言 digest、依赖、
  typed trace、fault、artifact、repeat/duration 和 E3/E4 边界固定成机器合同；单个 scenario 只覆盖合法子集，
  只有同一 C/M/target commit、platform profile、backend profile 和 exact qualification tuple 下多个
  `EXECUTED_PASS` 的确定性聚合记录可以宣告 Case 完成；外层 integration/release descriptor 不得为解析后的
  completion record 换标签。
- `directpath-case-evaluator-tool-manifest.schema.json`：为 Case-completion evaluator 单独固定目标代码、完整
  source tree、接口、runtime/dependency/environment/build artifact 和签名；Scenario `RunnerManifest` 或其
  `TOOL_MANIFEST` 不能替代这个求值器专用证明。
- `directpath-runner-manifest.schema.json`、`directpath-source-tree-manifest.schema.json`、
  `directpath-build-attestation.schema.json` 与 `directpath-execution-evidence-index.schema.json`：从目标 commit
  的完整 Git tracked tree（含 mode、object、raw content hash 和递归 submodule）固定 runner build、
  predicate/evaluator、builder/toolchain/dependency/environment/input/output，并用 SOURCE_TREE_MANIFEST/
  BUILD_ATTESTATION/BUILD_LOG/TEST_LOG/TOOL_MANIFEST/RUNNER_BINARY 六个互斥控制制品形成逐
  iteration/oracle/artifact 闭包；dirty tree、hash 标签或一份通用日志不能充当全部证明。
- `directpath-qualification-workload-definition.schema.json`、`directpath-qualification-run-request.schema.json`、
  `directpath-qualification-workload-result.schema.json`、`directpath-qualification-measurement.schema.json`、
  `directpath-qualification-run-manifest.schema.json` 与 `directpath-qualification-subject-manifest.schema.json`：
  先冻结 workload binary/config/assertion/metric 和带 nonce 的请求；host inventory、firmware/provider、
  guest/workload、taxonomy 和 scenario core 再分别生成可定位、raw hash-bound、typed、签名的实测对象。
  RunRequest 在任何 collector 前冻结 exact deviceUid/deviceRecordHash；RunManifest 和每条 Measurement
  逐字节继承该 tuple。identity/traits 同时绑定 current HostSnapshot 与其成员 DeviceRecord，不能在同一主机
  的多张卡之间拼接证据。RunManifest 双签 host/boot/epoch、起止、完整 measurement/core/workload 集合，Subject 最后重算
  exactQualificationKey 与运行时长；QualificationRecord/Subject 不能互相回抄 qualification subject。
  WorkloadDefinition 用 `supportedQualificationTuples` 的每一行同时固定 guest
  ABI/architecture/OS/kernel/driver 与 runtime platform/backend/IOMMU/machine/firmware；两半不得独立命中或
  做笛卡尔扩展。
  vCPU/memory/capability/provider 必须来自同一次运行的 signed Measurement，再做 exact/minimum match。
- `directpath-workload-evaluator-manifest.schema.json` 与
  `directpath-workload-evaluation-report.schema.json`：把 workload 判定器固定到 exact C/M/portable contract、
  source tree、BuildAttestation、runtime closure、path/symbol/blob/interface 与数值语义；判定器只消费冻结的
  WorkloadDefinition、signed RunRequest、canonical artifact-observation descriptors、其 path/hash 精确绑定的
  read-only raw observation closure 和预签名 EvaluationContext，产生可重放的
  signed EvaluationReport。`QualificationWorkloadResult` 必须绑定该报告并逐字节复制 observation/assertion/metric
  与 outcome；重放只能经 verifier 外置、受信、按目标架构运行的 isolation runner，禁止把 evidence binary
  直接作为 validator 子进程执行。进程退出码、日志摘要或事后脚本不能替换这一链。
- `directpath-device-taxonomy-definition.schema.json` 与
  `directpath-device-classification-record.schema.json`：先独立签发固定 archetype/profile 与 classifier
  source/build/runtime 的 taxonomy，再由 signed `ClassificationContext` 固定 classification ID/time/signer 与
  exact snapshot/device，并嵌入 Host Inventory authority 在 `classifiedAt` 对完整 HostAuthority current pointer
  签发的 receipt；classifier 只生成 deterministic trace/archetype/profile 构造投影，authority 后填
  `signedAt` 并签名。classification 不能读取隐藏时钟、QualificationRecord、SupportedCatalog 或 HCL 结论。
  classifier 重放同样必须经过外置受信 isolation runner；无完整 closure 或可验证 sandbox 即 fail closed。
- `directpath-trust-key-ring-history.schema.json` 与 `directpath-anchor-freshness-envelope.schema.json`：完整解析
  genesis→current key-ring chain，并用 evaluator 外部生成的 nonce 获取最长 300 秒的 live anchor 回执；旁置
  anchor 快照只能证明历史签名，不能证明 freshness。
- `qemu-vfio-launch-surface.json`：QEMU 5.0/6.2/10.2 的版本化 `vfio-pci` 管控 surface，固定
  Legacy `AUTHORIZED_DEVICE_PATH` 与 future cdev fd passing 的差异。
- `vmware-source-register.json`：Broadcom KB、Compatibility Guide 和 vSphere API 的
  source/claim/baseline/limitations 注册表。
- `vmware-behavior-model.json`：39 个 Tech Story 到 VMware `VMW-*` 实验、现有 evidence、
  覆盖状态和缺口的机器映射；人类可读入口为 `ipd/VMWARE-BEHAVIOR-MODEL.md`。
- `vmware-experiment-result.schema.json`：新 `VMW-*` run 必须提交的 SUT profile、输入、
  预期、观察、verdict、limitations 和 artifact SHA-256 合同。
- `vmware-evidence-index.json`：36 个 VMware 实验的 TS→实验→代表 run→evidence/hash
  机器索引。已执行的 28 项固定现有 evidence 文件 hash；6 个 planned 与 2 个 physical-blocked
  项显式记录 `noRunReason`。Acceptance Case 只通过 `requiredTechStories` 派生关联，索引没有
  Qman Case、实现、qualification 或 release 的关闭权限。证据或模型变更后用
  `python tools/generate_vmware_evidence_index.py` 确定性重建，并用 `--check` 检查漂移。
- `qman-technical-evidence.schema.json`：Qman reference/component/end-to-end 结果的 subject、
  E2/E3/E4、SUT、TS/Case/Risk mapping、artifact hash、关闭效果和 limitations 合同。
- `authoritative-snapshot.schema.json`：bounded snapshot publisher 的完整 envelope、full-host scope、
  exact launch identity/group 与 component HMAC 边界；跨字段 hash/signature、epoch、boot、store identity
  仍由实现验证，schema 本身不是生产 trust root。
- `qman-evidence-index.json`：Qman 技术证据的权威索引；当前登记 10 条结果（E2=2、E3=8）：
  5 条 `REFERENCE_ONLY`、5 条 `COMPONENT_ONLY`，均不关闭产品 Case、Risk 或 milestone。人类可读入口为
  `ipd/QMAN-TECHNICAL-EVIDENCE.md`。
- `project-status.json`：当前 milestone、能力声明、决策注册表和冻结规则。
- `risk-status.json`：R01-R39 的可变治理字段。风险名称、后果、预防控制和检测依据仍以
  `qemu-static-dynamic-directpath-design.md` 第 18 节为权威来源；发布门会把两者合并。风险若标为
  `VERIFIED`/`FEATURE_DISABLED`，其已知产品 Case、E3/E4 等级和 artifact hash 还必须匹配
  Qman evidence index 中显式 `risksClosed` 的 end-to-end 结果。
- `acceptance-policy.json`：从详细设计第 19 节提取 Case ID，并检查 `acceptance/cases/`
  是否存在对应场景定义；schema v2 还要求每个 Case 声明 `requiredTechStories` 与
  `dependsOnCaseIds`。未知 TS/Case、自依赖或环使合同无效；未定义/未关闭前置以及用 reference
  Case 满足产品前置会保持 release blocked。当前 101/101 已分类；分类完成只关闭 G0 的范围未知，
  94 个 implementation-blocked 与 6 个 hardware-blocked Case 仍阻止产品 release；C20 的
  E2 reference runner 不会被误算为 PRODUCT Case 完成。

VMware 与 Qman 结果使用 subject-specific schema，因为两者字段和关闭权限不同；“统一证据合同”
指统一的 subject、fact layer、SUT/version、mapping、artifact hash、limitation 和禁止证据转授规则，
不是把 VMware observation 和 Qman product result 强压成同一个 JSON shape。未注册的历史 result
只作 source material；发布门只消费已注册并通过 schema/hash 校验的记录。

发布门会同时校验产品树中的 ID、父子关系、资料路径和人机文档一致性。产品树节点存在只表示
范围已定义，不表示实现或验收完成。

仓库内受合同约束的 `*.py`、`*.json` 和 `*.md` 使用 Git blob 的原始 LF 字节计算 SHA-256；
`.gitattributes` 固定 checkout 行尾，避免 Windows CRLF 工作树把同一仓库对象误报为 evidence drift。
历史登记从 CRLF 工作树 hash 迁移到 LF blob 时必须在对应 limitation 中声明，不能冒充实验重跑。

Qman 证据门另外执行以下不可绕过规则：reference/component subject 不关闭产品状态；E2 永不
关闭产品 Case/Risk；E3 不得关闭要求物理验证的 Risk；`SUPPORTED` 必须同时具有目标真实硬件
E4 qualification 和产品 gate。result、runner、可选的 `sourceState.inputHashes` 或 artifact hash
漂移会使证据失效；`inputHashes` 用于把模型、fixture 与测试输入和 runner 分开固定。

查看当前状态：

```text
python tools/generate_directpath_portable_package.py --check
python tools/generate_directpath_case_contracts.py --check
python tools/validate_portable_handoff.py baseline --root .
python tools/evaluate_release.py status
```

前两条只验证 target-independent portable axis：normative closure、293 项 mapping/verification matrix、
35 operation/70 payload profile、可重放 workload evaluator、独立 device taxonomy、closed schema、baseline
template 和 handoff scenario；不需要私有仓库。进入内网后，先对 detached map
运行 `validate_portable_handoff.py all --map <map>`，并从部署环境另行提供 trust-root digest、key-ring
rollback anchor 和 catalog rollback anchor，再调用统一 release gate。

尝试生产发布门：

```text
python tools/evaluate_release.py release --map <detached-final-map.json> --trusted-root-digest <sha256:...> --external-rollback-anchor <key-ring-anchor.json> --external-catalog-anchor <catalog-anchor.json> --trust-anchor-freshness-envelope <trust-freshness.json> --catalog-anchor-freshness-envelope <catalog-freshness.json> --verifier-nonce <fresh-out-of-band-nonce>
```

省略参数时默认使用 UNMAPPED template，因此当前 release 命令失败是预期结果。只有 portable map 四轴、
风险、验收、ADR、milestone、签名和物理 qualification 全部闭环后才能返回 0。
