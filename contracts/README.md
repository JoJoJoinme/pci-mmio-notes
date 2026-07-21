# Governance contracts

该目录保存项目治理的机器可读合同：

- `ipd-tree.json`：唯一的 Epic → Feature → User Story → Tech Story 层级、主归属、
  多对多 `supports`、V3 单一目标、实现波次和通用机制/HCL 支持边界；人类可读入口为
  `ipd/README.md`。
- `product-decisions.json`：ADR-002/003/005/007/010 的 owner、日期、正式决定、后果和
  TS/Case/Risk 影响映射；人类解释位于 `decisions/`。
- `compatibility-profile-policy.json`：六个平台基线、Legacy-first/no-fallback、单一控制面、
  HCL archetype/审批生命周期和双在线主机 cold relocation 边界。
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
  93 个 implementation-blocked 与 6 个 hardware-blocked Case 仍阻止产品 release。

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
python tools/evaluate_release.py status
```

尝试生产发布门：

```text
python tools/evaluate_release.py release
```

当前 release 命令失败是预期结果。只有风险、验收、ADR 和 milestone 全部闭环后才能返回 0。
