# Governance contracts

该目录保存项目治理的机器可读合同：

- `ipd-tree.json`：唯一的 Epic → Feature → User Story → Tech Story 层级、主归属、
  多对多 `supports`、V3 单一目标、实现波次和通用机制/HCL 支持边界；人类可读入口为
  `ipd/README.md`。
- `vmware-source-register.json`：Broadcom KB、Compatibility Guide 和 vSphere API 的
  source/claim/baseline/limitations 注册表。
- `vmware-behavior-model.json`：39 个 Tech Story 到 VMware `VMW-*` 实验、现有 evidence、
  覆盖状态和缺口的机器映射；人类可读入口为 `ipd/VMWARE-BEHAVIOR-MODEL.md`。
- `vmware-experiment-result.schema.json`：新 `VMW-*` run 必须提交的 SUT profile、输入、
  预期、观察、verdict、limitations 和 artifact SHA-256 合同。
- `qman-technical-evidence.schema.json`：Qman reference/component/end-to-end 结果的 subject、
  E2/E3/E4、SUT、TS/Case/Risk mapping、artifact hash、关闭效果和 limitations 合同。
- `qman-evidence-index.json`：Qman 技术证据的权威索引；当前登记 4 条结果（E2=1、E3=3），
  都是 `REFERENCE_ONLY`，因此不关闭产品 Case、Risk 或 milestone。人类可读入口为
  `ipd/QMAN-TECHNICAL-EVIDENCE.md`。
- `project-status.json`：当前 milestone、能力声明、开放决策和冻结规则。
- `risk-status.json`：R01-R39 的可变治理字段。风险名称、后果、预防控制和检测依据仍以
  `qemu-static-dynamic-directpath-design.md` 第 18 节为权威来源；发布门会把两者合并。风险若标为
  `VERIFIED`/`FEATURE_DISABLED`，其已知产品 Case、E3/E4 等级和 artifact hash 还必须匹配
  Qman evidence index 中显式 `risksClosed` 的 end-to-end 结果。
- `acceptance-policy.json`：从详细设计第 19 节提取 Case ID，并检查 `acceptance/cases/`
  是否存在对应场景定义。

发布门会同时校验产品树中的 ID、父子关系、资料路径和人机文档一致性。产品树节点存在只表示
范围已定义，不表示实现或验收完成。

Qman 证据门另外执行以下不可绕过规则：reference/component subject 不关闭产品状态；E2 永不
关闭产品 Case/Risk；E3 不得关闭要求物理验证的 Risk；`SUPPORTED` 必须同时具有目标真实硬件
E4 qualification 和产品 gate。result、runner 或 artifact hash 漂移会使证据失效。

查看当前状态：

```text
python tools/evaluate_release.py status
```

尝试生产发布门：

```text
python tools/evaluate_release.py release
```

当前 release 命令失败是预期结果。只有风险、验收、ADR 和 milestone 全部闭环后才能返回 0。
