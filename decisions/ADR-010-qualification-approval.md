# ADR-010：Qualification 与支持目录审批

状态：`ACCEPTED`
日期：2026-07-22
Owner：Product Release

## 决定

Qualification Engineering 对精确平台、设备/固件、Guest/driver、workload 和 feature 组合执行自动化，
并签发 `QUALIFIED` profile。Product Release 审核证据与风险后，才可把 profile 提升为 `SUPPORTED`。
目录必须签名、版本化、可撤销并绑定 evidence hash；依赖版本或 hash 变化要在 scheduling/attach 前失效。

角色名后续可以映射到实际团队和个人，但签发与发布批准不能合并成一次无审计动作。
