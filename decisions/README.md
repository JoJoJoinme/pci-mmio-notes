# Qman DirectPath 架构决策

本目录保存 G0 已冻结的产品和平台决策。机器真相源是
[`contracts/product-decisions.json`](../contracts/product-decisions.json)；各 ADR 只解释上下文、决定和后果。

- [`ADR-002`](ADR-002-platform-and-vfio-backend.md)：平台矩阵、Legacy-first 与禁止静默 fallback。
- [`ADR-003`](ADR-003-control-plane-boundary.md)：单一控制面、全局事务存储和 Host Agent 边界。
- [`ADR-005`](ADR-005-generic-pci-and-hcl.md)：通用 PCI 引擎与精确 HCL support。
- [`ADR-007`](ADR-007-online-cold-relocation.md)：双在线主机 cold relocation；失联源主机不接管。
- [`ADR-010`](ADR-010-qualification-approval.md)：`QUALIFIED` 与 `SUPPORTED` 的签发、审批和撤销。

这些 ADR 关闭的是“设计选择不清楚”，不是产品实现、硬件 qualification 或 release gate。
