# ADR-005：通用 PCI 引擎与 HCL 支持边界

状态：`ACCEPTED`
日期：2026-07-22
Owner：Qualification Engineering

## 决定

主流程按 PCI 技术事实工作，不按设备类别或 VID:DID 分叉。只要实例满足 DMA 隔离、dependency
闭包、reset、owner、MMIO/拓扑与 Guest 约束，引擎原则上可以生成 attach plan；生产仅支持签名、
版本化 compatibility catalog 中的精确 profile。

首批 qualification 以四类技术 archetype 组织：消费级 GPU、专业级 GPU、HBA 和加速卡。具体 SKU、
firmware、Guest driver 与 workload 在 G6 录入；没有这些 E4 事实时只能声明 `UNQUALIFIED_LAB`。

## 后果

HCL 是 support 边界，不是技术引擎的硬编码清单。一次 synthetic 或 nested ESXi 成功不能提升为
`QUALIFIED` 或 `SUPPORTED`。
