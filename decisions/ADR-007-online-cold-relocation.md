# ADR-007：在线主机间的计划性 cold relocation

状态：`ACCEPTED`
日期：2026-07-22
Owner：Qman Control Plane

## 决定

V3 只支持源、目标 Host Agent 都在线时的计划性冷搬迁。源端必须停止 VM，并形成涵盖 DMA/IRQ
teardown、reset、owner restore 和 lease release 的 clean-release receipt；目标端随后重新求解，不能复制
源 BDF。

源主机失联、断电或分区时，系统保留 lease、VM 保持 stopped、禁止目标接管，直到源主机返回并
完成 reconcile。BMC/Redfish/IPMI、电源 fencing 与 host-failure 自动 HA restart 均不在范围内。

## 后果

host epoch 与 operation generation 只能阻止 stale 控制请求，不能被描述成物理 DMA fence。VMware 的
host-failure/BMC 行为可保留为参考，但不再是 Qman V3 的发布条件。
