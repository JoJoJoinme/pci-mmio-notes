# ADR-002：受控平台基线与 VFIO 后端策略

状态：`ACCEPTED`
日期：2026-07-22
Owner：Platform Architecture

## 决定

小规模测试线为 Kylin V10 ARM/C86（Kernel 4.19、QEMU 5.0）与 RH-family x86
（Kernel 4.18、QEMU 5.0）；主线为 Kylin V11 ARM/C86 与 openEuler x86
（Kernel 6.6、QEMU 10.2）。所有行承诺同一 V3 语义，不把测试线降级成部分 Feature。

x86/C86 具有相同的 `q35/i440fx × UEFI/SeaBIOS` 逻辑矩阵；ARM 为 `virt + UEFI`。
精确 versioned machine 名、固件 package/hash 和 kernel config 是 qualification 证据，而不是聊天决策。

当前产品统一走 Legacy VFIO TYPE1 family。每个 profile 精确钉住 TYPE1v2 或 TYPE1；不可用时拒绝，
不得自动切换。IOMMUFD/cdev 是未来独立 profile，只能在相同控制面状态机上增加 backend adapter。
Qman 不修改 BIOS 或 kernel boot args；运行时无法证明逐设备 IOMMU 和中断隔离时拒绝直通。

## 后果

- 现有 cdev/IOMMUFD 实验仍是有效的未来后端 E3，但不关闭当前 Legacy 产品路径。
- Legacy 与 IOMMUFD 必须具有同一 API、lease、FSM、reason code 和 manifest 语义。
- no-IOMMU 永久不允许用于不可信 VM；宿主可信 DPDK 的显式保留设备不进入 VM candidate pool。
