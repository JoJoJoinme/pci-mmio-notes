# QEMU VFIO no-IOMMU 与 IOMMU 逐设备分流实测

日期：2026-07-18

## 1. 要回答的问题

宿主 DPDK 需要保持 `enable_unsafe_noiommu_mode=1`，但 VM PCI passthrough 仍要求真实
IOMMU translation。需要验证全局 module parameter 是否等于“所有 `vfio-pci` 设备都在
no-IOMMU 模式”，并给 Qman 的逐设备 gate 提供可重复证据。

## 2. 方法

[`test_qemu_vfio_noiommu_split.py`](../vmware-esxi8-lab/test_qemu_vfio_noiommu_split.py)
使用 QEMU 11.0.2、Q35/OVMF 和 Ubuntu 24.04 cloud guest，创建两个除 vIOMMU 外完全相同的
场景。guest 内对同一个 QEMU e1000e `0000:01:00.0` 执行：

1. 记录 bind 前 `iommu_group`。
2. 设置 `enable_unsafe_noiommu_mode=1` 并加载 `vfio-pci`。
3. 从 native e1000e driver 解绑，再绑定到 `vfio-pci`。
4. 记录 bind 后 group、driver 和全部 `/dev/vfio` node。
5. 关机并保存 serial log、QEMU command、binary/image hash 和 JSON summary。

复现命令：

```bash
python3 vmware-esxi8-lab/test_qemu_vfio_noiommu_split.py \
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/\
20260718-qemu-vfio-noiommu-split-v2
```

## 3. 结果

| 场景 | vIOMMU | unsafe switch | bind 前 group | bind 后 node | 结论 |
| --- | --- | --- | --- | --- | --- |
| `no-iommu` | 无 | `Y` | none | `/dev/vfio/noiommu-0` | `DMA_MODE=no-iommu`，pass |
| `iommu-with-unsafe-switch` | Intel VT-d + interrupt remap | `Y` | 7 | `/dev/vfio/7`、`/dev/vfio/devices/vfio0` | `DMA_MODE=iommu`，pass |

两次都由 `vfio-pci` 成功接管同型号设备，也都保持全局 unsafe switch 为 `Y`。唯一决定实际
DMA backend 的变量是该设备是否挂在真实 IOMMU domain，而不是全局允许位。

关键 serial 摘录：

```text
# no-iommu
PRE_BIND_GROUP=none
UNSAFE_SWITCH=Y
POST_BIND_DRIVER=vfio-pci
POST_BIND_GROUP=0
VFIO_NODE=/dev/vfio/noiommu-0
DMA_MODE=no-iommu
VFIO_SPLIT_FAILURES=0
VFIO_SPLIT_PASS

# iommu-with-unsafe-switch
PRE_BIND_GROUP=7
UNSAFE_SWITCH=Y
POST_BIND_DRIVER=vfio-pci
POST_BIND_GROUP=7
VFIO_NODE=/dev/vfio/7
VFIO_NODE=/dev/vfio/devices/vfio0
DMA_MODE=iommu
VFIO_SPLIT_FAILURES=0
VFIO_SPLIT_PASS
```

## 4. 对 Qman 的直接结论

1. `unsafeNoIommuModeEnabled=true` 只能是 host warning，不能整机 hard reject。
2. VM gate 必须读取每个 payload 的 `dmaIsolationMode`；`NO_IOMMU` 和 `UNKNOWN` 都拒绝。
3. `/dev/vfio/noiommu-$GROUP` 是明确反例；普通 group node 或 cdev 是更强正向线索。
4. 最终 authoritative proof 仍应是 VFIO cdev 成功 bind IOMMUFD/IOAS，或 legacy container
   明确选择 TYPE1/TYPE1v2；scanner 证据不替代 attach-time recheck。
5. DPDK BDF 必须另以 `hostReservation=dataplane-dpdk` 排除出 VM candidate pool。

## 5. 证据与边界

```text
QEMU binary SHA256:
021bda3344eadf7fd12cb66665351ef6d1e6734ab2c69ab8ab36441afc09b393

Ubuntu base image SHA256:
5fa5b05e5ec239858c4531485d6023b0896448c2df7c63b34f8dae6ea6051a44

v2 summary SHA256:
a0b62e2b3af2cfdf1b155fab5427415299f93b24d0c964fe8b74afa6dee70227

no-iommu serial SHA256:
2fdb0dabbec328e1c8ad3e0f3de98f78537d85e5f704c78e5250b6e47b7e69e1

iommu-with-unsafe-switch serial SHA256:
efdd3c872d72c3296775b0ead5dfcc7b1605cd31609242736bfc69b52447a4d3
```

这是 QEMU 虚拟 PCI 与 Linux VFIO provider 的软件层实测，不替代真实 NIC/平台的 DMA fault、
interrupt-remap、性能或厂商 errata 验收。无 IOMMU 场景已经证明 VFIO 接管和 noiommu node，
但未在 guest 内运行 DPDK PMD 数据包转发；DPDK PMD 功能/性能仍属于平台 qualification。
