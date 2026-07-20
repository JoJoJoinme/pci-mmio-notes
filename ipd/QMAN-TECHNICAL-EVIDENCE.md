# Qman 技术证据树与 WSL/QEMU 验证结果

状态：`TECHNICAL EVIDENCE / PRODUCT NOT IMPLEMENTED`
实验日期：`2026-07-21 Asia/Shanghai`
环境：`WSL2 Ubuntu-22.04 + KVM + QEMU 11.0.2 + OVMF 2022.02`

本文把 [`ipd/README.md`](README.md) 中的 Tech Story 接到 Qman 自身证据链。机器索引位于
[`contracts/qman-evidence-index.json`](../contracts/qman-evidence-index.json)，单次结果必须满足
[`contracts/qman-technical-evidence.schema.json`](../contracts/qman-technical-evidence.schema.json)。

这里的“Qman 技术证据”包括 Qman reference model、QEMU control reference、QEMU/Guest/VFIO
集成和后续 Qman component/end-to-end 结果。它不意味着仓库里已经存在完整 Qman controller。

## 1. 证据等级与关闭权限

| 等级 | 含义 | 可以支持 | 不能关闭 |
| --- | --- | --- | --- |
| E2 | 单元、纯函数、schema、源码或模型证据 | 算法语义与 fail-closed 规则 | 产品 Case、物理 Risk、qualification |
| E3 | 实际 QEMU、firmware、Guest、VFIO 或 Qman component 的虚拟集成 | control/backend 行为与故障前提 | E4 硬件 Risk、HCL、`SUPPORTED` |
| E4 | 目标 server/device/firmware/Guest/driver/workload 的物理证据 | qualification review 输入 | 未通过产品 gate 的 release claim |

强制不变量：

```text
VMware observation != Qman evidence
QEMU/Guest reference != Qman product Case pass
Qman component result != end-to-end product closure
E2/E3 != physical qualification
SUPPORTED => E4 qualification + Qman product gate
artifact hash drift => evidence invalidated
```

## 2. 本轮结论

| Evidence | 等级 | 已实锤 | 影响的 TS / Case 前提 | 本轮没有宣告 |
| --- | --- | --- | --- | --- |
| `QMAN-E2-REFERENCE-MODEL-001` | E2 | WSL 下 87/87 reference-model tests pass | TS-F1-02/03/04、F2-01/02、F4-01；C05/C06/O09/M22 | controller、provider、lease store、C20 完整固定点 |
| `QMAN-QEMU-CONTROL-001` | E3 | 建机后可通过 QMP 向 QEMU device tree 加入 PCI endpoint（本次在 machine 暂停态）；同 guest BDF 可换 VID:DID；`device_del` reply 后设备仍存在 | TS-F3-01/04、F4-05、F5-05；S01/S15/F09 前提 | Guest 在线热插、Qman QMP ACL 已实现、S15/F09 已通过 |
| `QMAN-E3-DMA-PROVIDER-001` | E3 | unsafe=`Y` 时，no-IOMMU 与 IOMMU-backed device 仍呈现不同 provider node | TS-F1-02、F3-03；C21 前提 | 物理 IOMMU/IR/errata、IOMMUFD IOAS attach、DPDK workload |
| `QMAN-E3-MMIO-OBSERVED-001` | E3 | QEMU floor 与 OVMF aperture 必须配对；双 64 GiB BAR 默认失败、128 GiB 配对成功 | TS-F4-01/02/04；M23 前提 | Qman observedPlan commit/rollback、物理 BAR qualification |

当前所有 Risk 仍为 `OPEN`。这些结果增加“为什么要这样设计”的技术证据，不改变 G0 和
release 的 `BLOCKED` 状态。

## 3. 被实验修正或强化的设计判断

### 3.1 不能把 VMware 默认配置翻译成固定的 QEMU `0/0`

历史任务早期猜测“VMware 默认 EFI 大致等价于 OVMF aperture=0、QEMU floor=0”，后续
ESXi 与 QEMU 实验都推翻了这种单值翻译。本轮在 QEMU 11.0.2/`pc-q35-11.0` 重跑双
64 GiB BAR：

- 默认 32 GiB QOM floor 下，OVMF 没有为两个 BAR 分配地址，Guest probe 无 heartbeat。
- `X-PciMmio64Mb=131072` 与 `pci-hole64-size=128G` 配对后，两个 BAR 分别位于
  `0x2000000000:0x3000000000` 和 `0x3000000000:0x4000000000`，Guest heartbeat 成功。
- Qman 必须保存 required span、firmware aperture、QEMU floor 和 observed runtime window
  四个事实，不能把 `pci-hole64-size` 当成 hard cap。

证据：[`qman-qemu-mmio-observed-20260721-summary.json`](../evidence/qman-qemu-mmio-observed-20260721-summary.json)。

### 3.2 全局 unsafe no-IOMMU 开关不是逐设备结论

两个 Guest 都把 `enable_unsafe_noiommu_mode` 设为 `Y` 并把相同 e1000e bind 到
`vfio-pci`：

- 无 vIOMMU：bind 前无 group，bind 后是 `/dev/vfio/noiommu-0`。
- 有 Intel vIOMMU：bind 前后存在正常 group，并出现 `/dev/vfio/N` 与 VFIO cdev。

因此 Qman 可以允许宿主为受信 DPDK workload 打开全局 unsafe switch，但 VM 目标设备必须
在 attach 时独立证明 IOMMU-backed provider；`noiommu-*` 必须拒绝。

证据：[`qman-vfio-dma-provider-20260721-summary.json`](../evidence/qman-vfio-dma-provider-20260721-summary.json)。

### 3.3 BDF 不是稳定身份，raw QMP 是真实绕过面

同一 QEMU machine address `0000:01:00.0` 在两次启动中分别承载：

```text
8086:10d3  QEMU e1000e
1b36:0005  QEMU pci-testdev
```

另一个 run 在建机后先暂停 machine，再通过 raw QMP 成功把 e1000e 加到原本为空的
`01:00.0`。它证明 QMP 能越过仅发生在冷启动前的设备规划边界，但不宣称 Guest 在线热插已
完成。这支持以下设计要求：

1. Static manifest 不能只保存 BDF，必须保存并重验稳定 fingerprint。
2. 冷启动 admission 不能只靠 launcher；QMP proxy/ACL、sandbox 和 fd-only attach 都是安全边界。
3. `device_del` 返回成功后，设备一秒后仍在 `query-pci`，所以 teardown 必须等待 Guest/backend/
   IOMMU/reset 的完成证据，不能以 QMP reply 提交 lease release。

证据：[`qman-qemu-control-20260721-summary.json`](../evidence/qman-qemu-control-20260721-summary.json)。

## 4. 可复现入口

实验复用了本地历史任务中沉淀的 WSL/QEMU 环境；可提交、可复现的权威环境说明为
[`vmware-esxi8-lab/README.md`](../vmware-esxi8-lab/README.md)。QEMU 11 必须显式指定，不能
误用 PATH 中的 QEMU 6.2。

```powershell
# QMP/BDF control reference
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/qman-lab/test_qemu_control_boundary.py `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-qmp

# VFIO no-IOMMU / IOMMU provider A/B
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_vfio_noiommu_split.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-vfio

# QEMU 11 + OVMF dual-64GiB BAR
wsl -d Ubuntu-22.04 -- env `
  WORKDIR=/root/pci-evidence/RUN-ID-mmio `
  QEMU_BIN=/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  MACHINE=pc-q35-11.0 `
  bash /mnt/e/Code/PCI/github-export/qemu-q35-ovmf-dual-64g-validate.sh

# Qman reference model
wsl -d Ubuntu-22.04 -- bash `
  /mnt/e/Code/PCI/github-export/qman-lab/run_reference_model_tests.sh `
  /mnt/e/Code/PCI/_artifacts/qman-wsl-qemu/RUN-ID-model/unittest.log
```

原始 Unix socket 必须放在 WSL 原生文件系统。把 monitor socket 放在 `/mnt/e` 会返回
`Operation not supported`；该 preflight failure 不能作为 QEMU/MMIO 结论。

## 5. 下一批 Qman 证据

按依赖顺序继续：

1. `QMAN-E2-CLOSURE-001`：补 C20 四格 fixture，证明 dependency/action/reset/qualification
   固定点；busy 只能改变 available，不能改变 capable/bundle hash。
2. `QMAN-E3-STATIC-FAULT-001`：QEMU pre-ready exit、SIGKILL、bind/reset 中途失败，验证
   journal/lease/fd/mapping/driver rollback 与 whole-bundle quarantine。
3. `QMAN-E3-QMP-GATE-001`：实现最小 QMP proxy/ACL 后重跑 S15/F09，要求 raw
   `device_add/device_del` 被拒绝且 device tree/fd/generation 不变。
4. E4：真实 NIC/GPU/HBA 上的 IOMMU/IR、ACS/RID alias、reset/state、INTx、P2P、RMRR、
   SR-IOV、errata 和 workload qualification。

Dynamic solver、cluster CAS/fencing 和 HA cold restart 在 Static safety core 的 component
证据之后推进；真实 BMC/power fence 仍必须由 E4 环境证明。
