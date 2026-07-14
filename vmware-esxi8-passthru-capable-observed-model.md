# ESXi 8 DirectPath `passthruCapable` 外部可观察模型

记录日期：2026-07-14
目标：VMware ESXi 8.0.3 build 24280767
范围：公开 vSphere API、`esxcli`、PCI config、VMX/host 日志与 QEMU trace；不推导 VMware 私有代码。

## 1. 结论

本地 15 项单变量矩阵表明，`HostPciPassthruInfo.passthruCapable` 不是“设备 ID 在白名单”
的同义词，也不是“当前 VM 一定能分配该设备”。对本轮受控端点，最小外部模型是：

```text
staticCapable = hostIommuPresent
             && acceptedResetBoundaryExists
             && acsPolicyPasses
             && deviceIsNotPlatformReserved

assignableNow = staticCapable
             && passthruEnabled
             && passthruActive
             && wholeDependencyIsExclusivelyLeased
             && assignableHardwareSelectionMatches
             && mmioAndRmrrAdmissionPasses
```

这是由实验现象归纳出的判别式，不是 VMware 内部实现声明。15 个资格样本全部符合；
共享 dependency 的大 BAR 负例又证明第二个判别式不能省略。

## 2. 15 项资格矩阵

| Case | 唯一变量 | ESXi 观察 | 结果 |
| --- | --- | --- | --- |
| `pcie-no-iommu` | 关闭 outer virtual VT-d | 可报告 `Bridge reset`，但 `Capable=false` | pass |
| `pcie-edu-bridge-reset` | EDU 位于 PCIe Root Port 后 | `Bridge reset`、`Capable=true` | pass |
| `root-e1000e-no-function-reset` | e1000e 直挂 Root Complex，无 FLR | `Reset=None`、`Capable=false` | pass |
| `root-virtio-flr-pm` | 直挂 virtio，同时有 FLR/PM | `Function reset`、`Capable=true` | pass |
| `root-virtio-flr-only` | 只保留 FLR | `Function reset`、`Capable=true` | pass |
| `root-virtio-pm-only` | 去掉 FLR，只保留 PM capability | `Reset=None`、`Capable=false` | pass |
| `root-virtio-d3hot-reset` | device model 实现 D3hot reset | ESXi 仍报 `Reset=None`、`Capable=false` | pass |
| `root-virtio-pme-d3hot-advertised-only` | 只广告 PME/D3 state bits | `Reset=None`、`Capable=false` | pass |
| `root-virtio-d3hot-reset-advertised` | D3hot callback 加能力广告 | `Reset=None`、`Capable=false` | pass |
| `root-virtio-no-flr-no-pm` | 无 FLR/PM，直挂 Root Complex | `Reset=None`、`Capable=false` | pass |
| `root-i82559-native-pm` | 换成带原生 PM 的 i82559 | `Reset=None`、`Capable=false` | pass |
| `pcie-virtio-no-flr-no-pm` | 同设备移到 Root Port 后 | `Bridge reset`、`Capable=true` | pass |
| `pcie-virtio-no-acs` | Root Port 隐藏 ACS，ESXi bypass policy | `Bridge reset`、`Capable=true` | pass |
| `pcie-virtio-no-acs-strict` | 同拓扑，只开启严格 ACS 检查 | `Bridge reset` 仍可见，但 `Capable=false` | pass |
| `legacy-virtio-no-flr-no-pm` | 同设备移到 conventional bridge 后 | `Bridge reset`、`Capable=true` | pass |

原始结果：

```text
_artifacts/vmware-directpath-runs/
  20260714-esxi8-passthru-capability-matrix-v4/matrix-result.json
```

矩阵 verdict 为 `pass`，restore verdict 为 `pass`。QEMU 11.0.2 lab binary SHA256：
`021bda3344eadf7fd12cb66665351ef6d1e6734ab2c69ab8ab36441afc09b393`。

## 3. 可成立的推理

### 3.1 IOMMU 是资格门槛，不只是运行时优化

关闭 virtual VT-d 后，设备仍有可识别拓扑和 bridge reset，但 ESXi 将其判为 incapable。
因此 QEMU/VFIO 对标不能使用 no-IOMMU mode，也不能把“QEMU 能启动设备”当成 DirectPath
资格等价证据。

### 3.2 ESXi 关心可隔离的 reset boundary

在 Root Complex 直挂路径中，公开 FLR 是本矩阵唯一得到 `Function reset` 和 capable 的
条件。PM capability、D3hot callback 或 PME/D3 能力位都没有被该 ESXi build 接受。

同一无 FLR/PM endpoint 放到可整体 reset 的 Root Port/legacy bridge 后会变为 capable，
并把上游桥记录为 parent/dependency。这说明 reset 可用性是“endpoint 或其隔离边界”属性，
不能只检查 endpoint 的 Device Capabilities FLR bit。

### 3.3 ACS policy 与 reset method 是两个独立 gate

无 ACS 且 `enableACSCheckForRP=FALSE` 时，日志显示 bypass，设备仍 capable；开启严格检查
后，同一设备仍能报告 `Bridge reset`，但 capability 变为 false。由此可见 reset path
成立并不足以绕过 ACS policy。生产实现应默认要求真实 ACS/干净 IOMMU group，不应把
实验 bypass 或 Linux `pcie_acs_override` 当成隔离证明。

### 3.4 `Capable/Enabled/Active` 仍不等于 AH 可分配

32G `pci-testdev` 与两个 e1000e 共用 Root Port 时：

- API：目标 `Capable/Enabled/Active=true`；
- VMX：静态 BDF、VID:DID、systemId 和 `ah.deviceHints` 均正确；
- 结果：BAR 枚举前报 `AH Failed to find a suitable device for pciPassthru0`。

QEMU 6.2 与 11.0.2 都复现。将大 BAR endpoint 移到独占 Root Port 后，只改变
dependency，VM 立即完成 IOMMU mapping 和 EFI Linux heartbeat。证据：

```text
20260714-lb32-qemu62-kvm-vcsa-v12/                 # shared dependency, fail
20260714-esxi8-largebar-32g-dedicated-after-enable/ # owner/dependency proof
20260714-lb32-dedicated-qemu11-kvm-v13/            # mapping + guest pass
```

所以 AH 的运行时选择至少还检查完整 dependency 的独占性/可租用性。Basic capability、
owner state、AH selection 和 VM MMIO admission 必须分别记录。

### 3.5 设备 ID 不是本矩阵的主要决定变量

矩阵覆盖 Intel e1000e/i82559、Red Hat virtio/EDU 与不同 class。相同 virtio identity
只改变 FLR、PM、拓扑、ACS 或 IOMMU 即发生 capability 翻转。可据此否定“仅由 VID:DID
白名单决定”的简单模型，但不能否定 VMware 对某些真实产品另有支持/HCL policy。

## 4. QEMU/VFIO 对齐核对表

| VMware 可观察层 | QEMU/VFIO 实现要求 | 验收值 |
| --- | --- | --- |
| Host IOMMU gate | 启用 VT-d/AMD-Vi；禁止 no-IOMMU/unsafe interrupts | IOMMU group、map/unmap 和 interrupt remap 可审计 |
| Reset boundary | 读取 host `reset_method`；FLR 优先，bus reset 时租用整组 | callback trace、影响 function 集合、十次复用 |
| ACS policy | 要求真实 ACS 或天然隔离拓扑 | 不依赖 ACS override；group 与拓扑一致 |
| Dependency | 将 IOMMU group、reset domain、multifunction/bridge dependency 合并成原子 lease | 同组不能拆给不同 VM；失败指出具体 dependency |
| Owner state | 分离 `eligible`、`bound-to-vfio`、`leased`、`attached` | 状态机与恢复日志，不用一个布尔值代替 |
| Dynamic candidate | 先按 ID/label 选具体 BDF，再展开 dependency | manifest 记录候选、拒绝原因和最终 BDF |
| MMIO/RMRR | 在选卡之后按整组 BAR/RMRR 计算 OVMF aperture 和 host hole64 | guest BAR/root window 与失败 budget |
| Migration | 默认拒绝运行态迁移；关机 relocate 后重新选卡 | lease 释放、目标主机重新解析、无持久 BDF |

推荐的 QEMU launcher 顺序：

1. 枚举候选及 host IOMMU group、ACS、`reset_method`、BAR、ROM、RMRR。
2. 合并完整 dependency，原子加锁；任何成员被占用则拒绝或选择下一候选。
3. 对最终候选计算 below-4G packing；不能容纳时计算对齐后的 high aperture。
4. 同时生成 `vfio-pci,host=BDF`、OVMF `X-PciMmio64Mb`、host bridge
   `pci-hole64-size` 和 machine-readable manifest。
5. 启动后验证 guest BAR/root window、IOMMU map 和中断；停止后先 detach/unmap 再释放 lease。

## 5. 复现

完整矩阵会逐案重启 outer ESXi，并在结束时恢复基线：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

大 BAR dependency A/B 复现见
[`vmware-esxi8-lab/README.md`](vmware-esxi8-lab/README.md)。每次结论至少保存 outer QEMU
argv/HMP、ESXi API `pciPassthruInfo`、`esxcli hardware pci list`、有效 VMX、
`vmware.log`、guest serial 和 restore verdict。

## 6. 仍需真实硬件回答的问题

- HCL/vendor driver 是否在 basic capability 之外增加设备级 policy。
- 真实 FLR/SBR 是否清除设备内部、链路外设或固件保留的敏感状态。
- 真实 ACS、root complex requester-ID alias 和平台 RMRR 的电气/固件边界。
- SR-IOV PF/VF 的 driver/NVM/firmware 初始化与 VF 独立 reset。

这些问题不应由虚拟 endpoint 的通过结果外推。
