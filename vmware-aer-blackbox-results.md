# ESXi DirectPath PCIe AER 黑盒验证与 QEMU 对标

记录日期：2026-07-11

## 1. 范围与结论

本报告只描述自有隔离实验环境中的公开接口、PCI config space、guest 输出和公开日志，
不推导 VMware 私有代码。

结论先行：ESXi 8.0 U3 的被测 EFI DirectPath VM 没有把 PCIe AER 服务原样交给
guest。VMware 把 endpoint 的 AER Extended Capability header 隐藏为 0，guest ACPI
也不授予 AER ownership；但是 AER capability body 的物理 status 寄存器仍可通过 raw
config read 观察。Correctable Receiver Error 和 Non-Fatal Unsupported Request 都表现为
“endpoint status 置位，guest/ESXi 无 AER 日志，上游 Root Port 状态不变”。

这不是 OVMF/SeaBIOS 的差异。Stock QEMU 6.2 的 Q35、Root Port、`e1000e` 和
`vfio-pci` 默认会暴露 AER；`x-pcie-extcap-init=off` 也不会删除设备随后创建的 AER
capability。完整对标需要一个 opt-in config-space filter，并在虚拟 Root Port 上禁用
AER capability/service。

## 2. 环境与前置条件

| 层 | 版本/配置 |
| --- | --- |
| 外层 VMM | QEMU 6.2.0，Q35/KVM，显式 PCIe Root Port |
| 被测 hypervisor | ESXi 8.0.3 build 24280767 |
| DirectPath endpoint | QEMU `e1000e` function `test_fn1`，ESXi `0000:01:00.1` |
| L3 guest | VMware EFI + Linux 5.15 initramfs |
| Correctable | Receiver Error，Correctable Status bit 0，`0x00000001` |
| Non-Fatal | Unsupported Request，Uncorrectable Status bit 20，`0x00100000` |

ESXi 使用本次启动参数，未修改持久默认值：

```text
enablePCIErrors:                 Configured=FALSE Runtime=TRUE
pcipDisablePciErrReporting:     Configured=TRUE  Runtime=FALSE
```

注意：第二个参数为 `FALSE` 只表示不强制关闭 passthrough error reporting，不表示 ESXi
会替 guest 把每个 endpoint 的 PCIe Device Control error-reporting bits 强制置 1。

## 3. 已执行矩阵

| Case | Owner/状态 | 注入 | 结果 |
| --- | --- | --- | --- |
| C00 | VMkernel owner | Correctable Receiver Error | QEMU `OK`；target CES=1；Root Port 与 ESXi 日志无变化 |
| C01 | VM Passthru、未分配 | 状态检查 | 切 owner 不改变 endpoint/Root Port AER enable bits |
| C02d | VM Passthru、L3 活跃 | Correctable Receiver Error | host/guest CES 0->1；guest 无 AER service/log；ESXi 无 AER log |
| C03 | VM Passthru、L3 活跃 | Non-Fatal Unsupported Request | host/guest UES 0->0x00100000；guest/ESXi 无 AER log |
| Q-AER-0 | QEMU Q35+OVMF 默认 | surface probe | Root Port 与 endpoint 均公开 AER |
| Q-AER-1 | QEMU Q35+OVMF，`x-pcie-extcap-init=off` | surface probe | AER 仍公开，参数不能实现目标过滤 |
| Q-AER-2 | QEMU Q35+SeaBIOS 默认 | surface probe | AER 仍公开，和 OVMF 一致 |

C02d、C03 均由 `vmware.log` 中目标 `pciPassthru1` 的首次真实访问加 12 秒触发，
而不是猜测固定开机时间。QEMU HMP 均返回目标 function 的明确 `OK id`。

## 4. 三层寄存器证据

### 4.1 Correctable Receiver Error

物理 endpoint / ESXi view：

```text
before: AER header=0x14020001, CES=0x00000000, Device Status=0x0000
after:  AER header=0x14020001, CES=0x00000001, Device Status=0x0001
```

L3 guest raw config view：

```text
before: AER header=0x00000000, CES=0x00000000, Device Status=0x0000
after:  AER header=0x00000000, CES=0x00000001, Device Status=0x0000
```

### 4.2 Non-Fatal Unsupported Request

物理 endpoint / ESXi view：

```text
before: UES=0x00000000, CES=0x00000001, Device Status=0x0001
after:  UES=0x00100000, CES=0x00000001, Device Status=0x000b
```

L3 guest raw config view：

```text
before: AER header=0x00000000, UES=0x00000000, CES=0x00000001
after:  AER header=0x00000000, UES=0x00100000, CES=0x00000001
```

两轮 guest 均报告：

```text
acpi PNP0A03:00: _OSC: platform does not support [AER LTR DPC]
```

guest 不生成 `aer_dev_correctable`/`aer_dev_nonfatal` sysfs 统计，`dmesg` 没有
`PCIe Bus Error`。ESXi `vmkernel.log`/`vobd.log` 没有本次 AER 事件，上游 QEMU
Root Port 的 Root Error Status 也没有变化。

外部可观察模型因此是：

1. AER Extended Capability header 与 PCIe Device Status 可被 VMware 过滤或合成。
2. capability body 的 error status 可保留物理设备状态并由 raw config read 看见。
3. guest 没有 AER capability discovery 和 Root Port AER service，driver 也没有打开
   endpoint Device Control 的 error-reporting bits。
4. 没有 endpoint Error Message，就不会沿链路更新 Root Port 或形成 host/guest AER log。

## 5. QEMU 对标

### 5.1 Stock QEMU 参数边界

下面的参数不是解决方案：

```text
-device pcie-root-port,...,x-pcie-extcap-init=off
-device e1000e,...,x-pcie-extcap-init=off
-device vfio-pci,...,x-pcie-extcap-init=off
```

本地 guest 实测 AER 仍存在。QEMU 6.2 源码显示，该属性只影响 PCIe capability
初始化时 `0x100` NULL Extended Capability Header 的 writable mask；`e1000e` 随后仍
无条件调用 `pcie_aer_init()`。`vfio-pci` 的 extended-capability rebuild 也默认保留
AER，只显式丢弃 capability ID 0、SR-IOV、ARI 和 ReBAR。

### 5.2 推荐实现

对 QEMU/VFIO 增加显式兼容 profile，例如 `x-vmware-hide-aer=on`：

1. 在 `vfio_add_ext_cap()` 遍历中把 `PCI_EXT_CAP_ID_ERR` 从 guest capability chain
   跳过；只模拟 header/next pointer，不要清空物理 capability body 的只读 status。
2. 给 generic PCIe Root Port 增加 `aer=off`，条件化跳过 `pcie_aer_init()` 和
   `pcie_aer_root_init()`。
3. 精确对齐时提供不授予 AER 的 ACPI `_OSC`；只要求行为对齐时，Root Port 与 endpoint
   都没有可发现 AER service 即可。
4. 物理 AER 的 host ownership 仍由 Linux/VFIO/kernel AER 路径处理；不要把 host
   AER IRQ 无条件转发给 guest。

对齐后的验收点：guest AER header 为 0，AER capability 不出现在 `lspci -vv`，无
`aer_dev_*`，raw body 是否可见由兼容 profile 明确定义；host 仍能记录真实 AER。

## 6. 复现

ESXi boot-only 参数注入：

```powershell
Start-Process -FilePath wsl.exe -WindowStyle Hidden -ArgumentList @(
  '-d','Ubuntu-22.04','--exec','python3',
  '/mnt/e/Code/PCI/_artifacts/qemu-esxi8-boot-options.py'
)
./_artifacts/Invoke-EsxiCaveatSsh.ps1 -RemoteCommand 'reboot'
```

构建并上传 AER guest：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "PROFILE=aer /mnt/e/Code/PCI/_artifacts/build-esxi-l3-probe-iso.sh"
./_artifacts/Copy-EsxiCaveatFile.ps1 -Direction ToEsxi `
  -Source /mnt/e/Code/PCI/_artifacts/esxi-l3-aer-probe.iso `
  -Destination /vmfs/volumes/pci-mmio-local/iso/esxi-l3-aer-probe.iso
```

执行：

```powershell
./_artifacts/Invoke-EsxiAerCase.ps1 `
  -CaseId C02-active-correctable -OwnerState PassthruActive `
  -ErrorClass Correctable -QemuDevice test_fn1 -EsxiBdf 0000:01:00.1 `
  -VmwarePassthruIndex 1 -RunId manual-aer

./_artifacts/Invoke-EsxiAerCase.ps1 `
  -CaseId C03-active-nonfatal -OwnerState PassthruActive `
  -ErrorClass NonFatal -AllowNonFatal -QemuDevice test_fn1 `
  -EsxiBdf 0000:01:00.1 -VmwarePassthruIndex 1 -RunId manual-aer
```

QEMU surface A/B：

```bash
./qemu-aer-surface-validate.sh
```

本地完整证据位于：

```text
_artifacts/vmware-directpath-runs/20260711-aer/C00-native-correctable/
_artifacts/vmware-directpath-runs/20260711-aer/C02d-active-correctable/
_artifacts/vmware-directpath-runs/20260711-aer/C03-active-nonfatal/
```

## 7. 公开依据

- [Broadcom KB 312208：VMDirectPath I/O and Dynamic DirectPath I/O](https://knowledge.broadcom.com/external/article/312208/vsphere-vmdirectpath-io-and-dynamic-dire.html)
- [QEMU 6.2 `pcie.c`：`x-pcie-extcap-init` 的实际作用](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/pci/pcie.c)
- [QEMU 6.2 `e1000e.c`：无条件初始化 AER](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/net/e1000e.c)
- [QEMU 6.2 `vfio/pci.c`：extended capability rebuild/filter](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/vfio/pci.c)
- [QEMU 6.2 `pcie_aer.c`：status、message 与 Root Error Command 模型](https://gitlab.com/qemu-project/qemu/-/blob/v6.2.0/hw/pci/pcie_aer.c)
