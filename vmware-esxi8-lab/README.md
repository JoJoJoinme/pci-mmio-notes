# ESXi 8 VMDirectPath 本地验证复现索引

本文档是 [`vmware-esxi8-directpath-local-results.md`](../vmware-esxi8-directpath-local-results.md) 的可执行入口。结果报告回答“已经证明了什么”；本文回答“如何重跑、看哪里、什么才算通过”。

## 1. 环境与约定

- Windows 仓库：`E:\Code\PCI\github-export`
- WSL 仓库：`/mnt/e/Code/PCI/github-export`
- ESXi A/B 外层状态目录：`/root/vm/esxi8-mf`、`/root/vm/esxi8-b`
- 管理地址：A=`172.31.91.10`、B=`172.31.91.11`、VCSA=`192.168.91.131`
- 共享 datastore：`qemu-shared`，WSL export=`/root/vm/esxi8-mf/nfsds`
- 凭据只从私有 Caveat 读取，不写入命令、日志或 Git。
- 生成的 ESXi 磁盘、Linux ISO、kernel、initrd 和运行期 trace 不纳入 Git。
- 当前自动化默认使用已准备好的嵌套 ESXi 8；若路径不同，先修改脚本顶部的环境变量，不要批量替换证据文件。

所有 PowerShell 命令均在 `E:\Code\PCI\github-export` 执行，所有 WSL 命令均从
Windows PowerShell 调用。

## 2. 基础启动与连通性

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
wsl -d Ubuntu-22.04 -- bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-b.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1 -HostName 172.31.91.10
.\vmware-esxi8-lab\Wait-EsxiReady.ps1 -HostName 172.31.91.11
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1 -HostName 172.31.91.10
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1 -HostName 172.31.91.11
```

验收点：

1. 外层 QEMU 命令包含 `-cpu host,+vmx,-vmx-tsc-scaling`。
2. ESXi `hostd`、`vmkernel` 可用；不能只以 SSH 端口打开作为 ready 条件。
3. 测试 VM 能进入 EFI Linux，串口日志中有完整 PCI resource 和 BAR 信息。
4. `esxcli storage nfs list` 中 `qemu-shared` 同时为 `Accessible=true/Mounted=true`。
5. QEMU management netdev 含 `vnet_hdr=off`，`br-esxi8` 的 GRO/GSO/TSO 为 off。

常用外层变量：

| 变量 | 示例 | 用途 |
|---|---:|---|
| `QEMU_ESXI_IVSHMEM_SIZE` | `1G`、`2G` | 改变透传设备的 64-bit BAR 大小 |
| `QEMU_ESXI_IVSHMEM_MEM_PATH` | `/root/vm/esxi8-b/ivmem.bin` | 用稀疏 regular file 承载大于 `/dev/shm` 的 BAR |
| `QEMU_ESXI_IVSHMEM_ALT_SIZE` | `1G`、`2G` | 在独立 root port 增加同 VID:DID candidate |
| `QEMU_ESXI_TOPOLOGY` | `pcie`、`root`、`legacy` | PCIe Root Port、根端点、传统 PCI 桥拓扑 |
| `QEMU_ESXI_DISABLE_ACS` | `1` | 构造缺少 ACS 的路径 |
| `QEMU_ESXI_LINK_SPEED` | `8` | 外层 PCIe 链路速度能力 |
| `QEMU_ESXI_LINK_WIDTH` | `4` | 外层 PCIe 链路宽度能力 |
| `QEMU_ESXI_TRACE` | `1` | 启用 QEMU IOMMU、MSI-X、reset trace |

改变外层设备或拓扑前先正常关闭 ESXi；若只能强制结束 QEMU，必须把该次执行标为环境中断，不能当作生命周期通过证据。

### 2.1 NFS transport 完整性

当前启动脚本会幂等恢复 NFS export，给 QEMU management TAP 设置 `vnet_hdr=off`，并
关闭 TAP/bridge 的 checksum、TSO/GSO/GRO/VLAN offload。缺少任一项时，本环境曾复现：

```text
nfsd RPC fragment too large
ESXi: Mounted=true, Accessible=false
datastore access: Input/output error
```

验收命令：

```powershell
wsl -d Ubuntu-22.04 -- ethtool -k br-esxi8
wsl -d Ubuntu-22.04 -- dmesg
.\vmware-esxi8-lab\Invoke-EsxiCaveatSsh.ps1 -HostName 172.31.91.11 -RemoteCommand "esxcli storage nfs list"
```

必须看到 bridge 的 GRO/GSO/TSO 为 off，连续 NFS 写入/哈希成功，并且测试期间没有新增
`RPC fragment too large`。这属于实验 transport integrity，不是 VMware 产品行为。

## 3. Case 总索引

| Case | 目标 | 入口 | 核心证据 |
|---|---|---|---|
| G0/G1 | ESXi 识别设备并成功启动 L3 EFI VM | 基础启动脚本 | `lspci`、串口、`vmware.log` |
| M00-M05 | 1G/2G BAR 与 `use64bitMMIO` 组合 | `Run-EsxiDirectPathMmioCase.ps1` | Guest BAR 地址、root window、effective VMX |
| M04/M07 | 4G/8G gate 与 aggregate packing | `test_esxi_dynamic_bar_aggregate.py` | page limit、BAR/root window、heartbeat |
| Q00-Q02 | QEMU/OVMF 对照 | `qemu-ovmf-initrd-mmio-check.sh` | OVMF resource map、BAR 是否分配 |
| A01 | 无 ACS 路径 | 外层 `DISABLE_ACS=1` | `vmkernel.log`、claim/owner |
| A04 | 根端点 reset 能力 | 外层 `TOPOLOGY=root` | ESXi passthru inventory |
| A05 | 传统桥依赖组 | 外层 `TOPOLOGY=legacy` | 依赖设备、批量 enable 行为 |
| A06 | 物理链路与虚拟链路呈现 | link speed/width 变量 | L1/L2 两侧 `LnkSta` |
| D00/I00 | DMA 翻译、requester 与中断重映射 | trace 模式和流量脚本 | QEMU trace、guest workload |
| C00-C03 | Correctable/Non-Fatal AER ownership | `Invoke-EsxiAerCase.ps1` | QEMU HMP、ESXi config/log、guest raw config/dmesg |
| R00/R01 | reset 与 guest reboot | trace + `test_esxi_guest_reboot.py` | reset trace、efivar phase、两次 I/O |
| L00-L03 | 电源与生命周期 | `Test-EsxiDirectPathLifecycle.ps1` | API 错误、重启后 BAR、串口 |
| T00 | 重复启动稳定性 | `Test-EsxiDirectPathStress.ps1` | 每轮结果与失败日志 |
| X00-X03 | Dynamic DirectPath | Python 动态分配/vMotion 脚本 | `assignedId`、耗尽、relocate |
| I01 | INTx 与 QEMU direct control | `test_esxi_intx_mode.py`、`qemu-intx-direct-validate.sh` | IRQ 计数、流量 |
| L02/L04 | vMotion 与 host crash | `test_esxi_vmotion_matrix.py`、`test_esxi_host_crash_recovery.py` | task fault、恢复状态 |

## 4. MMIO Case：VMware 默认与高级参数

### 4.1 启动 1G BAR 环境

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
```

```powershell
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId M00-1G-Absent -Use64BitMmio Absent
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId M01-1G-False -Use64BitMmio False
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId M02-1G-True -Use64BitMmio True
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId M03-1G-True-Size4 -Use64BitMmio True -SizeGb 4
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId M05-1G-Size4Only -Use64BitMmio Absent -SizeGb 4
```

预期：1G 64-bit BAR 均位于 4G 以下，当前样本为 `0x80000000-0xbfffffff`，Guest 不出现 64-bit root window。各 Case 的 placement 应一致。

### 4.2 启动 2G BAR 环境

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=2G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
```

用上一节相同五条命令，将 Case ID 中的 `1G` 改为 `2G`。

预期：2G 64-bit BAR 自动位于 4G 以上，当前样本为 `0x1fff80000000-0x1fffffffffff`。Absent、FALSE、TRUE、TRUE+Size4、Size4-only 的 placement 仍一致。

### 4.3 4G/8G gate 与 aggregate

大 BAR 使用稀疏 regular file，避免 `/dev/shm` 容量成为假阻塞：

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=4G QEMU_ESXI_IVSHMEM_MEM_PATH=/root/vm/esxi8-b/ivmem-sparse.bin bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-b.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_dynamic_bar_aggregate.py --requested-devices 1 --use64bit-mmio true --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

4G 要分别跑 absent、`--size-gb 4` only、TRUE-only、TRUE+Size4。预期只有含
`use64bitMMIO=TRUE` 的两组通过。8G 同样使用 sparse backing，但当前 nested 平台只
通过 VMX/IOMMU mapping，未得到 guest heartbeat；不要直接扩到 32G/64G。

aggregate 需要两个独立 root port：

```powershell
# 两个 1G candidate
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=1G QEMU_ESXI_IVSHMEM_ALT_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-b.sh

# 一个 2G + 一个 1G candidate
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=2G QEMU_ESXI_IVSHMEM_ALT_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-b.sh

wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_dynamic_bar_aggregate.py --requested-devices 2 --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

同 root port 负例可加 `QEMU_ESXI_IVSHMEM_ALT_SHARED_ROOT_PORT=1`；预期因完整
IOMMU/reset dependency 不能拆分而失败。

每个 Case 至少保留：

- 输入参数和 Case 元数据；
- 生效后的 `.vmx`；
- Guest 串口；
- 对应 `vmware.log`；
- ESXi PCI owner/claim 信息；
- 可定位本次外层 QEMU 命令的记录。

## 5. QEMU/OVMF 对照矩阵

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/e/Code/PCI/github-export && WORKDIR=/tmp/qemu-mmio-2g MACHINE=pc-q35-jammy BAR_SIZES=2G CASES='ovmf_default ovmf_both_zero ovmf_both_2g' ./qemu-ovmf-initrd-mmio-check.sh"
```

验收点：

| Case | `X-PciMmio64Mb` | `pci-hole64-size` | 预期 |
|---|---:|---:|---|
| `ovmf_default` | 默认 | 默认 | 约 32G high window，2G BAR 在 4G 以上 |
| `ovmf_both_zero` | `0` | `0` | 2G BAR 不应被成功分配 |
| `ovmf_both_2g` | `2048` | `2G` | 2G high window，BAR 位于其中 |

结论判定不能只看 QEMU 命令行；必须同时看 OVMF/Guest 的 root resource window 和端点 BAR 最终地址。

当前与 VMware 样本直接对照的一键入口：

```powershell
wsl -d Ubuntu-22.04 -- env WORKDIR=/mnt/e/Code/PCI/_artifacts/mmio-tests/qemu-vmware-default-profile-REPLAY bash /mnt/e/Code/PCI/github-export/qemu-vmware-default-profile-validate.sh
```

它包含 i440fx 1G 低置通过、i440fx 2G 高置通过和 q35 zero/zero 负例。SeaBIOS
矩阵由 `qemu-ovmf-real-linux-validate.sh` 复现；它只验证固件/ACPI 边界，不作为
VMware EFI 等价 profile。

## 6. 拓扑、ACS、依赖和链路

### A01：无 ACS 路径

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=1G QEMU_ESXI_DISABLE_ACS=1 bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
```

收集 `vmkernel.log` 中 ACS 检查、claim 和 owner 记录。当前环境出现 `enableACSCheckForRP=FALSE`，因此只能证明此嵌套环境绕过了检查，不能推出生产 ESXi 的隔离安全性。

### A04：根端点

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_TOPOLOGY=root QEMU_ESXI_IVSHMEM_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
```

预期：ESXi inventory 显示 `Reset Method: None` 或设备不可用于 DirectPath。需同时保存 `esxcli hardware pci list` 和 passthru 列表。

### A05：传统 PCI 桥

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_TOPOLOGY=legacy QEMU_ESXI_IVSHMEM_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
```

预期：桥后设备形成依赖组；enable 一个设备时同组成员被一起启用。证据必须包含启用前后完整 passthru inventory。

### A06：链路能力重写

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_LINK_SPEED=8 QEMU_ESXI_LINK_WIDTH=4 QEMU_ESXI_TRACE=1 bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
```

对比外层 QEMU 设备、ESXi L1 和 L3 Guest 的 `lspci -vv`。当前实测外层为 8GT/s x4、L1 端点为 2.5GT/s x1，而 VMware 向 L3 呈现 5GT/s x32；这证明 Guest 看到的是 VMware 合成能力，不能当作物理链路透传。

## 7. DMA、IOMMU、MSI-X 与 reset

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_TRACE=1 QEMU_ESXI_IVSHMEM_SIZE=1G bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
.\vmware-esxi8-lab\Run-EsxiDirectPathMmioCase.ps1 -CaseId D00-I00-A06-traced-traffic -Use64BitMmio Absent
```

仓库目前没有独立的 `Run-EsxiTracedTrafficCase.ps1`。上面的 MMIO Case 会完成 L3 启动和设备访问；若要复现已记录的持续流量 trace，还需按 Case 中的 Guest 网络配置手工发流，并从 `/root/vm/esxi8-mf/qemu-trace.log` 裁剪相同时间窗。因此 D00/I00 当前是“证据已取得、复现半自动”，不是一条命令即可验收。

通过标准：

1. workload 确实触发设备 DMA/中断，而非只有枚举。
2. QEMU trace 能定位 requester ID `01:00.0`。
3. trace 能对应 IOMMU domain 翻译和 interrupt remap。
4. Case 目录保存 trace 的裁剪依据和原始文件哈希。

R01 guest reboot 已自动化：

```powershell
wsl -d Ubuntu-22.04 -- env PROFILE=reboot bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_guest_reboot.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

通过标准是 efivar first/second phase、reboot 前后各一次 `tx>0`、最终关机解绑。R00
具体 reset 类型仍需 endpoint generation counter 或 QEMU reset callback trace。

INTx A/B：

```powershell
wsl -d Ubuntu-22.04 -- env PROFILE=intx bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_intx_mode.py --settle-seconds 60 --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- env WORKDIR=/mnt/e/Code/PCI/_artifacts/mmio-tests/qemu-intx-direct-REPLAY bash /mnt/e/Code/PCI/github-export/qemu-intx-direct-validate.sh
```

当前 ESXi nested path 为可重复 functional fail，QEMU direct control 为 pass。必须保留
两边同 ISO 的结果，不能只凭 guest 出现 IO-APIC 行就判 INTx 通过。

## 8. 生命周期与压力测试

```powershell
.\vmware-esxi8-lab\Test-EsxiDirectPathLifecycle.ps1
.\vmware-esxi8-lab\Test-EsxiDirectPathStress.ps1 -Cycles 10
```

当前预期：

- snapshot 和 suspend 被 ESXi 以 `InvalidState` 拒绝；
- 强制关机后可重新启动；
- 10/10 次循环成功，且 BAR placement 稳定。

生命周期脚本的通过条件必须包含“预期拒绝也得到正确错误类型”，不能只检查命令返回非零。

双主机与 host crash：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_vmotion_matrix.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_host_crash_recovery.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

vMotion runner 必须同时得到普通 VM live migration pass、Classic/Dynamic expected reject、
powered-off Dynamic relocate pass。host-crash runner 会 `SIGKILL` outer QEMU，只能在可回滚
副本上执行，并必须验证 datastore、owner、同 VM 再启动和再次 I/O。

## 9. Dynamic DirectPath

先用动态 VM 模板注册独立测试 VM：

```powershell
.\vmware-esxi8-lab\Invoke-EsxiCaveatSsh.ps1 -RemoteCommand "mkdir -p /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe"
.\vmware-esxi8-lab\Copy-EsxiCaveatFile.ps1 -Direction ToEsxi -Source /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/dynamic-directpath-probe.vmx -Destination /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe/dynamic-directpath-probe.vmx
.\vmware-esxi8-lab\Invoke-EsxiCaveatSsh.ps1 -RemoteCommand "vim-cmd solo/registervm /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe/dynamic-directpath-probe.vmx"
```

若同名 VM 已经注册，不要重复注册，直接执行 inventory 和绑定测试：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/esxi_dynamic_directpath.py --output /tmp/esxi-dynamic-inventory.json
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_dynamic_directpath.py --vm-name dynamic-directpath-probe --output /tmp/esxi-dynamic-result.json
```

模板见 [`dynamic-directpath-probe.vmx`](dynamic-directpath-probe.vmx)。验收点：

1. VM 关闭时 `assignedId` 为空；
2. 开机时动态绑定 `01:00.1`、`01:00.0`、`01:01.0`；
3. 关机后 `assignedId` 再次为空；
4. 保存每次 resolve/bind/unbind 的 hostd/vmkernel 日志，而非只保存最终 VMX。

X01 异构 BAR、X02 candidate 耗尽/释放恢复、X03 powered-off relocate 已由
`test_esxi_dynamic_bar_envelope.py` 与 `test_esxi_vmotion_matrix.py` 完成。第一次把两个
candidate 放进同一 outer root port 的失败也保留为 dependency 负例。

## 10. 产物与结果合同

建议每个 Case 统一输出：

```text
case-id/
  case.json
  result.json
  qemu-command.txt
  effective.vmx
  guest-serial.log
  vmware.log
  esxi-pci-inventory.txt
  esxi-passthru-state.txt
  vmkernel-extract.log
  hostd-extract.log
  trace-extract.log
  SHA256SUMS
```

`result.json` 至少包含 `case_id`、环境版本、输入参数、实际 BAR/root window、设备 owner、预期、实际、`pass|partial|blocked|fail` 和证据相对路径。只有满足此合同，Case 才适合跨版本回归和机器比较。

## 11. 推荐执行顺序

1. G0/G1 基线启动与设备识别。
2. 1G/2G 的 M00-M05，并立即跑 QEMU 对照矩阵。
3. A01/A04/A05/A06 拓扑组。
4. D00/I00 trace 流量。
5. L00-L03 和 T00 生命周期。
6. X00-X03 Dynamic DirectPath 与 vMotion。
7. R01/I01；最后才执行 AER injection 与 host crash 等破坏性用例。

不可逆或高风险 Case 应始终在可回滚 ESXi 副本上运行，并把“环境被破坏”与“产品行为失败”分开记录。
