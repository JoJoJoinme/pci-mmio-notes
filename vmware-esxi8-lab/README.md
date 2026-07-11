# ESXi 8 VMDirectPath 本地验证复现索引

本文档是 [`vmware-esxi8-directpath-local-results.md`](../vmware-esxi8-directpath-local-results.md) 的可执行入口。结果报告回答“已经证明了什么”；本文回答“如何重跑、看哪里、什么才算通过”。

## 1. 环境与约定

- Windows 工作区：`E:\Code\PCI`
- WSL 路径：`/mnt/e/Code/PCI`
- ESXi 外层 QEMU 状态目录：`/root/vm/esxi8-mf`
- ESXi 本地 datastore：`pci-mmio-local`
- 凭据只从私有 Caveat 读取，不写入命令、日志或 Git。
- 生成的 ESXi 磁盘、Linux ISO、kernel、initrd 和运行期 trace 不纳入 Git。
- 当前自动化默认使用已准备好的嵌套 ESXi 8；若路径不同，先修改脚本顶部的环境变量，不要批量替换证据文件。

所有 PowerShell 命令均在 `E:\Code\PCI` 执行，所有 WSL 命令均从 Windows PowerShell 调用。

## 2. 基础启动与连通性

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
```

验收点：

1. 外层 QEMU 命令包含 `-cpu host,+vmx,-vmx-tsc-scaling`。
2. ESXi `hostd`、`vmkernel` 可用；不能只以 SSH 端口打开作为 ready 条件。
3. 测试 VM 能进入 EFI Linux，串口日志中有完整 PCI resource 和 BAR 信息。

常用外层变量：

| 变量 | 示例 | 用途 |
|---|---:|---|
| `QEMU_ESXI_IVSHMEM_SIZE` | `1G`、`2G` | 改变透传设备的 64-bit BAR 大小 |
| `QEMU_ESXI_TOPOLOGY` | `pcie`、`root`、`legacy` | PCIe Root Port、根端点、传统 PCI 桥拓扑 |
| `QEMU_ESXI_DISABLE_ACS` | `1` | 构造缺少 ACS 的路径 |
| `QEMU_ESXI_LINK_SPEED` | `8` | 外层 PCIe 链路速度能力 |
| `QEMU_ESXI_LINK_WIDTH` | `4` | 外层 PCIe 链路宽度能力 |
| `QEMU_ESXI_TRACE` | `1` | 启用 QEMU IOMMU、MSI-X、reset trace |

改变外层设备或拓扑前先正常关闭 ESXi；若只能强制结束 QEMU，必须把该次执行标为环境中断，不能当作生命周期通过证据。

## 3. Case 总索引

| Case | 目标 | 入口 | 核心证据 |
|---|---|---|---|
| G0/G1 | ESXi 识别设备并成功启动 L3 EFI VM | 基础启动脚本 | `lspci`、串口、`vmware.log` |
| M00-M05 | 1G/2G BAR 与 `use64bitMMIO` 组合 | `Run-EsxiDirectPathMmioCase.ps1` | Guest BAR 地址、root window、effective VMX |
| Q00-Q02 | QEMU/OVMF 对照 | `qemu-ovmf-initrd-mmio-check.sh` | OVMF resource map、BAR 是否分配 |
| A01 | 无 ACS 路径 | 外层 `DISABLE_ACS=1` | `vmkernel.log`、claim/owner |
| A04 | 根端点 reset 能力 | 外层 `TOPOLOGY=root` | ESXi passthru inventory |
| A05 | 传统桥依赖组 | 外层 `TOPOLOGY=legacy` | 依赖设备、批量 enable 行为 |
| A06 | 物理链路与虚拟链路呈现 | link speed/width 变量 | L1/L2 两侧 `LnkSta` |
| D00/I00 | DMA 翻译、requester 与中断重映射 | trace 模式和流量脚本 | QEMU trace、guest workload |
| R00/R01 | reset 行为 | trace + 重启/关机 | reset trace、设备状态计数器 |
| L00-L03 | 电源与生命周期 | `Test-EsxiDirectPathLifecycle.ps1` | API 错误、重启后 BAR、串口 |
| T00 | 重复启动稳定性 | `Test-EsxiDirectPathStress.ps1` | 每轮结果与失败日志 |
| X00-X02 | Dynamic DirectPath | Python 动态分配脚本 | `assignedId`、绑定/解绑日志 |

## 4. MMIO Case：VMware 默认与高级参数

### 4.1 启动 1G BAR 环境

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_IVSHMEM_SIZE=1G /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
```

```powershell
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId M00-1G-Absent -Use64BitMmio Absent
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId M01-1G-False -Use64BitMmio False
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId M02-1G-True -Use64BitMmio True
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId M03-1G-True-Size4 -Use64BitMmio True -SizeGb 4
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId M05-1G-Size4Only -Use64BitMmio Absent -SizeGb 4
```

预期：1G 64-bit BAR 均位于 4G 以下，当前样本为 `0x80000000-0xbfffffff`，Guest 不出现 64-bit root window。各 Case 的 placement 应一致。

### 4.2 启动 2G BAR 环境

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_IVSHMEM_SIZE=2G /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
```

用上一节相同五条命令，将 Case ID 中的 `1G` 改为 `2G`。

预期：2G 64-bit BAR 自动位于 4G 以上，当前样本为 `0x1fff80000000-0x1fffffffffff`。Absent、FALSE、TRUE、TRUE+Size4、Size4-only 的 placement 仍一致。

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

## 6. 拓扑、ACS、依赖和链路

### A01：无 ACS 路径

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_IVSHMEM_SIZE=1G QEMU_ESXI_DISABLE_ACS=1 /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
```

收集 `vmkernel.log` 中 ACS 检查、claim 和 owner 记录。当前环境出现 `enableACSCheckForRP=FALSE`，因此只能证明此嵌套环境绕过了检查，不能推出生产 ESXi 的隔离安全性。

### A04：根端点

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_TOPOLOGY=root QEMU_ESXI_IVSHMEM_SIZE=1G /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
```

预期：ESXi inventory 显示 `Reset Method: None` 或设备不可用于 DirectPath。需同时保存 `esxcli hardware pci list` 和 passthru 列表。

### A05：传统 PCI 桥

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_TOPOLOGY=legacy QEMU_ESXI_IVSHMEM_SIZE=1G /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
```

预期：桥后设备形成依赖组；enable 一个设备时同组成员被一起启用。证据必须包含启用前后完整 passthru inventory。

### A06：链路能力重写

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_LINK_SPEED=8 QEMU_ESXI_LINK_WIDTH=4 QEMU_ESXI_TRACE=1 /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
```

对比外层 QEMU 设备、ESXi L1 和 L3 Guest 的 `lspci -vv`。当前实测外层为 8GT/s x4、L1 端点为 2.5GT/s x1，而 VMware 向 L3 呈现 5GT/s x32；这证明 Guest 看到的是 VMware 合成能力，不能当作物理链路透传。

## 7. DMA、IOMMU、MSI-X 与 reset

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "QEMU_ESXI_TRACE=1 QEMU_ESXI_IVSHMEM_SIZE=1G /mnt/e/Code/PCI/_artifacts/start-qemu-esxi8-mf.sh"
.\_artifacts\Wait-EsxiReady.ps1
.\_artifacts\Enable-EsxiTestPassthru.ps1
.\_artifacts\Run-EsxiDirectPathMmioCase.ps1 -CaseId D00-I00-A06-traced-traffic -Use64BitMmio Absent
```

仓库目前没有独立的 `Run-EsxiTracedTrafficCase.ps1`。上面的 MMIO Case 会完成 L3 启动和设备访问；若要复现已记录的持续流量 trace，还需按 Case 中的 Guest 网络配置手工发流，并从 `/root/vm/esxi8-mf/qemu-trace.log` 裁剪相同时间窗。因此 D00/I00 当前是“证据已取得、复现半自动”，不是一条命令即可验收。

通过标准：

1. workload 确实触发设备 DMA/中断，而非只有枚举。
2. QEMU trace 能定位 requester ID `01:00.0`。
3. trace 能对应 IOMMU domain 翻译和 interrupt remap。
4. Case 目录保存 trace 的裁剪依据和原始文件哈希。

R00/R01 当前只获得“VMware 能关机/重启、设备仍可用”的证据，未观察到外层 qdev reset 事件。要把 reset 提升为硬证据，需给测试设备增加 reset generation counter，或在 QEMU 设备模型的 reset callback 打点，再区分 FLR、总线 reset、宿主重新绑定和仅 Guest 软件复位。

## 8. 生命周期与压力测试

```powershell
.\_artifacts\Test-EsxiDirectPathLifecycle.ps1
.\_artifacts\Test-EsxiDirectPathStress.ps1 -Cycles 10
```

当前预期：

- snapshot 和 suspend 被 ESXi 以 `InvalidState` 拒绝；
- 强制关机后可重新启动；
- 10/10 次循环成功，且 BAR placement 稳定。

生命周期脚本的通过条件必须包含“预期拒绝也得到正确错误类型”，不能只检查命令返回非零。

## 9. Dynamic DirectPath

先用动态 VM 模板注册独立测试 VM：

```powershell
.\_artifacts\Invoke-EsxiCaveatSsh.ps1 -RemoteCommand "mkdir -p /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe"
.\_artifacts\Copy-EsxiCaveatFile.ps1 -Direction ToEsxi -Source /mnt/e/Code/PCI/_artifacts/dynamic-directpath-probe.vmx -Destination /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe/dynamic-directpath-probe.vmx
.\_artifacts\Invoke-EsxiCaveatSsh.ps1 -RemoteCommand "vim-cmd solo/registervm /vmfs/volumes/pci-mmio-local/dynamic-directpath-probe/dynamic-directpath-probe.vmx"
```

若同名 VM 已经注册，不要重复注册，直接执行 inventory 和绑定测试：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/_artifacts/esxi_dynamic_directpath.py --output /tmp/esxi-dynamic-inventory.json
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/_artifacts/test_esxi_dynamic_directpath.py --vm-name dynamic-directpath-probe --output /tmp/esxi-dynamic-result.json
```

模板见 [`dynamic-directpath-probe.vmx`](dynamic-directpath-probe.vmx)。验收点：

1. VM 关闭时 `assignedId` 为空；
2. 开机时动态绑定 `01:00.1`、`01:00.0`、`01:01.0`；
3. 关机后 `assignedId` 再次为空；
4. 保存每次 resolve/bind/unbind 的 hostd/vmkernel 日志，而非只保存最终 VMX。

X01/X02 仍缺“同一 Dynamic DirectPath 配置跨主机重新解析”和“候选设备不足/不兼容时的负面路径”。需要第二台可用 ESXi 或在同一管理域内构造两组不同 PCI inventory。

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
6. X00 Dynamic DirectPath 单机绑定。
7. 最后再做 AER、宿主崩溃、真实复位、vMotion 等破坏性或多主机测试。

不可逆或高风险 Case 应始终在可回滚 ESXi 副本上运行，并把“环境被破坏”与“产品行为失败”分开记录。
