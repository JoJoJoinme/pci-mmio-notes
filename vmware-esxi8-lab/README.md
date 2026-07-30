# ESXi 8 VMDirectPath 本地验证复现索引

本文档是 [`vmware-esxi8-directpath-local-results.md`](../vmware-esxi8-directpath-local-results.md) 的可执行入口。结果报告回答“已经证明了什么”；本文回答“如何重跑、看哪里、什么才算通过”。

## 1. 环境与约定

- Windows 仓库：`E:\Code\PCI\github-export`
- WSL 仓库：`/mnt/e/Code/PCI/github-export`
- ESXi A/B 外层状态目录：`/root/vm/esxi8-mf`、`/root/vm/esxi8-b`
- 管理地址：A=`172.31.91.10`、B=`172.31.91.11`、VCSA=`192.168.91.131`
- 共享 datastore：`qemu-shared`，WSL export=`/root/vm/esxi8-mf/nfsds`；A 主机本地
  VMFS `pci-mmio-local` 用于 D01 等不依赖共享存储的长时 trace。
- 凭据只从私有 Caveat 读取，不写入命令、日志或 Git。
- 生成的 ESXi 磁盘、Linux ISO、kernel、initrd 和运行期 trace 不纳入 Git。
- 当前大 BAR/endpoint patch 基线为 WSL `6.6.123.2-microsoft-standard-WSL2+` 与
  QEMU 11.0.2 lab binary；旧 QEMU 6.2 保留作 A/B。
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
4. 使用 NFS 的 Case 中，`qemu-shared` 同时为 `Accessible=true/Mounted=true`；使用
   `--esxi-local-storage` 的 Case 则检查 `pci-mmio-local` 已挂载且空间充足。
5. QEMU management netdev 含 `vnet_hdr=off`，`br-esxi8` 的 GRO/GSO/TSO 为 off。

常用外层变量：

| 变量 | 示例 | 用途 |
|---|---:|---|
| `QEMU_ESXI_IVSHMEM_SIZE` | `1G`、`2G` | 改变透传设备的 64-bit BAR 大小 |
| `QEMU_ESXI_QEMU_BINARY` | `/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64` | 选择 capability-lab QEMU；每次结果记录 hash |
| `QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE` | `8G`、`32G`、`64G` | 无等量 backing 的超大 64-bit BAR；与主 ivshmem/EDU 互斥 |
| `QEMU_ESXI_HOST_HOLE64_SIZE` | `64G` | 外层 q35 high-MMIO window；大于 32G 的 testdev 会自动补齐 |
| `QEMU_ESXI_OVMF_MMIO64_MB` | `65536` | 外层 OVMF high-MMIO aperture，单位 MiB |
| `QEMU_ESXI_PRIMARY_DEDICATED_ROOT_PORT` | `1` | 将主测试 endpoint 放到独占 Root Port；大 BAR正式正例必须启用 |
| `QEMU_ESXI_EDU` | `1` | 增加 MSI-only、可编程 DMA 的 QEMU EDU endpoint |
| `QEMU_ESXI_EDU_DMA_MASK` | `0xfffffff` | 可选覆盖 EDU DMA mask |
| `QEMU_ESXI_IVSHMEM_MEM_PATH` | `/root/vm/esxi8-b/ivmem.bin` | 用稀疏 regular file 承载大于 `/dev/shm` 的 BAR |
| `QEMU_ESXI_IVSHMEM_ALT_SIZE` | `1G`、`2G` | 在独立 root port 增加同 VID:DID candidate |
| `QEMU_ESXI_TOPOLOGY` | `pcie`、`root`、`legacy` | PCIe Root Port、根端点、传统 PCI 桥拓扑 |
| `QEMU_ESXI_DISABLE_ACS` | `1` | 构造缺少 ACS 的路径 |
| `QEMU_ESXI_LINK_SPEED` | `8` | 外层 PCIe 链路速度能力 |
| `QEMU_ESXI_LINK_WIDTH` | `4` | 外层 PCIe 链路宽度能力 |
| `QEMU_ESXI_TRACE` | `1` | 启用 QEMU IOMMU、MSI-X、reset trace |

改变外层设备或拓扑前先正常关闭 ESXi；若只能强制结束 QEMU，必须把该次执行标为环境中断，不能当作生命周期通过证据。

### 2.1 Workstation ESXi 无 IOMMU 负控

当前 Workstation ESXi 可作为不带 virtual VT-d 的实际负控。`snapshot --observe-all` 只读取
vSphere property、ESXCLI 和 vmkernel log，不改变 owner：

```powershell
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' start `
  'E:\vm\vmware\esxi8-auto-codex\esxi8-auto-codex.vmx' nogui
.\vmware-esxi8-lab\Wait-EsxiReady.ps1 -HostName 192.168.91.128
wsl -e python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_owner_activation.py snapshot `
  --host 192.168.91.128 --target 0000:02:00.0 --observe-all `
  --expected-system-uuid c6fc4d56-d087-918d-f012-631536abaf6d `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/20260718-workstation-esxi8-noiommu-live-v4
```

验收点：`iommuEvidence` 同时包含 DMAR 缺失和 IOMMU unavailable；全部 API 条目
`capable=false`，`passthruList.stdout` 为空。完整结果见
[`evidence/esxi8-workstation-noiommu-20260718.md`](../evidence/esxi8-workstation-noiommu-20260718.md)。

### 2.2 NFS transport 完整性

当前启动脚本会先加载 `sunrpc`、`nfsd`、`auth_rpcgss`，幂等恢复 NFS export，给
QEMU management TAP 设置 `vnet_hdr=off`，并
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

### 2.3 VFIO no-IOMMU 与 IOMMU 分流

这个用例不启动 ESXi；它在两个 QEMU Ubuntu guest 内实际把同一 e1000e 从 native driver
切换给 `vfio-pci`，验证宿主全局 unsafe 允许位与逐设备 DMA backend 是两个事实：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/e/Code/PCI/github-export && \
python3 vmware-esxi8-lab/test_qemu_vfio_noiommu_split.py \
--output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/vfio-noiommu-split"
```

通过条件：

1. 两个 guest 都输出 `UNSAFE_SWITCH=Y` 和 `POST_BIND_DRIVER=vfio-pci`。
2. 无 vIOMMU 场景 bind 前 group=none，bind 后出现 `/dev/vfio/noiommu-N`。
3. Intel vIOMMU 场景 bind 前后 group 不变，出现 `/dev/vfio/N` 和 VFIO cdev。
4. 两侧均输出 `VFIO_SPLIT_FAILURES=0`、`VFIO_SPLIT_PASS`，最终 `summary.json` verdict=pass。

已归档结论和 artifact hash 见
[`../evidence/qemu-vfio-noiommu-split-20260718.md`](../evidence/qemu-vfio-noiommu-split-20260718.md)。

D01 的正式结果改用 `pci-mmio-local`。早期 NFS 尝试在 Linux server 侧出现
`svc_tcp_read_marker ... RPC fragment too large`，ESXi 随后把 datastore 标为
`Accessible=false`；该失败属于嵌套网络 transport，不作为 DirectPath 结论。

## 3. Case 总索引

| Case | 目标 | 入口 | 核心证据 |
|---|---|---|---|
| G0/G1 | ESXi 识别设备并成功启动 L3 EFI VM | 基础启动脚本 | `lspci`、串口、`vmware.log` |
| LF00-LF06 | VMware firmware/layout 显式四格与两种缺省路径 | `Test-EsxiFirmwareLayoutMatrix.ps1`、`Test-EsxiCreateVmLayoutDefault.ps1` | 输入/生效 VMX、API 三阶段 layout、root bus、BAR2、IOMMU、power-on fault |
| M00-M05 | 1G/2G BAR 与 `use64bitMMIO` 组合 | `Run-EsxiDirectPathMmioCase.ps1` | Guest BAR 地址、root window、effective VMX |
| M04/M07 | 4G/8G gate 与 aggregate packing | `test_esxi_dynamic_bar_aggregate.py` | page limit、BAR/root window、heartbeat |
| M04 8/32/64G | no-backing large-BAR gate/预算/runtime | `test_esxi_largebar_matrix.py` | page limit、IOMMU mapping、guest BAR/heartbeat、outer QEMU argv/HMP |
| Q00-Q06 | QEMU SeaBIOS/OVMF、single/bridge/PXB/q35 对照 | `qemu-firmware-layout-matrix-validate.sh` | 固件、chipset、ACPI roots、BAR2、预期正负断言 |
| A01 | 无 ACS 路径 | 外层 `DISABLE_ACS=1` | `vmkernel.log`、claim/owner |
| A04 | 根端点 reset 能力 | 外层 `TOPOLOGY=root` | ESXi passthru inventory |
| A05 | 传统桥依赖组 | 外层 `TOPOLOGY=legacy` | 依赖设备、批量 enable 行为 |
| A06 | 物理链路与虚拟链路呈现 | link speed/width 变量 | L1/L2 两侧 `LnkSta` |
| D00/I00 | DMA 翻译、requester 与中断重映射 | trace 模式和流量脚本 | QEMU trace、guest workload |
| D01 | power-off 前后 DMA domain 切换 | `test_esxi_edu.py --verify-dma-teardown` | 同 SID/IOVA 的 live/post-off VT-d translation 与 invalidation |
| C00-C03 / COR-8 / M26 正控 | AER surface/status projection、公开 gate 与 Root sequence 对照 | `test_esxi_aer_correctable_matrix.py`、`test_qemu_aer_correctable_matrix.py`、`test_qemu_aer_root_sequence.py`、`test_esxi_aer_root_sequence.py`；旧 `Invoke-EsxiAerCase.ps1` 仅保留历史基线 | Correctable-only allow-list、endpoint/root/ESXi/guest 快照、effective gates、first/multiple、独立 W1C、OR、re-arm、owner、bounded logs、safety stop |
| R00/R01 | reset 与 guest reboot | trace + `test_esxi_guest_reboot.py` | reset trace、efivar phase、两次 I/O |
| L00-L03 | 电源与生命周期 | `Test-EsxiDirectPathLifecycle.ps1` | API 错误、重启后 BAR、串口 |
| T00 | 重复启动稳定性 | `Test-EsxiDirectPathStress.ps1` | 每轮结果与失败日志 |
| X00-X03 | Dynamic DirectPath | Python 动态分配/vMotion 脚本 | `assignedId`、耗尽、relocate |
| I01 | INTx 与 QEMU direct control | `test_esxi_intx_mode.py`、`qemu-intx-direct-validate.sh` | IRQ 计数、流量 |
| I02/D00/R00 | EDU MSI-only、DMA、reset sentinel | `test_esxi_edu.py`、`qemu-edu-direct-validate.sh` | Guest IRQ/DMA、VT-d/IR trace、VMware reset log |
| L02/L04 | vMotion 与 host crash | `test_esxi_vmotion_matrix.py`、`test_esxi_host_crash_recovery.py` | task fault、恢复状态 |
| CAP00-CAP22 | `passthruCapable` 资格判定 | `test_esxi_passthru_capability_matrix.py` | IOMMU、FLR/bridge reset、ACS policy、class code、真实 Type-1 bridge、dependency、restore |
| O00-O10 | owner activation、deferred/reboot、consumer Busy、依赖扩组、VM 独占 lease | `test_esxi_owner_activation.py` + 受控 vSwitch | Configured/Current Owner、SOAP fault、ESXCLI、host/vSwitch snapshot、`vmware.log` |
| S01-S05 | Option ROM、PME、AER、P2P、RMRR | `test_esxi_optionrom.py`、`test_esxi_pme.py`、上述两个 AER runner、`test_esxi_p2p_matrix.py`、`test_esxi_rmrr_matrix.py` | guest/config/log/QEMU trace；AER 必须分 deposition/route/log/recovery |
| SRIOV | PF/VF 公开 surface | `test_esxi_sriov.py`、`collect_esxi_sriov_driver_surface.py` | raw capability、driver state、VF inventory |

### 3.1 Correctable AER 黑盒入口

先运行 QEMU 公开模型正控。它为每个 tuple 启动 fresh QEMU，并验证 8 个 Correctable bit
在 `G=(E,M,R)` 的 `000`—`111` 全部八种 gate 下的寄存器与 Root Source 行为。2026-07-23
的完整运行是 64/64 PASS；只有 `E=1,M=0` 的 `g100/g101` 记录 Root reception，R 只改变
notification eligibility，不抑制 QEMU Root Status 沉积：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_aer_correctable_matrix.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/qemu-cor-emr-64
```

对应 64-row `result.json` SHA-256 为
`40880169d5a4deaf01019af7d0e4618886464256cd5513f1e6d06be14cff52a4`。

Root Status/Source 的 first/multiple、独立 W1C、B0/B1 OR 与 re-arm 使用独立 runner；
每个 sequence/repeat 都启动 fresh QEMU：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_qemu_aer_root_sequence.py `
  --qemu /root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID `
  --gate g101 --repeat 3
```

2026-07-26 的正式运行是 12/12 `MATCH`，聚合 `result.json` SHA-256 为
`59839df23f9711162f4d8548b7e258e355957bda23348f6acd727eb219decb5b`，12 个逐案 manifest
共 276 个 hash 均已校验。摘要见
[`../evidence/qman-qemu-aer-root-sequence-20260726-summary.json`](../evidence/qman-qemu-aer-root-sequence-20260726-summary.json)。
这只建立 QEMU public-model 正控；ESXi live observation 由独立 canonical artifact 授权，
不能由该正控代证。

这里必须把 runner readiness 与 live observation 分开：

- QEMU root-state 正控是 12/12 formal evidence。
- canonical V17 `20260729-esxi8-aer-root-o4-v17-full1` 已在 O4/`g101` 完成
  First/Multiple、独立 W1C、B0/B1 OR、re-arm 各 3 次，12/12 `MATCH`、`FULL_PLAN`，
  offline exact 与 `--require-complete` 校验均通过。冻结
  [`campaign result`](../evidence/esxi8-aer-root-o4-v17-full1-20260729-campaign-result.json)
  SHA-256 为
  `847a2500ae868a47d1abe8ae9765848085f8c31605afaa74b78cbc1923d40b7f`；canonical
  [`result record`](../evidence/esxi8-aer-root-o4-v17-full1-20260729-result.json) 与
  [`summary`](../evidence/esxi8-aer-root-o4-v17-full1-20260729-summary.json) 固定边界。
- canonical V19 `20260730-esxi8-aer-root-o0-v19-full1` 已在 O0/`g101` 完成相同
  12 案，12/12 `MATCH`、`FULL_PLAN`。canonical
  [`result record`](../evidence/esxi8-aer-root-o0-v19-full1-20260730-result.json)、
  [`summary`](../evidence/esxi8-aer-root-o0-v19-full1-20260730-summary.json) 与
  [`campaign result`](../evidence/esxi8-aer-root-o0-v19-full1-20260730-campaign-result.json)
  SHA-256 分别为 `538aaf8c…310b`、`5a58f4de…dff`、`b2ab49a2…c6d6`。
- V19 与 V17 的 12 对 `evaluation-input.snapshots` 逐字段 exact，形成
  [`O0+O4 observed profile`](../contracts/vmware-aer-root-sequence-frozen-observed-g101-o0-o4-v1.json)
  （SHA-256 `cafa0835…1a6e`）与
  [`promotion receipt`](../evidence/esxi8-aer-root-g101-o0-o4-profile-promotion-20260730-summary.json)
  （SHA-256 `fab09980…12a`）。
- 该闭环只授权 exact build/device/QEMU/`g101` 外部寄存器状态。O0 目标
  `Module Name=None`，未证明 bound native driver，也不证明 owner-independent 私有机制、
  service/IRQ、其他 gate、guest write、lifecycle 或物理 qualification；M26、M06、R13、
  G1-G6 不关闭，也不从外部现象还原 VMware 私有实现。

离线门和无副作用计划入口为：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_aer_root_sequence.py selftest

wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_aer_root_sequence_unit.py

wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_aer_root_sequence.py `
  plan --owner-phase O0 --gate g101 --repeat 3 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/esxi-root-o0-plan
```

live `run` 还必须绑定 exact ESXi build/system UUID、endpoint/root BDF、QEMU/QTest socket、
base VMX 与本地 ISO/attestation，并显式提供 `--authorized-lab-target` 和
`--execute-correctable`。缺任一绑定都应 fail closed；任何 `plan`、selftest 或 unit 结果
都不得登记为 VMware observation。V17/V19 的 live authority 也只能用于它们共同绑定的
exact O0+O4/`g101` profile，不能替代 bound native driver 或其他 gate。

当前本地 AER guest fixture ISO SHA-256 为
`3DE27D166EE6881BFB60D8DA233A0B3E6871532108D01D5741C8A43BA91777DE`，
build attestation SHA-256 为
`103941485D8B1679D6DA18312025F5155F4A027F86EFA99E5BAD2FAA66FD67C1`。
它们只绑定 guest fixture/build 输入，不构成 ESXi 行为证据。
离线冻结账本为
[`20260726-esxi-aer-root-runner-offline-v3/result.json`](../../_artifacts/vmware-directpath-runs/20260726-esxi-aer-root-runner-offline-v3/result.json)，
SHA-256 为
`bae6e1e0d552a2d2859250a3ac61448c010df37f27903c774e79713f8f90cf23`；
它绑定 helper/runner/unit 源码哈希与 78 × 3 回归账本，仍不构成 ESXi observation。

ESXi runner 只暴露 `pcie_aer_inject_error -c` 和封闭的八位 allow-list；没有 Uncorrectable
注入参数。当前保留两个并列 profile，不能用后一个覆盖前一个：

- 历史 `e1000e 8086:10d3` 使用 `status-routing`，只容许已观察到的 sticky CED；其
  endpoint/root CERE 与 Root COR_EN 均为 0，结论限于 status/guest projection。
- 受控 `virtio-net-pci 1af4:1041,aer=on` 使用 `strict` baseline；runner 独立 lease
  upstream `BridgeCtl.SERR` 与 Root `DeviceCtl.CERE`，再设置 EMR tuple，并在 finally
  恢复原 gate。

两种模式都要求 CES、UES、Root Status/Source、root Device Status 和上游拓扑按各自策略
clean/readback。Active VM 在 owner 建立前后各清一次基线。任何 UES、非 CED Device Status
或 Root Uncorrectable 增量都会 `FAIL_SAFETY` 并停止剩余 case。

历史 e1000e deposition：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_aer_correctable_matrix.py `
  --host 172.31.91.10 --owner-state PassthruIdle `
  --error-bits receiver_error,bad_tlp,bad_dllp,replay_number_rollover,replay_timer_timeout,advisory_nonfatal,corrected_internal_error,header_log_overflow `
  --qemu-monitor /root/vm/esxi8-mf/monitor.sock `
  --qtest-socket /root/vm/esxi8-mf/qtest.sock --qtest-clean-baseline `
  --qtest-baseline-policy status-routing `
  --outer-endpoint-bdf 0000:01:00.1 --outer-root-bdf 0000:00:08.0 `
  --esxi-bdf 0000:01:00.1 --esxi-root-bdf 0000:00:08.0 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/esxi-cor-idle-8
```

受控 virtio Idle Receiver EMR：

```bash
QEMU_ESXI_TEST_FN1_MODEL=virtio-net-pci \
QEMU_ESXI_TEST_FN1_AER=on \
./vmware-esxi8-lab/start-qemu-esxi8-mf.sh
```

确认 ESXi SSH ready、`01:00.1` 为 `1af4:1041` 且 Current Owner 为 `VM Passthru` 后，再执行：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_aer_correctable_matrix.py `
  --host 172.31.91.10 --owner-state PassthruIdle `
  --error-bits receiver_error `
  --gate-tuples 000,001,010,011,100,101,110,111 `
  --enable-root-path `
  --qemu-monitor /root/vm/esxi8-mf/monitor.sock `
  --qtest-socket /root/vm/esxi8-mf/qtest.sock --qtest-clean-baseline `
  --qtest-baseline-policy strict `
  --outer-endpoint-bdf 0000:01:00.1 --outer-root-bdf 0000:00:08.0 `
  --esxi-bdf 0000:01:00.1 --esxi-root-bdf 0000:00:08.0 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/esxi-virtio-idle-emr-8
```

该矩阵的已固定结果为 8/8 PASS，raw `result.json` SHA-256：
`655337743c4189fa0d08482159109ce3ee85bb7267c52b4714998b0ad0051bf1`。只有
`g100/g101` 在 outer QEMU 暂停期间出现 Root reception/Source；这个 frozen snapshot
证明 QEMU fabric transport，不证明 ESXi service、IRQ 或私有实现。恢复 ESXi 后的
register timeline、owner 和日志是另一层黑盒观察。Active `g100/g101` 已各完成一次
Correctable-only 注入：virtio guest 的 AER header 为 `0x00020001`，raw CES `0→1`，
`TOTAL_ERR_COR/FATAL/NONFATAL` 均保持 `0→0`，且没有实际 `PCIe Bus Error` 或 AER
`severity=` kernel event。`aer_dev_correctable:`、`aer_dev_fatal:` 和
`aer_dev_nonfatal:` 只是 sysfs 标题，不是事件；ESXi 的 SCP 审计路径和采集命令也必须从
host AER event 匹配中排除。
最终 active g101/g100 result SHA-256 分别为
`c4511cb3514fd27b992a44af44c7dbdcf339c1a364730adcd06fb884ba700d72` 与
`bd455a4d9278e53687cf16dd2cfefe161bad78ec946249725a614dce2dd975c0`；治理入口见
[`../evidence/esxi8-aer-correctable-virtio-route-20260723-result.json`](../evidence/esxi8-aer-correctable-virtio-route-20260723-result.json)。

case 的 `PASS` 仅表示对应 observation oracle 满足。历史 CERE=0 行必须读取
`observations.messageRouting.conclusion`，只能写
`NOT_TESTABLE_ENDPOINT_CERE_DISABLED`，不能写成“ESXi 收到 ERR_COR 后静默”。所有 profile
的日志为空都只表示 `NOT_OBSERVED_IN_CAPTURED_TAIL_WINDOW`，即 bounded negative，不是
“无 service/IRQ”的证明。capability/header 可见性、raw status projection、Linux AER
counter 和 service/event delivery 必须分别判定。完整矩阵与 Qman 设计消费见
[`../vmware-aer-correctable-validation-plan.md`](../vmware-aer-correctable-validation-plan.md)。

### 3.2 O00-O10 owner activation 复现入口

统一脚本只从 Caveat 读取密码，不把凭据写入 argv、结果或仓库。`snapshot` 是只读；`api-set` 和
`admission-pair` 必须显式带 `--execute`。`--target` 是 SOAP 的 request set，`--observe` 只增加
事务前后读回的 BDF，正是验证“请求一个 member、观察整个 owner group”的关键：

```powershell
# 只读 inventory/owner/vSwitch/vmk 快照
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_owner_activation.py snapshot `
  --host 172.31.91.10 `
  --target 0000:02:01.0 --observe 0000:02:01.1 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/snapshot

# 只请求空闲 function 0，同时观察共享 dependency 的 function 1
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_owner_activation.py api-set `
  --host 172.31.91.10 `
  --target 0000:02:01.0 --observe 0000:02:01.1 `
  --apply-now --execute `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/api-idle-request

# 两 VM 和同 VM shared-dependent admission；临时 VM 在 finally 中销毁
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_owner_activation.py admission-pair `
  --host 172.31.91.10 `
  --target 0000:02:01.0 --target 0000:02:01.1 `
  --datastore pci-mmio-local --execute `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID/admission
```

脚本固定检查 ESXi build `24280767` 和实验 host system UUID，拒绝管理 BDF/重复 target，并保存 SOAP state、ESXCLI PCI state、
physical NIC、vSwitch、vmkernel interface、相关 hostd/vmkernel 日志和临时 VM `vmware.log`。
`admission-pair` 要求 host 已退出 maintenance mode；脚本会在 `CreateVM` 前明确拒绝，避免把
笼统的 `InvalidState` 误判为 passthrough admission 结果。
若实验环境的管理 BDF 不同，先用只读 snapshot 确认，再显式传正确的 `--management-bdf`；不能
为了跑 case 把保护参数指向待测设备。

受控 Busy 用非管理、非 datastore uplink 构造，完整对象为：

```text
test BDF -> vmnic2 -> vSwitchBusy -> BusyPG -> vmk1
```

O04 必须对同一 BDF 成对运行：consumer 存在时 apply-now/direct deferred 都失败；删除 `vmk1`、
`BusyPG`、uplink 和 `vSwitchBusy` 后 apply-now 成功。O03/O07 则在 disposable overlay 上发 deferred
请求、保存 reboot 前快照、真实重启 host，再核对 uptime、Configured/Current Owner 和 module。
共享 bridge case 使用 `QEMU_ESXI_TOPOLOGY=legacy`；PCIe different-dependent control 使用
`QEMU_ESXI_TOPOLOGY=pcie`。每次 mutation 后都必须恢复 owner/vSwitch/临时 VM，或直接丢弃 overlay。

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
`use64bitMMIO=TRUE` 的两组通过。旧 8G sparse-ivshmem 样本只到 mapping；当前正式
8G 结论使用下一节的 no-backing endpoint + 独占 Root Port，七项矩阵已得到 guest
heartbeat。32/64G 也使用同一方法，不能继续扩大 ivshmem backing。

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

### 4.4 8/32/64G no-backing BAR gate 与 guest runtime

先做 QEMU direct control：

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/e/Code/PCI/github-export/qemu-pci-testdev-largebar-validate.sh
```

正常关闭 ESXi 后，以独占 Root Port 挂载 `pci-testdev`。下面是已验证的 32G 形态；
8G 把三处值改为 `8G/8G/8192`，64G 改为 `64G/64G/65536`：

```powershell
wsl -d Ubuntu-22.04 -- env `
  QEMU_ESXI_QEMU_BINARY=/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 `
  QEMU_ESXI_IVSHMEM_SIZE=0 `
  QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE=32G `
  QEMU_ESXI_HOST_HOLE64_SIZE=32G `
  QEMU_ESXI_OVMF_MMIO64_MB=32768 `
  QEMU_ESXI_PRIMARY_DEDICATED_ROOT_PORT=1 `
  bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-mf.sh

wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_largebar_matrix.py `
  --qemu-name esxi8-mf --bdf 0000:02:00.0 --bar-size-gb 32 `
  --serial-timeout 180 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

验收要求正例同时满足 EFI heartbeat、guest 目标 VID:DID、IOMMU mapping 和 outer HMP
物理 BAR；只到 `mapping-pass-guest-timeout` 不再算最终通过。失败 case 必须保存
`required pages/limit`。共享 Root Port 是故意保留的 AH 负例；正式正例必须独占
dependency。当前通过地址：8G=`0x1ffe00000000-0x1fffffffffff`、
32G=`0x1ff800000000-0x1fffffffffff`、64G=`0x1ff000000000-0x1fffffffffff`。

## 5. Firmware/layout 与 QEMU 对照矩阵

### 5.1 VMware vHW20 矩阵

VMware 的固件值是 `bios|efi`，不是 SeaBIOS/OVMF；`motherboardLayout=acpi` 表示多个
ACPI host bridge，不是“是否启用 ACPI”。显式四格与直接注册 key-absent controls：

```powershell
.\vmware-esxi8-lab\Test-EsxiFirmwareLayoutMatrix.ps1 `
  -RunId 20260715-layout-replay `
  -BridgePolicy PcieRootPorts `
  -IncludeDefaultControls

# 调用端超时但 serial/vmware.log 已完整时，只重新分析同一批产物
.\vmware-esxi8-lab\Test-EsxiFirmwareLayoutMatrix.ps1 `
  -RunId 20260715-layout-replay `
  -BridgePolicy PcieRootPorts `
  -IncludeDefaultControls `
  -AnalyzeOnly
```

CreateVM API 的 layout field unset 必须与直接注册分开测试；临时 VM 会自动销毁：

```powershell
.\vmware-esxi8-lab\Test-EsxiCreateVmLayoutDefault.ps1 `
  -Firmware Efi -PowerOn -RunId 20260715-create-efi-replay
.\vmware-esxi8-lab\Test-EsxiCreateVmLayoutDefault.ps1 `
  -Firmware Bios -PowerOn -RunId 20260715-create-bios-replay
```

默认 `-ExpectedLayout Auto` 会自断言 EFI/acpi、BIOS/i440bx。测试未知 ESXi/vHW 版本的
实际缺省值时使用 `-ExpectedLayout Observe`，先保留观测结果，再为该版本建立独立 profile。

通过条件：

| Case | 预期 |
|---|---|
| `i440bx+bios` | 单根 `PCI0 [00-7f]`；endpoint/IOMMU/小 BAR 正常；2GiB BAR2 未分配 |
| `i440bx+efi` | 单根；2GiB BAR2 高置 |
| `acpi+efi` | 多根 `PCI0/PC08/PC0G`；2GiB BAR2 高置；保存 effective slot/bridge rewrite |
| `acpi+bios` | power-on 精确失败：`ACPI motherboard layout requires EFI.` |
| CreateVM field unset | EFI 解析为 `acpiHostBridges`；BIOS 解析为 `i440bxHostBridge` |
| 直接注册 key absent | EFI/BIOS 均走 i440bx-like fallback；不能写成 CreateVM 默认 |

完整已执行结果、artifact 索引和产品文档解释见
[`vmware-firmware-layout-matrix.md`](../vmware-firmware-layout-matrix.md)。

### 5.2 QEMU/OVMF high-MMIO 基础矩阵

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

当前 firmware/layout 全矩阵的一键入口：

```powershell
wsl -d Ubuntu-22.04 -- env `
  WORKDIR=/mnt/e/Code/PCI/_artifacts/mmio-tests/qemu-firmware-layout-REPLAY `
  bash /mnt/e/Code/PCI/github-export/qemu-firmware-layout-matrix-validate.sh
```

脚本自动断言 7 个 profile：SeaBIOS+i440fx single/bridge、OVMF+i440fx
single/bridge exact-2G、bridge 4G 正控、OVMF+i440fx+PXB multi-root 和
OVMF+q35+pcie-root-port。结果写入 `results.tsv`。

这些 profile 分别验证固件、资源装箱和拓扑边界，不是一个统一的 VMware 精确替代：
i440fx 保留 legacy chipset 类别但不是 VMware 440BX/PIIX4，PXB 的 bridge identity 不同，
q35 则向 guest 暴露 Q35/ICH9。SeaBIOS 还会把 2GiB BAR 高置，与 VMware
`i440bx+bios` 的 BAR2 未分配结果相反。

## 6. 拓扑、ACS、依赖和链路

### A01：无 ACS 路径

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=1G QEMU_ESXI_DISABLE_ACS=1 bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
.\vmware-esxi8-lab\Wait-EsxiReady.ps1
.\vmware-esxi8-lab\Enable-EsxiTestPassthru.ps1
```

收集 `vmkernel.log` 中 ACS 检查、claim 和 owner 记录。当前环境出现
`enableACSCheckForRP=FALSE`，因此只能证明此嵌套环境绕过了检查，不能推出生产 ESXi 的
隔离安全性。runner 另含 `pcie-virtio-no-acs-strict` 和
`pcie-virtio-no-acs-global-bypass`，分别验证严格 Root Port 检查与 Broadcom KB 391460
公开 `disableACSCheck=TRUE` workaround 的优先关系。

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

通过标准是 efivar first/second phase、reboot 前后各一次 `tx>0`、最终关机解绑。
R00 虚拟 FLR callback 已由 `test_esxi_flr_reset.py` 自动化：Root Complex 直挂 virtio
必须得到 `Function reset`，且 VM power-on/off 两侧都要出现目标 qdev reset trace。

INTx A/B：

```powershell
wsl -d Ubuntu-22.04 -- env PROFILE=intx bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_intx_mode.py --settle-seconds 60 --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- env WORKDIR=/mnt/e/Code/PCI/_artifacts/mmio-tests/qemu-intx-direct-REPLAY bash /mnt/e/Code/PCI/github-export/qemu-intx-direct-validate.sh
```

当前 ESXi nested path 为可重复 functional fail，QEMU direct control 为 pass。必须保留
两边同 ISO 的结果，不能只凭 guest 出现 IO-APIC 行就判 INTx 通过。

EDU MSI-only/DMA/reset A/B：

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/e/Code/PCI/github-export/qemu-edu-direct-validate.sh /mnt/e/Code/PCI/_artifacts/mmio-tests/qemu-edu-direct-REPLAY

# 正常关闭 ESXi，再用 EDU + trace 重启外层 A
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_IVSHMEM_SIZE=0 QEMU_ESXI_EDU=1 QEMU_ESXI_TRACE=1 bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-host-a.sh
wsl -d Ubuntu-22.04 -- env PROFILE=edu bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_edu.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

`PROFILE=edu` 需要与 Guest kernel 完全匹配的 headers；当前为
`linux-headers-5.15.0-185-generic`。通过条件包括两阶段各一次 MSI self-IRQ、两次
DMA-completion IRQ、双向 DMA 比对、Guest IOVA 被 requester `01:01.0` 的 VT-d range
覆盖、四次 DMA 后均有 MSI remap，且无 DMAR fault。reset sentinel 是观察值：必须明确
为 `reset` 或 `persisted`，不能把 `vmware.log` 的 reset 行自动解释成状态已清零。

D01 同 SID/IOVA teardown A/B 使用独占 Root Port、QEMU 11 trace、QTest socket 和本地
VMFS。先正常关闭当前 ESXi，再执行：

```powershell
wsl -d Ubuntu-22.04 -- env QEMU_ESXI_QEMU_BINARY=/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 QEMU_ESXI_IVSHMEM_SIZE=0 QEMU_ESXI_EDU=1 QEMU_ESXI_TRACE=1 QEMU_ESXI_PRIMARY_DEDICATED_ROOT_PORT=1 QEMU_ESXI_QTEST_SOCKET=/root/vm/esxi8-mf/qtest.sock bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/start-qemu-esxi8-mf.sh
wsl -d Ubuntu-22.04 -- env PROFILE=edu bash /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/build-esxi-l3-probe-iso.sh
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_edu.py --vcenter 192.168.91.131 --host 172.31.91.10 --bdf 0000:02:00.0 --qemu-name esxi8-mf --qemu-monitor /root/vm/esxi8-mf/monitor.sock --qemu-trace /root/vm/esxi8-mf/qemu-trace.log --qtest-socket /root/vm/esxi8-mf/qtest.sock --verify-dma-teardown --datastore pci-mmio-local --esxi-local-storage --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

通过条件不是“post-off 必须 fault”。必须同时满足：live DMA 使用 guest domain 且解析
到非恒等 guest backing；power-off 窗口有 context/IOTLB invalidation；post-off 同一
SID/IOVA 不再解析到旧 backing，并被分类为 fault、context absent 或 host-domain
rebound。当前 v5 实测是 domain 2 切到 domain 1 的 host identity rebound。

`passthruCapable` 累计 23 项矩阵：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

该 runner 会逐案切换 IOMMU、FLR/PM/D3hot、Root Complex/PCIe/legacy topology、ACS、
同 endpoint class code，并加入带原生 FLR 的真实 Type-1 X3130 bridge。必须同时检查
`passthruCapable`、`Reset Method`、header/PCIe port type、parent/dependent device 和
restore verdict；专题解释见
[`../vmware-esxi8-passthru-capable-observed-model.md`](../vmware-esxi8-passthru-capable-observed-model.md)。

只复现 class 与真实 bridge gate：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID `
  --cases root-virtio-class-network root-virtio-class-memory `
    root-virtio-class-pentium root-virtio-class-coprocessor `
    root-virtio-class-host-bridge root-virtio-class-pci-bridge `
    pcie-x3130-upstream-flr
```

只复现 ACS policy 三段式 A/B/C：

```powershell
wsl -d Ubuntu-22.04 -- python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_passthru_capability_matrix.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID `
  --cases pcie-virtio-no-acs pcie-virtio-no-acs-strict `
    pcie-virtio-no-acs-global-bypass
```

PME/P2P/RMRR/Option ROM 当前入口：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_pme.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_p2p_matrix.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_rmrr_matrix.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_optionrom.py --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID
```

这些 runner 会重启 outer ESXi 或执行故障注入，必须使用独立 run ID 并保留 restore。
当前结论不是全部“pass”：Option ROM enabled 是已执行但 entry-not-observed 的负例，
P2P default/relax-only 的 IOMMU fault 是预期拒绝；详见主结果报告与 20260714 JSON 摘要。

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

同 BDF 身份替换的黑盒 runner 会在保持 ESXi system disk、host UUID、BDF 和 topology 不变时，
分别替换 MAC/DSN、subsystem 与 device model，并在每个变体后恢复 card-A baseline：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_static_identity_replacement.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID-static-identity
```

该 runner 会重启 outer ESXi、创建/销毁 VM 并改变 synthetic endpoint identity。目前只完成
`py_compile/--help`，尚无 canonical run，`VMW-STATIC-IDENTITY-001` 仍为 `PLANNED`；不能把
runner 存在写成 VMware 已验证行为。

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

完整 candidate set、runtime `assignedId`、multi-requirement all-or-fail、双 VM 并发 task
overlap 和 global matching 判别由下列 runner 预注册：

```powershell
wsl -d Ubuntu-22.04 -- python3 /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_dynamic_solver_behavior.py `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/RUN-ID-dynamic-solver
```

它只根据公开 API、task 时间、binding/assignedId 和候选集合分类外部行为，不命名 VMware
私有 solver 或锁实现。当前脚本仅通过 `py_compile/--help`，还没有 live canonical run；因此
global optimality、双 VM 原子抢占和失败回滚仍保持未验证。

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

M26 AER root-sequence 在上述通用合同上增加以下权威边界：

- raw endpoint/root/ESXi/guest snapshot 必须先于解析和判定落盘；解析失败不能抹去已采集的
  原始安全观察。
- sampler、parser、monitored worker 或 cleanup 任一异常都必须产生 typed
  partial/safety result、触发幂等 safe-stop，并停止后续注入；不得把不完整尾窗包装成 clean PASS。
- continuous sampler 已落盘 raw numeric snapshot、但 gate readback 随后中断时，当前
  `effective` 必须保持未确认，最近一次完整值单独记录为 `lastConfirmedEffective`；只有与该
  raw snapshot 精确绑定的 producer fault 才可进入此分支，并且窗口必须以 paused fail-stop
  收口。用于 current/last-confirmed effective 的样本还必须显式满足 `partial=false`；
  缺失、`null`、`true` 或非布尔标记以及任意伪造/malformed partial 都是 typed failure。
- T0/T1/T4/T5 的路径、采样时间、最大间隔、numeric safety surface 和 stop-tail 必须可从
  manifest-bound artifact 重算；host raw logs 与 guest serial 必须从原始文件重新解析，不能信任
  summary 自报字段。
- 只有 `verify-run` 对 campaign、case、artifact manifest 和 aggregate sidecar 全部
  exact-match 时，聚合 summary 才有权威性。离线 78/78 只验证这个 harness contract，
  不能自行形成 ESXi observation；V17/V19 已满足 exact O0+O4/`g101` 的该门，但不能
  替代 bound native driver、其他 gate、service/IRQ、guest write、lifecycle 或物理
  qualification。

## 11. 推荐执行顺序

1. G0/G1 基线启动与设备识别。
2. 1G/2G 的 M00-M05，并立即跑 QEMU 对照矩阵。
3. A01/A04/A05/A06 拓扑组。
4. D00/I00 trace 流量。
5. L00-L03 和 T00 生命周期。
6. X00-X03 Dynamic DirectPath 与 vMotion。
7. R01/I01；最后才执行 AER injection 与 host crash 等破坏性用例。

不可逆或高风险 Case 应始终在可回滚 ESXi 副本上运行，并把“环境被破坏”与“产品行为失败”分开记录。
