# ESXi 8.0.3 无 IOMMU DirectPath 负控实测

日期：2026-07-18

## 1. 要回答的问题

Qman 宿主允许可信 DPDK 使用 no-IOMMU，但 VM PCI passthrough 仍必须要求 IOMMU。需要一个
VMware 实际环境负控，验证 ESXi 8.0.3 在平台没有可用 DMA remapping 时，是否会因为设备是
网卡、具有 Function/Bridge reset 或 class 看起来可直通而放行。

## 2. 环境与无副作用方法

- 外层：VMware Workstation 17.5.0 build 22583795，virtual hardware 20，EFI。
- 内层：VMware ESXi 8.0.3 build 24280767，平台 `VMware20,1`。
- 安全边界：只运行 vSphere property read、`esxcli ... list/get` 和 vmkernel log grep；没有执行
  `pcipassthru set`、bind/unbind、VM power operation 或 host reboot。
- runner：[`test_esxi_owner_activation.py`](../vmware-esxi8-lab/test_esxi_owner_activation.py)
  的 `snapshot --observe-all` 模式。

复现命令：

```powershell
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' start `
  'E:\vm\vmware\esxi8-auto-codex\esxi8-auto-codex.vmx' nogui
.\vmware-esxi8-lab\Wait-EsxiReady.ps1 `
  -HostName 192.168.91.128 -TimeoutSeconds 420
wsl -e python3 `
  /mnt/e/Code/PCI/github-export/vmware-esxi8-lab/test_esxi_owner_activation.py snapshot `
  --host 192.168.91.128 `
  --output /mnt/e/Code/PCI/_artifacts/vmware-directpath-runs/20260718-workstation-esxi8-noiommu-live-v4 `
  --target 0000:02:00.0 --observe-all `
  --expected-system-uuid c6fc4d56-d087-918d-f012-631536abaf6d
```

地址、UUID 和 VMX 路径是本地实验实例标识；换实例时必须显式改成目标 host 的读回值。

## 3. 实际结果

| 观测 | 结果 |
| --- | --- |
| vSphere `HostPciPassthruInfo` 条目 | 45 |
| `passthruCapable=true` | 0 |
| `passthruEnabled=true` | 0 |
| `passthruActive=true` | 0 |
| ESXCLI PCI block 找不到 | 0 |
| `esxcli hardware pci pcipassthru list` | 成功但为空 |

本次启动的公开日志直接给出平台原因：

```text
WARNING: VTD: 747: ACPI DMAR table not found
DCF is disabled because the IOMMU is not available.
```

三个有区分度的设备如下：

| BDF | 角色/class | ESXi reset | `passthruCapable` |
| --- | --- | --- | --- |
| `0000:00:00.0` | host bridge | None | false |
| `0000:02:00.0` | USB controller | Function reset | false |
| `0000:0b:00.0` | vmxnet3 Ethernet controller | Bridge reset | false |

因此在该 ESXi 8.0.3 平台上，class 是网卡以及存在 Function/Bridge reset 都不足以越过 host
IOMMU gate。这与 QEMU-ESXi virtual VT-d 正样本共同排除了 `class-only` 和 `reset-only`
capable 模型。

## 4. 对 Qman 的结论

1. **VM path**：host IOMMU 不存在时整条 VM passthrough admission hard reject；存在时仍需
   对每个 payload 证明实际 IOMMU backend，不能只读全局开关。
2. **Host DPDK path**：可以保留独立 no-IOMMU provider，但 BDF 必须显式
   `hostReservation=dataplane-dpdk`，永不进入 VM candidate/activation。
3. **Reboot**：IOMMU 缺失属于 hardware capability failure，不是 owner transition；不能返回
   `REBOOT_REQUIRED`。只有已证明 early-boot exact claim 能解决的暂态 owner 冲突才可建议重启。
4. **Reset**：reset contract 是 attach/release 安全门，不替代 role、IOMMU、ACS 或平台保留门。

## 5. 证据与边界

```text
Local artifact:
_artifacts/vmware-directpath-runs/
20260718-workstation-esxi8-noiommu-live-v4/result.json

result.json SHA256:
1b1fa1e740fb084c7513e12e2cc37197fb13a3c088e66e6e61be6ecc956e812d
```

这是 VMware Workstation 虚拟平台上的 ESXi 实际行为，不是物理服务器 qualification。它证明
“DMAR 缺失时 ESXi 全量拒绝”以及 class/reset 不足以越过该门；它不能回答真实 VT-d errata、
ACS/P2P、电气 reset、interrupt remapping 或真实 NIC DPDK PMD 包转发/性能。
