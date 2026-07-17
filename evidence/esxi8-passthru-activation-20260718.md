# ESXi 8.0.3 DirectPath owner activation 证据摘录

日期：2026-07-18

范围：只记录 ESXi 8.0.3 build 24280767 的公开接口和本地黑盒输出，不推导 VMware 私有实现。
本文件是脱敏摘录；机器可读结论见
[`esxi8-passthru-activation-20260718-summary.json`](esxi8-passthru-activation-20260718-summary.json)。

## 1. 原始产物完整性

| 产物 | SHA256 | 用途 |
| --- | --- | --- |
| `20260713-capability-smoke-v5/root-virtio-flr-pm/owner-toggle.txt` | `c62ad74bd660f4e16cc30f21b0b8662ad00a3c069e552f408fea10d0db2cf525` | `--apply-now` owner 切换与立即读回 |
| `20260713-esxi8-flr-vm-power-v1/result.json` | `eaa24b1ff6ba5a621eb937e50794c011e2af80418c7b6ac6f408e63c534b3a23` | owner 切换后的 vSphere API enabled/active |
| `20260711-largebar2g/M00-largebar2g-default/esxi-pci-before.txt` | `aafb68f85accb3554e67652da134315f5ff6db57bb4e8e4bb86415393404dee5` | configured/effective mismatch |
| `20260711-largebar2g/M00b-largebar2g-default-active/esxi-pci-before.txt` | `b6a6c58a07424acf085713c535da5fef2ffb1aac90534bd19bf0a45d39ba3aa8` | 同组设备 active 后的 owner/provider |

原始产物位于授权实验机的 `_artifacts/vmware-directpath-runs/`，未把凭据、管理地址或完整
运行日志提交到公共仓库。

## 2. `--apply-now` 无重启立即生效

本地命令和返回：

```text
$ esxcli hardware pci pcipassthru set -d 0000:00:09.0 -e true -a
exit=0

$ esxcli hardware pci list | sed -n '/0000:00:09.0/,/^$/p'
exit=0
0000:00:09.0
   Vendor Name: Red Hat, Inc.
   Device Name: Virtio 1.0 network device
   Configured Owner: VM Passthru
   Current Owner: VM Passthru
   Module Name: pciPassthru
   Passthru Capable: true
   Dependent Device Address: 0000:00:09.0
   Reset Method: Function reset
```

命令与读回之间没有 host reboot。随后同一运行的 vSphere API 摘录为：

```json
{
  "capability": {
    "passthruCapable": "true",
    "configuredOwner": "VM Passthru",
    "currentOwner": "VM Passthru",
    "resetMethod": "Function reset"
  },
  "vSpherePassthruInfo": {
    "enabled": true,
    "active": true,
    "capable": true
  }
}
```

这直接否定“`passthruActive=true` 必须有一次真实 host reboot history”。可观察提交条件是
effective owner/provider 已匹配，不是是否重启过。

## 3. Configured 与 Current 可以分离

启用列表已经为 true 时，`M00-largebar2g-default` 的成员仍可处于：

```text
0000:01:00.0
   Configured Owner: VM Passthru
   Current Owner: VMkernel
   Module Name: ne1000
   Passthru Capable: true
   Dependent Device Address: 0000:00:08.0
   Reset Method: Bridge reset

0000:01:00.1
   Configured Owner: VM Passthru
   Current Owner: VMkernel
   Module Name: ne1000
   Passthru Capable: true
   Dependent Device Address: 0000:01:00.1
   Reset Method: Bridge reset
```

对应 active 样本 `M00b-largebar2g-default-active` 的同组成员为：

```text
0000:01:00.0
   Configured Owner: VM Passthru
   Current Owner: VM Passthru
   Module Name: pciPassthru

0000:01:00.1
   Configured Owner: VM Passthru
   Current Owner: VM Passthru
   Module Name: pciPassthru
```

因此 `Enabled/Configured` 只能表示 desired state，不能替代 `Active/Current/Module` 读回。

## 4. 重启边界的公开合同

- [ESXCLI 8.0.3](https://developer.broadcom.com/xapis/esxcli-command-reference/8.0.3/namespace/esxcli_hardware.html)
  明确说明 `--apply-now` 立即在 native driver 与 passthrough driver 间重绑；不带该参数则在
  host reboot 后应用。
- [HostPciPassthruInfo](https://developer.broadcom.com/xapis/vsphere-web-services-api/8.0U3/vim.host.PciPassthruInfo.html)
  分开暴露 `passthruEnabled`、`passthruActive` 与 `dependentDevice`。
- [Broadcom KB 309986](https://knowledge.broadcom.com/external/article/309986/configuring-vmdirectpath-io-passthrough.html)
  将绿色描述为 enabled+active，将橙色描述为状态已改变但需要重启。
- [Broadcom KB 434815](https://knowledge.broadcom.com/external/article/434815/hba-adapter-hba355i-registers-as-storage.html)
  记录 active storage paths 令 native HBA driver detach 返回 Busy，立即切换失败而配置可在
  reboot 后应用。

合并这些证据后，重启是 owner transition 的执行路径，不是 FLR、class code 或 BAR 的静态
属性。只有 exact early-boot claim 能在 native consumer 之前接管完整 dependency bundle 时，
Qman 才能返回 `REBOOT_REQUIRED`；capability/policy、stale identity、host-critical、foreign lease
和 incomplete dependency 必须返回 `DENIED`。

## 5. 仍未本地闭合的负例

当前 nested lab 尚未专门制造一个受控 native-driver Busy，并采集同一 BDF 在 `--apply-now`
前后的完整失败输出；O04 的 Busy 机制来自 Broadcom 公开 HBA 案例。真实 storage/network
consumer、boot ordering 和 vendor recovery 也仍需物理 host qualification。文档和实现不得把
这些项目标成 local pass。
