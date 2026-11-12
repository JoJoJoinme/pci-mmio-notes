# PCIe 多功能设备依赖的成功对照

2026-11-11，在 ESXi 8.0.3 build-24280767 的合成 PCIe 多功能设备场景中，已经建立完整成功对照：**两个 Function 放在同一台 VM 可以开机；分别配置到两台 VM 后，第二台开机失败；交换启动顺序结果相同。只启用或禁用其中一项，主机都会共同切换两项。**

这里包含两项作用不同的改变：移除传统桥、改为直接位于 PCIe root port 下后，同 VM 双设备已经能够开机；再为第二个 Function 补上 `multifunction=on`，才使本例 ESXi 把两项识别为共同依赖，得到跨 VM 第二台启动失败的对照。不能把多功能标记单独写成“同 VM 开机成功”的原因。移除试验性 `passthru.map` 规则并重启后，最终矩阵仍然成立。

2026-11-12 补充：[传统桥下为什么同 VM 双设备仍失败](../vmware-legacy-bridge-cause-20261112/README.md)。新实验在保留传统桥并补齐两个多功能标记后仍复现失败，并直接采集了 VT-d context 的整体切换和回退。

这是新的 PCIe 成功对照。[此前传统 PCI 桥场景](../vmware-dependency-ui-20261111/README.md)的共享 requester ID / IOMMU 域检查失败仍保留为历史结果，未宣称已修复该传统桥场景，也没有修改 ESXi 二进制或关闭 IOMMU/ACS 检查。

## 单变量比较

| 条件 | Function 0 / 1 的 Header Type | 依赖信息 | 同 VM A+B | A、B 分别放两台 VM |
| --- | --- | --- | --- | --- |
| PCIe 原始描述 | `0x80 / 0x00` | A → root port；B → 自身 | 成功，包括反序 | 两种启动顺序均可同时开机 |
| 为 Function 1 加 multifunction 标志，保留试验规则 | `0x80 / 0x80` | 两者 → `0000:00:08.0` | 成功，包括反序 | 第一台成功，第二台失败；反向相同 |
| 保留标志修正，移除试验规则并重启 | `0x80 / 0x80` | 两者 → `0000:00:08.0` | 成功，包括反序 | 第一台成功，第二台失败；反向相同 |

A=`0000:01:00.0`，B=`0000:01:00.1`，设备模型为 e1000e，VID:DID=`8086:10d3`，复位方法均为 Bridge reset。两项在 PCIe root port 下，没有旧场景中的 PCIe-to-PCI bridge。VM 为静态 `DeviceBackingInfo`，1 vCPU、768 MiB、EFI、vmx-20、全额内存预留。

对应 [原始描述矩阵](raw/pcie-baseline-results.json)、[标志修正后矩阵](raw/mf-header-matrix-results.json)、[移除规则后的矩阵](raw/native-mf-matrix-results.json)。原始配置空间的偏移 14 保存在 [修正前](raw/before-header-fix-config-space.txt)和[修正后](raw/after-header-fix-config-space.txt)，硬件描述变更记录见 [mf-header-change.json](raw/mf-header-change.json)。

单个设备的先发 VM 能启动，并不表示依赖组中的所有 Function 都已作为 guest PCI device 暴露。这里证明的是同组资源不能同时交给两个 VM 运行；没有观测到“单项配置必然在保存前被拒绝”。

## 主机模式联动

[单项切换回执](raw/native-mf-owner-results.json)分别记录只请求 A、只请求 B 的启用和禁用，各次都从明确的双设备基线开始。四项操作都成功，最终两项 enabled/active 一致。没有注入中途故障，也没有连续采集调用内部状态，因此不证明主机切换事务的原子性。

本轮 Host Client 中点击 A 自动联选 B，提交后两者 Active；双设备 VM 的 UI 开机任务也成功。对应 [联选页面](screenshots/host-01-select-a.jpg)、[启用结果](screenshots/host-02-enabled.jpg)、[双设备开机页面](screenshots/host-04-both-after-power.jpg)及 [API/任务读回](raw/ui-host-both-on.json)。任务时间区分这次 UI 开机和之前 API 运行的成功任务。

## 依赖规则排查的边界

实验曾写入 `8086 10d3 default false`。该 VID:DID 还匹配管理网卡，因此修改前验证了管理网卡原本即不可直通、owner 为 VMkernel、FPT 标志为 false；未对管理网卡发出直通切换请求。相关守卫见 [记录](raw/functional-policy-management-guard.json)。最终已移除该新增规则，[后续读回](raw/native-mf-policy-final.json)确认没有匹配行，测试 Function 的底层 shareable 值恢复为 `1`。

排查期间，启动日志中的 `Restoring passthru map attributes ... Not supported` 不能直接当作“该拓扑不支持依赖声明”的证明。Broadcom 说明启动插件会对非直通设备调用仅适用于直通设备的 LoadConfig，此时可能出现该日志。[KB 389756](https://knowledge.broadcom.com/external/article/389756)

不同读回渠道也不一致：在试验规则存在时，Function 0 的 VSI `fptShareable` 已是 `0`，ESXCLI 仍报告 true；Function 1 未设置 multifunction 位时，其 VSI 值仍为 `1`。因此部分早期 `*-verified.json` 的 `valid=false` 表示未通过当时采用的 ESXCLI 判据，不能替代最后的状态与行为对照。最终无额外规则的结论由规则移除记录、VSI 读回、共同依赖信息和开机矩阵共同支持。

总线级复位相关 Function 应共同分配给同一 VM，这是官方要求；本报告的成功与失败是限定环境中的实测结果。[KB 312208](https://knowledge.broadcom.com/external/article/312208)

## 环境与资源差异

实验链为 Windows → WSL2 → QEMU/KVM → ESXi → 空 EFI VM。初始 API 矩阵和 Host Client UI 验证使用外层 4 vCPU / 8192 MiB。与 14 GiB VCSA 同时运行时，Windows 可用物理内存降到约 400 MiB，浏览器与 SSH 操作超时；这些超时未计为 PCI 拦截。

为继续界面验证，正常关闭实验实例后将外层 ESXi 改为 6144 MiB，并重跑完整矩阵：[6 GiB 矩阵](raw/ui6-matrix-results.json)仍为同 VM 成功、跨 VM 第二台失败。此资源调整见 [记录](raw/ui-memory-adjustment.json)，两阶段 QEMU 参数分别保存在 [8 GiB](raw/mf-header-runtime.json)和 [6 GiB](raw/resume-runtime.json)。6 GiB 是本次资源受限的嵌套实验配置，不构成受支持的服务器规格结论。

vCenter 本次界面复验受许可证过期阻挡。恢复登录与管理服务后，首次重连因许可证服务未运行而失败；启动该服务并确认 HEALTHY 后，第二次重连明确返回 `vmodl.fault.NotEnoughLicenses`：vCenter 的 Evaluation Mode 已过期。对应 [首次失败](raw/vc-reconnect-license-failure.json)、[服务恢复](log-excerpts/vcenter-license-service-health.txt)、[最终重连 task-7110](raw/vc-reconnect.json)及[不含密钥的许可证元数据](raw/vc-license-metadata.json)。最终错误同时出现在 vCenter 的 Recent Tasks 界面；现有许可证清单没有可用的正式许可证。

因此，本轮有效的界面开机证据来自 Host Client；没有把旧场景的 vCenter 截图、管理服务恢复或重连失败当作本次 PCI 行为的验证。继续本轮 vCenter UI 复验需要有效的 vCenter 许可及成功连接的实验主机。

为恢复管理环境，保留冷启动故障状态快照后恢复既有检查点，恢复 IPv6 loopback，并将 SPS 启动宽限时间由 600 秒调至 900 秒。这些属于管理环境恢复，与 PCI 修正分开记录，见[恢复说明](raw/environment-recovery.json)和[检查点回执](raw/vcsa-checkpoint-recovery.json)。

结束时四台测试 VM 均为 poweredOff、A/B 直通均 disabled/inactive；测试 VM 配置保留在实验覆盖盘中。删除测试 VM 的尝试返回 InvalidState，因此未把删除动作记为成功。ESXi 正常关机、VCSA 挂起保留恢复状态，专用隧道、端口转发和临时路由已撤除；Windows 的临时 WSL 内存限制已恢复原文件。基础镜像哈希未变。对应[保留状态](raw/final-preserved-state.json)、[网络与镜像校验](raw/final-network-cleanup.json)、[Windows 收尾](raw/final-windows-cleanup.json)和[WSL 配置恢复](raw/wsl-cap-restored.json)。

## 复现和核验

仓库启动器新增可选参数：

```console
QEMU_ESXI_TOPOLOGY=pcie
QEMU_ESXI_TEST_FN0_MODEL=e1000e
QEMU_ESXI_TEST_FN1_MODEL=e1000e
QEMU_ESXI_TEST_FN1_MULTIFUNCTION=1
```

启动器原本已对 Function 0 指定 `multifunction=on`；新参数让 Function 1 也设置该位。默认行为保持原样，避免改变其他既有实验。

[脚本快照](source-snapshots/README.md)记录最终采集辅助代码及使用条件。实验 VM 必须保持专用且可丢弃，先核对 host UUID/build、PCI ID、依赖、所有者和存储，再按“同 VM、反序、分拆两个启动顺序”执行。不能仅凭两个设备同槽、FPT 显示值或一次接口成功认定具备独立使用能力。

公开包提供 [逐文件 SHA-256 和来源映射](manifest.json)及[机器摘要](summary.json)；日志为保留行号及原文件哈希的摘录。没有分发凭据、虚拟磁盘、安装介质或完整宿主机日志。离线校验方式：

```console
python evidence/vmware-pci-multifunction-fix-20261111/verify_bundle.py
```

本轮只验证配置、所有权和开机行为，没有运行 guest OS 的真实设备 I/O，也没有验证实际硬件的隔离与复位质量。
