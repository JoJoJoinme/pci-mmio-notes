# ACS override provenance kernel patch

本目录解决一个明确约束：host 必须长期启用 `pcie_acs_override`，但平台不能把补丁拆出的
IOMMU group 当成真实硬件隔离证明。

[`0001-PCI-expose-ACS-override-provenance.patch`](0001-PCI-expose-ACS-override-provenance.patch)
基于 `linux-msft-wsl-6.6.123.2`，把 ACS 判定拆成两层：

- `pci_acs_native_enabled()`：标准 ACS、PCIe 天然拓扑规则和上游认可的 device quirk；不含
  强制 override。
- `pci_acs_enabled()`：先接受 native verdict，native 不满足时才应用
  `pcie_acs_override`。

每个 PCI function 导出三个只读 sysfs 属性：

```text
/sys/bus/pci/devices/BDF/acs_native_isolation
/sys/bus/pci/devices/BDF/acs_effective_isolation
/sys/bus/pci/devices/BDF/acs_override_source
```

`acs_override_source` 为 `none`、`id`、`downstream` 或 `multifunction`。当 native 已经满足
IOMMU 所需的 `SV|RR|CR|UF` 时，即使命令行规则能匹配，该值仍为 `none`；因此它表示本次
effective verdict 是否真正依赖 override，而不只是“全机打开过该参数”。

该补丁包含 `pcie_acs_override` 参数实现本身，是常见社区补丁的带 provenance 替代版。
已经合入同名 override 实现的 kernel tree 不应直接叠加；应先替换旧补丁，或仅移植本补丁中
native/effective/source 接口及相应调用拆分，避免重复注册 `early_param`。

## 自动构建

```bash
bash kernel-patches/build-acs-provenance-wsl-kernel.sh
```

默认读取 `/root/src/WSL2-Linux-Kernel-6.6`，在新的 detached worktree 中应用补丁，并把
`bzImage`、commit、config hash 和 image hash 写入
`/mnt/e/Code/PCI/_artifacts/acs-provenance-kernel/`。可用环境变量覆盖：

```text
KERNEL_SOURCE
KERNEL_WORKTREE
KERNEL_OUTPUT
KERNEL_JOBS
KERNEL_RESUME
KERNEL_COMMITTER_NAME
KERNEL_COMMITTER_EMAIL
```

脚本不会替换正在运行的 WSL kernel，也不会删除已有 worktree。构建中断后，对同一路径设置
`KERNEL_RESUME=1` 会续跑已有对象；默认仍拒绝复用目录。构建完成后再把 Windows
`%UserProfile%\.wslconfig` 的 `[wsl2] kernel=` 指向生成的 `bzImage`，并在
`kernelCommandLine=` 中保留实际需要的
`pcie_acs_override=downstream,multifunction`。这一步需要重启 WSL，故不放进构建脚本。

## 与 capable 模型的关系

`pci-resource-model scan` 同时保留：

```text
kernelIommuGroup          # override 后的 VFIO 操作单位
physicalIsolationDomain  # 依据 native verdict 和真实父拓扑保守重建
```

重建会把最高的 non-isolating native 节点以下 function 合并，并继续闭包 patched group 和
multifunction aliases。capable 默认允许 mandatory override，但必须满足：

1. 三个 sysfs provenance 属性在全量 inventory 中均存在且自洽。
2. `physicalIsolationDomain` 包含目标和全部依赖。
3. 整个 physical domain 可由同一 owner 原子租用。

缺少定制内核接口时不会退回“相信 patched group”，而是保持
`PHYSICAL_ISOLATION_DOMAIN_UNKNOWN`。该模型有意偏向过度合并；误合并只会造成拒绝，不会把
未知 P2P 路径误报为安全隔离。

## 已完成验证

- `scripts/checkpatch.pl --strict`：0 error、0 warning、0 check。
- 补丁对 `linux-msft-wsl-6.6.123.2` 基线执行 `git apply --check`：通过。
- 使用仓库现有 WSL `.config` 完整构建 `bzImage`：
  `Kernel: arch/x86/boot/bzImage is ready (#1)`。
- 最终镜像大小 `16617472` bytes，SHA-256 为
  `368ce6851bd056bc0c205611b9052a0cf966f188f8b4a5eb2a9b5d584bb9055c`。
- Python 侧在 Windows 和 WSL 各通过 46 项测试，包含 override root-port、native-only
  path、provenance 缺失和整域租用案例。

完整构建不等于运行时验收。当前 WSL 尚未切换到该镜像；真实 host 仍必须在启动新 kernel
后核对 sysfs、IOMMU group、PCI 父拓扑、预期租约域和 P2P DMA 边界。
