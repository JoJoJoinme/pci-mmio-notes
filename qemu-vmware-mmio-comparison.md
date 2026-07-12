# QEMU/OVMF/SeaBIOS PCI 64-bit MMIO 对比测试与结论

日期：2026-07-09

> 2026-07-11 运行时更新：本文最初把普通 EFI VMX 中“没有显式
> `use64bitMMIO`”推导成了 DirectPath guest 默认不自动建立高窗。新的
> ESXi 8.0 U3 active-passthrough 实验推翻了这个推导：1GB 64-bit BAR 默认
> 低置，2GB BAR 即使显式 `use64bitMMIO=FALSE` 也会自动获得 2GB 高窗。
> 完整证据见 `vmware-esxi8-directpath-local-results.md`。下文的 QEMU knob
> 单项行为仍有效，但固定的 `both_zero = VMware default` 映射已被取代。

本文记录本目录中围绕 QEMU、OVMF、SeaBIOS 与 VMware EFI 默认 PCI MMIO 行为的对比测试。重点不是证明某个单独 BAR 是否能启动，而是确定：如果要模拟 VMware EFI 默认 VM 的 PCI MMIO 语义，QEMU 参数应该如何设置。

## 原始结论与修正

### 1. VMware EFI 默认行为的目标语义

active DirectPath 实测后，“像 VMware EFI 默认 VM”应理解为按需求分支，而不是固定
关闭或固定打开高窗：

```text
1GB BAR：缺省 key，低置到 0x80000000-0xbfffffff，无高窗。
2GB BAR：缺省或 FALSE，自动得到最小 2GB 高窗。
4GB BAR：缺省与 Size4-only 因默认 mapping-page limit 失败；TRUE-only 即通过。
```

所以它既不应被理解为：

```text
缺省固定给 guest 一个 4GB above-4G window。
```

也不应被理解为：

```text
缺省绝不允许 above-4G BAR。
```

默认 EFI VMX 确实没有两个 64-bit MMIO key，但“配置缺省”不能推出“运行时无高窗”。
QEMU 对标必须先选 candidate、按每个 BAR 的自然对齐和 bridge packing 试算低端布局，
再选择 below-4G 或计算后的 high profile。`both_zero` 只代表第一条分支。

### 2. OVMF 推荐参数

如果固件是 OVMF，并且目标仅是“强制不发布 high aperture”的 QEMU profile：

```bash
# i440fx
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global i440FX-pcihost.pci-hole64-size=0
```

```bash
# q35
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global q35-pcihost.pci-hole64-size=0
```

两个参数都需要：

- `X-PciMmio64Mb=0`：关闭 OVMF firmware-stage 的 64-bit PCI host aperture。
- `pci-hole64-size=0`：关闭 QEMU host bridge / ACPI 层默认扩出的 high PCI MMIO aperture。

只配其中一个都不等价：

- 只配 `X-PciMmio64Mb=0`，QEMU ACPI 仍可能暴露默认 high window。
- 只配 `pci-hole64-size=0`，OVMF 仍可能在 firmware 阶段把小 64-bit BAR 放到 4G 以上，QEMU ACPI 会报告覆盖实际 BAR 的最小 high window。

如果目标是显式配置 4GB 64-bit aperture，可以使用：

```bash
# i440fx + OVMF, explicit 4GB high MMIO aperture
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
-global i440FX-pcihost.pci-hole64-size=4G
```

```bash
# q35 + OVMF, explicit 4GB high MMIO aperture
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
-global q35-pcihost.pci-hole64-size=4G
```

### 3. SeaBIOS 推荐参数

SeaBIOS 不使用 OVMF 的 `X-PciMmio64Mb` fw_cfg knob。因此 SeaBIOS 下不要用它表达 PCI MMIO 策略。

如果固件是 SeaBIOS，并且目标是“不预留默认 high MMIO aperture”：

```bash
# i440fx + SeaBIOS
-global i440FX-pcihost.pci-hole64-size=0
```

```bash
# q35 + SeaBIOS
-global q35-pcihost.pci-hole64-size=0
```

注意 SeaBIOS 的行为和 OVMF 不完全一样：即使 `pci-hole64-size=0`，如果 SeaBIOS 已经把某个 64-bit BAR 分配到 4G 以上，QEMU/ACPI 仍会向 Linux 报告一个覆盖实际 BAR 的最小 high window。这代表“不预留默认 aperture”，不代表“禁止所有 above-4G BAR”。

如果 SeaBIOS 下要显式给 4GB high window：

```bash
# i440fx + SeaBIOS
-global i440FX-pcihost.pci-hole64-size=4G
```

```bash
# q35 + SeaBIOS
-global q35-pcihost.pci-hole64-size=4G
```

## 测试环境

测试在 WSL Ubuntu-22.04 中执行：

```text
QEMU emulator version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.30)
/dev/kvm=yes
OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS.fd
```

Guest 使用 Ubuntu Noble cloud image，真实启动链路为：

```text
QEMU -> OVMF pflash 或 SeaBIOS -> Ubuntu cloud image -> Linux 6.8 guest
```

不是 `-kernel/-initrd` 直接启动。直接启动 Linux 不会经过 OVMF/SeaBIOS 的 PCI firmware allocation 路径，不能用于判断 firmware-stage PCI aperture 行为。

测试脚本：

```text
qemu-ovmf-real-linux-validate.sh
```

主要日志目录：

```text
_artifacts/mmio-tests/
```

脚本支持：

- `FIRMWARE=ovmf`：使用 OVMF pflash。
- `FIRMWARE=seabios`：不加载 OVMF pflash，使用 QEMU 默认 SeaBIOS。
- `NO_IVSHMEM=0`：挂一个可控 64-bit BAR 探针。
- `NO_IVSHMEM=1`：不挂探针，用来观察是否存在“默认预留”的 high window。

## 如何验证

### 1. Guest 侧观察点

核心判断依据是 Linux dmesg 中 root bus resource：

```text
pci_bus 0000:00: root bus resource [mem 0x...-0x... window]
```

这个字段表示 guest OS 最终从 ACPI/root bridge 看到的 PCI MMIO window。它比 QEMU HMP `info pci` 更接近 guest 实际行为，因为 Linux 已经读取并接受了 ACPI `_CRS`/host bridge resource。

### 2. 64-bit BAR 探针

使用 ivshmem 设备制造一个确定的 64-bit prefetchable BAR：

```bash
-object memory-backend-memfd,id=shm,size=1G,share=on
-device ivshmem-plain,memdev=shm
```

guest 中通过 sysfs 查看它的 BAR：

```text
BAR/resource2  0x... 0x... 0x...
```

这个探针的作用是：

- 让固件和 OS 有一个明确的 64-bit BAR 可分配。
- 观察 BAR 是否落到 above-4G。
- 观察 ACPI root bus window 是否只覆盖实际 BAR，还是额外预留固定大小 aperture。

### 3. 为什么还需要 `NO_IVSHMEM=1`

只看带大 BAR 的测试容易误判。因为 QEMU 的 `pci-hole64-size` 不是绝对上限，而是“在实际 64-bit BAR range 基础上至少扩到多大”。如果固件已经分配了 64-bit BAR，QEMU/ACPI 可能会报告一个覆盖实际 BAR 的 high window，即使 `pci-hole64-size=0`。

因此必须同时跑：

- 带 `ivshmem` 的测试：观察实际 64-bit BAR 分配。
- 不带 `ivshmem` 的测试：观察是否存在默认预留 high aperture。

这两个组合才能区分：

```text
没有默认 high aperture
```

和：

```text
有实际 64-bit BAR，因此 ACPI 报告了最小覆盖范围
```

## OVMF 测试结果

### OVMF + i440fx + 1G BAR 探针

日志目录：

```text
_artifacts/mmio-tests/i440fx-1g-core/
```

| Case | QEMU/OVMF 参数 | Linux high window | ivshmem BAR2 | 结论 |
|---|---|---:|---:|---|
| default | 无额外 MMIO 参数 | `0x800000000-0x87fffffff`，2G | `0x800000000-0x83fffffff` | QEMU i440fx 默认会暴露 2G high window，不像 VMware 的 1GB 低置分支 |
| fwcfg_4g only | `X-PciMmio64Mb=4096` | `0x200000000-0x27fffffff`，2G | `0x200000000-0x23fffffff` | OVMF 位置变化，但 OS-visible size 仍是 QEMU 默认 2G |
| host_4g only | `i440FX-pcihost.pci-hole64-size=4G` | `0x800000000-0x8ffffffff`，4G | `0x800000000-0x83fffffff` | OS-visible window 变 4G，但 OVMF firmware aperture 未同步 |
| both_4g | `X-PciMmio64Mb=4096` + `pci-hole64-size=4G` | `0x200000000-0x2ffffffff`，4G | `0x200000000-0x23fffffff` | firmware 与 OS-visible window 同步为 4G |
| both_zero | `X-PciMmio64Mb=0` + `pci-hole64-size=0` | 无结果，timeout | 无 | 1G 64-bit BAR 探针下无法完成 guest report，是关闭 high aperture 的负例 |

关键解释：

- `X-PciMmio64Mb=4096` 单独不能让 Linux high window 变成 4G；它影响 OVMF 固件阶段的 aperture 选择和 BAR 放置位置。
- `pci-hole64-size=4G` 单独能让 Linux 看到 4G high window；它影响 QEMU host bridge / ACPI 暴露给 OS 的 window size。
- 如果要模拟“显式 4G high MMIO aperture”，两个都要配。
- 如果要构造 VMware 1GB 样本对应的 below-4G 分支，应从 `0/0` profile 开始做完整布局冷启动验证，而不是使用 `4096/4G`。

### OVMF + i440fx + 无 BAR 探针

日志目录：

```text
_artifacts/mmio-tests/i440fx-zero-no-ivshmem/
```

| Case | 参数 | Linux high window | 结论 |
|---|---|---:|---|
| default | 无额外 MMIO 参数 | `0x800000000-0x87fffffff`，2G | QEMU 默认仍预留 high aperture |
| fwcfg_zero only | `X-PciMmio64Mb=0` | `0x140000000-0x1bfffffff`，2G | 只关 OVMF 不够，QEMU ACPI 仍扩出默认 2G |
| host_zero only | `pci-hole64-size=0` | `0x800000000-0x80000bfff`，最小实际范围 | OVMF 仍可能分配小 64-bit BAR，ACPI 覆盖实际范围 |
| both_zero | `X-PciMmio64Mb=0` + `pci-hole64-size=0` | 无 above-4G window | OVMF 下“不预留 high aperture”的隔离控制，不代表完整 VMware 默认策略 |

`both_zero` 下 Linux 只看到低地址 PCI windows：

```text
root bus resource [mem 0x000a0000-0x000bffff window]
root bus resource [mem 0xc0000000-0xfebfffff window]
```

没有 above-4G `root bus resource [mem 0x... window]`。

### OVMF + q35

日志目录：

```text
_artifacts/mmio-tests/q35-1g-core/
```

| Case | 参数 | Linux high window | 结论 |
|---|---|---:|---|
| default | 无额外 MMIO 参数 | `0x800000000-0xfffffffff`，32G | q35 默认比 i440fx 更大，默认是 32G |
| both_4g | `X-PciMmio64Mb=4096` + `q35-pcihost.pci-hole64-size=4G` | `0x200000000-0x2ffffffff`，4G | 显式 4G high aperture 生效 |

q35 默认不是 VMware 默认模型，因为默认直接暴露 32G high aperture。

## SeaBIOS 测试结果

SeaBIOS 不读取 OVMF 的：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,...
```

所以 SeaBIOS 下有效控制面只有 QEMU host bridge property。

测试日志里 case 名仍然叫 `ovmf_*`，这是脚本复用 case 名称；在 `FIRMWARE=seabios` 下它们代表相同 QEMU 参数组合，不代表实际加载了 OVMF。

### SeaBIOS + i440fx + 1G BAR 探针

日志目录：

```text
_artifacts/mmio-tests/seabios-i440fx-1g-core/
```

| Case | 参数 | Linux high window | ivshmem BAR2 | 结论 |
|---|---|---:|---:|---|
| default | 无额外 MMIO 参数 | `0x140000000-0x1bfffffff`，2G | `0x140000000-0x17fffffff` | SeaBIOS + i440fx 默认也有 2G high window |
| fwcfg_zero | `X-PciMmio64Mb=0` | `0x140000000-0x1bfffffff`，2G | `0x140000000-0x17fffffff` | fw_cfg 对 SeaBIOS 无效 |
| fwcfg_4g | `X-PciMmio64Mb=4096` | `0x140000000-0x1bfffffff`，2G | `0x140000000-0x17fffffff` | fw_cfg 对 SeaBIOS 无效 |
| host_4g | `i440FX-pcihost.pci-hole64-size=4G` | `0x140000000-0x23fffffff`，4G | `0x140000000-0x17fffffff` | host bridge property 生效 |
| host_zero | `i440FX-pcihost.pci-hole64-size=0` | `0x140000000-0x18000bfff`，最小实际范围 | `0x140000000-0x17fffffff` | 不预留默认 aperture，但覆盖 SeaBIOS 已分配 BAR |

### SeaBIOS + i440fx + 无 BAR 探针

日志目录：

```text
_artifacts/mmio-tests/seabios-i440fx-no-ivshmem/
```

| Case | 参数 | Linux high window | 结论 |
|---|---|---:|---|
| default | 无额外 MMIO 参数 | `0x140000000-0x1bfffffff`，2G | QEMU 默认预留 high aperture |
| host_4g | `i440FX-pcihost.pci-hole64-size=4G` | `0x140000000-0x23fffffff`，4G | 显式 4G 生效 |
| host_zero | `i440FX-pcihost.pci-hole64-size=0` | 无 above-4G window | 不挂 64-bit BAR 时，host_zero 不预留 high aperture |

这组是 SeaBIOS 下最关键的隔离测试：没有 64-bit BAR 探针时，`pci-hole64-size=0` 确实取消了默认 high window。

### SeaBIOS + q35 + 1G BAR 探针

日志目录：

```text
_artifacts/mmio-tests/seabios-q35-1g-core/
```

| Case | 参数 | Linux high window | ivshmem BAR2 | 结论 |
|---|---|---:|---:|---|
| default | 无额外 MMIO 参数 | `0x180000000-0x97fffffff`，32G | `0x180000000-0x1bfffffff` | q35 默认 32G |
| host_4g | `q35-pcihost.pci-hole64-size=4G` | `0x180000000-0x27fffffff`，4G | `0x180000000-0x1bfffffff` | 显式 4G 生效 |
| host_zero | `q35-pcihost.pci-hole64-size=0` | `0x180000000-0x1c000bfff`，最小实际范围 | `0x180000000-0x1bfffffff` | 不预留默认 aperture，但覆盖 SeaBIOS 已分配 BAR |

## `pci=realloc` 不是本问题的控制面

额外测试目录：

```text
_artifacts/mmio-tests/i440fx-realloc-1g/
```

脚本通过修改 grub 让 guest 第二次启动带上：

```text
pci=realloc
```

观察到 root bus high window 不因 `pci=realloc` 从 2G 变 4G：

- default 仍是 `0x800000000-0x87fffffff`。
- both_4g 仍是 `0x200000000-0x2ffffffff`。

因此 `pci=realloc` 不是“生成 VMware-like high MMIO 默认行为”的参数。它只影响 Linux PCI resource 重新分配策略，不能替代 firmware / QEMU host bridge aperture 配置。

## 原理分析

### 1. OVMF 的 `X-PciMmio64Mb`

OVMF 源码位置：

```text
_src/edk2/OvmfPkg/Library/PlatformInitLib/MemDetect.c
```

关键行为：

- OVMF 解析 `opt/ovmf/X-PciMmio64Mb`。
- 成功解析后设置 `PcdPciMmio64Size = FwCfgPciMmio64Mb << 20`。
- 设置 `PcdPciMmio64Override = TRUE`。
- 如果 size 为 0，OVMF 打印语义是 disabling 64-bit PCI host aperture，并返回。
- 如果 size 非 0，OVMF 会按 1GB 对齐，并按 aperture size 自然对齐 base。

因此：

```text
X-PciMmio64Mb=0
```

是关闭 OVMF firmware-stage 64-bit PCI aperture，不是“auto 4G”。

```text
X-PciMmio64Mb=4096
```

是让 OVMF firmware-stage aperture size 为 4096MB，即 4GB。

但它只管 OVMF firmware 阶段；Linux 最终看到的 ACPI root bus window 还取决于 QEMU host bridge。

### 2. QEMU `pci-hole64-size`

QEMU i440fx 源码位置：

```text
_src/qemu/hw/pci-host/i440fx.c
```

关键点：

- i440fx 默认 `I440FX_PCI_HOST_HOLE64_SIZE_DEFAULT = 1ULL << 31`，即 2G。
- 属性名是 `i440FX-pcihost.pci-hole64-size`。
- hole64 start 来自当前 PCI bus 上已分配的 64-bit BAR range；如果没有实际 range，则退回 `pc_pci_hole64_start()`。
- hole64 end 取实际 64-bit BAR range 的 end，并在需要时扩到 `start + pci_hole64_size`。

q35 源码位置：

```text
_src/qemu/hw/pci-host/q35.c
```

关键点：

- q35 默认 `Q35_PCI_HOST_HOLE64_SIZE_DEFAULT = 1ULL << 35`，即 32G。
- 属性名是 `q35-pcihost.pci-hole64-size`。
- start/end 逻辑和 i440fx 同类。

因此 `pci-hole64-size` 不是绝对上限，也不是“禁止 above-4G BAR”的开关。它更准确地说是：

```text
在 firmware 已分配 64-bit BAR range 的基础上，QEMU/ACPI 至少向 OS 暴露多大的 high PCI window。
```

当它为 0 时：

- 如果没有任何 64-bit BAR range，Linux 不会看到默认 high window。
- 如果 firmware 已经分配了 64-bit BAR range，Linux 仍可能看到覆盖实际 BAR 的最小 high window。

这正是 SeaBIOS `host_zero + 1G BAR` 和 OVMF `host_zero only` 测试会出现最小 high window 的原因。

### 3. SeaBIOS 与 OVMF 的关键差异

OVMF 有自己的 `X-PciMmio64Mb` knob，能控制 firmware-stage 64-bit aperture。

SeaBIOS 不吃这个 knob。因此 SeaBIOS 下：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
```

和：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
```

测试结果完全一样。

SeaBIOS 下要控制 OS-visible high window，只能通过 QEMU host bridge property：

```bash
-global i440FX-pcihost.pci-hole64-size=...
-global q35-pcihost.pci-hole64-size=...
```

但 SeaBIOS 仍可能先把 present 的 64-bit BAR 分到 above-4G；此时即便 `pci-hole64-size=0`，QEMU/ACPI 也需要把实际 BAR 覆盖范围报告给 Linux，否则 guest resource tree 会不一致。

## 为什么这些 testcase 有效

1. 使用真实 firmware boot，而不是 Linux direct boot。

   OVMF/SeaBIOS 的 PCI allocation 发生在 firmware 阶段。`-kernel/-initrd` 直启绕过 firmware boot path，不能证明 OVMF/SeaBIOS aperture 语义。

2. 使用真实 Linux guest 读取最终 OS-visible resource。

   Linux dmesg 的 `root bus resource [mem ... window]` 是 guest 最终接受的 ACPI/root bridge 结果，比只看 QEMU HMP 更接近用户实际看到的系统行为。

3. 同时使用有 BAR 探针和无 BAR 探针。

   有 BAR 探针可以验证实际 64-bit BAR 怎么落点；无 BAR 探针可以验证是否存在默认预留 high aperture。只跑其中一种会误判。

4. 对照了 OVMF 与 SeaBIOS。

   同一 guest image、同一 QEMU、同一机器类型下切换 firmware，可以明确区分 OVMF fw_cfg knob 和 QEMU host bridge property 的作用边界。

5. 对照了 i440fx 与 q35。

   i440fx 默认 high aperture 是 2G，q35 默认 high aperture 是 32G。机器类型本身会改变默认行为，不能混用结论。

## 最终建议落地

### 实现 VMware 默认策略的 below-4G 分支

先说明边界：下列是强制不发布 high aperture 的 QEMU profile，不是完整 VMware
默认策略。当前一键实测中，i440fx + 1GB RAM + 1GB BAR 成功得到与 VMware 相同的
`0x80000000-0xbfffffff`；q35 同参数的 BAR 未分配，是负例。入口为：

```bash
./qemu-vmware-default-profile-validate.sh
```

OVMF + i440fx：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global i440FX-pcihost.pci-hole64-size=0
```

OVMF + q35：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
-global q35-pcihost.pci-hole64-size=0
```

SeaBIOS + i440fx：

```bash
-global i440FX-pcihost.pci-hole64-size=0
```

SeaBIOS + q35：

```bash
-global q35-pcihost.pci-hole64-size=0
```

SeaBIOS 四组命令仅用于 allocator/ACPI 边界控制，不能作为 VMware EFI 等价配置。

### 实现计算后的 high 分支

如果实际 BAR 不能低置，N 必须来自逐 BAR 对齐和 bridge packing，而不是简单总和：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=$((N * 1024))
-global i440FX-pcihost.pci-hole64-size=${N}G
```

本轮 i440fx 2GB 档已用 `N=2` 启动并得到 2GB high window；高/低分类和大小与 VMware
相符，基址不同。若只是显式测试 4GB QEMU aperture，可使用下面的固定控制组。

### 显式 4GB QEMU 控制组

OVMF + i440fx：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
-global i440FX-pcihost.pci-hole64-size=4G
```

OVMF + q35：

```bash
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096
-global q35-pcihost.pci-hole64-size=4G
```

SeaBIOS + i440fx：

```bash
-global i440FX-pcihost.pci-hole64-size=4G
```

SeaBIOS + q35：

```bash
-global q35-pcihost.pci-hole64-size=4G
```

## 一句话版本

`X-PciMmio64Mb=0` 加 `pci-hole64-size=0` 只表示 QEMU 的 below-4G-only
profile，不再代表完整 VMware 默认策略。对标 ESXi 8 U3 默认 DirectPath
需要启动器先选择 Dynamic candidate，再按每个 BAR 对齐/packing 计算包络：能低置时
使用通过冷启动验证的 zero/zero machine profile，不能低置时同时给 OVMF 和 host
bridge 设置所需高窗；精确复刻 VMware 高窗基址还需要修改 allocator。
