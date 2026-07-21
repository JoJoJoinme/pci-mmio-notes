# QEMU Legacy VFIO launch surface verification (2026-07-22)

结论：当前 Legacy-first 产品不能沿用设计中原有的“Host Agent 把 raw VFIO device fd 直接交给
stock QEMU 5.0”假设。QEMU 5.0 的 legacy `vfio-pci` 仅接受 `host`/`sysfsdev`，源码还保留
passed group/device fd 的 TODO；QEMU 10.2 的 `fd` property 位于 `CONFIG_IOMMUFD` 分支，是
cdev/IOMMUFD surface，不是 legacy group-container fd 接口。

因此同一个启用 `CONFIG_IOMMUFD` 的 QEMU 10.2 binary 可以在 `-device vfio-pci,help` 中显示
`fd/iommufd`，但当前 QEMU 10.2 Legacy qualification profile 仍只允许 `host/sysfsdev`；只有未来
独立的 cdev/IOMMUFD profile 才允许使用 `fd/iommufd`。binary 暴露 property 不等于运行时可以
在 Legacy 与 cdev 之间 fallback。

因此当前产品的 `launchGrant` 是 `AUTHORIZED_DEVICE_PATH`：Host Agent 在 durable lease 后创建
每 VM 独立 uid、mount namespace、device-cgroup/LSM allowlist 和只读 sysfs view，只暴露已租用
group/BDF，然后用 `-device vfio-pci,host=<exact-bdf>` 启动 QEMU。启动后必须核对 PID starttime、
argv hash、`/proc/<pid>/fd` 的 device identity、QMP/QOM device identity、lease 与 run generation。

## 可复现检查

WSL 当前安装的 QEMU 6.2：

```text
/usr/bin/qemu-system-x86_64 -nodefaults -machine none -device vfio-pci,help
```

输出包含 `host` 与 `sysfsdev`，不包含 `fd` 或 `iommufd`。

本地 QEMU 11.0.2 lab build：

```text
/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64 -nodefaults -machine none -device vfio-pci,help
```

输出包含 `host`、`sysfsdev`、`iommufd` 和 `fd`。源码进一步证明 `fd` property 只在
`CONFIG_IOMMUFD` 下注册。

官方、版本固定的源码入口：

- [QEMU v5.0.0 `hw/vfio/pci.c`](https://gitlab.com/qemu-project/qemu/-/blob/v5.0.0/hw/vfio/pci.c)
- [QEMU v10.2.0 `hw/vfio/pci.c`](https://gitlab.com/qemu-project/qemu/-/blob/v10.2.0/hw/vfio/pci.c)
- [QEMU IOMMUFD integration](https://www.qemu.org/docs/master/devel/vfio-iommufd.html)

## 证据边界

这是版本化 QEMU source/runtime surface 的 E2 设计依据，不是 Qman 产品 launcher、Legacy attach、
DMA 隔离或物理设备 qualification 证据。它关闭的是“Legacy 传参和权限边界怎么设计”的未知项，
不会关闭 C21、S15、F09 或任何产品风险。
