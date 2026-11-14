# 实验研究证据

- [ESXi PCI 资格、依赖与开机检查的汇编核对](vmware-pci-admission-assembly-20261114/README.md)：同 build 管理库与内核的分层条件、共同依赖代表、主机配置联动、开机 owner 比较及已有域拒绝；含 121 项只读静态核对，区别于新运行验收。
- [传统 PCI 桥问题归因与新版本复核](vmware-passthrough-version-review-20261113/README.md)：ESXi 8.0 U3k / 25595708、ESX 9.1.0.0100 / 25433460 实际升级后仍复现，原生 PCI e1000 控制相同。结合精确 build 汇编区分软件初始化缺口、保护条件与未确认的厂商意图；最新 9.1.1.0100 未取得介质，修复状态未知。
- [传统 PCI 桥下双设备注册失败的定位](vmware-legacy-bridge-cause-20261112/README.md)：运行采样与同 build 静态检查定位了“逐设备登记、整组切域”的前提冲突；修复未验证。含 5 Why、产品影响和未覆盖的验收项。
- [PCIe 多功能设备依赖的成功对照](vmware-pci-multifunction-fix-20261111/README.md)：PCIe 直连场景同 VM 双设备开机成功；补齐 Function 1 的 multifunction 标志后，跨 VM 第二台失败。两处改变分别说明，含移除额外规则的控制实验。
- [VMware PCI 依赖的启用、禁用、分配和开机验证](vmware-dependency-ui-20261111/README.md)：2026 年 11 月 10—11 日，ESXi 8.0.3 与 vCenter 8.0.3 的 API、Host Client 和 vCenter 界面实测，含截图、原始回执、日志摘录、脚本快照和 SHA-256 清单。

每份报告分别说明实验条件、直接观察及尚未成立的验证条件。合成实验结果不等同于真实硬件资格认证。
