# 实验研究证据

- [PCI 直通资格与开机依赖检查设计视图](vmware-pci-decision-design-20261114/README.md)：将汇编证据转换成三张可编辑架构/流程图，聚焦 `passthruCapable`、宿主 owner、活动 VM owner 和已有域检查，附传统桥同 VM 失败的逐步解释。
- [PCI 直通汇编证据文档集](vmware-pci-assembly-dossier-20261114/README.md)：正文直接展示 55 个代码切片、1778 条指令，以及 PLT/GOT、vtable、字段读写和分支解释；按资格、依赖、主机切换、VM 登记、域状态及 map/ACS 分篇审阅。
- [VMware PCI 直通原理与竞品分析](vmware-directpath-principles-20261114/README.md)：17 页技术决策报告，串联资格、依赖、主机切换、动态选卡、VM 启动和恢复；附 30 条结论与 29 项来源，单列 Enhanced DirectPath 的官方条件化能力及我方实现边界。
- [ESXi PCI 资格、依赖与开机检查的汇编核对](vmware-pci-admission-assembly-20261114/README.md)：同 build 管理库与内核的分层条件、共同依赖代表、主机配置联动、开机 owner 比较及已有域拒绝；含 121 项只读静态核对，区别于新运行验收。
- [传统 PCI 桥问题归因与新版本复核](vmware-passthrough-version-review-20261113/README.md)：ESXi 8.0 U3k / 25595708、ESX 9.1.0.0100 / 25433460 实际升级后仍复现，原生 PCI e1000 控制相同。结合精确 build 汇编区分软件初始化缺口、保护条件与未确认的厂商意图；最新 9.1.1.0100 未取得介质，修复状态未知。
- [传统 PCI 桥下双设备注册失败的定位](vmware-legacy-bridge-cause-20261112/README.md)：运行采样与同 build 静态检查定位了“逐设备登记、整组切域”的前提冲突；修复未验证。含 5 Why、产品影响和未覆盖的验收项。
- [PCIe 多功能设备依赖的成功对照](vmware-pci-multifunction-fix-20261111/README.md)：PCIe 直连场景同 VM 双设备开机成功；补齐 Function 1 的 multifunction 标志后，跨 VM 第二台失败。两处改变分别说明，含移除额外规则的控制实验。
- [VMware PCI 依赖的启用、禁用、分配和开机验证](vmware-dependency-ui-20261111/README.md)：2026 年 11 月 10—11 日，ESXi 8.0.3 与 vCenter 8.0.3 的 API、Host Client 和 vCenter 界面实测，含截图、原始回执、日志摘录、脚本快照和 SHA-256 清单。

每份报告分别说明实验条件、直接观察及尚未成立的验证条件。合成实验结果不等同于真实硬件资格认证。
