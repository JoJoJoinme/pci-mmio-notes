# VMware PCI 直通原理与竞品分析

面向产品、架构、研发和测试评审的系统报告。主线包含设备发现、资格、依赖、主机切换、静态与动态选择、VM 启动、I/O、释放恢复、迁移和对我方产品的判断。

- [PDF 主报告](VMware_PCI_DirectPath_Principles_20261114.pdf)：17 页，包含流程图、原理说明、竞争判断和证据附录。
- [可检索的报告正文](REPORT.md)：与 PDF 同源生成的 Markdown 版。
- [30 条结论登记](claims.json)：逐项列出证据类型、版本范围、限制及产品含义。
- [29 项来源](sources.json)：官方资料与现有实验、汇编、设计文件；仓库来源固定版本并记录 SHA-256。
- [旧故障回执的本轮复核](observations/release-fault-review.json)：解释候选仍发布但健康同组成员无法启动的场景，保留注入方式、原始摘要和日志源行号。
- [历史 DPDK 使用上下文](observations/host-dpdk-context.json)：保留端口分工与证据边界，不含宿主身份或凭据。
- [文件校验清单](manifest.json)与[离线核对程序](verify_report.py)。

主机制分析绑定 ESXi 8.0 U3b / 24280767。8.0 U3k 和 9.1.0.0100 只用于此前已验证的特定传统桥路径；Enhanced DirectPath 的条件化生命周期能力作为官方声明单列，未冒充本项目实测。

本轮新增系统整理、来源核对及历史回执复核，没有新增硬件运行实验。报告区分 VMware 已有证据、分析判断和我方设计目标，不能把参考代码或组件测试写成目标产品已经交付的商业能力。

```console
python evidence/vmware-directpath-principles-20261114/verify_report.py
```

PDF 已逐页检查；预览图片仅用于内部版式核验，不包含在发布包中。公开包不含 VMware 二进制、安装介质、完整反汇编或凭据。
