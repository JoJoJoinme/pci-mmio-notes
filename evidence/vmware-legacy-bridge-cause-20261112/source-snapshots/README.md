# 采集脚本快照

这些 `.txt` 文件用于审计和复现准备，公开包的 `verify_bundle.py` 只作离线校验，不启动 VM 或修改主机。

- `bridge_cause_probe.py.txt`：最终采集版本，按清单选择 legacy/PCIe BDF，校验 UUID/build/设备 ID、所有 VM 关机状态，保存任务、日志及只读 VT-d context 采样。
- `executed-root-control.py.txt`、`executed-root-single.py.txt`：各 PCIe 阶段启动时保存的实际脚本字节。
- `set_bridge_policy.py.txt`、`wait_bridge_policy.py.txt`、`wait_dependency_policy.py.txt`：显式依赖规则的守卫、持久化、新启动时间与两个 VSI 标志验证。规则影响范围同时匹配管理网卡，脚本只接受其原有 owner/FPT 属性不变的指定实验条件。
- `prepare_dependency_interaction_run.py.txt`：独立覆盖盘、内存门槛、启动参数和就绪检查；本次增加可选 trace event 列表参数。
- `test_esxi_dependency_interaction.py.txt`：VM 配置/任务/日志的公共辅助函数；只导入函数，不直接运行其带历史默认值的主入口。
- `compare_qemu_source.py.txt`：通过任务级代理下载官方 v11.0.2 对应源码并比较哈希。

`esxi_passthru_capability.py.txt` 保留本地实际使用的连接辅助代码；它与远端仓库基线版本有差异，因此不要用基线文件替代本次快照。另一依赖 [`test_esxi_owner_activation.py`](../../../vmware-esxi8-lab/test_esxi_owner_activation.py) 已核对与仓库文件逐字节一致。凭据由实验机私有存储提供，不包含在公开包内。

复现前必须使用专用、可丢弃的覆盖盘，检查脚本中的路径、host UUID、build、BDF 和资源门槛。传统桥和 PCIe 场景使用同一测试 IP/MAC，必须先正常关闭前一个实例再启动后一个。默认规则矩阵、显式规则矩阵以及规则恢复分别保存，不得把失败请求或旧启动时间的读回当作生效结果。

本轮没有改写 IOMMU 表、关闭 ACS/IOMMU 隔离或运行 guest DMA 负载。VT-d 采样的 `readl/readq` 命令均为只读；`multifunction` 标记与 `passthru.map` 规则改变属于被单独记录的实验变量。
