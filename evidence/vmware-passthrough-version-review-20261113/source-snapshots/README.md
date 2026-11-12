# 采集与复核脚本

`u3k-executed-probe.py.txt`、`esx91-executed-probe.py.txt` 和 `esx91-native-executed-probe.py.txt` 是各阶段实际启动时保存的脚本字节。它们校验实验 UUID、build、目标 BDF 和设备 ID，分别保存任务、VM 状态、日志与只读 VT-d 表采样。不能把 API 任务成功或 EOF 当作 guest I/O 验证。

原始输出和脚本快照保留已有换行与行尾空格，以逐字节哈希核对为准；Git 对这些存档关闭空白格式检查，避免为了排版改写证据。报告与核对工具仍使用正常文本检查。

升级辅助脚本先核对完整离线包哈希和目标主机，在维护模式下执行 dry run，然后执行默认签名校验的 profile update，最后等待新 bootTime 和目标 build。提交记录已存在时拒绝重复升级；超时应先核对效果。

`prepare_esx91_nativepci.py.txt` 使用已关闭的 ESX 9.1 实验盘作为只读父盘，创建独立覆盖盘并只更换测试网卡模型。恢复这个子实验前，必须重新核对 manifest 中的 parentImages 哈希。

`fetch_iso_modules.py.txt` 只从官方 OEM 目录中精确匹配的 ISO URL 读取选定范围，检查 HTTP Range 和 ETag/长度一致性；它不计算完整 ISO 摘要。完整离线包另由下载脚本核对厂商 SHA-1 并记录 SHA-256。

静态提取和比较是对合法本地副本的只读分析，没有修改、加载或分发 VMware 模块。`verify_guard_predicate.py` 的复核对象是固定 build 的固定模块哈希，依赖 Capstone 和 pyelftools；只验证选定分支，不等于完整源码或修复后的运行验收。

公共辅助函数来自[此前的精确脚本快照](../../vmware-legacy-bridge-cause-20261112/source-snapshots/README.md)及仓库中的 [`test_esxi_owner_activation.py`](../../../vmware-esxi8-lab/test_esxi_owner_activation.py)。采集脚本的顶层入口会访问实验机，不应直接导入；离线核对仅作 AST 语法和证据检查。

本包是实验记录，不是无条件可运行的生产控制器。复现前需替换并核对路径、主机身份、版本、存储、设备标识、凭据来源与资源门槛。
