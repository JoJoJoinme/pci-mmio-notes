# 实验辅助脚本快照

这些 `.py.txt` 文件是本轮结束时的辅助脚本字节快照。附加 `.txt` 防止自动执行和测试框架收集；它们不是冻结的每一步执行版本，也不是已封装的通用 SDK。

| 文件 | 用途 |
| --- | --- |
| [prepare_dependency_interaction_run.py](prepare_dependency_interaction_run.py.txt) | 资源检查、独立 qcow2 overlay、QEMU 启动 |
| [test_esxi_dependency_interaction.py](test_esxi_dependency_interaction.py.txt) | 直连 ESXi 的主机、配置、开机矩阵及清理 |
| [collect_dependency_ui.py](collect_dependency_ui.py.txt) | Host Client 操作后的配置、任务和日志采样 |
| [collect_vcenter_dependency_readiness.py](collect_vcenter_dependency_readiness.py.txt) | vCenter 连接与实验就绪检查 |
| [vcenter_dependency_ui.py](vcenter_dependency_ui.py.txt) | vCenter API 矩阵、UI 后台核对、清理 |
| [test_esxi_dependency_disable.py](test_esxi_dependency_disable.py.txt) | A/B 单项禁用、前后 owner、双 API 属性采样 |
| [declare_functional_dependency.py](declare_functional_dependency.py.txt) | 功能依赖补充试验；本轮前置条件失败，不能当成功配方 |
| [dependency_ui_tcp_relay.py](dependency_ui_tcp_relay.py.txt) | 本机回环 TLS 字节转发，导入即运行，不应为语法核验而导入 |

脚本依赖 Python 3、pyVmomi，以及仓库既有的 [owner 辅助函数](../../../vmware-esxi8-lab/test_esxi_owner_activation.py)、[ESXi 采集辅助函数](../../../vmware-esxi8-lab/esxi_passthru_capability.py)和 [QEMU 启动脚本](../../../vmware-esxi8-lab/start-qemu-esxi8-mf.sh)。实验中这些基础文件有本地变更，例如 SSH 连接复用和 vCPU 环境变量；此提交不将其他开发变更一起发布，不能把仓库基线与本包当作精确可重建镜像。

要复现，应将需用的 `.py.txt` 复制为 `.py` 放回辅助函数同目录，先审查固定输出目录、run ID、设备地址、ESXi UUID/build、实验 VM 名称及凭据读取方式，再在独立实验环境配置。现有凭据来自本地 Caveat 条目，未包含在本包。固定身份校验必须按新实验对象重新建立，不能为了跳过错误直接移除。脚本含创建 VM、主机模式切换和关机等有状态操作；语法检查应使用 `ast.parse`，不要导入执行。

禁用采集入口示例（完成上述实验配置后）：

```console
python test_esxi_dependency_disable.py matrix --endpoint esxi --label single-disable
python test_esxi_dependency_disable.py matrix --endpoint vcenter --label single-disable
python test_esxi_dependency_disable.py snapshot --endpoint vcenter --label ui-result
```

`matrix` 每个方向分别启用两项后，只对指定一项提交 false；脚本不预设另一项的结果。UI 选择与弹窗行为需按报告的界面步骤独立操作，这些 API 命令不能提供 UI 证据。
