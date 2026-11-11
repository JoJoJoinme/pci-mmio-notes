# 辅助脚本的使用范围

这里保存本轮结束时的辅助脚本快照，追加 `.txt` 以防自动执行。它们包含本机目录、目标 UUID/build、实验 VM 名称及凭据条目名称，必须在审查并配置自己的独立实验环境后使用；不包含凭据值或 VMware 镜像，也不保证单独复制即可运行。

- [启动准备](prepare_dependency_interaction_run.py.txt)：独立 overlay、内存预检及运行参数记录。
- [启动器快照](start-qemu-esxi8-mf.sh.txt)：实际使用的最终启动器，含原工作区其他既有功能；本次提交到仓库启动器的修改只增加 Function 1 的可选 multifunction 参数。
- [矩阵与收尾](repair_dependency_positive_control.py.txt)：主机开关、配置、开机、UI 后台采样及只清理本轮 VM。
- [重启后的规则核验](wait_dependency_policy.py.txt)：记录启动时间、文件、ESXCLI 和 VSI；最终无新增规则。
- [诊断采集](inspect_dependency_host.py.txt)：只读采集服务、日志、PCI 配置空间和底层属性。

脚本依赖 pyVmomi 和本仓库的 [ESXi 辅助函数](../../../vmware-esxi8-lab/esxi_passthru_capability.py)、[owner 辅助函数](../../../vmware-esxi8-lab/test_esxi_owner_activation.py)，以及[前一包中的基础矩阵辅助脚本](../../vmware-dependency-ui-20261111/source-snapshots/test_esxi_dependency_interaction.py.txt)。最终快照不是逐次执行版本；阶段回执和参数变更文件保留实际行为。

复现需将需用的 `.py.txt` 复制为 `.py`，放在依赖模块同目录，并重新配置受控目录和目标身份。语法检查应使用 `ast.parse`，不要通过导入脚本做检查。运行 `policy`、`matrix`、`owner-matrix`、`cleanup` 或 `shutdown` 会修改实验环境；`collect` 和 `preflight` 为采样入口。

本轮成功对照最终没有额外 passthru.map 行，优先复现报告中的原生 PCIe 多功能描述，不必重演前期所有规则排查分支。
