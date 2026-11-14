# 08 字段索引 可复核方法与未确定部分

## 1 字段名称怎样建立而不是猜出来

以下偏移是**对应软件对象内的偏移**，不是同一组 PCI 配置空间寄存器地址，也不能用于其他 build。

| 对象和偏移 | 本文使用的含义 | 读写证据 |
| --- | --- | --- |
| PciDeviceImpl `+0x77` | 保存的全局直通禁用值 | A02 写，A01/O01 读 |
| 内核 PCI 对象 `+0` | packed SBDF | D01/D02 读，A05 拆成四字段 |
| 内核 PCI 对象 `+0xe8` | 父对象指针 | D03 沿该字段遍历，D01 用它作父边界 |
| 内核 PCI 对象 `+0x1f8` | 显式多功能依赖值 | M04 写，D01 读 |
| 内核 PCI 对象 `+0x18` 高位 | 当前 Function 的多功能描述条件 | M04 与 D01 的符号位测试；并与配置空间对照一致 |
| 内核 PCI 对象 `+0x1fa/+0x1fb` | ACS 缓存有效位与结果 | M07 入口读、出口写 |
| 内核 PCI 对象 `+0x378` | 域指针 | I03 读，I05 写，I04 与 fromDom 比较 |
| 内核 PCI 对象 `+0x370` | 关联计数字段 | I05 的加减及保留关联分支；原结构体类型名未取得 |
| 登记表输出对象 `+0x10` | 活动登记指针 | R08 取指针并检查是否为空 |
| 活动登记 `+0x70` | 与当前 VMM owner 比较的标识 | R08 比较；相关日志称其为 owner world |
| 登记表对象 `+4` | 允许跳过某些 owner 检查的标志 | R08 只确认判断，未命名业务含义 |
| 全局 `configOption+0x1b8` | 影响部分复位依赖判断的值 G | D01 读取并与 1 比较；业务选项名未知 |

同一偏移出现在不同结构中，不代表同一字段。尤其管理库 configured-owner 的 1/2，不能拿去解释内核 FPT owner 比较的数字 1。

## 2 可以直接复核的内容

| 层次 | 复核方式 |
| --- | --- |
| 文件身份 | 对照 selection-plan.json 中五个 ELF SHA-256 |
| 指令来源 | 按 section、ELF 地址和文件偏移读取原始字节 |
| 指令边界 | Capstone 与 GNU objdump 对每个窗口独立解码 |
| 直接跳转 | 对照目标地址和 fallthrough；窗口外目标不会被删掉 |
| 动态链接目标 | 检查 PLT/GOT 或 `.rela.text/.rela.dyn` 的符号和 addend |
| C++ 间接调用 | 对照构造函数主地址点和 vtable 槽重定位 |
| 对运行结果的解释 | 对照任务、电源状态、警告和表采样的具体 build |

| 项目 | 结果 |
| --- | --- |
| 独立解码器 | GNU objdump (GNU Binutils for Ubuntu) 2.38 |
| 窗口数 | 55 |
| 指令边界与字节 | 1778 条一致 |
| 直接跳转目标 | 232 项一致 |
| 动态重定位 | 16 项一致 |
| 指令拼写差异 | 0 |
| 范围 | 静态核对，不是新的 VM 或硬件运行验证 |

解码一致不是语义证明的替代品。例如“返回零”可能是布尔 false，也可能是状态 Success。本文按具体函数的输出位置与调用者条件分别解释。

## 3 用自己的合法副本重新导出

依赖为 Python、Capstone、pyelftools；第二套核对需要 GNU objdump。当前记录保留了实际导入库版本和 objdump 版本。

建立本地输入映射，文件路径由复核者填写：

```json
{
  "vmkctl242": "/licensed/24280767/libvmkctl.so",
  "kernel242": "/licensed/24280767/k.b00.decoded",
  "pcip242": "/licensed/24280767/pcip.elf",
  "pcip255": "/licensed/25595708/pcip.elf",
  "pcip254": "/licensed/25433460/pcip.elf"
}
```

```console
python tools/export_snippets.py --inputs inputs.json --out replay
python tools/verify_objdump.py --inputs inputs.json --snippets replay/snippets.json --out replay/objdump-verification.json
python tools/verify_dossier.py
```

若 Capstone/pyelftools 位于专用依赖目录，可给第一条命令增加 `--dependency-path`。工具先验证 ELF 哈希，只读取映像，不加载、执行或改写 VMware 代码。`verify_dossier.py` 核对发布包内部一致性，不能替代带原始 ELF 的前两步。

## 4 哪些问题仍没有汇编级闭合

| 问题 | 已有证据 | 缺少什么 |
| --- | --- | --- |
| Dynamic 的候选排序与多设备求解 | API 条件、分配结果和受控竞争实验 | 完整 Assignable Hardware / hostd / vCenter 调用图及求解实现 |
| UI 在哪个按钮前校验 | 指定版本操作记录，管理库中有验证入口 | 每条前端/API 到入口的完整连接 |
| 依赖查找跨 segment 行为 | 管理库三字段比较；内核 packed 比较 | 多 segment 实测与枚举范围约束证明 |
| 配置联动是否原子 | 逐成员写和补偿代码 | 中途失败、补偿失败、并发可见性与上层协调 |
| 全部切域和复位语义 | 所选 fromDom 检查、迭代器和回调 | 所有 domainOps backend、异常恢复与真实硬件动作 |
| 新版本是否整体相同 | 两份新版已有域分支及运行失败 | 新版整条链路与未取得版本的介质 |
| 修复是否安全有效 | 已定位的状态冲突与成功拓扑对照 | 保留共享身份的修复后运行、DMA/IRQ 与恢复验证 |

本套比概述多的是可逐条审查的实现证据，并没有把以上未知项改写成已完成。对竞品判断，应引用具体章节、切片编号和 build，而不是只引用“VMware 有/没有依赖检查”。
