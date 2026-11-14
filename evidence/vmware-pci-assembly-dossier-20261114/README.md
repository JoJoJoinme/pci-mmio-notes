# VMware PCI 直通汇编证据文档集

这里直接展示原始指令、机器字节与逐段解释。先读你关心的实现：

- [01 可直通资格的完整谓词](01-capable.md)：174 字节函数、三个 VSI 读取、禁用字段来源和无效 SBDF 判断。
- [02 依赖代表计算](02-dependency-construction.md)：完整函数、父链、复位候选和 packed SBDF 的选择。
- [03 主机启用禁用](03-owner-transitions.md)：四个验证关口、vtable 解析、成员循环、配置写入与补偿。
- [04 VM 开机登记](04-vm-admission.md)：内存前提、FPT 回调、宿主 owner、同组 VM owner 和 RMRR。
- [05 域状态与同 VM 失败](05-domain-lifecycle.md)：查询读字段、子树写字段、同域计数、代理 RID 组合及上层拒绝。
- [06 map 复位与 ACS](06-reset-map-acs.md)：字符串到选择器、依赖字段写入、D3D0 前提、完整 ACS 函数。
- [07 运行与版本对照](07-runtime-and-versions.md)：任务、表采样、真实警告及三份 build 的分支并列。
- [08 字段与复核入口](08-reproduce-and-unknowns.md)：字段证据、重放命令和未确定的内部机制。

地址和重定位的读法见 [00 阅读说明](00-reading-guide.md)。旧 PDF 保留为概览；技术审阅以本套代码正文为入口。

按函数名查找切片，可用[函数索引](FUNCTIONS.md)。

## 先看一段真正决定同组占用的代码

下面这一段来自 build 24280767 的 `PCIPassthruRegisterDeviceInt`。`0x4e4e` 比较依赖代表；`0x4e80` 比较 VMM owner；相同 owner 跳回循环，不同 owner 选择失败状态。完整解释在第 04 篇。

<!-- evidence:R08:begin -->

### 切片 R08 共同代表与同一 VM 的完整比较循环

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4b6c`，函数大小 `3720` 字节。
- 窗口：`0x4de9` 到 `0x4ea2`（右端不含）；文件偏移 `0x4e29`；47 条指令。
- 窗口 SHA-256：`6ef505dcdd0f50a900a72f6bf23d47e4a2bb66912d52061befcc07ab7bedbfe1`。[单独查看汇编](snippets/R08.asm)

```asm
            0x4de9 (+027d)  4c 8b 6c 24 10                                mov     r13, qword ptr [rsp + 0x10]
            0x4dee (+0282)  48 8d 74 24 64                                lea     rsi, [rsp + 0x64]
            0x4df3 (+0287)  4c 89 ef                                      mov     rdi, r13
            0x4df6 (+028a)  e8 00 00 00 00                                call    0x4dfb ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x4dfb (+028f)  8b 74 24 64                                   mov     esi, dword ptr [rsp + 0x64]
            0x4dff (+0293)  41 39 75 00                                   cmp     dword ptr [r13], esi
            0x4e03 (+0297)  0f 84 99 00 00 00                             je      0x4ea2 ; branch leaves this window
            0x4e09 (+029d)  e8 00 00 00 00                                call    0x4e0e ; REL type=2 PCI_GetFirstDevice A=-4
            0x4e0e (+02a2)  48 85 c0                                      test    rax, rax
            0x4e11 (+02a5)  0f 84 8b 00 00 00                             je      0x4ea2 ; branch leaves this window
            0x4e17 (+02ab)  4c 89 64 24 38                                mov     qword ptr [rsp + 0x38], r12
            0x4e1c (+02b0)  41 89 ed                                      mov     r13d, ebp
            0x4e1f (+02b3)  49 89 c4                                      mov     r12, rax
            0x4e22 (+02b6)  48 8b 6c 24 28                                mov     rbp, qword ptr [rsp + 0x28]
            0x4e27 (+02bb)  eb 10                                         jmp     0x4e39
            0x4e29 (+02bd)  4c 89 e7                                      mov     rdi, r12
            0x4e2c (+02c0)  e8 00 00 00 00                                call    0x4e31 ; REL type=2 PCI_GetNextDevice A=-4
            0x4e31 (+02c5)  49 89 c4                                      mov     r12, rax
            0x4e34 (+02c8)  48 85 c0                                      test    rax, rax
            0x4e37 (+02cb)  74 64                                         je      0x4e9d
            0x4e39 (+02cd)  48 8d 74 24 68                                lea     rsi, [rsp + 0x68]
            0x4e3e (+02d2)  4c 89 e7                                      mov     rdi, r12
            0x4e41 (+02d5)  e8 00 00 00 00                                call    0x4e46 ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x4e46 (+02da)  85 c0                                         test    eax, eax
            0x4e48 (+02dc)  75 df                                         jne     0x4e29
            0x4e4a (+02de)  8b 44 24 68                                   mov     eax, dword ptr [rsp + 0x68]
            0x4e4e (+02e2)  39 44 24 64                                   cmp     dword ptr [rsp + 0x64], eax
            0x4e52 (+02e6)  75 d5                                         jne     0x4e29
            0x4e54 (+02e8)  41 8b 34 24                                   mov     esi, dword ptr [r12]
            0x4e58 (+02ec)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 pcipDevTable A=-4
            0x4e5f (+02f3)  48 89 ea                                      mov     rdx, rbp
            0x4e62 (+02f6)  e8 00 00 00 00                                call    0x4e67 ; REL type=2 PCISbdfMap_Find A=-4
            0x4e67 (+02fb)  48 8b 44 24 70                                mov     rax, qword ptr [rsp + 0x70]
            0x4e6c (+0300)  48 85 c0                                      test    rax, rax
            0x4e6f (+0303)  74 b8                                         je      0x4e29
            0x4e71 (+0305)  48 8b 50 10                                   mov     rdx, qword ptr [rax + 0x10]
            0x4e75 (+0309)  48 85 d2                                      test    rdx, rdx
            0x4e78 (+030c)  74 af                                         je      0x4e29
            0x4e7a (+030e)  80 78 04 00                                   cmp     byte ptr [rax + 4], 0
            0x4e7e (+0312)  75 a9                                         jne     0x4e29
            0x4e80 (+0314)  44 3b 6a 70                                   cmp     r13d, dword ptr [rdx + 0x70]
            0x4e84 (+0318)  74 a3                                         je      0x4e29
            0x4e86 (+031a)  4c 8b 64 24 10                                mov     r12, qword ptr [rsp + 0x10]
            0x4e8b (+031f)  41 bd 04 00 ad 0b                             mov     r13d, 0xbad0004
            0x4e91 (+0325)  49 81 c4 08 01 00 00                          add     r12, 0x108
            0x4e98 (+032c)  e9 9c fe ff ff                                jmp     0x4d39 ; branch leaves this window
            0x4e9d (+0331)  4c 8b 64 24 38                                mov     r12, qword ptr [rsp + 0x38]
```

<!-- evidence:R08:end -->

这就是为什么“两个 BDF 不同”仍会冲突，也说明“同一 VM 的 owner 检查允许继续”并不保证后面的域初始化通过。后一条链路的实际读写与分支在第 05 篇，不用一句“可能是 IOMMU”代替证据。

## 文档集的可核对材料

本套包含 **55 个切片、1778 条指令（按窗口计）、232 个直接跳转目标**，来自五份固定哈希映像。主题正文为 00—08 共九篇；另有本入口、逐段 `.asm` 和机器记录。没有新增运行实验。

- [机器可读切片和重定位](evidence/snippets.json)
- [第二套解码核对](evidence/objdump-verification.json)
- [运行证据对应表](evidence/runtime-crosswalk.json)
- [切片选择范围](selection-plan.json)
- [逐文件校验清单](manifest.json)

仅保留本主题所需的判定窗口及必要上下文，没有把整个 VMware 库或内核的全量反汇编塞进仓库。每个省略与跳出窗口都能由地址复核；未取得原始结构定义和未分析完整的路径会明确保留未知。
