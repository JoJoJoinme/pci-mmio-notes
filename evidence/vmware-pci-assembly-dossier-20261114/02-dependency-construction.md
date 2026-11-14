# 02 依赖代表怎样计算

本章的输入是有效的内核 PCI 设备对象，输出是一个 32 位 packed SBDF。它不是 Linux IOMMU group，也不是完整的成员数组。

## 1 完整的依赖计算函数

<!-- evidence:D01:begin -->

### 切片 D01 完整依赖代表计算

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`VMKPCIPassthru_GetDeviceDependencies`；入口 `0x4200001a0e38`，函数大小 `197` 字节。
- 窗口：`0x4200001a0e38` 到 `0x4200001a0efd`（右端不含）；文件偏移 `0x45fe38`；65 条指令。
- 窗口 SHA-256：`916b3c8853f3bd971b838933dca8c443c664b6b5946fd67d9ee736ac2f5af793`。[单独查看汇编](snippets/D01.asm)

```asm
    0x4200001a0e38 (+0000)  41 54                                         push    r12
    0x4200001a0e3a (+0002)  55                                            push    rbp
    0x4200001a0e3b (+0003)  48 89 f5                                      mov     rbp, rsi
    0x4200001a0e3e (+0006)  53                                            push    rbx
    0x4200001a0e3f (+0007)  48 89 fb                                      mov     rbx, rdi
    0x4200001a0e42 (+000a)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200001a0e46 (+000e)  48 85 ff                                      test    rdi, rdi
    0x4200001a0e49 (+0011)  74 14                                         je      0x4200001a0e5f
    0x4200001a0e4b (+0013)  f6 47 04 02                                   test    byte ptr [rdi + 4], 2
    0x4200001a0e4f (+0017)  74 0e                                         je      0x4200001a0e5f
    0x4200001a0e51 (+0019)  48 83 c4 10                                   add     rsp, 0x10
    0x4200001a0e55 (+001d)  b8 01 00 ad 0b                                mov     eax, 0xbad0001
    0x4200001a0e5a (+0022)  5b                                            pop     rbx
    0x4200001a0e5b (+0023)  5d                                            pop     rbp
    0x4200001a0e5c (+0024)  41 5c                                         pop     r12
    0x4200001a0e5e (+0026)  c3                                            ret
    0x4200001a0e5f (+0027)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200001a0e61 (+0029)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200001a0e66 (+002e)  e8 9d 37 fc ff                                call    0x420000164608 ; directSymbol -> IOMMU_GetReqIdDependencies
    0x4200001a0e6b (+0033)  80 bb f8 01 00 00 00                          cmp     byte ptr [rbx + 0x1f8], 0
    0x4200001a0e72 (+003a)  48 89 d8                                      mov     rax, rbx
    0x4200001a0e75 (+003d)  75 47                                         jne     0x4200001a0ebe
    0x4200001a0e77 (+003f)  48 83 3d 99 4f f2 bf 01                       cmp     qword ptr [rip - 0x400db067], 1 ; configOption+0x1b8
    0x4200001a0e7f (+0047)  44 8b 20                                      mov     r12d, dword ptr [rax]
    0x4200001a0e82 (+004a)  74 0c                                         je      0x4200001a0e90
    0x4200001a0e84 (+004c)  48 89 df                                      mov     rdi, rbx
    0x4200001a0e87 (+004f)  e8 64 b7 f5 ff                                call    0x4200000fc5f0 ; directSymbol -> PCI_HasFuncIndependentReset
    0x4200001a0e8c (+0054)  84 c0                                         test    al, al
    0x4200001a0e8e (+0056)  74 49                                         je      0x4200001a0ed9
    0x4200001a0e90 (+0058)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200001a0e94 (+005c)  8b 0b                                         mov     ecx, dword ptr [rbx]
    0x4200001a0e96 (+005e)  44 89 e3                                      mov     ebx, r12d
    0x4200001a0e99 (+0061)  0f b6 f7                                      movzx   esi, bh
    0x4200001a0e9c (+0064)  0f b6 d4                                      movzx   edx, ah
    0x4200001a0e9f (+0067)  39 f2                                         cmp     edx, esi
    0x4200001a0ea1 (+0069)  72 05                                         jb      0x4200001a0ea8
    0x4200001a0ea3 (+006b)  89 f2                                         mov     edx, esi
    0x4200001a0ea5 (+006d)  44 89 e0                                      mov     eax, r12d
    0x4200001a0ea8 (+0070)  0f b6 f5                                      movzx   esi, ch
    0x4200001a0eab (+0073)  39 d6                                         cmp     esi, edx
    0x4200001a0ead (+0075)  0f 46 c1                                      cmovbe  eax, ecx
    0x4200001a0eb0 (+0078)  89 45 00                                      mov     dword ptr [rbp], eax
    0x4200001a0eb3 (+007b)  48 83 c4 10                                   add     rsp, 0x10
    0x4200001a0eb7 (+007f)  31 c0                                         xor     eax, eax
    0x4200001a0eb9 (+0081)  5b                                            pop     rbx
    0x4200001a0eba (+0082)  5d                                            pop     rbp
    0x4200001a0ebb (+0083)  41 5c                                         pop     r12
    0x4200001a0ebd (+0085)  c3                                            ret
    0x4200001a0ebe (+0086)  48 8b 83 e8 00 00 00                          mov     rax, qword ptr [rbx + 0xe8]
    0x4200001a0ec5 (+008d)  48 85 c0                                      test    rax, rax
    0x4200001a0ec8 (+0090)  74 87                                         je      0x4200001a0e51
    0x4200001a0eca (+0092)  48 83 3d 46 4f f2 bf 01                       cmp     qword ptr [rip - 0x400db0ba], 1 ; configOption+0x1b8
    0x4200001a0ed2 (+009a)  44 8b 20                                      mov     r12d, dword ptr [rax]
    0x4200001a0ed5 (+009d)  75 ad                                         jne     0x4200001a0e84
    0x4200001a0ed7 (+009f)  eb b7                                         jmp     0x4200001a0e90
    0x4200001a0ed9 (+00a1)  48 89 df                                      mov     rdi, rbx
    0x4200001a0edc (+00a4)  e8 5b a5 f4 ff                                call    0x4200000eb43c ; directSymbol -> PCI_IsPCIeEndpointDevice
    0x4200001a0ee1 (+00a9)  80 7b 18 00                                   cmp     byte ptr [rbx + 0x18], 0
    0x4200001a0ee5 (+00ad)  78 04                                         js      0x4200001a0eeb
    0x4200001a0ee7 (+00af)  84 c0                                         test    al, al
    0x4200001a0ee9 (+00b1)  75 a5                                         jne     0x4200001a0e90
    0x4200001a0eeb (+00b3)  48 8b 9b e8 00 00 00                          mov     rbx, qword ptr [rbx + 0xe8]
    0x4200001a0ef2 (+00ba)  48 85 db                                      test    rbx, rbx
    0x4200001a0ef5 (+00bd)  0f 84 56 ff ff ff                             je      0x4200001a0e51
    0x4200001a0efb (+00c3)  eb 93                                         jmp     0x4200001a0e90
```

<!-- evidence:D01:end -->

逐段对应关系：

| 区间或地址 | 作用 |
| --- | --- |
| `0x1a0e4b` 的结构字段掩码 `2` | 命中时返回 `0x0bad0001`；不要把它简单等同于 PCI class code |
| `0x1a0e66` | 取得请求者身份相关的候选代表 |
| `0x1a0e6b` 与 `0x1a0ebe` | 读取多功能依赖字段 `+0x1f8`；置位则把父设备纳入候选，缺父设备报错 |
| `0x1a0e77` / `0x1a0eca` | 读 `configOption+0x1b8` 并比较 1，决定是否跳过部分复位检查 |
| `0x1a0e87` | 调用独立复位判断 |
| `0x1a0edc` 到 `0x1a0efb` | 结合 PCIe endpoint 类型与 Header 多功能标志，必要时选择父设备 |
| `0x1a0e99` 到 `0x1a0eb0` | 比较候选的 bus 字段，写出最终代表 |

上表为节省宽度省略了地址公共前缀 `0x420000`；代码块保留完整地址。`configOption+0x1b8` 的符号内偏移可以核对，**该元素的业务选项名仍未可靠确定**。本文用 G 表示该读取值，不编造一个可配置开关名。

在有效输入与请求者查询按调用契约成功的前提下，可以整理为：

```text
requester_candidate = RequesterDependency(d)
functional_candidate = d
reset_candidate = d

if d.multi_function_dependency:
    functional_candidate = parent(d)
    if missing: error

if G != 1 and not HasFunctionIndependentReset(d):
    if d.header_multifunction or not IsPCIeEndpoint(d):
        reset_candidate = parent(d)
        if missing: error

result = select_by_bus(requester_candidate,
                       functional_candidate,
                       reset_candidate)
```

源码级前置条件也要保留：入口的 NULL 测试不能被读成“NULL 一定安全返回”；后面仍会解引用设备。所分析调用者先查到有效设备再调用。函数紧随请求者查询后没有另一个显式返回码分支，因此伪代码不增加一个不存在的错误处理块。

## 2 select_by_bus 究竟比较什么

`movzx edx, ah` 取请求者候选的 bus；`movzx esi, bh` 取另一个候选的 bus。`jb` 在无符号较小时保留请求者候选，否则选择 functional 候选。随后 `cmovbe` 在 reset 候选 bus 小于等于当前候选时选择 reset。

它没有比较整个 SBDF 的数值大小，更不是对任意不相干设备执行通用最小公共祖先算法。相等时的选择顺序也不能随意删掉。这里的候选来自当前设备及相关父链；对异常拓扑、跨 segment 和未覆盖架构约束不能直接外推。

## 3 RequesterDependency 不是实际线上 DMA RID 的直接读数

<!-- evidence:D02:begin -->

### 切片 D02 请求者依赖代表

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMU_GetReqIdDependencies`；入口 `0x420000164608`，函数大小 `69` 字节。
- 窗口：`0x420000164608` 到 `0x42000016464d`（右端不含）；文件偏移 `0x423608`；25 条指令。
- 窗口 SHA-256：`2e28f2e0d92d2df6b6a7c219114e5509911fc5c68f93e1ec00c8fa603f19f2f9`。[单独查看汇编](snippets/D02.asm)

```asm
    0x420000164608 (+0000)  55                                            push    rbp
    0x420000164609 (+0001)  48 89 f5                                      mov     rbp, rsi
    0x42000016460c (+0004)  53                                            push    rbx
    0x42000016460d (+0005)  48 83 ec 18                                   sub     rsp, 0x18
    0x420000164611 (+0009)  e8 f6 6d f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000164616 (+000e)  48 85 c0                                      test    rax, rax
    0x420000164619 (+0011)  74 26                                         je      0x420000164641
    0x42000016461b (+0013)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x420000164620 (+0018)  48 89 c7                                      mov     rdi, rax
    0x420000164623 (+001b)  48 89 c3                                      mov     rbx, rax
    0x420000164626 (+001e)  e8 d5 75 f8 ff                                call    0x4200000ebc00 ; directSymbol -> PCI_GetTopmostAliasingBridge
    0x42000016462b (+0023)  85 c0                                         test    eax, eax
    0x42000016462d (+0025)  48 0f 44 5c 24 08                             cmove   rbx, qword ptr [rsp + 8]
    0x420000164633 (+002b)  8b 03                                         mov     eax, dword ptr [rbx]
    0x420000164635 (+002d)  89 45 00                                      mov     dword ptr [rbp], eax
    0x420000164638 (+0030)  48 83 c4 18                                   add     rsp, 0x18
    0x42000016463c (+0034)  31 c0                                         xor     eax, eax
    0x42000016463e (+0036)  5b                                            pop     rbx
    0x42000016463f (+0037)  5d                                            pop     rbp
    0x420000164640 (+0038)  c3                                            ret
    0x420000164641 (+0039)  48 83 c4 18                                   add     rsp, 0x18
    0x420000164645 (+003d)  b8 01 00 ad 0b                                mov     eax, 0xbad0001
    0x42000016464a (+0042)  5b                                            pop     rbx
    0x42000016464b (+0043)  5d                                            pop     rbp
    0x42000016464c (+0044)  c3                                            ret
```

<!-- evidence:D02:end -->

先按设备地址找到对象，再查询最上层别名桥。查询成功时把桥对象作为代表；没有找到时保留自身对象，然后写出对象起始字段中的 packed SBDF。

沿父链寻找最上层别名桥的完整代码如下。每遇到一个被分类为 aliasing 的桥就更新候选，继续向上直到父链结束。

<!-- evidence:D03:begin -->

### 切片 D03 沿父链选最上层别名桥

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_GetTopmostAliasingBridge`；入口 `0x4200000ebc00`，函数大小 `80` 字节。
- 窗口：`0x4200000ebc00` 到 `0x4200000ebc50`（右端不含）；文件偏移 `0x3aac00`；29 条指令。
- 窗口 SHA-256：`5ef21b016dad0b7725351101217e83a4e01577ec15bea4befe16eb6a012b282c`。[单独查看汇编](snippets/D03.asm)

```asm
    0x4200000ebc00 (+0000)  41 54                                         push    r12
    0x4200000ebc02 (+0002)  49 89 f4                                      mov     r12, rsi
    0x4200000ebc05 (+0005)  55                                            push    rbp
    0x4200000ebc06 (+0006)  53                                            push    rbx
    0x4200000ebc07 (+0007)  48 8b 9f e8 00 00 00                          mov     rbx, qword ptr [rdi + 0xe8]
    0x4200000ebc0e (+000e)  48 85 db                                      test    rbx, rbx
    0x4200000ebc11 (+0011)  74 2c                                         je      0x4200000ebc3f
    0x4200000ebc13 (+0013)  31 ed                                         xor     ebp, ebp
    0x4200000ebc15 (+0015)  48 89 df                                      mov     rdi, rbx
    0x4200000ebc18 (+0018)  e8 1b 95 ff ff                                call    0x4200000e5138 ; directSymbol -> PCIBridge_IsAliasing
    0x4200000ebc1d (+001d)  84 c0                                         test    al, al
    0x4200000ebc1f (+001f)  48 0f 45 eb                                   cmovne  rbp, rbx
    0x4200000ebc23 (+0023)  48 8b 9b e8 00 00 00                          mov     rbx, qword ptr [rbx + 0xe8]
    0x4200000ebc2a (+002a)  48 85 db                                      test    rbx, rbx
    0x4200000ebc2d (+002d)  75 e6                                         jne     0x4200000ebc15
    0x4200000ebc2f (+002f)  49 89 2c 24                                   mov     qword ptr [r12], rbp
    0x4200000ebc33 (+0033)  31 c0                                         xor     eax, eax
    0x4200000ebc35 (+0035)  48 85 ed                                      test    rbp, rbp
    0x4200000ebc38 (+0038)  74 0c                                         je      0x4200000ebc46
    0x4200000ebc3a (+003a)  5b                                            pop     rbx
    0x4200000ebc3b (+003b)  5d                                            pop     rbp
    0x4200000ebc3c (+003c)  41 5c                                         pop     r12
    0x4200000ebc3e (+003e)  c3                                            ret
    0x4200000ebc3f (+003f)  48 c7 06 00 00 00 00                          mov     qword ptr [rsi], 0
    0x4200000ebc46 (+0046)  5b                                            pop     rbx
    0x4200000ebc47 (+0047)  b8 03 00 ad 0b                                mov     eax, 0xbad0003
    0x4200000ebc4c (+004c)  5d                                            pop     rbp
    0x4200000ebc4d (+004d)  41 5c                                         pop     r12
    0x4200000ebc4f (+004f)  c3                                            ret
```

<!-- evidence:D03:end -->

桥分类函数的直接判定是内部类型值属于 `{1,2,4,5}`：

<!-- evidence:D04:begin -->

### 切片 D04 别名桥内部类型集合

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCIBridge_IsAliasing`；入口 `0x4200000e5138`，函数大小 `27` 字节。
- 窗口：`0x4200000e5138` 到 `0x4200000e5153`（右端不含）；文件偏移 `0x3a4138`；9 条指令。
- 窗口 SHA-256：`c06b4c59bf0f97cb0ceb33933e9945ec251e1a6ce87b02d5e94e75d3a0cd521e`。[单独查看汇编](snippets/D04.asm)

```asm
    0x4200000e5138 (+0000)  8b 97 f8 00 00 00                             mov     edx, dword ptr [rdi + 0xf8]
    0x4200000e513e (+0006)  8d 42 ff                                      lea     eax, [rdx - 1]
    0x4200000e5141 (+0009)  83 f8 01                                      cmp     eax, 1
    0x4200000e5144 (+000c)  0f 96 c0                                      setbe   al
    0x4200000e5147 (+000f)  83 ea 04                                      sub     edx, 4
    0x4200000e514a (+0012)  83 fa 01                                      cmp     edx, 1
    0x4200000e514d (+0015)  0f 96 c2                                      setbe   dl
    0x4200000e5150 (+0018)  09 d0                                         or      eax, edx
    0x4200000e5152 (+001a)  c3                                            ret
```

<!-- evidence:D04:end -->

本套没有给这四个内部数值全部补上未经核对的枚举名。类型 4 在后续 IOMMU 迭代器中有明确的 PCIe-to-PCI 专门处理调用，见 [05](05-domain-lifecycle.md#6-为什么会出现没有实际-function-的代理地址)。

## 4 复位与多功能描述如何改变结果

<!-- evidence:D05:begin -->

### 切片 D05 独立复位方法的位运算

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_HasFuncIndependentReset`；入口 `0x4200000fc5f0`，函数大小 `26` 字节。
- 窗口：`0x4200000fc5f0` 到 `0x4200000fc60a`（右端不含）；文件偏移 `0x3bb5f0`；8 条指令。
- 窗口 SHA-256：`73748866fe9ab41eba417a51bb260aa1ff6903ab825973242c74a9ed25e46fb6`。[单独查看汇编](snippets/D05.asm)

```asm
    0x4200000fc5f0 (+0000)  48 83 ec 08                                   sub     rsp, 8
    0x4200000fc5f4 (+0004)  e8 57 fe ff ff                                call    0x4200000fc450 ; directSymbol -> PCI_FindResetMethod
    0x4200000fc5f9 (+0009)  83 e0 fb                                      and     eax, 0xfffffffb
    0x4200000fc5fc (+000c)  83 e8 01                                      sub     eax, 1
    0x4200000fc5ff (+000f)  83 f8 01                                      cmp     eax, 1
    0x4200000fc602 (+0012)  0f 96 c0                                      setbe   al
    0x4200000fc605 (+0015)  48 83 c4 08                                   add     rsp, 8
    0x4200000fc609 (+0019)  c3                                            ret
```

<!-- evidence:D05:end -->

独立复位谓词实际上是 `((method & ~4) - 1) <= 1` 的无符号判断。对于该选择函数产生的枚举，它接受 1、2、5、6，不接受 link/bridge。复位选择过程和 map 如何改变 method，见 [06](06-reset-map-acs.md)。

<!-- evidence:D06:begin -->

### 切片 D06 PCIe endpoint 类型判定

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_IsPCIeEndpointDevice`；入口 `0x4200000eb43c`，函数大小 `37` 字节。
- 窗口：`0x4200000eb43c` 到 `0x4200000eb461`（右端不含）；文件偏移 `0x3aa43c`；11 条指令。
- 窗口 SHA-256：`2e262c4111ac433f54191c16c79242c59dfdafd9cd2786220c1c3eb1388b8b47`。[单独查看汇编](snippets/D06.asm)

```asm
    0x4200000eb43c (+0000)  48 83 ec 18                                   sub     rsp, 0x18
    0x4200000eb440 (+0004)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000eb445 (+0009)  e8 ae ad 00 00                                call    0x4200000f61f8 ; directSymbol -> PCIE_GetPortType
    0x4200000eb44a (+000e)  41 89 c0                                      mov     r8d, eax
    0x4200000eb44d (+0011)  31 c0                                         xor     eax, eax
    0x4200000eb44f (+0013)  45 85 c0                                      test    r8d, r8d
    0x4200000eb452 (+0016)  75 08                                         jne     0x4200000eb45c
    0x4200000eb454 (+0018)  83 7c 24 0c 01                                cmp     dword ptr [rsp + 0xc], 1
    0x4200000eb459 (+001d)  0f 96 c0                                      setbe   al
    0x4200000eb45c (+0020)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000eb460 (+0024)  c3                                            ret
```

<!-- evidence:D06:end -->

PCIe endpoint 判断要求 `PCIE_GetPortType` 成功，并且类型值不大于 1。它不是一个泛泛的“有 PCIe capability 就算 endpoint”判断。

在 `G != 1` 的复位检查分支中，结合已有实验可作下列受限对应：

| 条件 | 本路径会发生什么 | 对应观察 |
| --- | --- | --- |
| PCIe endpoint，不能独立复位，当前 Function 的多功能位为 1 | 纳入父设备代表 | 两项描述完整后共同依赖 root port |
| 相同 endpoint，但 Function 1 的多功能位为 0，且无其他依赖 | 可能保留自身代表 | 早期 Function 1 被识别为自身依赖 |
| 显式多功能依赖字段为 1 | 即使有独立复位，也纳入父设备候选 | 不能用 FLR 抹掉已声明功能依赖 |
| 上游有 aliasing bridge | 请求者候选扩大到该桥 | 传统桥实例共同代表为 `01:00.0` |

这些是代码条件与既有受控描述的对应，不是所有真实多口网卡都必然具有相同结果。

## 5 四字段 VSI 输出与 packed SBDF

<!-- evidence:A05:begin -->

### 切片 A05 内核状态转为四字段 SBDF

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`Hardware_PCIPassthruDependentGet`；入口 `0x420000072288`，函数大小 `131` 字节。
- 窗口：`0x420000072288` 到 `0x42000007230b`（右端不含）；文件偏移 `0x331288`；44 条指令。
- 窗口 SHA-256：`21ba16e89ca8f023dc9618728d2a3eb9722244aa22e91fc9cfa326d3dcacb993`。[单独查看汇编](snippets/A05.asm)

```asm
    0x420000072288 (+0000)  41 54                                         push    r12
    0x42000007228a (+0002)  48 89 f7                                      mov     rdi, rsi
    0x42000007228d (+0005)  53                                            push    rbx
    0x42000007228e (+0006)  48 89 d3                                      mov     rbx, rdx
    0x420000072291 (+0009)  48 83 ec 18                                   sub     rsp, 0x18
    0x420000072295 (+000d)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x42000007229a (+0012)  e8 b1 fc ff ff                                call    0x420000071f50 ; directSymbol -> Hardware_PCIGetDevFromInstArgs
    0x42000007229f (+0017)  41 89 c4                                      mov     r12d, eax
    0x4200000722a2 (+001a)  85 c0                                         test    eax, eax
    0x4200000722a4 (+001c)  74 0b                                         je      0x4200000722b1
    0x4200000722a6 (+001e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000722aa (+0022)  44 89 e0                                      mov     eax, r12d
    0x4200000722ad (+0025)  5b                                            pop     rbx
    0x4200000722ae (+0026)  41 5c                                         pop     r12
    0x4200000722b0 (+0028)  c3                                            ret
    0x4200000722b1 (+0029)  48 8b 7c 24 08                                mov     rdi, qword ptr [rsp + 8]
    0x4200000722b6 (+002e)  48 8d 74 24 04                                lea     rsi, [rsp + 4]
    0x4200000722bb (+0033)  e8 78 eb 12 00                                call    0x4200001a0e38 ; directSymbol -> VMKPCIPassthru_GetDeviceDependencies
    0x4200000722c0 (+0038)  85 c0                                         test    eax, eax
    0x4200000722c2 (+003a)  74 1a                                         je      0x4200000722de
    0x4200000722c4 (+003c)  48 c7 03 ff ff ff ff                          mov     qword ptr [rbx], 0xffffffffffffffff
    0x4200000722cb (+0043)  44 89 e0                                      mov     eax, r12d
    0x4200000722ce (+0046)  48 c7 43 08 ff ff ff ff                       mov     qword ptr [rbx + 8], 0xffffffffffffffff
    0x4200000722d6 (+004e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000722da (+0052)  5b                                            pop     rbx
    0x4200000722db (+0053)  41 5c                                         pop     r12
    0x4200000722dd (+0055)  c3                                            ret
    0x4200000722de (+0056)  8b 44 24 04                                   mov     eax, dword ptr [rsp + 4]
    0x4200000722e2 (+005a)  89 c2                                         mov     edx, eax
    0x4200000722e4 (+005c)  c1 ea 10                                      shr     edx, 0x10
    0x4200000722e7 (+005f)  89 13                                         mov     dword ptr [rbx], edx
    0x4200000722e9 (+0061)  0f b6 d4                                      movzx   edx, ah
    0x4200000722ec (+0064)  89 53 04                                      mov     dword ptr [rbx + 4], edx
    0x4200000722ef (+0067)  89 c2                                         mov     edx, eax
    0x4200000722f1 (+0069)  83 e0 07                                      and     eax, 7
    0x4200000722f4 (+006c)  c1 ea 03                                      shr     edx, 3
    0x4200000722f7 (+006f)  89 43 0c                                      mov     dword ptr [rbx + 0xc], eax
    0x4200000722fa (+0072)  44 89 e0                                      mov     eax, r12d
    0x4200000722fd (+0075)  83 e2 1f                                      and     edx, 0x1f
    0x420000072300 (+0078)  89 53 08                                      mov     dword ptr [rbx + 8], edx
    0x420000072303 (+007b)  48 83 c4 18                                   add     rsp, 0x18
    0x420000072307 (+007f)  5b                                            pop     rbx
    0x420000072308 (+0080)  41 5c                                         pop     r12
    0x42000007230a (+0082)  c3                                            ret
```

<!-- evidence:A05:end -->

内核函数输出的 packed 值在这里拆为 segment、bus、slot、function 四个 32 位字段。失败时写两个全一 64 位值，也就是 16 字节无效哨兵。A01 读取的是这个四字段结果，而开机登记循环比较的是 packed 值。

因此本例同时存在：设备地址 `02:01.0/02:01.1`、依赖代表 `01:00.0`、IOMMU 代理身份 `02:00.0`。它们分别用于设备定位、共同处理范围和实际 DMA 身份，不能用一个字段替代全部三者。
