# 04 VM 开机登记的详细检查

这里的“登记”是设备进入 VM 运行使用的后端路径，不等于把一个引用保存到 VM 配置。接口允许保存两个不同 BDF，仍可能在这些分支里拒绝启动。

## 1 最外层登记包装先检查内存状态

<!-- evidence:R01:begin -->

### 切片 R01 VM 内存前提与普通登记入口

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDevice`；入口 `0x9a50`，函数大小 `299` 字节。
- 窗口：`0x9a50` 到 `0x9abb`（右端不含）；文件偏移 `0x9a90`；30 条指令。
- 窗口 SHA-256：`cd09024d0f467a61cea26f0a174572a379643f3e600e7182c64589dcf444b301`。[单独查看汇编](snippets/R01.asm)

```asm
            0x9a50 (+0000)  41 56                                         push    r14
            0x9a52 (+0002)  49 89 fe                                      mov     r14, rdi
            0x9a55 (+0005)  41 55                                         push    r13
            0x9a57 (+0007)  41 54                                         push    r12
            0x9a59 (+0009)  49 89 d4                                      mov     r12, rdx
            0x9a5c (+000c)  55                                            push    rbp
            0x9a5d (+000d)  89 f5                                         mov     ebp, esi
            0x9a5f (+000f)  48 83 ec 08                                   sub     rsp, 8
            0x9a63 (+0013)  65 48 8b 3c 25 10 00 00 00                    mov     rdi, qword ptr gs:[0x10]
            0x9a6c (+001c)  e8 00 00 00 00                                call    0x9a71 ; REL type=2 MemSched_GetVmMemInfo A=-4
            0x9a71 (+0021)  80 78 02 00                                   cmp     byte ptr [rax + 2], 0
            0x9a75 (+0025)  0f 84 9d 00 00 00                             je      0x9b18 ; branch leaves this window
            0x9a7b (+002b)  65 48 8b 3c 25 10 00 00 00                    mov     rdi, qword ptr gs:[0x10]
            0x9a84 (+0034)  e8 00 00 00 00                                call    0x9a89 ; REL type=2 MemSched_GetVmMemInfo A=-4
            0x9a89 (+0039)  80 38 00                                      cmp     byte ptr [rax], 0
            0x9a8c (+003c)  0f 84 86 00 00 00                             je      0x9b18 ; branch leaves this window
            0x9a92 (+0042)  49 c7 c1 ff ff ff ff                          mov     r9, 0xffffffffffffffff
            0x9a99 (+0049)  4d 85 f6                                      test    r14, r14
            0x9a9c (+004c)  78 1d                                         js      0x9abb ; branch leaves this window
            0x9a9e (+004e)  48 83 c4 08                                   add     rsp, 8
            0x9aa2 (+0052)  4c 89 e2                                      mov     rdx, r12
            0x9aa5 (+0055)  89 ee                                         mov     esi, ebp
            0x9aa7 (+0057)  44 89 f7                                      mov     edi, r14d
            0x9aaa (+005a)  5d                                            pop     rbp
            0x9aab (+005b)  45 31 c0                                      xor     r8d, r8d
            0x9aae (+005e)  41 5c                                         pop     r12
            0x9ab0 (+0060)  31 c9                                         xor     ecx, ecx
            0x9ab2 (+0062)  41 5d                                         pop     r13
            0x9ab4 (+0064)  41 5e                                         pop     r14
            0x9ab6 (+0066)  e9 b1 b0 ff ff                                jmp     0x4b6c ; directSymbol -> PCIPassthruRegisterDeviceInt; branch leaves this window
```

<!-- evidence:R01:end -->

两个关键检查分别读取 `MemSched_GetVmMemInfo` 返回对象的字节 `+2` 与 `+0`。任一个为零都会去 `0x9b18`。本套保留它们为两个内存前提字段；仅凭失败日志列出的名称，不能无额外字段定义就逐个给偏移强行命名。

普通物理 PCI 请求继续到 `jmp 0x4b6c`，即 `PCIPassthruRegisterDeviceInt`。RDI 高位标识的设备组件请求另有分支，不能拿普通 FPT 解释所有设备模式。

<!-- evidence:R02:begin -->

### 切片 R02 内存前提失败的返回

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDevice`；入口 `0x9a50`，函数大小 `299` 字节。
- 窗口：`0x9b18` 到 `0x9b3c`（右端不含）；文件偏移 `0x9b58`；11 条指令。
- 窗口 SHA-256：`938449fb9f384ee915bc9ebbb36259051bf077084b5f6b9387ed3bb579bee4a2`。[单独查看汇编](snippets/R02.asm)

```asm
            0x9b18 (+00c8)  31 c0                                         xor     eax, eax
            0x9b1a (+00ca)  be 28 15 00 00                                mov     esi, 0x1528
            0x9b1f (+00cf)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC108 A=-4 "PCIPassthru: %d: PCI Passthru requires pinnedMainMem and preallocGuestMem\n"
            0x9b26 (+00d6)  e8 00 00 00 00                                call    0x9b2b ; REL type=2 _Log A=-4
            0x9b2b (+00db)  b8 20 00 ad 0b                                mov     eax, 0xbad0020
            0x9b30 (+00e0)  48 83 c4 08                                   add     rsp, 8
            0x9b34 (+00e4)  5d                                            pop     rbp
            0x9b35 (+00e5)  41 5c                                         pop     r12
            0x9b37 (+00e7)  41 5d                                         pop     r13
            0x9b39 (+00e9)  41 5e                                         pop     r14
            0x9b3b (+00eb)  c3                                            ret
```

<!-- evidence:R02:end -->

该失败路径的格式字符串对应 `pinnedMainMem` 和 `preallocGuestMem`，随后选择 `0x0bad0020` 返回。它证明内部前提存在，但不提供 UI 内存字段到这些内部字节的完整生成逻辑。

## 2 IOMMU 条件和模式回调

<!-- evidence:R03:begin -->

### 切片 R03 IOMMU 与模式回调前置检查

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4b6c`，函数大小 `3720` 字节。
- 窗口：`0x4b6c` 到 `0x4c52`（右端不含）；文件偏移 `0x4bac`；55 条指令。
- 窗口 SHA-256：`c1fe02ace603ab267926f4b270d34b68134302b5f7344a506abe4a6839ef199a`。[单独查看汇编](snippets/R03.asm)

```asm
            0x4b6c (+0000)  41 57                                         push    r15
            0x4b6e (+0002)  41 56                                         push    r14
            0x4b70 (+0004)  41 55                                         push    r13
            0x4b72 (+0006)  41 bd 20 00 ad 0b                             mov     r13d, 0xbad0020
            0x4b78 (+000c)  41 54                                         push    r12
            0x4b7a (+000e)  55                                            push    rbp
            0x4b7b (+000f)  53                                            push    rbx
            0x4b7c (+0010)  48 81 ec 88 00 00 00                          sub     rsp, 0x88
            0x4b83 (+0017)  48 89 4c 24 18                                mov     qword ptr [rsp + 0x18], rcx
            0x4b88 (+001c)  44 89 04 24                                   mov     dword ptr [rsp], r8d
            0x4b8c (+0020)  4c 89 4c 24 08                                mov     qword ptr [rsp + 8], r9
            0x4b91 (+0025)  65 4c 8b 34 25 10 00 00 00                    mov     r14, qword ptr gs:[0x10]
            0x4b9a (+002e)  83 fe 04                                      cmp     esi, 4
            0x4b9d (+0031)  0f 87 c9 01 00 00                             ja      0x4d6c ; branch leaves this window
            0x4ba3 (+0037)  89 fb                                         mov     ebx, edi
            0x4ba5 (+0039)  41 89 f7                                      mov     r15d, esi
            0x4ba8 (+003c)  49 89 d4                                      mov     r12, rdx
            0x4bab (+003f)  e8 00 00 00 00                                call    0x4bb0 ; REL type=2 IOMMU_IsIommuEnabled A=-4
            0x4bb0 (+0044)  84 c0                                         test    al, al
            0x4bb2 (+0046)  0f 84 15 07 00 00                             je      0x52cd ; branch leaves this window
            0x4bb8 (+004c)  89 df                                         mov     edi, ebx
            0x4bba (+004e)  e8 00 00 00 00                                call    0x4bbf ; REL type=2 PCI_GetDevice A=-4
            0x4bbf (+0053)  48 89 44 24 10                                mov     qword ptr [rsp + 0x10], rax
            0x4bc4 (+0058)  48 85 c0                                      test    rax, rax
            0x4bc7 (+005b)  0f 84 c8 01 00 00                             je      0x4d95 ; branch leaves this window
            0x4bcd (+0061)  89 df                                         mov     edi, ebx
            0x4bcf (+0063)  e8 00 00 00 00                                call    0x4bd4 ; REL type=2 IOMMU_IsDeviceSupported A=-4
            0x4bd4 (+0068)  84 c0                                         test    al, al
            0x4bd6 (+006a)  0f 84 c9 08 00 00                             je      0x54a5 ; branch leaves this window
            0x4bdc (+0070)  49 8b 86 98 1a 00 00                          mov     rax, qword ptr [r14 + 0x1a98]
            0x4be3 (+0077)  48 8b 80 f0 26 00 00                          mov     rax, qword ptr [rax + 0x26f0]
            0x4bea (+007e)  48 89 44 24 20                                mov     qword ptr [rsp + 0x20], rax
            0x4bef (+0083)  48 85 c0                                      test    rax, rax
            0x4bf2 (+0086)  74 13                                         je      0x4c07
            0x4bf4 (+0088)  48 8d 35 00 00 00 00                          lea     rsi, [rip]
            0x4bfb (+008f)  48 8d b8 78 02 00 00                          lea     rdi, [rax + 0x278]
            0x4c02 (+0096)  e8 00 00 00 00                                call    0x4c07 ; REL type=2 Mutex_LockWithRA A=-4
            0x4c07 (+009b)  44 89 f9                                      mov     ecx, r15d
            0x4c0a (+009e)  48 8d 15 00 00 00 00                          lea     rdx, [rip] ; REL type=2 section#8 A=156
            0x4c11 (+00a5)  48 8d 04 cd 00 00 00 00                       lea     rax, [rcx*8]
            0x4c19 (+00ad)  48 89 4c 24 30                                mov     qword ptr [rsp + 0x30], rcx
            0x4c1e (+00b2)  48 29 c8                                      sub     rax, rcx
            0x4c21 (+00b5)  48 8b 04 c2                                   mov     rax, qword ptr [rdx + rax*8]
            0x4c25 (+00b9)  48 85 c0                                      test    rax, rax
            0x4c28 (+00bc)  74 15                                         je      0x4c3f
            0x4c2a (+00be)  4c 89 e2                                      mov     rdx, r12
            0x4c2d (+00c1)  89 de                                         mov     esi, ebx
            0x4c2f (+00c3)  4c 89 f7                                      mov     rdi, r14
            0x4c32 (+00c6)  ff d0                                         call    rax
            0x4c34 (+00c8)  41 89 c5                                      mov     r13d, eax
            0x4c37 (+00cb)  85 c0                                         test    eax, eax
            0x4c39 (+00cd)  0f 85 1c 01 00 00                             jne     0x4d5b ; branch leaves this window
            0x4c3f (+00d3)  48 8d 05 00 00 00 00                          lea     rax, [rip]
            0x4c46 (+00da)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x4c4d (+00e1)  e8 00 00 00 00                                call    0x4c52 ; REL type=2 SPLockWork A=-4
```

<!-- evidence:R03:end -->

入口先限制模式编号，再检查 IOMMU 已启用、设备存在、设备被 IOMMU 支持。`mode*8-mode` 再乘 8，构成每项 56 字节的分发表访问；表项非空才间接调用。

| 模式索引 | 表内偏移 | 原始槽值 | 重定位目标 |
| --- | --- | --- | --- |
| 0 | 0x0 | 0x0 | PCIPassthruFPTAllowPassthru |
| 1 | 0x38 | 0x0 | 空回调 |
| 2 | 0x70 | 0x0 | PCIPassthruMPTAllowPassthru |
| 3 | 0xa8 | 0x0 | PCIPassthruMPTAllowPassthru |
| 4 | 0xe0 | 0x0 | 空回调 |

普通 FPT 索引 0 的前置回调解析为 `PCIPassthruFPTAllowPassthru`。其他索引存在不同回调或空槽；本套不把一个分支扩成所有 passthrough 模式的统一规范。

随后出现 `pcipCfgLock` 与 `SPLockWork`。锁的存在支持所见登记表操作有局部同步；它不证明主机配置联动、多个设备初始化及集群调度形成一个端到端原子事务。

## 3 FPT 前置检查宿主是否已交出相关端点

<!-- evidence:R04:begin -->

### 切片 R04 依赖桥展开与宿主 owner 检查

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruFPTAllowPassthru`；入口 `0x2548`，函数大小 `604` 字节。
- 窗口：`0x255e` 到 `0x263e`（右端不含）；文件偏移 `0x259e`；54 条指令。
- 窗口 SHA-256：`b638c2c92527727806b7b91e255176c18f49c8b20f56722bd933388e2926e6d3`。[单独查看汇编](snippets/R04.asm)

```asm
            0x255e (+0016)  e8 00 00 00 00                                call    0x2563 ; REL type=2 PCI_GetDevice A=-4
            0x2563 (+001b)  48 85 c0                                      test    rax, rax
            0x2566 (+001e)  0f 84 c2 01 00 00                             je      0x272e ; branch leaves this window
            0x256c (+0024)  48 8d 74 24 18                                lea     rsi, [rsp + 0x18]
            0x2571 (+0029)  48 89 c7                                      mov     rdi, rax
            0x2574 (+002c)  49 89 c4                                      mov     r12, rax
            0x2577 (+002f)  e8 00 00 00 00                                call    0x257c ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x257c (+0034)  41 89 c5                                      mov     r13d, eax
            0x257f (+0037)  85 c0                                         test    eax, eax
            0x2581 (+0039)  0f 85 3d 01 00 00                             jne     0x26c4 ; branch leaves this window
            0x2587 (+003f)  8b 7c 24 18                                   mov     edi, dword ptr [rsp + 0x18]
            0x258b (+0043)  41 39 3c 24                                   cmp     dword ptr [r12], edi
            0x258f (+0047)  0f 84 18 01 00 00                             je      0x26ad ; branch leaves this window
            0x2595 (+004d)  e8 00 00 00 00                                call    0x259a ; REL type=2 PCI_GetDevice A=-4
            0x259a (+0052)  48 89 c7                                      mov     rdi, rax
            0x259d (+0055)  48 89 c3                                      mov     rbx, rax
            0x25a0 (+0058)  e8 00 00 00 00                                call    0x25a5 ; REL type=2 PCI_GetDeviceCountUnderBridge A=-4
            0x25a5 (+005d)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 passthruHeap A=-4
            0x25ac (+0064)  8d 34 c5 00 00 00 00                          lea     esi, [rax*8]
            0x25b3 (+006b)  41 89 c7                                      mov     r15d, eax
            0x25b6 (+006e)  e8 00 00 00 00                                call    0x25bb ; REL type=2 Heap_Alloc A=-4
            0x25bb (+0073)  48 89 44 24 08                                mov     qword ptr [rsp + 8], rax
            0x25c0 (+0078)  48 85 c0                                      test    rax, rax
            0x25c3 (+007b)  0f 84 a1 01 00 00                             je      0x276a ; branch leaves this window
            0x25c9 (+0081)  48 8b 54 24 08                                mov     rdx, qword ptr [rsp + 8]
            0x25ce (+0086)  48 89 df                                      mov     rdi, rbx
            0x25d1 (+0089)  44 89 fe                                      mov     esi, r15d
            0x25d4 (+008c)  e8 00 00 00 00                                call    0x25d9 ; REL type=2 PCI_GetDevicesUnderBridge A=-4
            0x25d9 (+0091)  89 c3                                         mov     ebx, eax
            0x25db (+0093)  85 c0                                         test    eax, eax
            0x25dd (+0095)  0f 85 92 01 00 00                             jne     0x2775 ; branch leaves this window
            0x25e3 (+009b)  45 85 ff                                      test    r15d, r15d
            0x25e6 (+009e)  7e 36                                         jle     0x261e
            0x25e8 (+00a0)  48 8b 4c 24 08                                mov     rcx, qword ptr [rsp + 8]
            0x25ed (+00a5)  41 8d 47 ff                                   lea     eax, [r15 - 1]
            0x25f1 (+00a9)  48 89 cb                                      mov     rbx, rcx
            0x25f4 (+00ac)  4c 8d 7c c1 08                                lea     r15, [rcx + rax*8 + 8]
            0x25f9 (+00b1)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
            0x25fc (+00b4)  48 85 ff                                      test    rdi, rdi
            0x25ff (+00b7)  74 06                                         je      0x2607
            0x2601 (+00b9)  f6 47 04 02                                   test    byte ptr [rdi + 4], 2
            0x2605 (+00bd)  75 0e                                         jne     0x2615
            0x2607 (+00bf)  e8 00 00 00 00                                call    0x260c ; REL type=2 PCI_GetDeviceOwnership A=-4
            0x260c (+00c4)  83 f8 01                                      cmp     eax, 1
            0x260f (+00c7)  0f 85 79 01 00 00                             jne     0x278e ; branch leaves this window
            0x2615 (+00cd)  48 83 c3 08                                   add     rbx, 8
            0x2619 (+00d1)  49 39 df                                      cmp     r15, rbx
            0x261c (+00d4)  75 db                                         jne     0x25f9
            0x261e (+00d6)  48 8b 74 24 08                                mov     rsi, qword ptr [rsp + 8]
            0x2623 (+00db)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 passthruHeap A=-4
            0x262a (+00e2)  e8 00 00 00 00                                call    0x262f ; REL type=2 Heap_Free A=-4
            0x262f (+00e7)  be 26 00 00 00                                mov     esi, 0x26
            0x2634 (+00ec)  48 8d 7c 24 18                                lea     rdi, [rsp + 0x18]
            0x2639 (+00f1)  e8 00 00 00 00                                call    0x263e ; REL type=2 HostID_GetString A=-4
```

<!-- evidence:R04:end -->

目标代表不同于自身时，代码取得代表对象，计算桥下设备数，分配数组，再调用 `PCI_GetDevicesUnderBridge`。循环对需要检查的对象调用 `PCI_GetDeviceOwnership`，并要求结果等于 1。结构标志为桥的对象有跳过分支，因此不要改写成“数组里每个节点都必须无条件 owner=1”。

<!-- evidence:R05:begin -->

### 切片 R05 无外部代表时检查自身 owner

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruFPTAllowPassthru`；入口 `0x2548`，函数大小 `604` 字节。
- 窗口：`0x26ad` 到 `0x26c4`（右端不含）；文件偏移 `0x26ed`；5 条指令。
- 窗口 SHA-256：`609e753bf9c9188ab8177f0748182c3121f30faa5d3eaa98ff2773fe9ba09472`。[单独查看汇编](snippets/R05.asm)

```asm
            0x26ad (+0165)  4c 89 e7                                      mov     rdi, r12
            0x26b0 (+0168)  e8 00 00 00 00                                call    0x26b5 ; REL type=2 PCI_GetDeviceOwnership A=-4
            0x26b5 (+016d)  83 f8 01                                      cmp     eax, 1
            0x26b8 (+0170)  0f 84 71 ff ff ff                             je      0x262f ; branch leaves this window
            0x26be (+0176)  41 bd 20 00 ad 0b                             mov     r13d, 0xbad0020
```

<!-- evidence:R05:end -->

代表等于自身时仅检查目标自身。失败分支选择 `0x0bad0020`，后续日志描述未启用直通。这里的内核 owner=1 与 [03 中管理库配置枚举](03-owner-transitions.md#6-配置具体写到哪里)不是同一套枚举。

## 4 身份检查也有具体前提和例外

<!-- evidence:R06:begin -->

### 切片 R06 宿主身份与非零 VID DID 条件

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruFPTAllowPassthru`；入口 `0x2548`，函数大小 `604` 字节。
- 窗口：`0x263e` 到 `0x269b`（右端不含）；文件偏移 `0x267e`；24 条指令。
- 窗口 SHA-256：`70b8ba448bd4ff18c7de689bd38a6dd5cb45c6ee6f57fad5c80255db1f77af52`。[单独查看汇编](snippets/R06.asm)

```asm
            0x263e (+00f6)  48 8d 4d 08                                   lea     rcx, [rbp + 8]
            0x2642 (+00fa)  31 c0                                         xor     eax, eax
            0x2644 (+00fc)  ba 42 00 00 00                                mov     edx, 0x42
            0x2649 (+0101)  48 8d 35 00 00 00 00                          lea     rsi, [rip] ; REL type=2 .LC17 A=-4 "BYPASS"
            0x2650 (+0108)  eb 04                                         jmp     0x2656
            0x2652 (+010a)  0f b6 14 06                                   movzx   edx, byte ptr [rsi + rax]
            0x2656 (+010e)  38 54 05 08                                   cmp     byte ptr [rbp + rax + 8], dl
            0x265a (+0112)  0f 85 97 00 00 00                             jne     0x26f7 ; branch leaves this window
            0x2660 (+0118)  84 d2                                         test    dl, dl
            0x2662 (+011a)  74 0a                                         je      0x266e
            0x2664 (+011c)  48 83 c0 01                                   add     rax, 1
            0x2668 (+0120)  48 83 f8 06                                   cmp     rax, 6
            0x266c (+0124)  75 e4                                         jne     0x2652
            0x266e (+0126)  0f b7 45 2e                                   movzx   eax, word ptr [rbp + 0x2e]
            0x2672 (+012a)  66 41 39 44 24 0e                             cmp     word ptr [r12 + 0xe], ax
            0x2678 (+0130)  74 09                                         je      0x2683
            0x267a (+0132)  66 85 c0                                      test    ax, ax
            0x267d (+0135)  0f 85 a0 00 00 00                             jne     0x2723 ; branch leaves this window
            0x2683 (+013b)  0f b7 45 30                                   movzx   eax, word ptr [rbp + 0x30]
            0x2687 (+013f)  66 41 39 44 24 0c                             cmp     word ptr [r12 + 0xc], ax
            0x268d (+0145)  74 0c                                         je      0x269b ; branch leaves this window
            0x268f (+0147)  66 85 c0                                      test    ax, ax
            0x2692 (+014a)  b8 07 00 ad 0b                                mov     eax, 0xbad0007
            0x2697 (+014f)  44 0f 45 e8                                   cmovne  r13d, eax
```

<!-- evidence:R06:end -->

可以直接看到 `HostID_GetString` 的结果参与字符串比较，以及请求中非零 VID/DID 与设备字段的比较。零值有例外分支，宿主身份也存在一个特殊字面量分支。

这些是内部调用约定的静态事实，不代表已确认普通用户可通过某个 UI 或 VMX 字段任意绕过它。本文不把内部例外输入写成配置建议。

## 5 同一个依赖代表为什么排斥另一台 VM

先看当前设备和 owner 标识怎样进入局部寄存器：

<!-- evidence:R07:begin -->

### 切片 R07 按 SBDF 取记录和当前 owner 标识

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4b6c`，函数大小 `3720` 字节。
- 窗口：`0x4c7d` 到 `0x4cda`（右端不含）；文件偏移 `0x4cbd`；19 条指令。
- 窗口 SHA-256：`ffd7f5fcfe27a241e1d00c1f74683cfe7e8eb145347ef847d0ca11896a639ef1`。[单独查看汇编](snippets/R07.asm)

```asm
            0x4c7d (+0111)  48 8b 44 24 10                                mov     rax, qword ptr [rsp + 0x10]
            0x4c82 (+0116)  48 8b 54 24 28                                mov     rdx, qword ptr [rsp + 0x28]
            0x4c87 (+011b)  48 c7 44 24 70 00 00 00 00                    mov     qword ptr [rsp + 0x70], 0
            0x4c90 (+0124)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 pcipDevTable A=-4
            0x4c97 (+012b)  44 8b 28                                      mov     r13d, dword ptr [rax]
            0x4c9a (+012e)  49 8b 86 98 1a 00 00                          mov     rax, qword ptr [r14 + 0x1a98]
            0x4ca1 (+0135)  44 89 ee                                      mov     esi, r13d
            0x4ca4 (+0138)  8b 68 08                                      mov     ebp, dword ptr [rax + 8]
            0x4ca7 (+013b)  e8 00 00 00 00                                call    0x4cac ; REL type=2 PCISbdfMap_Find A=-4
            0x4cac (+0140)  84 c0                                         test    al, al
            0x4cae (+0142)  0f 84 cd 00 00 00                             je      0x4d81 ; branch leaves this window
            0x4cb4 (+0148)  41 80 7c 24 03 00                             cmp     byte ptr [r12 + 3], 0
            0x4cba (+014e)  0f 84 a4 06 00 00                             je      0x5364 ; branch leaves this window
            0x4cc0 (+0154)  48 8b 44 24 70                                mov     rax, qword ptr [rsp + 0x70]
            0x4cc5 (+0159)  4c 8b 68 10                                   mov     r13, qword ptr [rax + 0x10]
            0x4cc9 (+015d)  4d 85 ed                                      test    r13, r13
            0x4ccc (+0160)  0f 84 07 01 00 00                             je      0x4dd9 ; branch leaves this window
            0x4cd2 (+0166)  41 80 7c 24 04 00                             cmp     byte ptr [r12 + 4], 0
            0x4cd8 (+016c)  74 2c                                         je      0x4d06 ; branch leaves this window
```

<!-- evidence:R07:end -->

`PCISbdfMap_Find` 按设备地址查表。当前 world 链上的一个 32 位标识保存到 EBP，稍后拷贝到 R13D；所查对象中的活动登记指针在另一字段。这是两个不同层次的 owner：宿主是否启用直通，以及活动登记属于哪个 VMM。

现有同 BDF 活动记录还会进入额外标志或迁移相关分支；R07 给的是入口上下文，没有把这些分支简化成“同 VM 就能重复登记同一个设备”。下面 R08 聚焦不同 BDF 共享代表的检查。

下面是共同代表与 owner 比较的完整循环：

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

关键分支的逐段含义：

| 地址 | 直接判断 | 结果 |
| --- | --- | --- |
| `0x4df6`、`0x4e41` | 对目标及枚举对象分别计算依赖代表 | 获取两个 packed SBDF |
| `0x4e4e` | 比较两个 32 位代表 | 不相等跳 `0x4e29`，继续下一设备 |
| `0x4e62` | 按当前枚举设备的 SBDF 查询登记表 | 后面检查输出对象是否为空 |
| `0x4e71` | 读取输出对象中的活动登记指针 | 空则继续 |
| `0x4e7a` | 检查登记条目的另一例外标志 | 置位则继续；本套不擅自给此标志命名 |
| `0x4e80` | 当前 VMM 标识与活动登记 `+0x70` 比较 | 相同跳回循环，允许继续 |
| `0x4e8b` | 不同 owner 路径选择 `0x0bad0004` | 跳向后续退出路径 |

所以这不是“两项 BDF 相同才冲突”。它先通过代表相等把不同 BDF 联系起来，再判断已有活动登记的 owner。也不是“第二个成员无条件失败”；同 owner 的这一关明确有继续分支。

说明性伪代码必须保留跳过项：

```text
for each other PCI object:
    if dependency_query(other) fails: continue
    if dep(other) != dep(target): continue
    record = lookup(other.sbdf)
    if output_record is null: continue
    if active_registration is null: continue
    if exception_flag != 0: continue
    if active_registration.owner_world == current_owner_world: continue
    return 0x0bad0004
```

当前所有者标识是 VMM/world 层值，不是 vCenter 的 VM 名称、UUID 或 managed-object ID。不同层的身份应分别记录。

## 6 RMRR 还有另一条拒绝路径

<!-- evidence:R09:begin -->

### 切片 R09 RMRR 重叠拒绝分支

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4b6c`，函数大小 `3720` 字节。
- 窗口：`0x5364` 到 `0x53bf`（右端不含）；文件偏移 `0x53a4`；22 条指令。
- 窗口 SHA-256：`3204f0068497bd758842d2ba0335097f2ac44ba21e82a94a062bce33d2694619`。[单独查看汇编](snippets/R09.asm)

```asm
            0x5364 (+07f8)  4c 89 f6                                      mov     rsi, r14
            0x5367 (+07fb)  44 89 ef                                      mov     edi, r13d
            0x536a (+07fe)  e8 00 00 00 00                                call    0x536f ; REL type=2 IOMMU_IsDeviceRMRROverlap A=-4
            0x536f (+0803)  84 c0                                         test    al, al
            0x5371 (+0805)  0f 84 49 f9 ff ff                             je      0x4cc0 ; branch leaves this window
            0x5377 (+080b)  45 89 e8                                      mov     r8d, r13d
            0x537a (+080e)  44 89 e8                                      mov     eax, r13d
            0x537d (+0811)  44 89 ea                                      mov     edx, r13d
            0x5380 (+0814)  45 89 e9                                      mov     r9d, r13d
            0x5383 (+0817)  41 c1 e8 03                                   shr     r8d, 3
            0x5387 (+081b)  0f b6 cc                                      movzx   ecx, ah
            0x538a (+081e)  c1 ea 10                                      shr     edx, 0x10
            0x538d (+0821)  41 83 e1 07                                   and     r9d, 7
            0x5391 (+0825)  41 83 e0 1f                                   and     r8d, 0x1f
            0x5395 (+0829)  be 32 10 00 00                                mov     esi, 0x1032
            0x539a (+082e)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC53 A=-4 "PCIPassthru: %d: Device %04x:%02x:%02x.%x cannot be used for passthrough because the host's BIOS ACPI RMRR structure indicates that the device DMAs to a host reserved memory region that conflicts with the VM's memory\n\n"
            0x53a1 (+0835)  31 c0                                         xor     eax, eax
            0x53a3 (+0837)  e8 00 00 00 00                                call    0x53a8 ; REL type=2 _Warning A=-4
            0x53a8 (+083c)  4c 8b 64 24 10                                mov     r12, qword ptr [rsp + 0x10]
            0x53ad (+0841)  41 bd 41 00 ad 0b                             mov     r13d, 0xbad0041
            0x53b3 (+0847)  49 81 c4 08 01 00 00                          add     r12, 0x108
            0x53ba (+084e)  e9 7a f9 ff ff                                jmp     0x4d39 ; branch leaves this window
```

<!-- evidence:R09:end -->

`IOMMU_IsDeviceRMRROverlap` 返回 false 时跳回正常路径 `0x4cc0`；为真时构造警告并选择 `0x0bad0041`。进入此分支还受更早的请求标志控制，R07 的 `cmp byte ptr [r12+3],0` 与跳转可以看到这一点。

这说明 `DevicePowerOn` 不是单一根因。相同的上层失败阶段，可能对应 owner 冲突、内存条件、RMRR、已有域或后续初始化失败。已有域拒绝链完整放在 [05](05-domain-lifecycle.md)。

## 7 与已有现场记录怎样对应

- 两台 VM 使用不同 BDF、共享代表，后启动者失败：与 R08 的跨 owner 拒绝相容。[PCIe 成功与冲突对照](../vmware-pci-multifunction-fix-20261111/README.md)
- 同一 VM 两项可以通过 owner 比较，却在域初始化失败：是后续另一关，不能归因于 R08 的“不同 VM”。[传统桥控制](../vmware-legacy-bridge-cause-20261112/README.md)
- 动态候选仍被发布却无法取得设备：这里只提供后端部分拒绝机制，尚未还原整个 Assignable Hardware 候选排序和选择器，不能声称它采用了某种完整 solver。
