# 05 同一 VM 仍失败的完整域状态证据链

这一章把三个问题逐项接起来：上层到底要求什么返回值；下层查询究竟读什么；初始化 A 为什么会改变 B 被查询到的状态。

## 1 上层只接受一个状态码

<!-- evidence:I01:begin -->

### 切片 I01 已有域拒绝条件及清理跳转

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4b6c`，函数大小 `3720` 字节。
- 窗口：`0x53bf` 到 `0x543c`（右端不含）；文件偏移 `0x53ff`；28 条指令。
- 窗口 SHA-256：`baed6153f7e9d414c9a3c2e85b56628a2623afb215bfbe7387eb3a7cee6eb7c7`。[单独查看汇编](snippets/I01.asm)

```asm
            0x53bf (+0853)  83 7c 24 58 01                                cmp     dword ptr [rsp + 0x58], 1
            0x53c4 (+0858)  0f 86 ff fc ff ff                             jbe     0x50c9 ; branch leaves this window
            0x53ca (+085e)  48 c7 44 24 70 00 00 00 00                    mov     qword ptr [rsp + 0x70], 0
            0x53d3 (+0867)  48 8b 74 24 28                                mov     rsi, qword ptr [rsp + 0x28]
            0x53d8 (+086c)  89 df                                         mov     edi, ebx
            0x53da (+086e)  e8 00 00 00 00                                call    0x53df ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x53df (+0873)  44 8b 54 24 40                                mov     r10d, dword ptr [rsp + 0x40]
            0x53e4 (+0878)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x53e9 (+087d)  89 c3                                         mov     ebx, eax
            0x53eb (+087f)  0f 84 d8 fc ff ff                             je      0x50c9 ; branch leaves this window
            0x53f1 (+0885)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x53f8 (+088c)  44 89 14 24                                   mov     dword ptr [rsp], r10d
            0x53fc (+0890)  e8 00 00 00 00                                call    0x5401 ; REL type=2 SP_Unlock A=-4
            0x5401 (+0895)  48 83 ec 08                                   sub     rsp, 8
            0x5405 (+0899)  44 89 ea                                      mov     edx, r13d
            0x5408 (+089c)  31 c0                                         xor     eax, eax
            0x540a (+089e)  53                                            push    rbx
            0x540b (+089f)  44 8b 54 24 10                                mov     r10d, dword ptr [rsp + 0x10]
            0x5410 (+08a4)  be ae 14 00 00                                mov     esi, 0x14ae
            0x5415 (+08a9)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC58 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x541c (+08b0)  44 8b 4c 24 58                                mov     r9d, dword ptr [rsp + 0x58]
            0x5421 (+08b5)  8b 4c 24 60                                   mov     ecx, dword ptr [rsp + 0x60]
            0x5425 (+08b9)  41 bd 05 00 ad 0b                             mov     r13d, 0xbad0005
            0x542b (+08bf)  45 89 d0                                      mov     r8d, r10d
            0x542e (+08c2)  e8 00 00 00 00                                call    0x5433 ; REL type=2 _Warning A=-4
            0x5433 (+08c7)  41 59                                         pop     r9
            0x5435 (+08c9)  41 5a                                         pop     r10
            0x5437 (+08cb)  e9 4e fd ff ff                                jmp     0x518a ; branch leaves this window
```

<!-- evidence:I01:end -->

`0x53da` 的外部调用由重定位明确指向 `IOMMU_GetAddressDomain`。紧接着 `cmp eax,0x0bad0003`；只有相等才跳 `0x50c9`。查询返回 0 时，继续走解锁、警告、设置 `0x0bad0005`、跳 `0x518a` 清理的路径。

切片开头还保留了 `0x53bf` 的例外跳转，说明并非函数所有模式都无条件执行这个查询。所分析普通 FPT 实验确实到达该警告；其他模式和特殊登记标志不能被这个片段概括。

| 查询返回 | 此检查点的结果 |
| --- | --- |
| `0x0bad0003` | 跳向正常后续路径 |
| `0` | 不匹配，警告并进入失败清理 |
| 其他值 | 同样不匹配；不能把全部其他码都称为“被另一 VM 占用” |

这里没有现有域是否属于当前 VM 的比较。与 [04 R08](04-vm-admission.md#5-同一个依赖代表为什么排斥另一台-vm) 的 owner 比较是两个不同检查点。

## 2 查询返回 Success 到底表示什么

<!-- evidence:I02:begin -->

### 切片 I02 域查询返回值的实际含义

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMU_GetAddressDomain`；入口 `0x42000016544c`，函数大小 `60` 字节。
- 窗口：`0x42000016544c` 到 `0x420000165488`（右端不含）；文件偏移 `0x42444c`；19 条指令。
- 窗口 SHA-256：`50d1111b38235829b3d3b1e7a02a90ad1d89332d8146adb4b9d65dd049d4b6c5`。[单独查看汇编](snippets/I02.asm)

```asm
    0x42000016544c (+0000)  53                                            push    rbx
    0x42000016544d (+0001)  48 89 f3                                      mov     rbx, rsi
    0x420000165450 (+0004)  e8 b7 5f f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000165455 (+0009)  48 89 c7                                      mov     rdi, rax
    0x420000165458 (+000c)  e8 5f ff ff ff                                call    0x4200001653bc ; directSymbol -> IOMMU_GetDeviceDomain
    0x42000016545d (+0011)  48 89 03                                      mov     qword ptr [rbx], rax
    0x420000165460 (+0014)  48 85 c0                                      test    rax, rax
    0x420000165463 (+0017)  74 11                                         je      0x420000165476
    0x420000165465 (+0019)  45 31 c0                                      xor     r8d, r8d
    0x420000165468 (+001c)  48 3b 05 f1 97 26 c0                          cmp     rax, qword ptr [rip - 0x3fd9680f] ; ripSymbol -> vmkDomain
    0x42000016546f (+0023)  74 05                                         je      0x420000165476
    0x420000165471 (+0025)  44 89 c0                                      mov     eax, r8d
    0x420000165474 (+0028)  5b                                            pop     rbx
    0x420000165475 (+0029)  c3                                            ret
    0x420000165476 (+002a)  41 b8 03 00 ad 0b                             mov     r8d, 0xbad0003
    0x42000016547c (+0030)  48 c7 03 00 00 00 00                          mov     qword ptr [rbx], 0
    0x420000165483 (+0037)  5b                                            pop     rbx
    0x420000165484 (+0038)  44 89 c0                                      mov     eax, r8d
    0x420000165487 (+003b)  c3                                            ret
```

<!-- evidence:I02:end -->

先查 PCI 对象，再调用 `IOMMU_GetDeviceDomain`。结果分为：

| 实际读到的指针 | 输出指针 | 返回值 |
| --- | --- | --- |
| NULL | NULL | `0x0bad0003` |
| 等于 `vmkDomain` | 被改为 NULL | `0x0bad0003` |
| 其他非 NULL 指针 | 保留该指针 | `0` |

所以“无域”是这个接口归一化后的语义，**不是证明硬件 VT-d context 完全不存在**。它把 VMkernel 域视作该查询意义上的“没有非 VMkernel 域”。反过来，返回 0 只证明存在非 VMkernel 域指针；本函数没有根据 VM ID 细分它属于谁。

## 3 查询读取的字段可以直接定位

<!-- evidence:I03:begin -->

### 切片 I03 域指针读取字段

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMU_GetDeviceDomain`；入口 `0x4200001653bc`，函数大小 `144` 字节。
- 窗口：`0x4200001653bc` 到 `0x42000016544c`（右端不含）；文件偏移 `0x4243bc`；43 条指令。
- 窗口 SHA-256：`c39141157f3c22bf0276e61b111f5f134c025c3652053efa9c57825a4df15473`。[单独查看汇编](snippets/I03.asm)

```asm
    0x4200001653bc (+0000)  41 54                                         push    r12
    0x4200001653be (+0002)  53                                            push    rbx
    0x4200001653bf (+0003)  48 89 fb                                      mov     rbx, rdi
    0x4200001653c2 (+0006)  48 83 ec 08                                   sub     rsp, 8
    0x4200001653c6 (+000a)  48 8d 05 00 00 00 00                          lea     rax, [rip]
    0x4200001653cd (+0011)  48 8d 3d 80 98 26 c0                          lea     rdi, [rip - 0x3fd96780] ; ripSymbol -> IOMMUDomainLock
    0x4200001653d4 (+0018)  e8 ef fe 01 00                                call    0x4200001852c8 ; directSymbol -> SPLockWork
    0x4200001653d9 (+001d)  48 85 db                                      test    rbx, rbx
    0x4200001653dc (+0020)  74 69                                         je      0x420000165447
    0x4200001653de (+0022)  4c 8b a3 78 03 00 00                          mov     r12, qword ptr [rbx + 0x378]
    0x4200001653e5 (+0029)  48 8d 3d 68 98 26 c0                          lea     rdi, [rip - 0x3fd96798] ; ripSymbol -> IOMMUDomainLock
    0x4200001653ec (+0030)  e8 33 fa 01 00                                call    0x420000184e24 ; directSymbol -> SP_Unlock
    0x4200001653f1 (+0035)  48 83 3d f7 08 f6 bf 01                       cmp     qword ptr [rip - 0x4009f709], 1 ; configOption+0x90
    0x4200001653f9 (+003d)  74 0b                                         je      0x420000165406
    0x4200001653fb (+003f)  48 83 c4 08                                   add     rsp, 8
    0x4200001653ff (+0043)  4c 89 e0                                      mov     rax, r12
    0x420000165402 (+0046)  5b                                            pop     rbx
    0x420000165403 (+0047)  41 5c                                         pop     r12
    0x420000165405 (+0049)  c3                                            ret
    0x420000165406 (+004a)  8b 03                                         mov     eax, dword ptr [rbx]
    0x420000165408 (+004c)  48 83 ec 08                                   sub     rsp, 8
    0x42000016540c (+0050)  be ec 0b 00 00                                mov     esi, 0xbec
    0x420000165411 (+0055)  48 8d 3d 98 68 6c 00                          lea     rdi, [rip + 0x6c6898] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x is assigned to IOMMU domain %p\n"
    0x420000165418 (+005c)  41 54                                         push    r12
    0x42000016541a (+005e)  41 89 c0                                      mov     r8d, eax
    0x42000016541d (+0061)  0f b6 cc                                      movzx   ecx, ah
    0x420000165420 (+0064)  89 c2                                         mov     edx, eax
    0x420000165422 (+0066)  83 e0 07                                      and     eax, 7
    0x420000165425 (+0069)  41 c1 e8 03                                   shr     r8d, 3
    0x420000165429 (+006d)  c1 ea 10                                      shr     edx, 0x10
    0x42000016542c (+0070)  41 89 c1                                      mov     r9d, eax
    0x42000016542f (+0073)  31 c0                                         xor     eax, eax
    0x420000165431 (+0075)  41 83 e0 1f                                   and     r8d, 0x1f
    0x420000165435 (+0079)  e8 12 4e 00 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x42000016543a (+007e)  58                                            pop     rax
    0x42000016543b (+007f)  5a                                            pop     rdx
    0x42000016543c (+0080)  4c 89 e0                                      mov     rax, r12
    0x42000016543f (+0083)  48 83 c4 08                                   add     rsp, 8
    0x420000165443 (+0087)  5b                                            pop     rbx
    0x420000165444 (+0088)  41 5c                                         pop     r12
    0x420000165446 (+008a)  c3                                            ret
    0x420000165447 (+008b)  45 31 e4                                      xor     r12d, r12d
    0x42000016544a (+008e)  eb 99                                         jmp     0x4200001653e5
```

<!-- evidence:I03:end -->

持有 `IOMMUDomainLock` 时，`0x4200001653de` 读取 PCI 对象的 `+0x378`。NULL 对象有单独的清零路径。后半段还有可选日志，不影响这里被返回的是该字段中的指针。

这个指针不是 vCenter VM ID，也不是实验输出里的 VT-d domainId 数字 1 或 2。后者是硬件表项解码字段，二者需要通过调用和运行采样建立对应，不能直接数值相等。

## 4 A 的激活动作在哪里切换域

普通 PCI 的激活入口先在当前 world 的直通状态中查找设备，检查相关状态和目标域等前提：

<!-- evidence:I06:begin -->

### 切片 I06 普通 PCI 激活入口的登记及状态条件

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruEnablePCIDevice`；入口 `0x7c40`，函数大小 `731` 字节。
- 窗口：`0x7c40` 到 `0x7cfc`（右端不含）；文件偏移 `0x7c80`；44 条指令。
- 窗口 SHA-256：`5939fdda343a8989e5abf6cde877e82fc51213297a67e46c2573cf000c6ffd5e`。[单独查看汇编](snippets/I06.asm)

```asm
            0x7c40 (+0000)  41 57                                         push    r15
            0x7c42 (+0002)  41 56                                         push    r14
            0x7c44 (+0004)  41 55                                         push    r13
            0x7c46 (+0006)  41 54                                         push    r12
            0x7c48 (+0008)  55                                            push    rbp
            0x7c49 (+0009)  53                                            push    rbx
            0x7c4a (+000a)  48 89 fb                                      mov     rbx, rdi
            0x7c4d (+000d)  48 83 ec 28                                   sub     rsp, 0x28
            0x7c51 (+0011)  48 85 ff                                      test    rdi, rdi
            0x7c54 (+0014)  0f 88 f1 00 00 00                             js      0x7d4b ; branch leaves this window
            0x7c5a (+001a)  65 48 8b 04 25 10 00 00 00                    mov     rax, qword ptr gs:[0x10]
            0x7c63 (+0023)  48 8b 80 98 1a 00 00                          mov     rax, qword ptr [rax + 0x1a98]
            0x7c6a (+002a)  89 fd                                         mov     ebp, edi
            0x7c6c (+002c)  41 bd 01 00 ad 0b                             mov     r13d, 0xbad0001
            0x7c72 (+0032)  4c 8b a0 f0 26 00 00                          mov     r12, qword ptr [rax + 0x26f0]
            0x7c79 (+0039)  4d 85 e4                                      test    r12, r12
            0x7c7c (+003c)  74 7e                                         je      0x7cfc ; branch leaves this window
            0x7c7e (+003e)  48 8d 35 00 00 00 00                          lea     rsi, [rip]
            0x7c85 (+0045)  4d 8d b4 24 78 02 00 00                       lea     r14, [r12 + 0x278]
            0x7c8d (+004d)  4c 89 f7                                      mov     rdi, r14
            0x7c90 (+0050)  e8 00 00 00 00                                call    0x7c95 ; REL type=2 Mutex_LockWithRA A=-4
            0x7c95 (+0055)  49 8b 84 24 a0 02 00 00                       mov     rax, qword ptr [r12 + 0x2a0]
            0x7c9d (+005d)  49 8d 8c 24 98 02 00 00                       lea     rcx, [r12 + 0x298]
            0x7ca5 (+0065)  48 39 c8                                      cmp     rax, rcx
            0x7ca8 (+0068)  75 12                                         jne     0x7cbc
            0x7caa (+006a)  e9 46 02 00 00                                jmp     0x7ef5 ; branch leaves this window
            0x7caf (+006f)  48 8b 40 08                                   mov     rax, qword ptr [rax + 8]
            0x7cb3 (+0073)  48 39 c8                                      cmp     rax, rcx
            0x7cb6 (+0076)  0f 84 39 02 00 00                             je      0x7ef5 ; branch leaves this window
            0x7cbc (+007c)  3b 68 10                                      cmp     ebp, dword ptr [rax + 0x10]
            0x7cbf (+007f)  75 ee                                         jne     0x7caf
            0x7cc1 (+0081)  80 b8 86 00 00 00 00                          cmp     byte ptr [rax + 0x86], 0
            0x7cc8 (+0088)  0f 85 b7 01 00 00                             jne     0x7e85 ; branch leaves this window
            0x7cce (+008e)  48 83 78 18 ff                                cmp     qword ptr [rax + 0x18], -1
            0x7cd3 (+0093)  75 39                                         jne     0x7d0e ; branch leaves this window
            0x7cd5 (+0095)  49 8b 6c 24 08                                mov     rbp, qword ptr [r12 + 8]
            0x7cda (+009a)  45 31 ed                                      xor     r13d, r13d
            0x7cdd (+009d)  48 85 ed                                      test    rbp, rbp
            0x7ce0 (+00a0)  74 12                                         je      0x7cf4
            0x7ce2 (+00a2)  48 8b 80 00 02 00 00                          mov     rax, qword ptr [rax + 0x200]
            0x7ce9 (+00a9)  48 83 78 18 00                                cmp     qword ptr [rax + 0x18], 0
            0x7cee (+00ae)  0f 84 bc 01 00 00                             je      0x7eb0 ; branch leaves this window
            0x7cf4 (+00b4)  4c 89 f7                                      mov     rdi, r14
            0x7cf7 (+00b7)  e8 00 00 00 00                                call    0x7cfc ; REL type=2 Mutex_Unlock A=-4
```

<!-- evidence:I06:end -->

它的普通切域分支如下：

<!-- evidence:I07:begin -->

### 切片 I07 普通 PCI 激活的切域调用和 VMkernel 域回退

- 文件：`PCIPassthru ELF in sb.v00`，build `24280767`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruEnablePCIDevice`；入口 `0x7c40`，函数大小 `731` 字节。
- 窗口：`0x7eb0` 到 `0x7ee3`（右端不含）；文件偏移 `0x7ef0`；15 条指令。
- 窗口 SHA-256：`1690a5c819df29595c07315de5cd74dd47580cc669de20807bd4c452fc8ca1c7`。[单独查看汇编](snippets/I07.asm)

```asm
            0x7eb0 (+0270)  89 df                                         mov     edi, ebx
            0x7eb2 (+0272)  48 8d 74 24 18                                lea     rsi, [rsp + 0x18]
            0x7eb7 (+0277)  e8 00 00 00 00                                call    0x7ebc ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x7ebc (+027c)  48 8b 7c 24 18                                mov     rdi, qword ptr [rsp + 0x18]
            0x7ec1 (+0281)  85 c0                                         test    eax, eax
            0x7ec3 (+0283)  75 14                                         jne     0x7ed9
            0x7ec5 (+0285)  31 c9                                         xor     ecx, ecx
            0x7ec7 (+0287)  89 da                                         mov     edx, ebx
            0x7ec9 (+0289)  48 89 ee                                      mov     rsi, rbp
            0x7ecc (+028c)  e8 00 00 00 00                                call    0x7ed1 ; REL type=2 IOMMU_SwitchAddressDomain A=-4
            0x7ed1 (+0291)  41 89 c5                                      mov     r13d, eax
            0x7ed4 (+0294)  e9 1b fe ff ff                                jmp     0x7cf4 ; branch leaves this window
            0x7ed9 (+0299)  e8 00 00 00 00                                call    0x7ede ; REL type=2 IOMMU_GetVmkernelDomain A=-4
            0x7ede (+029e)  48 89 c7                                      mov     rdi, rax
            0x7ee1 (+02a1)  eb e2                                         jmp     0x7ec5
```

<!-- evidence:I07:end -->

`0x7eb7` 查询原域。若返回非零，`0x7ed9` 取 VMkernel 域作为 fromDom；然后 `0x7ecc` 调用 `IOMMU_SwitchAddressDomain`。因此不能把 `PCIPassthruRegisterDeviceInt` 直接写成一个“登记时内部立刻切域”的函数；登记和后续激活有不同调用点。

本用例中“初始化 A 后 B 的状态已改变”由日志顺序和表采样支持。完整 VMX 用户态每个调用点与异常分支尚未逐一还原。

## 5 切域为何会覆盖别名桥子树

<!-- evidence:I04:begin -->

### 切片 I04 校验旧域并遍历别名子树

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMU_SwitchAddressDomain`；入口 `0x4200001654e4`，函数大小 `257` 字节。
- 窗口：`0x4200001654e4` 到 `0x4200001655e5`（右端不含）；文件偏移 `0x4244e4`；71 条指令。
- 窗口 SHA-256：`b96db720277a1c191972265faa857737c31718e0b7e98cc8169efd545b23b05e`。[单独查看汇编](snippets/I04.asm)

```asm
    0x4200001654e4 (+0000)  41 56                                         push    r14
    0x4200001654e6 (+0002)  41 89 ce                                      mov     r14d, ecx
    0x4200001654e9 (+0005)  41 55                                         push    r13
    0x4200001654eb (+0007)  49 89 fd                                      mov     r13, rdi
    0x4200001654ee (+000a)  89 d7                                         mov     edi, edx
    0x4200001654f0 (+000c)  41 54                                         push    r12
    0x4200001654f2 (+000e)  49 89 f4                                      mov     r12, rsi
    0x4200001654f5 (+0011)  55                                            push    rbp
    0x4200001654f6 (+0012)  53                                            push    rbx
    0x4200001654f7 (+0013)  89 d3                                         mov     ebx, edx
    0x4200001654f9 (+0015)  48 83 ec 20                                   sub     rsp, 0x20
    0x4200001654fd (+0019)  e8 0a 5f f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000165502 (+001e)  48 89 c5                                      mov     rbp, rax
    0x420000165505 (+0021)  48 8d 05 00 00 00 00                          lea     rax, [rip]
    0x42000016550c (+0028)  48 8d 3d 41 97 26 c0                          lea     rdi, [rip - 0x3fd968bf] ; ripSymbol -> IOMMUDomainLock
    0x420000165513 (+002f)  e8 b0 fd 01 00                                call    0x4200001852c8 ; directSymbol -> SPLockWork
    0x420000165518 (+0034)  4c 39 ad 78 03 00 00                          cmp     qword ptr [rbp + 0x378], r13
    0x42000016551f (+003b)  75 62                                         jne     0x420000165583
    0x420000165521 (+003d)  4c 39 25 38 97 26 c0                          cmp     qword ptr [rip - 0x3fd968c8], r12 ; ripSymbol -> vmkDomain
    0x420000165528 (+0044)  48 89 ef                                      mov     rdi, rbp
    0x42000016552b (+0047)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x420000165530 (+004c)  4c 89 64 24 10                                mov     qword ptr [rsp + 0x10], r12
    0x420000165535 (+0051)  0f 94 44 24 19                                sete    byte ptr [rsp + 0x19]
    0x42000016553a (+0056)  44 88 74 24 18                                mov     byte ptr [rsp + 0x18], r14b
    0x42000016553f (+005b)  e8 bc 66 f8 ff                                call    0x4200000ebc00 ; directSymbol -> PCI_GetTopmostAliasingBridge
    0x420000165544 (+0060)  48 8d 54 24 10                                lea     rdx, [rsp + 0x10]
    0x420000165549 (+0065)  48 8d 35 20 ef ff ff                          lea     rsi, [rip - 0x10e0] ; ripSymbol -> IOMMUSwitchDeviceIterator
    0x420000165550 (+006c)  85 c0                                         test    eax, eax
    0x420000165552 (+006e)  48 0f 44 6c 24 08                             cmove   rbp, qword ptr [rsp + 8]
    0x420000165558 (+0074)  48 89 ef                                      mov     rdi, rbp
    0x42000016555b (+0077)  e8 e4 64 f8 ff                                call    0x4200000eba44 ; directSymbol -> PCI_IterateDeviceTree
    0x420000165560 (+007c)  41 89 c4                                      mov     r12d, eax
    0x420000165563 (+007f)  85 c0                                         test    eax, eax
    0x420000165565 (+0081)  75 50                                         jne     0x4200001655b7
    0x420000165567 (+0083)  48 8d 3d e6 96 26 c0                          lea     rdi, [rip - 0x3fd9691a] ; ripSymbol -> IOMMUDomainLock
    0x42000016556e (+008a)  e8 b1 f8 01 00                                call    0x420000184e24 ; directSymbol -> SP_Unlock
    0x420000165573 (+008f)  48 83 c4 20                                   add     rsp, 0x20
    0x420000165577 (+0093)  44 89 e0                                      mov     eax, r12d
    0x42000016557a (+0096)  5b                                            pop     rbx
    0x42000016557b (+0097)  5d                                            pop     rbp
    0x42000016557c (+0098)  41 5c                                         pop     r12
    0x42000016557e (+009a)  41 5d                                         pop     r13
    0x420000165580 (+009c)  41 5e                                         pop     r14
    0x420000165582 (+009e)  c3                                            ret
    0x420000165583 (+009f)  41 89 d8                                      mov     r8d, ebx
    0x420000165586 (+00a2)  0f b6 cf                                      movzx   ecx, bh
    0x420000165589 (+00a5)  89 da                                         mov     edx, ebx
    0x42000016558b (+00a7)  83 e3 07                                      and     ebx, 7
    0x42000016558e (+00aa)  41 c1 e8 03                                   shr     r8d, 3
    0x420000165592 (+00ae)  c1 ea 10                                      shr     edx, 0x10
    0x420000165595 (+00b1)  41 89 d9                                      mov     r9d, ebx
    0x420000165598 (+00b4)  be 80 0c 00 00                                mov     esi, 0xc80
    0x42000016559d (+00b9)  41 83 e0 1f                                   and     r8d, 0x1f
    0x4200001655a1 (+00bd)  48 8d 3d 20 27 5e 00                          lea     rdi, [rip + 0x5e2720] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x is not switched to the new domain because the fromDom does not match its current domain.\n"
    0x4200001655a8 (+00c4)  31 c0                                         xor     eax, eax
    0x4200001655aa (+00c6)  41 bc 01 00 ad 0b                             mov     r12d, 0xbad0001
    0x4200001655b0 (+00cc)  e8 ef 50 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x4200001655b5 (+00d1)  eb b0                                         jmp     0x420000165567
    0x4200001655b7 (+00d3)  41 89 d8                                      mov     r8d, ebx
    0x4200001655ba (+00d6)  0f b6 cf                                      movzx   ecx, bh
    0x4200001655bd (+00d9)  89 da                                         mov     edx, ebx
    0x4200001655bf (+00db)  83 e3 07                                      and     ebx, 7
    0x4200001655c2 (+00de)  41 c1 e8 03                                   shr     r8d, 3
    0x4200001655c6 (+00e2)  c1 ea 10                                      shr     edx, 0x10
    0x4200001655c9 (+00e5)  41 89 d9                                      mov     r9d, ebx
    0x4200001655cc (+00e8)  be 90 0c 00 00                                mov     esi, 0xc90
    0x4200001655d1 (+00ed)  41 83 e0 1f                                   and     r8d, 0x1f
    0x4200001655d5 (+00f1)  48 8d 3d ac b6 66 00                          lea     rdi, [rip + 0x66b6ac] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x could not be switched to the specified domain.\n"
    0x4200001655dc (+00f8)  31 c0                                         xor     eax, eax
    0x4200001655de (+00fa)  e8 c1 50 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x4200001655e3 (+00ff)  eb 82                                         jmp     0x420000165567
```

<!-- evidence:I04:end -->

这里的输入关系可以从前部寄存器搬运看出：R13 保存 fromDom，R12 保存 toDom，EBX 保存设备地址。

1. `0x165518` 先比较目标设备 `+0x378` 与 fromDom，不符则拒绝。
2. `0x16553f` 查询最上层别名桥。
3. 查询成功时，`cmove rbp,[rsp+8]` 把遍历起点从设备替换为该桥。
4. `lea rsi,...IOMMUSwitchDeviceIterator` 设置回调，再调用 `PCI_IterateDeviceTree`。

也就是说，API 指定的是一个设备地址，真正作用范围可以扩成整棵有关子树。

<!-- evidence:I09:begin -->

### 切片 I09 子树回调前的节点资格过滤

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_CanDeviceBeAssignedToIOMMUDomain`；入口 `0x4200000eb9b8`，函数大小 `62` 字节。
- 窗口：`0x4200000eb9b8` 到 `0x4200000eb9f6`（右端不含）；文件偏移 `0x3aa9b8`；25 条指令。
- 窗口 SHA-256：`b73d8db19c5db9a399d30336bf7f3dd41a242550120c86f868d4cd769dd4d4ff`。[单独查看汇编](snippets/I09.asm)

```asm
    0x4200000eb9b8 (+0000)  53                                            push    rbx
    0x4200000eb9b9 (+0001)  48 89 fb                                      mov     rbx, rdi
    0x4200000eb9bc (+0004)  8b 3f                                         mov     edi, dword ptr [rdi]
    0x4200000eb9be (+0006)  e8 f5 9c ff ff                                call    0x4200000e56b8 ; directSymbol -> PCIBridge_IsHostBridge
    0x4200000eb9c3 (+000b)  84 c0                                         test    al, al
    0x4200000eb9c5 (+000d)  75 1d                                         jne     0x4200000eb9e4
    0x4200000eb9c7 (+000f)  f6 43 04 02                                   test    byte ptr [rbx + 4], 2
    0x4200000eb9cb (+0013)  74 0c                                         je      0x4200000eb9d9
    0x4200000eb9cd (+0015)  48 89 df                                      mov     rdi, rbx
    0x4200000eb9d0 (+0018)  e8 63 97 ff ff                                call    0x4200000e5138 ; directSymbol -> PCIBridge_IsAliasing
    0x4200000eb9d5 (+001d)  84 c0                                         test    al, al
    0x4200000eb9d7 (+001f)  74 0b                                         je      0x4200000eb9e4
    0x4200000eb9d9 (+0021)  31 c0                                         xor     eax, eax
    0x4200000eb9db (+0023)  e8 54 aa f8 ff                                call    0x420000076434 ; directSymbol -> IOV_IsInitialized
    0x4200000eb9e0 (+0028)  84 c0                                         test    al, al
    0x4200000eb9e2 (+002a)  75 04                                         jne     0x4200000eb9e8
    0x4200000eb9e4 (+002c)  31 c0                                         xor     eax, eax
    0x4200000eb9e6 (+002e)  5b                                            pop     rbx
    0x4200000eb9e7 (+002f)  c3                                            ret
    0x4200000eb9e8 (+0030)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000eb9ea (+0032)  e8 09 9c 07 00                                call    0x4200001655f8 ; directSymbol -> IOMMU_IsDeviceSupported
    0x4200000eb9ef (+0037)  5b                                            pop     rbx
    0x4200000eb9f0 (+0038)  84 c0                                         test    al, al
    0x4200000eb9f2 (+003a)  0f 95 c0                                      setne   al
    0x4200000eb9f5 (+003d)  c3                                            ret
```

<!-- evidence:I09:end -->

迭代器先调用这个节点资格函数，可能跳过 host bridge、非别名桥或其他不受支持对象。因此准确说法是“遍历子树并处理符合条件的节点”，不是无条件改写树上每个 PCI 对象。

<!-- evidence:I05:begin -->

### 切片 I05 成员域写入 同域引用与错误处理

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMUSwitchDeviceIterator`；入口 `0x420000164470`，函数大小 `408` 字节。
- 窗口：`0x420000164470` 到 `0x420000164608`（右端不含）；文件偏移 `0x423470`；114 条指令。
- 窗口 SHA-256：`b69b9cd144ec112d2c8868e3ec0c799149475c04614e2e9919723cef39c9018e`。[单独查看汇编](snippets/I05.asm)

```asm
    0x420000164470 (+0000)  41 56                                         push    r14
    0x420000164472 (+0002)  41 55                                         push    r13
    0x420000164474 (+0004)  41 54                                         push    r12
    0x420000164476 (+0006)  45 31 e4                                      xor     r12d, r12d
    0x420000164479 (+0009)  55                                            push    rbp
    0x42000016447a (+000a)  48 89 d5                                      mov     rbp, rdx
    0x42000016447d (+000d)  53                                            push    rbx
    0x42000016447e (+000e)  48 89 fb                                      mov     rbx, rdi
    0x420000164481 (+0011)  e8 32 75 f8 ff                                call    0x4200000eb9b8 ; directSymbol -> PCI_CanDeviceBeAssignedToIOMMUDomain
    0x420000164486 (+0016)  84 c0                                         test    al, al
    0x420000164488 (+0018)  0f 84 b1 00 00 00                             je      0x42000016453f
    0x42000016448e (+001e)  4c 8b ab 78 03 00 00                          mov     r13, qword ptr [rbx + 0x378]
    0x420000164495 (+0025)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x420000164499 (+0029)  4c 39 ef                                      cmp     rdi, r13
    0x42000016449c (+002c)  0f 84 da 00 00 00                             je      0x42000016457c
    0x4200001644a2 (+0032)  80 bb 80 03 00 00 00                          cmp     byte ptr [rbx + 0x380], 0
    0x4200001644a9 (+0039)  0f 84 9c 00 00 00                             je      0x42000016454b
    0x4200001644af (+003f)  83 3d fe a7 26 c0 01                          cmp     dword ptr [rip - 0x3fd95802], 1 ; ripSymbol -> iommuMapReservedMem
    0x4200001644b6 (+0046)  76 15                                         jbe     0x4200001644cd
    0x4200001644b8 (+0048)  48 8b 05 a9 a7 26 c0                          mov     rax, qword ptr [rip - 0x3fd95857] ; ripSymbol -> domainOps
    0x4200001644bf (+004f)  ff 90 a0 00 00 00                             call    qword ptr [rax + 0xa0]
    0x4200001644c5 (+0055)  84 c0                                         test    al, al
    0x4200001644c7 (+0057)  75 12                                         jne     0x4200001644db
    0x4200001644c9 (+0059)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x4200001644cd (+005d)  8b 33                                         mov     esi, dword ptr [rbx]
    0x4200001644cf (+005f)  e8 ec fa ff ff                                call    0x420000163fc0 ; directSymbol -> IOMMUMapRMRRForDevice
    0x4200001644d4 (+0064)  41 89 c4                                      mov     r12d, eax
    0x4200001644d7 (+0067)  85 c0                                         test    eax, eax
    0x4200001644d9 (+0069)  75 64                                         jne     0x42000016453f
    0x4200001644db (+006b)  48 8b 05 86 a7 26 c0                          mov     rax, qword ptr [rip - 0x3fd9587a] ; ripSymbol -> domainOps
    0x4200001644e2 (+0072)  8b 13                                         mov     edx, dword ptr [rbx]
    0x4200001644e4 (+0074)  4c 89 ef                                      mov     rdi, r13
    0x4200001644e7 (+0077)  48 8b 75 00                                   mov     rsi, qword ptr [rbp]
    0x4200001644eb (+007b)  ff 50 60                                      call    qword ptr [rax + 0x60]
    0x4200001644ee (+007e)  41 89 c4                                      mov     r12d, eax
    0x4200001644f1 (+0081)  85 c0                                         test    eax, eax
    0x4200001644f3 (+0083)  75 4a                                         jne     0x42000016453f
    0x4200001644f5 (+0085)  f6 43 04 02                                   test    byte ptr [rbx + 4], 2
    0x4200001644f9 (+0089)  74 0d                                         je      0x420000164508
    0x4200001644fb (+008b)  83 bb f8 00 00 00 04                          cmp     dword ptr [rbx + 0xf8], 4
    0x420000164502 (+0092)  0f 84 96 00 00 00                             je      0x42000016459e
    0x420000164508 (+0098)  80 7d 09 00                                   cmp     byte ptr [rbp + 9], 0
    0x42000016450c (+009c)  75 61                                         jne     0x42000016456f
    0x42000016450e (+009e)  0f b6 83 80 03 00 00                          movzx   eax, byte ptr [rbx + 0x380]
    0x420000164515 (+00a5)  84 c0                                         test    al, al
    0x420000164517 (+00a7)  74 0b                                         je      0x420000164524
    0x420000164519 (+00a9)  83 83 70 03 00 00 01                          add     dword ptr [rbx + 0x370], 1
    0x420000164520 (+00b0)  0f b6 45 09                                   movzx   eax, byte ptr [rbp + 9]
    0x420000164524 (+00b4)  0f b6 55 08                                   movzx   edx, byte ptr [rbp + 8]
    0x420000164528 (+00b8)  48 8b 4d 00                                   mov     rcx, qword ptr [rbp]
    0x42000016452c (+00bc)  88 83 80 03 00 00                             mov     byte ptr [rbx + 0x380], al
    0x420000164532 (+00c2)  48 89 8b 78 03 00 00                          mov     qword ptr [rbx + 0x378], rcx
    0x420000164539 (+00c9)  88 93 81 03 00 00                             mov     byte ptr [rbx + 0x381], dl
    0x42000016453f (+00cf)  5b                                            pop     rbx
    0x420000164540 (+00d0)  44 89 e0                                      mov     eax, r12d
    0x420000164543 (+00d3)  5d                                            pop     rbp
    0x420000164544 (+00d4)  41 5c                                         pop     r12
    0x420000164546 (+00d6)  41 5d                                         pop     r13
    0x420000164548 (+00d8)  41 5e                                         pop     r14
    0x42000016454a (+00da)  c3                                            ret
    0x42000016454b (+00db)  8b 83 70 03 00 00                             mov     eax, dword ptr [rbx + 0x370]
    0x420000164551 (+00e1)  83 f8 01                                      cmp     eax, 1
    0x420000164554 (+00e4)  0f 86 55 ff ff ff                             jbe     0x4200001644af
    0x42000016455a (+00ea)  83 e8 01                                      sub     eax, 1
    0x42000016455d (+00ed)  89 83 70 03 00 00                             mov     dword ptr [rbx + 0x370], eax
    0x420000164563 (+00f3)  5b                                            pop     rbx
    0x420000164564 (+00f4)  44 89 e0                                      mov     eax, r12d
    0x420000164567 (+00f7)  5d                                            pop     rbp
    0x420000164568 (+00f8)  41 5c                                         pop     r12
    0x42000016456a (+00fa)  41 5d                                         pop     r13
    0x42000016456c (+00fc)  41 5e                                         pop     r14
    0x42000016456e (+00fe)  c3                                            ret
    0x42000016456f (+00ff)  83 ab 70 03 00 00 01                          sub     dword ptr [rbx + 0x370], 1
    0x420000164576 (+0106)  0f b6 45 09                                   movzx   eax, byte ptr [rbp + 9]
    0x42000016457a (+010a)  eb a8                                         jmp     0x420000164524
    0x42000016457c (+010c)  80 7d 09 00                                   cmp     byte ptr [rbp + 9], 0
    0x420000164580 (+0110)  75 bd                                         jne     0x42000016453f
    0x420000164582 (+0112)  44 8b a3 70 03 00 00                          mov     r12d, dword ptr [rbx + 0x370]
    0x420000164589 (+0119)  45 85 e4                                      test    r12d, r12d
    0x42000016458c (+011c)  74 b1                                         je      0x42000016453f
    0x42000016458e (+011e)  41 83 c4 01                                   add     r12d, 1
    0x420000164592 (+0122)  44 89 a3 70 03 00 00                          mov     dword ptr [rbx + 0x370], r12d
    0x420000164599 (+0129)  45 31 e4                                      xor     r12d, r12d
    0x42000016459c (+012c)  eb a1                                         jmp     0x42000016453f
    0x42000016459e (+012e)  ba 02 00 00 00                                mov     edx, 2
    0x4200001645a3 (+0133)  48 89 ee                                      mov     rsi, rbp
    0x4200001645a6 (+0136)  48 89 df                                      mov     rdi, rbx
    0x4200001645a9 (+0139)  e8 02 fb ff ff                                call    0x4200001640b0 ; directSymbol -> IOMMUHandleBridgePCIEToPCI.isra.0
    0x4200001645ae (+013e)  41 89 c6                                      mov     r14d, eax
    0x4200001645b1 (+0141)  85 c0                                         test    eax, eax
    0x4200001645b3 (+0143)  0f 84 4f ff ff ff                             je      0x420000164508
    0x4200001645b9 (+0149)  48 8b 05 a8 a6 26 c0                          mov     rax, qword ptr [rip - 0x3fd95958] ; ripSymbol -> domainOps
    0x4200001645c0 (+0150)  8b 13                                         mov     edx, dword ptr [rbx]
    0x4200001645c2 (+0152)  4c 89 ee                                      mov     rsi, r13
    0x4200001645c5 (+0155)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x4200001645c9 (+0159)  ff 50 60                                      call    qword ptr [rax + 0x60]
    0x4200001645cc (+015c)  85 c0                                         test    eax, eax
    0x4200001645ce (+015e)  75 08                                         jne     0x4200001645d8
    0x4200001645d0 (+0160)  45 89 f4                                      mov     r12d, r14d
    0x4200001645d3 (+0163)  e9 67 ff ff ff                                jmp     0x42000016453f
    0x4200001645d8 (+0168)  8b 03                                         mov     eax, dword ptr [rbx]
    0x4200001645da (+016a)  be f2 04 00 00                                mov     esi, 0x4f2
    0x4200001645df (+016f)  48 8d 3d 92 99 6a 00                          lea     rdi, [rip + 0x6a9992] ; literal "IOMMU: %d: Unable to switch back %04x:%02x:%02x.%x to domain on failure\n"
    0x4200001645e6 (+0176)  41 89 c0                                      mov     r8d, eax
    0x4200001645e9 (+0179)  0f b6 cc                                      movzx   ecx, ah
    0x4200001645ec (+017c)  89 c2                                         mov     edx, eax
    0x4200001645ee (+017e)  83 e0 07                                      and     eax, 7
    0x4200001645f1 (+0181)  41 c1 e8 03                                   shr     r8d, 3
    0x4200001645f5 (+0185)  41 89 c1                                      mov     r9d, eax
    0x4200001645f8 (+0188)  c1 ea 10                                      shr     edx, 0x10
    0x4200001645fb (+018b)  31 c0                                         xor     eax, eax
    0x4200001645fd (+018d)  41 83 e0 1f                                   and     r8d, 0x1f
    0x420000164601 (+0191)  e8 9e 60 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x420000164606 (+0196)  eb c8                                         jmp     0x4200001645d0
```

<!-- evidence:I05:end -->

`0x164532` 把新域写到同一个 `+0x378` 字段，和 I03 的读取偏移完全对应。到这里，读字段、写字段、扩展作用范围的三段证据闭合。

同域分支也必须完整阅读：`0x164499` 比较目标指针与现有指针，相等跳 `0x16457c`；只有目标不是 VMkernel 域、关联计数字段非零时才执行递增。不能把它简化成任何“已经有域”都自动成功递增。

| 条件 | 所见行为 |
| --- | --- |
| 当前域等于目标域，目标是 VMkernel 域 | 不走该计数递增路径 |
| 当前域等于目标域，目标非 VMkernel 域，计数为 0 | 跳过递增 |
| 当前域等于目标域，目标非 VMkernel 域，计数非 0 | `+0x370` 增加 1 |
| 当前域不同 | 进入其他映射、RMRR、计数及错误处理分支 |

这里把 `+0x370` 称为关联计数字段，是基于这段加减及保留关联的行为解释；没有取得 VMware 的原始结构体类型定义。

## 6 为什么会出现没有实际 Function 的代理地址

I05 对某类桥调用下面的专门函数。前部的地址构造本身就是证据：

<!-- evidence:I08:begin -->

### 切片 I08 PCIe 到 PCI 桥的专门映射处理

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`IOMMUHandleBridgePCIEToPCI.isra.0`；入口 `0x4200001640b0`，函数大小 `267` 字节。
- 窗口：`0x4200001640b0` 到 `0x4200001641bb`（右端不含）；文件偏移 `0x4230b0`；82 条指令。
- 窗口 SHA-256：`433f6fc5bddb9c22f1e9eef857329b263bbd998a87a43c5d1c6ef66869440efe`。[单独查看汇编](snippets/I08.asm)

```asm
    0x4200001640b0 (+0000)  41 56                                         push    r14
    0x4200001640b2 (+0002)  41 55                                         push    r13
    0x4200001640b4 (+0004)  41 54                                         push    r12
    0x4200001640b6 (+0006)  55                                            push    rbp
    0x4200001640b7 (+0007)  53                                            push    rbx
    0x4200001640b8 (+0008)  0f b6 47 1b                                   movzx   eax, byte ptr [rdi + 0x1b]
    0x4200001640bc (+000c)  85 c0                                         test    eax, eax
    0x4200001640be (+000e)  75 0f                                         jne     0x4200001640cf
    0x4200001640c0 (+0010)  45 31 e4                                      xor     r12d, r12d
    0x4200001640c3 (+0013)  5b                                            pop     rbx
    0x4200001640c4 (+0014)  44 89 e0                                      mov     eax, r12d
    0x4200001640c7 (+0017)  5d                                            pop     rbp
    0x4200001640c8 (+0018)  41 5c                                         pop     r12
    0x4200001640ca (+001a)  41 5d                                         pop     r13
    0x4200001640cc (+001c)  41 5e                                         pop     r14
    0x4200001640ce (+001e)  c3                                            ret
    0x4200001640cf (+001f)  8b 2f                                         mov     ebp, dword ptr [rdi]
    0x4200001640d1 (+0021)  c1 e0 08                                      shl     eax, 8
    0x4200001640d4 (+0024)  48 89 fb                                      mov     rbx, rdi
    0x4200001640d7 (+0027)  49 89 f6                                      mov     r14, rsi
    0x4200001640da (+002a)  41 89 d5                                      mov     r13d, edx
    0x4200001640dd (+002d)  66 31 ed                                      xor     bp, bp
    0x4200001640e0 (+0030)  09 c5                                         or      ebp, eax
    0x4200001640e2 (+0032)  89 ef                                         mov     edi, ebp
    0x4200001640e4 (+0034)  e8 23 73 f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x4200001640e9 (+0039)  48 85 c0                                      test    rax, rax
    0x4200001640ec (+003c)  75 d2                                         jne     0x4200001640c0
    0x4200001640ee (+003e)  83 3d bf ab 26 c0 01                          cmp     dword ptr [rip - 0x3fd95441], 1 ; ripSymbol -> iommuMapReservedMem
    0x4200001640f5 (+0045)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x4200001640f8 (+0048)  76 14                                         jbe     0x42000016410e
    0x4200001640fa (+004a)  48 8b 05 67 ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd95499] ; ripSymbol -> domainOps
    0x420000164101 (+0051)  ff 90 a0 00 00 00                             call    qword ptr [rax + 0xa0]
    0x420000164107 (+0057)  84 c0                                         test    al, al
    0x420000164109 (+0059)  75 2a                                         jne     0x420000164135
    0x42000016410b (+005b)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x42000016410e (+005e)  48 8b 05 53 ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954ad] ; ripSymbol -> domainOps
    0x420000164115 (+0065)  41 83 fd 01                                   cmp     r13d, 1
    0x420000164119 (+0069)  75 7f                                         jne     0x42000016419a
    0x42000016411b (+006b)  89 ee                                         mov     esi, ebp
    0x42000016411d (+006d)  ff 50 50                                      call    qword ptr [rax + 0x50]
    0x420000164120 (+0070)  41 89 c4                                      mov     r12d, eax
    0x420000164123 (+0073)  85 c0                                         test    eax, eax
    0x420000164125 (+0075)  75 9c                                         jne     0x4200001640c3
    0x420000164127 (+0077)  48 8b 05 3a ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954c6] ; ripSymbol -> domainOps
    0x42000016412e (+007e)  89 ef                                         mov     edi, ebp
    0x420000164130 (+0080)  ff 50 78                                      call    qword ptr [rax + 0x78]
    0x420000164133 (+0083)  eb 8e                                         jmp     0x4200001640c3
    0x420000164135 (+0085)  48 8b 05 2c ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954d4] ; ripSymbol -> domainOps
    0x42000016413c (+008c)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x42000016413f (+008f)  48 89 c1                                      mov     rcx, rax
    0x420000164142 (+0092)  41 83 fd 01                                   cmp     r13d, 1
    0x420000164146 (+0096)  74 d3                                         je      0x42000016411b
    0x420000164148 (+0098)  41 83 fd 02                                   cmp     r13d, 2
    0x42000016414c (+009c)  74 2a                                         je      0x420000164178
    0x42000016414e (+009e)  89 ee                                         mov     esi, ebp
    0x420000164150 (+00a0)  ff 51 40                                      call    qword ptr [rcx + 0x40]
    0x420000164153 (+00a3)  41 89 c4                                      mov     r12d, eax
    0x420000164156 (+00a6)  85 c0                                         test    eax, eax
    0x420000164158 (+00a8)  0f 85 65 ff ff ff                             jne     0x4200001640c3
    0x42000016415e (+00ae)  45 85 ed                                      test    r13d, r13d
    0x420000164161 (+00b1)  0f 85 59 ff ff ff                             jne     0x4200001640c0
    0x420000164167 (+00b7)  48 8b 05 fa aa 26 c0                          mov     rax, qword ptr [rip - 0x3fd95506] ; ripSymbol -> domainOps
    0x42000016416e (+00be)  89 ef                                         mov     edi, ebp
    0x420000164170 (+00c0)  ff 50 70                                      call    qword ptr [rax + 0x70]
    0x420000164173 (+00c3)  e9 4b ff ff ff                                jmp     0x4200001640c3
    0x420000164178 (+00c8)  4c 8b 83 78 03 00 00                          mov     r8, qword ptr [rbx + 0x378]
    0x42000016417f (+00cf)  48 89 fe                                      mov     rsi, rdi
    0x420000164182 (+00d2)  89 ea                                         mov     edx, ebp
    0x420000164184 (+00d4)  4c 89 c7                                      mov     rdi, r8
    0x420000164187 (+00d7)  ff 51 60                                      call    qword ptr [rcx + 0x60]
    0x42000016418a (+00da)  41 89 c4                                      mov     r12d, eax
    0x42000016418d (+00dd)  85 c0                                         test    eax, eax
    0x42000016418f (+00df)  0f 84 2b ff ff ff                             je      0x4200001640c0
    0x420000164195 (+00e5)  e9 29 ff ff ff                                jmp     0x4200001640c3
    0x42000016419a (+00ea)  89 ee                                         mov     esi, ebp
    0x42000016419c (+00ec)  41 bc 01 00 ad 0b                             mov     r12d, 0xbad0001
    0x4200001641a2 (+00f2)  e8 19 fe ff ff                                call    0x420000163fc0 ; directSymbol -> IOMMUMapRMRRForDevice
    0x4200001641a7 (+00f7)  85 c0                                         test    eax, eax
    0x4200001641a9 (+00f9)  0f 85 14 ff ff ff                             jne     0x4200001640c3
    0x4200001641af (+00ff)  48 8b 0d b2 aa 26 c0                          mov     rcx, qword ptr [rip - 0x3fd9554e] ; ripSymbol -> domainOps
    0x4200001641b6 (+0106)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x4200001641b9 (+0109)  eb 8d                                         jmp     0x420000164148
```

<!-- evidence:I08:end -->

关键运算是：读取对象 `+0x1b` 的总线字段，左移 8；取原 packed SBDF 后 `xor bp,bp` 清掉低 16 位；再 OR 入该总线值。结果保留 segment，把 slot/function 置零。

```text
proxy = (bridge_sbdf & 0xffff0000) | (bus_field << 8)
```

组合后调用 `PCI_GetDevice(proxy)`：若真实对象已存在，这段专门处理返回；不存在时才继续相应的底层 domainOps 路径。因而“没有名为 02:00.0 的真实 Function”不妨碍它作为桥代理身份参与 IOMMU 处理。

静态代码能证明组合公式。将字段理解为该桥的下游 bus，与相邻桥遍历逻辑和本例 secondary bus=2 / 代理 RID=02:00.0 的证据相符；本轮没有单独转储运行内核对象 `+0x1b` 的数值。它也不是 API 中依赖代表 `01:00.0` 的简单复制。

## 7 同一 VM 故障链的可核对结论

```text
04 的 owner 比较允许同一 VM 继续
    ↓
A 激活时，I04 把切域范围扩成 alias 子树
    ↓
I05 写入 B 的 +0x378 等关联字段
    ↓
B 新登记调用 I02，读到非 VMkernel 域，返回 0
    ↓
I01 要求 0x0bad0003，不接受 0，进入失败路径
```

下层存在条件化的同域复用能力，不能保证上层一定能走到它。上层的新登记前提可能更早阻断正常复用。这里支持的是该 build、该分支和该拓扑中的机制解释；没有执行删除检查、改写跳转或软件补丁验证。

对应运行证据和较新版本字节对照放在 [07](07-runtime-and-versions.md)。
