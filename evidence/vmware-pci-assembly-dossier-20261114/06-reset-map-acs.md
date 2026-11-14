# 06 passthru.map 复位与 ACS 的实际插入点

这几个机制会影响资格和依赖，但不处于同一个层次。本章分别展示解析器、字段写入者、复位判定和 ACS 策略，避免把一个文件开关说成能改变硬件隔离。

## 1 map 的字符串如何变成数值

<!-- evidence:M01:begin -->

### 切片 M01 map 中复位选择器及 shareable 值

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::LoadPassthruMap`；入口 `0x4c8e7a`，函数大小 `1010` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl15LoadPassthruMapEv`。
- 窗口：`0x4c909d` 到 `0x4c91db`（右端不含）；文件偏移 `0x4c909d`；74 条指令。
- 窗口 SHA-256：`e93a2326fca61f03a3a6112f2e60bb3da869d0c24a050b23cb2ff473ff614e08`。[单独查看汇编](snippets/M01.asm)

```asm
          0x4c909d (+0223)  48 8d 35 01 cd 37 00                          lea     rsi, [rip + 0x37cd01] ; literal "flr"
          0x4c90a4 (+022a)  4c 89 f7                                      mov     rdi, r14
          0x4c90a7 (+022d)  e8 34 32 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c90ac (+0232)  5a                                            pop     rdx
          0x4c90ad (+0233)  59                                            pop     rcx
          0x4c90ae (+0234)  84 c0                                         test    al, al
          0x4c90b0 (+0236)  74 2c                                         je      0x4c90de
          0x4c90b2 (+0238)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c90b9 (+023f)  4c 89 fe                                      mov     rsi, r15
          0x4c90bc (+0242)  4c 89 e7                                      mov     rdi, r12
          0x4c90bf (+0245)  e8 1c 7a ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c90c4 (+024a)  48 8b 3d 45 dc 59 00                          mov     rdi, qword ptr [rip + 0x59dc45] ; GOT -> PciDeviceImpl::_resetMap
          0x4c90cb (+0251)  4c 89 e6                                      mov     rsi, r12
          0x4c90ce (+0254)  e8 cd 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c90d3 (+0259)  c7 00 01 00 00 00                             mov     dword ptr [rax], 1
          0x4c90d9 (+025f)  e9 b2 00 00 00                                jmp     0x4c9190
          0x4c90de (+0264)  48 8d 35 c4 cc 37 00                          lea     rsi, [rip + 0x37ccc4] ; literal "d3d0"
          0x4c90e5 (+026b)  4c 89 f7                                      mov     rdi, r14
          0x4c90e8 (+026e)  e8 f3 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c90ed (+0273)  84 c0                                         test    al, al
          0x4c90ef (+0275)  74 29                                         je      0x4c911a
          0x4c90f1 (+0277)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c90f8 (+027e)  4c 89 fe                                      mov     rsi, r15
          0x4c90fb (+0281)  4c 89 e7                                      mov     rdi, r12
          0x4c90fe (+0284)  e8 dd 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c9103 (+0289)  48 8b 3d 06 dc 59 00                          mov     rdi, qword ptr [rip + 0x59dc06] ; GOT -> PciDeviceImpl::_resetMap
          0x4c910a (+0290)  4c 89 e6                                      mov     rsi, r12
          0x4c910d (+0293)  e8 8e 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c9112 (+0298)  c7 00 02 00 00 00                             mov     dword ptr [rax], 2
          0x4c9118 (+029e)  eb 76                                         jmp     0x4c9190
          0x4c911a (+02a0)  48 8d 35 cd 9a 38 00                          lea     rsi, [rip + 0x389acd] ; literal "link"
          0x4c9121 (+02a7)  4c 89 f7                                      mov     rdi, r14
          0x4c9124 (+02aa)  e8 b7 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c9129 (+02af)  84 c0                                         test    al, al
          0x4c912b (+02b1)  74 29                                         je      0x4c9156
          0x4c912d (+02b3)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c9134 (+02ba)  4c 89 fe                                      mov     rsi, r15
          0x4c9137 (+02bd)  4c 89 e7                                      mov     rdi, r12
          0x4c913a (+02c0)  e8 a1 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c913f (+02c5)  48 8b 3d ca db 59 00                          mov     rdi, qword ptr [rip + 0x59dbca] ; GOT -> PciDeviceImpl::_resetMap
          0x4c9146 (+02cc)  4c 89 e6                                      mov     rsi, r12
          0x4c9149 (+02cf)  e8 52 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c914e (+02d4)  c7 00 03 00 00 00                             mov     dword ptr [rax], 3
          0x4c9154 (+02da)  eb 3a                                         jmp     0x4c9190
          0x4c9156 (+02dc)  48 8d 35 26 9f 37 00                          lea     rsi, [rip + 0x379f26] ; literal "bridge"
          0x4c915d (+02e3)  4c 89 f7                                      mov     rdi, r14
          0x4c9160 (+02e6)  e8 7b 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c9165 (+02eb)  84 c0                                         test    al, al
          0x4c9167 (+02ed)  74 2f                                         je      0x4c9198
          0x4c9169 (+02ef)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c9170 (+02f6)  4c 89 fe                                      mov     rsi, r15
          0x4c9173 (+02f9)  4c 89 e7                                      mov     rdi, r12
          0x4c9176 (+02fc)  e8 65 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c917b (+0301)  48 8b 3d 8e db 59 00                          mov     rdi, qword ptr [rip + 0x59db8e] ; GOT -> PciDeviceImpl::_resetMap
          0x4c9182 (+0308)  4c 89 e6                                      mov     rsi, r12
          0x4c9185 (+030b)  e8 16 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c918a (+0310)  c7 00 04 00 00 00                             mov     dword ptr [rax], 4
          0x4c9190 (+0316)  4c 89 e7                                      mov     rdi, r12
          0x4c9193 (+0319)  e8 c8 b6 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c9198 (+031e)  48 8d bd 40 f9 ff ff                          lea     rdi, [rbp - 0x6c0]
          0x4c919f (+0325)  48 8d 35 00 f4 3a 00                          lea     rsi, [rip + 0x3af400] ; literal "false"
          0x4c91a6 (+032c)  e8 35 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c91ab (+0331)  84 c0                                         test    al, al
          0x4c91ad (+0333)  74 2c                                         je      0x4c91db ; branch leaves this window
          0x4c91af (+0335)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c91b6 (+033c)  4c 89 fe                                      mov     rsi, r15
          0x4c91b9 (+033f)  4c 89 e7                                      mov     rdi, r12
          0x4c91bc (+0342)  e8 1f 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c91c1 (+0347)  48 8b 3d 48 cd 59 00                          mov     rdi, qword ptr [rip + 0x59cd48] ; GOT -> PciDeviceImpl::_fptShareableMap
          0x4c91c8 (+034e)  4c 89 e6                                      mov     rsi, r12
          0x4c91cb (+0351)  e8 10 d5 eb ff                                call    0x3866e0 ; PLT -> _ZNSt3mapISsbSt4lessISsESaISt4pairIKSsbEEEixEOSs
          0x4c91d0 (+0356)  c6 00 00                                      mov     byte ptr [rax], 0
          0x4c91d3 (+0359)  4c 89 e7                                      mov     rdi, r12
          0x4c91d6 (+035c)  e8 85 b6 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
```

<!-- evidence:M01:end -->

字符串比较后的写入点直接给出对应关系：

| 解析到的选择 | 写入指令 | 值 |
| --- | --- | --- |
| flr | `0x4c90d3` | 1 |
| d3d0 | `0x4c9112` | 2 |
| link | `0x4c914e` | 3 |
| bridge | `0x4c918a` | 4 |
| shareable 为 false | `0x4c91d0` | 共享属性写 0 |

这是解析器中对应分支的结果。VID:DID 的全部匹配优先级、重复行处理和所有通配组合，不由这一个窗口推导。

## 2 shareable 怎样进入内核依赖字段

<!-- evidence:M02:begin -->

### 切片 M02 共享属性写入 VSI

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::RestoreFptShareableAttr`；入口 `0x4c9714`，函数大小 `134` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23RestoreFptShareableAttrEv`。
- 窗口：`0x4c9714` 到 `0x4c979a`（右端不含）；文件偏移 `0x4c9714`；37 条指令。
- 窗口 SHA-256：`881ed8775642b633af92afa708e36b3b1e9af828dfcba5507afb9e7112c4349f`。[单独查看汇编](snippets/M02.asm)

```asm
          0x4c9714 (+0000)  55                                            push    rbp
          0x4c9715 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c9718 (+0004)  41 55                                         push    r13
          0x4c971a (+0006)  41 54                                         push    r12
          0x4c971c (+0008)  53                                            push    rbx
          0x4c971d (+0009)  48 89 fb                                      mov     rbx, rdi
          0x4c9720 (+000c)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c9724 (+0010)  e8 a7 26 ec ff                                call    0x38bdd0 ; PLT -> PciDeviceImpl::GetConfiguredFptShareable
          0x4c9729 (+0015)  84 c0                                         test    al, al
          0x4c972b (+0017)  75 62                                         jne     0x4c978f
          0x4c972d (+0019)  4c 8d 65 c8                                   lea     r12, [rbp - 0x38]
          0x4c9731 (+001d)  48 8d 75 c4                                   lea     rsi, [rbp - 0x3c]
          0x4c9735 (+0021)  48 c7 45 c8 00 00 00 00                       mov     qword ptr [rbp - 0x38], 0
          0x4c973d (+0029)  4c 89 e7                                      mov     rdi, r12
          0x4c9740 (+002c)  48 c7 45 d0 00 00 00 00                       mov     qword ptr [rbp - 0x30], 0
          0x4c9748 (+0034)  48 c7 45 d8 00 00 00 00                       mov     qword ptr [rbp - 0x28], 0
          0x4c9750 (+003c)  c7 45 c4 00 00 00 00                          mov     dword ptr [rbp - 0x3c], 0
          0x4c9757 (+0043)  e8 c4 ae ec ff                                call    0x394620 ; PLT -> _ZNSt6vectorIjSaIjEE12emplace_backIJjEEERjDpOT_
          0x4c975c (+0048)  48 8b 05 ad c4 59 00                          mov     rax, qword ptr [rip + 0x59c4ad] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_fptShareable
          0x4c9763 (+004f)  48 8b 53 48                                   mov     rdx, qword ptr [rbx + 0x48]
          0x4c9767 (+0053)  4c 89 e6                                      mov     rsi, r12
          0x4c976a (+0056)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c976d (+0059)  e8 be a9 ea ff                                call    0x374130 ; PLT -> SysinfoUtil::SysinfoSet
          0x4c9772 (+005e)  4c 89 e7                                      mov     rdi, r12
          0x4c9775 (+0061)  e8 e6 46 ec ff                                call    0x38de60 ; PLT -> _ZNSt12_Vector_baseIjSaIjEED2Ev
          0x4c977a (+0066)  eb 13                                         jmp     0x4c978f
          0x4c977c (+0068)  49 89 c5                                      mov     r13, rax
          0x4c977f (+006b)  4c 89 e7                                      mov     rdi, r12
          0x4c9782 (+006e)  e8 d9 46 ec ff                                call    0x38de60 ; PLT -> _ZNSt12_Vector_baseIjSaIjEED2Ev
          0x4c9787 (+0073)  4c 89 ef                                      mov     rdi, r13
          0x4c978a (+0076)  e8 71 73 eb ff                                call    0x380b00 ; PLT -> _Unwind_Resume
          0x4c978f (+007b)  48 83 c4 28                                   add     rsp, 0x28
          0x4c9793 (+007f)  5b                                            pop     rbx
          0x4c9794 (+0080)  41 5c                                         pop     r12
          0x4c9796 (+0082)  41 5d                                         pop     r13
          0x4c9798 (+0084)  5d                                            pop     rbp
          0x4c9799 (+0085)  c3                                            ret
```

<!-- evidence:M02:end -->

该函数调用 `GetConfiguredFptShareable`，再用 `fptShareable` 对应的 VSI 节点执行写入。下层 setter 为：

<!-- evidence:M03:begin -->

### 切片 M03 shareable 输入取反后设置依赖

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`Hardware_PCIPassthruShareableSet`；入口 `0x42000007263c`，函数大小 `78` 字节。
- 窗口：`0x42000007263c` 到 `0x42000007268a`（右端不含）；文件偏移 `0x33163c`；26 条指令。
- 窗口 SHA-256：`ea6d741c92876fbbd3bfc589214a2a32841e603ae04191dc789728d03ccb4f8c`。[单独查看汇编](snippets/M03.asm)

```asm
    0x42000007263c (+0000)  55                                            push    rbp
    0x42000007263d (+0001)  48 89 f7                                      mov     rdi, rsi
    0x420000072640 (+0004)  48 89 d5                                      mov     rbp, rdx
    0x420000072643 (+0007)  48 83 ec 10                                   sub     rsp, 0x10
    0x420000072647 (+000b)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x42000007264c (+0010)  e8 ff f8 ff ff                                call    0x420000071f50 ; directSymbol -> Hardware_PCIGetDevFromInstArgs
    0x420000072651 (+0015)  85 c0                                         test    eax, eax
    0x420000072653 (+0017)  74 06                                         je      0x42000007265b
    0x420000072655 (+0019)  48 83 c4 10                                   add     rsp, 0x10
    0x420000072659 (+001d)  5d                                            pop     rbp
    0x42000007265a (+001e)  c3                                            ret
    0x42000007265b (+001f)  31 f6                                         xor     esi, esi
    0x42000007265d (+0021)  48 8d 54 24 04                                lea     rdx, [rsp + 4]
    0x420000072662 (+0026)  48 89 ef                                      mov     rdi, rbp
    0x420000072665 (+0029)  e8 9a 2a f9 ff                                call    0x420000005104 ; directSymbol -> VSI_ParamListGetUInt32
    0x42000007266a (+002e)  85 c0                                         test    eax, eax
    0x42000007266c (+0030)  75 e7                                         jne     0x420000072655
    0x42000007266e (+0032)  8b 44 24 04                                   mov     eax, dword ptr [rsp + 4]
    0x420000072672 (+0036)  48 8b 7c 24 08                                mov     rdi, qword ptr [rsp + 8]
    0x420000072677 (+003b)  31 f6                                         xor     esi, esi
    0x420000072679 (+003d)  85 c0                                         test    eax, eax
    0x42000007267b (+003f)  40 0f 94 c6                                   sete    sil
    0x42000007267f (+0043)  e8 b0 90 07 00                                call    0x4200000eb734 ; directSymbol -> PCI_SetMultiFuncDependency
    0x420000072684 (+0048)  48 83 c4 10                                   add     rsp, 0x10
    0x420000072688 (+004c)  5d                                            pop     rbp
    0x420000072689 (+004d)  c3                                            ret
```

<!-- evidence:M03:end -->

`test eax,eax` / `sete sil` 将输入值取反，再调用 `PCI_SetMultiFuncDependency`。因此 false 共享属性对应的是“有多功能依赖”，不是“允许同一 VM 共享一个 IOMMU 域”的直接按钮。

<!-- evidence:M04:begin -->

### 切片 M04 设置依赖所需 Header 和端口类型

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_SetMultiFuncDependency`；入口 `0x4200000eb734`，函数大小 `70` 字节。
- 窗口：`0x4200000eb734` 到 `0x4200000eb77a`（右端不含）；文件偏移 `0x3aa734`；25 条指令。
- 窗口 SHA-256：`9fc524b812bf19ae1af25efa3611047a1979ca75604d67e98f0b466774b8309c`。[单独查看汇编](snippets/M04.asm)

```asm
    0x4200000eb734 (+0000)  80 7f 18 00                                   cmp     byte ptr [rdi + 0x18], 0
    0x4200000eb738 (+0004)  79 3a                                         jns     0x4200000eb774
    0x4200000eb73a (+0006)  55                                            push    rbp
    0x4200000eb73b (+0007)  89 f5                                         mov     ebp, esi
    0x4200000eb73d (+0009)  53                                            push    rbx
    0x4200000eb73e (+000a)  48 89 fb                                      mov     rbx, rdi
    0x4200000eb741 (+000d)  48 83 ec 18                                   sub     rsp, 0x18
    0x4200000eb745 (+0011)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000eb74a (+0016)  e8 a9 aa 00 00                                call    0x4200000f61f8 ; directSymbol -> PCIE_GetPortType
    0x4200000eb74f (+001b)  85 c0                                         test    eax, eax
    0x4200000eb751 (+001d)  75 15                                         jne     0x4200000eb768
    0x4200000eb753 (+001f)  83 7c 24 0c 01                                cmp     dword ptr [rsp + 0xc], 1
    0x4200000eb758 (+0024)  77 0e                                         ja      0x4200000eb768
    0x4200000eb75a (+0026)  40 88 ab f8 01 00 00                          mov     byte ptr [rbx + 0x1f8], bpl
    0x4200000eb761 (+002d)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000eb765 (+0031)  5b                                            pop     rbx
    0x4200000eb766 (+0032)  5d                                            pop     rbp
    0x4200000eb767 (+0033)  c3                                            ret
    0x4200000eb768 (+0034)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000eb76c (+0038)  b8 20 00 ad 0b                                mov     eax, 0xbad0020
    0x4200000eb771 (+003d)  5b                                            pop     rbx
    0x4200000eb772 (+003e)  5d                                            pop     rbp
    0x4200000eb773 (+003f)  c3                                            ret
    0x4200000eb774 (+0040)  b8 20 00 ad 0b                                mov     eax, 0xbad0020
    0x4200000eb779 (+0045)  c3                                            ret
```

<!-- evidence:M04:end -->

写入前先检查当前 Function 的 Header 多功能位；未置位直接返回不支持。随后 `PCIE_GetPortType` 必须成功，且类型值不大于 1，才将依赖值写到 `+0x1f8`。这正是 [02 D01](02-dependency-construction.md#1-完整的依赖计算函数) 读取的字段。

这条“解析值 → VSI setter → 取反 → 字段写入 → 依赖读取”链能解释为什么补上 Function 1 的多功能描述会改变识别结果。它不能证明所有物理设备都能靠这个配置发现真实功能依赖。

## 3 D3D0 为什么不是只要有 PM 就自动使用

<!-- evidence:M05:begin -->

### 切片 M05 D3D0 需要显式选择器

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_HasD3D0Reset`；入口 `0x4200000fc074`，函数大小 `99` 字节。
- 窗口：`0x4200000fc074` 到 `0x4200000fc0d7`（右端不含）；文件偏移 `0x3bb074`；28 条指令。
- 窗口 SHA-256：`a289ea18f3d3731722b3935fa4e0891bf5ecf4128704069190a40071f1cdd46b`。[单独查看汇编](snippets/M05.asm)

```asm
    0x4200000fc074 (+0000)  53                                            push    rbx
    0x4200000fc075 (+0001)  48 89 fb                                      mov     rbx, rdi
    0x4200000fc078 (+0004)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200000fc07c (+0008)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x4200000fc081 (+000d)  c7 44 24 08 00 00 00 00                       mov     dword ptr [rsp + 8], 0
    0x4200000fc089 (+0015)  e8 7a f6 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc08e (+001a)  31 c0                                         xor     eax, eax
    0x4200000fc090 (+001c)  83 7c 24 08 02                                cmp     dword ptr [rsp + 8], 2
    0x4200000fc095 (+0021)  74 06                                         je      0x4200000fc09d
    0x4200000fc097 (+0023)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc09b (+0027)  5b                                            pop     rbx
    0x4200000fc09c (+0028)  c3                                            ret
    0x4200000fc09d (+0029)  48 8d 54 24 07                                lea     rdx, [rsp + 7]
    0x4200000fc0a2 (+002e)  be 01 00 00 00                                mov     esi, 1
    0x4200000fc0a7 (+0033)  48 89 df                                      mov     rdi, rbx
    0x4200000fc0aa (+0036)  e8 2d 40 ff ff                                call    0x4200000f00dc ; directSymbol -> PCI_GetCapOffset
    0x4200000fc0af (+003b)  84 c0                                         test    al, al
    0x4200000fc0b1 (+003d)  74 e4                                         je      0x4200000fc097
    0x4200000fc0b3 (+003f)  0f b6 44 24 07                                movzx   eax, byte ptr [rsp + 7]
    0x4200000fc0b8 (+0044)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000fc0ba (+0046)  48 8d 4c 24 0c                                lea     rcx, [rsp + 0xc]
    0x4200000fc0bf (+004b)  ba 02 00 00 00                                mov     edx, 2
    0x4200000fc0c4 (+0050)  8d 70 04                                      lea     esi, [rax + 4]
    0x4200000fc0c7 (+0053)  e8 38 0e 00 00                                call    0x4200000fcf04 ; directSymbol -> PCIConfig_ReadSafe
    0x4200000fc0cc (+0058)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc0d0 (+005c)  b8 01 00 00 00                                mov     eax, 1
    0x4200000fc0d5 (+0061)  5b                                            pop     rbx
    0x4200000fc0d6 (+0062)  c3                                            ret
```

<!-- evidence:M05:end -->

在 `0x4200000fc090`，已配置的 reset method 必须等于 2，才进入 PM capability 查询。并不是“默认值 0 或显式 2 都可以”。找到 PM capability 以后返回真，也不能单凭这个谓词就证明硬件执行复位后已经清除了敏感状态。

这与早期 PM-only 模型在默认选择下仍被报告 Reset=None 相容。我们没有在这里补造一轮指定 d3d0 后的实测成功。

## 4 完整复位选择函数

<!-- evidence:M06:begin -->

### 切片 M06 复位方法选择的完整函数

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCI_FindResetMethod`；入口 `0x4200000fc450`，函数大小 `358` 字节。
- 窗口：`0x4200000fc450` 到 `0x4200000fc5b6`（右端不含）；文件偏移 `0x3bb450`；93 条指令。
- 窗口 SHA-256：`7742f18c071240660379f560bcd30b9027df6c4b35fd3a7de879320a85a9e2f6`。[单独查看汇编](snippets/M06.asm)

```asm
    0x4200000fc450 (+0000)  53                                            push    rbx
    0x4200000fc451 (+0001)  48 89 fb                                      mov     rbx, rdi
    0x4200000fc454 (+0004)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200000fc458 (+0008)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000fc45d (+000d)  c7 44 24 0c 00 00 00 00                       mov     dword ptr [rsp + 0xc], 0
    0x4200000fc465 (+0015)  e8 9e f2 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc46a (+001a)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200000fc46e (+001e)  85 c0                                         test    eax, eax
    0x4200000fc470 (+0020)  0f 84 89 00 00 00                             je      0x4200000fc4ff
    0x4200000fc476 (+0026)  83 f8 06                                      cmp     eax, 6
    0x4200000fc479 (+0029)  0f 84 80 00 00 00                             je      0x4200000fc4ff
    0x4200000fc47f (+002f)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000fc484 (+0034)  48 89 df                                      mov     rdi, rbx
    0x4200000fc487 (+0037)  c7 44 24 0c 00 00 00 00                       mov     dword ptr [rsp + 0xc], 0
    0x4200000fc48f (+003f)  e8 74 f2 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc494 (+0044)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200000fc498 (+0048)  85 c0                                         test    eax, eax
    0x4200000fc49a (+004a)  74 7c                                         je      0x4200000fc518
    0x4200000fc49c (+004c)  83 f8 05                                      cmp     eax, 5
    0x4200000fc49f (+004f)  74 77                                         je      0x4200000fc518
    0x4200000fc4a1 (+0051)  48 89 df                                      mov     rdi, rbx
    0x4200000fc4a4 (+0054)  e8 a3 fa ff ff                                call    0x4200000fbf4c ; directSymbol -> PCI_HasFLR
    0x4200000fc4a9 (+0059)  41 89 c0                                      mov     r8d, eax
    0x4200000fc4ac (+005c)  b8 01 00 00 00                                mov     eax, 1
    0x4200000fc4b1 (+0061)  45 84 c0                                      test    r8b, r8b
    0x4200000fc4b4 (+0064)  75 43                                         jne     0x4200000fc4f9
    0x4200000fc4b6 (+0066)  48 89 df                                      mov     rdi, rbx
    0x4200000fc4b9 (+0069)  e8 b6 fb ff ff                                call    0x4200000fc074 ; directSymbol -> PCI_HasD3D0Reset
    0x4200000fc4be (+006e)  41 89 c0                                      mov     r8d, eax
    0x4200000fc4c1 (+0071)  b8 02 00 00 00                                mov     eax, 2
    0x4200000fc4c6 (+0076)  45 84 c0                                      test    r8b, r8b
    0x4200000fc4c9 (+0079)  75 2e                                         jne     0x4200000fc4f9
    0x4200000fc4cb (+007b)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000fc4d0 (+0080)  48 89 df                                      mov     rdi, rbx
    0x4200000fc4d3 (+0083)  c7 44 24 0c 00 00 00 00                       mov     dword ptr [rsp + 0xc], 0
    0x4200000fc4db (+008b)  e8 28 f2 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc4e0 (+0090)  f7 44 24 0c fb ff ff ff                       test    dword ptr [rsp + 0xc], 0xfffffffb
    0x4200000fc4e8 (+0098)  75 54                                         jne     0x4200000fc53e
    0x4200000fc4ea (+009a)  48 83 bb e8 00 00 00 00                       cmp     qword ptr [rbx + 0xe8], 0
    0x4200000fc4f2 (+00a2)  b8 04 00 00 00                                mov     eax, 4
    0x4200000fc4f7 (+00a7)  74 73                                         je      0x4200000fc56c
    0x4200000fc4f9 (+00a9)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc4fd (+00ad)  5b                                            pop     rbx
    0x4200000fc4fe (+00ae)  c3                                            ret
    0x4200000fc4ff (+00af)  48 83 bb b8 03 00 00 00                       cmp     qword ptr [rbx + 0x3b8], 0
    0x4200000fc507 (+00b7)  b8 06 00 00 00                                mov     eax, 6
    0x4200000fc50c (+00bc)  0f 84 6d ff ff ff                             je      0x4200000fc47f
    0x4200000fc512 (+00c2)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc516 (+00c6)  5b                                            pop     rbx
    0x4200000fc517 (+00c7)  c3                                            ret
    0x4200000fc518 (+00c8)  31 d2                                         xor     edx, edx
    0x4200000fc51a (+00ca)  48 89 de                                      mov     rsi, rbx
    0x4200000fc51d (+00cd)  bf 03 00 00 00                                mov     edi, 3
    0x4200000fc522 (+00d2)  e8 b9 5c ff ff                                call    0x4200000f21e0 ; directSymbol -> PCIQuirks_CheckDevice
    0x4200000fc527 (+00d7)  41 89 c0                                      mov     r8d, eax
    0x4200000fc52a (+00da)  b8 05 00 00 00                                mov     eax, 5
    0x4200000fc52f (+00df)  45 85 c0                                      test    r8d, r8d
    0x4200000fc532 (+00e2)  0f 85 69 ff ff ff                             jne     0x4200000fc4a1
    0x4200000fc538 (+00e8)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc53c (+00ec)  5b                                            pop     rbx
    0x4200000fc53d (+00ed)  c3                                            ret
    0x4200000fc53e (+00ee)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000fc543 (+00f3)  48 89 df                                      mov     rdi, rbx
    0x4200000fc546 (+00f6)  c7 44 24 0c 00 00 00 00                       mov     dword ptr [rsp + 0xc], 0
    0x4200000fc54e (+00fe)  e8 b5 f1 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc553 (+0103)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200000fc557 (+0107)  85 c0                                         test    eax, eax
    0x4200000fc559 (+0109)  74 05                                         je      0x4200000fc560
    0x4200000fc55b (+010b)  83 f8 03                                      cmp     eax, 3
    0x4200000fc55e (+010e)  75 05                                         jne     0x4200000fc565
    0x4200000fc560 (+0110)  48 85 db                                      test    rbx, rbx
    0x4200000fc563 (+0113)  75 29                                         jne     0x4200000fc58e
    0x4200000fc565 (+0115)  b8 07 00 00 00                                mov     eax, 7
    0x4200000fc56a (+011a)  eb 8d                                         jmp     0x4200000fc4f9
    0x4200000fc56c (+011c)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000fc571 (+0121)  48 89 df                                      mov     rdi, rbx
    0x4200000fc574 (+0124)  c7 44 24 0c 00 00 00 00                       mov     dword ptr [rsp + 0xc], 0
    0x4200000fc57c (+012c)  e8 87 f1 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc581 (+0131)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200000fc585 (+0135)  83 f8 03                                      cmp     eax, 3
    0x4200000fc588 (+0138)  74 04                                         je      0x4200000fc58e
    0x4200000fc58a (+013a)  85 c0                                         test    eax, eax
    0x4200000fc58c (+013c)  75 d7                                         jne     0x4200000fc565
    0x4200000fc58e (+013e)  31 d2                                         xor     edx, edx
    0x4200000fc590 (+0140)  be 10 00 00 00                                mov     esi, 0x10
    0x4200000fc595 (+0145)  48 89 df                                      mov     rdi, rbx
    0x4200000fc598 (+0148)  e8 3f 3b ff ff                                call    0x4200000f00dc ; directSymbol -> PCI_GetCapOffset
    0x4200000fc59d (+014d)  84 c0                                         test    al, al
    0x4200000fc59f (+014f)  74 c4                                         je      0x4200000fc565
    0x4200000fc5a1 (+0151)  48 83 bb e8 00 00 00 00                       cmp     qword ptr [rbx + 0xe8], 0
    0x4200000fc5a9 (+0159)  b8 03 00 00 00                                mov     eax, 3
    0x4200000fc5ae (+015e)  0f 85 45 ff ff ff                             jne     0x4200000fc4f9
    0x4200000fc5b4 (+0164)  eb af                                         jmp     0x4200000fc565
```

<!-- evidence:M06:end -->

这段代码会结合配置选择器、软件回调、quirk、FLR、D3D0、父设备及 PCIe capability 决定方法。不能只截取 `PCI_HasFLR` 一个调用，就称其为全部复位策略。

后续独立复位谓词的完整位运算是 [02 D05](02-dependency-construction.md#4-复位与多功能描述如何改变结果)。方法 1、2、5、6 进入其独立分支；link/bridge 不进入。对于 5、6，本文按本函数调用路径分别描述为 quirk 与软件回调相关方法，不冒充取得了原始枚举头文件。

显式多功能依赖、DMA alias 与复位可独立是三个不同条件。就算选中了独立复位，前两项仍然可能扩大共同管理范围。

## 5 ACS 路径的完整检查和缓存

<!-- evidence:M07:begin -->

### 切片 M07 ACS 类型 检查 缓存与软件策略

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCIE_EnforceACS`；入口 `0x4200000f52d4`，函数大小 `591` 字节。
- 窗口：`0x4200000f52d4` 到 `0x4200000f5523`（右端不含）；文件偏移 `0x3b42d4`；151 条指令。
- 窗口 SHA-256：`51096facac62cfa185314701008cf3345e0fc7aefacfdb8e685d8e454ccee113`。[单独查看汇编](snippets/M07.asm)

```asm
    0x4200000f52d4 (+0000)  41 56                                         push    r14
    0x4200000f52d6 (+0002)  41 55                                         push    r13
    0x4200000f52d8 (+0004)  41 54                                         push    r12
    0x4200000f52da (+0006)  49 89 fc                                      mov     r12, rdi
    0x4200000f52dd (+0009)  55                                            push    rbp
    0x4200000f52de (+000a)  53                                            push    rbx
    0x4200000f52df (+000b)  48 89 fb                                      mov     rbx, rdi
    0x4200000f52e2 (+000e)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200000f52e6 (+0012)  80 bf fa 01 00 00 00                          cmp     byte ptr [rdi + 0x1fa], 0
    0x4200000f52ed (+0019)  74 2d                                         je      0x4200000f531c
    0x4200000f52ef (+001b)  e9 ee 01 00 00                                jmp     0x4200000f54e2
    0x4200000f52f4 (+0020)  83 e5 fd                                      and     ebp, 0xfffffffd
    0x4200000f52f7 (+0023)  40 80 fd 04                                   cmp     bpl, 4
    0x4200000f52fb (+0027)  0f 84 43 01 00 00                             je      0x4200000f5444
    0x4200000f5301 (+002d)  8b 03                                         mov     eax, dword ptr [rbx]
    0x4200000f5303 (+002f)  0f b6 f4                                      movzx   esi, ah
    0x4200000f5306 (+0032)  c1 e8 10                                      shr     eax, 0x10
    0x4200000f5309 (+0035)  89 c7                                         mov     edi, eax
    0x4200000f530b (+0037)  e8 dc 61 ff ff                                call    0x4200000eb4ec ; directSymbol -> PCI_GetParent
    0x4200000f5310 (+003c)  48 89 c3                                      mov     rbx, rax
    0x4200000f5313 (+003f)  48 85 c0                                      test    rax, rax
    0x4200000f5316 (+0042)  0f 84 5f 01 00 00                             je      0x4200000f547b
    0x4200000f531c (+0048)  48 8b 83 48 02 00 00                          mov     rax, qword ptr [rbx + 0x248]
    0x4200000f5323 (+004f)  48 85 c0                                      test    rax, rax
    0x4200000f5326 (+0052)  74 d9                                         je      0x4200000f5301
    0x4200000f5328 (+0054)  0f b6 68 02                                   movzx   ebp, byte ptr [rax + 2]
    0x4200000f532c (+0058)  40 c0 ed 04                                   shr     bpl, 4
    0x4200000f5330 (+005c)  41 89 ee                                      mov     r14d, ebp
    0x4200000f5333 (+005f)  44 0f b6 ed                                   movzx   r13d, bpl
    0x4200000f5337 (+0063)  41 83 e6 fb                                   and     r14d, 0xfffffffb
    0x4200000f533b (+0067)  41 83 fd 06                                   cmp     r13d, 6
    0x4200000f533f (+006b)  74 05                                         je      0x4200000f5346
    0x4200000f5341 (+006d)  45 84 f6                                      test    r14b, r14b
    0x4200000f5344 (+0070)  75 bb                                         jne     0x4200000f5301
    0x4200000f5346 (+0072)  48 8d 54 24 0a                                lea     rdx, [rsp + 0xa]
    0x4200000f534b (+0077)  be 0d 00 00 00                                mov     esi, 0xd
    0x4200000f5350 (+007c)  48 89 df                                      mov     rdi, rbx
    0x4200000f5353 (+007f)  e8 c4 ad ff ff                                call    0x4200000f011c ; directSymbol -> PCI_GetExtCapOffset
    0x4200000f5358 (+0084)  84 c0                                         test    al, al
    0x4200000f535a (+0086)  74 98                                         je      0x4200000f52f4
    0x4200000f535c (+0088)  0f b7 44 24 0a                                movzx   eax, word ptr [rsp + 0xa]
    0x4200000f5361 (+008d)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000f5363 (+008f)  48 8d 4c 24 0c                                lea     rcx, [rsp + 0xc]
    0x4200000f5368 (+0094)  ba 02 00 00 00                                mov     edx, 2
    0x4200000f536d (+0099)  bd ff ff ff ff                                mov     ebp, 0xffffffff
    0x4200000f5372 (+009e)  8d 70 04                                      lea     esi, [rax + 4]
    0x4200000f5375 (+00a1)  0f b7 f6                                      movzx   esi, si
    0x4200000f5378 (+00a4)  e8 87 7b 00 00                                call    0x4200000fcf04 ; directSymbol -> PCIConfig_ReadSafe
    0x4200000f537d (+00a9)  48 89 df                                      mov     rdi, rbx
    0x4200000f5380 (+00ac)  85 c0                                         test    eax, eax
    0x4200000f5382 (+00ae)  66 0f 44 6c 24 0c                             cmove   bp, word ptr [rsp + 0xc]
    0x4200000f5388 (+00b4)  e8 6f 83 00 00                                call    0x4200000fd6fc ; directSymbol -> PCIQuirks_GetAcsCtrlOffset
    0x4200000f538d (+00b9)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000f538f (+00bb)  66 03 44 24 0a                                add     ax, word ptr [rsp + 0xa]
    0x4200000f5394 (+00c0)  48 8d 4c 24 0c                                lea     rcx, [rsp + 0xc]
    0x4200000f5399 (+00c5)  0f b7 f0                                      movzx   esi, ax
    0x4200000f539c (+00c8)  ba 02 00 00 00                                mov     edx, 2
    0x4200000f53a1 (+00cd)  e8 5e 7b 00 00                                call    0x4200000fcf04 ; directSymbol -> PCIConfig_ReadSafe
    0x4200000f53a6 (+00d2)  85 c0                                         test    eax, eax
    0x4200000f53a8 (+00d4)  b8 ff ff ff ff                                mov     eax, 0xffffffff
    0x4200000f53ad (+00d9)  66 0f 44 44 24 0c                             cmove   ax, word ptr [rsp + 0xc]
    0x4200000f53b3 (+00df)  45 84 f6                                      test    r14b, r14b
    0x4200000f53b6 (+00e2)  0f 85 e2 00 00 00                             jne     0x4200000f549e
    0x4200000f53bc (+00e8)  89 ea                                         mov     edx, ebp
    0x4200000f53be (+00ea)  83 e2 0c                                      and     edx, 0xc
    0x4200000f53c1 (+00ed)  66 83 fa 0c                                   cmp     dx, 0xc
    0x4200000f53c5 (+00f1)  0f 84 dd 00 00 00                             je      0x4200000f54a8
    0x4200000f53cb (+00f7)  41 83 fd 04                                   cmp     r13d, 4
    0x4200000f53cf (+00fb)  0f 85 2c ff ff ff                             jne     0x4200000f5301
    0x4200000f53d5 (+0101)  8d 14 ad 00 00 00 00                          lea     edx, [rbp*4]
    0x4200000f53dc (+0108)  83 e2 10                                      and     edx, 0x10
    0x4200000f53df (+010b)  83 ca 01                                      or      edx, 1
    0x4200000f53e2 (+010e)  89 d1                                         mov     ecx, edx
    0x4200000f53e4 (+0110)  21 e9                                         and     ecx, ebp
    0x4200000f53e6 (+0112)  66 39 d1                                      cmp     cx, dx
    0x4200000f53e9 (+0115)  0f 85 07 01 00 00                             jne     0x4200000f54f6
    0x4200000f53ef (+011b)  89 d1                                         mov     ecx, edx
    0x4200000f53f1 (+011d)  21 c1                                         and     ecx, eax
    0x4200000f53f3 (+011f)  66 39 d1                                      cmp     cx, dx
    0x4200000f53f6 (+0122)  0f 85 fa 00 00 00                             jne     0x4200000f54f6
    0x4200000f53fc (+0128)  45 85 ed                                      test    r13d, r13d
    0x4200000f53ff (+012b)  0f 84 fc fe ff ff                             je      0x4200000f5301
    0x4200000f5405 (+0131)  40 84 ed                                      test    bpl, bpl
    0x4200000f5408 (+0134)  0f 89 f3 fe ff ff                             jns     0x4200000f5301
    0x4200000f540e (+013a)  0f b6 c4                                      movzx   eax, ah
    0x4200000f5411 (+013d)  83 e0 0f                                      and     eax, 0xf
    0x4200000f5414 (+0140)  3c 0a                                         cmp     al, 0xa
    0x4200000f5416 (+0142)  0f 84 e5 fe ff ff                             je      0x4200000f5301
    0x4200000f541c (+0148)  44 89 e8                                      mov     eax, r13d
    0x4200000f541f (+014b)  48 8d 15 fa ee fc bf                          lea     rdx, [rip - 0x40031106] ; GOT ->
    0x4200000f5426 (+0152)  be d3 00 00 00                                mov     esi, 0xd3
    0x4200000f542b (+0157)  48 8b 0c c2                                   mov     rcx, qword ptr [rdx + rax*8]
    0x4200000f542f (+015b)  48 8d 3d c2 e8 67 00                          lea     rdi, [rip + 0x67e8c2] ; literal "PCIE: %d: %s: %s ACS Memory Target Access Control not configured\n"
    0x4200000f5436 (+0162)  48 8d 93 08 01 00 00                          lea     rdx, [rbx + 0x108]
    0x4200000f543d (+0169)  31 c0                                         xor     eax, eax
    0x4200000f543f (+016b)  e8 08 4e 07 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x4200000f5444 (+0170)  0f b6 05 7a 86 1e c0                          movzx   eax, byte ptr [rip - 0x3fe17986] ; ripSymbol -> disableACSCheck
    0x4200000f544b (+0177)  84 c0                                         test    al, al
    0x4200000f544d (+0179)  75 11                                         jne     0x4200000f5460
    0x4200000f544f (+017b)  41 83 fd 04                                   cmp     r13d, 4
    0x4200000f5453 (+017f)  75 2b                                         jne     0x4200000f5480
    0x4200000f5455 (+0181)  0f b6 05 68 86 1e c0                          movzx   eax, byte ptr [rip - 0x3fe17998] ; ripSymbol -> disableACSCheckForRP
    0x4200000f545c (+0188)  84 c0                                         test    al, al
    0x4200000f545e (+018a)  74 20                                         je      0x4200000f5480
    0x4200000f5460 (+018c)  49 8d 94 24 08 01 00 00                       lea     rdx, [r12 + 0x108]
    0x4200000f5468 (+0194)  be e4 00 00 00                                mov     esi, 0xe4
    0x4200000f546d (+0199)  48 8d 3d 24 bc 6b 00                          lea     rdi, [rip + 0x6bbc24] ; literal "PCIE: %d: %s: Bypassing non-ACS capable device in hierarchy\n"
    0x4200000f5474 (+01a0)  31 c0                                         xor     eax, eax
    0x4200000f5476 (+01a2)  e8 d1 4d 07 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x4200000f547b (+01a7)  b8 01 00 00 00                                mov     eax, 1
    0x4200000f5480 (+01ac)  41 88 84 24 fb 01 00 00                       mov     byte ptr [r12 + 0x1fb], al
    0x4200000f5488 (+01b4)  41 c6 84 24 fa 01 00 00 01                    mov     byte ptr [r12 + 0x1fa], 1
    0x4200000f5491 (+01bd)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000f5495 (+01c1)  5b                                            pop     rbx
    0x4200000f5496 (+01c2)  5d                                            pop     rbp
    0x4200000f5497 (+01c3)  41 5c                                         pop     r12
    0x4200000f5499 (+01c5)  41 5d                                         pop     r13
    0x4200000f549b (+01c7)  41 5e                                         pop     r14
    0x4200000f549d (+01c9)  c3                                            ret
    0x4200000f549e (+01ca)  ba 1d 00 00 00                                mov     edx, 0x1d
    0x4200000f54a3 (+01cf)  e9 3a ff ff ff                                jmp     0x4200000f53e2
    0x4200000f54a8 (+01d4)  89 c2                                         mov     edx, eax
    0x4200000f54aa (+01d6)  31 ea                                         xor     edx, ebp
    0x4200000f54ac (+01d8)  83 e2 0c                                      and     edx, 0xc
    0x4200000f54af (+01db)  0f 84 16 ff ff ff                             je      0x4200000f53cb
    0x4200000f54b5 (+01e1)  44 89 e8                                      mov     eax, r13d
    0x4200000f54b8 (+01e4)  48 8d 15 61 ee fc bf                          lea     rdx, [rip - 0x4003119f] ; GOT ->
    0x4200000f54bf (+01eb)  be aa 00 00 00                                mov     esi, 0xaa
    0x4200000f54c4 (+01f0)  48 8b 0c c2                                   mov     rcx, qword ptr [rdx + rax*8]
    0x4200000f54c8 (+01f4)  48 8d 3d 31 4f 73 00                          lea     rdi, [rip + 0x734f31] ; literal "PCIE: %d: %s: %s ACS settings (R, C) not configured for blocking P2P\n"
    0x4200000f54cf (+01fb)  48 8d 93 08 01 00 00                          lea     rdx, [rbx + 0x108]
    0x4200000f54d6 (+0202)  31 c0                                         xor     eax, eax
    0x4200000f54d8 (+0204)  e8 6f 4d 07 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x4200000f54dd (+0209)  e9 62 ff ff ff                                jmp     0x4200000f5444
    0x4200000f54e2 (+020e)  0f b6 87 fb 01 00 00                          movzx   eax, byte ptr [rdi + 0x1fb]
    0x4200000f54e9 (+0215)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000f54ed (+0219)  5b                                            pop     rbx
    0x4200000f54ee (+021a)  5d                                            pop     rbp
    0x4200000f54ef (+021b)  41 5c                                         pop     r12
    0x4200000f54f1 (+021d)  41 5d                                         pop     r13
    0x4200000f54f3 (+021f)  41 5e                                         pop     r14
    0x4200000f54f5 (+0221)  c3                                            ret
    0x4200000f54f6 (+0222)  44 89 e8                                      mov     eax, r13d
    0x4200000f54f9 (+0225)  48 8d 15 20 ee fc bf                          lea     rdx, [rip - 0x400311e0] ; GOT ->
    0x4200000f5500 (+022c)  be c3 00 00 00                                mov     esi, 0xc3
    0x4200000f5505 (+0231)  48 8b 0c c2                                   mov     rcx, qword ptr [rdx + rax*8]
    0x4200000f5509 (+0235)  48 8d 3d c8 27 6d 00                          lea     rdi, [rip + 0x6d27c8] ; literal "PCIE: %d: %s: %s ACS settings (V, U) not configured for blocking P2P\n"
    0x4200000f5510 (+023c)  48 8d 93 08 01 00 00                          lea     rdx, [rbx + 0x108]
    0x4200000f5517 (+0243)  31 c0                                         xor     eax, eax
    0x4200000f5519 (+0245)  e8 2e 4d 07 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x4200000f551e (+024a)  e9 21 ff ff ff                                jmp     0x4200000f5444
```

<!-- evidence:M07:end -->

可以分为四段阅读：

1. `0xf52e6` 先检查对象 `+0x1fa`。已有缓存时跳到 `0xf54e2` 返回 `+0x1fb`，并不是每次都重新读 PCI 配置。
2. 沿当前节点和上游节点处理相关 PCIe 类型，查 extended capability `0x0d`，读取 capability/control，并使用 quirk 提供的 control offset。
3. 按节点类型检查相应位组合。代码中能看到 `0x0c`、`0x1d` 等掩码及不同跳转，不能把它简化成只有一个 ACS present 位。
4. 拒绝点还会检查 `disableACSCheck`，以及特定 root-port 情况下的 `disableACSCheckForRP`。最后保存 verdict 与缓存有效位。

上表省略公共地址前缀；代码块保留完整地址。缓存何时失效与重新计算，需要检查它的所有写入者，本套没有由这段函数推断完整失效协议。

因此，`meetsPassthruAcsReq=true` 可以来自实际检查接受，也可能经过所见策略例外。它不是无条件的物理隔离证书。我们的 Linux ACS override 常开前提仍需要独立的原生安全域证据，不能把 VMware 此处的策略例外或 patched group 当作硬件事实。

## 6 对本次传统桥失败的边界

修改 shareable 可以改变 `+0x1f8`，从而改变依赖代表；修改 reset method 可以改变复位选择。但是 [05](05-domain-lifecycle.md) 中的域查询、整组切域和新登记返回码比较是另外的代码。

已有 default false 控制在底层读回为 0 后，仍命中已有域拒绝。这个结果证明该次共享属性修改没有解决该故障；不证明所有 map 组合都被测试过，也不证明强制某个复位方法会对真实设备安全有效。
