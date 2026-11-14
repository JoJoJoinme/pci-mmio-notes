# 01 IsPassthruCapable 的逐段证据

本章要证明的不是“VMware 大概检查 IOMMU”，而是这个 build 的管理库究竟读取什么、在哪个条件返回 false，以及这些字段从哪里来。

## 1 完整的 174 字节函数

<!-- evidence:A01:begin -->

### 切片 A01 完整 capable 谓词

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::IsPassthruCapable`；入口 `0x4c2438`，函数大小 `174` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl17IsPassthruCapableEv`。
- 窗口：`0x4c2438` 到 `0x4c24e6`（右端不含）；文件偏移 `0x4c2438`；46 条指令。
- 窗口 SHA-256：`9a4ff2c07205b2267b41f3510776b3f1d58d790b3d31ba51d8078a8be91e24dc`。[单独查看汇编](snippets/A01.asm)

```asm
          0x4c2438 (+0000)  80 7f 77 00                                   cmp     byte ptr [rdi + 0x77], 0
          0x4c243c (+0004)  0f 85 a1 00 00 00                             jne     0x4c24e3
          0x4c2442 (+000a)  55                                            push    rbp
          0x4c2443 (+000b)  ba 01 00 00 00                                mov     edx, 1
          0x4c2448 (+0010)  48 89 e5                                      mov     rbp, rsp
          0x4c244b (+0013)  53                                            push    rbx
          0x4c244c (+0014)  48 89 fb                                      mov     rbx, rdi
          0x4c244f (+0017)  48 8d 75 de                                   lea     rsi, [rbp - 0x22]
          0x4c2453 (+001b)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c2457 (+001f)  48 8b 05 6a 49 5a 00                          mov     rax, qword ptr [rip + 0x5a496a] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_inIommuScope
          0x4c245e (+0026)  48 8b 4f 48                                   mov     rcx, qword ptr [rdi + 0x48]
          0x4c2462 (+002a)  c6 45 de 00                                   mov     byte ptr [rbp - 0x22], 0
          0x4c2466 (+002e)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c2469 (+0031)  e8 22 ef eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c246e (+0036)  80 7d de 00                                   cmp     byte ptr [rbp - 0x22], 0
          0x4c2472 (+003a)  75 04                                         jne     0x4c2478
          0x4c2474 (+003c)  31 c0                                         xor     eax, eax
          0x4c2476 (+003e)  eb 64                                         jmp     0x4c24dc
          0x4c2478 (+0040)  48 8b 05 29 4e 5a 00                          mov     rax, qword ptr [rip + 0x5a4e29] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_meetsPassthruAcsReq
          0x4c247f (+0047)  48 8b 4b 48                                   mov     rcx, qword ptr [rbx + 0x48]
          0x4c2483 (+004b)  48 8d 75 df                                   lea     rsi, [rbp - 0x21]
          0x4c2487 (+004f)  ba 01 00 00 00                                mov     edx, 1
          0x4c248c (+0054)  c6 45 df 00                                   mov     byte ptr [rbp - 0x21], 0
          0x4c2490 (+0058)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c2493 (+005b)  e8 f8 ee eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c2498 (+0060)  80 7d df 00                                   cmp     byte ptr [rbp - 0x21], 0
          0x4c249c (+0064)  74 d6                                         je      0x4c2474
          0x4c249e (+0066)  48 8b 05 93 32 5a 00                          mov     rax, qword ptr [rip + 0x5a3293] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_passthruDependent
          0x4c24a5 (+006d)  48 8b 4b 48                                   mov     rcx, qword ptr [rbx + 0x48]
          0x4c24a9 (+0071)  48 8d 75 e0                                   lea     rsi, [rbp - 0x20]
          0x4c24ad (+0075)  ba 10 00 00 00                                mov     edx, 0x10
          0x4c24b2 (+007a)  48 c7 45 e0 ff ff ff ff                       mov     qword ptr [rbp - 0x20], 0xffffffffffffffff
          0x4c24ba (+0082)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c24bd (+0085)  48 c7 45 e8 ff ff ff ff                       mov     qword ptr [rbp - 0x18], 0xffffffffffffffff
          0x4c24c5 (+008d)  e8 c6 ee eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c24ca (+0092)  48 8b 7d e0                                   mov     rdi, qword ptr [rbp - 0x20]
          0x4c24ce (+0096)  48 8b 75 e8                                   mov     rsi, qword ptr [rbp - 0x18]
          0x4c24d2 (+009a)  e8 b9 f4 ff ff                                call    0x4c1990
          0x4c24d7 (+009f)  84 c0                                         test    al, al
          0x4c24d9 (+00a1)  0f 94 c0                                      sete    al
          0x4c24dc (+00a4)  48 83 c4 28                                   add     rsp, 0x28
          0x4c24e0 (+00a8)  5b                                            pop     rbx
          0x4c24e1 (+00a9)  5d                                            pop     rbp
          0x4c24e2 (+00aa)  c3                                            ret
          0x4c24e3 (+00ab)  31 c0                                         xor     eax, eax
          0x4c24e5 (+00ad)  c3                                            ret
```

<!-- evidence:A01:end -->

### 调用名称的 PLT 和 GOT 证据

下表把关键名字展开到链接数据。GOT 槽的原始内容与运行时解析后的地址不是一回事；重定位记录才说明加载器应把哪个符号放进槽。三个 VSI 节点都来自这些记录，不是靠字符串搜索附会。

| 源指令 | PLT 地址与原始跳转字节 | GOT 槽与原始内容 | 重定位类型及目标 |
| --- | --- | --- | --- |
| 0x4c2457 | 直接 RIP 取槽  | 0xa66dc8 / 0000000000000000 | 6 / `VSI_NODE_hardware_pci_seg_bus_slot_func_inIommuScope` |
| 0x4c2469 | 0x381390 ff250a9e6d00 | 0xa5b1a0 / 9613380000000000 | 7 / `SysinfoUtil::SysinfoGet` |
| 0x4c2478 | 直接 RIP 取槽  | 0xa672a8 / 0000000000000000 | 6 / `VSI_NODE_hardware_pci_seg_bus_slot_func_meetsPassthruAcsReq` |
| 0x4c249e | 直接 RIP 取槽  | 0xa65738 / 0000000000000000 | 6 / `VSI_NODE_hardware_pci_seg_bus_slot_func_passthruDependent` |
| 0x4c6db7 | 0x389060 ff25a25f6d00 | 0xa5f008 / 6690380000000000 | 7 / `KernelOpts::GetRuntimeValueBool` |

把这段代码按基本块阅读：

| 地址 | 指令事实 | 允许继续的条件 |
| --- | --- | --- |
| `0x4c2438` | 比较 `this+0x77`；非零跳 `0x4c24e3` 清零返回 | 字段为零 |
| `0x4c2457` | GOT 指向 `inIommuScope` 节点，输出缓冲长 1 字节 | 查询后的栈字节不为零 |
| `0x4c2478` | GOT 指向 `meetsPassthruAcsReq` 节点 | 查询后的另一栈字节不为零 |
| `0x4c249e` | GOT 指向 `passthruDependent`，读取 16 字节结果 | 结果不等于无效 SBDF 哨兵 |
| `0x4c24d2` | 调用匿名无效值判定，随后 `test` 与 `sete` | 将“无效”为真取反后返回 |

注意：两个布尔 VSI 查询后，检查的是**栈上的输出字节**，不是把 `SysinfoGet` 返回的 EAX 当成布尔值。上表描述普通返回路径；读取异常如何交给上层处理，不应由这几次 `cmp` 自行补出来。

等价的说明性伪代码为：

```text
if saved_disable_flag != 0: return false
if read_bool(inIommuScope) == false: return false
if read_bool(meetsPassthruAcsReq) == false: return false
sbdf_tuple = read_16_bytes(passthruDependent)
return not is_invalid_sbdf_tuple(sbdf_tuple)
```

## 2 this 加 0x77 为什么解释为禁用位

不能看见一个字节比较就给它起业务名字。这里有写入者：`SetFromSBDF` 读取运行选项 `disablePciPassthrough` 后，把 AL 写到同一对象的 `+0x77`。

<!-- evidence:A02:begin -->

### 切片 A02 禁用字段的写入来源

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SetFromSBDF`；入口 `0x4c6bca`，函数大小 `611` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl11SetFromSBDFEthhh`。
- 窗口：`0x4c6d9f` 到 `0x4c6dc9`（右端不含）；文件偏移 `0x4c6d9f`；10 条指令。
- 窗口 SHA-256：`0439b0da11f8d629e84200b69b93bdb39d7720780846dfa2da5427e672d6ff2e`。[单独查看汇编](snippets/A02.asm)

```asm
          0x4c6d9f (+01d5)  48 89 da                                      mov     rdx, rbx
          0x4c6da2 (+01d8)  48 8d 35 01 eb 37 00                          lea     rsi, [rip + 0x37eb01] ; literal "disablePciPassthrough"
          0x4c6da9 (+01df)  4c 89 ef                                      mov     rdi, r13
          0x4c6dac (+01e2)  e8 2f 9d ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c6db1 (+01e7)  4c 89 ee                                      mov     rsi, r13
          0x4c6db4 (+01ea)  4c 89 f7                                      mov     rdi, r14
          0x4c6db7 (+01ed)  e8 a4 22 ec ff                                call    0x389060 ; PLT -> KernelOpts::GetRuntimeValueBool
          0x4c6dbc (+01f2)  41 88 44 24 77                                mov     byte ptr [r12 + 0x77], al
          0x4c6dc1 (+01f7)  4c 89 ef                                      mov     rdi, r13
          0x4c6dc4 (+01fa)  e8 97 da ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
```

<!-- evidence:A02:end -->

`0x4c6db7` 的 PLT 目标为 `KernelOpts::GetRuntimeValueBool`，紧接着的 `0x4c6dbc` 保存 AL。选项字符串通过调用前构造的参数传入；该字符串地址及原函数范围可用相同 ELF 复核。

所以 `IsPassthruCapable` 的入口读的是对象中保存的值；不能再扩写成“每次调用都即时重读全局内核选项”。对象刷新时机还需结合它的调用者。

## 3 无效 SBDF 不是一个凭经验猜出的特殊值

下面是 `0x4c1990` 的完整 23 字节辅助函数。这个标签由本文为阅读方便命名；原 ELF 没有给出相应可用函数名。

<!-- evidence:A03:begin -->

### 切片 A03 全一 SBDF 哨兵的判定

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`匿名无效 SBDF 辅助函数`；入口 `0x4c1990`，函数大小 `23` 字节。
- 窗口：`0x4c1990` 到 `0x4c19a7`（右端不含）；文件偏移 `0x4c1990`；9 条指令。
- 窗口 SHA-256：`e1968ecb7ea9647b5ccb90af72d9d4b69ffc6dbcddda850741cbd68466a54aad`。[单独查看汇编](snippets/A03.asm)

```asm
          0x4c1990 (+0000)  48 89 f8                                      mov     rax, rdi
          0x4c1993 (+0003)  48 c1 e8 20                                   shr     rax, 0x20
          0x4c1997 (+0007)  21 c7                                         and     edi, eax
          0x4c1999 (+0009)  21 f7                                         and     edi, esi
          0x4c199b (+000b)  48 c1 ee 20                                   shr     rsi, 0x20
          0x4c199f (+000f)  21 f7                                         and     edi, esi
          0x4c19a1 (+0011)  ff c7                                         inc     edi
          0x4c19a3 (+0013)  0f 94 c0                                      sete    al
          0x4c19a6 (+0016)  c3                                            ret
```

<!-- evidence:A03:end -->

RDI 和 RSI 各带两个 32 位字段。代码把四个字段按位与，再加一，只有与结果为 `0xffffffff` 时才产生零并令 AL=1。四个字段同时全一才满足这个条件。

调用者读取 16 字节，先初始化为全一；内核 VSI 提供者在依赖查找失败时也写入同样的哨兵。代表是设备自身仍然是有效结果；“没有外部依赖”不是 capable=false 的理由。VSI 到 packed SBDF 的转换见 [02](02-dependency-construction.md#5-四字段-vsi-输出与-packed-sbdf)。

## 4 inIommuScope 的下一层

<!-- evidence:A04:begin -->

### 切片 A04 IOMMU 覆盖条件

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`Hardware_PCIIsInIommuScope`；入口 `0x4200000734b4`，函数大小 `90` 字节。
- 窗口：`0x4200000734b4` 到 `0x42000007350e`（右端不含）；文件偏移 `0x3324b4`；33 条指令。
- 窗口 SHA-256：`6f0650815d0a677739d65cb08b29784ae2c4309bf24b779e7a3d2c8138bdeee5`。[单独查看汇编](snippets/A04.asm)

```asm
    0x4200000734b4 (+0000)  41 54                                         push    r12
    0x4200000734b6 (+0002)  48 89 f7                                      mov     rdi, rsi
    0x4200000734b9 (+0005)  53                                            push    rbx
    0x4200000734ba (+0006)  48 89 d3                                      mov     rbx, rdx
    0x4200000734bd (+0009)  48 83 ec 18                                   sub     rsp, 0x18
    0x4200000734c1 (+000d)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x4200000734c6 (+0012)  e8 85 ea ff ff                                call    0x420000071f50 ; directSymbol -> Hardware_PCIGetDevFromInstArgs
    0x4200000734cb (+0017)  41 89 c4                                      mov     r12d, eax
    0x4200000734ce (+001a)  85 c0                                         test    eax, eax
    0x4200000734d0 (+001c)  74 0b                                         je      0x4200000734dd
    0x4200000734d2 (+001e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000734d6 (+0022)  44 89 e0                                      mov     eax, r12d
    0x4200000734d9 (+0025)  5b                                            pop     rbx
    0x4200000734da (+0026)  41 5c                                         pop     r12
    0x4200000734dc (+0028)  c3                                            ret
    0x4200000734dd (+0029)  e8 52 08 0f 00                                call    0x420000163d34 ; directSymbol -> IOMMU_IsIommuEnabled
    0x4200000734e2 (+002e)  41 89 c0                                      mov     r8d, eax
    0x4200000734e5 (+0031)  31 c0                                         xor     eax, eax
    0x4200000734e7 (+0033)  45 84 c0                                      test    r8b, r8b
    0x4200000734ea (+0036)  75 0d                                         jne     0x4200000734f9
    0x4200000734ec (+0038)  88 03                                         mov     byte ptr [rbx], al
    0x4200000734ee (+003a)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000734f2 (+003e)  44 89 e0                                      mov     eax, r12d
    0x4200000734f5 (+0041)  5b                                            pop     rbx
    0x4200000734f6 (+0042)  41 5c                                         pop     r12
    0x4200000734f8 (+0044)  c3                                            ret
    0x4200000734f9 (+0045)  48 8b 44 24 08                                mov     rax, qword ptr [rsp + 8]
    0x4200000734fe (+004a)  8b 38                                         mov     edi, dword ptr [rax]
    0x420000073500 (+004c)  e8 f3 20 0f 00                                call    0x4200001655f8 ; directSymbol -> IOMMU_IsDeviceSupported
    0x420000073505 (+0051)  84 c0                                         test    al, al
    0x420000073507 (+0053)  0f 95 c0                                      setne   al
    0x42000007350a (+0056)  88 03                                         mov     byte ptr [rbx], al
    0x42000007350c (+0058)  eb e0                                         jmp     0x4200000734ee
```

<!-- evidence:A04:end -->

`0x4200000734dd` 调用 `IOMMU_IsIommuEnabled`。为假时输出字节为零；为真才用设备的 packed SBDF 调用 `IOMMU_IsDeviceSupported`，把其真假写入输出。

这建立了实际调用链：

```text
IsPassthruCapable
  → SysinfoGet(inIommuScope)
    → Hardware_PCIIsInIommuScope
      → IOMMU_IsIommuEnabled
      → IOMMU_IsDeviceSupported
```

它证明主机 IOMMU 开启与设备落入支持范围是两项条件；没有继续还原所有架构 IOMMU backend 的 `IsDeviceSupported` 实现。

## 5 本函数没有回答的问题

完整 A01 中没有当前 VM 的 owner 比较，没有 guest BAR 布局计算，也没有启动盘用途判断。启动盘和保留用途检查在 [03](03-owner-transitions.md)，VM owner 冲突在 [04](04-vm-admission.md)，已有域初始化冲突在 [05](05-domain-lifecycle.md)。ACS 节点的真实实现另见 [06](06-reset-map-acs.md)。

与运行数据对应：同 VID:DID 的 IOMMU、ACS、复位/拓扑控制可以改变 capable；[历史资格矩阵](../../vmware-esxi8-passthru-capable-observed-model.md)支持这里的分层解释，但不把合成设备变成正式兼容目录条目。
