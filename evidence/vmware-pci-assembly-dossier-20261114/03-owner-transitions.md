# 03 主机启用禁用和依赖联动的指令证据

本章区分 configured owner 与 runtime owner。下面能直接看到的是管理库的条件和配置写入，不把写 ConfigStore 这一刻描述成设备已经完成解绑、复位或硬件切域。

## 1 启用验证的四个连续关口

下面四个切片来自同一个 `ValidateOwnerToPassthru`。切片之间的大段 C++ 字符串和异常构造没有连写；它们各自的跳转地址保留在代码里。

<!-- evidence:O01:begin -->

### 切片 O01 禁用状态的拒绝条件

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbace` 到 `0x4cbafa`（右端不含）；文件偏移 `0x4cbace`；9 条指令。
- 窗口 SHA-256：`845c8f84dacca29c6c35382646e050ed7a39b302676d94b5ac827ba132b427e9`。[单独查看汇编](snippets/O01.asm)

```asm
          0x4cbace (+0022)  80 7f 77 00                                   cmp     byte ptr [rdi + 0x77], 0
          0x4cbad2 (+0026)  48 8d 43 18                                   lea     rax, [rbx + 0x18]
          0x4cbad6 (+002a)  48 89 85 78 ff ff ff                          mov     qword ptr [rbp - 0x88], rax
          0x4cbadd (+0031)  0f 84 d5 00 00 00                             je      0x4cbbb8 ; branch leaves this window
          0x4cbae3 (+0037)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbae7 (+003b)  48 8d 35 21 9d 37 00                          lea     rsi, [rip + 0x379d21] ; literal " for PCI passthrough when this feature is disabled."
          0x4cbaee (+0042)  e8 7d 66 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbaf3 (+0047)  4c 8d 75 80                                   lea     r14, [rbp - 0x80]
          0x4cbaf7 (+004b)  4c 89 e6                                      mov     rsi, r12
```

<!-- evidence:O01:end -->

字段 `+0x77` 为零时，`je 0x4cbbb8` 去下一关；非零走功能禁用的异常构造。字段来源见 [01 A02](01-capable.md#2-this-加-0x77-为什么解释为禁用位)。

<!-- evidence:O02:begin -->

### 切片 O02 启动设备检查

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbbb8` 到 `0x4cbbed`（右端不含）；文件偏移 `0x4cbbb8`；13 条指令。
- 窗口 SHA-256：`3de81051074d58da24434a70b23da009d7cbec2384ba0a238229510d191c4449`。[单独查看汇编](snippets/O02.asm)

```asm
          0x4cbbb8 (+010c)  e8 93 cb eb ff                                call    0x388750 ; PLT -> PciDeviceImpl::IsBootDevice
          0x4cbbbd (+0111)  84 c0                                         test    al, al
          0x4cbbbf (+0113)  0f 84 a5 00 00 00                             je      0x4cbc6a ; branch leaves this window
          0x4cbbc5 (+0119)  4c 8d 75 b0                                   lea     r14, [rbp - 0x50]
          0x4cbbc9 (+011d)  4c 89 e6                                      mov     rsi, r12
          0x4cbbcc (+0120)  4c 89 f7                                      mov     rdi, r14
          0x4cbbcf (+0123)  e8 1c 38 ec ff                                call    0x38f3f0 ; PLT -> PciDeviceImpl::GetSBDFString
          0x4cbbd4 (+0128)  4c 8d 65 c0                                   lea     r12, [rbp - 0x40]
          0x4cbbd8 (+012c)  48 8d 15 d3 a2 37 00                          lea     rdx, [rip + 0x37a2d3] ; literal "Cannot configure passthru on boot device."
          0x4cbbdf (+0133)  4c 89 f6                                      mov     rsi, r14
          0x4cbbe2 (+0136)  4c 89 e7                                      mov     rdi, r12
          0x4cbbe5 (+0139)  e8 36 59 ea ff                                call    0x371520 ; PLT -> _ZStplIcSt11char_traitsIcESaIcEESbIT_T0_T1_EOS6_PKS3_
          0x4cbbea (+013e)  4c 89 e6                                      mov     rsi, r12
```

<!-- evidence:O02:end -->

调用目标由 PLT 解析为 `IsBootDevice`。AL=0 跳 `0x4cbc6a`；AL 非零走启动设备拒绝路径。不能把启动盘保护算成 A01 内部已有的一项比较。

<!-- evidence:O03:begin -->

### 切片 O03 资格再次检查

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbc6d` 到 `0x4cbc91`（右端不含）；文件偏移 `0x4cbc6d`；8 条指令。
- 窗口 SHA-256：`f4315b08398cb72b684174df59407ddcb2813cce199a3644c3c104028718e7d9`。[单独查看汇编](snippets/O03.asm)

```asm
          0x4cbc6d (+01c1)  e8 de 0b eb ff                                call    0x37c850 ; PLT -> PciDeviceImpl::IsPassthruCapable
          0x4cbc72 (+01c6)  84 c0                                         test    al, al
          0x4cbc74 (+01c8)  0f 85 d5 00 00 00                             jne     0x4cbd4f ; branch leaves this window
          0x4cbc7a (+01ce)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbc7e (+01d2)  48 8d 35 57 a2 37 00                          lea     rsi, [rip + 0x37a257] ; literal " is not passthrough capable."
          0x4cbc85 (+01d9)  e8 e6 64 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbc8a (+01de)  4c 8d 75 88                                   lea     r14, [rbp - 0x78]
          0x4cbc8e (+01e2)  4c 89 e6                                      mov     rsi, r12
```

<!-- evidence:O03:end -->

`IsPassthruCapable` 返回非零才跳到 `0x4cbd4f`。注意这次使用 `jne`，和上一关使用 `je` 的逻辑相反。

<!-- evidence:O04:begin -->

### 切片 O04 系统保留设备检查

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbd59` 到 `0x4cbd7d`（右端不含）；文件偏移 `0x4cbd59`；8 条指令。
- 窗口 SHA-256：`2a00d284b2ad1189e3120f382808623ec6c1337279d059c45adb87767d53725a`。[单独查看汇编](snippets/O04.asm)

```asm
          0x4cbd59 (+02ad)  e8 f2 56 eb ff                                call    0x381450 ; PLT -> PciDeviceImpl::IsEsxioReservedDevice
          0x4cbd5e (+02b2)  84 c0                                         test    al, al
          0x4cbd60 (+02b4)  0f 84 d3 00 00 00                             je      0x4cbe39 ; branch leaves this window
          0x4cbd66 (+02ba)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbd6a (+02be)  48 8d 35 27 9d 37 00                          lea     rsi, [rip + 0x379d27] ; literal " is system reserved and does not support passthru."
          0x4cbd71 (+02c5)  e8 fa 63 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbd76 (+02ca)  4c 8d 75 90                                   lea     r14, [rbp - 0x70]
          0x4cbd7a (+02ce)  4c 89 e6                                      mov     rsi, r12
```

<!-- evidence:O04:end -->

`IsEsxioReservedDevice` 返回零才跳到 `0x4cbe39`，之后继续依赖验证。这里仅确认所见系统保留检查；并未由该函数名推导所有保留设备类型。

| 检查 | 允许继续时的 AL/字段 | 继续目标 |
| --- | --- | --- |
| 全局禁用字段 | 0 | `0x4cbbb8` |
| IsBootDevice | 0 | `0x4cbc6a` |
| IsPassthruCapable | 非 0 | `0x4cbd4f` |
| IsEsxioReservedDevice | 0 | `0x4cbe39` |

管理库存在这些分支，不能自动证明每个 UI/API 都在相同按钮前经过同一入口。完整 hostd 调用图尚未还原。

## 2 依赖代表怎样成为管理库对象

<!-- evidence:O05:begin -->

### 切片 O05 管理库取得依赖代表对象

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetDependantDevice`；入口 `0x4c7142`，函数大小 `109` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl18GetDependantDeviceEv`。
- 窗口：`0x4c7142` 到 `0x4c71af`（右端不含）；文件偏移 `0x4c7142`；31 条指令。
- 窗口 SHA-256：`6d5f39abb8acfa24a7220577b9932354e1f33f4b006b85aa063cf41813ed9085`。[单独查看汇编](snippets/O05.asm)

```asm
          0x4c7142 (+0000)  55                                            push    rbp
          0x4c7143 (+0001)  ba 10 00 00 00                                mov     edx, 0x10
          0x4c7148 (+0006)  48 89 e5                                      mov     rbp, rsp
          0x4c714b (+0009)  41 54                                         push    r12
          0x4c714d (+000b)  49 89 fc                                      mov     r12, rdi
          0x4c7150 (+000e)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c7154 (+0012)  48 8b 05 dd e5 59 00                          mov     rax, qword ptr [rip + 0x59e5dd] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_passthruDependent
          0x4c715b (+0019)  48 8b 4e 48                                   mov     rcx, qword ptr [rsi + 0x48]
          0x4c715f (+001d)  48 8d 75 e0                                   lea     rsi, [rbp - 0x20]
          0x4c7163 (+0021)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c7166 (+0024)  e8 25 a2 eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c716b (+0029)  48 8b 7d e0                                   mov     rdi, qword ptr [rbp - 0x20]
          0x4c716f (+002d)  48 8b 75 e8                                   mov     rsi, qword ptr [rbp - 0x18]
          0x4c7173 (+0031)  e8 18 a8 ff ff                                call    0x4c1990
          0x4c7178 (+0036)  84 c0                                         test    al, al
          0x4c717a (+0038)  74 0a                                         je      0x4c7186
          0x4c717c (+003a)  49 c7 04 24 00 00 00 00                       mov     qword ptr [r12], 0
          0x4c7184 (+0042)  eb 1e                                         jmp     0x4c71a4
          0x4c7186 (+0044)  44 8a 45 ec                                   mov     r8b, byte ptr [rbp - 0x14]
          0x4c718a (+0048)  8a 4d e8                                      mov     cl, byte ptr [rbp - 0x18]
          0x4c718d (+004b)  48 8d 7d d8                                   lea     rdi, [rbp - 0x28]
          0x4c7191 (+004f)  8a 55 e4                                      mov     dl, byte ptr [rbp - 0x1c]
          0x4c7194 (+0052)  8b 75 e0                                      mov     esi, dword ptr [rbp - 0x20]
          0x4c7197 (+0055)  e8 c5 fe ff ff                                call    0x4c7061
          0x4c719c (+005a)  48 8b 45 d8                                   mov     rax, qword ptr [rbp - 0x28]
          0x4c71a0 (+005e)  49 89 04 24                                   mov     qword ptr [r12], rax
          0x4c71a4 (+0062)  48 83 c4 28                                   add     rsp, 0x28
          0x4c71a8 (+0066)  4c 89 e0                                      mov     rax, r12
          0x4c71ab (+0069)  41 5c                                         pop     r12
          0x4c71ad (+006b)  5d                                            pop     rbp
          0x4c71ae (+006c)  c3                                            ret
```

<!-- evidence:O05:end -->

它读取同一个 `passthruDependent` VSI 结果，再调用 A03 的无效值判断。无效时返回空指针；有效时用四字段建立/取得相应 `PciDevice` 对象。因此后续成员展开操作拿到的可以是桥对象，也可以是自身对象。

## 3 反向找成员实际比较了哪些字段

<!-- evidence:O06:begin -->

### 切片 O06 反向查找相关设备的比较字段

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetDependentChildDevices`；入口 `0x4cb4c0`，函数大小 `282` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl24GetDependentChildDevicesEv`。
- 窗口：`0x4cb510` 到 `0x4cb581`（右端不含）；文件偏移 `0x4cb510`；33 条指令。
- 窗口 SHA-256：`566628e9ea27d3d465155d2d6683262bcc732522802f672ef5b6ccc6bd441b20`。[单独查看汇编](snippets/O06.asm)

```asm
          0x4cb510 (+0050)  48 8b 5d b8                                   mov     rbx, qword ptr [rbp - 0x48]
          0x4cb514 (+0054)  4c 8d 7d 98                                   lea     r15, [rbp - 0x68]
          0x4cb518 (+0058)  48 3b 5d c0                                   cmp     rbx, qword ptr [rbp - 0x40]
          0x4cb51c (+005c)  0f 84 95 00 00 00                             je      0x4cb5b7 ; branch leaves this window
          0x4cb522 (+0062)  48 8b 33                                      mov     rsi, qword ptr [rbx]
          0x4cb525 (+0065)  4c 89 ff                                      mov     rdi, r15
          0x4cb528 (+0068)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4cb52b (+006b)  ff 90 58 01 00 00                             call    qword ptr [rax + 0x158]
          0x4cb531 (+0071)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb535 (+0075)  48 85 ff                                      test    rdi, rdi
          0x4cb538 (+0078)  75 0e                                         jne     0x4cb548
          0x4cb53a (+007a)  4c 89 ff                                      mov     rdi, r15
          0x4cb53d (+007d)  48 83 c3 08                                   add     rbx, 8
          0x4cb541 (+0081)  e8 ca 69 ea ff                                call    0x371f10 ; PLT -> _ZNSt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS2_EED1Ev
          0x4cb546 (+0086)  eb d0                                         jmp     0x4cb518
          0x4cb548 (+0088)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb54b (+008b)  ff 50 40                                      call    qword ptr [rax + 0x40]
          0x4cb54e (+008e)  41 38 45 6a                                   cmp     byte ptr [r13 + 0x6a], al
          0x4cb552 (+0092)  75 e6                                         jne     0x4cb53a
          0x4cb554 (+0094)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb558 (+0098)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb55b (+009b)  ff 50 48                                      call    qword ptr [rax + 0x48]
          0x4cb55e (+009e)  41 3a 45 6b                                   cmp     al, byte ptr [r13 + 0x6b]
          0x4cb562 (+00a2)  75 d6                                         jne     0x4cb53a
          0x4cb564 (+00a4)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb568 (+00a8)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb56b (+00ab)  ff 50 50                                      call    qword ptr [rax + 0x50]
          0x4cb56e (+00ae)  41 3a 45 6c                                   cmp     al, byte ptr [r13 + 0x6c]
          0x4cb572 (+00b2)  75 c6                                         jne     0x4cb53a
          0x4cb574 (+00b4)  48 89 de                                      mov     rsi, rbx
          0x4cb577 (+00b7)  4c 89 e7                                      mov     rdi, r12
          0x4cb57a (+00ba)  e8 21 0a ec ff                                call    0x38bfa0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EE12emplace_backIJS6_EEERS6_DpOT_
          0x4cb57f (+00bf)  eb b9                                         jmp     0x4cb53a
```

<!-- evidence:O06:end -->

这里枚举全部设备，对每项调用 vptr 的 `+0x158` 槽，取得其依赖代表。随后通过 `+0x40/+0x48/+0x50` 三个 getter，分别与当前对象的 `+0x6a/+0x6b/+0x6c` 比较，相等才把该项加入输出容器。

这些偏移的名称不能靠猜。下节由实际 vtable 重定位确认它们分别为 GetBus、GetSlot、GetFunction。

**一个必须保留的细节：这段反向查询中没有看到 GetSeg 比较。** 所测拓扑均在 segment 0，不能据此宣称多 segment 必然出错，也不能把这里写成“完整 SBDF 四字段比较”。枚举范围或调用上下文是否另有限制，需要独立核验。开机内核循环比较 packed SBDF，是另一段实现，见 [04](04-vm-admission.md#5-同一个依赖代表为什么排斥另一台-vm)。

## 4 间接调用目标怎样确认

<!-- evidence:O10:begin -->

### 切片 O10 主 vtable 地址点的构造

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::constructor`；入口 `0x4c6f46`，函数大小 `283` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImplC1Ethhh`。
- 窗口：`0x4c6fa2` 到 `0x4c6fee`（右端不含）；文件偏移 `0x4c6fa2`；15 条指令。
- 窗口 SHA-256：`0edc5dcab9cd86f4791d5058da6582d71f4e3e72aed0683aaa04d323f2469ece`。[单独查看汇编](snippets/O10.asm)

```asm
          0x4c6fa2 (+005c)  48 8b 05 47 e0 59 00                          mov     rax, qword ptr [rip + 0x59e047] ; GOT -> _ZTVN6VmkCtl8Hardware13PciDeviceImplE
          0x4c6fa9 (+0063)  48 8d 50 48                                   lea     rdx, [rax + 0x48]
          0x4c6fad (+0067)  48 05 50 04 00 00                             add     rax, 0x450
          0x4c6fb3 (+006d)  49 89 44 24 08                                mov     qword ptr [r12 + 8], rax
          0x4c6fb8 (+0072)  48 8b 05 d9 f0 59 00                          mov     rax, qword ptr [rip + 0x59f0d9] ; GOT -> _ZNSs4_Rep20_S_empty_rep_storageE
          0x4c6fbf (+0079)  49 89 14 24                                   mov     qword ptr [r12], rdx
          0x4c6fc3 (+007d)  0f b6 55 c8                                   movzx   edx, byte ptr [rbp - 0x38]
          0x4c6fc7 (+0081)  48 83 c0 18                                   add     rax, 0x18
          0x4c6fcb (+0085)  49 89 44 24 18                                mov     qword ptr [r12 + 0x18], rax
          0x4c6fd0 (+008a)  49 89 44 24 20                                mov     qword ptr [r12 + 0x20], rax
          0x4c6fd5 (+008f)  49 89 44 24 28                                mov     qword ptr [r12 + 0x28], rax
          0x4c6fda (+0094)  49 89 44 24 30                                mov     qword ptr [r12 + 0x30], rax
          0x4c6fdf (+0099)  49 89 44 24 38                                mov     qword ptr [r12 + 0x38], rax
          0x4c6fe4 (+009e)  49 89 44 24 40                                mov     qword ptr [r12 + 0x40], rax
          0x4c6fe9 (+00a3)  e8 b2 52 eb ff                                call    0x37c2a0 ; PLT -> PciDeviceImpl::SetFromSBDF
```

<!-- evidence:O10:end -->

构造函数先从 GOT 取得 `_ZTVN6VmkCtl8Hardware13PciDeviceImplE`，再用 `lea rdx,[rax+0x48]` 形成主地址点，并写入对象。这里的地址点是 vtable 符号加 `0x48`，不能套用“所有 C++ vtable 都加 0x10”的简化规则。

| vptr 槽偏移 | ELF 槽地址 | 重定位类型 | 目标 |
| --- | --- | --- | --- |
| 0x38 | 0x9fc540 | 1 | `PciDeviceImpl::GetSeg` |
| 0x40 | 0x9fc548 | 1 | `PciDeviceImpl::GetBus` |
| 0x48 | 0x9fc550 | 1 | `PciDeviceImpl::GetSlot` |
| 0x50 | 0x9fc558 | 1 | `PciDeviceImpl::GetFunction` |
| 0xe0 | 0x9fc5e8 | 1 | `PciDeviceImpl::GetSBDFString` |
| 0x138 | 0x9fc640 | 1 | `PciDeviceImpl::GetConfiguredDeviceOwner` |
| 0x148 | 0x9fc650 | 1 | `PciDeviceImpl::SetConfiguredDevOwnerNoDeps` |
| 0x158 | 0x9fc660 | 1 | `PciDeviceImpl::GetDependantDevice` |
| 0x160 | 0x9fc668 | 1 | `PciDeviceImpl::GetDependentChildDevices` |

例如：`0x9fc4c0 + 0x48 + 0x148 = 0x9fc650`；该地址的 `R_X86_64_64` 重定位指向 `SetConfiguredDevOwnerNoDeps`。所以后面 `call [rax+0x148]` 的目标有数据依据，而不是根据附近日志猜测。

四个 getter 自身也列出，避免只有名字没有字段证据。O06 实际调用后三个槽，没有调用 GetSeg 槽。

<!-- evidence:O14:begin -->

### 切片 O14 GetSeg getter 的真实字段读取

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetSeg`；入口 `0x4c1980`，函数大小 `4` 字节。
- 原始符号：`_ZNK6VmkCtl8Hardware13PciDeviceImpl6GetSegEv`。
- 窗口：`0x4c1980` 到 `0x4c1984`（右端不含）；文件偏移 `0x4c1980`；2 条指令。
- 窗口 SHA-256：`604f885ca70d689e943955b19c3dece54072c92e86c652f4fd211a19f35f4635`。[单独查看汇编](snippets/O14.asm)

```asm
          0x4c1980 (+0000)  8b 47 5c                                      mov     eax, dword ptr [rdi + 0x5c]
          0x4c1983 (+0003)  c3                                            ret
```

<!-- evidence:O14:end -->

<!-- evidence:O15:begin -->

### 切片 O15 GetBus getter 的真实字段读取

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetBus`；入口 `0x4c1984`，函数大小 `4` 字节。
- 原始符号：`_ZNK6VmkCtl8Hardware13PciDeviceImpl6GetBusEv`。
- 窗口：`0x4c1984` 到 `0x4c1988`（右端不含）；文件偏移 `0x4c1984`；2 条指令。
- 窗口 SHA-256：`182a6a1ac93040326f6a36f186c870419276eaad6f015acc3ffc6b5674c6dc5c`。[单独查看汇编](snippets/O15.asm)

```asm
          0x4c1984 (+0000)  8a 47 6a                                      mov     al, byte ptr [rdi + 0x6a]
          0x4c1987 (+0003)  c3                                            ret
```

<!-- evidence:O15:end -->

<!-- evidence:O16:begin -->

### 切片 O16 GetSlot getter 的真实字段读取

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetSlot`；入口 `0x4c1988`，函数大小 `4` 字节。
- 原始符号：`_ZNK6VmkCtl8Hardware13PciDeviceImpl7GetSlotEv`。
- 窗口：`0x4c1988` 到 `0x4c198c`（右端不含）；文件偏移 `0x4c1988`；2 条指令。
- 窗口 SHA-256：`b821cd1de40a9d7c0f75cdc363fb3dfcd4bbe4f19aa6bfba4b7691082c1fbd9d`。[单独查看汇编](snippets/O16.asm)

```asm
          0x4c1988 (+0000)  8a 47 6b                                      mov     al, byte ptr [rdi + 0x6b]
          0x4c198b (+0003)  c3                                            ret
```

<!-- evidence:O16:end -->

<!-- evidence:O17:begin -->

### 切片 O17 GetFunction getter 的真实字段读取

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetFunction`；入口 `0x4c198c`，函数大小 `4` 字节。
- 原始符号：`_ZNK6VmkCtl8Hardware13PciDeviceImpl11GetFunctionEv`。
- 窗口：`0x4c198c` 到 `0x4c1990`（右端不含）；文件偏移 `0x4c198c`；2 条指令。
- 窗口 SHA-256：`d4a9292b526610de6cbd2eed6fa20f79e351c5b26f7053fbbee322483b67810f`。[单独查看汇编](snippets/O17.asm)

```asm
          0x4c198c (+0000)  8a 47 6c                                      mov     al, byte ptr [rdi + 0x6c]
          0x4c198f (+0003)  c3                                            ret
```

<!-- evidence:O17:end -->

## 5 联动配置的主循环

<!-- evidence:O07:begin -->

### 切片 O07 配置依赖成员的主循环

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SetConfiguredDeviceOwner`；入口 `0x4c78a0`，函数大小 `1664` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl24SetConfiguredDeviceOwnerEN7HostCtl8Hardware9PciDevice14PciDeviceOwnerE`。
- 窗口：`0x4c7b72` 到 `0x4c7c71`（右端不含）；文件偏移 `0x4c7b72`；64 条指令。
- 窗口 SHA-256：`a1c5a143953e1bf6233068c07625cb7a7fa739147f9225fd8c97a6eaf3a35ebc`。[单独查看汇编](snippets/O07.asm)

```asm
          0x4c7b72 (+02d2)  48 8b b5 70 ff ff ff                          mov     rsi, qword ptr [rbp - 0x90]
          0x4c7b79 (+02d9)  4c 8d 7d 88                                   lea     r15, [rbp - 0x78]
          0x4c7b7d (+02dd)  4c 89 ff                                      mov     rdi, r15
          0x4c7b80 (+02e0)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4c7b83 (+02e3)  ff 90 e0 00 00 00                             call    qword ptr [rax + 0xe0]
          0x4c7b89 (+02e9)  4c 89 e6                                      mov     rsi, r12
          0x4c7b8c (+02ec)  4c 89 ff                                      mov     rdi, r15
          0x4c7b8f (+02ef)  e8 ec 1d eb ff                                call    0x379980 ; PLT -> _ZSteqIcEN9__gnu_cxx11__enable_ifIXsrSt9__is_charIT_E7__valueEbE6__typeERKSbIS3_St11char_traitsIS3_ESaIS3_EESC_
          0x4c7b94 (+02f4)  4c 89 ff                                      mov     rdi, r15
          0x4c7b97 (+02f7)  89 c3                                         mov     ebx, eax
          0x4c7b99 (+02f9)  e8 c2 cc ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c7b9e (+02fe)  4c 89 e7                                      mov     rdi, r12
          0x4c7ba1 (+0301)  e8 ba cc ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c7ba6 (+0306)  84 db                                         test    bl, bl
          0x4c7ba8 (+0308)  0f 85 8d 00 00 00                             jne     0x4c7c3b
          0x4c7bae (+030e)  48 8b b5 70 ff ff ff                          mov     rsi, qword ptr [rbp - 0x90]
          0x4c7bb5 (+0315)  48 8d 45 a0                                   lea     rax, [rbp - 0x60]
          0x4c7bb9 (+0319)  48 89 85 50 ff ff ff                          mov     qword ptr [rbp - 0xb0], rax
          0x4c7bc0 (+0320)  48 8b bd 50 ff ff ff                          mov     rdi, qword ptr [rbp - 0xb0]
          0x4c7bc7 (+0327)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4c7bca (+032a)  ff 90 60 01 00 00                             call    qword ptr [rax + 0x160]
          0x4c7bd0 (+0330)  48 c7 45 b8 00 00 00 00                       mov     qword ptr [rbp - 0x48], 0
          0x4c7bd8 (+0338)  48 8b 5d a0                                   mov     rbx, qword ptr [rbp - 0x60]
          0x4c7bdc (+033c)  48 c7 45 c0 00 00 00 00                       mov     qword ptr [rbp - 0x40], 0
          0x4c7be4 (+0344)  48 c7 45 c8 00 00 00 00                       mov     qword ptr [rbp - 0x38], 0
          0x4c7bec (+034c)  48 3b 5d a8                                   cmp     rbx, qword ptr [rbp - 0x58]
          0x4c7bf0 (+0350)  74 33                                         je      0x4c7c25
          0x4c7bf2 (+0352)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7bf5 (+0355)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7bf8 (+0358)  ff 90 38 01 00 00                             call    qword ptr [rax + 0x138]
          0x4c7bfe (+035e)  41 39 c6                                      cmp     r14d, eax
          0x4c7c01 (+0361)  75 11                                         jne     0x4c7c14
          0x4c7c03 (+0363)  48 89 de                                      mov     rsi, rbx
          0x4c7c06 (+0366)  4c 89 e7                                      mov     rdi, r12
          0x4c7c09 (+0369)  e8 92 43 ec ff                                call    0x38bfa0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EE12emplace_backIJS6_EEERS6_DpOT_
          0x4c7c0e (+036e)  48 83 c3 08                                   add     rbx, 8
          0x4c7c12 (+0372)  eb d8                                         jmp     0x4c7bec
          0x4c7c14 (+0374)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7c17 (+0377)  44 89 f6                                      mov     esi, r14d
          0x4c7c1a (+037a)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7c1d (+037d)  ff 90 48 01 00 00                             call    qword ptr [rax + 0x148]
          0x4c7c23 (+0383)  eb de                                         jmp     0x4c7c03
          0x4c7c25 (+0385)  4c 89 e7                                      mov     rdi, r12
          0x4c7c28 (+0388)  e8 b3 22 eb ff                                call    0x379ee0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EED1Ev
          0x4c7c2d (+038d)  48 8b bd 50 ff ff ff                          mov     rdi, qword ptr [rbp - 0xb0]
          0x4c7c34 (+0394)  e8 a7 22 eb ff                                call    0x379ee0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EED1Ev
          0x4c7c39 (+0399)  eb 18                                         jmp     0x4c7c53
          0x4c7c3b (+039b)  4c 89 ef                                      mov     rdi, r13
          0x4c7c3e (+039e)  e8 4d 37 ec ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4c7c43 (+03a3)  41 39 c6                                      cmp     r14d, eax
          0x4c7c46 (+03a6)  74 0b                                         je      0x4c7c53
          0x4c7c48 (+03a8)  44 89 f6                                      mov     esi, r14d
          0x4c7c4b (+03ab)  4c 89 ef                                      mov     rdi, r13
          0x4c7c4e (+03ae)  e8 2d 26 ec ff                                call    0x38a280 ; PLT -> PciDeviceImpl::SetConfiguredDevOwnerNoDeps
          0x4c7c53 (+03b3)  48 8b bd 58 ff ff ff                          mov     rdi, qword ptr [rbp - 0xa8]
          0x4c7c5a (+03ba)  e8 b1 a2 ea ff                                call    0x371f10 ; PLT -> _ZNSt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS2_EED1Ev
          0x4c7c5f (+03bf)  48 81 c4 88 00 00 00                          add     rsp, 0x88
          0x4c7c66 (+03c6)  5b                                            pop     rbx
          0x4c7c67 (+03c7)  41 5c                                         pop     r12
          0x4c7c69 (+03c9)  41 5d                                         pop     r13
          0x4c7c6b (+03cb)  41 5e                                         pop     r14
          0x4c7c6d (+03cd)  41 5f                                         pop     r15
          0x4c7c6f (+03cf)  5d                                            pop     rbp
          0x4c7c70 (+03d0)  c3                                            ret
```

<!-- evidence:O07:end -->

逐行看关键部分：

- `0x4c7b83` 取得代表对象的 SBDF 字符串，随后与目标比较。相同走自身更新；不相同走成员展开。
- `0x4c7bca` 经 `+0x160` 调 `GetDependentChildDevices`。
- `0x4c7bf8` 经 `+0x138` 读当前 configured owner。
- `0x4c7bfe` 与请求 owner（R14D）比较；不相等才到 `0x4c7c1d` 调 `+0x148` 写入。
- 两条路径随后都到 `0x4c7c03`，把该成员加入已处理容器，再继续循环。

这解释了为什么只请求一个 Function，会联动多个配置项。它没有直接证明同样范围的设备此时已经全部 runtime-active。

## 6 配置具体写到哪里

<!-- evidence:O09:begin -->

### 切片 O09 具体 ConfigStore owner 写入

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SetConfiguredDevOwnerNoDeps`；入口 `0x4c62c6`，函数大小 `397` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl27SetConfiguredDevOwnerNoDepsEN7HostCtl8Hardware9PciDevice14PciDeviceOwnerE`。
- 窗口：`0x4c6399` 到 `0x4c63f7`（右端不含）；文件偏移 `0x4c6399`；23 条指令。
- 窗口 SHA-256：`85d920c914b7c16f4c65f29f0916cb8eb045b8c60b1813b64bd5a9734db39a26`。[单独查看汇编](snippets/O09.asm)

```asm
          0x4c6399 (+00d3)  48 8b 05 f8 fc 59 00                          mov     rax, qword ptr [rip + 0x59fcf8] ; GOT -> _ZNSs4_Rep20_S_empty_rep_storageE
          0x4c63a0 (+00da)  48 83 c0 18                                   add     rax, 0x18
          0x4c63a4 (+00de)  48 89 45 c0                                   mov     qword ptr [rbp - 0x40], rax
          0x4c63a8 (+00e2)  83 fe 02                                      cmp     esi, 2
          0x4c63ab (+00e5)  75 23                                         jne     0x4c63d0
          0x4c63ad (+00e7)  48 8d 35 e2 f3 37 00                          lea     rsi, [rip + 0x37f3e2] ; literal "OWNER_PASSTHRU"
          0x4c63b4 (+00ee)  4c 89 e7                                      mov     rdi, r12
          0x4c63b7 (+00f1)  e8 44 e9 eb ff                                call    0x384d00 ; PLT -> _ZNSsaSEPKc
          0x4c63bc (+00f6)  4c 89 fa                                      mov     rdx, r15
          0x4c63bf (+00f9)  48 8d 35 b2 08 3b 00                          lea     rsi, [rip + 0x3b08b2] ; literal "owner"
          0x4c63c6 (+0100)  4c 89 f7                                      mov     rdi, r14
          0x4c63c9 (+0103)  e8 12 a7 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c63ce (+0108)  eb 09                                         jmp     0x4c63d9
          0x4c63d0 (+010a)  48 8d 35 ce f3 37 00                          lea     rsi, [rip + 0x37f3ce] ; literal "OWNER_VMKERNEL"
          0x4c63d7 (+0111)  eb db                                         jmp     0x4c63b4
          0x4c63d9 (+0113)  4c 89 e2                                      mov     rdx, r12
          0x4c63dc (+0116)  4c 89 f6                                      mov     rsi, r14
          0x4c63df (+0119)  48 89 df                                      mov     rdi, rbx
          0x4c63e2 (+011c)  e8 d9 dd eb ff                                call    0x3841c0 ; PLT -> PciDeviceImpl::SetValueToCS
          0x4c63e7 (+0121)  4c 89 f7                                      mov     rdi, r14
          0x4c63ea (+0124)  e8 71 e4 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c63ef (+0129)  4c 89 e7                                      mov     rdi, r12
          0x4c63f2 (+012c)  e8 69 e4 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
```

<!-- evidence:O09:end -->

`SetConfiguredDevOwnerNoDeps` 组织 `OWNER_PASSTHRU` 或 `OWNER_VMKERNEL`，然后通过 `SetValueToCS` 写 owner 配置项。其调用名和字符串来源可以在重定位及本函数范围里复核。

<!-- evidence:O11:begin -->

### 切片 O11 管理库 owner 枚举解释

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::GetOwnerString`；入口 `0x4c3590`，函数大小 `71` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl14GetOwnerStringEN7HostCtl8Hardware9PciDevice14PciDeviceOwnerE`。
- 窗口：`0x4c3590` 到 `0x4c35d7`（右端不含）；文件偏移 `0x4c3590`；21 条指令。
- 窗口 SHA-256：`7da85a3a97c2e0234ed53d24391de2ee1fd643712ec466765f34e319f85165b3`。[单独查看汇编](snippets/O11.asm)

```asm
          0x4c3590 (+0000)  55                                            push    rbp
          0x4c3591 (+0001)  89 f0                                         mov     eax, esi
          0x4c3593 (+0003)  48 8d 35 0a 4a 3c 00                          lea     rsi, [rip + 0x3c4a0a] ; literal "vmkernel"
          0x4c359a (+000a)  48 89 e5                                      mov     rbp, rsp
          0x4c359d (+000d)  41 54                                         push    r12
          0x4c359f (+000f)  49 89 fc                                      mov     r12, rdi
          0x4c35a2 (+0012)  48 83 ec 18                                   sub     rsp, 0x18
          0x4c35a6 (+0016)  83 f8 01                                      cmp     eax, 1
          0x4c35a9 (+0019)  74 15                                         je      0x4c35c0
          0x4c35ab (+001b)  83 f8 02                                      cmp     eax, 2
          0x4c35ae (+001e)  48 8d 35 8d 2e 38 00                          lea     rsi, [rip + 0x382e8d]
          0x4c35b5 (+0025)  48 8d 05 59 20 38 00                          lea     rax, [rip + 0x382059] ; literal "VM passthru"
          0x4c35bc (+002c)  48 0f 44 f0                                   cmove   rsi, rax
          0x4c35c0 (+0030)  48 8d 55 ef                                   lea     rdx, [rbp - 0x11]
          0x4c35c4 (+0034)  4c 89 e7                                      mov     rdi, r12
          0x4c35c7 (+0037)  e8 14 d5 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c35cc (+003c)  48 83 c4 18                                   add     rsp, 0x18
          0x4c35d0 (+0040)  4c 89 e0                                      mov     rax, r12
          0x4c35d3 (+0043)  41 5c                                         pop     r12
          0x4c35d5 (+0045)  5d                                            pop     rbp
          0x4c35d6 (+0046)  c3                                            ret
```

<!-- evidence:O11:end -->

这个管理库枚举中，1 对应 VMkernel，2 对应 VM passthru。内核 FPT 检查使用的是另一套值；不能看见 `cmp eax,1` 就套用这一层的枚举名。

## 7 异常补偿为何不能叫成绝对原子

<!-- evidence:O08:begin -->

### 切片 O08 异常补偿目标与循环

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SetConfiguredDeviceOwner`；入口 `0x4c78a0`，函数大小 `1664` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl24SetConfiguredDeviceOwnerEN7HostCtl8Hardware9PciDevice14PciDeviceOwnerE`。
- 窗口：`0x4c7cd5` 到 `0x4c7d18`（右端不含）；文件偏移 `0x4c7cd5`；19 条指令。
- 窗口 SHA-256：`4599497935f4705fb89dcf845423d735694ee6783d24f68c3ecaa66578c7960b`。[单独查看汇编](snippets/O08.asm)

```asm
          0x4c7cd5 (+0435)  48 89 c7                                      mov     rdi, rax
          0x4c7cd8 (+0438)  48 ff ca                                      dec     rdx
          0x4c7cdb (+043b)  74 08                                         je      0x4c7ce5
          0x4c7cdd (+043d)  49 89 c5                                      mov     r13, rax
          0x4c7ce0 (+0440)  e9 0e 01 00 00                                jmp     0x4c7df3 ; branch leaves this window
          0x4c7ce5 (+0445)  e8 86 03 eb ff                                call    0x378070 ; PLT -> __cxa_begin_catch
          0x4c7cea (+044a)  41 83 fe 02                                   cmp     r14d, 2
          0x4c7cee (+044e)  48 8b 5d b8                                   mov     rbx, qword ptr [rbp - 0x48]
          0x4c7cf2 (+0452)  41 0f 95 c6                                   setne   r14b
          0x4c7cf6 (+0456)  45 0f b6 f6                                   movzx   r14d, r14b
          0x4c7cfa (+045a)  41 ff c6                                      inc     r14d
          0x4c7cfd (+045d)  48 39 5d c0                                   cmp     qword ptr [rbp - 0x40], rbx
          0x4c7d01 (+0461)  74 15                                         je      0x4c7d18 ; branch leaves this window
          0x4c7d03 (+0463)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7d06 (+0466)  44 89 f6                                      mov     esi, r14d
          0x4c7d09 (+0469)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7d0c (+046c)  ff 90 48 01 00 00                             call    qword ptr [rax + 0x148]
          0x4c7d12 (+0472)  48 83 c3 08                                   add     rbx, 8
          0x4c7d16 (+0476)  eb e5                                         jmp     0x4c7cfd
```

<!-- evidence:O08:end -->

请求 owner=2 时，`setne` 得 0，再 `inc` 得补偿值 1；其他请求得到补偿值 2。接着对已处理容器逐项调用 `SetConfiguredDevOwnerNoDeps`。

这是一条确实存在的补偿路径，但有三个不同结论：

1. 写入是逐成员发生的，不能从中证明外部不可见中间态。
2. 主循环把“原本已经等于请求 owner”的成员也放入处理容器；补偿不是逐项保存并恢复任意原始 owner 值的通用算法。
3. 补偿写入自身是否失败、是否有更上层恢复，以及并发观察语义，还需要完整异常图和故障注入。

因此“没有在既有正常请求中看到部分成功”与“已证明原子性”是两回事。[既有切换回执](../vmware-pci-multifunction-fix-20261111/raw/native-mf-owner-results.json)

## 8 禁用为什么也可能联动

<!-- evidence:O12:begin -->

### 切片 O12 禁用直通进入共同配置路径

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SwitchOwnerToVmkernel`；入口 `0x4c7f20`，函数大小 `115` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl21SwitchOwnerToVmkernelEv`。
- 窗口：`0x4c7f20` 到 `0x4c7f93`（右端不含）；文件偏移 `0x4c7f20`；32 条指令。
- 窗口 SHA-256：`5452a9960bcf9e019aa517b247cd1262dd202fa0a91343f2cc8848f74435aab4`。[单独查看汇编](snippets/O12.asm)

```asm
          0x4c7f20 (+0000)  55                                            push    rbp
          0x4c7f21 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c7f24 (+0004)  41 55                                         push    r13
          0x4c7f26 (+0006)  41 54                                         push    r12
          0x4c7f28 (+0008)  48 83 ec 10                                   sub     rsp, 0x10
          0x4c7f2c (+000c)  48 89 7d e8                                   mov     qword ptr [rbp - 0x18], rdi
          0x4c7f30 (+0010)  e8 5b 34 ec ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4c7f35 (+0015)  48 8b 7d e8                                   mov     rdi, qword ptr [rbp - 0x18]
          0x4c7f39 (+0019)  ff c8                                         dec     eax
          0x4c7f3b (+001b)  75 32                                         jne     0x4c7f6f
          0x4c7f3d (+001d)  bf 20 00 00 00                                mov     edi, 0x20
          0x4c7f42 (+0022)  e8 49 4b ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4c7f47 (+0027)  48 8d 35 8f dc 37 00                          lea     rsi, [rip + 0x37dc8f] ; literal "Device owner is already configured to vmkernel."
          0x4c7f4e (+002e)  48 89 c7                                      mov     rdi, rax
          0x4c7f51 (+0031)  49 89 c4                                      mov     r12, rax
          0x4c7f54 (+0034)  e8 07 5b eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4c7f59 (+0039)  48 8b 15 b0 d2 59 00                          mov     rdx, qword ptr [rip + 0x59d2b0] ; GOT -> Lib::HostCtlException
          0x4c7f60 (+0040)  48 8b 35 f9 ec 59 00                          mov     rsi, qword ptr [rip + 0x59ecf9] ; GOT -> _ZTIN7HostCtl3Lib16HostCtlExceptionE
          0x4c7f67 (+0047)  4c 89 e7                                      mov     rdi, r12
          0x4c7f6a (+004a)  e8 51 6d ec ff                                call    0x38ecc0 ; PLT -> __cxa_throw
          0x4c7f6f (+004f)  58                                            pop     rax
          0x4c7f70 (+0050)  be 01 00 00 00                                mov     esi, 1
          0x4c7f75 (+0055)  5a                                            pop     rdx
          0x4c7f76 (+0056)  41 5c                                         pop     r12
          0x4c7f78 (+0058)  41 5d                                         pop     r13
          0x4c7f7a (+005a)  5d                                            pop     rbp
          0x4c7f7b (+005b)  e9 50 bb ea ff                                jmp     0x373ad0 ; PLT -> PciDeviceImpl::SetConfiguredDeviceOwner; branch leaves this window
          0x4c7f80 (+0060)  49 89 c5                                      mov     r13, rax
          0x4c7f83 (+0063)  4c 89 e7                                      mov     rdi, r12
          0x4c7f86 (+0066)  e8 25 23 ec ff                                call    0x38a2b0 ; PLT -> __cxa_free_exception
          0x4c7f8b (+006b)  4c 89 ef                                      mov     rdi, r13
          0x4c7f8e (+006e)  e8 6d 8b eb ff                                call    0x380b00 ; PLT -> _Unwind_Resume
```

<!-- evidence:O12:end -->

`SwitchOwnerToVmkernel` 最后把目标值 1 交给共同的 `SetConfiguredDeviceOwner`，因此同样会走代表查询和成员展开。它没有为禁用另起一套完全无依赖的配置写法。

<!-- evidence:O13:begin -->

### 切片 O13 禁用前的 VM 使用检查

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToVmkernel`；入口 `0x4c35d8`，函数大小 `249` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToVmkernelEv`。
- 窗口：`0x4c35d8` 到 `0x4c361d`（右端不含）；文件偏移 `0x4c35d8`；19 条指令。
- 窗口 SHA-256：`c5abdc34b546800476254f2d7cc1588fcc78655ad6e3a1a08763ee684fadb714`。[单独查看汇编](snippets/O13.asm)

```asm
          0x4c35d8 (+0000)  55                                            push    rbp
          0x4c35d9 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c35dc (+0004)  41 56                                         push    r14
          0x4c35de (+0006)  41 55                                         push    r13
          0x4c35e0 (+0008)  41 54                                         push    r12
          0x4c35e2 (+000a)  49 89 fc                                      mov     r12, rdi
          0x4c35e5 (+000d)  48 83 ec 48                                   sub     rsp, 0x48
          0x4c35e9 (+0011)  e8 42 2e eb ff                                call    0x376430 ; PLT -> PciDeviceImpl::IsInPassthruUseByVM
          0x4c35ee (+0016)  84 c0                                         test    al, al
          0x4c35f0 (+0018)  0f 84 cf 00 00 00                             je      0x4c36c5 ; branch leaves this window
          0x4c35f6 (+001e)  48 8d 7d d0                                   lea     rdi, [rbp - 0x30]
          0x4c35fa (+0022)  48 8d 35 20 20 38 00                          lea     rsi, [rip + 0x382020] ; literal " is in use by a VM in passthru mode"
          0x4c3601 (+0029)  e8 6a eb ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4c3606 (+002e)  4c 8d 75 b8                                   lea     r14, [rbp - 0x48]
          0x4c360a (+0032)  4c 89 e6                                      mov     rsi, r12
          0x4c360d (+0035)  4c 8d 6d b0                                   lea     r13, [rbp - 0x50]
          0x4c3611 (+0039)  4c 89 f7                                      mov     rdi, r14
          0x4c3614 (+003c)  e8 d7 bd ec ff                                call    0x38f3f0 ; PLT -> PciDeviceImpl::GetSBDFString
          0x4c3619 (+0041)  4c 8b 65 b8                                   mov     r12, qword ptr [rbp - 0x48]
```

<!-- evidence:O13:end -->

另一个验证入口 `ValidateOwnerToVmkernel` 调用 `IsInPassthruUseByVM`，有正在被 VM 使用的拒绝路径。是否由具体 API 先调用这个验证入口仍须区分；本章没有把函数存在等同于所有路径都强制执行。
