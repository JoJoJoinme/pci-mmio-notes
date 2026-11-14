# 主机启用直通的补充汇编证据

补齐原证据集未展示的依赖非空检查、切换入口和网络占用拒绝。固定 build 24280767；不包含 hostd 的完整 API 编排，也不执行新的主机切换。

E01/E02 证明依赖对象必须非空；E03 展示 capable、已配置状态和启动设备判断；E04 是网络信息来源；E05 是设备名查找与配置写入的分叉；E06 展示拒绝分支中的业务原因。网络收集循环中的全部虚表槽尚未逐项命名。

[返回 API 设计](../02-host-api-enable.md) · [独立 objdump 核对](objdump-verification.json)

<!-- evidence:E01:begin -->

### 切片 E01 依赖对象必须非空

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbe39` 到 `0x4cbe53`（右端不含）；文件偏移 `0x4cbe39`；6 条指令。
- 窗口 SHA-256：`4f54e8f4905b7b611fa0dc19de3c115559dfb3b3140fb53a0f5cfa63af76998b`。[单独查看汇编](snippets/E01.asm)

```asm
          0x4cbe39 (+038d)  4c 8d 75 98                                   lea     r14, [rbp - 0x68]
          0x4cbe3d (+0391)  4c 89 e6                                      mov     rsi, r12
          0x4cbe40 (+0394)  4c 89 f7                                      mov     rdi, r14
          0x4cbe43 (+0397)  e8 28 22 eb ff                                call    0x37e070 ; PLT -> PciDeviceImpl::GetDependantDevice
          0x4cbe48 (+039c)  48 83 7d 98 00                                cmp     qword ptr [rbp - 0x68], 0
          0x4cbe4d (+03a1)  0f 85 de 00 00 00                             jne     0x4cbf31 ; branch leaves this window
```

<!-- evidence:E01:end -->

<!-- evidence:E02:begin -->

### 切片 E02 无依赖对象的拒绝文字

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::ValidateOwnerToPassthru`；入口 `0x4cbaac`，函数大小 `1233` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl23ValidateOwnerToPassthruEv`。
- 窗口：`0x4cbe53` 到 `0x4cbe63`（右端不含）；文件偏移 `0x4cbe53`；3 条指令。
- 窗口 SHA-256：`797abeb924df7e6e585ac2dd5ec354efc157647055d2602f4637b55e4d557608`。[单独查看汇编](snippets/E02.asm)

```asm
          0x4cbe53 (+03a7)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbe57 (+03ab)  48 8d 35 a7 a0 37 00                          lea     rsi, [rip + 0x37a0a7] ; literal " is not passthrough capable because it is directly under the PCI host bridge."
          0x4cbe5e (+03b2)  e8 0d 63 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
```

<!-- evidence:E02:end -->

<!-- evidence:E03:begin -->

### 切片 E03 切换入口的资格与现有配置检查

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SwitchOwnerToPassthru`；入口 `0x4cc032`，函数大小 `1706` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl21SwitchOwnerToPassthruEv`。
- 窗口：`0x4cc032` 到 `0x4cc0bf`（右端不含）；文件偏移 `0x4cc032`；37 条指令。
- 窗口 SHA-256：`6d09723270266cc2e055d87c797ee2d45084daff52cb22abd6ee84f883d569bc`。[单独查看汇编](snippets/E03.asm)

```asm
          0x4cc032 (+0000)  55                                            push    rbp
          0x4cc033 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4cc036 (+0004)  41 57                                         push    r15
          0x4cc038 (+0006)  41 56                                         push    r14
          0x4cc03a (+0008)  49 89 fe                                      mov     r14, rdi
          0x4cc03d (+000b)  41 55                                         push    r13
          0x4cc03f (+000d)  41 54                                         push    r12
          0x4cc041 (+000f)  53                                            push    rbx
          0x4cc042 (+0010)  48 81 ec 48 01 00 00                          sub     rsp, 0x148
          0x4cc049 (+0017)  e8 02 08 eb ff                                call    0x37c850 ; PLT -> PciDeviceImpl::IsPassthruCapable
          0x4cc04e (+001c)  84 c0                                         test    al, al
          0x4cc050 (+001e)  75 1e                                         jne     0x4cc070
          0x4cc052 (+0020)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc057 (+0025)  e8 34 0a ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc05c (+002a)  48 8d 35 01 9f 37 00                          lea     rsi, [rip + 0x379f01] ; literal "Device is not capable of passthru. Refer to KB 2142307 for the list of requirements"
          0x4cc063 (+0031)  48 89 c7                                      mov     rdi, rax
          0x4cc066 (+0034)  49 89 c4                                      mov     r12, rax
          0x4cc069 (+0037)  e8 f2 19 eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4cc06e (+003c)  eb 29                                         jmp     0x4cc099
          0x4cc070 (+003e)  4c 89 f7                                      mov     rdi, r14
          0x4cc073 (+0041)  e8 18 f3 eb ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4cc078 (+0046)  83 f8 02                                      cmp     eax, 2
          0x4cc07b (+0049)  75 32                                         jne     0x4cc0af
          0x4cc07d (+004b)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc082 (+0050)  e8 09 0a ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc087 (+0055)  48 8d 35 2a 9f 37 00                          lea     rsi, [rip + 0x379f2a] ; literal "Device owner is already configured to passthru."
          0x4cc08e (+005c)  48 89 c7                                      mov     rdi, rax
          0x4cc091 (+005f)  49 89 c4                                      mov     r12, rax
          0x4cc094 (+0062)  e8 c7 19 eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4cc099 (+0067)  48 8b 15 70 91 59 00                          mov     rdx, qword ptr [rip + 0x599170] ; GOT -> Lib::HostCtlException
          0x4cc0a0 (+006e)  48 8b 35 b9 ab 59 00                          mov     rsi, qword ptr [rip + 0x59abb9] ; GOT -> _ZTIN7HostCtl3Lib16HostCtlExceptionE
          0x4cc0a7 (+0075)  4c 89 e7                                      mov     rdi, r12
          0x4cc0aa (+0078)  e9 a5 00 00 00                                jmp     0x4cc154 ; branch leaves this window
          0x4cc0af (+007d)  4c 89 f7                                      mov     rdi, r14
          0x4cc0b2 (+0080)  e8 99 c6 eb ff                                call    0x388750 ; PLT -> PciDeviceImpl::IsBootDevice
          0x4cc0b7 (+0085)  84 c0                                         test    al, al
          0x4cc0b9 (+0087)  0f 84 9a 00 00 00                             je      0x4cc159 ; branch leaves this window
```

<!-- evidence:E03:end -->

<!-- evidence:E04:begin -->

### 切片 E04 取得虚拟交换机信息

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SwitchOwnerToPassthru`；入口 `0x4cc032`，函数大小 `1706` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl21SwitchOwnerToPassthruEv`。
- 窗口：`0x4cc16f` 到 `0x4cc1a2`（右端不含）；文件偏移 `0x4cc16f`；9 条指令。
- 窗口 SHA-256：`a37535acc6911012042ae21145d0c53729376ce2f6e399ab6712ea8f00f2cd2a`。[单独查看汇编](snippets/E04.asm)

```asm
          0x4cc16f (+013d)  48 8d 85 28 ff ff ff                          lea     rax, [rbp - 0xd8]
          0x4cc176 (+0144)  48 89 c7                                      mov     rdi, rax
          0x4cc179 (+0147)  48 89 85 d0 fe ff ff                          mov     qword ptr [rbp - 0x130], rax
          0x4cc180 (+014e)  e8 6b 46 eb ff                                call    0x3807f0 ; PLT -> Network::NetworkInfoImpl
          0x4cc185 (+0153)  48 8d 85 e0 fe ff ff                          lea     rax, [rbp - 0x120]
          0x4cc18c (+015a)  48 8b b5 d0 fe ff ff                          mov     rsi, qword ptr [rbp - 0x130]
          0x4cc193 (+0161)  48 89 c7                                      mov     rdi, rax
          0x4cc196 (+0164)  48 89 85 b8 fe ff ff                          mov     qword ptr [rbp - 0x148], rax
          0x4cc19d (+016b)  e8 4e 63 eb ff                                call    0x3824f0 ; PLT -> NetworkInfoImpl::GetVirtualSwitchInfo
```

<!-- evidence:E04:end -->

<!-- evidence:E05:begin -->

### 切片 E05 目标网络设备查找与 owner 写入分叉

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SwitchOwnerToPassthru`；入口 `0x4cc032`，函数大小 `1706` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl21SwitchOwnerToPassthruEv`。
- 窗口：`0x4cc451` 到 `0x4cc484`（右端不含）；文件偏移 `0x4cc451`；12 条指令。
- 窗口 SHA-256：`12c2763afe68a18b60fab4606859a9173cf26a09329989f3f76f389973777d4a`。[单独查看汇编](snippets/E05.asm)

```asm
          0x4cc451 (+041f)  4c 89 f6                                      mov     rsi, r14
          0x4cc454 (+0422)  48 89 df                                      mov     rdi, rbx
          0x4cc457 (+0425)  e8 c4 40 eb ff                                call    0x380520 ; PLT -> PciDeviceImpl::GetVmKernelDeviceName
          0x4cc45c (+042a)  4c 8d ad 48 ff ff ff                          lea     r13, [rbp - 0xb8]
          0x4cc463 (+0431)  48 89 de                                      mov     rsi, rbx
          0x4cc466 (+0434)  4c 89 ef                                      mov     rdi, r13
          0x4cc469 (+0437)  e8 e2 6d eb ff                                call    0x383250 ; PLT -> _ZNKSt8_Rb_treeISsSt4pairIKSsSsESt10_Select1stIS2_ESt4lessISsESaIS2_EE4findERS1_
          0x4cc46e (+043c)  48 39 85 c0 fe ff ff                          cmp     qword ptr [rbp - 0x140], rax
          0x4cc475 (+0443)  75 44                                         jne     0x4cc4bb ; branch leaves this window
          0x4cc477 (+0445)  be 02 00 00 00                                mov     esi, 2
          0x4cc47c (+044a)  4c 89 f7                                      mov     rdi, r14
          0x4cc47f (+044d)  e8 4c 76 ea ff                                call    0x373ad0 ; PLT -> PciDeviceImpl::SetConfiguredDeviceOwner
```

<!-- evidence:E05:end -->

<!-- evidence:E06:begin -->

### 切片 E06 vSwitch 和 uplink 占用拒绝文字

- 文件：`libvmkctl.so`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PciDeviceImpl::SwitchOwnerToPassthru`；入口 `0x4cc032`，函数大小 `1706` 字节。
- 原始符号：`_ZN6VmkCtl8Hardware13PciDeviceImpl21SwitchOwnerToPassthruEv`。
- 窗口：`0x4cc4bb` 到 `0x4cc53d`（右端不含）；文件偏移 `0x4cc4bb`；24 条指令。
- 窗口 SHA-256：`3aef6acea4303a40155f35fe4cef76f46cd18f0588e1157e092b438441e216f6`。[单独查看汇编](snippets/E06.asm)

```asm
          0x4cc4bb (+0489)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc4c0 (+048e)  e8 cb 05 ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc4c5 (+0493)  48 8d bd 78 ff ff ff                          lea     rdi, [rbp - 0x88]
          0x4cc4cc (+049a)  48 8d 35 15 9b 37 00                          lea     rsi, [rip + 0x379b15] ; literal " for uplink "
          0x4cc4d3 (+04a1)  49 89 c4                                      mov     r12, rax
          0x4cc4d6 (+04a4)  48 8b 85 e8 fe ff ff                          mov     rax, qword ptr [rbp - 0x118]
          0x4cc4dd (+04ab)  48 89 85 c0 fe ff ff                          mov     qword ptr [rbp - 0x140], rax
          0x4cc4e4 (+04b2)  48 8b 40 e8                                   mov     rax, qword ptr [rax - 0x18]
          0x4cc4e8 (+04b6)  48 89 85 c8 fe ff ff                          mov     qword ptr [rbp - 0x138], rax
          0x4cc4ef (+04bd)  e8 7c 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cc4f4 (+04c2)  48 89 de                                      mov     rsi, rbx
          0x4cc4f7 (+04c5)  4c 89 ef                                      mov     rdi, r13
          0x4cc4fa (+04c8)  e8 11 92 ea ff                                call    0x375710 ; PLT -> _ZNSt3mapISsSsSt4lessISsESaISt4pairIKSsSsEEEixERS3_
          0x4cc4ff (+04cd)  48 8b 08                                      mov     rcx, qword ptr [rax]
          0x4cc502 (+04d0)  48 8b bd d8 fe ff ff                          mov     rdi, qword ptr [rbp - 0x128]
          0x4cc509 (+04d7)  48 8d 35 e5 9a 37 00                          lea     rsi, [rip + 0x379ae5] ; literal " as it is used by vswitch "
          0x4cc510 (+04de)  4c 8d ad f0 fe ff ff                          lea     r13, [rbp - 0x110]
          0x4cc517 (+04e5)  48 8b 51 e8                                   mov     rdx, qword ptr [rcx - 0x18]
          0x4cc51b (+04e9)  48 89 8d a0 fe ff ff                          mov     qword ptr [rbp - 0x160], rcx
          0x4cc522 (+04f0)  48 89 95 a8 fe ff ff                          mov     qword ptr [rbp - 0x158], rdx
          0x4cc529 (+04f7)  e8 42 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cc52e (+04fc)  48 8d 35 db 9a 37 00                          lea     rsi, [rip + 0x379adb] ; literal "Device ownership cannot be changed to passthru"
          0x4cc535 (+0503)  4c 89 ff                                      mov     rdi, r15
          0x4cc538 (+0506)  e8 33 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
```

<!-- evidence:E06:end -->
