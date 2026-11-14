# ACS quirk 的完整函数证据

本函数按 vendor/device 字段返回 ACS Control 的相对偏移，默认 6，特定 Intel 范围返回 8。M07 的调用点将该结果加到 ACS capability 起始地址后读取控制值；该 quirk 本身没有返回通过/拒绝结论。

16 位加法分支对应的 device 范围为 a110–a11f、9d10–9d1b、a290–a29f、9db0–9dbf。这里没有据此声称取得了芯片勘误或厂商原始结构体定义。

[返回 ACS 规则详解](../03-acs-rule-details.md#quirk) · [独立 objdump 核对](objdump-verification.json)

<!-- evidence:Q01:begin -->

### 切片 Q01 按设备型号返回 ACS Control 偏移

- 文件：`decompressed k.b00`，build `24280767`；地址类型：ELF linked virtual address。
- 函数：`PCIQuirks_GetAcsCtrlOffset`；入口 `0x4200000fd6fc`，函数大小 `83` 字节。
- 窗口：`0x4200000fd6fc` 到 `0x4200000fd74f`（右端不含）；文件偏移 `0x3bc6fc`；23 条指令。
- 窗口 SHA-256：`19655097f5505efc1b70b312cc3c4b7e1b700b97c7e0517469b1604322993fae`。[单独查看汇编](snippets/Q01.asm)

```asm
    0x4200000fd6fc (+0000)  66 81 7f 0c 86 80                             cmp     word ptr [rdi + 0xc], 0x8086
    0x4200000fd702 (+0006)  b8 06 00 00 00                                mov     eax, 6
    0x4200000fd707 (+000b)  74 01                                         je      0x4200000fd70a
    0x4200000fd709 (+000d)  c3                                            ret
    0x4200000fd70a (+000e)  0f b7 57 0e                                   movzx   edx, word ptr [rdi + 0xe]
    0x4200000fd70e (+0012)  8d 82 f0 5e 00 00                             lea     eax, [rdx + 0x5ef0]
    0x4200000fd714 (+0018)  66 83 f8 0f                                   cmp     ax, 0xf
    0x4200000fd718 (+001c)  76 2f                                         jbe     0x4200000fd749
    0x4200000fd71a (+001e)  8d 82 f0 62 00 00                             lea     eax, [rdx + 0x62f0]
    0x4200000fd720 (+0024)  66 83 f8 0b                                   cmp     ax, 0xb
    0x4200000fd724 (+0028)  76 23                                         jbe     0x4200000fd749
    0x4200000fd726 (+002a)  8d 8a 70 5d 00 00                             lea     ecx, [rdx + 0x5d70]
    0x4200000fd72c (+0030)  b8 08 00 00 00                                mov     eax, 8
    0x4200000fd731 (+0035)  66 83 f9 0f                                   cmp     cx, 0xf
    0x4200000fd735 (+0039)  76 d2                                         jbe     0x4200000fd709
    0x4200000fd737 (+003b)  66 81 c2 50 62                                add     dx, 0x6250
    0x4200000fd73c (+0040)  66 83 fa 10                                   cmp     dx, 0x10
    0x4200000fd740 (+0044)  19 c0                                         sbb     eax, eax
    0x4200000fd742 (+0046)  83 e0 02                                      and     eax, 2
    0x4200000fd745 (+0049)  83 c0 06                                      add     eax, 6
    0x4200000fd748 (+004c)  c3                                            ret
    0x4200000fd749 (+004d)  b8 08 00 00 00                                mov     eax, 8
    0x4200000fd74e (+0052)  c3                                            ret
```

<!-- evidence:Q01:end -->
