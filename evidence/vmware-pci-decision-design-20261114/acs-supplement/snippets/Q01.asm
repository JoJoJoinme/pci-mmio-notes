; Q01 build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; window SHA256 19655097f5505efc1b70b312cc3c4b7e1b700b97c7e0517469b1604322993fae

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
