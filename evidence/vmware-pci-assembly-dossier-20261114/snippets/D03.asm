; D03 沿父链选最上层别名桥
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_GetTopmostAliasingBridge
; [0x4200000ebc00, 0x4200000ebc50) file offset 0x3aac00
; window SHA256 5ef21b016dad0b7725351101217e83a4e01577ec15bea4befe16eb6a012b282c

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
