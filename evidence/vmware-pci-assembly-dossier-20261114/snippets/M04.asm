; M04 设置依赖所需 Header 和端口类型
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_SetMultiFuncDependency
; [0x4200000eb734, 0x4200000eb77a) file offset 0x3aa734
; window SHA256 9fc524b812bf19ae1af25efa3611047a1979ca75604d67e98f0b466774b8309c

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
