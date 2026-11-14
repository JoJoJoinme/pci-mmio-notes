; M03 shareable 输入取反后设置依赖
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / Hardware_PCIPassthruShareableSet
; [0x42000007263c, 0x42000007268a) file offset 0x33163c
; window SHA256 ea6d741c92876fbbd3bfc589214a2a32841e603ae04191dc789728d03ccb4f8c

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
