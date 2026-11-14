; M07 ACS 类型 检查 缓存与软件策略
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCIE_EnforceACS
; [0x4200000f52d4, 0x4200000f5523) file offset 0x3b42d4
; window SHA256 51096facac62cfa185314701008cf3345e0fc7aefacfdb8e685d8e454ccee113

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
