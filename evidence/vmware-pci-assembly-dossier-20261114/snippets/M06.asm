; M06 复位方法选择的完整函数
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_FindResetMethod
; [0x4200000fc450, 0x4200000fc5b6) file offset 0x3bb450
; window SHA256 7742f18c071240660379f560bcd30b9027df6c4b35fd3a7de879320a85a9e2f6

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
