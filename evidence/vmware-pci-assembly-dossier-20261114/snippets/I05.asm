; I05 成员域写入 同域引用与错误处理
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMUSwitchDeviceIterator
; [0x420000164470, 0x420000164608) file offset 0x423470
; window SHA256 b69b9cd144ec112d2c8868e3ec0c799149475c04614e2e9919723cef39c9018e

    0x420000164470 (+0000)  41 56                                         push    r14
    0x420000164472 (+0002)  41 55                                         push    r13
    0x420000164474 (+0004)  41 54                                         push    r12
    0x420000164476 (+0006)  45 31 e4                                      xor     r12d, r12d
    0x420000164479 (+0009)  55                                            push    rbp
    0x42000016447a (+000a)  48 89 d5                                      mov     rbp, rdx
    0x42000016447d (+000d)  53                                            push    rbx
    0x42000016447e (+000e)  48 89 fb                                      mov     rbx, rdi
    0x420000164481 (+0011)  e8 32 75 f8 ff                                call    0x4200000eb9b8 ; directSymbol -> PCI_CanDeviceBeAssignedToIOMMUDomain
    0x420000164486 (+0016)  84 c0                                         test    al, al
    0x420000164488 (+0018)  0f 84 b1 00 00 00                             je      0x42000016453f
    0x42000016448e (+001e)  4c 8b ab 78 03 00 00                          mov     r13, qword ptr [rbx + 0x378]
    0x420000164495 (+0025)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x420000164499 (+0029)  4c 39 ef                                      cmp     rdi, r13
    0x42000016449c (+002c)  0f 84 da 00 00 00                             je      0x42000016457c
    0x4200001644a2 (+0032)  80 bb 80 03 00 00 00                          cmp     byte ptr [rbx + 0x380], 0
    0x4200001644a9 (+0039)  0f 84 9c 00 00 00                             je      0x42000016454b
    0x4200001644af (+003f)  83 3d fe a7 26 c0 01                          cmp     dword ptr [rip - 0x3fd95802], 1 ; ripSymbol -> iommuMapReservedMem
    0x4200001644b6 (+0046)  76 15                                         jbe     0x4200001644cd
    0x4200001644b8 (+0048)  48 8b 05 a9 a7 26 c0                          mov     rax, qword ptr [rip - 0x3fd95857] ; ripSymbol -> domainOps
    0x4200001644bf (+004f)  ff 90 a0 00 00 00                             call    qword ptr [rax + 0xa0]
    0x4200001644c5 (+0055)  84 c0                                         test    al, al
    0x4200001644c7 (+0057)  75 12                                         jne     0x4200001644db
    0x4200001644c9 (+0059)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x4200001644cd (+005d)  8b 33                                         mov     esi, dword ptr [rbx]
    0x4200001644cf (+005f)  e8 ec fa ff ff                                call    0x420000163fc0 ; directSymbol -> IOMMUMapRMRRForDevice
    0x4200001644d4 (+0064)  41 89 c4                                      mov     r12d, eax
    0x4200001644d7 (+0067)  85 c0                                         test    eax, eax
    0x4200001644d9 (+0069)  75 64                                         jne     0x42000016453f
    0x4200001644db (+006b)  48 8b 05 86 a7 26 c0                          mov     rax, qword ptr [rip - 0x3fd9587a] ; ripSymbol -> domainOps
    0x4200001644e2 (+0072)  8b 13                                         mov     edx, dword ptr [rbx]
    0x4200001644e4 (+0074)  4c 89 ef                                      mov     rdi, r13
    0x4200001644e7 (+0077)  48 8b 75 00                                   mov     rsi, qword ptr [rbp]
    0x4200001644eb (+007b)  ff 50 60                                      call    qword ptr [rax + 0x60]
    0x4200001644ee (+007e)  41 89 c4                                      mov     r12d, eax
    0x4200001644f1 (+0081)  85 c0                                         test    eax, eax
    0x4200001644f3 (+0083)  75 4a                                         jne     0x42000016453f
    0x4200001644f5 (+0085)  f6 43 04 02                                   test    byte ptr [rbx + 4], 2
    0x4200001644f9 (+0089)  74 0d                                         je      0x420000164508
    0x4200001644fb (+008b)  83 bb f8 00 00 00 04                          cmp     dword ptr [rbx + 0xf8], 4
    0x420000164502 (+0092)  0f 84 96 00 00 00                             je      0x42000016459e
    0x420000164508 (+0098)  80 7d 09 00                                   cmp     byte ptr [rbp + 9], 0
    0x42000016450c (+009c)  75 61                                         jne     0x42000016456f
    0x42000016450e (+009e)  0f b6 83 80 03 00 00                          movzx   eax, byte ptr [rbx + 0x380]
    0x420000164515 (+00a5)  84 c0                                         test    al, al
    0x420000164517 (+00a7)  74 0b                                         je      0x420000164524
    0x420000164519 (+00a9)  83 83 70 03 00 00 01                          add     dword ptr [rbx + 0x370], 1
    0x420000164520 (+00b0)  0f b6 45 09                                   movzx   eax, byte ptr [rbp + 9]
    0x420000164524 (+00b4)  0f b6 55 08                                   movzx   edx, byte ptr [rbp + 8]
    0x420000164528 (+00b8)  48 8b 4d 00                                   mov     rcx, qword ptr [rbp]
    0x42000016452c (+00bc)  88 83 80 03 00 00                             mov     byte ptr [rbx + 0x380], al
    0x420000164532 (+00c2)  48 89 8b 78 03 00 00                          mov     qword ptr [rbx + 0x378], rcx
    0x420000164539 (+00c9)  88 93 81 03 00 00                             mov     byte ptr [rbx + 0x381], dl
    0x42000016453f (+00cf)  5b                                            pop     rbx
    0x420000164540 (+00d0)  44 89 e0                                      mov     eax, r12d
    0x420000164543 (+00d3)  5d                                            pop     rbp
    0x420000164544 (+00d4)  41 5c                                         pop     r12
    0x420000164546 (+00d6)  41 5d                                         pop     r13
    0x420000164548 (+00d8)  41 5e                                         pop     r14
    0x42000016454a (+00da)  c3                                            ret
    0x42000016454b (+00db)  8b 83 70 03 00 00                             mov     eax, dword ptr [rbx + 0x370]
    0x420000164551 (+00e1)  83 f8 01                                      cmp     eax, 1
    0x420000164554 (+00e4)  0f 86 55 ff ff ff                             jbe     0x4200001644af
    0x42000016455a (+00ea)  83 e8 01                                      sub     eax, 1
    0x42000016455d (+00ed)  89 83 70 03 00 00                             mov     dword ptr [rbx + 0x370], eax
    0x420000164563 (+00f3)  5b                                            pop     rbx
    0x420000164564 (+00f4)  44 89 e0                                      mov     eax, r12d
    0x420000164567 (+00f7)  5d                                            pop     rbp
    0x420000164568 (+00f8)  41 5c                                         pop     r12
    0x42000016456a (+00fa)  41 5d                                         pop     r13
    0x42000016456c (+00fc)  41 5e                                         pop     r14
    0x42000016456e (+00fe)  c3                                            ret
    0x42000016456f (+00ff)  83 ab 70 03 00 00 01                          sub     dword ptr [rbx + 0x370], 1
    0x420000164576 (+0106)  0f b6 45 09                                   movzx   eax, byte ptr [rbp + 9]
    0x42000016457a (+010a)  eb a8                                         jmp     0x420000164524
    0x42000016457c (+010c)  80 7d 09 00                                   cmp     byte ptr [rbp + 9], 0
    0x420000164580 (+0110)  75 bd                                         jne     0x42000016453f
    0x420000164582 (+0112)  44 8b a3 70 03 00 00                          mov     r12d, dword ptr [rbx + 0x370]
    0x420000164589 (+0119)  45 85 e4                                      test    r12d, r12d
    0x42000016458c (+011c)  74 b1                                         je      0x42000016453f
    0x42000016458e (+011e)  41 83 c4 01                                   add     r12d, 1
    0x420000164592 (+0122)  44 89 a3 70 03 00 00                          mov     dword ptr [rbx + 0x370], r12d
    0x420000164599 (+0129)  45 31 e4                                      xor     r12d, r12d
    0x42000016459c (+012c)  eb a1                                         jmp     0x42000016453f
    0x42000016459e (+012e)  ba 02 00 00 00                                mov     edx, 2
    0x4200001645a3 (+0133)  48 89 ee                                      mov     rsi, rbp
    0x4200001645a6 (+0136)  48 89 df                                      mov     rdi, rbx
    0x4200001645a9 (+0139)  e8 02 fb ff ff                                call    0x4200001640b0 ; directSymbol -> IOMMUHandleBridgePCIEToPCI.isra.0
    0x4200001645ae (+013e)  41 89 c6                                      mov     r14d, eax
    0x4200001645b1 (+0141)  85 c0                                         test    eax, eax
    0x4200001645b3 (+0143)  0f 84 4f ff ff ff                             je      0x420000164508
    0x4200001645b9 (+0149)  48 8b 05 a8 a6 26 c0                          mov     rax, qword ptr [rip - 0x3fd95958] ; ripSymbol -> domainOps
    0x4200001645c0 (+0150)  8b 13                                         mov     edx, dword ptr [rbx]
    0x4200001645c2 (+0152)  4c 89 ee                                      mov     rsi, r13
    0x4200001645c5 (+0155)  48 8b 7d 00                                   mov     rdi, qword ptr [rbp]
    0x4200001645c9 (+0159)  ff 50 60                                      call    qword ptr [rax + 0x60]
    0x4200001645cc (+015c)  85 c0                                         test    eax, eax
    0x4200001645ce (+015e)  75 08                                         jne     0x4200001645d8
    0x4200001645d0 (+0160)  45 89 f4                                      mov     r12d, r14d
    0x4200001645d3 (+0163)  e9 67 ff ff ff                                jmp     0x42000016453f
    0x4200001645d8 (+0168)  8b 03                                         mov     eax, dword ptr [rbx]
    0x4200001645da (+016a)  be f2 04 00 00                                mov     esi, 0x4f2
    0x4200001645df (+016f)  48 8d 3d 92 99 6a 00                          lea     rdi, [rip + 0x6a9992] ; literal "IOMMU: %d: Unable to switch back %04x:%02x:%02x.%x to domain on failure\n"
    0x4200001645e6 (+0176)  41 89 c0                                      mov     r8d, eax
    0x4200001645e9 (+0179)  0f b6 cc                                      movzx   ecx, ah
    0x4200001645ec (+017c)  89 c2                                         mov     edx, eax
    0x4200001645ee (+017e)  83 e0 07                                      and     eax, 7
    0x4200001645f1 (+0181)  41 c1 e8 03                                   shr     r8d, 3
    0x4200001645f5 (+0185)  41 89 c1                                      mov     r9d, eax
    0x4200001645f8 (+0188)  c1 ea 10                                      shr     edx, 0x10
    0x4200001645fb (+018b)  31 c0                                         xor     eax, eax
    0x4200001645fd (+018d)  41 83 e0 1f                                   and     r8d, 0x1f
    0x420000164601 (+0191)  e8 9e 60 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x420000164606 (+0196)  eb c8                                         jmp     0x4200001645d0
