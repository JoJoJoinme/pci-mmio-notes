; I08 PCIe 到 PCI 桥的专门映射处理
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMUHandleBridgePCIEToPCI.isra.0
; [0x4200001640b0, 0x4200001641bb) file offset 0x4230b0
; window SHA256 433f6fc5bddb9c22f1e9eef857329b263bbd998a87a43c5d1c6ef66869440efe

    0x4200001640b0 (+0000)  41 56                                         push    r14
    0x4200001640b2 (+0002)  41 55                                         push    r13
    0x4200001640b4 (+0004)  41 54                                         push    r12
    0x4200001640b6 (+0006)  55                                            push    rbp
    0x4200001640b7 (+0007)  53                                            push    rbx
    0x4200001640b8 (+0008)  0f b6 47 1b                                   movzx   eax, byte ptr [rdi + 0x1b]
    0x4200001640bc (+000c)  85 c0                                         test    eax, eax
    0x4200001640be (+000e)  75 0f                                         jne     0x4200001640cf
    0x4200001640c0 (+0010)  45 31 e4                                      xor     r12d, r12d
    0x4200001640c3 (+0013)  5b                                            pop     rbx
    0x4200001640c4 (+0014)  44 89 e0                                      mov     eax, r12d
    0x4200001640c7 (+0017)  5d                                            pop     rbp
    0x4200001640c8 (+0018)  41 5c                                         pop     r12
    0x4200001640ca (+001a)  41 5d                                         pop     r13
    0x4200001640cc (+001c)  41 5e                                         pop     r14
    0x4200001640ce (+001e)  c3                                            ret
    0x4200001640cf (+001f)  8b 2f                                         mov     ebp, dword ptr [rdi]
    0x4200001640d1 (+0021)  c1 e0 08                                      shl     eax, 8
    0x4200001640d4 (+0024)  48 89 fb                                      mov     rbx, rdi
    0x4200001640d7 (+0027)  49 89 f6                                      mov     r14, rsi
    0x4200001640da (+002a)  41 89 d5                                      mov     r13d, edx
    0x4200001640dd (+002d)  66 31 ed                                      xor     bp, bp
    0x4200001640e0 (+0030)  09 c5                                         or      ebp, eax
    0x4200001640e2 (+0032)  89 ef                                         mov     edi, ebp
    0x4200001640e4 (+0034)  e8 23 73 f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x4200001640e9 (+0039)  48 85 c0                                      test    rax, rax
    0x4200001640ec (+003c)  75 d2                                         jne     0x4200001640c0
    0x4200001640ee (+003e)  83 3d bf ab 26 c0 01                          cmp     dword ptr [rip - 0x3fd95441], 1 ; ripSymbol -> iommuMapReservedMem
    0x4200001640f5 (+0045)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x4200001640f8 (+0048)  76 14                                         jbe     0x42000016410e
    0x4200001640fa (+004a)  48 8b 05 67 ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd95499] ; ripSymbol -> domainOps
    0x420000164101 (+0051)  ff 90 a0 00 00 00                             call    qword ptr [rax + 0xa0]
    0x420000164107 (+0057)  84 c0                                         test    al, al
    0x420000164109 (+0059)  75 2a                                         jne     0x420000164135
    0x42000016410b (+005b)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x42000016410e (+005e)  48 8b 05 53 ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954ad] ; ripSymbol -> domainOps
    0x420000164115 (+0065)  41 83 fd 01                                   cmp     r13d, 1
    0x420000164119 (+0069)  75 7f                                         jne     0x42000016419a
    0x42000016411b (+006b)  89 ee                                         mov     esi, ebp
    0x42000016411d (+006d)  ff 50 50                                      call    qword ptr [rax + 0x50]
    0x420000164120 (+0070)  41 89 c4                                      mov     r12d, eax
    0x420000164123 (+0073)  85 c0                                         test    eax, eax
    0x420000164125 (+0075)  75 9c                                         jne     0x4200001640c3
    0x420000164127 (+0077)  48 8b 05 3a ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954c6] ; ripSymbol -> domainOps
    0x42000016412e (+007e)  89 ef                                         mov     edi, ebp
    0x420000164130 (+0080)  ff 50 78                                      call    qword ptr [rax + 0x78]
    0x420000164133 (+0083)  eb 8e                                         jmp     0x4200001640c3
    0x420000164135 (+0085)  48 8b 05 2c ab 26 c0                          mov     rax, qword ptr [rip - 0x3fd954d4] ; ripSymbol -> domainOps
    0x42000016413c (+008c)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x42000016413f (+008f)  48 89 c1                                      mov     rcx, rax
    0x420000164142 (+0092)  41 83 fd 01                                   cmp     r13d, 1
    0x420000164146 (+0096)  74 d3                                         je      0x42000016411b
    0x420000164148 (+0098)  41 83 fd 02                                   cmp     r13d, 2
    0x42000016414c (+009c)  74 2a                                         je      0x420000164178
    0x42000016414e (+009e)  89 ee                                         mov     esi, ebp
    0x420000164150 (+00a0)  ff 51 40                                      call    qword ptr [rcx + 0x40]
    0x420000164153 (+00a3)  41 89 c4                                      mov     r12d, eax
    0x420000164156 (+00a6)  85 c0                                         test    eax, eax
    0x420000164158 (+00a8)  0f 85 65 ff ff ff                             jne     0x4200001640c3
    0x42000016415e (+00ae)  45 85 ed                                      test    r13d, r13d
    0x420000164161 (+00b1)  0f 85 59 ff ff ff                             jne     0x4200001640c0
    0x420000164167 (+00b7)  48 8b 05 fa aa 26 c0                          mov     rax, qword ptr [rip - 0x3fd95506] ; ripSymbol -> domainOps
    0x42000016416e (+00be)  89 ef                                         mov     edi, ebp
    0x420000164170 (+00c0)  ff 50 70                                      call    qword ptr [rax + 0x70]
    0x420000164173 (+00c3)  e9 4b ff ff ff                                jmp     0x4200001640c3
    0x420000164178 (+00c8)  4c 8b 83 78 03 00 00                          mov     r8, qword ptr [rbx + 0x378]
    0x42000016417f (+00cf)  48 89 fe                                      mov     rsi, rdi
    0x420000164182 (+00d2)  89 ea                                         mov     edx, ebp
    0x420000164184 (+00d4)  4c 89 c7                                      mov     rdi, r8
    0x420000164187 (+00d7)  ff 51 60                                      call    qword ptr [rcx + 0x60]
    0x42000016418a (+00da)  41 89 c4                                      mov     r12d, eax
    0x42000016418d (+00dd)  85 c0                                         test    eax, eax
    0x42000016418f (+00df)  0f 84 2b ff ff ff                             je      0x4200001640c0
    0x420000164195 (+00e5)  e9 29 ff ff ff                                jmp     0x4200001640c3
    0x42000016419a (+00ea)  89 ee                                         mov     esi, ebp
    0x42000016419c (+00ec)  41 bc 01 00 ad 0b                             mov     r12d, 0xbad0001
    0x4200001641a2 (+00f2)  e8 19 fe ff ff                                call    0x420000163fc0 ; directSymbol -> IOMMUMapRMRRForDevice
    0x4200001641a7 (+00f7)  85 c0                                         test    eax, eax
    0x4200001641a9 (+00f9)  0f 85 14 ff ff ff                             jne     0x4200001640c3
    0x4200001641af (+00ff)  48 8b 0d b2 aa 26 c0                          mov     rcx, qword ptr [rip - 0x3fd9554e] ; ripSymbol -> domainOps
    0x4200001641b6 (+0106)  49 8b 3e                                      mov     rdi, qword ptr [r14]
    0x4200001641b9 (+0109)  eb 8d                                         jmp     0x420000164148
