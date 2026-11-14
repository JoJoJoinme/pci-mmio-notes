; I02 域查询返回值的实际含义
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMU_GetAddressDomain
; [0x42000016544c, 0x420000165488) file offset 0x42444c
; window SHA256 50d1111b38235829b3d3b1e7a02a90ad1d89332d8146adb4b9d65dd049d4b6c5

    0x42000016544c (+0000)  53                                            push    rbx
    0x42000016544d (+0001)  48 89 f3                                      mov     rbx, rsi
    0x420000165450 (+0004)  e8 b7 5f f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000165455 (+0009)  48 89 c7                                      mov     rdi, rax
    0x420000165458 (+000c)  e8 5f ff ff ff                                call    0x4200001653bc ; directSymbol -> IOMMU_GetDeviceDomain
    0x42000016545d (+0011)  48 89 03                                      mov     qword ptr [rbx], rax
    0x420000165460 (+0014)  48 85 c0                                      test    rax, rax
    0x420000165463 (+0017)  74 11                                         je      0x420000165476
    0x420000165465 (+0019)  45 31 c0                                      xor     r8d, r8d
    0x420000165468 (+001c)  48 3b 05 f1 97 26 c0                          cmp     rax, qword ptr [rip - 0x3fd9680f] ; ripSymbol -> vmkDomain
    0x42000016546f (+0023)  74 05                                         je      0x420000165476
    0x420000165471 (+0025)  44 89 c0                                      mov     eax, r8d
    0x420000165474 (+0028)  5b                                            pop     rbx
    0x420000165475 (+0029)  c3                                            ret
    0x420000165476 (+002a)  41 b8 03 00 ad 0b                             mov     r8d, 0xbad0003
    0x42000016547c (+0030)  48 c7 03 00 00 00 00                          mov     qword ptr [rbx], 0
    0x420000165483 (+0037)  5b                                            pop     rbx
    0x420000165484 (+0038)  44 89 c0                                      mov     eax, r8d
    0x420000165487 (+003b)  c3                                            ret
