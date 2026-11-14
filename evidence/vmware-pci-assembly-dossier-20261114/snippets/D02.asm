; D02 请求者依赖代表
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMU_GetReqIdDependencies
; [0x420000164608, 0x42000016464d) file offset 0x423608
; window SHA256 2e28f2e0d92d2df6b6a7c219114e5509911fc5c68f93e1ec00c8fa603f19f2f9

    0x420000164608 (+0000)  55                                            push    rbp
    0x420000164609 (+0001)  48 89 f5                                      mov     rbp, rsi
    0x42000016460c (+0004)  53                                            push    rbx
    0x42000016460d (+0005)  48 83 ec 18                                   sub     rsp, 0x18
    0x420000164611 (+0009)  e8 f6 6d f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000164616 (+000e)  48 85 c0                                      test    rax, rax
    0x420000164619 (+0011)  74 26                                         je      0x420000164641
    0x42000016461b (+0013)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x420000164620 (+0018)  48 89 c7                                      mov     rdi, rax
    0x420000164623 (+001b)  48 89 c3                                      mov     rbx, rax
    0x420000164626 (+001e)  e8 d5 75 f8 ff                                call    0x4200000ebc00 ; directSymbol -> PCI_GetTopmostAliasingBridge
    0x42000016462b (+0023)  85 c0                                         test    eax, eax
    0x42000016462d (+0025)  48 0f 44 5c 24 08                             cmove   rbx, qword ptr [rsp + 8]
    0x420000164633 (+002b)  8b 03                                         mov     eax, dword ptr [rbx]
    0x420000164635 (+002d)  89 45 00                                      mov     dword ptr [rbp], eax
    0x420000164638 (+0030)  48 83 c4 18                                   add     rsp, 0x18
    0x42000016463c (+0034)  31 c0                                         xor     eax, eax
    0x42000016463e (+0036)  5b                                            pop     rbx
    0x42000016463f (+0037)  5d                                            pop     rbp
    0x420000164640 (+0038)  c3                                            ret
    0x420000164641 (+0039)  48 83 c4 18                                   add     rsp, 0x18
    0x420000164645 (+003d)  b8 01 00 ad 0b                                mov     eax, 0xbad0001
    0x42000016464a (+0042)  5b                                            pop     rbx
    0x42000016464b (+0043)  5d                                            pop     rbp
    0x42000016464c (+0044)  c3                                            ret
