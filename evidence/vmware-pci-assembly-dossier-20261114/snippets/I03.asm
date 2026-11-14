; I03 域指针读取字段
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMU_GetDeviceDomain
; [0x4200001653bc, 0x42000016544c) file offset 0x4243bc
; window SHA256 c39141157f3c22bf0276e61b111f5f134c025c3652053efa9c57825a4df15473

    0x4200001653bc (+0000)  41 54                                         push    r12
    0x4200001653be (+0002)  53                                            push    rbx
    0x4200001653bf (+0003)  48 89 fb                                      mov     rbx, rdi
    0x4200001653c2 (+0006)  48 83 ec 08                                   sub     rsp, 8
    0x4200001653c6 (+000a)  48 8d 05 00 00 00 00                          lea     rax, [rip]
    0x4200001653cd (+0011)  48 8d 3d 80 98 26 c0                          lea     rdi, [rip - 0x3fd96780] ; ripSymbol -> IOMMUDomainLock
    0x4200001653d4 (+0018)  e8 ef fe 01 00                                call    0x4200001852c8 ; directSymbol -> SPLockWork
    0x4200001653d9 (+001d)  48 85 db                                      test    rbx, rbx
    0x4200001653dc (+0020)  74 69                                         je      0x420000165447
    0x4200001653de (+0022)  4c 8b a3 78 03 00 00                          mov     r12, qword ptr [rbx + 0x378]
    0x4200001653e5 (+0029)  48 8d 3d 68 98 26 c0                          lea     rdi, [rip - 0x3fd96798] ; ripSymbol -> IOMMUDomainLock
    0x4200001653ec (+0030)  e8 33 fa 01 00                                call    0x420000184e24 ; directSymbol -> SP_Unlock
    0x4200001653f1 (+0035)  48 83 3d f7 08 f6 bf 01                       cmp     qword ptr [rip - 0x4009f709], 1 ; configOption+0x90
    0x4200001653f9 (+003d)  74 0b                                         je      0x420000165406
    0x4200001653fb (+003f)  48 83 c4 08                                   add     rsp, 8
    0x4200001653ff (+0043)  4c 89 e0                                      mov     rax, r12
    0x420000165402 (+0046)  5b                                            pop     rbx
    0x420000165403 (+0047)  41 5c                                         pop     r12
    0x420000165405 (+0049)  c3                                            ret
    0x420000165406 (+004a)  8b 03                                         mov     eax, dword ptr [rbx]
    0x420000165408 (+004c)  48 83 ec 08                                   sub     rsp, 8
    0x42000016540c (+0050)  be ec 0b 00 00                                mov     esi, 0xbec
    0x420000165411 (+0055)  48 8d 3d 98 68 6c 00                          lea     rdi, [rip + 0x6c6898] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x is assigned to IOMMU domain %p\n"
    0x420000165418 (+005c)  41 54                                         push    r12
    0x42000016541a (+005e)  41 89 c0                                      mov     r8d, eax
    0x42000016541d (+0061)  0f b6 cc                                      movzx   ecx, ah
    0x420000165420 (+0064)  89 c2                                         mov     edx, eax
    0x420000165422 (+0066)  83 e0 07                                      and     eax, 7
    0x420000165425 (+0069)  41 c1 e8 03                                   shr     r8d, 3
    0x420000165429 (+006d)  c1 ea 10                                      shr     edx, 0x10
    0x42000016542c (+0070)  41 89 c1                                      mov     r9d, eax
    0x42000016542f (+0073)  31 c0                                         xor     eax, eax
    0x420000165431 (+0075)  41 83 e0 1f                                   and     r8d, 0x1f
    0x420000165435 (+0079)  e8 12 4e 00 00                                call    0x42000016a24c ; directSymbol -> _Log
    0x42000016543a (+007e)  58                                            pop     rax
    0x42000016543b (+007f)  5a                                            pop     rdx
    0x42000016543c (+0080)  4c 89 e0                                      mov     rax, r12
    0x42000016543f (+0083)  48 83 c4 08                                   add     rsp, 8
    0x420000165443 (+0087)  5b                                            pop     rbx
    0x420000165444 (+0088)  41 5c                                         pop     r12
    0x420000165446 (+008a)  c3                                            ret
    0x420000165447 (+008b)  45 31 e4                                      xor     r12d, r12d
    0x42000016544a (+008e)  eb 99                                         jmp     0x4200001653e5
