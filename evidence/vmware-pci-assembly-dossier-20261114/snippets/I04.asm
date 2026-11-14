; I04 校验旧域并遍历别名子树
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / IOMMU_SwitchAddressDomain
; [0x4200001654e4, 0x4200001655e5) file offset 0x4244e4
; window SHA256 b96db720277a1c191972265faa857737c31718e0b7e98cc8169efd545b23b05e

    0x4200001654e4 (+0000)  41 56                                         push    r14
    0x4200001654e6 (+0002)  41 89 ce                                      mov     r14d, ecx
    0x4200001654e9 (+0005)  41 55                                         push    r13
    0x4200001654eb (+0007)  49 89 fd                                      mov     r13, rdi
    0x4200001654ee (+000a)  89 d7                                         mov     edi, edx
    0x4200001654f0 (+000c)  41 54                                         push    r12
    0x4200001654f2 (+000e)  49 89 f4                                      mov     r12, rsi
    0x4200001654f5 (+0011)  55                                            push    rbp
    0x4200001654f6 (+0012)  53                                            push    rbx
    0x4200001654f7 (+0013)  89 d3                                         mov     ebx, edx
    0x4200001654f9 (+0015)  48 83 ec 20                                   sub     rsp, 0x20
    0x4200001654fd (+0019)  e8 0a 5f f8 ff                                call    0x4200000eb40c ; directSymbol -> PCI_GetDevice
    0x420000165502 (+001e)  48 89 c5                                      mov     rbp, rax
    0x420000165505 (+0021)  48 8d 05 00 00 00 00                          lea     rax, [rip]
    0x42000016550c (+0028)  48 8d 3d 41 97 26 c0                          lea     rdi, [rip - 0x3fd968bf] ; ripSymbol -> IOMMUDomainLock
    0x420000165513 (+002f)  e8 b0 fd 01 00                                call    0x4200001852c8 ; directSymbol -> SPLockWork
    0x420000165518 (+0034)  4c 39 ad 78 03 00 00                          cmp     qword ptr [rbp + 0x378], r13
    0x42000016551f (+003b)  75 62                                         jne     0x420000165583
    0x420000165521 (+003d)  4c 39 25 38 97 26 c0                          cmp     qword ptr [rip - 0x3fd968c8], r12 ; ripSymbol -> vmkDomain
    0x420000165528 (+0044)  48 89 ef                                      mov     rdi, rbp
    0x42000016552b (+0047)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x420000165530 (+004c)  4c 89 64 24 10                                mov     qword ptr [rsp + 0x10], r12
    0x420000165535 (+0051)  0f 94 44 24 19                                sete    byte ptr [rsp + 0x19]
    0x42000016553a (+0056)  44 88 74 24 18                                mov     byte ptr [rsp + 0x18], r14b
    0x42000016553f (+005b)  e8 bc 66 f8 ff                                call    0x4200000ebc00 ; directSymbol -> PCI_GetTopmostAliasingBridge
    0x420000165544 (+0060)  48 8d 54 24 10                                lea     rdx, [rsp + 0x10]
    0x420000165549 (+0065)  48 8d 35 20 ef ff ff                          lea     rsi, [rip - 0x10e0] ; ripSymbol -> IOMMUSwitchDeviceIterator
    0x420000165550 (+006c)  85 c0                                         test    eax, eax
    0x420000165552 (+006e)  48 0f 44 6c 24 08                             cmove   rbp, qword ptr [rsp + 8]
    0x420000165558 (+0074)  48 89 ef                                      mov     rdi, rbp
    0x42000016555b (+0077)  e8 e4 64 f8 ff                                call    0x4200000eba44 ; directSymbol -> PCI_IterateDeviceTree
    0x420000165560 (+007c)  41 89 c4                                      mov     r12d, eax
    0x420000165563 (+007f)  85 c0                                         test    eax, eax
    0x420000165565 (+0081)  75 50                                         jne     0x4200001655b7
    0x420000165567 (+0083)  48 8d 3d e6 96 26 c0                          lea     rdi, [rip - 0x3fd9691a] ; ripSymbol -> IOMMUDomainLock
    0x42000016556e (+008a)  e8 b1 f8 01 00                                call    0x420000184e24 ; directSymbol -> SP_Unlock
    0x420000165573 (+008f)  48 83 c4 20                                   add     rsp, 0x20
    0x420000165577 (+0093)  44 89 e0                                      mov     eax, r12d
    0x42000016557a (+0096)  5b                                            pop     rbx
    0x42000016557b (+0097)  5d                                            pop     rbp
    0x42000016557c (+0098)  41 5c                                         pop     r12
    0x42000016557e (+009a)  41 5d                                         pop     r13
    0x420000165580 (+009c)  41 5e                                         pop     r14
    0x420000165582 (+009e)  c3                                            ret
    0x420000165583 (+009f)  41 89 d8                                      mov     r8d, ebx
    0x420000165586 (+00a2)  0f b6 cf                                      movzx   ecx, bh
    0x420000165589 (+00a5)  89 da                                         mov     edx, ebx
    0x42000016558b (+00a7)  83 e3 07                                      and     ebx, 7
    0x42000016558e (+00aa)  41 c1 e8 03                                   shr     r8d, 3
    0x420000165592 (+00ae)  c1 ea 10                                      shr     edx, 0x10
    0x420000165595 (+00b1)  41 89 d9                                      mov     r9d, ebx
    0x420000165598 (+00b4)  be 80 0c 00 00                                mov     esi, 0xc80
    0x42000016559d (+00b9)  41 83 e0 1f                                   and     r8d, 0x1f
    0x4200001655a1 (+00bd)  48 8d 3d 20 27 5e 00                          lea     rdi, [rip + 0x5e2720] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x is not switched to the new domain because the fromDom does not match its current domain.\n"
    0x4200001655a8 (+00c4)  31 c0                                         xor     eax, eax
    0x4200001655aa (+00c6)  41 bc 01 00 ad 0b                             mov     r12d, 0xbad0001
    0x4200001655b0 (+00cc)  e8 ef 50 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x4200001655b5 (+00d1)  eb b0                                         jmp     0x420000165567
    0x4200001655b7 (+00d3)  41 89 d8                                      mov     r8d, ebx
    0x4200001655ba (+00d6)  0f b6 cf                                      movzx   ecx, bh
    0x4200001655bd (+00d9)  89 da                                         mov     edx, ebx
    0x4200001655bf (+00db)  83 e3 07                                      and     ebx, 7
    0x4200001655c2 (+00de)  41 c1 e8 03                                   shr     r8d, 3
    0x4200001655c6 (+00e2)  c1 ea 10                                      shr     edx, 0x10
    0x4200001655c9 (+00e5)  41 89 d9                                      mov     r9d, ebx
    0x4200001655cc (+00e8)  be 90 0c 00 00                                mov     esi, 0xc90
    0x4200001655d1 (+00ed)  41 83 e0 1f                                   and     r8d, 0x1f
    0x4200001655d5 (+00f1)  48 8d 3d ac b6 66 00                          lea     rdi, [rip + 0x66b6ac] ; literal "IOMMU: %d: Device %04x:%02x:%02x.%x could not be switched to the specified domain.\n"
    0x4200001655dc (+00f8)  31 c0                                         xor     eax, eax
    0x4200001655de (+00fa)  e8 c1 50 00 00                                call    0x42000016a6a4 ; directSymbol -> _Warning
    0x4200001655e3 (+00ff)  eb 82                                         jmp     0x420000165567
