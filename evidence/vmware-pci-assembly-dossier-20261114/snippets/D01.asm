; D01 完整依赖代表计算
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / VMKPCIPassthru_GetDeviceDependencies
; [0x4200001a0e38, 0x4200001a0efd) file offset 0x45fe38
; window SHA256 916b3c8853f3bd971b838933dca8c443c664b6b5946fd67d9ee736ac2f5af793

    0x4200001a0e38 (+0000)  41 54                                         push    r12
    0x4200001a0e3a (+0002)  55                                            push    rbp
    0x4200001a0e3b (+0003)  48 89 f5                                      mov     rbp, rsi
    0x4200001a0e3e (+0006)  53                                            push    rbx
    0x4200001a0e3f (+0007)  48 89 fb                                      mov     rbx, rdi
    0x4200001a0e42 (+000a)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200001a0e46 (+000e)  48 85 ff                                      test    rdi, rdi
    0x4200001a0e49 (+0011)  74 14                                         je      0x4200001a0e5f
    0x4200001a0e4b (+0013)  f6 47 04 02                                   test    byte ptr [rdi + 4], 2
    0x4200001a0e4f (+0017)  74 0e                                         je      0x4200001a0e5f
    0x4200001a0e51 (+0019)  48 83 c4 10                                   add     rsp, 0x10
    0x4200001a0e55 (+001d)  b8 01 00 ad 0b                                mov     eax, 0xbad0001
    0x4200001a0e5a (+0022)  5b                                            pop     rbx
    0x4200001a0e5b (+0023)  5d                                            pop     rbp
    0x4200001a0e5c (+0024)  41 5c                                         pop     r12
    0x4200001a0e5e (+0026)  c3                                            ret
    0x4200001a0e5f (+0027)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200001a0e61 (+0029)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200001a0e66 (+002e)  e8 9d 37 fc ff                                call    0x420000164608 ; directSymbol -> IOMMU_GetReqIdDependencies
    0x4200001a0e6b (+0033)  80 bb f8 01 00 00 00                          cmp     byte ptr [rbx + 0x1f8], 0
    0x4200001a0e72 (+003a)  48 89 d8                                      mov     rax, rbx
    0x4200001a0e75 (+003d)  75 47                                         jne     0x4200001a0ebe
    0x4200001a0e77 (+003f)  48 83 3d 99 4f f2 bf 01                       cmp     qword ptr [rip - 0x400db067], 1 ; configOption+0x1b8
    0x4200001a0e7f (+0047)  44 8b 20                                      mov     r12d, dword ptr [rax]
    0x4200001a0e82 (+004a)  74 0c                                         je      0x4200001a0e90
    0x4200001a0e84 (+004c)  48 89 df                                      mov     rdi, rbx
    0x4200001a0e87 (+004f)  e8 64 b7 f5 ff                                call    0x4200000fc5f0 ; directSymbol -> PCI_HasFuncIndependentReset
    0x4200001a0e8c (+0054)  84 c0                                         test    al, al
    0x4200001a0e8e (+0056)  74 49                                         je      0x4200001a0ed9
    0x4200001a0e90 (+0058)  8b 44 24 0c                                   mov     eax, dword ptr [rsp + 0xc]
    0x4200001a0e94 (+005c)  8b 0b                                         mov     ecx, dword ptr [rbx]
    0x4200001a0e96 (+005e)  44 89 e3                                      mov     ebx, r12d
    0x4200001a0e99 (+0061)  0f b6 f7                                      movzx   esi, bh
    0x4200001a0e9c (+0064)  0f b6 d4                                      movzx   edx, ah
    0x4200001a0e9f (+0067)  39 f2                                         cmp     edx, esi
    0x4200001a0ea1 (+0069)  72 05                                         jb      0x4200001a0ea8
    0x4200001a0ea3 (+006b)  89 f2                                         mov     edx, esi
    0x4200001a0ea5 (+006d)  44 89 e0                                      mov     eax, r12d
    0x4200001a0ea8 (+0070)  0f b6 f5                                      movzx   esi, ch
    0x4200001a0eab (+0073)  39 d6                                         cmp     esi, edx
    0x4200001a0ead (+0075)  0f 46 c1                                      cmovbe  eax, ecx
    0x4200001a0eb0 (+0078)  89 45 00                                      mov     dword ptr [rbp], eax
    0x4200001a0eb3 (+007b)  48 83 c4 10                                   add     rsp, 0x10
    0x4200001a0eb7 (+007f)  31 c0                                         xor     eax, eax
    0x4200001a0eb9 (+0081)  5b                                            pop     rbx
    0x4200001a0eba (+0082)  5d                                            pop     rbp
    0x4200001a0ebb (+0083)  41 5c                                         pop     r12
    0x4200001a0ebd (+0085)  c3                                            ret
    0x4200001a0ebe (+0086)  48 8b 83 e8 00 00 00                          mov     rax, qword ptr [rbx + 0xe8]
    0x4200001a0ec5 (+008d)  48 85 c0                                      test    rax, rax
    0x4200001a0ec8 (+0090)  74 87                                         je      0x4200001a0e51
    0x4200001a0eca (+0092)  48 83 3d 46 4f f2 bf 01                       cmp     qword ptr [rip - 0x400db0ba], 1 ; configOption+0x1b8
    0x4200001a0ed2 (+009a)  44 8b 20                                      mov     r12d, dword ptr [rax]
    0x4200001a0ed5 (+009d)  75 ad                                         jne     0x4200001a0e84
    0x4200001a0ed7 (+009f)  eb b7                                         jmp     0x4200001a0e90
    0x4200001a0ed9 (+00a1)  48 89 df                                      mov     rdi, rbx
    0x4200001a0edc (+00a4)  e8 5b a5 f4 ff                                call    0x4200000eb43c ; directSymbol -> PCI_IsPCIeEndpointDevice
    0x4200001a0ee1 (+00a9)  80 7b 18 00                                   cmp     byte ptr [rbx + 0x18], 0
    0x4200001a0ee5 (+00ad)  78 04                                         js      0x4200001a0eeb
    0x4200001a0ee7 (+00af)  84 c0                                         test    al, al
    0x4200001a0ee9 (+00b1)  75 a5                                         jne     0x4200001a0e90
    0x4200001a0eeb (+00b3)  48 8b 9b e8 00 00 00                          mov     rbx, qword ptr [rbx + 0xe8]
    0x4200001a0ef2 (+00ba)  48 85 db                                      test    rbx, rbx
    0x4200001a0ef5 (+00bd)  0f 84 56 ff ff ff                             je      0x4200001a0e51
    0x4200001a0efb (+00c3)  eb 93                                         jmp     0x4200001a0e90
