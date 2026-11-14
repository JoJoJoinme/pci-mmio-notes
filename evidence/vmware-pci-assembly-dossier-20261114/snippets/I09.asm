; I09 子树回调前的节点资格过滤
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_CanDeviceBeAssignedToIOMMUDomain
; [0x4200000eb9b8, 0x4200000eb9f6) file offset 0x3aa9b8
; window SHA256 b73d8db19c5db9a399d30336bf7f3dd41a242550120c86f868d4cd769dd4d4ff

    0x4200000eb9b8 (+0000)  53                                            push    rbx
    0x4200000eb9b9 (+0001)  48 89 fb                                      mov     rbx, rdi
    0x4200000eb9bc (+0004)  8b 3f                                         mov     edi, dword ptr [rdi]
    0x4200000eb9be (+0006)  e8 f5 9c ff ff                                call    0x4200000e56b8 ; directSymbol -> PCIBridge_IsHostBridge
    0x4200000eb9c3 (+000b)  84 c0                                         test    al, al
    0x4200000eb9c5 (+000d)  75 1d                                         jne     0x4200000eb9e4
    0x4200000eb9c7 (+000f)  f6 43 04 02                                   test    byte ptr [rbx + 4], 2
    0x4200000eb9cb (+0013)  74 0c                                         je      0x4200000eb9d9
    0x4200000eb9cd (+0015)  48 89 df                                      mov     rdi, rbx
    0x4200000eb9d0 (+0018)  e8 63 97 ff ff                                call    0x4200000e5138 ; directSymbol -> PCIBridge_IsAliasing
    0x4200000eb9d5 (+001d)  84 c0                                         test    al, al
    0x4200000eb9d7 (+001f)  74 0b                                         je      0x4200000eb9e4
    0x4200000eb9d9 (+0021)  31 c0                                         xor     eax, eax
    0x4200000eb9db (+0023)  e8 54 aa f8 ff                                call    0x420000076434 ; directSymbol -> IOV_IsInitialized
    0x4200000eb9e0 (+0028)  84 c0                                         test    al, al
    0x4200000eb9e2 (+002a)  75 04                                         jne     0x4200000eb9e8
    0x4200000eb9e4 (+002c)  31 c0                                         xor     eax, eax
    0x4200000eb9e6 (+002e)  5b                                            pop     rbx
    0x4200000eb9e7 (+002f)  c3                                            ret
    0x4200000eb9e8 (+0030)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000eb9ea (+0032)  e8 09 9c 07 00                                call    0x4200001655f8 ; directSymbol -> IOMMU_IsDeviceSupported
    0x4200000eb9ef (+0037)  5b                                            pop     rbx
    0x4200000eb9f0 (+0038)  84 c0                                         test    al, al
    0x4200000eb9f2 (+003a)  0f 95 c0                                      setne   al
    0x4200000eb9f5 (+003d)  c3                                            ret
