; A04 IOMMU 覆盖条件
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / Hardware_PCIIsInIommuScope
; [0x4200000734b4, 0x42000007350e) file offset 0x3324b4
; window SHA256 6f0650815d0a677739d65cb08b29784ae2c4309bf24b779e7a3d2c8138bdeee5

    0x4200000734b4 (+0000)  41 54                                         push    r12
    0x4200000734b6 (+0002)  48 89 f7                                      mov     rdi, rsi
    0x4200000734b9 (+0005)  53                                            push    rbx
    0x4200000734ba (+0006)  48 89 d3                                      mov     rbx, rdx
    0x4200000734bd (+0009)  48 83 ec 18                                   sub     rsp, 0x18
    0x4200000734c1 (+000d)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x4200000734c6 (+0012)  e8 85 ea ff ff                                call    0x420000071f50 ; directSymbol -> Hardware_PCIGetDevFromInstArgs
    0x4200000734cb (+0017)  41 89 c4                                      mov     r12d, eax
    0x4200000734ce (+001a)  85 c0                                         test    eax, eax
    0x4200000734d0 (+001c)  74 0b                                         je      0x4200000734dd
    0x4200000734d2 (+001e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000734d6 (+0022)  44 89 e0                                      mov     eax, r12d
    0x4200000734d9 (+0025)  5b                                            pop     rbx
    0x4200000734da (+0026)  41 5c                                         pop     r12
    0x4200000734dc (+0028)  c3                                            ret
    0x4200000734dd (+0029)  e8 52 08 0f 00                                call    0x420000163d34 ; directSymbol -> IOMMU_IsIommuEnabled
    0x4200000734e2 (+002e)  41 89 c0                                      mov     r8d, eax
    0x4200000734e5 (+0031)  31 c0                                         xor     eax, eax
    0x4200000734e7 (+0033)  45 84 c0                                      test    r8b, r8b
    0x4200000734ea (+0036)  75 0d                                         jne     0x4200000734f9
    0x4200000734ec (+0038)  88 03                                         mov     byte ptr [rbx], al
    0x4200000734ee (+003a)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000734f2 (+003e)  44 89 e0                                      mov     eax, r12d
    0x4200000734f5 (+0041)  5b                                            pop     rbx
    0x4200000734f6 (+0042)  41 5c                                         pop     r12
    0x4200000734f8 (+0044)  c3                                            ret
    0x4200000734f9 (+0045)  48 8b 44 24 08                                mov     rax, qword ptr [rsp + 8]
    0x4200000734fe (+004a)  8b 38                                         mov     edi, dword ptr [rax]
    0x420000073500 (+004c)  e8 f3 20 0f 00                                call    0x4200001655f8 ; directSymbol -> IOMMU_IsDeviceSupported
    0x420000073505 (+0051)  84 c0                                         test    al, al
    0x420000073507 (+0053)  0f 95 c0                                      setne   al
    0x42000007350a (+0056)  88 03                                         mov     byte ptr [rbx], al
    0x42000007350c (+0058)  eb e0                                         jmp     0x4200000734ee
