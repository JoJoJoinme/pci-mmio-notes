; M05 D3D0 需要显式选择器
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_HasD3D0Reset
; [0x4200000fc074, 0x4200000fc0d7) file offset 0x3bb074
; window SHA256 a289ea18f3d3731722b3935fa4e0891bf5ecf4128704069190a40071f1cdd46b

    0x4200000fc074 (+0000)  53                                            push    rbx
    0x4200000fc075 (+0001)  48 89 fb                                      mov     rbx, rdi
    0x4200000fc078 (+0004)  48 83 ec 10                                   sub     rsp, 0x10
    0x4200000fc07c (+0008)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x4200000fc081 (+000d)  c7 44 24 08 00 00 00 00                       mov     dword ptr [rsp + 8], 0
    0x4200000fc089 (+0015)  e8 7a f6 fe ff                                call    0x4200000eb708 ; directSymbol -> PCI_GetResetMethod
    0x4200000fc08e (+001a)  31 c0                                         xor     eax, eax
    0x4200000fc090 (+001c)  83 7c 24 08 02                                cmp     dword ptr [rsp + 8], 2
    0x4200000fc095 (+0021)  74 06                                         je      0x4200000fc09d
    0x4200000fc097 (+0023)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc09b (+0027)  5b                                            pop     rbx
    0x4200000fc09c (+0028)  c3                                            ret
    0x4200000fc09d (+0029)  48 8d 54 24 07                                lea     rdx, [rsp + 7]
    0x4200000fc0a2 (+002e)  be 01 00 00 00                                mov     esi, 1
    0x4200000fc0a7 (+0033)  48 89 df                                      mov     rdi, rbx
    0x4200000fc0aa (+0036)  e8 2d 40 ff ff                                call    0x4200000f00dc ; directSymbol -> PCI_GetCapOffset
    0x4200000fc0af (+003b)  84 c0                                         test    al, al
    0x4200000fc0b1 (+003d)  74 e4                                         je      0x4200000fc097
    0x4200000fc0b3 (+003f)  0f b6 44 24 07                                movzx   eax, byte ptr [rsp + 7]
    0x4200000fc0b8 (+0044)  8b 3b                                         mov     edi, dword ptr [rbx]
    0x4200000fc0ba (+0046)  48 8d 4c 24 0c                                lea     rcx, [rsp + 0xc]
    0x4200000fc0bf (+004b)  ba 02 00 00 00                                mov     edx, 2
    0x4200000fc0c4 (+0050)  8d 70 04                                      lea     esi, [rax + 4]
    0x4200000fc0c7 (+0053)  e8 38 0e 00 00                                call    0x4200000fcf04 ; directSymbol -> PCIConfig_ReadSafe
    0x4200000fc0cc (+0058)  48 83 c4 10                                   add     rsp, 0x10
    0x4200000fc0d0 (+005c)  b8 01 00 00 00                                mov     eax, 1
    0x4200000fc0d5 (+0061)  5b                                            pop     rbx
    0x4200000fc0d6 (+0062)  c3                                            ret
