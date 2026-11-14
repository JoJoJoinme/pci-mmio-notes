; R02 内存前提失败的返回
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDevice
; [0x9b18, 0x9b3c) file offset 0x9b58
; window SHA256 938449fb9f384ee915bc9ebbb36259051bf077084b5f6b9387ed3bb579bee4a2

            0x9b18 (+00c8)  31 c0                                         xor     eax, eax
            0x9b1a (+00ca)  be 28 15 00 00                                mov     esi, 0x1528
            0x9b1f (+00cf)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC108 A=-4 "PCIPassthru: %d: PCI Passthru requires pinnedMainMem and preallocGuestMem\n"
            0x9b26 (+00d6)  e8 00 00 00 00                                call    0x9b2b ; REL type=2 _Log A=-4
            0x9b2b (+00db)  b8 20 00 ad 0b                                mov     eax, 0xbad0020
            0x9b30 (+00e0)  48 83 c4 08                                   add     rsp, 8
            0x9b34 (+00e4)  5d                                            pop     rbp
            0x9b35 (+00e5)  41 5c                                         pop     r12
            0x9b37 (+00e7)  41 5d                                         pop     r13
            0x9b39 (+00e9)  41 5e                                         pop     r14
            0x9b3b (+00eb)  c3                                            ret
