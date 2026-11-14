; R01 VM 内存前提与普通登记入口
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDevice
; [0x9a50, 0x9abb) file offset 0x9a90
; window SHA256 cd09024d0f467a61cea26f0a174572a379643f3e600e7182c64589dcf444b301

            0x9a50 (+0000)  41 56                                         push    r14
            0x9a52 (+0002)  49 89 fe                                      mov     r14, rdi
            0x9a55 (+0005)  41 55                                         push    r13
            0x9a57 (+0007)  41 54                                         push    r12
            0x9a59 (+0009)  49 89 d4                                      mov     r12, rdx
            0x9a5c (+000c)  55                                            push    rbp
            0x9a5d (+000d)  89 f5                                         mov     ebp, esi
            0x9a5f (+000f)  48 83 ec 08                                   sub     rsp, 8
            0x9a63 (+0013)  65 48 8b 3c 25 10 00 00 00                    mov     rdi, qword ptr gs:[0x10]
            0x9a6c (+001c)  e8 00 00 00 00                                call    0x9a71 ; REL type=2 MemSched_GetVmMemInfo A=-4
            0x9a71 (+0021)  80 78 02 00                                   cmp     byte ptr [rax + 2], 0
            0x9a75 (+0025)  0f 84 9d 00 00 00                             je      0x9b18 ; branch leaves this window
            0x9a7b (+002b)  65 48 8b 3c 25 10 00 00 00                    mov     rdi, qword ptr gs:[0x10]
            0x9a84 (+0034)  e8 00 00 00 00                                call    0x9a89 ; REL type=2 MemSched_GetVmMemInfo A=-4
            0x9a89 (+0039)  80 38 00                                      cmp     byte ptr [rax], 0
            0x9a8c (+003c)  0f 84 86 00 00 00                             je      0x9b18 ; branch leaves this window
            0x9a92 (+0042)  49 c7 c1 ff ff ff ff                          mov     r9, 0xffffffffffffffff
            0x9a99 (+0049)  4d 85 f6                                      test    r14, r14
            0x9a9c (+004c)  78 1d                                         js      0x9abb ; branch leaves this window
            0x9a9e (+004e)  48 83 c4 08                                   add     rsp, 8
            0x9aa2 (+0052)  4c 89 e2                                      mov     rdx, r12
            0x9aa5 (+0055)  89 ee                                         mov     esi, ebp
            0x9aa7 (+0057)  44 89 f7                                      mov     edi, r14d
            0x9aaa (+005a)  5d                                            pop     rbp
            0x9aab (+005b)  45 31 c0                                      xor     r8d, r8d
            0x9aae (+005e)  41 5c                                         pop     r12
            0x9ab0 (+0060)  31 c9                                         xor     ecx, ecx
            0x9ab2 (+0062)  41 5d                                         pop     r13
            0x9ab4 (+0064)  41 5e                                         pop     r14
            0x9ab6 (+0066)  e9 b1 b0 ff ff                                jmp     0x4b6c ; directSymbol -> PCIPassthruRegisterDeviceInt; branch leaves this window
