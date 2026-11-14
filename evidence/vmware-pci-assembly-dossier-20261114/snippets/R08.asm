; R08 共同代表与同一 VM 的完整比较循环
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x4de9, 0x4ea2) file offset 0x4e29
; window SHA256 6ef505dcdd0f50a900a72f6bf23d47e4a2bb66912d52061befcc07ab7bedbfe1

            0x4de9 (+027d)  4c 8b 6c 24 10                                mov     r13, qword ptr [rsp + 0x10]
            0x4dee (+0282)  48 8d 74 24 64                                lea     rsi, [rsp + 0x64]
            0x4df3 (+0287)  4c 89 ef                                      mov     rdi, r13
            0x4df6 (+028a)  e8 00 00 00 00                                call    0x4dfb ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x4dfb (+028f)  8b 74 24 64                                   mov     esi, dword ptr [rsp + 0x64]
            0x4dff (+0293)  41 39 75 00                                   cmp     dword ptr [r13], esi
            0x4e03 (+0297)  0f 84 99 00 00 00                             je      0x4ea2 ; branch leaves this window
            0x4e09 (+029d)  e8 00 00 00 00                                call    0x4e0e ; REL type=2 PCI_GetFirstDevice A=-4
            0x4e0e (+02a2)  48 85 c0                                      test    rax, rax
            0x4e11 (+02a5)  0f 84 8b 00 00 00                             je      0x4ea2 ; branch leaves this window
            0x4e17 (+02ab)  4c 89 64 24 38                                mov     qword ptr [rsp + 0x38], r12
            0x4e1c (+02b0)  41 89 ed                                      mov     r13d, ebp
            0x4e1f (+02b3)  49 89 c4                                      mov     r12, rax
            0x4e22 (+02b6)  48 8b 6c 24 28                                mov     rbp, qword ptr [rsp + 0x28]
            0x4e27 (+02bb)  eb 10                                         jmp     0x4e39
            0x4e29 (+02bd)  4c 89 e7                                      mov     rdi, r12
            0x4e2c (+02c0)  e8 00 00 00 00                                call    0x4e31 ; REL type=2 PCI_GetNextDevice A=-4
            0x4e31 (+02c5)  49 89 c4                                      mov     r12, rax
            0x4e34 (+02c8)  48 85 c0                                      test    rax, rax
            0x4e37 (+02cb)  74 64                                         je      0x4e9d
            0x4e39 (+02cd)  48 8d 74 24 68                                lea     rsi, [rsp + 0x68]
            0x4e3e (+02d2)  4c 89 e7                                      mov     rdi, r12
            0x4e41 (+02d5)  e8 00 00 00 00                                call    0x4e46 ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x4e46 (+02da)  85 c0                                         test    eax, eax
            0x4e48 (+02dc)  75 df                                         jne     0x4e29
            0x4e4a (+02de)  8b 44 24 68                                   mov     eax, dword ptr [rsp + 0x68]
            0x4e4e (+02e2)  39 44 24 64                                   cmp     dword ptr [rsp + 0x64], eax
            0x4e52 (+02e6)  75 d5                                         jne     0x4e29
            0x4e54 (+02e8)  41 8b 34 24                                   mov     esi, dword ptr [r12]
            0x4e58 (+02ec)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 pcipDevTable A=-4
            0x4e5f (+02f3)  48 89 ea                                      mov     rdx, rbp
            0x4e62 (+02f6)  e8 00 00 00 00                                call    0x4e67 ; REL type=2 PCISbdfMap_Find A=-4
            0x4e67 (+02fb)  48 8b 44 24 70                                mov     rax, qword ptr [rsp + 0x70]
            0x4e6c (+0300)  48 85 c0                                      test    rax, rax
            0x4e6f (+0303)  74 b8                                         je      0x4e29
            0x4e71 (+0305)  48 8b 50 10                                   mov     rdx, qword ptr [rax + 0x10]
            0x4e75 (+0309)  48 85 d2                                      test    rdx, rdx
            0x4e78 (+030c)  74 af                                         je      0x4e29
            0x4e7a (+030e)  80 78 04 00                                   cmp     byte ptr [rax + 4], 0
            0x4e7e (+0312)  75 a9                                         jne     0x4e29
            0x4e80 (+0314)  44 3b 6a 70                                   cmp     r13d, dword ptr [rdx + 0x70]
            0x4e84 (+0318)  74 a3                                         je      0x4e29
            0x4e86 (+031a)  4c 8b 64 24 10                                mov     r12, qword ptr [rsp + 0x10]
            0x4e8b (+031f)  41 bd 04 00 ad 0b                             mov     r13d, 0xbad0004
            0x4e91 (+0325)  49 81 c4 08 01 00 00                          add     r12, 0x108
            0x4e98 (+032c)  e9 9c fe ff ff                                jmp     0x4d39 ; branch leaves this window
            0x4e9d (+0331)  4c 8b 64 24 38                                mov     r12, qword ptr [rsp + 0x38]
