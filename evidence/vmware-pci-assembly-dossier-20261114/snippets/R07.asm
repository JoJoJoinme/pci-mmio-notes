; R07 按 SBDF 取记录和当前 owner 标识
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x4c7d, 0x4cda) file offset 0x4cbd
; window SHA256 ffd7f5fcfe27a241e1d00c1f74683cfe7e8eb145347ef847d0ca11896a639ef1

            0x4c7d (+0111)  48 8b 44 24 10                                mov     rax, qword ptr [rsp + 0x10]
            0x4c82 (+0116)  48 8b 54 24 28                                mov     rdx, qword ptr [rsp + 0x28]
            0x4c87 (+011b)  48 c7 44 24 70 00 00 00 00                    mov     qword ptr [rsp + 0x70], 0
            0x4c90 (+0124)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 pcipDevTable A=-4
            0x4c97 (+012b)  44 8b 28                                      mov     r13d, dword ptr [rax]
            0x4c9a (+012e)  49 8b 86 98 1a 00 00                          mov     rax, qword ptr [r14 + 0x1a98]
            0x4ca1 (+0135)  44 89 ee                                      mov     esi, r13d
            0x4ca4 (+0138)  8b 68 08                                      mov     ebp, dword ptr [rax + 8]
            0x4ca7 (+013b)  e8 00 00 00 00                                call    0x4cac ; REL type=2 PCISbdfMap_Find A=-4
            0x4cac (+0140)  84 c0                                         test    al, al
            0x4cae (+0142)  0f 84 cd 00 00 00                             je      0x4d81 ; branch leaves this window
            0x4cb4 (+0148)  41 80 7c 24 03 00                             cmp     byte ptr [r12 + 3], 0
            0x4cba (+014e)  0f 84 a4 06 00 00                             je      0x5364 ; branch leaves this window
            0x4cc0 (+0154)  48 8b 44 24 70                                mov     rax, qword ptr [rsp + 0x70]
            0x4cc5 (+0159)  4c 8b 68 10                                   mov     r13, qword ptr [rax + 0x10]
            0x4cc9 (+015d)  4d 85 ed                                      test    r13, r13
            0x4ccc (+0160)  0f 84 07 01 00 00                             je      0x4dd9 ; branch leaves this window
            0x4cd2 (+0166)  41 80 7c 24 04 00                             cmp     byte ptr [r12 + 4], 0
            0x4cd8 (+016c)  74 2c                                         je      0x4d06 ; branch leaves this window
