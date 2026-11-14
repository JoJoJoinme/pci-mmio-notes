; R06 宿主身份与非零 VID DID 条件
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruFPTAllowPassthru
; [0x263e, 0x269b) file offset 0x267e
; window SHA256 70b8ba448bd4ff18c7de689bd38a6dd5cb45c6ee6f57fad5c80255db1f77af52

            0x263e (+00f6)  48 8d 4d 08                                   lea     rcx, [rbp + 8]
            0x2642 (+00fa)  31 c0                                         xor     eax, eax
            0x2644 (+00fc)  ba 42 00 00 00                                mov     edx, 0x42
            0x2649 (+0101)  48 8d 35 00 00 00 00                          lea     rsi, [rip] ; REL type=2 .LC17 A=-4 "BYPASS"
            0x2650 (+0108)  eb 04                                         jmp     0x2656
            0x2652 (+010a)  0f b6 14 06                                   movzx   edx, byte ptr [rsi + rax]
            0x2656 (+010e)  38 54 05 08                                   cmp     byte ptr [rbp + rax + 8], dl
            0x265a (+0112)  0f 85 97 00 00 00                             jne     0x26f7 ; branch leaves this window
            0x2660 (+0118)  84 d2                                         test    dl, dl
            0x2662 (+011a)  74 0a                                         je      0x266e
            0x2664 (+011c)  48 83 c0 01                                   add     rax, 1
            0x2668 (+0120)  48 83 f8 06                                   cmp     rax, 6
            0x266c (+0124)  75 e4                                         jne     0x2652
            0x266e (+0126)  0f b7 45 2e                                   movzx   eax, word ptr [rbp + 0x2e]
            0x2672 (+012a)  66 41 39 44 24 0e                             cmp     word ptr [r12 + 0xe], ax
            0x2678 (+0130)  74 09                                         je      0x2683
            0x267a (+0132)  66 85 c0                                      test    ax, ax
            0x267d (+0135)  0f 85 a0 00 00 00                             jne     0x2723 ; branch leaves this window
            0x2683 (+013b)  0f b7 45 30                                   movzx   eax, word ptr [rbp + 0x30]
            0x2687 (+013f)  66 41 39 44 24 0c                             cmp     word ptr [r12 + 0xc], ax
            0x268d (+0145)  74 0c                                         je      0x269b ; branch leaves this window
            0x268f (+0147)  66 85 c0                                      test    ax, ax
            0x2692 (+014a)  b8 07 00 ad 0b                                mov     eax, 0xbad0007
            0x2697 (+014f)  44 0f 45 e8                                   cmovne  r13d, eax
