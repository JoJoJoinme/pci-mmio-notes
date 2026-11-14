; R03 IOMMU 与模式回调前置检查
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x4b6c, 0x4c52) file offset 0x4bac
; window SHA256 c1fe02ace603ab267926f4b270d34b68134302b5f7344a506abe4a6839ef199a

            0x4b6c (+0000)  41 57                                         push    r15
            0x4b6e (+0002)  41 56                                         push    r14
            0x4b70 (+0004)  41 55                                         push    r13
            0x4b72 (+0006)  41 bd 20 00 ad 0b                             mov     r13d, 0xbad0020
            0x4b78 (+000c)  41 54                                         push    r12
            0x4b7a (+000e)  55                                            push    rbp
            0x4b7b (+000f)  53                                            push    rbx
            0x4b7c (+0010)  48 81 ec 88 00 00 00                          sub     rsp, 0x88
            0x4b83 (+0017)  48 89 4c 24 18                                mov     qword ptr [rsp + 0x18], rcx
            0x4b88 (+001c)  44 89 04 24                                   mov     dword ptr [rsp], r8d
            0x4b8c (+0020)  4c 89 4c 24 08                                mov     qword ptr [rsp + 8], r9
            0x4b91 (+0025)  65 4c 8b 34 25 10 00 00 00                    mov     r14, qword ptr gs:[0x10]
            0x4b9a (+002e)  83 fe 04                                      cmp     esi, 4
            0x4b9d (+0031)  0f 87 c9 01 00 00                             ja      0x4d6c ; branch leaves this window
            0x4ba3 (+0037)  89 fb                                         mov     ebx, edi
            0x4ba5 (+0039)  41 89 f7                                      mov     r15d, esi
            0x4ba8 (+003c)  49 89 d4                                      mov     r12, rdx
            0x4bab (+003f)  e8 00 00 00 00                                call    0x4bb0 ; REL type=2 IOMMU_IsIommuEnabled A=-4
            0x4bb0 (+0044)  84 c0                                         test    al, al
            0x4bb2 (+0046)  0f 84 15 07 00 00                             je      0x52cd ; branch leaves this window
            0x4bb8 (+004c)  89 df                                         mov     edi, ebx
            0x4bba (+004e)  e8 00 00 00 00                                call    0x4bbf ; REL type=2 PCI_GetDevice A=-4
            0x4bbf (+0053)  48 89 44 24 10                                mov     qword ptr [rsp + 0x10], rax
            0x4bc4 (+0058)  48 85 c0                                      test    rax, rax
            0x4bc7 (+005b)  0f 84 c8 01 00 00                             je      0x4d95 ; branch leaves this window
            0x4bcd (+0061)  89 df                                         mov     edi, ebx
            0x4bcf (+0063)  e8 00 00 00 00                                call    0x4bd4 ; REL type=2 IOMMU_IsDeviceSupported A=-4
            0x4bd4 (+0068)  84 c0                                         test    al, al
            0x4bd6 (+006a)  0f 84 c9 08 00 00                             je      0x54a5 ; branch leaves this window
            0x4bdc (+0070)  49 8b 86 98 1a 00 00                          mov     rax, qword ptr [r14 + 0x1a98]
            0x4be3 (+0077)  48 8b 80 f0 26 00 00                          mov     rax, qword ptr [rax + 0x26f0]
            0x4bea (+007e)  48 89 44 24 20                                mov     qword ptr [rsp + 0x20], rax
            0x4bef (+0083)  48 85 c0                                      test    rax, rax
            0x4bf2 (+0086)  74 13                                         je      0x4c07
            0x4bf4 (+0088)  48 8d 35 00 00 00 00                          lea     rsi, [rip]
            0x4bfb (+008f)  48 8d b8 78 02 00 00                          lea     rdi, [rax + 0x278]
            0x4c02 (+0096)  e8 00 00 00 00                                call    0x4c07 ; REL type=2 Mutex_LockWithRA A=-4
            0x4c07 (+009b)  44 89 f9                                      mov     ecx, r15d
            0x4c0a (+009e)  48 8d 15 00 00 00 00                          lea     rdx, [rip] ; REL type=2 section#8 A=156
            0x4c11 (+00a5)  48 8d 04 cd 00 00 00 00                       lea     rax, [rcx*8]
            0x4c19 (+00ad)  48 89 4c 24 30                                mov     qword ptr [rsp + 0x30], rcx
            0x4c1e (+00b2)  48 29 c8                                      sub     rax, rcx
            0x4c21 (+00b5)  48 8b 04 c2                                   mov     rax, qword ptr [rdx + rax*8]
            0x4c25 (+00b9)  48 85 c0                                      test    rax, rax
            0x4c28 (+00bc)  74 15                                         je      0x4c3f
            0x4c2a (+00be)  4c 89 e2                                      mov     rdx, r12
            0x4c2d (+00c1)  89 de                                         mov     esi, ebx
            0x4c2f (+00c3)  4c 89 f7                                      mov     rdi, r14
            0x4c32 (+00c6)  ff d0                                         call    rax
            0x4c34 (+00c8)  41 89 c5                                      mov     r13d, eax
            0x4c37 (+00cb)  85 c0                                         test    eax, eax
            0x4c39 (+00cd)  0f 85 1c 01 00 00                             jne     0x4d5b ; branch leaves this window
            0x4c3f (+00d3)  48 8d 05 00 00 00 00                          lea     rax, [rip]
            0x4c46 (+00da)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x4c4d (+00e1)  e8 00 00 00 00                                call    0x4c52 ; REL type=2 SPLockWork A=-4
