; I06 普通 PCI 激活入口的登记及状态条件
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruEnablePCIDevice
; [0x7c40, 0x7cfc) file offset 0x7c80
; window SHA256 5939fdda343a8989e5abf6cde877e82fc51213297a67e46c2573cf000c6ffd5e

            0x7c40 (+0000)  41 57                                         push    r15
            0x7c42 (+0002)  41 56                                         push    r14
            0x7c44 (+0004)  41 55                                         push    r13
            0x7c46 (+0006)  41 54                                         push    r12
            0x7c48 (+0008)  55                                            push    rbp
            0x7c49 (+0009)  53                                            push    rbx
            0x7c4a (+000a)  48 89 fb                                      mov     rbx, rdi
            0x7c4d (+000d)  48 83 ec 28                                   sub     rsp, 0x28
            0x7c51 (+0011)  48 85 ff                                      test    rdi, rdi
            0x7c54 (+0014)  0f 88 f1 00 00 00                             js      0x7d4b ; branch leaves this window
            0x7c5a (+001a)  65 48 8b 04 25 10 00 00 00                    mov     rax, qword ptr gs:[0x10]
            0x7c63 (+0023)  48 8b 80 98 1a 00 00                          mov     rax, qword ptr [rax + 0x1a98]
            0x7c6a (+002a)  89 fd                                         mov     ebp, edi
            0x7c6c (+002c)  41 bd 01 00 ad 0b                             mov     r13d, 0xbad0001
            0x7c72 (+0032)  4c 8b a0 f0 26 00 00                          mov     r12, qword ptr [rax + 0x26f0]
            0x7c79 (+0039)  4d 85 e4                                      test    r12, r12
            0x7c7c (+003c)  74 7e                                         je      0x7cfc ; branch leaves this window
            0x7c7e (+003e)  48 8d 35 00 00 00 00                          lea     rsi, [rip]
            0x7c85 (+0045)  4d 8d b4 24 78 02 00 00                       lea     r14, [r12 + 0x278]
            0x7c8d (+004d)  4c 89 f7                                      mov     rdi, r14
            0x7c90 (+0050)  e8 00 00 00 00                                call    0x7c95 ; REL type=2 Mutex_LockWithRA A=-4
            0x7c95 (+0055)  49 8b 84 24 a0 02 00 00                       mov     rax, qword ptr [r12 + 0x2a0]
            0x7c9d (+005d)  49 8d 8c 24 98 02 00 00                       lea     rcx, [r12 + 0x298]
            0x7ca5 (+0065)  48 39 c8                                      cmp     rax, rcx
            0x7ca8 (+0068)  75 12                                         jne     0x7cbc
            0x7caa (+006a)  e9 46 02 00 00                                jmp     0x7ef5 ; branch leaves this window
            0x7caf (+006f)  48 8b 40 08                                   mov     rax, qword ptr [rax + 8]
            0x7cb3 (+0073)  48 39 c8                                      cmp     rax, rcx
            0x7cb6 (+0076)  0f 84 39 02 00 00                             je      0x7ef5 ; branch leaves this window
            0x7cbc (+007c)  3b 68 10                                      cmp     ebp, dword ptr [rax + 0x10]
            0x7cbf (+007f)  75 ee                                         jne     0x7caf
            0x7cc1 (+0081)  80 b8 86 00 00 00 00                          cmp     byte ptr [rax + 0x86], 0
            0x7cc8 (+0088)  0f 85 b7 01 00 00                             jne     0x7e85 ; branch leaves this window
            0x7cce (+008e)  48 83 78 18 ff                                cmp     qword ptr [rax + 0x18], -1
            0x7cd3 (+0093)  75 39                                         jne     0x7d0e ; branch leaves this window
            0x7cd5 (+0095)  49 8b 6c 24 08                                mov     rbp, qword ptr [r12 + 8]
            0x7cda (+009a)  45 31 ed                                      xor     r13d, r13d
            0x7cdd (+009d)  48 85 ed                                      test    rbp, rbp
            0x7ce0 (+00a0)  74 12                                         je      0x7cf4
            0x7ce2 (+00a2)  48 8b 80 00 02 00 00                          mov     rax, qword ptr [rax + 0x200]
            0x7ce9 (+00a9)  48 83 78 18 00                                cmp     qword ptr [rax + 0x18], 0
            0x7cee (+00ae)  0f 84 bc 01 00 00                             je      0x7eb0 ; branch leaves this window
            0x7cf4 (+00b4)  4c 89 f7                                      mov     rdi, r14
            0x7cf7 (+00b7)  e8 00 00 00 00                                call    0x7cfc ; REL type=2 Mutex_Unlock A=-4
