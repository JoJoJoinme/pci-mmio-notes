; O05 管理库取得依赖代表对象
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::GetDependantDevice
; [0x4c7142, 0x4c71af) file offset 0x4c7142
; window SHA256 6d5f39abb8acfa24a7220577b9932354e1f33f4b006b85aa063cf41813ed9085

          0x4c7142 (+0000)  55                                            push    rbp
          0x4c7143 (+0001)  ba 10 00 00 00                                mov     edx, 0x10
          0x4c7148 (+0006)  48 89 e5                                      mov     rbp, rsp
          0x4c714b (+0009)  41 54                                         push    r12
          0x4c714d (+000b)  49 89 fc                                      mov     r12, rdi
          0x4c7150 (+000e)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c7154 (+0012)  48 8b 05 dd e5 59 00                          mov     rax, qword ptr [rip + 0x59e5dd] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_passthruDependent
          0x4c715b (+0019)  48 8b 4e 48                                   mov     rcx, qword ptr [rsi + 0x48]
          0x4c715f (+001d)  48 8d 75 e0                                   lea     rsi, [rbp - 0x20]
          0x4c7163 (+0021)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c7166 (+0024)  e8 25 a2 eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c716b (+0029)  48 8b 7d e0                                   mov     rdi, qword ptr [rbp - 0x20]
          0x4c716f (+002d)  48 8b 75 e8                                   mov     rsi, qword ptr [rbp - 0x18]
          0x4c7173 (+0031)  e8 18 a8 ff ff                                call    0x4c1990
          0x4c7178 (+0036)  84 c0                                         test    al, al
          0x4c717a (+0038)  74 0a                                         je      0x4c7186
          0x4c717c (+003a)  49 c7 04 24 00 00 00 00                       mov     qword ptr [r12], 0
          0x4c7184 (+0042)  eb 1e                                         jmp     0x4c71a4
          0x4c7186 (+0044)  44 8a 45 ec                                   mov     r8b, byte ptr [rbp - 0x14]
          0x4c718a (+0048)  8a 4d e8                                      mov     cl, byte ptr [rbp - 0x18]
          0x4c718d (+004b)  48 8d 7d d8                                   lea     rdi, [rbp - 0x28]
          0x4c7191 (+004f)  8a 55 e4                                      mov     dl, byte ptr [rbp - 0x1c]
          0x4c7194 (+0052)  8b 75 e0                                      mov     esi, dword ptr [rbp - 0x20]
          0x4c7197 (+0055)  e8 c5 fe ff ff                                call    0x4c7061
          0x4c719c (+005a)  48 8b 45 d8                                   mov     rax, qword ptr [rbp - 0x28]
          0x4c71a0 (+005e)  49 89 04 24                                   mov     qword ptr [r12], rax
          0x4c71a4 (+0062)  48 83 c4 28                                   add     rsp, 0x28
          0x4c71a8 (+0066)  4c 89 e0                                      mov     rax, r12
          0x4c71ab (+0069)  41 5c                                         pop     r12
          0x4c71ad (+006b)  5d                                            pop     rbp
          0x4c71ae (+006c)  c3                                            ret
