; A01 完整 capable 谓词
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::IsPassthruCapable
; [0x4c2438, 0x4c24e6) file offset 0x4c2438
; window SHA256 9a4ff2c07205b2267b41f3510776b3f1d58d790b3d31ba51d8078a8be91e24dc

          0x4c2438 (+0000)  80 7f 77 00                                   cmp     byte ptr [rdi + 0x77], 0
          0x4c243c (+0004)  0f 85 a1 00 00 00                             jne     0x4c24e3
          0x4c2442 (+000a)  55                                            push    rbp
          0x4c2443 (+000b)  ba 01 00 00 00                                mov     edx, 1
          0x4c2448 (+0010)  48 89 e5                                      mov     rbp, rsp
          0x4c244b (+0013)  53                                            push    rbx
          0x4c244c (+0014)  48 89 fb                                      mov     rbx, rdi
          0x4c244f (+0017)  48 8d 75 de                                   lea     rsi, [rbp - 0x22]
          0x4c2453 (+001b)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c2457 (+001f)  48 8b 05 6a 49 5a 00                          mov     rax, qword ptr [rip + 0x5a496a] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_inIommuScope
          0x4c245e (+0026)  48 8b 4f 48                                   mov     rcx, qword ptr [rdi + 0x48]
          0x4c2462 (+002a)  c6 45 de 00                                   mov     byte ptr [rbp - 0x22], 0
          0x4c2466 (+002e)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c2469 (+0031)  e8 22 ef eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c246e (+0036)  80 7d de 00                                   cmp     byte ptr [rbp - 0x22], 0
          0x4c2472 (+003a)  75 04                                         jne     0x4c2478
          0x4c2474 (+003c)  31 c0                                         xor     eax, eax
          0x4c2476 (+003e)  eb 64                                         jmp     0x4c24dc
          0x4c2478 (+0040)  48 8b 05 29 4e 5a 00                          mov     rax, qword ptr [rip + 0x5a4e29] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_meetsPassthruAcsReq
          0x4c247f (+0047)  48 8b 4b 48                                   mov     rcx, qword ptr [rbx + 0x48]
          0x4c2483 (+004b)  48 8d 75 df                                   lea     rsi, [rbp - 0x21]
          0x4c2487 (+004f)  ba 01 00 00 00                                mov     edx, 1
          0x4c248c (+0054)  c6 45 df 00                                   mov     byte ptr [rbp - 0x21], 0
          0x4c2490 (+0058)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c2493 (+005b)  e8 f8 ee eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c2498 (+0060)  80 7d df 00                                   cmp     byte ptr [rbp - 0x21], 0
          0x4c249c (+0064)  74 d6                                         je      0x4c2474
          0x4c249e (+0066)  48 8b 05 93 32 5a 00                          mov     rax, qword ptr [rip + 0x5a3293] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_passthruDependent
          0x4c24a5 (+006d)  48 8b 4b 48                                   mov     rcx, qword ptr [rbx + 0x48]
          0x4c24a9 (+0071)  48 8d 75 e0                                   lea     rsi, [rbp - 0x20]
          0x4c24ad (+0075)  ba 10 00 00 00                                mov     edx, 0x10
          0x4c24b2 (+007a)  48 c7 45 e0 ff ff ff ff                       mov     qword ptr [rbp - 0x20], 0xffffffffffffffff
          0x4c24ba (+0082)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c24bd (+0085)  48 c7 45 e8 ff ff ff ff                       mov     qword ptr [rbp - 0x18], 0xffffffffffffffff
          0x4c24c5 (+008d)  e8 c6 ee eb ff                                call    0x381390 ; PLT -> SysinfoUtil::SysinfoGet
          0x4c24ca (+0092)  48 8b 7d e0                                   mov     rdi, qword ptr [rbp - 0x20]
          0x4c24ce (+0096)  48 8b 75 e8                                   mov     rsi, qword ptr [rbp - 0x18]
          0x4c24d2 (+009a)  e8 b9 f4 ff ff                                call    0x4c1990
          0x4c24d7 (+009f)  84 c0                                         test    al, al
          0x4c24d9 (+00a1)  0f 94 c0                                      sete    al
          0x4c24dc (+00a4)  48 83 c4 28                                   add     rsp, 0x28
          0x4c24e0 (+00a8)  5b                                            pop     rbx
          0x4c24e1 (+00a9)  5d                                            pop     rbp
          0x4c24e2 (+00aa)  c3                                            ret
          0x4c24e3 (+00ab)  31 c0                                         xor     eax, eax
          0x4c24e5 (+00ad)  c3                                            ret
