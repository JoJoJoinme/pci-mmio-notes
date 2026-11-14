; O07 配置依赖成员的主循环
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::SetConfiguredDeviceOwner
; [0x4c7b72, 0x4c7c71) file offset 0x4c7b72
; window SHA256 a1c5a143953e1bf6233068c07625cb7a7fa739147f9225fd8c97a6eaf3a35ebc

          0x4c7b72 (+02d2)  48 8b b5 70 ff ff ff                          mov     rsi, qword ptr [rbp - 0x90]
          0x4c7b79 (+02d9)  4c 8d 7d 88                                   lea     r15, [rbp - 0x78]
          0x4c7b7d (+02dd)  4c 89 ff                                      mov     rdi, r15
          0x4c7b80 (+02e0)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4c7b83 (+02e3)  ff 90 e0 00 00 00                             call    qword ptr [rax + 0xe0]
          0x4c7b89 (+02e9)  4c 89 e6                                      mov     rsi, r12
          0x4c7b8c (+02ec)  4c 89 ff                                      mov     rdi, r15
          0x4c7b8f (+02ef)  e8 ec 1d eb ff                                call    0x379980 ; PLT -> _ZSteqIcEN9__gnu_cxx11__enable_ifIXsrSt9__is_charIT_E7__valueEbE6__typeERKSbIS3_St11char_traitsIS3_ESaIS3_EESC_
          0x4c7b94 (+02f4)  4c 89 ff                                      mov     rdi, r15
          0x4c7b97 (+02f7)  89 c3                                         mov     ebx, eax
          0x4c7b99 (+02f9)  e8 c2 cc ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c7b9e (+02fe)  4c 89 e7                                      mov     rdi, r12
          0x4c7ba1 (+0301)  e8 ba cc ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c7ba6 (+0306)  84 db                                         test    bl, bl
          0x4c7ba8 (+0308)  0f 85 8d 00 00 00                             jne     0x4c7c3b
          0x4c7bae (+030e)  48 8b b5 70 ff ff ff                          mov     rsi, qword ptr [rbp - 0x90]
          0x4c7bb5 (+0315)  48 8d 45 a0                                   lea     rax, [rbp - 0x60]
          0x4c7bb9 (+0319)  48 89 85 50 ff ff ff                          mov     qword ptr [rbp - 0xb0], rax
          0x4c7bc0 (+0320)  48 8b bd 50 ff ff ff                          mov     rdi, qword ptr [rbp - 0xb0]
          0x4c7bc7 (+0327)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4c7bca (+032a)  ff 90 60 01 00 00                             call    qword ptr [rax + 0x160]
          0x4c7bd0 (+0330)  48 c7 45 b8 00 00 00 00                       mov     qword ptr [rbp - 0x48], 0
          0x4c7bd8 (+0338)  48 8b 5d a0                                   mov     rbx, qword ptr [rbp - 0x60]
          0x4c7bdc (+033c)  48 c7 45 c0 00 00 00 00                       mov     qword ptr [rbp - 0x40], 0
          0x4c7be4 (+0344)  48 c7 45 c8 00 00 00 00                       mov     qword ptr [rbp - 0x38], 0
          0x4c7bec (+034c)  48 3b 5d a8                                   cmp     rbx, qword ptr [rbp - 0x58]
          0x4c7bf0 (+0350)  74 33                                         je      0x4c7c25
          0x4c7bf2 (+0352)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7bf5 (+0355)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7bf8 (+0358)  ff 90 38 01 00 00                             call    qword ptr [rax + 0x138]
          0x4c7bfe (+035e)  41 39 c6                                      cmp     r14d, eax
          0x4c7c01 (+0361)  75 11                                         jne     0x4c7c14
          0x4c7c03 (+0363)  48 89 de                                      mov     rsi, rbx
          0x4c7c06 (+0366)  4c 89 e7                                      mov     rdi, r12
          0x4c7c09 (+0369)  e8 92 43 ec ff                                call    0x38bfa0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EE12emplace_backIJS6_EEERS6_DpOT_
          0x4c7c0e (+036e)  48 83 c3 08                                   add     rbx, 8
          0x4c7c12 (+0372)  eb d8                                         jmp     0x4c7bec
          0x4c7c14 (+0374)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7c17 (+0377)  44 89 f6                                      mov     esi, r14d
          0x4c7c1a (+037a)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7c1d (+037d)  ff 90 48 01 00 00                             call    qword ptr [rax + 0x148]
          0x4c7c23 (+0383)  eb de                                         jmp     0x4c7c03
          0x4c7c25 (+0385)  4c 89 e7                                      mov     rdi, r12
          0x4c7c28 (+0388)  e8 b3 22 eb ff                                call    0x379ee0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EED1Ev
          0x4c7c2d (+038d)  48 8b bd 50 ff ff ff                          mov     rdi, qword ptr [rbp - 0xb0]
          0x4c7c34 (+0394)  e8 a7 22 eb ff                                call    0x379ee0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EED1Ev
          0x4c7c39 (+0399)  eb 18                                         jmp     0x4c7c53
          0x4c7c3b (+039b)  4c 89 ef                                      mov     rdi, r13
          0x4c7c3e (+039e)  e8 4d 37 ec ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4c7c43 (+03a3)  41 39 c6                                      cmp     r14d, eax
          0x4c7c46 (+03a6)  74 0b                                         je      0x4c7c53
          0x4c7c48 (+03a8)  44 89 f6                                      mov     esi, r14d
          0x4c7c4b (+03ab)  4c 89 ef                                      mov     rdi, r13
          0x4c7c4e (+03ae)  e8 2d 26 ec ff                                call    0x38a280 ; PLT -> PciDeviceImpl::SetConfiguredDevOwnerNoDeps
          0x4c7c53 (+03b3)  48 8b bd 58 ff ff ff                          mov     rdi, qword ptr [rbp - 0xa8]
          0x4c7c5a (+03ba)  e8 b1 a2 ea ff                                call    0x371f10 ; PLT -> _ZNSt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS2_EED1Ev
          0x4c7c5f (+03bf)  48 81 c4 88 00 00 00                          add     rsp, 0x88
          0x4c7c66 (+03c6)  5b                                            pop     rbx
          0x4c7c67 (+03c7)  41 5c                                         pop     r12
          0x4c7c69 (+03c9)  41 5d                                         pop     r13
          0x4c7c6b (+03cb)  41 5e                                         pop     r14
          0x4c7c6d (+03cd)  41 5f                                         pop     r15
          0x4c7c6f (+03cf)  5d                                            pop     rbp
          0x4c7c70 (+03d0)  c3                                            ret
