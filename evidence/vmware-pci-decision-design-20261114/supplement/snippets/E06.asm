; E06 vSwitch 和 uplink 占用拒绝文字
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 3aef6acea4303a40155f35fe4cef76f46cd18f0588e1157e092b438441e216f6

          0x4cc4bb (+0489)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc4c0 (+048e)  e8 cb 05 ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc4c5 (+0493)  48 8d bd 78 ff ff ff                          lea     rdi, [rbp - 0x88]
          0x4cc4cc (+049a)  48 8d 35 15 9b 37 00                          lea     rsi, [rip + 0x379b15] ; literal " for uplink "
          0x4cc4d3 (+04a1)  49 89 c4                                      mov     r12, rax
          0x4cc4d6 (+04a4)  48 8b 85 e8 fe ff ff                          mov     rax, qword ptr [rbp - 0x118]
          0x4cc4dd (+04ab)  48 89 85 c0 fe ff ff                          mov     qword ptr [rbp - 0x140], rax
          0x4cc4e4 (+04b2)  48 8b 40 e8                                   mov     rax, qword ptr [rax - 0x18]
          0x4cc4e8 (+04b6)  48 89 85 c8 fe ff ff                          mov     qword ptr [rbp - 0x138], rax
          0x4cc4ef (+04bd)  e8 7c 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cc4f4 (+04c2)  48 89 de                                      mov     rsi, rbx
          0x4cc4f7 (+04c5)  4c 89 ef                                      mov     rdi, r13
          0x4cc4fa (+04c8)  e8 11 92 ea ff                                call    0x375710 ; PLT -> _ZNSt3mapISsSsSt4lessISsESaISt4pairIKSsSsEEEixERS3_
          0x4cc4ff (+04cd)  48 8b 08                                      mov     rcx, qword ptr [rax]
          0x4cc502 (+04d0)  48 8b bd d8 fe ff ff                          mov     rdi, qword ptr [rbp - 0x128]
          0x4cc509 (+04d7)  48 8d 35 e5 9a 37 00                          lea     rsi, [rip + 0x379ae5] ; literal " as it is used by vswitch "
          0x4cc510 (+04de)  4c 8d ad f0 fe ff ff                          lea     r13, [rbp - 0x110]
          0x4cc517 (+04e5)  48 8b 51 e8                                   mov     rdx, qword ptr [rcx - 0x18]
          0x4cc51b (+04e9)  48 89 8d a0 fe ff ff                          mov     qword ptr [rbp - 0x160], rcx
          0x4cc522 (+04f0)  48 89 95 a8 fe ff ff                          mov     qword ptr [rbp - 0x158], rdx
          0x4cc529 (+04f7)  e8 42 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cc52e (+04fc)  48 8d 35 db 9a 37 00                          lea     rsi, [rip + 0x379adb] ; literal "Device ownership cannot be changed to passthru"
          0x4cc535 (+0503)  4c 89 ff                                      mov     rdi, r15
          0x4cc538 (+0506)  e8 33 5c ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
