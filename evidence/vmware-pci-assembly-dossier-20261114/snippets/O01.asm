; O01 禁用状态的拒绝条件
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::ValidateOwnerToPassthru
; [0x4cbace, 0x4cbafa) file offset 0x4cbace
; window SHA256 845c8f84dacca29c6c35382646e050ed7a39b302676d94b5ac827ba132b427e9

          0x4cbace (+0022)  80 7f 77 00                                   cmp     byte ptr [rdi + 0x77], 0
          0x4cbad2 (+0026)  48 8d 43 18                                   lea     rax, [rbx + 0x18]
          0x4cbad6 (+002a)  48 89 85 78 ff ff ff                          mov     qword ptr [rbp - 0x88], rax
          0x4cbadd (+0031)  0f 84 d5 00 00 00                             je      0x4cbbb8 ; branch leaves this window
          0x4cbae3 (+0037)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbae7 (+003b)  48 8d 35 21 9d 37 00                          lea     rsi, [rip + 0x379d21] ; literal " for PCI passthrough when this feature is disabled."
          0x4cbaee (+0042)  e8 7d 66 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbaf3 (+0047)  4c 8d 75 80                                   lea     r14, [rbp - 0x80]
          0x4cbaf7 (+004b)  4c 89 e6                                      mov     rsi, r12
