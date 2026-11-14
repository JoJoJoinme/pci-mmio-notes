; E05 目标网络设备查找与 owner 写入分叉
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 12c2763afe68a18b60fab4606859a9173cf26a09329989f3f76f389973777d4a

          0x4cc451 (+041f)  4c 89 f6                                      mov     rsi, r14
          0x4cc454 (+0422)  48 89 df                                      mov     rdi, rbx
          0x4cc457 (+0425)  e8 c4 40 eb ff                                call    0x380520 ; PLT -> PciDeviceImpl::GetVmKernelDeviceName
          0x4cc45c (+042a)  4c 8d ad 48 ff ff ff                          lea     r13, [rbp - 0xb8]
          0x4cc463 (+0431)  48 89 de                                      mov     rsi, rbx
          0x4cc466 (+0434)  4c 89 ef                                      mov     rdi, r13
          0x4cc469 (+0437)  e8 e2 6d eb ff                                call    0x383250 ; PLT -> _ZNKSt8_Rb_treeISsSt4pairIKSsSsESt10_Select1stIS2_ESt4lessISsESaIS2_EE4findERS1_
          0x4cc46e (+043c)  48 39 85 c0 fe ff ff                          cmp     qword ptr [rbp - 0x140], rax
          0x4cc475 (+0443)  75 44                                         jne     0x4cc4bb ; branch leaves this window
          0x4cc477 (+0445)  be 02 00 00 00                                mov     esi, 2
          0x4cc47c (+044a)  4c 89 f7                                      mov     rdi, r14
          0x4cc47f (+044d)  e8 4c 76 ea ff                                call    0x373ad0 ; PLT -> PciDeviceImpl::SetConfiguredDeviceOwner
