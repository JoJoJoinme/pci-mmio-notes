; O12 禁用直通进入共同配置路径
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::SwitchOwnerToVmkernel
; [0x4c7f20, 0x4c7f93) file offset 0x4c7f20
; window SHA256 5452a9960bcf9e019aa517b247cd1262dd202fa0a91343f2cc8848f74435aab4

          0x4c7f20 (+0000)  55                                            push    rbp
          0x4c7f21 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c7f24 (+0004)  41 55                                         push    r13
          0x4c7f26 (+0006)  41 54                                         push    r12
          0x4c7f28 (+0008)  48 83 ec 10                                   sub     rsp, 0x10
          0x4c7f2c (+000c)  48 89 7d e8                                   mov     qword ptr [rbp - 0x18], rdi
          0x4c7f30 (+0010)  e8 5b 34 ec ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4c7f35 (+0015)  48 8b 7d e8                                   mov     rdi, qword ptr [rbp - 0x18]
          0x4c7f39 (+0019)  ff c8                                         dec     eax
          0x4c7f3b (+001b)  75 32                                         jne     0x4c7f6f
          0x4c7f3d (+001d)  bf 20 00 00 00                                mov     edi, 0x20
          0x4c7f42 (+0022)  e8 49 4b ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4c7f47 (+0027)  48 8d 35 8f dc 37 00                          lea     rsi, [rip + 0x37dc8f] ; literal "Device owner is already configured to vmkernel."
          0x4c7f4e (+002e)  48 89 c7                                      mov     rdi, rax
          0x4c7f51 (+0031)  49 89 c4                                      mov     r12, rax
          0x4c7f54 (+0034)  e8 07 5b eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4c7f59 (+0039)  48 8b 15 b0 d2 59 00                          mov     rdx, qword ptr [rip + 0x59d2b0] ; GOT -> Lib::HostCtlException
          0x4c7f60 (+0040)  48 8b 35 f9 ec 59 00                          mov     rsi, qword ptr [rip + 0x59ecf9] ; GOT -> _ZTIN7HostCtl3Lib16HostCtlExceptionE
          0x4c7f67 (+0047)  4c 89 e7                                      mov     rdi, r12
          0x4c7f6a (+004a)  e8 51 6d ec ff                                call    0x38ecc0 ; PLT -> __cxa_throw
          0x4c7f6f (+004f)  58                                            pop     rax
          0x4c7f70 (+0050)  be 01 00 00 00                                mov     esi, 1
          0x4c7f75 (+0055)  5a                                            pop     rdx
          0x4c7f76 (+0056)  41 5c                                         pop     r12
          0x4c7f78 (+0058)  41 5d                                         pop     r13
          0x4c7f7a (+005a)  5d                                            pop     rbp
          0x4c7f7b (+005b)  e9 50 bb ea ff                                jmp     0x373ad0 ; PLT -> PciDeviceImpl::SetConfiguredDeviceOwner; branch leaves this window
          0x4c7f80 (+0060)  49 89 c5                                      mov     r13, rax
          0x4c7f83 (+0063)  4c 89 e7                                      mov     rdi, r12
          0x4c7f86 (+0066)  e8 25 23 ec ff                                call    0x38a2b0 ; PLT -> __cxa_free_exception
          0x4c7f8b (+006b)  4c 89 ef                                      mov     rdi, r13
          0x4c7f8e (+006e)  e8 6d 8b eb ff                                call    0x380b00 ; PLT -> _Unwind_Resume
