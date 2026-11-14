; O13 禁用前的 VM 使用检查
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::ValidateOwnerToVmkernel
; [0x4c35d8, 0x4c361d) file offset 0x4c35d8
; window SHA256 c5abdc34b546800476254f2d7cc1588fcc78655ad6e3a1a08763ee684fadb714

          0x4c35d8 (+0000)  55                                            push    rbp
          0x4c35d9 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c35dc (+0004)  41 56                                         push    r14
          0x4c35de (+0006)  41 55                                         push    r13
          0x4c35e0 (+0008)  41 54                                         push    r12
          0x4c35e2 (+000a)  49 89 fc                                      mov     r12, rdi
          0x4c35e5 (+000d)  48 83 ec 48                                   sub     rsp, 0x48
          0x4c35e9 (+0011)  e8 42 2e eb ff                                call    0x376430 ; PLT -> PciDeviceImpl::IsInPassthruUseByVM
          0x4c35ee (+0016)  84 c0                                         test    al, al
          0x4c35f0 (+0018)  0f 84 cf 00 00 00                             je      0x4c36c5 ; branch leaves this window
          0x4c35f6 (+001e)  48 8d 7d d0                                   lea     rdi, [rbp - 0x30]
          0x4c35fa (+0022)  48 8d 35 20 20 38 00                          lea     rsi, [rip + 0x382020] ; literal " is in use by a VM in passthru mode"
          0x4c3601 (+0029)  e8 6a eb ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4c3606 (+002e)  4c 8d 75 b8                                   lea     r14, [rbp - 0x48]
          0x4c360a (+0032)  4c 89 e6                                      mov     rsi, r12
          0x4c360d (+0035)  4c 8d 6d b0                                   lea     r13, [rbp - 0x50]
          0x4c3611 (+0039)  4c 89 f7                                      mov     rdi, r14
          0x4c3614 (+003c)  e8 d7 bd ec ff                                call    0x38f3f0 ; PLT -> PciDeviceImpl::GetSBDFString
          0x4c3619 (+0041)  4c 8b 65 b8                                   mov     r12, qword ptr [rbp - 0x48]
