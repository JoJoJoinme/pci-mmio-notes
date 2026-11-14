; O02 启动设备检查
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::ValidateOwnerToPassthru
; [0x4cbbb8, 0x4cbbed) file offset 0x4cbbb8
; window SHA256 3de81051074d58da24434a70b23da009d7cbec2384ba0a238229510d191c4449

          0x4cbbb8 (+010c)  e8 93 cb eb ff                                call    0x388750 ; PLT -> PciDeviceImpl::IsBootDevice
          0x4cbbbd (+0111)  84 c0                                         test    al, al
          0x4cbbbf (+0113)  0f 84 a5 00 00 00                             je      0x4cbc6a ; branch leaves this window
          0x4cbbc5 (+0119)  4c 8d 75 b0                                   lea     r14, [rbp - 0x50]
          0x4cbbc9 (+011d)  4c 89 e6                                      mov     rsi, r12
          0x4cbbcc (+0120)  4c 89 f7                                      mov     rdi, r14
          0x4cbbcf (+0123)  e8 1c 38 ec ff                                call    0x38f3f0 ; PLT -> PciDeviceImpl::GetSBDFString
          0x4cbbd4 (+0128)  4c 8d 65 c0                                   lea     r12, [rbp - 0x40]
          0x4cbbd8 (+012c)  48 8d 15 d3 a2 37 00                          lea     rdx, [rip + 0x37a2d3] ; literal "Cannot configure passthru on boot device."
          0x4cbbdf (+0133)  4c 89 f6                                      mov     rsi, r14
          0x4cbbe2 (+0136)  4c 89 e7                                      mov     rdi, r12
          0x4cbbe5 (+0139)  e8 36 59 ea ff                                call    0x371520 ; PLT -> _ZStplIcSt11char_traitsIcESaIcEESbIT_T0_T1_EOS6_PKS3_
          0x4cbbea (+013e)  4c 89 e6                                      mov     rsi, r12
