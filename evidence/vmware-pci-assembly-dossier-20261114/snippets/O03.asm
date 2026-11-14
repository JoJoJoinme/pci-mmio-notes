; O03 资格再次检查
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::ValidateOwnerToPassthru
; [0x4cbc6d, 0x4cbc91) file offset 0x4cbc6d
; window SHA256 f4315b08398cb72b684174df59407ddcb2813cce199a3644c3c104028718e7d9

          0x4cbc6d (+01c1)  e8 de 0b eb ff                                call    0x37c850 ; PLT -> PciDeviceImpl::IsPassthruCapable
          0x4cbc72 (+01c6)  84 c0                                         test    al, al
          0x4cbc74 (+01c8)  0f 85 d5 00 00 00                             jne     0x4cbd4f ; branch leaves this window
          0x4cbc7a (+01ce)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbc7e (+01d2)  48 8d 35 57 a2 37 00                          lea     rsi, [rip + 0x37a257] ; literal " is not passthrough capable."
          0x4cbc85 (+01d9)  e8 e6 64 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbc8a (+01de)  4c 8d 75 88                                   lea     r14, [rbp - 0x78]
          0x4cbc8e (+01e2)  4c 89 e6                                      mov     rsi, r12
