; O04 系统保留设备检查
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::ValidateOwnerToPassthru
; [0x4cbd59, 0x4cbd7d) file offset 0x4cbd59
; window SHA256 2a00d284b2ad1189e3120f382808623ec6c1337279d059c45adb87767d53725a

          0x4cbd59 (+02ad)  e8 f2 56 eb ff                                call    0x381450 ; PLT -> PciDeviceImpl::IsEsxioReservedDevice
          0x4cbd5e (+02b2)  84 c0                                         test    al, al
          0x4cbd60 (+02b4)  0f 84 d3 00 00 00                             je      0x4cbe39 ; branch leaves this window
          0x4cbd66 (+02ba)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbd6a (+02be)  48 8d 35 27 9d 37 00                          lea     rsi, [rip + 0x379d27] ; literal " is system reserved and does not support passthru."
          0x4cbd71 (+02c5)  e8 fa 63 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
          0x4cbd76 (+02ca)  4c 8d 75 90                                   lea     r14, [rbp - 0x70]
          0x4cbd7a (+02ce)  4c 89 e6                                      mov     rsi, r12
