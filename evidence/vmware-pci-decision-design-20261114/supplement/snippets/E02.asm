; E02 无依赖对象的拒绝文字
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 797abeb924df7e6e585ac2dd5ec354efc157647055d2602f4637b55e4d557608

          0x4cbe53 (+03a7)  48 8d 7d c0                                   lea     rdi, [rbp - 0x40]
          0x4cbe57 (+03ab)  48 8d 35 a7 a0 37 00                          lea     rsi, [rip + 0x37a0a7] ; literal " is not passthrough capable because it is directly under the PCI host bridge."
          0x4cbe5e (+03b2)  e8 0d 63 ec ff                                call    0x392170 ; PLT -> Detail::StrBuf
