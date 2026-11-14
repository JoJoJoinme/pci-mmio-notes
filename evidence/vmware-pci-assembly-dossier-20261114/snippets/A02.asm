; A02 禁用字段的写入来源
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::SetFromSBDF
; [0x4c6d9f, 0x4c6dc9) file offset 0x4c6d9f
; window SHA256 0439b0da11f8d629e84200b69b93bdb39d7720780846dfa2da5427e672d6ff2e

          0x4c6d9f (+01d5)  48 89 da                                      mov     rdx, rbx
          0x4c6da2 (+01d8)  48 8d 35 01 eb 37 00                          lea     rsi, [rip + 0x37eb01] ; literal "disablePciPassthrough"
          0x4c6da9 (+01df)  4c 89 ef                                      mov     rdi, r13
          0x4c6dac (+01e2)  e8 2f 9d ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c6db1 (+01e7)  4c 89 ee                                      mov     rsi, r13
          0x4c6db4 (+01ea)  4c 89 f7                                      mov     rdi, r14
          0x4c6db7 (+01ed)  e8 a4 22 ec ff                                call    0x389060 ; PLT -> KernelOpts::GetRuntimeValueBool
          0x4c6dbc (+01f2)  41 88 44 24 77                                mov     byte ptr [r12 + 0x77], al
          0x4c6dc1 (+01f7)  4c 89 ef                                      mov     rdi, r13
          0x4c6dc4 (+01fa)  e8 97 da ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
