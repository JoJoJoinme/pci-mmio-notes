; E01 依赖对象必须非空
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 4f54e8f4905b7b611fa0dc19de3c115559dfb3b3140fb53a0f5cfa63af76998b

          0x4cbe39 (+038d)  4c 8d 75 98                                   lea     r14, [rbp - 0x68]
          0x4cbe3d (+0391)  4c 89 e6                                      mov     rsi, r12
          0x4cbe40 (+0394)  4c 89 f7                                      mov     rdi, r14
          0x4cbe43 (+0397)  e8 28 22 eb ff                                call    0x37e070 ; PLT -> PciDeviceImpl::GetDependantDevice
          0x4cbe48 (+039c)  48 83 7d 98 00                                cmp     qword ptr [rbp - 0x68], 0
          0x4cbe4d (+03a1)  0f 85 de 00 00 00                             jne     0x4cbf31 ; branch leaves this window
