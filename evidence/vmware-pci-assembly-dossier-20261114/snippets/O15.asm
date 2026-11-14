; O15 GetBus getter 的真实字段读取
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::GetBus
; [0x4c1984, 0x4c1988) file offset 0x4c1984
; window SHA256 182a6a1ac93040326f6a36f186c870419276eaad6f015acc3ffc6b5674c6dc5c

          0x4c1984 (+0000)  8a 47 6a                                      mov     al, byte ptr [rdi + 0x6a]
          0x4c1987 (+0003)  c3                                            ret
