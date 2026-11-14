; O14 GetSeg getter 的真实字段读取
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::GetSeg
; [0x4c1980, 0x4c1984) file offset 0x4c1980
; window SHA256 604f885ca70d689e943955b19c3dece54072c92e86c652f4fd211a19f35f4635

          0x4c1980 (+0000)  8b 47 5c                                      mov     eax, dword ptr [rdi + 0x5c]
          0x4c1983 (+0003)  c3                                            ret
