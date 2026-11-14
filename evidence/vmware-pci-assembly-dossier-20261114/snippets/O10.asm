; O10 主 vtable 地址点的构造
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::constructor
; [0x4c6fa2, 0x4c6fee) file offset 0x4c6fa2
; window SHA256 0edc5dcab9cd86f4791d5058da6582d71f4e3e72aed0683aaa04d323f2469ece

          0x4c6fa2 (+005c)  48 8b 05 47 e0 59 00                          mov     rax, qword ptr [rip + 0x59e047] ; GOT -> _ZTVN6VmkCtl8Hardware13PciDeviceImplE
          0x4c6fa9 (+0063)  48 8d 50 48                                   lea     rdx, [rax + 0x48]
          0x4c6fad (+0067)  48 05 50 04 00 00                             add     rax, 0x450
          0x4c6fb3 (+006d)  49 89 44 24 08                                mov     qword ptr [r12 + 8], rax
          0x4c6fb8 (+0072)  48 8b 05 d9 f0 59 00                          mov     rax, qword ptr [rip + 0x59f0d9] ; GOT -> _ZNSs4_Rep20_S_empty_rep_storageE
          0x4c6fbf (+0079)  49 89 14 24                                   mov     qword ptr [r12], rdx
          0x4c6fc3 (+007d)  0f b6 55 c8                                   movzx   edx, byte ptr [rbp - 0x38]
          0x4c6fc7 (+0081)  48 83 c0 18                                   add     rax, 0x18
          0x4c6fcb (+0085)  49 89 44 24 18                                mov     qword ptr [r12 + 0x18], rax
          0x4c6fd0 (+008a)  49 89 44 24 20                                mov     qword ptr [r12 + 0x20], rax
          0x4c6fd5 (+008f)  49 89 44 24 28                                mov     qword ptr [r12 + 0x28], rax
          0x4c6fda (+0094)  49 89 44 24 30                                mov     qword ptr [r12 + 0x30], rax
          0x4c6fdf (+0099)  49 89 44 24 38                                mov     qword ptr [r12 + 0x38], rax
          0x4c6fe4 (+009e)  49 89 44 24 40                                mov     qword ptr [r12 + 0x40], rax
          0x4c6fe9 (+00a3)  e8 b2 52 eb ff                                call    0x37c2a0 ; PLT -> PciDeviceImpl::SetFromSBDF
