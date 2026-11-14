; O11 管理库 owner 枚举解释
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::GetOwnerString
; [0x4c3590, 0x4c35d7) file offset 0x4c3590
; window SHA256 7da85a3a97c2e0234ed53d24391de2ee1fd643712ec466765f34e319f85165b3

          0x4c3590 (+0000)  55                                            push    rbp
          0x4c3591 (+0001)  89 f0                                         mov     eax, esi
          0x4c3593 (+0003)  48 8d 35 0a 4a 3c 00                          lea     rsi, [rip + 0x3c4a0a] ; literal "vmkernel"
          0x4c359a (+000a)  48 89 e5                                      mov     rbp, rsp
          0x4c359d (+000d)  41 54                                         push    r12
          0x4c359f (+000f)  49 89 fc                                      mov     r12, rdi
          0x4c35a2 (+0012)  48 83 ec 18                                   sub     rsp, 0x18
          0x4c35a6 (+0016)  83 f8 01                                      cmp     eax, 1
          0x4c35a9 (+0019)  74 15                                         je      0x4c35c0
          0x4c35ab (+001b)  83 f8 02                                      cmp     eax, 2
          0x4c35ae (+001e)  48 8d 35 8d 2e 38 00                          lea     rsi, [rip + 0x382e8d]
          0x4c35b5 (+0025)  48 8d 05 59 20 38 00                          lea     rax, [rip + 0x382059] ; literal "VM passthru"
          0x4c35bc (+002c)  48 0f 44 f0                                   cmove   rsi, rax
          0x4c35c0 (+0030)  48 8d 55 ef                                   lea     rdx, [rbp - 0x11]
          0x4c35c4 (+0034)  4c 89 e7                                      mov     rdi, r12
          0x4c35c7 (+0037)  e8 14 d5 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c35cc (+003c)  48 83 c4 18                                   add     rsp, 0x18
          0x4c35d0 (+0040)  4c 89 e0                                      mov     rax, r12
          0x4c35d3 (+0043)  41 5c                                         pop     r12
          0x4c35d5 (+0045)  5d                                            pop     rbp
          0x4c35d6 (+0046)  c3                                            ret
