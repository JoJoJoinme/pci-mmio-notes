; O09 具体 ConfigStore owner 写入
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::SetConfiguredDevOwnerNoDeps
; [0x4c6399, 0x4c63f7) file offset 0x4c6399
; window SHA256 85d920c914b7c16f4c65f29f0916cb8eb045b8c60b1813b64bd5a9734db39a26

          0x4c6399 (+00d3)  48 8b 05 f8 fc 59 00                          mov     rax, qword ptr [rip + 0x59fcf8] ; GOT -> _ZNSs4_Rep20_S_empty_rep_storageE
          0x4c63a0 (+00da)  48 83 c0 18                                   add     rax, 0x18
          0x4c63a4 (+00de)  48 89 45 c0                                   mov     qword ptr [rbp - 0x40], rax
          0x4c63a8 (+00e2)  83 fe 02                                      cmp     esi, 2
          0x4c63ab (+00e5)  75 23                                         jne     0x4c63d0
          0x4c63ad (+00e7)  48 8d 35 e2 f3 37 00                          lea     rsi, [rip + 0x37f3e2] ; literal "OWNER_PASSTHRU"
          0x4c63b4 (+00ee)  4c 89 e7                                      mov     rdi, r12
          0x4c63b7 (+00f1)  e8 44 e9 eb ff                                call    0x384d00 ; PLT -> _ZNSsaSEPKc
          0x4c63bc (+00f6)  4c 89 fa                                      mov     rdx, r15
          0x4c63bf (+00f9)  48 8d 35 b2 08 3b 00                          lea     rsi, [rip + 0x3b08b2] ; literal "owner"
          0x4c63c6 (+0100)  4c 89 f7                                      mov     rdi, r14
          0x4c63c9 (+0103)  e8 12 a7 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c63ce (+0108)  eb 09                                         jmp     0x4c63d9
          0x4c63d0 (+010a)  48 8d 35 ce f3 37 00                          lea     rsi, [rip + 0x37f3ce] ; literal "OWNER_VMKERNEL"
          0x4c63d7 (+0111)  eb db                                         jmp     0x4c63b4
          0x4c63d9 (+0113)  4c 89 e2                                      mov     rdx, r12
          0x4c63dc (+0116)  4c 89 f6                                      mov     rsi, r14
          0x4c63df (+0119)  48 89 df                                      mov     rdi, rbx
          0x4c63e2 (+011c)  e8 d9 dd eb ff                                call    0x3841c0 ; PLT -> PciDeviceImpl::SetValueToCS
          0x4c63e7 (+0121)  4c 89 f7                                      mov     rdi, r14
          0x4c63ea (+0124)  e8 71 e4 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c63ef (+0129)  4c 89 e7                                      mov     rdi, r12
          0x4c63f2 (+012c)  e8 69 e4 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
