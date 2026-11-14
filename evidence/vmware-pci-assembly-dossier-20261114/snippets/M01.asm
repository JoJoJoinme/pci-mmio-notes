; M01 map 中复位选择器及 shareable 值
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::LoadPassthruMap
; [0x4c909d, 0x4c91db) file offset 0x4c909d
; window SHA256 e93a2326fca61f03a3a6112f2e60bb3da869d0c24a050b23cb2ff473ff614e08

          0x4c909d (+0223)  48 8d 35 01 cd 37 00                          lea     rsi, [rip + 0x37cd01] ; literal "flr"
          0x4c90a4 (+022a)  4c 89 f7                                      mov     rdi, r14
          0x4c90a7 (+022d)  e8 34 32 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c90ac (+0232)  5a                                            pop     rdx
          0x4c90ad (+0233)  59                                            pop     rcx
          0x4c90ae (+0234)  84 c0                                         test    al, al
          0x4c90b0 (+0236)  74 2c                                         je      0x4c90de
          0x4c90b2 (+0238)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c90b9 (+023f)  4c 89 fe                                      mov     rsi, r15
          0x4c90bc (+0242)  4c 89 e7                                      mov     rdi, r12
          0x4c90bf (+0245)  e8 1c 7a ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c90c4 (+024a)  48 8b 3d 45 dc 59 00                          mov     rdi, qword ptr [rip + 0x59dc45] ; GOT -> PciDeviceImpl::_resetMap
          0x4c90cb (+0251)  4c 89 e6                                      mov     rsi, r12
          0x4c90ce (+0254)  e8 cd 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c90d3 (+0259)  c7 00 01 00 00 00                             mov     dword ptr [rax], 1
          0x4c90d9 (+025f)  e9 b2 00 00 00                                jmp     0x4c9190
          0x4c90de (+0264)  48 8d 35 c4 cc 37 00                          lea     rsi, [rip + 0x37ccc4] ; literal "d3d0"
          0x4c90e5 (+026b)  4c 89 f7                                      mov     rdi, r14
          0x4c90e8 (+026e)  e8 f3 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c90ed (+0273)  84 c0                                         test    al, al
          0x4c90ef (+0275)  74 29                                         je      0x4c911a
          0x4c90f1 (+0277)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c90f8 (+027e)  4c 89 fe                                      mov     rsi, r15
          0x4c90fb (+0281)  4c 89 e7                                      mov     rdi, r12
          0x4c90fe (+0284)  e8 dd 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c9103 (+0289)  48 8b 3d 06 dc 59 00                          mov     rdi, qword ptr [rip + 0x59dc06] ; GOT -> PciDeviceImpl::_resetMap
          0x4c910a (+0290)  4c 89 e6                                      mov     rsi, r12
          0x4c910d (+0293)  e8 8e 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c9112 (+0298)  c7 00 02 00 00 00                             mov     dword ptr [rax], 2
          0x4c9118 (+029e)  eb 76                                         jmp     0x4c9190
          0x4c911a (+02a0)  48 8d 35 cd 9a 38 00                          lea     rsi, [rip + 0x389acd] ; literal "link"
          0x4c9121 (+02a7)  4c 89 f7                                      mov     rdi, r14
          0x4c9124 (+02aa)  e8 b7 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c9129 (+02af)  84 c0                                         test    al, al
          0x4c912b (+02b1)  74 29                                         je      0x4c9156
          0x4c912d (+02b3)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c9134 (+02ba)  4c 89 fe                                      mov     rsi, r15
          0x4c9137 (+02bd)  4c 89 e7                                      mov     rdi, r12
          0x4c913a (+02c0)  e8 a1 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c913f (+02c5)  48 8b 3d ca db 59 00                          mov     rdi, qword ptr [rip + 0x59dbca] ; GOT -> PciDeviceImpl::_resetMap
          0x4c9146 (+02cc)  4c 89 e6                                      mov     rsi, r12
          0x4c9149 (+02cf)  e8 52 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c914e (+02d4)  c7 00 03 00 00 00                             mov     dword ptr [rax], 3
          0x4c9154 (+02da)  eb 3a                                         jmp     0x4c9190
          0x4c9156 (+02dc)  48 8d 35 26 9f 37 00                          lea     rsi, [rip + 0x379f26] ; literal "bridge"
          0x4c915d (+02e3)  4c 89 f7                                      mov     rdi, r14
          0x4c9160 (+02e6)  e8 7b 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c9165 (+02eb)  84 c0                                         test    al, al
          0x4c9167 (+02ed)  74 2f                                         je      0x4c9198
          0x4c9169 (+02ef)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c9170 (+02f6)  4c 89 fe                                      mov     rsi, r15
          0x4c9173 (+02f9)  4c 89 e7                                      mov     rdi, r12
          0x4c9176 (+02fc)  e8 65 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c917b (+0301)  48 8b 3d 8e db 59 00                          mov     rdi, qword ptr [rip + 0x59db8e] ; GOT -> PciDeviceImpl::_resetMap
          0x4c9182 (+0308)  4c 89 e6                                      mov     rsi, r12
          0x4c9185 (+030b)  e8 16 76 ec ff                                call    0x3907a0 ; PLT -> _ZNSt3mapISs23Hardware_PCIResetMethodSt4lessISsESaISt4pairIKSsS0_EEEixEOSs
          0x4c918a (+0310)  c7 00 04 00 00 00                             mov     dword ptr [rax], 4
          0x4c9190 (+0316)  4c 89 e7                                      mov     rdi, r12
          0x4c9193 (+0319)  e8 c8 b6 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
          0x4c9198 (+031e)  48 8d bd 40 f9 ff ff                          lea     rdi, [rbp - 0x6c0]
          0x4c919f (+0325)  48 8d 35 00 f4 3a 00                          lea     rsi, [rip + 0x3af400] ; literal "false"
          0x4c91a6 (+032c)  e8 35 31 eb ff                                call    0x37c2e0 ; PLT -> _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
          0x4c91ab (+0331)  84 c0                                         test    al, al
          0x4c91ad (+0333)  74 2c                                         je      0x4c91db ; branch leaves this window
          0x4c91af (+0335)  48 8d 95 33 f9 ff ff                          lea     rdx, [rbp - 0x6cd]
          0x4c91b6 (+033c)  4c 89 fe                                      mov     rsi, r15
          0x4c91b9 (+033f)  4c 89 e7                                      mov     rdi, r12
          0x4c91bc (+0342)  e8 1f 79 ec ff                                call    0x390ae0 ; PLT -> _ZNSsC1EPKcRKSaIcE
          0x4c91c1 (+0347)  48 8b 3d 48 cd 59 00                          mov     rdi, qword ptr [rip + 0x59cd48] ; GOT -> PciDeviceImpl::_fptShareableMap
          0x4c91c8 (+034e)  4c 89 e6                                      mov     rsi, r12
          0x4c91cb (+0351)  e8 10 d5 eb ff                                call    0x3866e0 ; PLT -> _ZNSt3mapISsbSt4lessISsESaISt4pairIKSsbEEEixEOSs
          0x4c91d0 (+0356)  c6 00 00                                      mov     byte ptr [rax], 0
          0x4c91d3 (+0359)  4c 89 e7                                      mov     rdi, r12
          0x4c91d6 (+035c)  e8 85 b6 ec ff                                call    0x394860 ; PLT -> _ZNSsD1Ev
