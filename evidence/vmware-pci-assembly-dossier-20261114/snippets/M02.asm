; M02 共享属性写入 VSI
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::RestoreFptShareableAttr
; [0x4c9714, 0x4c979a) file offset 0x4c9714
; window SHA256 881ed8775642b633af92afa708e36b3b1e9af828dfcba5507afb9e7112c4349f

          0x4c9714 (+0000)  55                                            push    rbp
          0x4c9715 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4c9718 (+0004)  41 55                                         push    r13
          0x4c971a (+0006)  41 54                                         push    r12
          0x4c971c (+0008)  53                                            push    rbx
          0x4c971d (+0009)  48 89 fb                                      mov     rbx, rdi
          0x4c9720 (+000c)  48 83 ec 28                                   sub     rsp, 0x28
          0x4c9724 (+0010)  e8 a7 26 ec ff                                call    0x38bdd0 ; PLT -> PciDeviceImpl::GetConfiguredFptShareable
          0x4c9729 (+0015)  84 c0                                         test    al, al
          0x4c972b (+0017)  75 62                                         jne     0x4c978f
          0x4c972d (+0019)  4c 8d 65 c8                                   lea     r12, [rbp - 0x38]
          0x4c9731 (+001d)  48 8d 75 c4                                   lea     rsi, [rbp - 0x3c]
          0x4c9735 (+0021)  48 c7 45 c8 00 00 00 00                       mov     qword ptr [rbp - 0x38], 0
          0x4c973d (+0029)  4c 89 e7                                      mov     rdi, r12
          0x4c9740 (+002c)  48 c7 45 d0 00 00 00 00                       mov     qword ptr [rbp - 0x30], 0
          0x4c9748 (+0034)  48 c7 45 d8 00 00 00 00                       mov     qword ptr [rbp - 0x28], 0
          0x4c9750 (+003c)  c7 45 c4 00 00 00 00                          mov     dword ptr [rbp - 0x3c], 0
          0x4c9757 (+0043)  e8 c4 ae ec ff                                call    0x394620 ; PLT -> _ZNSt6vectorIjSaIjEE12emplace_backIJjEEERjDpOT_
          0x4c975c (+0048)  48 8b 05 ad c4 59 00                          mov     rax, qword ptr [rip + 0x59c4ad] ; GOT -> VSI_NODE_hardware_pci_seg_bus_slot_func_fptShareable
          0x4c9763 (+004f)  48 8b 53 48                                   mov     rdx, qword ptr [rbx + 0x48]
          0x4c9767 (+0053)  4c 89 e6                                      mov     rsi, r12
          0x4c976a (+0056)  0f b7 38                                      movzx   edi, word ptr [rax]
          0x4c976d (+0059)  e8 be a9 ea ff                                call    0x374130 ; PLT -> SysinfoUtil::SysinfoSet
          0x4c9772 (+005e)  4c 89 e7                                      mov     rdi, r12
          0x4c9775 (+0061)  e8 e6 46 ec ff                                call    0x38de60 ; PLT -> _ZNSt12_Vector_baseIjSaIjEED2Ev
          0x4c977a (+0066)  eb 13                                         jmp     0x4c978f
          0x4c977c (+0068)  49 89 c5                                      mov     r13, rax
          0x4c977f (+006b)  4c 89 e7                                      mov     rdi, r12
          0x4c9782 (+006e)  e8 d9 46 ec ff                                call    0x38de60 ; PLT -> _ZNSt12_Vector_baseIjSaIjEED2Ev
          0x4c9787 (+0073)  4c 89 ef                                      mov     rdi, r13
          0x4c978a (+0076)  e8 71 73 eb ff                                call    0x380b00 ; PLT -> _Unwind_Resume
          0x4c978f (+007b)  48 83 c4 28                                   add     rsp, 0x28
          0x4c9793 (+007f)  5b                                            pop     rbx
          0x4c9794 (+0080)  41 5c                                         pop     r12
          0x4c9796 (+0082)  41 5d                                         pop     r13
          0x4c9798 (+0084)  5d                                            pop     rbp
          0x4c9799 (+0085)  c3                                            ret
