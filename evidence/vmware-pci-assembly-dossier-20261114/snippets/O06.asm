; O06 反向查找相关设备的比较字段
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::GetDependentChildDevices
; [0x4cb510, 0x4cb581) file offset 0x4cb510
; window SHA256 566628e9ea27d3d465155d2d6683262bcc732522802f672ef5b6ccc6bd441b20

          0x4cb510 (+0050)  48 8b 5d b8                                   mov     rbx, qword ptr [rbp - 0x48]
          0x4cb514 (+0054)  4c 8d 7d 98                                   lea     r15, [rbp - 0x68]
          0x4cb518 (+0058)  48 3b 5d c0                                   cmp     rbx, qword ptr [rbp - 0x40]
          0x4cb51c (+005c)  0f 84 95 00 00 00                             je      0x4cb5b7 ; branch leaves this window
          0x4cb522 (+0062)  48 8b 33                                      mov     rsi, qword ptr [rbx]
          0x4cb525 (+0065)  4c 89 ff                                      mov     rdi, r15
          0x4cb528 (+0068)  48 8b 06                                      mov     rax, qword ptr [rsi]
          0x4cb52b (+006b)  ff 90 58 01 00 00                             call    qword ptr [rax + 0x158]
          0x4cb531 (+0071)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb535 (+0075)  48 85 ff                                      test    rdi, rdi
          0x4cb538 (+0078)  75 0e                                         jne     0x4cb548
          0x4cb53a (+007a)  4c 89 ff                                      mov     rdi, r15
          0x4cb53d (+007d)  48 83 c3 08                                   add     rbx, 8
          0x4cb541 (+0081)  e8 ca 69 ea ff                                call    0x371f10 ; PLT -> _ZNSt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS2_EED1Ev
          0x4cb546 (+0086)  eb d0                                         jmp     0x4cb518
          0x4cb548 (+0088)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb54b (+008b)  ff 50 40                                      call    qword ptr [rax + 0x40]
          0x4cb54e (+008e)  41 38 45 6a                                   cmp     byte ptr [r13 + 0x6a], al
          0x4cb552 (+0092)  75 e6                                         jne     0x4cb53a
          0x4cb554 (+0094)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb558 (+0098)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb55b (+009b)  ff 50 48                                      call    qword ptr [rax + 0x48]
          0x4cb55e (+009e)  41 3a 45 6b                                   cmp     al, byte ptr [r13 + 0x6b]
          0x4cb562 (+00a2)  75 d6                                         jne     0x4cb53a
          0x4cb564 (+00a4)  48 8b 7d 98                                   mov     rdi, qword ptr [rbp - 0x68]
          0x4cb568 (+00a8)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4cb56b (+00ab)  ff 50 50                                      call    qword ptr [rax + 0x50]
          0x4cb56e (+00ae)  41 3a 45 6c                                   cmp     al, byte ptr [r13 + 0x6c]
          0x4cb572 (+00b2)  75 c6                                         jne     0x4cb53a
          0x4cb574 (+00b4)  48 89 de                                      mov     rsi, rbx
          0x4cb577 (+00b7)  4c 89 e7                                      mov     rdi, r12
          0x4cb57a (+00ba)  e8 21 0a ec ff                                call    0x38bfa0 ; PLT -> _ZNSt6vectorISt10unique_ptrIN7HostCtl8Hardware9PciDeviceESt14default_deleteIS3_EESaIS6_EE12emplace_backIJS6_EEERS6_DpOT_
          0x4cb57f (+00bf)  eb b9                                         jmp     0x4cb53a
