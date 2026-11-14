; O08 异常补偿目标与循环
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / PciDeviceImpl::SetConfiguredDeviceOwner
; [0x4c7cd5, 0x4c7d18) file offset 0x4c7cd5
; window SHA256 4599497935f4705fb89dcf845423d735694ee6783d24f68c3ecaa66578c7960b

          0x4c7cd5 (+0435)  48 89 c7                                      mov     rdi, rax
          0x4c7cd8 (+0438)  48 ff ca                                      dec     rdx
          0x4c7cdb (+043b)  74 08                                         je      0x4c7ce5
          0x4c7cdd (+043d)  49 89 c5                                      mov     r13, rax
          0x4c7ce0 (+0440)  e9 0e 01 00 00                                jmp     0x4c7df3 ; branch leaves this window
          0x4c7ce5 (+0445)  e8 86 03 eb ff                                call    0x378070 ; PLT -> __cxa_begin_catch
          0x4c7cea (+044a)  41 83 fe 02                                   cmp     r14d, 2
          0x4c7cee (+044e)  48 8b 5d b8                                   mov     rbx, qword ptr [rbp - 0x48]
          0x4c7cf2 (+0452)  41 0f 95 c6                                   setne   r14b
          0x4c7cf6 (+0456)  45 0f b6 f6                                   movzx   r14d, r14b
          0x4c7cfa (+045a)  41 ff c6                                      inc     r14d
          0x4c7cfd (+045d)  48 39 5d c0                                   cmp     qword ptr [rbp - 0x40], rbx
          0x4c7d01 (+0461)  74 15                                         je      0x4c7d18 ; branch leaves this window
          0x4c7d03 (+0463)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
          0x4c7d06 (+0466)  44 89 f6                                      mov     esi, r14d
          0x4c7d09 (+0469)  48 8b 07                                      mov     rax, qword ptr [rdi]
          0x4c7d0c (+046c)  ff 90 48 01 00 00                             call    qword ptr [rax + 0x148]
          0x4c7d12 (+0472)  48 83 c3 08                                   add     rbx, 8
          0x4c7d16 (+0476)  eb e5                                         jmp     0x4c7cfd
