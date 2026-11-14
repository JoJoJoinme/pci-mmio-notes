; E03 切换入口的资格与现有配置检查
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 6d09723270266cc2e055d87c797ee2d45084daff52cb22abd6ee84f883d569bc

          0x4cc032 (+0000)  55                                            push    rbp
          0x4cc033 (+0001)  48 89 e5                                      mov     rbp, rsp
          0x4cc036 (+0004)  41 57                                         push    r15
          0x4cc038 (+0006)  41 56                                         push    r14
          0x4cc03a (+0008)  49 89 fe                                      mov     r14, rdi
          0x4cc03d (+000b)  41 55                                         push    r13
          0x4cc03f (+000d)  41 54                                         push    r12
          0x4cc041 (+000f)  53                                            push    rbx
          0x4cc042 (+0010)  48 81 ec 48 01 00 00                          sub     rsp, 0x148
          0x4cc049 (+0017)  e8 02 08 eb ff                                call    0x37c850 ; PLT -> PciDeviceImpl::IsPassthruCapable
          0x4cc04e (+001c)  84 c0                                         test    al, al
          0x4cc050 (+001e)  75 1e                                         jne     0x4cc070
          0x4cc052 (+0020)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc057 (+0025)  e8 34 0a ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc05c (+002a)  48 8d 35 01 9f 37 00                          lea     rsi, [rip + 0x379f01] ; literal "Device is not capable of passthru. Refer to KB 2142307 for the list of requirements"
          0x4cc063 (+0031)  48 89 c7                                      mov     rdi, rax
          0x4cc066 (+0034)  49 89 c4                                      mov     r12, rax
          0x4cc069 (+0037)  e8 f2 19 eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4cc06e (+003c)  eb 29                                         jmp     0x4cc099
          0x4cc070 (+003e)  4c 89 f7                                      mov     rdi, r14
          0x4cc073 (+0041)  e8 18 f3 eb ff                                call    0x38b390 ; PLT -> PciDeviceImpl::GetConfiguredDeviceOwner
          0x4cc078 (+0046)  83 f8 02                                      cmp     eax, 2
          0x4cc07b (+0049)  75 32                                         jne     0x4cc0af
          0x4cc07d (+004b)  bf 20 00 00 00                                mov     edi, 0x20
          0x4cc082 (+0050)  e8 09 0a ec ff                                call    0x38ca90 ; PLT -> __cxa_allocate_exception
          0x4cc087 (+0055)  48 8d 35 2a 9f 37 00                          lea     rsi, [rip + 0x379f2a] ; literal "Device owner is already configured to passthru."
          0x4cc08e (+005c)  48 89 c7                                      mov     rdi, rax
          0x4cc091 (+005f)  49 89 c4                                      mov     r12, rax
          0x4cc094 (+0062)  e8 c7 19 eb ff                                call    0x37da60 ; PLT -> Lib::HostCtlException
          0x4cc099 (+0067)  48 8b 15 70 91 59 00                          mov     rdx, qword ptr [rip + 0x599170] ; GOT -> Lib::HostCtlException
          0x4cc0a0 (+006e)  48 8b 35 b9 ab 59 00                          mov     rsi, qword ptr [rip + 0x59abb9] ; GOT -> _ZTIN7HostCtl3Lib16HostCtlExceptionE
          0x4cc0a7 (+0075)  4c 89 e7                                      mov     rdi, r12
          0x4cc0aa (+0078)  e9 a5 00 00 00                                jmp     0x4cc154 ; branch leaves this window
          0x4cc0af (+007d)  4c 89 f7                                      mov     rdi, r14
          0x4cc0b2 (+0080)  e8 99 c6 eb ff                                call    0x388750 ; PLT -> PciDeviceImpl::IsBootDevice
          0x4cc0b7 (+0085)  84 c0                                         test    al, al
          0x4cc0b9 (+0087)  0f 84 9a 00 00 00                             je      0x4cc159 ; branch leaves this window
