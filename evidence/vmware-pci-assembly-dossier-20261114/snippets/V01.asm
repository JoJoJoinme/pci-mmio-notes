; V01 U3k 25595708 的已有域分支
; build 25595708 / PCIPassthru ELF in sb.v00
; image SHA256 f5911caac9fa163786ce59a78bfc20284696d205b4a76c8180a141fd0214e089
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x5307, 0x536a) file offset 0x5347
; window SHA256 d5319d216ca07c6e18b210430b0be14f0fc6600f1699889e061b0c9939164e8d

            0x5307 (+0bd3)  e8 00 00 00 00                                call    0x530c ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x530c (+0bd8)  44 8b 54 24 50                                mov     r10d, dword ptr [rsp + 0x50]
            0x5311 (+0bdd)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x5316 (+0be2)  89 c3                                         mov     ebx, eax
            0x5318 (+0be4)  0f 84 27 fa ff ff                             je      0x4d45 ; branch leaves this window
            0x531e (+0bea)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x5325 (+0bf1)  44 89 54 24 08                                mov     dword ptr [rsp + 8], r10d
            0x532a (+0bf6)  e8 00 00 00 00                                call    0x532f ; REL type=2 SP_Unlock A=-4
            0x532f (+0bfb)  48 83 ec 08                                   sub     rsp, 8
            0x5333 (+0bff)  44 89 f2                                      mov     edx, r14d
            0x5336 (+0c02)  31 c0                                         xor     eax, eax
            0x5338 (+0c04)  53                                            push    rbx
            0x5339 (+0c05)  44 8b 54 24 18                                mov     r10d, dword ptr [rsp + 0x18]
            0x533e (+0c0a)  be b8 14 00 00                                mov     esi, 0x14b8
            0x5343 (+0c0f)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC59 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x534a (+0c16)  44 8b 4c 24 6c                                mov     r9d, dword ptr [rsp + 0x6c]
            0x534f (+0c1b)  8b 4c 24 70                                   mov     ecx, dword ptr [rsp + 0x70]
            0x5353 (+0c1f)  41 be 05 00 ad 0b                             mov     r14d, 0xbad0005
            0x5359 (+0c25)  45 89 d0                                      mov     r8d, r10d
            0x535c (+0c28)  e8 00 00 00 00                                call    0x5361 ; REL type=2 _Warning A=-4
            0x5361 (+0c2d)  41 59                                         pop     r9
            0x5363 (+0c2f)  41 5a                                         pop     r10
            0x5365 (+0c31)  e9 30 fe ff ff                                jmp     0x519a ; branch leaves this window
