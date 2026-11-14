; V02 9.1 25433460 的已有域分支
; build 25433460 / PCIPassthru ELF in sb.v00
; image SHA256 47d5ac91f8c8e2ddc0b68ef2a8c145aa427ad6a99f0c863ed380091cc2fcc8ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x4418, 0x4472) file offset 0x4458
; window SHA256 630ca9e9e00dad36adf3cf96409b40556dafd619a17f64b73b9588b8378b92ce

            0x4418 (+0b88)  e8 00 00 00 00                                call    0x441d ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x441d (+0b8d)  41 89 c7                                      mov     r15d, eax
            0x4420 (+0b90)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x4425 (+0b95)  0f 84 a1 fc ff ff                             je      0x40cc ; branch leaves this window
            0x442b (+0b9b)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x4432 (+0ba2)  e8 00 00 00 00                                call    0x4437 ; REL type=2 SP_Unlock A=-4
            0x4437 (+0ba7)  44 89 3c 24                                   mov     dword ptr [rsp], r15d
            0x443b (+0bab)  41 89 d8                                      mov     r8d, ebx
            0x443e (+0bae)  0f b6 cf                                      movzx   ecx, bh
            0x4441 (+0bb1)  89 da                                         mov     edx, ebx
            0x4443 (+0bb3)  41 c1 e8 03                                   shr     r8d, 3
            0x4447 (+0bb7)  83 e3 07                                      and     ebx, 7
            0x444a (+0bba)  be b0 16 00 00                                mov     esi, 0x16b0
            0x444f (+0bbf)  c1 ea 10                                      shr     edx, 0x10
            0x4452 (+0bc2)  41 89 d9                                      mov     r9d, ebx
            0x4455 (+0bc5)  41 83 e0 1f                                   and     r8d, 0x1f
            0x4459 (+0bc9)  31 c0                                         xor     eax, eax
            0x445b (+0bcb)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC48 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x4462 (+0bd2)  41 bf 05 00 ad 0b                             mov     r15d, 0xbad0005
            0x4468 (+0bd8)  e8 00 00 00 00                                call    0x446d ; REL type=2 _Warning A=-4
            0x446d (+0bdd)  e9 2f f8 ff ff                                jmp     0x3ca1 ; branch leaves this window
