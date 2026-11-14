; R09 RMRR 重叠拒绝分支
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x5364, 0x53bf) file offset 0x53a4
; window SHA256 3204f0068497bd758842d2ba0335097f2ac44ba21e82a94a062bce33d2694619

            0x5364 (+07f8)  4c 89 f6                                      mov     rsi, r14
            0x5367 (+07fb)  44 89 ef                                      mov     edi, r13d
            0x536a (+07fe)  e8 00 00 00 00                                call    0x536f ; REL type=2 IOMMU_IsDeviceRMRROverlap A=-4
            0x536f (+0803)  84 c0                                         test    al, al
            0x5371 (+0805)  0f 84 49 f9 ff ff                             je      0x4cc0 ; branch leaves this window
            0x5377 (+080b)  45 89 e8                                      mov     r8d, r13d
            0x537a (+080e)  44 89 e8                                      mov     eax, r13d
            0x537d (+0811)  44 89 ea                                      mov     edx, r13d
            0x5380 (+0814)  45 89 e9                                      mov     r9d, r13d
            0x5383 (+0817)  41 c1 e8 03                                   shr     r8d, 3
            0x5387 (+081b)  0f b6 cc                                      movzx   ecx, ah
            0x538a (+081e)  c1 ea 10                                      shr     edx, 0x10
            0x538d (+0821)  41 83 e1 07                                   and     r9d, 7
            0x5391 (+0825)  41 83 e0 1f                                   and     r8d, 0x1f
            0x5395 (+0829)  be 32 10 00 00                                mov     esi, 0x1032
            0x539a (+082e)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC53 A=-4 "PCIPassthru: %d: Device %04x:%02x:%02x.%x cannot be used for passthrough because the host's BIOS ACPI RMRR structure indicates that the device DMAs to a host reserved memory region that conflicts with the VM's memory\n\n"
            0x53a1 (+0835)  31 c0                                         xor     eax, eax
            0x53a3 (+0837)  e8 00 00 00 00                                call    0x53a8 ; REL type=2 _Warning A=-4
            0x53a8 (+083c)  4c 8b 64 24 10                                mov     r12, qword ptr [rsp + 0x10]
            0x53ad (+0841)  41 bd 41 00 ad 0b                             mov     r13d, 0xbad0041
            0x53b3 (+0847)  49 81 c4 08 01 00 00                          add     r12, 0x108
            0x53ba (+084e)  e9 7a f9 ff ff                                jmp     0x4d39 ; branch leaves this window
