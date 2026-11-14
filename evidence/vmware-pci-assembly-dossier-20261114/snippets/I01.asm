; I01 已有域拒绝条件及清理跳转
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruRegisterDeviceInt
; [0x53bf, 0x543c) file offset 0x53ff
; window SHA256 baed6153f7e9d414c9a3c2e85b56628a2623afb215bfbe7387eb3a7cee6eb7c7

            0x53bf (+0853)  83 7c 24 58 01                                cmp     dword ptr [rsp + 0x58], 1
            0x53c4 (+0858)  0f 86 ff fc ff ff                             jbe     0x50c9 ; branch leaves this window
            0x53ca (+085e)  48 c7 44 24 70 00 00 00 00                    mov     qword ptr [rsp + 0x70], 0
            0x53d3 (+0867)  48 8b 74 24 28                                mov     rsi, qword ptr [rsp + 0x28]
            0x53d8 (+086c)  89 df                                         mov     edi, ebx
            0x53da (+086e)  e8 00 00 00 00                                call    0x53df ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x53df (+0873)  44 8b 54 24 40                                mov     r10d, dword ptr [rsp + 0x40]
            0x53e4 (+0878)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x53e9 (+087d)  89 c3                                         mov     ebx, eax
            0x53eb (+087f)  0f 84 d8 fc ff ff                             je      0x50c9 ; branch leaves this window
            0x53f1 (+0885)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x53f8 (+088c)  44 89 14 24                                   mov     dword ptr [rsp], r10d
            0x53fc (+0890)  e8 00 00 00 00                                call    0x5401 ; REL type=2 SP_Unlock A=-4
            0x5401 (+0895)  48 83 ec 08                                   sub     rsp, 8
            0x5405 (+0899)  44 89 ea                                      mov     edx, r13d
            0x5408 (+089c)  31 c0                                         xor     eax, eax
            0x540a (+089e)  53                                            push    rbx
            0x540b (+089f)  44 8b 54 24 10                                mov     r10d, dword ptr [rsp + 0x10]
            0x5410 (+08a4)  be ae 14 00 00                                mov     esi, 0x14ae
            0x5415 (+08a9)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC58 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x541c (+08b0)  44 8b 4c 24 58                                mov     r9d, dword ptr [rsp + 0x58]
            0x5421 (+08b5)  8b 4c 24 60                                   mov     ecx, dword ptr [rsp + 0x60]
            0x5425 (+08b9)  41 bd 05 00 ad 0b                             mov     r13d, 0xbad0005
            0x542b (+08bf)  45 89 d0                                      mov     r8d, r10d
            0x542e (+08c2)  e8 00 00 00 00                                call    0x5433 ; REL type=2 _Warning A=-4
            0x5433 (+08c7)  41 59                                         pop     r9
            0x5435 (+08c9)  41 5a                                         pop     r10
            0x5437 (+08cb)  e9 4e fd ff ff                                jmp     0x518a ; branch leaves this window
