; I07 普通 PCI 激活的切域调用和 VMkernel 域回退
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruEnablePCIDevice
; [0x7eb0, 0x7ee3) file offset 0x7ef0
; window SHA256 1690a5c819df29595c07315de5cd74dd47580cc669de20807bd4c452fc8ca1c7

            0x7eb0 (+0270)  89 df                                         mov     edi, ebx
            0x7eb2 (+0272)  48 8d 74 24 18                                lea     rsi, [rsp + 0x18]
            0x7eb7 (+0277)  e8 00 00 00 00                                call    0x7ebc ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x7ebc (+027c)  48 8b 7c 24 18                                mov     rdi, qword ptr [rsp + 0x18]
            0x7ec1 (+0281)  85 c0                                         test    eax, eax
            0x7ec3 (+0283)  75 14                                         jne     0x7ed9
            0x7ec5 (+0285)  31 c9                                         xor     ecx, ecx
            0x7ec7 (+0287)  89 da                                         mov     edx, ebx
            0x7ec9 (+0289)  48 89 ee                                      mov     rsi, rbp
            0x7ecc (+028c)  e8 00 00 00 00                                call    0x7ed1 ; REL type=2 IOMMU_SwitchAddressDomain A=-4
            0x7ed1 (+0291)  41 89 c5                                      mov     r13d, eax
            0x7ed4 (+0294)  e9 1b fe ff ff                                jmp     0x7cf4 ; branch leaves this window
            0x7ed9 (+0299)  e8 00 00 00 00                                call    0x7ede ; REL type=2 IOMMU_GetVmkernelDomain A=-4
            0x7ede (+029e)  48 89 c7                                      mov     rdi, rax
            0x7ee1 (+02a1)  eb e2                                         jmp     0x7ec5
