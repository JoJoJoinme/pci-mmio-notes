; R05 无外部代表时检查自身 owner
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruFPTAllowPassthru
; [0x26ad, 0x26c4) file offset 0x26ed
; window SHA256 609e753bf9c9188ab8177f0748182c3121f30faa5d3eaa98ff2773fe9ba09472

            0x26ad (+0165)  4c 89 e7                                      mov     rdi, r12
            0x26b0 (+0168)  e8 00 00 00 00                                call    0x26b5 ; REL type=2 PCI_GetDeviceOwnership A=-4
            0x26b5 (+016d)  83 f8 01                                      cmp     eax, 1
            0x26b8 (+0170)  0f 84 71 ff ff ff                             je      0x262f ; branch leaves this window
            0x26be (+0176)  41 bd 20 00 ad 0b                             mov     r13d, 0xbad0020
