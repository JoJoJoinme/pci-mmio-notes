; D04 别名桥内部类型集合
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCIBridge_IsAliasing
; [0x4200000e5138, 0x4200000e5153) file offset 0x3a4138
; window SHA256 c06b4c59bf0f97cb0ceb33933e9945ec251e1a6ce87b02d5e94e75d3a0cd521e

    0x4200000e5138 (+0000)  8b 97 f8 00 00 00                             mov     edx, dword ptr [rdi + 0xf8]
    0x4200000e513e (+0006)  8d 42 ff                                      lea     eax, [rdx - 1]
    0x4200000e5141 (+0009)  83 f8 01                                      cmp     eax, 1
    0x4200000e5144 (+000c)  0f 96 c0                                      setbe   al
    0x4200000e5147 (+000f)  83 ea 04                                      sub     edx, 4
    0x4200000e514a (+0012)  83 fa 01                                      cmp     edx, 1
    0x4200000e514d (+0015)  0f 96 c2                                      setbe   dl
    0x4200000e5150 (+0018)  09 d0                                         or      eax, edx
    0x4200000e5152 (+001a)  c3                                            ret
