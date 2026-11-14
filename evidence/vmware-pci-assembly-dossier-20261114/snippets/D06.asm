; D06 PCIe endpoint 类型判定
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_IsPCIeEndpointDevice
; [0x4200000eb43c, 0x4200000eb461) file offset 0x3aa43c
; window SHA256 2e262c4111ac433f54191c16c79242c59dfdafd9cd2786220c1c3eb1388b8b47

    0x4200000eb43c (+0000)  48 83 ec 18                                   sub     rsp, 0x18
    0x4200000eb440 (+0004)  48 8d 74 24 0c                                lea     rsi, [rsp + 0xc]
    0x4200000eb445 (+0009)  e8 ae ad 00 00                                call    0x4200000f61f8 ; directSymbol -> PCIE_GetPortType
    0x4200000eb44a (+000e)  41 89 c0                                      mov     r8d, eax
    0x4200000eb44d (+0011)  31 c0                                         xor     eax, eax
    0x4200000eb44f (+0013)  45 85 c0                                      test    r8d, r8d
    0x4200000eb452 (+0016)  75 08                                         jne     0x4200000eb45c
    0x4200000eb454 (+0018)  83 7c 24 0c 01                                cmp     dword ptr [rsp + 0xc], 1
    0x4200000eb459 (+001d)  0f 96 c0                                      setbe   al
    0x4200000eb45c (+0020)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000eb460 (+0024)  c3                                            ret
