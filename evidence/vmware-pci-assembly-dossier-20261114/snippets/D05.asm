; D05 独立复位方法的位运算
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / PCI_HasFuncIndependentReset
; [0x4200000fc5f0, 0x4200000fc60a) file offset 0x3bb5f0
; window SHA256 73748866fe9ab41eba417a51bb260aa1ff6903ab825973242c74a9ed25e46fb6

    0x4200000fc5f0 (+0000)  48 83 ec 08                                   sub     rsp, 8
    0x4200000fc5f4 (+0004)  e8 57 fe ff ff                                call    0x4200000fc450 ; directSymbol -> PCI_FindResetMethod
    0x4200000fc5f9 (+0009)  83 e0 fb                                      and     eax, 0xfffffffb
    0x4200000fc5fc (+000c)  83 e8 01                                      sub     eax, 1
    0x4200000fc5ff (+000f)  83 f8 01                                      cmp     eax, 1
    0x4200000fc602 (+0012)  0f 96 c0                                      setbe   al
    0x4200000fc605 (+0015)  48 83 c4 08                                   add     rsp, 8
    0x4200000fc609 (+0019)  c3                                            ret
