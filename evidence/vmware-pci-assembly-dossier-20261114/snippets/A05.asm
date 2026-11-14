; A05 内核状态转为四字段 SBDF
; build 24280767 / decompressed k.b00
; image SHA256 5b8bef496e20e3d4194af7439f2f0a7273b77c15ab15ba1b117ddbcef9d9f775
; ELF linked virtual address / Hardware_PCIPassthruDependentGet
; [0x420000072288, 0x42000007230b) file offset 0x331288
; window SHA256 21ba16e89ca8f023dc9618728d2a3eb9722244aa22e91fc9cfa326d3dcacb993

    0x420000072288 (+0000)  41 54                                         push    r12
    0x42000007228a (+0002)  48 89 f7                                      mov     rdi, rsi
    0x42000007228d (+0005)  53                                            push    rbx
    0x42000007228e (+0006)  48 89 d3                                      mov     rbx, rdx
    0x420000072291 (+0009)  48 83 ec 18                                   sub     rsp, 0x18
    0x420000072295 (+000d)  48 8d 74 24 08                                lea     rsi, [rsp + 8]
    0x42000007229a (+0012)  e8 b1 fc ff ff                                call    0x420000071f50 ; directSymbol -> Hardware_PCIGetDevFromInstArgs
    0x42000007229f (+0017)  41 89 c4                                      mov     r12d, eax
    0x4200000722a2 (+001a)  85 c0                                         test    eax, eax
    0x4200000722a4 (+001c)  74 0b                                         je      0x4200000722b1
    0x4200000722a6 (+001e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000722aa (+0022)  44 89 e0                                      mov     eax, r12d
    0x4200000722ad (+0025)  5b                                            pop     rbx
    0x4200000722ae (+0026)  41 5c                                         pop     r12
    0x4200000722b0 (+0028)  c3                                            ret
    0x4200000722b1 (+0029)  48 8b 7c 24 08                                mov     rdi, qword ptr [rsp + 8]
    0x4200000722b6 (+002e)  48 8d 74 24 04                                lea     rsi, [rsp + 4]
    0x4200000722bb (+0033)  e8 78 eb 12 00                                call    0x4200001a0e38 ; directSymbol -> VMKPCIPassthru_GetDeviceDependencies
    0x4200000722c0 (+0038)  85 c0                                         test    eax, eax
    0x4200000722c2 (+003a)  74 1a                                         je      0x4200000722de
    0x4200000722c4 (+003c)  48 c7 03 ff ff ff ff                          mov     qword ptr [rbx], 0xffffffffffffffff
    0x4200000722cb (+0043)  44 89 e0                                      mov     eax, r12d
    0x4200000722ce (+0046)  48 c7 43 08 ff ff ff ff                       mov     qword ptr [rbx + 8], 0xffffffffffffffff
    0x4200000722d6 (+004e)  48 83 c4 18                                   add     rsp, 0x18
    0x4200000722da (+0052)  5b                                            pop     rbx
    0x4200000722db (+0053)  41 5c                                         pop     r12
    0x4200000722dd (+0055)  c3                                            ret
    0x4200000722de (+0056)  8b 44 24 04                                   mov     eax, dword ptr [rsp + 4]
    0x4200000722e2 (+005a)  89 c2                                         mov     edx, eax
    0x4200000722e4 (+005c)  c1 ea 10                                      shr     edx, 0x10
    0x4200000722e7 (+005f)  89 13                                         mov     dword ptr [rbx], edx
    0x4200000722e9 (+0061)  0f b6 d4                                      movzx   edx, ah
    0x4200000722ec (+0064)  89 53 04                                      mov     dword ptr [rbx + 4], edx
    0x4200000722ef (+0067)  89 c2                                         mov     edx, eax
    0x4200000722f1 (+0069)  83 e0 07                                      and     eax, 7
    0x4200000722f4 (+006c)  c1 ea 03                                      shr     edx, 3
    0x4200000722f7 (+006f)  89 43 0c                                      mov     dword ptr [rbx + 0xc], eax
    0x4200000722fa (+0072)  44 89 e0                                      mov     eax, r12d
    0x4200000722fd (+0075)  83 e2 1f                                      and     edx, 0x1f
    0x420000072300 (+0078)  89 53 08                                      mov     dword ptr [rbx + 8], edx
    0x420000072303 (+007b)  48 83 c4 18                                   add     rsp, 0x18
    0x420000072307 (+007f)  5b                                            pop     rbx
    0x420000072308 (+0080)  41 5c                                         pop     r12
    0x42000007230a (+0082)  c3                                            ret
