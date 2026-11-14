; E04 取得虚拟交换机信息
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address
; window SHA256 a37535acc6911012042ae21145d0c53729376ce2f6e399ab6712ea8f00f2cd2a

          0x4cc16f (+013d)  48 8d 85 28 ff ff ff                          lea     rax, [rbp - 0xd8]
          0x4cc176 (+0144)  48 89 c7                                      mov     rdi, rax
          0x4cc179 (+0147)  48 89 85 d0 fe ff ff                          mov     qword ptr [rbp - 0x130], rax
          0x4cc180 (+014e)  e8 6b 46 eb ff                                call    0x3807f0 ; PLT -> Network::NetworkInfoImpl
          0x4cc185 (+0153)  48 8d 85 e0 fe ff ff                          lea     rax, [rbp - 0x120]
          0x4cc18c (+015a)  48 8b b5 d0 fe ff ff                          mov     rsi, qword ptr [rbp - 0x130]
          0x4cc193 (+0161)  48 89 c7                                      mov     rdi, rax
          0x4cc196 (+0164)  48 89 85 b8 fe ff ff                          mov     qword ptr [rbp - 0x148], rax
          0x4cc19d (+016b)  e8 4e 63 eb ff                                call    0x3824f0 ; PLT -> NetworkInfoImpl::GetVirtualSwitchInfo
