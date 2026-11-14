; A03 全一 SBDF 哨兵的判定
; build 24280767 / libvmkctl.so
; image SHA256 3432f1036270968cb0a01970a493da2d27033070ebb6dce2546d910c78b135da
; ELF linked virtual address / 匿名无效 SBDF 辅助函数
; [0x4c1990, 0x4c19a7) file offset 0x4c1990
; window SHA256 e1968ecb7ea9647b5ccb90af72d9d4b69ffc6dbcddda850741cbd68466a54aad

          0x4c1990 (+0000)  48 89 f8                                      mov     rax, rdi
          0x4c1993 (+0003)  48 c1 e8 20                                   shr     rax, 0x20
          0x4c1997 (+0007)  21 c7                                         and     edi, eax
          0x4c1999 (+0009)  21 f7                                         and     edi, esi
          0x4c199b (+000b)  48 c1 ee 20                                   shr     rsi, 0x20
          0x4c199f (+000f)  21 f7                                         and     edi, esi
          0x4c19a1 (+0011)  ff c7                                         inc     edi
          0x4c19a3 (+0013)  0f 94 c0                                      sete    al
          0x4c19a6 (+0016)  c3                                            ret
