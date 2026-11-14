; R04 依赖桥展开与宿主 owner 检查
; build 24280767 / PCIPassthru ELF in sb.v00
; image SHA256 ca5e97d71c9360804c2b3d480e4272c52d0225efbe45fe0b359c739da41077ca
; section-relative .text offset / PCIPassthruFPTAllowPassthru
; [0x255e, 0x263e) file offset 0x259e
; window SHA256 b638c2c92527727806b7b91e255176c18f49c8b20f56722bd933388e2926e6d3

            0x255e (+0016)  e8 00 00 00 00                                call    0x2563 ; REL type=2 PCI_GetDevice A=-4
            0x2563 (+001b)  48 85 c0                                      test    rax, rax
            0x2566 (+001e)  0f 84 c2 01 00 00                             je      0x272e ; branch leaves this window
            0x256c (+0024)  48 8d 74 24 18                                lea     rsi, [rsp + 0x18]
            0x2571 (+0029)  48 89 c7                                      mov     rdi, rax
            0x2574 (+002c)  49 89 c4                                      mov     r12, rax
            0x2577 (+002f)  e8 00 00 00 00                                call    0x257c ; REL type=2 VMKPCIPassthru_GetDeviceDependencies A=-4
            0x257c (+0034)  41 89 c5                                      mov     r13d, eax
            0x257f (+0037)  85 c0                                         test    eax, eax
            0x2581 (+0039)  0f 85 3d 01 00 00                             jne     0x26c4 ; branch leaves this window
            0x2587 (+003f)  8b 7c 24 18                                   mov     edi, dword ptr [rsp + 0x18]
            0x258b (+0043)  41 39 3c 24                                   cmp     dword ptr [r12], edi
            0x258f (+0047)  0f 84 18 01 00 00                             je      0x26ad ; branch leaves this window
            0x2595 (+004d)  e8 00 00 00 00                                call    0x259a ; REL type=2 PCI_GetDevice A=-4
            0x259a (+0052)  48 89 c7                                      mov     rdi, rax
            0x259d (+0055)  48 89 c3                                      mov     rbx, rax
            0x25a0 (+0058)  e8 00 00 00 00                                call    0x25a5 ; REL type=2 PCI_GetDeviceCountUnderBridge A=-4
            0x25a5 (+005d)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 passthruHeap A=-4
            0x25ac (+0064)  8d 34 c5 00 00 00 00                          lea     esi, [rax*8]
            0x25b3 (+006b)  41 89 c7                                      mov     r15d, eax
            0x25b6 (+006e)  e8 00 00 00 00                                call    0x25bb ; REL type=2 Heap_Alloc A=-4
            0x25bb (+0073)  48 89 44 24 08                                mov     qword ptr [rsp + 8], rax
            0x25c0 (+0078)  48 85 c0                                      test    rax, rax
            0x25c3 (+007b)  0f 84 a1 01 00 00                             je      0x276a ; branch leaves this window
            0x25c9 (+0081)  48 8b 54 24 08                                mov     rdx, qword ptr [rsp + 8]
            0x25ce (+0086)  48 89 df                                      mov     rdi, rbx
            0x25d1 (+0089)  44 89 fe                                      mov     esi, r15d
            0x25d4 (+008c)  e8 00 00 00 00                                call    0x25d9 ; REL type=2 PCI_GetDevicesUnderBridge A=-4
            0x25d9 (+0091)  89 c3                                         mov     ebx, eax
            0x25db (+0093)  85 c0                                         test    eax, eax
            0x25dd (+0095)  0f 85 92 01 00 00                             jne     0x2775 ; branch leaves this window
            0x25e3 (+009b)  45 85 ff                                      test    r15d, r15d
            0x25e6 (+009e)  7e 36                                         jle     0x261e
            0x25e8 (+00a0)  48 8b 4c 24 08                                mov     rcx, qword ptr [rsp + 8]
            0x25ed (+00a5)  41 8d 47 ff                                   lea     eax, [r15 - 1]
            0x25f1 (+00a9)  48 89 cb                                      mov     rbx, rcx
            0x25f4 (+00ac)  4c 8d 7c c1 08                                lea     r15, [rcx + rax*8 + 8]
            0x25f9 (+00b1)  48 8b 3b                                      mov     rdi, qword ptr [rbx]
            0x25fc (+00b4)  48 85 ff                                      test    rdi, rdi
            0x25ff (+00b7)  74 06                                         je      0x2607
            0x2601 (+00b9)  f6 47 04 02                                   test    byte ptr [rdi + 4], 2
            0x2605 (+00bd)  75 0e                                         jne     0x2615
            0x2607 (+00bf)  e8 00 00 00 00                                call    0x260c ; REL type=2 PCI_GetDeviceOwnership A=-4
            0x260c (+00c4)  83 f8 01                                      cmp     eax, 1
            0x260f (+00c7)  0f 85 79 01 00 00                             jne     0x278e ; branch leaves this window
            0x2615 (+00cd)  48 83 c3 08                                   add     rbx, 8
            0x2619 (+00d1)  49 39 df                                      cmp     r15, rbx
            0x261c (+00d4)  75 db                                         jne     0x25f9
            0x261e (+00d6)  48 8b 74 24 08                                mov     rsi, qword ptr [rsp + 8]
            0x2623 (+00db)  48 8b 3d 00 00 00 00                          mov     rdi, qword ptr [rip] ; REL type=2 passthruHeap A=-4
            0x262a (+00e2)  e8 00 00 00 00                                call    0x262f ; REL type=2 Heap_Free A=-4
            0x262f (+00e7)  be 26 00 00 00                                mov     esi, 0x26
            0x2634 (+00ec)  48 8d 7c 24 18                                lea     rdi, [rsp + 0x18]
            0x2639 (+00f1)  e8 00 00 00 00                                call    0x263e ; REL type=2 HostID_GetString A=-4
