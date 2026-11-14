# 07 汇编分支与运行证据的逐项对应

本章重新读取已保存的回执与日志，不是新开了一轮 VM 实验。每个投影都有来源文件及 SHA-256，机器可读数据在 [runtime-crosswalk.json](evidence/runtime-crosswalk.json)。

## 1 先看实验真正得到的结果

| 场景 | build | 设备数 | task | 最终 VM 状态 | 回执 |
| --- | --- | --- | --- | --- | --- |
| legacy-A | 24280767 | 1 | success | poweredOn | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/native-mf-power-a.json) |
| legacy-B | 24280767 | 1 | success | poweredOn | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/native-mf-power-b.json) |
| legacy-AB | 24280767 | 2 | error | poweredOff | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/native-mf-power-both.json) |
| legacy-BA | 24280767 | 2 | error | poweredOff | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/native-mf-power-reverse.json) |
| pcie-AB | 24280767 | 2 | success | poweredOn | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/root-control/root-control-power-both.json) |
| pcie-BA | 24280767 | 2 | success | poweredOn | [原文件](../../evidence/vmware-legacy-bridge-cause-20261112/raw/root-control/root-control-power-reverse.json) |
| u3k-AB | 25595708 | 2 | error | poweredOff | [原文件](../../evidence/vmware-passthrough-version-review-20261113/raw/u3k/u3k-default-power-both.json) |
| 9.1-AB | 25433460 | 2 | error | poweredOff | [原文件](../../evidence/vmware-passthrough-version-review-20261113/raw/esx91/esx91-default-power-both.json) |
| 9.1-native-pci-AB | 25433460 | 2 | error | poweredOff | [原文件](../../evidence/vmware-passthrough-version-review-20261113/raw/esx91-native/esx91-nativepci-power-both.json) |

这些结果只表示对应 task 和 VM 电源状态。11 月这批用例使用空 EFI VM，不能自动升级为 guest 设备驱动或业务 I/O 验收。

传统桥正反顺序都失败，而单 A / 单 B 成功，说明故障跟随后登记者；PCIe 对照正反顺序都成功，又排除了“同一 VM 的两个设备原则上不能共用一个域”的说法。

## 2 表采样记录了什么

以下为旧 `native-mf-context-both.json` 的直接字段投影：保留三个状态变化及每个相关 context 的 present、domainId、pageTable。它是硬件表解码，不是对内核 PCI 对象 `+0x378` 的直接内存转储。

来源 SHA-256：`8bee7fb21f9b27a6ab6d60889f48b029cf9c9be438c36829e8a90eae39ddc659`；采样轮次 130。

```json
[
  {
    "changeIndex": 0,
    "contexts": {
      "01:00.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:00.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:01.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:01.1": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      }
    }
  },
  {
    "changeIndex": 1,
    "contexts": {
      "01:00.0": {
        "present": true,
        "domainId": 2,
        "pageTable": "0x168ddb000"
      },
      "02:00.0": {
        "present": true,
        "domainId": 2,
        "pageTable": "0x168ddb000"
      },
      "02:01.0": {
        "present": true,
        "domainId": 2,
        "pageTable": "0x168ddb000"
      },
      "02:01.1": {
        "present": true,
        "domainId": 2,
        "pageTable": "0x168ddb000"
      }
    }
  },
  {
    "changeIndex": 2,
    "contexts": {
      "01:00.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:00.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:01.0": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      },
      "02:01.1": {
        "present": true,
        "domainId": 1,
        "pageTable": "0x10b25b000"
      }
    }
  }
]
```

代码证据 [05 I04/I05](05-domain-lifecycle.md#5-切域为何会覆盖别名桥子树) 解释了整组改变的原因；表采样支持本用例中确实发生了整组客体关联和失败回退。多项读取不是原子快照，不能用它推导亚毫秒级的跨组件精确先后顺序。

## 3 较新版本保留的到底是哪一条条件

build 24280767 的原分支在 [05 I01](05-domain-lifecycle.md#1-上层只接受一个状态码)。下面直接展示另两份真实模块的指令。

<!-- evidence:V01:begin -->

### 切片 V01 U3k 25595708 的已有域分支

- 文件：`PCIPassthru ELF in sb.v00`，build `25595708`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x4734`，函数大小 `3926` 字节。
- 窗口：`0x5307` 到 `0x536a`（右端不含）；文件偏移 `0x5347`；23 条指令。
- 窗口 SHA-256：`d5319d216ca07c6e18b210430b0be14f0fc6600f1699889e061b0c9939164e8d`。[单独查看汇编](snippets/V01.asm)

```asm
            0x5307 (+0bd3)  e8 00 00 00 00                                call    0x530c ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x530c (+0bd8)  44 8b 54 24 50                                mov     r10d, dword ptr [rsp + 0x50]
            0x5311 (+0bdd)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x5316 (+0be2)  89 c3                                         mov     ebx, eax
            0x5318 (+0be4)  0f 84 27 fa ff ff                             je      0x4d45 ; branch leaves this window
            0x531e (+0bea)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x5325 (+0bf1)  44 89 54 24 08                                mov     dword ptr [rsp + 8], r10d
            0x532a (+0bf6)  e8 00 00 00 00                                call    0x532f ; REL type=2 SP_Unlock A=-4
            0x532f (+0bfb)  48 83 ec 08                                   sub     rsp, 8
            0x5333 (+0bff)  44 89 f2                                      mov     edx, r14d
            0x5336 (+0c02)  31 c0                                         xor     eax, eax
            0x5338 (+0c04)  53                                            push    rbx
            0x5339 (+0c05)  44 8b 54 24 18                                mov     r10d, dword ptr [rsp + 0x18]
            0x533e (+0c0a)  be b8 14 00 00                                mov     esi, 0x14b8
            0x5343 (+0c0f)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC59 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x534a (+0c16)  44 8b 4c 24 6c                                mov     r9d, dword ptr [rsp + 0x6c]
            0x534f (+0c1b)  8b 4c 24 70                                   mov     ecx, dword ptr [rsp + 0x70]
            0x5353 (+0c1f)  41 be 05 00 ad 0b                             mov     r14d, 0xbad0005
            0x5359 (+0c25)  45 89 d0                                      mov     r8d, r10d
            0x535c (+0c28)  e8 00 00 00 00                                call    0x5361 ; REL type=2 _Warning A=-4
            0x5361 (+0c2d)  41 59                                         pop     r9
            0x5363 (+0c2f)  41 5a                                         pop     r10
            0x5365 (+0c31)  e9 30 fe ff ff                                jmp     0x519a ; branch leaves this window
```

<!-- evidence:V01:end -->

该窗口的关键是 `0x5311` 比较 `0x0bad0003`，`0x5318` 相等跳正常路径；失败路径设置 `0x0bad0005`。`mov esi,0x14b8` 的十进制值为 5304，对应该 build 的日志源行号。

<!-- evidence:V02:begin -->

### 切片 V02 9.1 25433460 的已有域分支

- 文件：`PCIPassthru ELF in sb.v00`，build `25433460`；地址类型：section-relative .text offset。
- 函数：`PCIPassthruRegisterDeviceInt`；入口 `0x3890`，函数大小 `3818` 字节。
- 窗口：`0x4418` 到 `0x4472`（右端不含）；文件偏移 `0x4458`；21 条指令。
- 窗口 SHA-256：`630ca9e9e00dad36adf3cf96409b40556dafd619a17f64b73b9588b8378b92ce`。[单独查看汇编](snippets/V02.asm)

```asm
            0x4418 (+0b88)  e8 00 00 00 00                                call    0x441d ; REL type=2 IOMMU_GetAddressDomain A=-4
            0x441d (+0b8d)  41 89 c7                                      mov     r15d, eax
            0x4420 (+0b90)  3d 03 00 ad 0b                                cmp     eax, 0xbad0003
            0x4425 (+0b95)  0f 84 a1 fc ff ff                             je      0x40cc ; branch leaves this window
            0x442b (+0b9b)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 pcipCfgLock A=-4
            0x4432 (+0ba2)  e8 00 00 00 00                                call    0x4437 ; REL type=2 SP_Unlock A=-4
            0x4437 (+0ba7)  44 89 3c 24                                   mov     dword ptr [rsp], r15d
            0x443b (+0bab)  41 89 d8                                      mov     r8d, ebx
            0x443e (+0bae)  0f b6 cf                                      movzx   ecx, bh
            0x4441 (+0bb1)  89 da                                         mov     edx, ebx
            0x4443 (+0bb3)  41 c1 e8 03                                   shr     r8d, 3
            0x4447 (+0bb7)  83 e3 07                                      and     ebx, 7
            0x444a (+0bba)  be b0 16 00 00                                mov     esi, 0x16b0
            0x444f (+0bbf)  c1 ea 10                                      shr     edx, 0x10
            0x4452 (+0bc2)  41 89 d9                                      mov     r9d, ebx
            0x4455 (+0bc5)  41 83 e0 1f                                   and     r8d, 0x1f
            0x4459 (+0bc9)  31 c0                                         xor     eax, eax
            0x445b (+0bcb)  48 8d 3d 00 00 00 00                          lea     rdi, [rip] ; REL type=2 .LC48 A=-4 "PCIPassthru: %d: Expected no IOMMU domain for %04x:%02x:%02x.%x, got %'us\n"
            0x4462 (+0bd2)  41 bf 05 00 ad 0b                             mov     r15d, 0xbad0005
            0x4468 (+0bd8)  e8 00 00 00 00                                call    0x446d ; REL type=2 _Warning A=-4
            0x446d (+0bdd)  e9 2f f8 ff ff                                jmp     0x3ca1 ; branch leaves this window
```

<!-- evidence:V02:end -->

该窗口在 `0x4420` 比较同一状态，相等跳 `0x40cc`；失败同样选择 `0x0bad0005`。`0x16b0` 的十进制值为 5808。

| build | 域查询 call | 比较位置 | 正常继续 | 警告源行号 |
| --- | --- | --- | --- | --- |
| 24280767 | `0x53da` | `0x53e4` | `0x50c9` | 5294 |
| 25595708 | `0x5307` | `0x5311` | `0x4d45` | 5304 |
| 25433460 | `0x4418` | `0x4420` | `0x40cc` | 5808 |

不同 build 的完整函数不是逐字节相同；本表只对所选条件负责。不能由同一句诊断字符串推导整个实现未变。

## 4 对应的实际警告行

**build 25595708**：[已有摘录](../../evidence/vmware-passthrough-version-review-20261113/logs/u3k-both-vmkernel.txt)，本文件第 11 行，文件 SHA-256 `c737e97988998570031fc766a7beb036d30af387fe91237ba78f93bc4a4c71be`。

```text
2266: 2026-11-12T16:42:03.266Z Wa(180) vmkwarning: cpu0:133494)WARNING: PCIPassthru: 5304: Expected no IOMMU domain for 0000:02:01.1, got Success
```

**build 25433460**：[已有摘录](../../evidence/vmware-passthrough-version-review-20261113/logs/esx91-both-vmkernel.txt)，本文件第 9 行，文件 SHA-256 `e1f794583e5337261e4d4d24c07861138faa9ecd7c41b478e4dead21dd9691e4`。

```text
2497: 2026-11-12T17:00:46.199Z -WARNING vmkwarning - [esx@4413] cpu2:133717) PCIPassthru: 5808: Expected no IOMMU domain for 0000:02:01.1, got Success
```

两条警告分别来自对应任务时间窗内的既有日志摘录，其原始日志来源和行号仍保留在被引用的文件中。源行号与汇编立即数对应，开机回执也为失败，三者共同支持“执行到了这一类拒绝路径”。

## 5 什么结论仍然没有成立

- 没有在保留共享身份时验证一个修复后的 VMware 二进制。
- 没有完整还原 8.0 U3k / 9.1 的所有管理库、依赖和调度分支。
- 未取得介质的 25782009 不能声称已修复或未修复。
- 未把此合成桥用例推广为全部物理 PCIe-to-PCI 桥的支持结论。
- 该机制与 8 月“释放时端点失去响应，健康 sibling 也暂时不能分配”的实验不同，不能把两个根因混为一谈。

较新版本来源与升级证明见[前序版本报告](../vmware-passthrough-version-review-20261113/README.md)，原始同 build 控制见[传统桥报告](../vmware-legacy-bridge-cause-20261112/README.md)。
