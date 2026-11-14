# 函数到正文的索引

地址类型和模块 SHA-256 见 [阅读说明](00-reading-guide.md)。这里按原始函数聚合，多个切片可能来自同一函数。

| 函数或人工标签 | build | ELF 入口 | 函数字节数 | 正文切片 |
| --- | --- | --- | --- | --- |
| Hardware_PCIPassthruDependentGet | 24280767 | 0x420000072288 | 131 | [A05](02-dependency-construction.md) |
| Hardware_PCIPassthruShareableSet | 24280767 | 0x42000007263c | 78 | [M03](06-reset-map-acs.md) |
| Hardware_PCIIsInIommuScope | 24280767 | 0x4200000734b4 | 90 | [A04](01-capable.md) |
| PCIBridge_IsAliasing | 24280767 | 0x4200000e5138 | 27 | [D04](02-dependency-construction.md) |
| PCI_IsPCIeEndpointDevice | 24280767 | 0x4200000eb43c | 37 | [D06](02-dependency-construction.md) |
| PCI_SetMultiFuncDependency | 24280767 | 0x4200000eb734 | 70 | [M04](06-reset-map-acs.md) |
| PCI_CanDeviceBeAssignedToIOMMUDomain | 24280767 | 0x4200000eb9b8 | 62 | [I09](05-domain-lifecycle.md) |
| PCI_GetTopmostAliasingBridge | 24280767 | 0x4200000ebc00 | 80 | [D03](02-dependency-construction.md) |
| PCIE_EnforceACS | 24280767 | 0x4200000f52d4 | 591 | [M07](06-reset-map-acs.md) |
| PCI_HasD3D0Reset | 24280767 | 0x4200000fc074 | 99 | [M05](06-reset-map-acs.md) |
| PCI_FindResetMethod | 24280767 | 0x4200000fc450 | 358 | [M06](06-reset-map-acs.md) |
| PCI_HasFuncIndependentReset | 24280767 | 0x4200000fc5f0 | 26 | [D05](02-dependency-construction.md) |
| IOMMUHandleBridgePCIEToPCI.isra.0 | 24280767 | 0x4200001640b0 | 267 | [I08](05-domain-lifecycle.md) |
| IOMMUSwitchDeviceIterator | 24280767 | 0x420000164470 | 408 | [I05](05-domain-lifecycle.md) |
| IOMMU_GetReqIdDependencies | 24280767 | 0x420000164608 | 69 | [D02](02-dependency-construction.md) |
| IOMMU_GetDeviceDomain | 24280767 | 0x4200001653bc | 144 | [I03](05-domain-lifecycle.md) |
| IOMMU_GetAddressDomain | 24280767 | 0x42000016544c | 60 | [I02](05-domain-lifecycle.md) |
| IOMMU_SwitchAddressDomain | 24280767 | 0x4200001654e4 | 257 | [I04](05-domain-lifecycle.md) |
| VMKPCIPassthru_GetDeviceDependencies | 24280767 | 0x4200001a0e38 | 197 | [D01](02-dependency-construction.md) |
| PCIPassthruFPTAllowPassthru | 24280767 | 0x2548 | 604 | [R04](04-vm-admission.md) [R05](04-vm-admission.md) [R06](04-vm-admission.md) |
| PCIPassthruRegisterDeviceInt | 24280767 | 0x4b6c | 3720 | [R03](04-vm-admission.md) [R07](04-vm-admission.md) [R08](04-vm-admission.md) [R09](04-vm-admission.md) [I01](05-domain-lifecycle.md) |
| PCIPassthruEnablePCIDevice | 24280767 | 0x7c40 | 731 | [I06](05-domain-lifecycle.md) [I07](05-domain-lifecycle.md) |
| PCIPassthruRegisterDevice | 24280767 | 0x9a50 | 299 | [R01](04-vm-admission.md) [R02](04-vm-admission.md) |
| PCIPassthruRegisterDeviceInt | 25433460 | 0x3890 | 3818 | [V02](07-runtime-and-versions.md) |
| PCIPassthruRegisterDeviceInt | 25595708 | 0x4734 | 3926 | [V01](07-runtime-and-versions.md) |
| PciDeviceImpl::GetSeg | 24280767 | 0x4c1980 | 4 | [O14](03-owner-transitions.md) |
| PciDeviceImpl::GetBus | 24280767 | 0x4c1984 | 4 | [O15](03-owner-transitions.md) |
| PciDeviceImpl::GetSlot | 24280767 | 0x4c1988 | 4 | [O16](03-owner-transitions.md) |
| PciDeviceImpl::GetFunction | 24280767 | 0x4c198c | 4 | [O17](03-owner-transitions.md) |
| 匿名无效 SBDF 辅助函数 | 24280767 | 0x4c1990 | 23 | [A03](01-capable.md) |
| PciDeviceImpl::IsPassthruCapable | 24280767 | 0x4c2438 | 174 | [A01](01-capable.md) |
| PciDeviceImpl::GetOwnerString | 24280767 | 0x4c3590 | 71 | [O11](03-owner-transitions.md) |
| PciDeviceImpl::ValidateOwnerToVmkernel | 24280767 | 0x4c35d8 | 249 | [O13](03-owner-transitions.md) |
| PciDeviceImpl::SetConfiguredDevOwnerNoDeps | 24280767 | 0x4c62c6 | 397 | [O09](03-owner-transitions.md) |
| PciDeviceImpl::SetFromSBDF | 24280767 | 0x4c6bca | 611 | [A02](01-capable.md) |
| PciDeviceImpl::constructor | 24280767 | 0x4c6f46 | 283 | [O10](03-owner-transitions.md) |
| PciDeviceImpl::GetDependantDevice | 24280767 | 0x4c7142 | 109 | [O05](03-owner-transitions.md) |
| PciDeviceImpl::SetConfiguredDeviceOwner | 24280767 | 0x4c78a0 | 1664 | [O07](03-owner-transitions.md) [O08](03-owner-transitions.md) |
| PciDeviceImpl::SwitchOwnerToVmkernel | 24280767 | 0x4c7f20 | 115 | [O12](03-owner-transitions.md) |
| PciDeviceImpl::LoadPassthruMap | 24280767 | 0x4c8e7a | 1010 | [M01](06-reset-map-acs.md) |
| PciDeviceImpl::RestoreFptShareableAttr | 24280767 | 0x4c9714 | 134 | [M02](06-reset-map-acs.md) |
| PciDeviceImpl::GetDependentChildDevices | 24280767 | 0x4cb4c0 | 282 | [O06](03-owner-transitions.md) |
| PciDeviceImpl::ValidateOwnerToPassthru | 24280767 | 0x4cbaac | 1233 | [O01](03-owner-transitions.md) [O02](03-owner-transitions.md) [O03](03-owner-transitions.md) [O04](03-owner-transitions.md) |
