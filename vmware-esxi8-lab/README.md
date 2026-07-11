# Nested ESXi 8 DirectPath lab

These scripts reproduce the local QEMU -> ESXi -> EFI Linux DirectPath tests
described in `../vmware-esxi8-directpath-local-results.md`.

They assume the original workspace layout under `/mnt/e/Code/PCI`, an existing
ESXi system/datastore image under `/root/vm/esxi8-mf`, and a private Caveat entry
named `esxi8-auto-codex-credentials`.  No credential is stored here.

Main entry points:

- `start-qemu-esxi8-mf.sh`: outer q35/VT-d topology, optional BAR, ACS, link,
  legacy-bridge, root-complex, and trace controls.
- `Run-EsxiDirectPathMmioCase.ps1`: one MMIO case with effective VMX, serial,
  and `vmware.log` collection.
- `Test-EsxiDirectPathLifecycle.ps1`: snapshot, suspend, forced-off, and restart.
- `Test-EsxiDirectPathStress.ps1`: repeated start/stop cycles.
- `esxi_dynamic_directpath.py` and `test_esxi_dynamic_directpath.py`: pyVmomi
  candidate inventory and runtime `assignedId` validation.
- `build-esxi-l3-probe-iso.sh`: rebuilds the probe ISO from the locally prepared
  initrd tree.  Kernel, initrd, and ISO binaries are intentionally excluded.

Important environment switches:

```bash
QEMU_ESXI_IVSHMEM_SIZE=2G
QEMU_ESXI_TOPOLOGY=pcie       # pcie, root, or legacy
QEMU_ESXI_DISABLE_ACS=1
QEMU_ESXI_LINK_SPEED=8
QEMU_ESXI_LINK_WIDTH=4
QEMU_ESXI_TRACE=1
```
