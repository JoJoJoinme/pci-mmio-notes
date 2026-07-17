from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence

from .allocator import AllocationPolicy, plan_mmio
from .capability import CapabilityPolicy, evaluate_passthrough
from .linux_sysfs import scan_linux_sysfs
from .model import AddressRange, HostInventory


_INHERIT = object()


def _tri_state(value: str) -> bool | None:
    normalized = value.lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    if normalized == "unknown":
        return None
    raise argparse.ArgumentTypeError("expected true, false, or unknown")


def _range(value: str) -> AddressRange:
    try:
        return AddressRange.parse(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _write_json(value: dict[str, Any], output: str) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if output == "-":
        print(text, end="")
    else:
        Path(output).write_text(text, encoding="utf-8")


def _load_inventory(path: str) -> HostInventory:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    return HostInventory.from_dict(value)


def _allocation_policy(args: argparse.Namespace) -> AllocationPolicy:
    return AllocationPolicy(
        prefer_64bit_high=args.prefer_high,
        force_64bit_high=args.force_high,
        top_down_high=args.top_down_high,
        power_of_two_high_aperture=not args.no_power_of_two_aperture,
    )


def _add_mmio_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mmio32",
        action="append",
        type=_range,
        required=True,
        metavar="START:END",
        help="below-4G half-open window; repeat for disjoint windows",
    )
    parser.add_argument(
        "--mmio64",
        action="append",
        type=_range,
        default=[],
        metavar="START:END",
        help="above-4G half-open window; repeat for disjoint windows",
    )
    parser.add_argument(
        "--reserve",
        action="append",
        type=_range,
        default=[],
        metavar="START:END",
        help="reserved range removed from every overlapping window",
    )
    parser.add_argument("--prefer-high", action="store_true")
    parser.add_argument("--force-high", action="store_true")
    parser.add_argument("--top-down-high", action="store_true")
    parser.add_argument("--no-power-of-two-aperture", action="store_true")
    parser.add_argument("--firmware", choices=("ovmf", "seabios"), default="ovmf")
    parser.add_argument("--host-bridge", default="q35-pcihost")


def _parse_leases(values: Sequence[str]) -> dict[str, str]:
    leases: dict[str, str] = {}
    for value in values:
        try:
            bdf, owner = value.split("=", 1)
        except ValueError as error:
            raise ValueError(f"lease must use BDF=OWNER: {value!r}") from error
        if not bdf or not owner:
            raise ValueError(f"lease must use BDF=OWNER: {value!r}")
        leases[bdf.lower()] = owner
    return leases


def _scan(args: argparse.Namespace) -> int:
    inventory = scan_linux_sysfs(
        sysfs_root=Path(args.sysfs_root),
        proc_cmdline=Path(args.proc_cmdline),
        interrupt_remapping=args.interrupt_remapping,
        selected_bdfs=args.device,
    )
    _write_json(inventory.to_dict(), args.output)
    return 0


def _allocate(args: argparse.Namespace) -> int:
    inventory = _load_inventory(args.inventory)
    requested = [bdf.lower() for bdf in args.device]
    missing = [bdf for bdf in requested if bdf not in inventory.devices]
    if missing:
        raise ValueError(f"devices absent from inventory: {', '.join(missing)}")
    bars = tuple(bar for bdf in requested for bar in inventory.devices[bdf].bars)
    result = plan_mmio(
        bars,
        low_windows=args.mmio32,
        high_windows=args.mmio64,
        reserved=args.reserve,
        policy=_allocation_policy(args),
    )
    output = {
        "devices": requested,
        "result": result.to_dict(firmware=args.firmware, host_bridge=args.host_bridge),
    }
    _write_json(output, args.output)
    return 0 if result.success else 1


def _capable(args: argparse.Namespace) -> int:
    inventory = _load_inventory(args.inventory)
    leases = dict(inventory.leases)
    leases.update(_parse_leases(args.lease))
    interrupt_remapping = (
        inventory.interrupt_remapping
        if args.interrupt_remapping is _INHERIT
        else args.interrupt_remapping
    )
    inventory = replace(
        inventory,
        leases=leases,
        interrupt_remapping=interrupt_remapping,
    )
    result = evaluate_passthrough(
        inventory,
        args.target,
        low_windows=args.mmio32,
        high_windows=args.mmio64,
        reserved=args.reserve,
        payload_devices=args.payload,
        lease_owner=args.lease_owner,
        policy=CapabilityPolicy(
            require_interrupt_remapping=not args.no_require_interrupt_remapping,
            allow_acs_override=args.allow_acs_override,
            allow_bus_reset=not args.no_bus_reset,
            allow_estimated_reset_domain=args.allow_estimated_reset_domain,
            allow_host_driver_rebind=not args.no_host_driver_rebind,
            qualified_shared_attach_groups=tuple(
                args.qualified_shared_attach_group
            ),
            trust_domain=args.trust_domain,
        ),
        allocation_policy=_allocation_policy(args),
    )
    _write_json(
        result.to_dict(firmware=args.firmware, host_bridge=args.host_bridge),
        args.output,
    )
    return 0 if result.attachable else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pci-resource-model",
        description="Probe inventory, plan guest MMIO, and evaluate passthrough capability",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="read the Linux kernel-probed PCI inventory without BAR writes"
    )
    scan.add_argument("--sysfs-root", default="/sys/bus/pci/devices")
    scan.add_argument("--proc-cmdline", default="/proc/cmdline")
    scan.add_argument(
        "--interrupt-remapping",
        type=_tri_state,
        default=None,
        metavar="STATE",
    )
    scan.add_argument("--device", action="append", default=None)
    scan.add_argument("--output", default="-")
    scan.set_defaults(handler=_scan)

    allocate = subparsers.add_parser(
        "allocate", help="transactionally place selected devices' memory BARs"
    )
    allocate.add_argument("--inventory", required=True)
    allocate.add_argument("--device", action="append", required=True)
    allocate.add_argument("--output", default="-")
    _add_mmio_arguments(allocate)
    allocate.set_defaults(handler=_allocate)

    capable = subparsers.add_parser(
        "capable", help="evaluate eligible, available, and attachable states"
    )
    capable.add_argument("--inventory", required=True)
    capable.add_argument("--target", required=True)
    capable.add_argument("--payload", action="append", default=None)
    capable.add_argument("--lease", action="append", default=[], metavar="BDF=OWNER")
    capable.add_argument("--lease-owner", default="candidate-vm")
    capable.add_argument(
        "--interrupt-remapping",
        type=_tri_state,
        default=_INHERIT,
        metavar="STATE",
    )
    acs_policy = capable.add_mutually_exclusive_group()
    acs_policy.add_argument(
        "--allow-acs-override",
        dest="allow_acs_override",
        action="store_true",
        default=True,
        help="accept override only with a trusted complete physical domain (default)",
    )
    acs_policy.add_argument(
        "--deny-acs-override",
        dest="allow_acs_override",
        action="store_false",
        help="reject every function whose isolation depends on ACS override",
    )
    capable.add_argument("--no-require-interrupt-remapping", action="store_true")
    capable.add_argument("--no-bus-reset", action="store_true")
    capable.add_argument("--allow-estimated-reset-domain", action="store_true")
    capable.add_argument("--no-host-driver-rebind", action="store_true")
    capable.add_argument(
        "--qualified-shared-attach-group",
        action="append",
        default=[],
        help="exact exclusive attach group qualified for same-VM co-assignment",
    )
    capable.add_argument("--trust-domain", default="untrusted-vm")
    capable.add_argument("--output", default="-")
    _add_mmio_arguments(capable)
    capable.set_defaults(handler=_capable)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
