#!/usr/bin/env python3
"""Run the C21 Qman VFIO provider gate in two real QEMU guests.

The two guests use the same virtual PCI endpoint and the same global VFIO
unsafe switch.  The negative guest has no vIOMMU and must be rejected by the
Qman provider.  The positive guest has an Intel vIOMMU and must complete an
actual VFIO cdev/IOMMUFD attach, or an explicitly enabled lab-only legacy
TYPE1v2/TYPE1 attach.

This runner deliberately embeds the byte-for-byte provider source in the
NoCloud seed.  The guest reports the embedded source hash so the retained
proof cannot silently exercise a different installed package.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_PROVIDER = (
    REPO_ROOT / "pci-resource-model" / "pci_resource_model" / "vfio_provider.py"
)
DEFAULT_QEMU = Path("/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64")
DEFAULT_BASE_IMAGE = Path(
    "/mnt/e/Code/PCI/_artifacts/noble-server-cloudimg-amd64.img"
)
DEFAULT_OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE.fd")
DEFAULT_OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS.fd")

CASES = ("no-iommu", "iommu-with-unsafe-switch")
SUCCESS_PROVIDERS = {
    "vfio-cdev-iommufd",
    "vfio-legacy-type1v2",
    "vfio-legacy-type1",
}
NO_IOMMU_REASON = "DEVICE_NO_IOMMU_DMA_ISOLATION"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def command_output(command: list[str]) -> str:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.strip()


def yaml_base64_block(payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return "\n".join(
        f"      {encoded[index:index + 76]}"
        for index in range(0, len(encoded), 76)
    )


def guest_proof_script(case: str) -> str:
    if case not in CASES:
        raise ValueError(f"unsupported case: {case}")
    template = r'''#!/usr/bin/env bash
set -u
exec >/dev/ttyS0 2>&1

case_name=@@CASE@@
provider=/usr/local/lib/qman/vfio_provider.py
reboot_marker=/var/lib/qman-vfio-provider-iommu-rebooted
setup_failures=0

echo QMAN_PROVIDER_BOOT_BEGIN
echo QMAN_PROVIDER_CASE="$case_name"
echo QMAN_PROVIDER_KERNEL="$(uname -r)"
echo QMAN_PROVIDER_CMDLINE="$(cat /proc/cmdline)"

target=
for device in /sys/bus/pci/devices/*; do
    [ "$(cat "$device/vendor" 2>/dev/null)" = "0x8086" ] || continue
    [ "$(cat "$device/device" 2>/dev/null)" = "0x10d3" ] || continue
    target=$device
    break
done

if [ -z "$target" ]; then
    echo QMAN_PROVIDER_SETUP_ERROR=TARGET_NOT_FOUND
    echo QMAN_PROVIDER_RC=125
    echo QMAN_PROVIDER_END
    sync
    poweroff -f
    exit 0
fi

bdf=${target##*/}
pre_group=
if [ -L "$target/iommu_group" ]; then
    pre_group=$(basename "$(readlink -f "$target/iommu_group")")
fi
echo QMAN_PROVIDER_TARGET_BDF="$bdf"
echo QMAN_PROVIDER_PRE_BIND_GROUP="${pre_group:-none}"

if [ "$case_name" = "iommu-with-unsafe-switch" ] \
   && [ -z "$pre_group" ] \
   && [ ! -e "$reboot_marker" ]; then
    mkdir -p /etc/default/grub.d
    printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"' \
        > /etc/default/grub.d/99-qman-vfio-provider-iommu.cfg
    if update-grub; then
        touch "$reboot_marker"
        echo QMAN_PROVIDER_IOMMU_REBOOT_REQUESTED
        sync
        reboot
        exit 0
    fi
    echo QMAN_PROVIDER_SETUP_ERROR=UPDATE_GRUB_FAILED
    setup_failures=$((setup_failures + 1))
fi

if ! modprobe vfio enable_unsafe_noiommu_mode=1; then
    echo QMAN_PROVIDER_SETUP_ERROR=VFIO_MODULE_LOAD_FAILED
    setup_failures=$((setup_failures + 1))
fi
if [ -e /sys/module/vfio/parameters/enable_unsafe_noiommu_mode ]; then
    if ! printf 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode; then
        echo QMAN_PROVIDER_SETUP_ERROR=UNSAFE_SWITCH_WRITE_FAILED
        setup_failures=$((setup_failures + 1))
    fi
fi
if ! modprobe vfio-pci; then
    echo QMAN_PROVIDER_SETUP_ERROR=VFIO_PCI_MODULE_LOAD_FAILED
    setup_failures=$((setup_failures + 1))
fi
# A modular IOMMUFD implementation creates /dev/iommu here.  A built-in
# implementation legitimately makes modprobe fail, so the provider and the
# facts below remain the authoritative checks.
modprobe iommufd 2>/dev/null || true

unsafe=$(cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true)
echo QMAN_PROVIDER_UNSAFE_SWITCH="${unsafe:-missing}"

if ! printf vfio-pci > "$target/driver_override"; then
    echo QMAN_PROVIDER_SETUP_ERROR=DRIVER_OVERRIDE_FAILED
    setup_failures=$((setup_failures + 1))
fi
if [ -L "$target/driver" ]; then
    if ! printf '%s' "$bdf" > "$target/driver/unbind"; then
        echo QMAN_PROVIDER_SETUP_ERROR=DRIVER_UNBIND_FAILED
        setup_failures=$((setup_failures + 1))
    fi
fi
if ! printf '%s' "$bdf" > /sys/bus/pci/drivers/vfio-pci/bind; then
    echo QMAN_PROVIDER_SETUP_ERROR=VFIO_BIND_FAILED
    setup_failures=$((setup_failures + 1))
fi
sleep 2

driver=$(basename "$(readlink -f "$target/driver" 2>/dev/null)" 2>/dev/null || true)
post_group=
if [ -L "$target/iommu_group" ]; then
    post_group=$(basename "$(readlink -f "$target/iommu_group")")
fi
snapshot_epoch=$(date +%s)

# This is intentionally an independent standard-library sysfs reader.  It
# does not import vfio_provider.py or call its capture/hash helpers.  The
# canonical preimages are retained so a verifier can recompute both hashes.
python3 - "$bdf" > /run/qman-provider-expected-snapshot.json <<'PY'
import hashlib
import json
import sys
from pathlib import Path

bdf = sys.argv[1].lower()
device = (Path("/sys/bus/pci/devices") / bdf).resolve(strict=True)

def read_hex(name):
    return int((device / name).read_text(encoding="ascii").strip(), 0)

identity = {
    "vendorId": read_hex("vendor"),
    "deviceId": read_hex("device"),
    "subsystemVendorId": read_hex("subsystem_vendor"),
    "subsystemDeviceId": read_hex("subsystem_device"),
    "classCode": read_hex("class"),
    "revision": read_hex("revision"),
}
group_path = (device / "iommu_group").resolve(strict=True)
group_id = group_path.name
members = sorted(
    member.name.lower() for member in (group_path / "devices").iterdir()
)
identity_value = {
    "bdf": bdf,
    "classCode": identity["classCode"],
    "deviceId": identity["deviceId"],
    "kind": "qman-vfio-identity-v1",
    "revision": identity["revision"],
    "subsystemDeviceId": identity["subsystemDeviceId"],
    "subsystemVendorId": identity["subsystemVendorId"],
    "vendorId": identity["vendorId"],
}
group_value = {
    "bdf": bdf,
    "groupId": group_id,
    "kind": "qman-vfio-iommu-group-v1",
    "members": members,
}
identity_preimage = json.dumps(
    identity_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
)
group_preimage = json.dumps(
    group_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
)
result = {
    "schemaVersion": 1,
    "source": "independent-guest-sysfs-reader",
    "bdf": bdf,
    "identity": identity,
    "iommuGroup": {"groupId": group_id, "members": members},
    "identityPreimage": identity_preimage,
    "groupPreimage": group_preimage,
    "expectedIdentityHash": hashlib.sha256(
        identity_preimage.encode("ascii")
    ).hexdigest(),
    "expectedGroupHash": hashlib.sha256(group_preimage.encode("ascii")).hexdigest(),
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
read -r expected_identity_hash expected_group_hash < <(
    python3 - /run/qman-provider-expected-snapshot.json <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="ascii"))
print(value["expectedIdentityHash"], value["expectedGroupHash"])
PY
)
# This single-device experiment uses the canonical exact group binding as its
# topology snapshot hash.  The distinct CLI fields remain explicit.
topology_hash=$expected_group_hash

provider_command=(
    python3 "$provider"
    --bdf "$bdf"
    --snapshot-epoch "$snapshot_epoch"
    --topology-hash "$topology_hash"
    --expected-identity-hash "$expected_identity_hash"
    --expected-group-hash "$expected_group_hash"
    --allow-legacy-lab
    --sysfs-root /sys/bus/pci/devices
    --vfio-root /dev/vfio
    --iommufd /dev/iommu
)
printf '%q ' "${provider_command[@]}" > /run/qman-provider-command.txt
printf '\n' >> /run/qman-provider-command.txt

"${provider_command[@]}" \
    > /run/qman-provider.stdout \
    2> /run/qman-provider.stderr
provider_rc=$?

python3 - \
    "$case_name" "$bdf" "$pre_group" "$post_group" "$driver" "$unsafe" \
    "$snapshot_epoch" "$topology_hash" "$provider" "$setup_failures" \
    /run/qman-provider-expected-snapshot.json \
    > /run/qman-provider-facts.json <<'PY'
import hashlib
import json
import os
import platform
import stat
import sys
from pathlib import Path

(
    case_name,
    bdf,
    pre_group,
    post_group,
    driver,
    unsafe,
    snapshot_epoch,
    topology_hash,
    provider_name,
    setup_failures,
    expected_snapshot_name,
) = sys.argv[1:]

target = Path("/sys/bus/pci/devices") / bdf
node_records = []
vfio_root = Path("/dev/vfio")
if vfio_root.exists():
    for path in sorted(vfio_root.rglob("*"), key=lambda item: str(item)):
        if path.is_dir():
            continue
        try:
            metadata = path.stat()
            node_records.append(
                {
                    "path": str(path),
                    "fileType": stat.S_IFMT(metadata.st_mode),
                    "major": os.major(metadata.st_rdev),
                    "minor": os.minor(metadata.st_rdev),
                }
            )
        except FileNotFoundError:
            continue

cdev_paths = []
vfio_dev_root = target / "vfio-dev"
if vfio_dev_root.is_dir():
    cdev_paths = sorted(str(path) for path in vfio_dev_root.glob("vfio*"))

group_members = []
if post_group:
    group_root = Path("/sys/kernel/iommu_groups") / post_group / "devices"
    if group_root.is_dir():
        group_members = sorted(path.name for path in group_root.iterdir())

provider_path = Path(provider_name)
provider_hash = hashlib.sha256(provider_path.read_bytes()).hexdigest()
expected_snapshot = json.loads(
    Path(expected_snapshot_name).read_text(encoding="ascii")
)
facts = {
    "schemaVersion": 1,
    "case": case_name,
    "bdf": bdf,
    "preBindGroup": pre_group or None,
    "postBindGroup": post_group or None,
    "driver": driver or None,
    "unsafeSwitch": unsafe or None,
    "snapshotEpoch": int(snapshot_epoch),
    "topologyHash": topology_hash,
    "groupMembers": group_members,
    "vfioNodes": node_records,
    "targetVfioCdevSysfsPaths": cdev_paths,
    "iommufdPresent": Path("/dev/iommu").exists(),
    "providerSourceSha256": provider_hash,
    "expectedSnapshot": expected_snapshot,
    "setupFailures": int(setup_failures),
    "kernel": platform.release(),
    "kernelCommandLine": Path("/proc/cmdline").read_text(encoding="ascii").strip(),
    "bootId": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
}
print(json.dumps(facts, sort_keys=True, separators=(",", ":")))
PY

echo QMAN_PROVIDER_COMMAND_B64="$(base64 -w0 /run/qman-provider-command.txt)"
echo QMAN_PROVIDER_STDOUT_B64="$(base64 -w0 /run/qman-provider.stdout)"
echo QMAN_PROVIDER_STDERR_B64="$(base64 -w0 /run/qman-provider.stderr)"
echo QMAN_PROVIDER_FACTS_B64="$(base64 -w0 /run/qman-provider-facts.json)"
echo QMAN_PROVIDER_RC="$provider_rc"
echo QMAN_PROVIDER_END
sync
poweroff -f
'''
    return template.replace("@@CASE@@", shlex.quote(case))


def write_seed(
    case: str,
    seed_dir: Path,
    seed_image: Path,
    provider_source: bytes,
) -> None:
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(
        f"instance-id: qman-vfio-provider-{case}-{time.time_ns()}\n"
        f"local-hostname: qman-vfio-provider-{case}\n",
        encoding="ascii",
    )
    proof = guest_proof_script(case).encode("utf-8")
    service = b"""[Unit]\nDescription=Qman C21 VFIO provider proof\nAfter=cloud-final.service\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/qman-vfio-provider-proof.sh\n\n[Install]\nWantedBy=multi-user.target\n"""
    user_data = f"""#cloud-config
datasource_list: [ NoCloud, None ]
network:
  config: disabled
output:
  all: "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"
write_files:
  - path: /usr/local/lib/qman/vfio_provider.py
    permissions: '0644'
    encoding: b64
    content: |
{yaml_base64_block(provider_source)}
  - path: /usr/local/sbin/qman-vfio-provider-proof.sh
    permissions: '0755'
    encoding: b64
    content: |
{yaml_base64_block(proof)}
  - path: /etc/systemd/system/qman-vfio-provider-proof.service
    permissions: '0644'
    encoding: b64
    content: |
{yaml_base64_block(service)}
runcmd:
  - [ systemctl, enable, qman-vfio-provider-proof.service ]
  - [ /usr/local/sbin/qman-vfio-provider-proof.sh ]
"""
    (seed_dir / "user-data").write_text(user_data, encoding="ascii")
    subprocess.run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-output",
            str(seed_image),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "user-data",
            "meta-data",
        ],
        cwd=seed_dir,
        check=True,
    )


def extract_marker(log: str, marker: str) -> str | None:
    prefix = marker + "="
    matches: list[str] = []
    for raw_line in log.splitlines():
        line = raw_line.strip()
        position = line.find(prefix)
        if position >= 0:
            matches.append(line[position + len(prefix) :].strip())
    return matches[-1] if matches else None


def decode_base64_marker(log: str, marker: str) -> tuple[str, str | None]:
    encoded = extract_marker(log, marker)
    if encoded is None:
        return "", f"missing {marker}"
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-8"), None
    except (ValueError, UnicodeDecodeError) as error:
        return "", f"invalid {marker}: {error}"


def parse_json_object(text: str, label: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return None, f"{label} is not JSON: {error}"
    if not isinstance(value, dict):
        return None, f"{label} is not a JSON object"
    return value, None


def vfio_node_paths(facts: dict[str, Any]) -> set[str]:
    records = facts.get("vfioNodes")
    if not isinstance(records, list):
        return set()
    return {
        record["path"]
        for record in records
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }


def evaluate_case(
    case: str,
    return_code: int | None,
    provider_output: dict[str, Any] | None,
    facts: dict[str, Any] | None,
    provider_source_hash: str,
    timed_out: bool,
    parse_errors: list[str],
) -> tuple[bool, list[str]]:
    failures = list(parse_errors)
    if timed_out:
        failures.append("QEMU timed out")
    if provider_output is None or facts is None:
        return False, failures

    if facts.get("case") != case:
        failures.append("guest fact case does not match requested case")
    if facts.get("unsafeSwitch") not in {"Y", "1"}:
        failures.append("global unsafe switch was not enabled")
    if facts.get("driver") != "vfio-pci":
        failures.append("target was not bound to vfio-pci")
    if facts.get("setupFailures") != 0:
        failures.append("guest setup reported failures")
    if facts.get("providerSourceSha256") != provider_source_hash:
        failures.append("guest provider source hash does not match host source")
    if not isinstance(facts.get("postBindGroup"), str):
        failures.append("target has no post-bind IOMMU group identity")

    expected_snapshot = facts.get("expectedSnapshot")
    if not isinstance(expected_snapshot, dict):
        failures.append("guest facts have no independent expected snapshot")
        expected_snapshot = {}
    elif expected_snapshot.get("source") != "independent-guest-sysfs-reader":
        failures.append("expected snapshot did not come from the independent reader")
    for preimage_name, hash_name in (
        ("identityPreimage", "expectedIdentityHash"),
        ("groupPreimage", "expectedGroupHash"),
    ):
        preimage = expected_snapshot.get(preimage_name)
        expected_hash = expected_snapshot.get(hash_name)
        if not isinstance(preimage, str) or not isinstance(expected_hash, str):
            failures.append(f"expected snapshot is missing {preimage_name}/{hash_name}")
        elif hashlib.sha256(preimage.encode("ascii")).hexdigest() != expected_hash:
            failures.append(f"expected snapshot {hash_name} does not match its preimage")
    if facts.get("topologyHash") != expected_snapshot.get("expectedGroupHash"):
        failures.append("topology hash does not bind the retained exact group preimage")
    if facts.get("bdf") != expected_snapshot.get("bdf"):
        failures.append("expected snapshot BDF does not match guest facts")

    snapshot_group = expected_snapshot.get("iommuGroup")
    if not isinstance(snapshot_group, dict):
        failures.append("expected snapshot has no IOMMU group object")
        snapshot_group = {}
    if facts.get("postBindGroup") != snapshot_group.get("groupId"):
        failures.append("expected group ID does not match post-bind guest facts")
    if facts.get("groupMembers") != snapshot_group.get("members"):
        failures.append("expected group members do not match post-bind guest facts")

    post_group = facts.get("postBindGroup")
    nodes = vfio_node_paths(facts)
    if case == "no-iommu":
        if facts.get("preBindGroup") is not None:
            failures.append("negative target unexpectedly had a pre-bind IOMMU group")
        if isinstance(post_group, str):
            expected_node = f"/dev/vfio/noiommu-{post_group}"
            if expected_node not in nodes:
                failures.append(f"negative target did not expose {expected_node}")
            if f"/dev/vfio/{post_group}" in nodes:
                failures.append("negative target also exposed an IOMMU-backed group node")
        if return_code != 2:
            failures.append(f"negative provider exit was {return_code!r}, expected 2")
        if provider_output.get("status") != "error":
            failures.append("negative provider result was not status=error")
        if provider_output.get("reasonCode") != NO_IOMMU_REASON:
            failures.append(
                "negative provider reason was not DEVICE_NO_IOMMU_DMA_ISOLATION"
            )
    else:
        if not isinstance(facts.get("preBindGroup"), str):
            failures.append("positive target had no pre-bind vIOMMU group")
        if isinstance(post_group, str):
            expected_node = f"/dev/vfio/{post_group}"
            if expected_node not in nodes:
                failures.append(f"positive target did not expose {expected_node}")
            if f"/dev/vfio/noiommu-{post_group}" in nodes:
                failures.append("positive target exposed a no-IOMMU group node")
        if return_code != 0:
            failures.append(f"positive provider exit was {return_code!r}, expected 0")
        if provider_output.get("status") != "ok":
            failures.append("positive provider result was not status=ok")
        proof = provider_output.get("proof")
        if not isinstance(proof, dict):
            failures.append("positive provider result has no proof object")
        else:
            provider = proof.get("provider")
            if provider not in SUCCESS_PROVIDERS:
                failures.append(f"unaccepted positive provider: {provider!r}")
            if proof.get("bdf") != facts.get("bdf"):
                failures.append("provider proof BDF does not match guest facts")
            if proof.get("snapshotEpoch") != facts.get("snapshotEpoch"):
                failures.append("provider proof snapshot epoch does not match command")
            if proof.get("topologyHash") != facts.get("topologyHash"):
                failures.append("provider proof topology hash does not match command")
            if proof.get("iommuGroup") != snapshot_group.get("groupId"):
                failures.append("provider proof IOMMU group does not match expected snapshot")
            if proof.get("groupMembers") != snapshot_group.get("members"):
                failures.append("provider proof group members do not match expected snapshot")
            if proof.get("snapshotBinding") != "CALLER_CORRELATION_ONLY":
                failures.append("provider overstated or omitted snapshot binding semantics")
            if proof.get("verifiedClaims") != [
                "pciIdentity",
                "iommuGroup",
                "vfioDmaProvider",
            ]:
                failures.append("provider proof has an unexpected verified-claim set")
            if proof.get("lifecycle") != "ACQUIRED_AND_CLOSED":
                failures.append("standalone provider proof did not close its live session")
            if proof.get("handlesUsable") is not False:
                failures.append("standalone provider proof exposed handles as usable")
            expected_identity = expected_snapshot.get("identity")
            proof_identity = proof.get("identity")
            if not isinstance(expected_identity, dict) or not isinstance(
                proof_identity, dict
            ):
                failures.append("provider proof or expected snapshot has no identity")
            else:
                for field, expected_value in expected_identity.items():
                    observed_value = proof_identity.get(field)
                    try:
                        normalized_observed = (
                            int(observed_value, 0)
                            if isinstance(observed_value, str)
                            else observed_value
                        )
                    except ValueError:
                        normalized_observed = None
                    if normalized_observed != expected_value:
                        failures.append(
                            f"provider proof identity {field} does not match snapshot"
                        )
            if provider == "vfio-cdev-iommufd":
                for field in ("ioasId", "hwptId", "deviceId"):
                    if field not in proof:
                        failures.append(f"cdev/IOMMUFD proof is missing {field}")
                if not facts.get("iommufdPresent"):
                    failures.append("cdev/IOMMUFD proof exists but /dev/iommu was absent")
                if not facts.get("targetVfioCdevSysfsPaths"):
                    failures.append("cdev/IOMMUFD proof exists but target cdev sysfs was absent")
            elif provider in {"vfio-legacy-type1v2", "vfio-legacy-type1"}:
                if "iommuType" not in proof:
                    failures.append("legacy provider proof is missing iommuType")

    return not failures, failures


def qemu_command(args: argparse.Namespace, case: str, case_dir: Path) -> list[str]:
    command = [
        str(args.qemu),
        "-machine",
        "q35,accel=kvm,kernel-irqchip=split",
        "-cpu",
        "host",
        "-m",
        "1536",
        "-smp",
        "2",
        "-nodefaults",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "pcie-root-port,id=test_rp,bus=pcie.0,addr=0x02,chassis=2",
        "-device",
        "e1000e,id=testnic,bus=test_rp,addr=0x00",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={case_dir / 'OVMF_VARS.fd'}",
        "-drive",
        f"if=none,id=osdisk,format=qcow2,file={case_dir / 'os.qcow2'}",
        "-device",
        "virtio-blk-pci,drive=osdisk",
        "-drive",
        f"if=none,id=cidata,format=raw,readonly=on,file={case_dir / 'seed.iso'}",
        "-device",
        "virtio-blk-pci,drive=cidata",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]
    if case == "iommu-with-unsafe-switch":
        command.extend(
            ["-device", "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on"]
        )
    return command


def run_case(
    args: argparse.Namespace,
    case: str,
    output: Path,
    provider_source: bytes,
    provider_source_hash: str,
) -> dict[str, Any]:
    case_dir = output / case
    case_dir.mkdir(parents=True, exist_ok=False)
    overlay = case_dir / "os.qcow2"
    vars_file = case_dir / "OVMF_VARS.fd"
    seed_image = case_dir / "seed.iso"
    serial_log = case_dir / "serial.log"

    shutil.copyfile(args.ovmf_vars, vars_file)
    image_info = json.loads(
        command_output(["qemu-img", "info", "--output=json", str(args.base_image)])
    )
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            image_info["format"],
            "-b",
            str(args.base_image),
            str(overlay),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    write_seed(case, case_dir / "seed", seed_image, provider_source)

    command = qemu_command(args, case, case_dir)
    write_json(case_dir / "qemu-command.json", command)
    started = time.monotonic()
    timed_out = False
    attempts: list[dict[str, Any]] = []
    for attempt in range(1, 3):
        with serial_log.open("a", encoding="utf-8") as stream:
            stream.write(f"\n===== QMAN HOST QEMU ATTEMPT {attempt} =====\n")
            stream.flush()
            attempt_started = time.monotonic()
            try:
                completed = subprocess.run(
                    command,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=args.timeout,
                )
                return_code: int | None = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                return_code = None
            attempts.append(
                {
                    "attempt": attempt,
                    "qemuReturnCode": return_code,
                    "timedOut": timed_out,
                    "durationSeconds": round(time.monotonic() - attempt_started, 3),
                }
            )
        log = serial_log.read_text(encoding="utf-8", errors="replace")
        needs_second_boot = (
            case == "iommu-with-unsafe-switch"
            and "QMAN_PROVIDER_IOMMU_REBOOT_REQUESTED" in log
            and "QMAN_PROVIDER_END" not in log
            and not timed_out
        )
        if needs_second_boot and attempt == 1:
            continue
        break

    log = serial_log.read_text(encoding="utf-8", errors="replace")
    parse_errors: list[str] = []
    decoded: dict[str, str] = {}
    for marker, filename in (
        ("QMAN_PROVIDER_COMMAND_B64", "guest-provider-command.txt"),
        ("QMAN_PROVIDER_STDOUT_B64", "provider.stdout"),
        ("QMAN_PROVIDER_STDERR_B64", "provider.stderr"),
        ("QMAN_PROVIDER_FACTS_B64", "facts.json"),
    ):
        value, error = decode_base64_marker(log, marker)
        decoded[marker] = value
        (case_dir / filename).write_text(value, encoding="utf-8")
        if error is not None:
            parse_errors.append(error)

    provider_output, error = parse_json_object(
        decoded["QMAN_PROVIDER_STDOUT_B64"], "provider stdout"
    )
    if error is not None:
        parse_errors.append(error)
    facts, error = parse_json_object(decoded["QMAN_PROVIDER_FACTS_B64"], "guest facts")
    if error is not None:
        parse_errors.append(error)
    if provider_output is not None:
        write_json(case_dir / "provider-proof.json", provider_output)

    provider_rc_text = extract_marker(log, "QMAN_PROVIDER_RC")
    provider_rc: int | None = None
    if provider_rc_text is None:
        parse_errors.append("missing QMAN_PROVIDER_RC")
    else:
        try:
            provider_rc = int(provider_rc_text)
        except ValueError:
            parse_errors.append(f"invalid QMAN_PROVIDER_RC: {provider_rc_text!r}")

    passed, failures = evaluate_case(
        case,
        provider_rc,
        provider_output,
        facts,
        provider_source_hash,
        timed_out,
        parse_errors,
    )
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "case": case,
        "passed": passed,
        "failures": failures,
        "durationSeconds": round(time.monotonic() - started, 3),
        "qemuAttempts": attempts,
        "providerReturnCode": provider_rc,
        "providerStatus": (
            provider_output.get("status") if provider_output is not None else None
        ),
        "providerReasonCode": (
            provider_output.get("reasonCode") if provider_output is not None else None
        ),
        "provider": (
            provider_output.get("proof", {}).get("provider")
            if provider_output is not None
            and isinstance(provider_output.get("proof"), dict)
            else None
        ),
        "providerLifecycle": (
            provider_output.get("proof", {}).get("lifecycle")
            if provider_output is not None
            and isinstance(provider_output.get("proof"), dict)
            else None
        ),
        "serialLog": str(serial_log),
        "qemuCommandFile": str(case_dir / "qemu-command.json"),
        "guestProviderCommandFile": str(case_dir / "guest-provider-command.txt"),
        "providerProofFile": (
            str(case_dir / "provider-proof.json")
            if provider_output is not None
            else None
        ),
        "factsFile": str(case_dir / "facts.json"),
    }
    write_json(case_dir / "result.json", result)
    return result


def retained_artifact_hashes(output: Path) -> dict[str, str]:
    retained_names = {
        "facts.json",
        "embedded-vfio-provider.py",
        "guest-provider-command.txt",
        "meta-data",
        "provider-proof.json",
        "provider.stderr",
        "provider.stdout",
        "qemu-command.json",
        "result.json",
        "serial.log",
        "user-data",
    }
    return {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name in retained_names
    }


def validate_prerequisites(args: argparse.Namespace) -> None:
    for name, path in (
        ("QEMU", args.qemu),
        ("base image", args.base_image),
        ("OVMF code", args.ovmf_code),
        ("OVMF vars", args.ovmf_vars),
        ("Qman VFIO provider source", args.provider_source),
    ):
        if not path.is_file():
            raise FileNotFoundError(f"{name} is not a file: {path}")
    if not args.qemu.stat().st_mode & 0o111:
        raise PermissionError(f"QEMU is not executable: {args.qemu}")
    for command in ("qemu-img", "xorriso"):
        if shutil.which(command) is None:
            raise FileNotFoundError(f"required command is missing: {command}")
    if args.output.exists():
        raise FileExistsError(f"output must not already exist: {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the C21 VFIO provider no-IOMMU/IOMMU-backed gate"
    )
    parser.add_argument("--qemu", type=Path, default=DEFAULT_QEMU)
    parser.add_argument("--base-image", type=Path, default=DEFAULT_BASE_IMAGE)
    parser.add_argument("--ovmf-code", type=Path, default=DEFAULT_OVMF_CODE)
    parser.add_argument("--ovmf-vars", type=Path, default=DEFAULT_OVMF_VARS)
    parser.add_argument("--provider-source", type=Path, default=DEFAULT_PROVIDER)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()

    validate_prerequisites(args)
    args.output.mkdir(parents=True)
    provider_source = args.provider_source.read_bytes()
    provider_source_hash = hashlib.sha256(provider_source).hexdigest()
    (args.output / "embedded-vfio-provider.py").write_bytes(provider_source)
    results = [
        run_case(args, case, args.output, provider_source, provider_source_hash)
        for case in CASES
    ]

    input_hashes = {
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "providerSource": {
            "path": str(args.provider_source.resolve()),
            "sha256": provider_source_hash,
        },
        "qemu": {"path": str(args.qemu), "sha256": sha256_file(args.qemu)},
        "baseImage": {
            "path": str(args.base_image),
            "sha256": sha256_file(args.base_image),
        },
        "ovmfCode": {
            "path": str(args.ovmf_code),
            "sha256": sha256_file(args.ovmf_code),
        },
        "ovmfVars": {
            "path": str(args.ovmf_vars),
            "sha256": sha256_file(args.ovmf_vars),
        },
    }
    hash_summary = {
        "schemaVersion": 1,
        "algorithm": "sha256",
        "inputs": input_hashes,
        "retainedArtifacts": retained_artifact_hashes(args.output),
    }
    write_json(args.output / "hashes.json", hash_summary)
    summary = {
        "schemaVersion": 1,
        "test": "qman-vfio-provider-c21",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "invocation": sys.argv,
        "environment": (
            "Two QEMU Ubuntu guests on WSL2/KVM; identical e1000e endpoint and "
            "unsafe=Y, with only the positive guest receiving an Intel vIOMMU"
        ),
        "legacyFallbackExplicitlyAllowedForLab": True,
        "expected": {
            "no-iommu": {
                "status": "error",
                "exitCode": 2,
                "reasonCode": NO_IOMMU_REASON,
            },
            "iommu-with-unsafe-switch": {
                "status": "ok",
                "providers": sorted(SUCCESS_PROVIDERS),
                "snapshotBinding": "CALLER_CORRELATION_ONLY",
                "lifecycle": "ACQUIRED_AND_CLOSED",
                "handlesUsable": False,
            },
        },
        "inputs": input_hashes,
        "cases": results,
        "hashSummary": {
            "path": str(args.output / "hashes.json"),
            "sha256": sha256_file(args.output / "hashes.json"),
        },
        "verdict": "pass" if all(result["passed"] for result in results) else "fail",
    }
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if summary["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
