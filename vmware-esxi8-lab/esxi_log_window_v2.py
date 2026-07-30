#!/usr/bin/env python3
"""Rotation-safe ESXi log windows for the Correctable AER lab runner.

The V1 runner treated ``inode + byte offset`` as the log-window authority.
ESXi's syslog daemon can copy/truncate an active log without changing that
active inode, so a shrink is detectable but a truncate followed by sufficient
regrowth can be mistaken for a stable append.  This module instead binds an
official, per-source marker bracket to an immutable staged copy of the active
file and every retained numeric rotation.

The module deliberately knows nothing about AER semantics.  It returns the
strictly cropped lines and accepts a caller-supplied semantic classifier.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
import zlib
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


PROTOCOL_ID = "ESXI-SYSLOG-MARK-CHAIN-V2"
PROTOCOL_VERSION = 2
MARKER_PREFIX = "QMLOGV2"
MAX_ROTATIONS_PER_SOURCE = 32
MAX_RAW_BYTES_PER_SOURCE = 128 * 1024 * 1024
MAX_DECODED_BYTES_PER_MEMBER = 64 * 1024 * 1024
MAX_DECODED_BYTES_PER_SOURCE = 128 * 1024 * 1024
MAX_CAPTURE_ATTEMPTS = 3

LOG_PATHS: dict[str, str] = {
    "syslog": "/var/run/log/syslog.log",
    "vmkernel": "/var/run/log/vmkernel.log",
    "vobd": "/var/run/log/vobd.log",
}

SAFE_MARKER_RE = re.compile(r"^QMLOGV2\.[0-9a-f]{32}\.[BA]$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INVENTORY_LINE_RE = re.compile(
    r"^MEMBER\t([a-z]+)\t(/[A-Za-z0-9_./-]+)\t"
    r"(\d+)\t(\d+)\t(\d+)\t(\d+)\t([0-9a-f]{64})$"
)
STAGE_LINE_RE = re.compile(
    r"^STAGE\t([a-z]+)\t(active|rot-[0-9]{3})\t"
    r"(\d+)\t([0-9a-f]{64})$"
)
PROOF_LINE_RE = re.compile(
    r"^P([12])\t([a-z]+)\t(active|rot-[0-9]{3})\t"
    r"(\d+)\t([0-9a-f]{64})$"
)


class LogWindowV2Error(RuntimeError):
    """The V2 marker/rotation evidence is incomplete or malformed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def protocol_for_case(campaign_id: str, case_id: str) -> dict[str, Any]:
    """Derive opaque, manifest-reproducible markers for one case."""

    if not isinstance(campaign_id, str) or not campaign_id:
        raise ValueError("campaign_id must be a non-empty string")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    marker_id = sha256_bytes(
        (
            f"{PROTOCOL_ID}\x00{campaign_id}\x00{case_id}"
        ).encode("utf-8")
    )[:32]
    before = f"{MARKER_PREFIX}.{marker_id}.B"
    after = f"{MARKER_PREFIX}.{marker_id}.A"
    return {
        "id": PROTOCOL_ID,
        "version": PROTOCOL_VERSION,
        "markerId": marker_id,
        "before": before,
        "after": after,
        "sources": list(LOG_PATHS),
    }


def validate_protocol(
    value: Any,
    *,
    campaign_id: str,
    case_id: str,
) -> dict[str, Any]:
    expected = protocol_for_case(campaign_id, case_id)
    if value != expected:
        raise LogWindowV2Error(
            "log-window protocol differs from the deterministic case binding"
        )
    return expected


def marker_command(marker: str) -> str:
    if not isinstance(marker, str) or SAFE_MARKER_RE.fullmatch(marker) is None:
        raise ValueError(f"unsafe V2 log marker: {marker!r}")
    return (
        "esxcli system syslog mark "
        f"--message={shlex.quote(marker)}"
    )


def _marker_pattern(marker: str) -> re.Pattern[str]:
    if not isinstance(marker, str) or SAFE_MARKER_RE.fullmatch(marker) is None:
        raise ValueError(f"unsafe V2 log marker: {marker!r}")
    return re.compile(
        r"^\d{4}-\d{2}-\d{2}T"
        r"\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"
        r"[ \t]+In\(\d+\)[ \t]+Hostd\[\d+\]:"
        r"[ \t]+mark:[ \t]+"
        + re.escape(marker)
        + r"[ \t]*$"
    )


def authentic_marker_lines(text: str, marker: str) -> list[str]:
    """Return exact official ``mark:`` lines, excluding SSH command audit."""

    pattern = _marker_pattern(marker)
    return [
        line
        for line in text.splitlines()
        if (
            pattern.search(line) is not None
            and "sshd-session" not in line
            and "running command" not in line
            and "esxcli system syslog mark" not in line
        )
    ]


def marker_probe_command(source: str) -> str:
    """Return a fixed probe that never contains a marker token."""

    if source not in LOG_PATHS:
        raise ValueError(f"unknown log source: {source!r}")
    active = LOG_PATHS[source]
    stem = active[:-4] if active.endswith(".log") else active
    parts = [
        "for p in "
        f"{shlex.quote(active)} {stem}.[0-9]* {active}.[0-9]*",
        "do",
        '  [ -f "$p" ] || continue',
        '  case "$p" in',
        '    *.gz) zcat "$p" 2>/dev/null | tail -n 160 ;;',
        '    *) tail -n 480 "$p" 2>/dev/null ;;',
        "  esac",
        "done",
    ]
    command = "\n".join(parts)
    if MARKER_PREFIX in command:
        raise AssertionError("fixed marker probe unexpectedly contains token")
    return command


def wait_for_marker(
    ssh: Any,
    marker: str,
    cancel: Any,
    *,
    timeout_seconds: float = 10.0,
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    """Wait until every logical source exposes exactly one official marker."""

    if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
        raise ValueError("marker timeout must be positive and finite")
    deadline = monotonic() + timeout_seconds
    attempts: list[dict[str, Any]] = []
    while not cancel.is_set() and monotonic() < deadline:
        sources: dict[str, Any] = {}
        ambiguous = False
        for source in LOG_PATHS:
            command = marker_probe_command(source)
            result = ssh.run(command, check=False, timeout=30)
            lines = (
                authentic_marker_lines(result.stdout, marker)
                if result.returncode == 0
                else []
            )
            sources[source] = {
                "command": command,
                "returnCode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "authenticCount": len(lines),
                "matchedLines": lines,
            }
            if len(lines) > 1:
                ambiguous = True
        attempt = {"sources": sources}
        attempts.append(attempt)
        if ambiguous:
            return {
                "protocol": PROTOCOL_ID,
                "marker": marker,
                "visible": False,
                "ambiguous": True,
                "sources": sources,
                "attempts": attempts,
            }
        if all(
            item["returnCode"] == 0
            and item["stderr"] == ""
            and item["authenticCount"] == 1
            for item in sources.values()
        ):
            return {
                "protocol": PROTOCOL_ID,
                "marker": marker,
                "visible": True,
                "ambiguous": False,
                "sources": sources,
                "attempts": attempts,
            }
        cancel.wait(0.1)
    return {
        "protocol": PROTOCOL_ID,
        "marker": marker,
        "visible": False,
        "ambiguous": False,
        "cancelled": cancel.is_set(),
        "sources": attempts[-1]["sources"] if attempts else {},
        "attempts": attempts,
    }


def _inventory_patterns(source: str) -> tuple[str, str, str]:
    active = LOG_PATHS[source]
    stem = active[:-4] if active.endswith(".log") else active
    return active, f"{stem}.[0-9]*", f"{active}.[0-9]*"


def inventory_command() -> str:
    """Build one ASCII-only inventory command for all three sources."""

    lines = ["set -e"]
    for source in LOG_PATHS:
        active, standard, alternate = _inventory_patterns(source)
        lines.extend(
            [
                (
                    "for p in "
                    f"{shlex.quote(active)} {standard} {alternate}"
                ),
                "do",
                '  [ -e "$p" ] || continue',
                '  [ -f "$p" ] || exit 41',
                "  li=$(stat -c '%i' \"$p\")",
                "  ls=$(stat -c '%s' \"$p\")",
                "  ti=$(stat -Lc '%i' \"$p\")",
                "  ts=$(stat -Lc '%s' \"$p\")",
                "  sh=$(sha256sum \"$p\")",
                "  sh=${sh%% *}",
                (
                    f"  printf 'MEMBER\\t{source}\\t%s\\t%s\\t%s"
                    "\\t%s\\t%s\\t%s\\n' "
                    '"$p" "$li" "$ls" "$ti" "$ts" "$sh"'
                ),
                "done",
            ]
        )
    return "\n".join(lines)


def _member_identity(
    source: str,
    remote_path: str,
) -> tuple[str, int | None, str]:
    active = LOG_PATHS[source]
    if remote_path == active:
        return "active", None, "plain"
    stem = active[:-4] if active.endswith(".log") else active
    escaped = (re.escape(stem), re.escape(active))
    match = re.fullmatch(
        rf"(?:{escaped[0]}|{escaped[1]})\.(\d+)(\.gz)?",
        remote_path,
    )
    if match is None:
        raise LogWindowV2Error(
            f"unknown rotation name for {source}: {remote_path}"
        )
    generation = int(match.group(1), 10)
    if generation > 999:
        raise LogWindowV2Error(
            f"rotation generation is unbounded: {remote_path}"
        )
    return (
        f"rot-{generation:03d}",
        generation,
        "gzip" if match.group(2) else "plain",
    )


def parse_inventory(
    stdout: str,
    *,
    command: str,
    return_code: int,
    stderr: str,
) -> dict[str, Any]:
    faults: list[str] = []
    if command != inventory_command():
        faults.append("inventory command differs from the closed V2 command")
    if return_code != 0:
        faults.append(f"inventory command returned {return_code}")
    if stderr:
        faults.append("inventory command produced stderr")
    members: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_slots: set[tuple[str, str]] = set()
    for index, line in enumerate(stdout.splitlines()):
        match = INVENTORY_LINE_RE.fullmatch(line)
        if match is None:
            faults.append(f"inventory line {index + 1} is malformed")
            continue
        (
            source,
            path,
            lstat_inode,
            lstat_size,
            target_inode,
            target_size,
            digest,
        ) = match.groups()
        if source not in LOG_PATHS:
            faults.append(f"inventory source is unknown: {source!r}")
            continue
        try:
            slot, generation, encoding = _member_identity(source, path)
        except LogWindowV2Error as error:
            faults.append(str(error))
            continue
        if path in seen_paths:
            faults.append(f"inventory path is duplicated: {path}")
        seen_paths.add(path)
        identity = (source, slot)
        if identity in seen_slots:
            faults.append(
                f"inventory slot is duplicated: {source}/{slot}"
            )
        seen_slots.add(identity)
        members.append(
            {
                "source": source,
                "remotePath": path,
                "slot": slot,
                "generation": generation,
                "encoding": encoding,
                "lstatInode": int(lstat_inode),
                "lstatSizeBytes": int(lstat_size),
                "targetInode": int(target_inode),
                "targetSizeBytes": int(target_size),
                "sha256": digest,
            }
        )

    for source in LOG_PATHS:
        selected = [item for item in members if item["source"] == source]
        active = [item for item in selected if item["slot"] == "active"]
        if len(active) != 1:
            faults.append(
                f"{source} inventory must contain exactly one active member"
            )
        rotations = sorted(
            item["generation"]
            for item in selected
            if item["generation"] is not None
        )
        if len(rotations) > MAX_ROTATIONS_PER_SOURCE:
            faults.append(f"{source} has too many retained rotations")
        if rotations and rotations != list(range(rotations[-1] + 1)):
            faults.append(
                f"{source} rotation generations are not continuous from zero"
            )
        total = sum(item["targetSizeBytes"] for item in selected)
        if total > MAX_RAW_BYTES_PER_SOURCE:
            faults.append(f"{source} raw rotation chain exceeds byte limit")
    members.sort(
        key=lambda item: (
            item["source"],
            (
                -1
                if item["generation"] is None
                else item["generation"]
            ),
        )
    )
    return {
        "command": command,
        "returnCode": return_code,
        "stderr": stderr,
        "stdout": stdout,
        "members": members,
        "complete": not faults,
        "faults": sorted(set(faults)),
    }


def capture_inventory(ssh: Any) -> dict[str, Any]:
    command = inventory_command()
    result = ssh.run(command, check=False, timeout=180)
    return parse_inventory(
        result.stdout,
        command=command,
        return_code=result.returncode,
        stderr=result.stderr,
    )


def _stage_name(member: Mapping[str, Any]) -> str:
    suffix = ".gz" if member["encoding"] == "gzip" else ".raw"
    return f"{member['source']}--{member['slot']}{suffix}"


def _artifact_relative(attempt: int, member: Mapping[str, Any]) -> str:
    if (
        not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or not 1 <= attempt <= MAX_CAPTURE_ATTEMPTS
    ):
        raise ValueError("capture attempt is outside the closed range")
    source = member.get("source")
    slot = member.get("slot")
    encoding = member.get("encoding")
    if source not in LOG_PATHS:
        raise ValueError("log artifact source is not closed")
    if (
        slot != "active"
        and (
            not isinstance(slot, str)
            or re.fullmatch(r"rot-[0-9]{3}", slot) is None
        )
    ):
        raise ValueError("log artifact slot is not canonical")
    if encoding not in ("plain", "gzip"):
        raise ValueError("log artifact encoding is not closed")
    return (
        f"raw-esxi/log-window-v2/attempt-{attempt:02d}/"
        f"{source}/{slot}"
        + (".gz" if encoding == "gzip" else ".raw")
    )


def _command_record(command: str, result: Any) -> dict[str, Any]:
    return {
        "command": command,
        "returnCode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _parse_single_stage_line(
    stdout: str,
    *,
    source: str,
    slot: str,
) -> tuple[int | None, str | None, list[str]]:
    faults: list[str] = []
    lines = stdout.splitlines()
    if len(lines) != 1:
        return None, None, ["stage command did not emit one exact line"]
    match = STAGE_LINE_RE.fullmatch(lines[0])
    if match is None:
        return None, None, ["stage command output is malformed"]
    actual_source, actual_slot, size, digest = match.groups()
    if actual_source != source or actual_slot != slot:
        faults.append("stage command identity is inconsistent")
    return int(size), digest, faults


def _stage_command(
    *,
    stage_dir: str,
    member: Mapping[str, Any],
) -> tuple[str, str]:
    source = str(member["source"])
    slot = str(member["slot"])
    remote_path = str(member["remotePath"])
    remote_stage = f"{stage_dir}/{_stage_name(member)}"
    command = "\n".join(
        [
            "set -e",
            f"cp {shlex.quote(remote_path)} {shlex.quote(remote_stage)}",
            f"sz=$(stat -c '%s' {shlex.quote(remote_stage)})",
            f"sh=$(sha256sum {shlex.quote(remote_stage)})",
            "sh=${sh%% *}",
            (
                f"printf 'STAGE\\t{source}\\t{slot}\\t%s\\t%s\\n' "
                '"$sz" "$sh"'
            ),
        ]
    )
    return remote_stage, command


def _stage_member(
    ssh: Any,
    transfer: Any,
    *,
    stage_dir: str,
    member: Mapping[str, Any],
    case_dir: Path,
    attempt: int,
) -> dict[str, Any]:
    source = str(member["source"])
    slot = str(member["slot"])
    remote_path = str(member["remotePath"])
    remote_stage, command = _stage_command(
        stage_dir=stage_dir,
        member=member,
    )
    result = ssh.run(command, check=False, timeout=180)
    size, digest, faults = _parse_single_stage_line(
        result.stdout,
        source=source,
        slot=slot,
    )
    if result.returncode != 0:
        faults.append(f"stage command returned {result.returncode}")
    if result.stderr:
        faults.append("stage command produced stderr")
    if (
        isinstance(size, int)
        and size > MAX_RAW_BYTES_PER_SOURCE
    ):
        faults.append("staged log member exceeds raw byte limit")
    artifact = _artifact_relative(attempt, member)
    local_path = case_dir / artifact
    copied = False
    copy_fault: str | None = None
    if not faults:
        try:
            copied = bool(
                transfer.from_esxi(
                    remote_stage,
                    local_path,
                    required=True,
                )
            )
        except BaseException as error:
            copy_fault = f"{type(error).__name__}: {error}"
            faults.append("staged log member could not be copied")
    local_size = local_path.stat().st_size if local_path.is_file() else None
    local_digest = sha256_file(local_path) if local_path.is_file() else None
    if (
        not copied
        or not isinstance(size, int)
        or local_size != size
        or local_digest != digest
    ):
        faults.append("local staged member size/hash is not exact")
    return {
        "source": source,
        "slot": slot,
        "generation": member["generation"],
        "encoding": member["encoding"],
        "remotePath": remote_path,
        "remoteStagePath": remote_stage,
        "artifact": artifact,
        "command": _command_record(command, result),
        "cutBytes": size,
        "stageSha256": digest,
        "copied": copied,
        "copyFault": copy_fault,
        "localSizeBytes": local_size,
        "localSha256": local_digest,
        "complete": not faults,
        "faults": sorted(set(faults)),
    }


def _proof_command(
    *,
    label: str,
    stage_dir: str,
    staged: Iterable[Mapping[str, Any]],
) -> tuple[str, dict[tuple[str, str], str]]:
    lines = ["set -e"]
    proof_paths: dict[tuple[str, str], str] = {}
    for item in staged:
        source = str(item["source"])
        slot = str(item["slot"])
        cut_bytes = item.get("cutBytes")
        if (
            not isinstance(cut_bytes, int)
            or isinstance(cut_bytes, bool)
            or cut_bytes < 0
        ):
            raise LogWindowV2Error("stage cutBytes is invalid")
        remote_path = str(item["remotePath"])
        proof_path = f"{stage_dir}/{source}--{slot}.{label.lower()}"
        proof_paths[(source, slot)] = proof_path
        lines.extend(
            [
                (
                    f"head -c {cut_bytes} {shlex.quote(remote_path)} "
                    f"> {shlex.quote(proof_path)}"
                ),
                f"sz=$(stat -c '%s' {shlex.quote(proof_path)})",
                f"sh=$(sha256sum {shlex.quote(proof_path)})",
                "sh=${sh%% *}",
                (
                    f"printf '{label}\\t{source}\\t{slot}"
                    "\\t%s\\t%s\\n' \"$sz\" \"$sh\""
                ),
            ]
        )
    return "\n".join(lines), proof_paths


def _capture_proofs(
    ssh: Any,
    *,
    label: str,
    stage_dir: str,
    staged: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[tuple[str, str], str]]:
    command, proof_paths = _proof_command(
        label=label,
        stage_dir=stage_dir,
        staged=staged,
    )
    result = ssh.run(command, check=False, timeout=180)
    return (
        _parse_proof_record(
            label=label,
            stage_dir=stage_dir,
            staged=staged,
            command=command,
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        ),
        proof_paths,
    )


def _parse_proof_record(
    *,
    label: str,
    stage_dir: str,
    staged: list[Mapping[str, Any]],
    command: Any,
    return_code: Any,
    stdout: Any,
    stderr: Any,
) -> dict[str, Any]:
    faults: list[str] = []
    proofs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        expected_command, _ = _proof_command(
            label=label,
            stage_dir=stage_dir,
            staged=staged,
        )
    except (KeyError, TypeError, ValueError, LogWindowV2Error) as error:
        expected_command = None
        faults.append(f"{label} command derivation failed: {error}")
    if command != expected_command:
        faults.append(f"{label} command differs from the closed command")
    if not isinstance(stdout, str):
        faults.append(f"{label} stdout is not text")
        stdout = ""
    if not isinstance(stderr, str):
        faults.append(f"{label} stderr is not text")
        stderr = ""
    for index, line in enumerate(stdout.splitlines()):
        match = PROOF_LINE_RE.fullmatch(line)
        if match is None:
            faults.append(f"{label} output line {index + 1} is malformed")
            continue
        proof_number, source, slot, size, digest = match.groups()
        if f"P{proof_number}" != label:
            faults.append(f"{label} output contains another proof label")
        identity = (source, slot)
        if identity in seen:
            faults.append(f"{label} duplicates {source}/{slot}")
        seen.add(identity)
        proofs.append(
            {
                "source": source,
                "slot": slot,
                "sizeBytes": int(size),
                "sha256": digest,
            }
        )
    expected = {
        (str(item["source"]), str(item["slot"]))
        for item in staged
    }
    if seen != expected:
        faults.append(f"{label} identities differ from staged members")
    if return_code != 0:
        faults.append(f"{label} command returned {return_code}")
    if stderr:
        faults.append(f"{label} command produced stderr")
    return {
        "label": label,
        "command": {
            "command": command,
            "returnCode": return_code,
            "stdout": stdout,
            "stderr": stderr,
        },
        "proofs": sorted(
            proofs,
            key=lambda item: (item["source"], item["slot"]),
        ),
        "complete": not faults,
        "faults": sorted(set(faults)),
    }


def _inventory_member_map(
    inventory: Mapping[str, Any],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(item["source"]), str(item["slot"])): item
        for item in inventory.get("members", [])
        if isinstance(item, Mapping)
    }


def _proof_map(
    value: Mapping[str, Any],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(item["source"]), str(item["slot"])): item
        for item in value.get("proofs", [])
        if isinstance(item, Mapping)
    }


def validate_cut_attempt(value: Mapping[str, Any]) -> list[str]:
    faults: list[str] = []
    attempt_number = value.get("attempt")
    if (
        not isinstance(attempt_number, int)
        or isinstance(attempt_number, bool)
        or not 1 <= attempt_number <= MAX_CAPTURE_ATTEMPTS
    ):
        faults.append("capture attempt identity is outside the closed range")
    stage_dir = value.get("stageDirectory")
    if (
        not isinstance(stage_dir, str)
        or re.fullmatch(
            r"/tmp/qmlogv2-[0-9a-f]{32}-[0-9]{2}",
            stage_dir,
        )
        is None
        or (
            isinstance(attempt_number, int)
            and not isinstance(attempt_number, bool)
            and not stage_dir.endswith(f"-{attempt_number:02d}")
        )
    ):
        faults.append("capture staging directory is not canonical")
    stage_create = value.get("stageCreate")
    expected_mkdir = (
        f"[ ! -e {shlex.quote(stage_dir)} ] "
        f"&& mkdir {shlex.quote(stage_dir)}"
        if isinstance(stage_dir, str)
        else None
    )
    if (
        not isinstance(stage_create, Mapping)
        or stage_create.get("command") != expected_mkdir
        or stage_create.get("returnCode") != 0
        or not isinstance(stage_create.get("stdout"), str)
        or stage_create.get("stderr") != ""
    ):
        faults.append("capture staging creation transcript is inconsistent")
    inventories = [
        value.get("inventoryA"),
        value.get("inventoryB"),
        value.get("inventoryC"),
    ]
    if any(
        not isinstance(item, Mapping)
        or item.get("complete") is not True
        for item in inventories
    ):
        faults.append("A/B/C inventory is incomplete")
        return sorted(set(faults))
    for label, inventory in zip(("A", "B", "C"), inventories):
        try:
            rebuilt_inventory = parse_inventory(
                inventory.get("stdout"),
                command=inventory.get("command"),
                return_code=inventory.get("returnCode"),
                stderr=inventory.get("stderr"),
            )
        except Exception as error:
            faults.append(
                f"inventory {label} raw transcript cannot be parsed: "
                f"{type(error).__name__}: {error}"
            )
            continue
        if rebuilt_inventory != inventory:
            faults.append(
                f"inventory {label} differs from its raw transcript"
            )
    if faults:
        return sorted(set(faults))
    maps = [_inventory_member_map(item) for item in inventories]
    for label, inventory, member_map in zip(
        ("A", "B", "C"),
        inventories,
        maps,
    ):
        raw_members = inventory.get("members")
        raw_members = raw_members if isinstance(raw_members, list) else []
        mapping_members = [
            item for item in raw_members if isinstance(item, Mapping)
        ]
        if len(mapping_members) != len(raw_members):
            faults.append(f"inventory {label} contains a non-object member")
        if len(member_map) != len(mapping_members):
            faults.append(f"inventory {label} duplicates a member identity")
    identities = [set(item) for item in maps]
    if not identities or not identities[0]:
        faults.append("A/B/C inventory member set is empty")
        return sorted(set(faults))
    if any(item != identities[0] for item in identities[1:]):
        faults.append("A/B/C inventory member sets differ")
        return sorted(set(faults))
    for source in LOG_PATHS:
        if (source, "active") not in identities[0]:
            faults.append(f"{source} inventory has no active member")
    for identity, member in maps[0].items():
        source, slot = identity
        remote_path = member.get("remotePath")
        if source not in LOG_PATHS or not isinstance(remote_path, str):
            faults.append(f"{source}/{slot} inventory identity is not closed")
            continue
        try:
            expected_slot, expected_generation, expected_encoding = (
                _member_identity(source, remote_path)
            )
        except LogWindowV2Error as error:
            faults.append(str(error))
            continue
        if (
            slot != expected_slot
            or member.get("generation") != expected_generation
            or member.get("encoding") != expected_encoding
        ):
            faults.append(
                f"{source}/{slot} inventory path metadata is inconsistent"
            )
    staged_list = value.get("stagedMembers")
    staged_list = staged_list if isinstance(staged_list, list) else []
    staged_map = {
        (str(item.get("source")), str(item.get("slot"))): item
        for item in staged_list
        if isinstance(item, Mapping)
    }
    mapping_staged = [
        item for item in staged_list if isinstance(item, Mapping)
    ]
    if len(mapping_staged) != len(staged_list):
        faults.append("staged members contain a non-object entry")
    if len(staged_map) != len(mapping_staged):
        faults.append("staged members duplicate an identity")
    inventory_order = [
        (str(item.get("source")), str(item.get("slot")))
        for item in inventories[0].get("members", [])
        if isinstance(item, Mapping)
    ]
    staged_order = [
        (str(item.get("source")), str(item.get("slot")))
        for item in mapping_staged
    ]
    if staged_order != inventory_order:
        faults.append("staged member order differs from inventory A")
    if set(staged_map) != identities[0]:
        faults.append("staged member set differs from A inventory")
    proof1 = value.get("prefixProof1")
    proof2 = value.get("prefixProof2")
    if not isinstance(proof1, Mapping) or proof1.get("complete") is not True:
        faults.append("prefix proof P1 is incomplete")
        p1 = {}
    else:
        p1 = _proof_map(proof1)
    if not isinstance(proof2, Mapping) or proof2.get("complete") is not True:
        faults.append("prefix proof P2 is incomplete")
        p2 = {}
    else:
        p2 = _proof_map(proof2)
    for label, proof in (("P1", proof1), ("P2", proof2)):
        command_record = (
            proof.get("command")
            if isinstance(proof, Mapping)
            else None
        )
        if not isinstance(command_record, Mapping):
            faults.append(f"{label} raw command record is malformed")
            continue
        rebuilt_proof = _parse_proof_record(
            label=label,
            stage_dir=stage_dir if isinstance(stage_dir, str) else "",
            staged=mapping_staged,
            command=command_record.get("command"),
            return_code=command_record.get("returnCode"),
            stdout=command_record.get("stdout"),
            stderr=command_record.get("stderr"),
        )
        if rebuilt_proof != proof:
            faults.append(f"{label} differs from its raw transcript")
    for label, proof, proof_map in (
        ("P1", proof1, p1),
        ("P2", proof2, p2),
    ):
        raw_proofs = (
            proof.get("proofs", [])
            if isinstance(proof, Mapping)
            else []
        )
        raw_proofs = raw_proofs if isinstance(raw_proofs, list) else []
        mapping_proofs = [
            item for item in raw_proofs if isinstance(item, Mapping)
        ]
        if len(mapping_proofs) != len(raw_proofs):
            faults.append(f"{label} contains a non-object proof")
        if len(proof_map) != len(mapping_proofs):
            faults.append(f"{label} duplicates a proof identity")
    if set(p1) != identities[0] or set(p2) != identities[0]:
        faults.append("prefix proof identities differ from inventory")

    for identity in sorted(identities[0]):
        first, second, third = (item[identity] for item in maps)
        staged = staged_map.get(identity, {})
        one = p1.get(identity, {})
        two = p2.get(identity, {})
        source, slot = identity
        if set(staged) != {
            "source",
            "slot",
            "generation",
            "encoding",
            "remotePath",
            "remoteStagePath",
            "artifact",
            "command",
            "cutBytes",
            "stageSha256",
            "copied",
            "copyFault",
            "localSizeBytes",
            "localSha256",
            "complete",
            "faults",
        }:
            faults.append(
                f"{source}/{slot} staged record shape is not exact"
            )
        for key in ("remotePath", "lstatInode", "targetInode"):
            if not (first.get(key) == second.get(key) == third.get(key)):
                faults.append(
                    f"{source}/{slot} {key} changed across A/B/C"
                )
        cut = staged.get("cutBytes")
        digest = staged.get("stageSha256")
        local_size = staged.get("localSizeBytes")
        local_digest = staged.get("localSha256")
        for key in ("remotePath", "generation", "encoding"):
            if staged.get(key) != first.get(key):
                faults.append(
                    f"{source}/{slot} staged {key} differs from inventory A"
                )
        command_record = staged.get("command")
        try:
            expected_remote_stage, expected_stage_command = _stage_command(
                stage_dir=stage_dir if isinstance(stage_dir, str) else "",
                member=first,
            )
        except (KeyError, TypeError, ValueError) as error:
            expected_remote_stage = None
            expected_stage_command = None
            faults.append(
                f"{source}/{slot} stage command cannot be derived: {error}"
            )
        if (
            not isinstance(command_record, Mapping)
            or set(command_record)
            != {"command", "returnCode", "stdout", "stderr"}
            or command_record.get("command") != expected_stage_command
            or command_record.get("returnCode") != 0
            or command_record.get("stderr") != ""
            or not isinstance(command_record.get("stdout"), str)
            or staged.get("remoteStagePath") != expected_remote_stage
        ):
            faults.append(
                f"{source}/{slot} stage command transcript is inconsistent"
            )
            parsed_stage_size = None
            parsed_stage_digest = None
        else:
            parsed_stage_size, parsed_stage_digest, stage_parse_faults = (
                _parse_single_stage_line(
                    command_record.get("stdout"),
                    source=source,
                    slot=slot,
                )
            )
            if stage_parse_faults:
                faults.append(
                    f"{source}/{slot} stage stdout is malformed"
                )
        if isinstance(attempt_number, int) and not isinstance(
            attempt_number,
            bool,
        ):
            try:
                expected_artifact = _artifact_relative(
                    attempt_number,
                    staged,
                )
            except (KeyError, TypeError, ValueError):
                expected_artifact = None
            if staged.get("artifact") != expected_artifact:
                faults.append(
                    f"{source}/{slot} staged artifact path is not canonical"
                )
        if (
            staged.get("complete") is not True
            or not isinstance(cut, int)
            or isinstance(cut, bool)
            or cut < 0
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or local_size != cut
            or local_digest != digest
            or parsed_stage_size != cut
            or parsed_stage_digest != digest
            or staged.get("copied") is not True
            or staged.get("copyFault") is not None
            or staged.get("faults") != []
            or one.get("sizeBytes") != cut
            or one.get("sha256") != digest
            or two.get("sizeBytes") != cut
            or two.get("sha256") != digest
        ):
            faults.append(
                f"{source}/{slot} staged cut/prefix hashes are inconsistent"
            )
        sizes = [
            item.get("targetSizeBytes")
            for item in (first, second, third)
        ]
        if not all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in sizes
        ):
            faults.append(f"{source}/{slot} target sizes are malformed")
            continue
        if slot == "active":
            if (
                not isinstance(cut, int)
                or isinstance(cut, bool)
                or sizes[0] > cut
                or sizes[1] < cut
                or sizes[2] < cut
            ):
                faults.append(
                    f"{source}/active is not an append-safe staged prefix"
                )
        elif not (
            isinstance(cut, int)
            and not isinstance(cut, bool)
            and sizes[0] == cut
            and sizes[1] == cut
            and sizes[2] == cut
            and first.get("sha256")
            == second.get("sha256")
            == third.get("sha256")
            == digest
        ):
            faults.append(
                f"{source}/{slot} rotated member changed across the cut"
            )
    for source in LOG_PATHS:
        source_cut_total = sum(
            int(item.get("cutBytes"))
            for item in mapping_staged
            if (
                item.get("source") == source
                and isinstance(item.get("cutBytes"), int)
                and not isinstance(item.get("cutBytes"), bool)
                and int(item.get("cutBytes")) >= 0
            )
        )
        if source_cut_total > MAX_RAW_BYTES_PER_SOURCE:
            faults.append(f"{source} staged rotation chain exceeds byte limit")
    proof_paths: list[str] = []
    try:
        for label in ("P1", "P2"):
            _, paths = _proof_command(
                label=label,
                stage_dir=stage_dir if isinstance(stage_dir, str) else "",
                staged=mapping_staged,
            )
            proof_paths.extend(paths.values())
        expected_cleanup = _cleanup_command(
            stage_dir=stage_dir if isinstance(stage_dir, str) else "",
            staged=mapping_staged,
            proof_paths=proof_paths,
        )
    except (KeyError, TypeError, ValueError, LogWindowV2Error) as error:
        expected_cleanup = None
        faults.append(f"cleanup command cannot be derived: {error}")
    cleanup = value.get("cleanup")
    if (
        not isinstance(cleanup, Mapping)
        or cleanup.get("command") != expected_cleanup
        or cleanup.get("returnCode") != 0
        or not isinstance(cleanup.get("stdout"), str)
        or cleanup.get("stderr") != ""
        or cleanup.get("complete") is not True
    ):
        faults.append("capture cleanup transcript is inconsistent")
    return sorted(set(faults))


def _cleanup_command(
    *,
    stage_dir: str,
    staged: Iterable[Mapping[str, Any]],
    proof_paths: Iterable[str],
) -> str:
    exact_files = sorted(
        {
            str(item["remoteStagePath"])
            for item in staged
            if isinstance(item.get("remoteStagePath"), str)
        }
        | {str(item) for item in proof_paths}
    )
    return "\n".join(
        [
            "set -e",
            *[
                f"rm -f {shlex.quote(path)}"
                for path in exact_files
            ],
            f"rmdir {shlex.quote(stage_dir)}",
        ]
    )


def _cleanup_stage(
    ssh: Any,
    *,
    stage_dir: str,
    staged: Iterable[Mapping[str, Any]],
    proof_paths: Iterable[str],
) -> dict[str, Any]:
    command = _cleanup_command(
        stage_dir=stage_dir,
        staged=staged,
        proof_paths=proof_paths,
    )
    result = ssh.run(command, check=False, timeout=60)
    return {
        **_command_record(command, result),
        "complete": result.returncode == 0 and not result.stderr,
    }


def capture_rotation_chain(
    ssh: Any,
    transfer: Any,
    case_dir: Path,
    protocol: Mapping[str, Any],
    *,
    maximum_attempts: int = MAX_CAPTURE_ATTEMPTS,
) -> dict[str, Any]:
    """Capture one immutable raw chain, retaining every failed transcript."""

    if (
        not isinstance(maximum_attempts, int)
        or isinstance(maximum_attempts, bool)
        or not 1 <= maximum_attempts <= MAX_CAPTURE_ATTEMPTS
    ):
        raise ValueError("maximum_attempts is outside the closed range")
    marker_id = protocol.get("markerId")
    if (
        protocol.get("id") != PROTOCOL_ID
        or not isinstance(marker_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", marker_id) is None
    ):
        raise ValueError("invalid V2 log-window protocol")
    attempts: list[dict[str, Any]] = []
    selected: int | None = None
    for attempt_number in range(1, maximum_attempts + 1):
        stage_dir = (
            f"/tmp/qmlogv2-{marker_id}-{attempt_number:02d}"
        )
        attempt: dict[str, Any] = {
            "protocol": PROTOCOL_ID,
            "attempt": attempt_number,
            "stageDirectory": stage_dir,
            "faults": [],
        }
        mkdir_command = (
            f"[ ! -e {shlex.quote(stage_dir)} ] "
            f"&& mkdir {shlex.quote(stage_dir)}"
        )
        mkdir_result = ssh.run(
            mkdir_command,
            check=False,
            timeout=60,
        )
        attempt["stageCreate"] = _command_record(
            mkdir_command,
            mkdir_result,
        )
        staged: list[dict[str, Any]] = []
        proof_paths: list[str] = []
        if mkdir_result.returncode != 0 or mkdir_result.stderr:
            attempt["faults"].append("unique staging directory creation failed")
        else:
            inventory_a = capture_inventory(ssh)
            attempt["inventoryA"] = inventory_a
            if inventory_a.get("complete") is not True:
                attempt["faults"].append("inventory A is incomplete")
            else:
                for member in inventory_a["members"]:
                    staged.append(
                        _stage_member(
                            ssh,
                            transfer,
                            stage_dir=stage_dir,
                            member=member,
                            case_dir=case_dir,
                            attempt=attempt_number,
                        )
                    )
                attempt["stagedMembers"] = staged
                attempt["inventoryB"] = capture_inventory(ssh)
                try:
                    proof1, paths1 = _capture_proofs(
                        ssh,
                        label="P1",
                        stage_dir=stage_dir,
                        staged=staged,
                    )
                    attempt["prefixProof1"] = proof1
                    proof_paths.extend(paths1.values())
                except BaseException as error:
                    attempt["faults"].append(
                        f"prefix proof P1 failed: "
                        f"{type(error).__name__}: {error}"
                    )
                attempt["inventoryC"] = capture_inventory(ssh)
                try:
                    proof2, paths2 = _capture_proofs(
                        ssh,
                        label="P2",
                        stage_dir=stage_dir,
                        staged=staged,
                    )
                    attempt["prefixProof2"] = proof2
                    proof_paths.extend(paths2.values())
                except BaseException as error:
                    attempt["faults"].append(
                        f"prefix proof P2 failed: "
                        f"{type(error).__name__}: {error}"
                    )
        attempt["cleanup"] = _cleanup_stage(
            ssh,
            stage_dir=stage_dir,
            staged=staged,
            proof_paths=proof_paths,
        )
        if attempt["cleanup"].get("complete") is not True:
            attempt["faults"].append("staging cleanup is incomplete")
        attempt["faults"].extend(validate_cut_attempt(attempt))
        attempt["faults"] = sorted(set(attempt["faults"]))
        attempt["complete"] = not attempt["faults"]
        control_relative = (
            f"raw-esxi/log-window-v2/attempt-{attempt_number:02d}/"
            "control.json"
        )
        attempt["controlArtifact"] = control_relative
        save_json(case_dir / control_relative, attempt)
        attempt["controlSha256"] = sha256_file(
            case_dir / control_relative
        )
        attempts.append(attempt)
        if attempt["complete"]:
            selected = attempt_number
            break
    return {
        "protocol": dict(protocol),
        "attemptCount": len(attempts),
        "selectedAttempt": selected,
        "attempts": [
            {
                "attempt": item["attempt"],
                "complete": item["complete"],
                "faults": item["faults"],
                "controlArtifact": item["controlArtifact"],
                "controlSha256": item["controlSha256"],
            }
            for item in attempts
        ],
        "complete": selected is not None,
    }


def _strict_gzip_decode(raw: bytes) -> bytes:
    if len(raw) > MAX_RAW_BYTES_PER_SOURCE:
        raise LogWindowV2Error("raw gzip member exceeds byte limit")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = decoder.decompress(
            raw,
            MAX_DECODED_BYTES_PER_MEMBER + 1,
        )
    except zlib.error as error:
        raise LogWindowV2Error(
            f"gzip member failed CRC/format validation: {error}"
        ) from error
    if len(decoded) > MAX_DECODED_BYTES_PER_MEMBER:
        raise LogWindowV2Error("decoded gzip member exceeds byte limit")
    if decoder.unconsumed_tail:
        raise LogWindowV2Error("decoded gzip member exceeds byte limit")
    if (
        not decoder.eof
        or decoder.unused_data
    ):
        raise LogWindowV2Error(
            "gzip member is truncated, concatenated, or has trailing bytes"
        )
    try:
        flushed = decoder.flush(
            MAX_DECODED_BYTES_PER_MEMBER - len(decoded) + 1
        )
    except zlib.error as error:
        raise LogWindowV2Error(
            f"gzip member failed final validation: {error}"
        ) from error
    decoded += flushed
    if len(decoded) > MAX_DECODED_BYTES_PER_MEMBER:
        raise LogWindowV2Error("decoded gzip member exceeds byte limit")
    return decoded


def _ordered_source_members(
    members: Iterable[Mapping[str, Any]],
    source: str,
) -> list[Mapping[str, Any]]:
    selected = [item for item in members if item.get("source") == source]
    rotations = sorted(
        (
            item
            for item in selected
            if isinstance(item.get("generation"), int)
        ),
        key=lambda item: int(item["generation"]),
        reverse=True,
    )
    active = [item for item in selected if item.get("slot") == "active"]
    if len(active) != 1:
        raise LogWindowV2Error(
            f"{source} does not have exactly one active staged member"
        )
    return rotations + active


def _line_spans(raw: bytes) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        end = offset + len(line)
        try:
            text = line.rstrip(b"\r\n").decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise LogWindowV2Error(
                f"log bytes are not strict UTF-8: {error}"
            ) from error
        spans.append((offset, end, text))
        offset = end
    if offset < len(raw):
        tail = raw[offset:]
        try:
            text = tail.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise LogWindowV2Error(
                f"log tail is not strict UTF-8: {error}"
            ) from error
        spans.append((offset, len(raw), text))
    return spans


def _marker_spans(
    spans: Iterable[tuple[int, int, str]],
    marker: str,
) -> list[tuple[int, int, str]]:
    pattern = _marker_pattern(marker)
    return [
        (start, end, text)
        for start, end, text in spans
        if (
            pattern.search(text) is not None
            and "sshd-session" not in text
            and "running command" not in text
            and "esxcli system syslog mark" not in text
        )
    ]


def _rebuild_source(
    *,
    case_dir: Path,
    members: list[Mapping[str, Any]],
    attempt: int,
    source: str,
    before_marker: str,
    after_marker: str,
    semantic_classifier: Callable[[Iterable[str]], list[str]],
) -> dict[str, Any]:
    ordered = _ordered_source_members(members, source)
    decoded_parts: list[bytes] = []
    decoded_total = 0
    decoded_budget_exhausted = False
    member_records: list[dict[str, Any]] = []
    faults: list[str] = []
    for item in ordered:
        artifact = item.get("artifact")
        try:
            expected_artifact = _artifact_relative(attempt, item)
        except (KeyError, TypeError, ValueError) as error:
            expected_artifact = None
            faults.append(
                f"{source}/{item.get('slot')} artifact identity is invalid: "
                f"{error}"
            )
        artifact_exact = artifact == expected_artifact
        if not artifact_exact:
            faults.append(
                f"{source}/{item.get('slot')} artifact path is not canonical"
            )
        path = (
            case_dir / expected_artifact
            if isinstance(expected_artifact, str)
            else case_dir / "__invalid-log-artifact__"
        )
        exists = artifact_exact and path.is_file()
        on_disk_size = path.stat().st_size if exists else None
        within_raw_limit = bool(
            isinstance(on_disk_size, int)
            and on_disk_size <= MAX_RAW_BYTES_PER_SOURCE
        )
        if exists and not within_raw_limit:
            faults.append(
                f"{source}/{item.get('slot')} raw artifact exceeds byte limit"
            )
        raw = path.read_bytes() if exists and within_raw_limit else b""
        actual_size = on_disk_size
        actual_digest = (
            sha256_bytes(raw) if exists and within_raw_limit else None
        )
        exact = bool(
            exists
            and within_raw_limit
            and actual_size == item.get("cutBytes")
            and actual_digest == item.get("stageSha256")
            and actual_size == item.get("localSizeBytes")
            and actual_digest == item.get("localSha256")
        )
        try:
            decoded = (
                b""
                if decoded_budget_exhausted
                else (
                    _strict_gzip_decode(raw)
                    if item.get("encoding") == "gzip"
                    else raw
                )
            )
        except LogWindowV2Error as error:
            decoded = b""
            faults.append(
                f"{source}/{item.get('slot')} decode failed: {error}"
            )
        if (
            not decoded_budget_exhausted
            and decoded_total + len(decoded)
            > MAX_DECODED_BYTES_PER_SOURCE
        ):
            decoded = b""
            decoded_budget_exhausted = True
            faults.append(f"{source} decoded rotation chain exceeds byte limit")
        else:
            decoded_total += len(decoded)
        if not exact:
            faults.append(
                f"{source}/{item.get('slot')} raw artifact size/hash drift"
            )
        decoded_parts.append(decoded)
        member_records.append(
            {
                "slot": item.get("slot"),
                "generation": item.get("generation"),
                "encoding": item.get("encoding"),
                "artifact": artifact,
                "rawSizeBytes": actual_size,
                "rawSha256": actual_digest,
                "decodedSizeBytes": len(decoded),
                "exact": exact,
            }
        )
    combined = b"".join(decoded_parts)
    try:
        spans = _line_spans(combined)
    except LogWindowV2Error as error:
        spans = []
        faults.append(str(error))
    before = _marker_spans(spans, before_marker)
    after = _marker_spans(spans, after_marker)
    if len(before) != 1:
        faults.append(
            f"{source} BEFORE marker count is {len(before)}, expected 1"
        )
    if len(after) != 1:
        faults.append(
            f"{source} AFTER marker count is {len(after)}, expected 1"
        )
    crop = b""
    crop_start: int | None = None
    crop_end: int | None = None
    if len(before) == 1 and len(after) == 1:
        crop_start = before[0][1]
        crop_end = after[0][0]
        if crop_start > crop_end:
            faults.append(f"{source} marker order is reversed")
        else:
            crop = combined[crop_start:crop_end]
    try:
        crop_text = crop.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        crop_text = ""
        faults.append(f"{source} strict marker crop is not UTF-8: {error}")
    semantic_lines = (
        semantic_classifier(crop_text.splitlines())
        if not faults
        else []
    )
    return {
        "source": source,
        "complete": not faults,
        "faults": sorted(set(faults)),
        "members": member_records,
        "combinedDecodedBytes": len(combined),
        "markers": {
            "before": {
                "value": before_marker,
                "count": len(before),
                "matchedLines": [item[2] for item in before],
                "byteOffset": before[0][0] if len(before) == 1 else None,
            },
            "after": {
                "value": after_marker,
                "count": len(after),
                "matchedLines": [item[2] for item in after],
                "byteOffset": after[0][0] if len(after) == 1 else None,
            },
        },
        "crop": {
            "startByte": crop_start,
            "endByte": crop_end,
            "sizeBytes": len(crop),
            "sha256": sha256_bytes(crop),
        },
        "semanticAerLines": semantic_lines,
    }


def rebuild_log_window(
    *,
    case_dir: Path,
    campaign_id: str,
    case_id: str,
    case_protocol: Any,
    capture_summary: Any,
    semantic_classifier: Callable[[Iterable[str]], list[str]],
) -> dict[str, Any]:
    """Rebuild the V2 conclusion solely from manifest-bound raw artifacts."""

    faults: list[str] = []
    try:
        protocol = validate_protocol(
            case_protocol,
            campaign_id=campaign_id,
            case_id=case_id,
        )
    except (LogWindowV2Error, ValueError) as error:
        faults.append(str(error))
        protocol = protocol_for_case(
            (
                campaign_id
                if isinstance(campaign_id, str) and campaign_id
                else "__invalid-campaign__"
            ),
            (
                case_id
                if isinstance(case_id, str) and case_id
                else "__invalid-case__"
            ),
        )
    if not isinstance(capture_summary, Mapping):
        faults.append("capture summary is not an object")
    summary = capture_summary if isinstance(capture_summary, Mapping) else {}
    if summary.get("protocol") != protocol:
        faults.append("capture summary protocol differs from the case binding")
    if summary.get("complete") is not True:
        faults.append("capture summary does not declare complete")
    attempts = summary.get("attempts")
    attempts = attempts if isinstance(attempts, list) else []
    if not isinstance(summary.get("attempts"), list):
        faults.append("capture summary attempts list is malformed")
    attempt_count = summary.get("attemptCount")
    if (
        not isinstance(attempt_count, int)
        or isinstance(attempt_count, bool)
        or not 1 <= attempt_count <= MAX_CAPTURE_ATTEMPTS
    ):
        faults.append("capture summary attemptCount is outside the closed range")
    elif attempt_count != len(attempts):
        faults.append("capture summary attemptCount differs from attempts")
    mapping_attempts = [
        item for item in attempts if isinstance(item, Mapping)
    ]
    if len(mapping_attempts) != len(attempts):
        faults.append("capture summary contains a non-object attempt")
    attempt_ids = [item.get("attempt") for item in mapping_attempts]
    if attempt_ids != list(range(1, len(mapping_attempts) + 1)):
        faults.append("capture summary attempts are not unique and sequential")
    selected = summary.get("selectedAttempt")
    if (
        not isinstance(selected, int)
        or isinstance(selected, bool)
        or not 1 <= selected <= MAX_CAPTURE_ATTEMPTS
    ):
        faults.append("capture summary has no selected attempt")
        selected = None
    elif selected != len(mapping_attempts):
        faults.append("selected capture attempt is not the final attempt")

    controls: dict[int, dict[str, Any]] = {}
    for ordinal, record in enumerate(mapping_attempts, start=1):
        expected_relative = (
            f"raw-esxi/log-window-v2/attempt-{ordinal:02d}/control.json"
        )
        declared_faults = record.get("faults")
        if (
            record.get("attempt") != ordinal
            or record.get("controlArtifact") != expected_relative
            or not isinstance(declared_faults, list)
            or not all(isinstance(item, str) for item in declared_faults)
        ):
            faults.append(
                f"capture summary attempt {ordinal} reference is malformed"
            )
        expected_complete = ordinal == selected
        if record.get("complete") is not expected_complete:
            faults.append(
                f"capture summary attempt {ordinal} completion state differs"
            )
        if expected_complete and declared_faults != []:
            faults.append("selected capture summary attempt contains faults")
        if not expected_complete and declared_faults == []:
            faults.append(
                f"failed capture summary attempt {ordinal} has no fault"
            )
        control_path_item = case_dir / expected_relative
        declared_hash = record.get("controlSha256")
        if (
            not isinstance(declared_hash, str)
            or SHA256_RE.fullmatch(declared_hash) is None
        ):
            faults.append(
                f"capture summary attempt {ordinal} control hash is malformed"
            )
        if not control_path_item.is_file():
            faults.append(
                f"capture summary attempt {ordinal} control artifact is missing"
            )
            continue
        try:
            if control_path_item.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("control artifact exceeds byte limit")
            loaded = json.loads(control_path_item.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise TypeError("control JSON is not an object")
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            faults.append(
                f"capture summary attempt {ordinal} control is invalid: {error}"
            )
            continue
        controls[ordinal] = loaded
        if declared_hash != sha256_file(control_path_item):
            faults.append(
                f"capture summary attempt {ordinal} control SHA-256 differs"
            )
        if (
            loaded.get("attempt") != ordinal
            or loaded.get("protocol") != PROTOCOL_ID
            or loaded.get("controlArtifact") != expected_relative
            or loaded.get("complete") is not record.get("complete")
            or loaded.get("faults") != declared_faults
            or loaded.get("stageDirectory")
            != f"/tmp/qmlogv2-{protocol['markerId']}-{ordinal:02d}"
        ):
            faults.append(
                f"capture summary attempt {ordinal} differs from its control"
            )

    control_relative = (
        f"raw-esxi/log-window-v2/attempt-{selected:02d}/control.json"
        if isinstance(selected, int)
        else None
    )
    control: dict[str, Any] = (
        controls.get(selected, {}) if isinstance(selected, int) else {}
    )
    if not control:
        faults.append("selected V2 control artifact is missing")
    if control:
        if control.get("attempt") != selected:
            faults.append("selected V2 control attempt identity differs")
        if control.get("protocol") != PROTOCOL_ID:
            faults.append("selected V2 control protocol differs")
        faults.extend(validate_cut_attempt(control))
        if control.get("complete") is not True:
            faults.append("selected V2 control does not declare complete")
        declared_faults = control.get("faults")
        if declared_faults != []:
            faults.append("selected V2 control contains declared faults")

    source_results: dict[str, Any] = {}
    staged_members = (
        control.get("stagedMembers")
        if isinstance(control.get("stagedMembers"), list)
        else []
    )
    for source in LOG_PATHS:
        try:
            source_results[source] = _rebuild_source(
                case_dir=case_dir,
                members=staged_members,
                attempt=selected if isinstance(selected, int) else 0,
                source=source,
                before_marker=protocol["before"],
                after_marker=protocol["after"],
                semantic_classifier=semantic_classifier,
            )
        except Exception as error:
            source_results[source] = {
                "source": source,
                "complete": False,
                "faults": [
                    "source rebuild failed closed: "
                    f"{type(error).__name__}: {error}"
                ],
                "members": [],
                "combinedDecodedBytes": 0,
                "markers": {
                    "before": {
                        "value": protocol["before"],
                        "count": 0,
                        "matchedLines": [],
                        "byteOffset": None,
                    },
                    "after": {
                        "value": protocol["after"],
                        "count": 0,
                        "matchedLines": [],
                        "byteOffset": None,
                    },
                },
                "crop": {
                    "startByte": None,
                    "endByte": None,
                    "sizeBytes": 0,
                    "sha256": sha256_bytes(b""),
                },
                "semanticAerLines": [],
            }
    sources_complete = bool(source_results) and all(
        item.get("complete") is True
        for item in source_results.values()
    )
    semantic_events = [
        {
            "source": source,
            "line": line,
        }
        for source, result in source_results.items()
        for line in result.get("semanticAerLines", [])
    ]
    complete = not faults and sources_complete
    classification = (
        "INCONCLUSIVE_LOG_WINDOW"
        if not complete
        else (
            "MATCHING_EVENT_OBSERVED"
            if semantic_events
            else "NOT_OBSERVED_IN_STRICT_PER_SOURCE_MARKER_WINDOW"
        )
    )
    return {
        "protocol": protocol,
        "complete": complete,
        "faults": sorted(set(faults)),
        "selectedAttempt": selected,
        "controlArtifact": control_relative,
        "sources": source_results,
        "semanticAerEvents": semantic_events,
        "semanticAerLines": [
            item["line"] for item in semantic_events
        ],
        "classification": classification,
        "notEquivalentTo": (
            "proof that ESXi did not deliver, service, clear, recover, "
            "or health-handle a PCIe notification"
        ),
    }


__all__ = [
    "LOG_PATHS",
    "LogWindowV2Error",
    "MAX_CAPTURE_ATTEMPTS",
    "MAX_DECODED_BYTES_PER_SOURCE",
    "PROTOCOL_ID",
    "authentic_marker_lines",
    "capture_inventory",
    "capture_rotation_chain",
    "inventory_command",
    "marker_command",
    "marker_probe_command",
    "parse_inventory",
    "protocol_for_case",
    "rebuild_log_window",
    "sha256_file",
    "validate_cut_attempt",
    "validate_protocol",
    "wait_for_marker",
]
