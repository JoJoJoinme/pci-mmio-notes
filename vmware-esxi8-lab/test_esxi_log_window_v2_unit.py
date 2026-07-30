#!/usr/bin/env python3
"""Offline unit tests for the ESXi marker/rotation log-window V2 protocol.

These tests deliberately use only temporary local artifacts.  They do not
connect to ESXi, QEMU, or any other laboratory endpoint.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable
from unittest import mock

import esxi_log_window_v2 as log_v2


CAMPAIGN_ID = "offline-log-v2-campaign"
CASE_ID = "first-multiple-r01"


def _marker_line(marker: str) -> bytes:
    return (
        "2026-07-28T17:06:51.886Z In(190) "
        f"Hostd[132082]: mark: {marker}\n"
    ).encode("utf-8")


def _semantic_classifier(lines: Iterable[str]) -> list[str]:
    return [line for line in lines if "AER-COR" in line]


def _remote_path(
    source: str,
    generation: int | None,
    encoding: str,
) -> str:
    active = log_v2.LOG_PATHS[source]
    if generation is None:
        return active
    stem = active[:-4] if active.endswith(".log") else active
    suffix = ".gz" if encoding == "gzip" else ""
    return f"{stem}.{generation}{suffix}"


def _encoded(decoded: bytes, encoding: str) -> bytes:
    if encoding == "gzip":
        return gzip.compress(decoded, mtime=0)
    if encoding == "plain":
        return decoded
    raise ValueError(encoding)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _rebind_inventory_transcript(inventory: dict[str, Any]) -> None:
    stdout = "".join(
        (
            f"MEMBER\t{item['source']}\t{item['remotePath']}\t"
            f"{item['lstatInode']}\t{item['lstatSizeBytes']}\t"
            f"{item['targetInode']}\t{item['targetSizeBytes']}\t"
            f"{item['sha256']}\n"
        )
        for item in inventory["members"]
    )
    rebuilt = log_v2.parse_inventory(
        stdout,
        command=log_v2.inventory_command(),
        return_code=0,
        stderr="",
    )
    inventory.clear()
    inventory.update(rebuilt)


def _rebind_proof_transcript(proof: dict[str, Any]) -> None:
    label = proof["label"]
    proof["command"]["stdout"] = "".join(
        (
            f"{label}\t{item['source']}\t{item['slot']}\t"
            f"{item['sizeBytes']}\t{item['sha256']}\n"
        )
        for item in proof["proofs"]
    )


class _CaseFixture:
    """Create a self-consistent, manifest-bound local capture."""

    def __init__(
        self,
        case_dir: Path,
        pieces_factory: Callable[
            [str, dict[str, Any]],
            list[tuple[int | None, str, bytes]],
        ],
    ) -> None:
        self.case_dir = case_dir
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.protocol = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)
        self.stage_dir = (
            f"/tmp/qmlogv2-{self.protocol['markerId']}-01"
        )
        self.staged: list[dict[str, Any]] = []
        inventory_members: list[dict[str, Any]] = []
        inode = 1000

        for source in log_v2.LOG_PATHS:
            pieces = pieces_factory(source, self.protocol)
            for generation, encoding, decoded in pieces:
                slot = (
                    "active"
                    if generation is None
                    else f"rot-{generation:03d}"
                )
                raw = _encoded(decoded, encoding)
                digest = hashlib.sha256(raw).hexdigest()
                extension = ".gz" if encoding == "gzip" else ".raw"
                artifact = (
                    "raw-esxi/log-window-v2/attempt-01/"
                    f"{source}/{slot}{extension}"
                )
                artifact_path = self.case_dir / artifact
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_bytes(raw)
                remote_path = _remote_path(source, generation, encoding)
                remote_stage = (
                    f"{self.stage_dir}/{source}--{slot}{extension}"
                )
                stage_command = "\n".join(
                    [
                        "set -e",
                        (
                            f"cp {shlex.quote(remote_path)} "
                            f"{shlex.quote(remote_stage)}"
                        ),
                        (
                            "sz=$(stat -c '%s' "
                            f"{shlex.quote(remote_stage)})"
                        ),
                        (
                            "sh=$(sha256sum "
                            f"{shlex.quote(remote_stage)})"
                        ),
                        "sh=${sh%% *}",
                        (
                            f"printf 'STAGE\\t{source}\\t{slot}"
                            "\\t%s\\t%s\\n' \"$sz\" \"$sh\""
                        ),
                    ]
                )
                staged = {
                    "source": source,
                    "slot": slot,
                    "generation": generation,
                    "encoding": encoding,
                    "remotePath": remote_path,
                    "remoteStagePath": remote_stage,
                    "artifact": artifact,
                    "command": {
                        "command": stage_command,
                        "returnCode": 0,
                        "stdout": (
                            f"STAGE\t{source}\t{slot}\t"
                            f"{len(raw)}\t{digest}\n"
                        ),
                        "stderr": "",
                    },
                    "cutBytes": len(raw),
                    "stageSha256": digest,
                    "copied": True,
                    "copyFault": None,
                    "localSizeBytes": len(raw),
                    "localSha256": digest,
                    "complete": True,
                    "faults": [],
                }
                self.staged.append(staged)
                inventory_members.append(
                    {
                        "source": source,
                        "remotePath": remote_path,
                        "slot": slot,
                        "generation": generation,
                        "encoding": encoding,
                        "lstatInode": inode,
                        "lstatSizeBytes": len(raw),
                        "targetInode": inode,
                        "targetSizeBytes": len(raw),
                        "sha256": digest,
                    }
                )
                inode += 1

        inventory_stdout = "".join(
            (
                f"MEMBER\t{item['source']}\t{item['remotePath']}\t"
                f"{item['lstatInode']}\t{item['lstatSizeBytes']}\t"
                f"{item['targetInode']}\t{item['targetSizeBytes']}\t"
                f"{item['sha256']}\n"
            )
            for item in inventory_members
        )
        inventory = log_v2.parse_inventory(
            inventory_stdout,
            command=log_v2.inventory_command(),
            return_code=0,
            stderr="",
        )
        if inventory["complete"] is not True:
            raise AssertionError(inventory["faults"])
        staged_by_identity = {
            (item["source"], item["slot"]): item
            for item in self.staged
        }
        self.staged = [
            staged_by_identity[(item["source"], item["slot"])]
            for item in inventory["members"]
        ]

        def proof(label: str) -> dict[str, Any]:
            command, _paths = log_v2._proof_command(
                label=label,
                stage_dir=self.stage_dir,
                staged=self.staged,
            )
            proofs = sorted(
                (
                    {
                        "source": item["source"],
                        "slot": item["slot"],
                        "sizeBytes": item["cutBytes"],
                        "sha256": item["stageSha256"],
                    }
                    for item in self.staged
                ),
                key=lambda item: (item["source"], item["slot"]),
            )
            stdout = "".join(
                (
                    f"{label}\t{item['source']}\t{item['slot']}\t"
                    f"{item['cutBytes']}\t{item['stageSha256']}\n"
                )
                for item in self.staged
            )
            return {
                "label": label,
                "command": {
                    "command": command,
                    "returnCode": 0,
                    "stdout": stdout,
                    "stderr": "",
                },
                "proofs": proofs,
                "complete": True,
                "faults": [],
            }

        proof1 = proof("P1")
        proof2 = proof("P2")
        proof_paths = sorted(
            (
                f"{self.stage_dir}/{item['source']}--"
                f"{item['slot']}.{label}"
            )
            for item in self.staged
            for label in ("p1", "p2")
        )
        cleanup_files = sorted(
            {item["remoteStagePath"] for item in self.staged}
            | set(proof_paths)
        )
        cleanup_command = "\n".join(
            [
                "set -e",
                *[
                    f"rm -f {shlex.quote(path)}"
                    for path in cleanup_files
                ],
                f"rmdir {shlex.quote(self.stage_dir)}",
            ]
        )
        stage_create_command = (
            f"[ ! -e {shlex.quote(self.stage_dir)} ] "
            f"&& mkdir {shlex.quote(self.stage_dir)}"
        )
        self.control: dict[str, Any] = {
            "protocol": log_v2.PROTOCOL_ID,
            "attempt": 1,
            "stageDirectory": self.stage_dir,
            "stageCreate": {
                "command": stage_create_command,
                "returnCode": 0,
                "stdout": "",
                "stderr": "",
            },
            "inventoryA": copy.deepcopy(inventory),
            "inventoryB": copy.deepcopy(inventory),
            "inventoryC": copy.deepcopy(inventory),
            "stagedMembers": self.staged,
            "prefixProof1": proof1,
            "prefixProof2": proof2,
            "cleanup": {
                "command": cleanup_command,
                "returnCode": 0,
                "stdout": "",
                "stderr": "",
                "complete": True,
            },
            "faults": [],
            "complete": True,
            "controlArtifact": (
                "raw-esxi/log-window-v2/attempt-01/control.json"
            ),
        }
        self.control_path = (
            self.case_dir
            / "raw-esxi/log-window-v2/attempt-01/control.json"
        )
        self.summary: dict[str, Any] = {
            "protocol": copy.deepcopy(self.protocol),
            "attemptCount": 1,
            "selectedAttempt": 1,
            "attempts": [
                {
                    "attempt": 1,
                    "complete": True,
                    "faults": [],
                    "controlArtifact": (
                        "raw-esxi/log-window-v2/attempt-01/control.json"
                    ),
                    "controlSha256": "",
                }
            ],
            "complete": True,
        }
        self.bind_control()

    def bind_control(self) -> None:
        _write_json(self.control_path, self.control)
        self.summary["attempts"][0]["controlSha256"] = (
            log_v2.sha256_file(self.control_path)
        )

    def rebuild(self) -> dict[str, Any]:
        return log_v2.rebuild_log_window(
            case_dir=self.case_dir,
            campaign_id=CAMPAIGN_ID,
            case_id=CASE_ID,
            case_protocol=self.protocol,
            capture_summary=self.summary,
            semantic_classifier=_semantic_classifier,
        )


def _active_pieces(
    _source: str,
    protocol: dict[str, Any],
) -> list[tuple[int | None, str, bytes]]:
    return [
        (
            None,
            "plain",
            (
                _marker_line(protocol["before"])
                + b"AER-COR one\n"
                + _marker_line(protocol["after"])
            ),
        )
    ]


class ProtocolAndMarkerTests(unittest.TestCase):
    def test_protocol_is_deterministic_opaque_and_case_bound(self) -> None:
        first = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)
        second = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)
        self.assertEqual(first, second)
        expected_id = hashlib.sha256(
            (
                f"{log_v2.PROTOCOL_ID}\x00{CAMPAIGN_ID}\x00{CASE_ID}"
            ).encode("utf-8")
        ).hexdigest()[:32]
        self.assertEqual(first["markerId"], expected_id)
        self.assertEqual(
            first["before"],
            f"QMLOGV2.{expected_id}.B",
        )
        self.assertEqual(
            first["after"],
            f"QMLOGV2.{expected_id}.A",
        )
        self.assertNotEqual(
            first,
            log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID + "-other"),
        )
        self.assertNotEqual(
            first,
            log_v2.protocol_for_case(CAMPAIGN_ID + "-other", CASE_ID),
        )

        changed = copy.deepcopy(first)
        changed["markerId"] = "0" * 32
        with self.assertRaises(log_v2.LogWindowV2Error):
            log_v2.validate_protocol(
                changed,
                campaign_id=CAMPAIGN_ID,
                case_id=CASE_ID,
            )

    def test_marker_authentication_accepts_only_exact_mark_lines(self) -> None:
        marker = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)["before"]
        authentic = (
            "2026-07-28T17:06:51.886Z In(190) "
            "Hostd[132082]: mark: "
            f"{marker}"
        )
        text = "\n".join(
            [
                authentic,
                (
                    "2026-07-28T17:06:51.886Z In(190) "
                    f"Vmkernel[7]: mark: {marker}"
                ),
                f"arbitrary payload mark: {marker}",
                f"sshd-session mark: {marker}",
                f"running command mark: {marker}",
                f"esxcli system syslog mark mark: {marker}",
                f"mark: {marker} suffix",
                f"mark:{marker}",
                f"mark: {marker.lower()[:-1]}A",
                "unrelated",
            ]
        )
        self.assertEqual(
            log_v2.authentic_marker_lines(text, marker),
            [authentic],
        )
        self.assertEqual(
            log_v2.marker_command(marker),
            f"esxcli system syslog mark --message={marker}",
        )
        for unsafe in (
            "",
            "QMLOGV2.bad.B",
            f"{marker}; reboot",
            marker + "\nanything",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    log_v2.marker_command(unsafe)

    def test_marker_probe_is_fixed_and_token_free(self) -> None:
        marker = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)["before"]
        commands = {
            source: log_v2.marker_probe_command(source)
            for source in log_v2.LOG_PATHS
        }
        for source, command in commands.items():
            with self.subTest(source=source):
                self.assertNotIn(marker, command)
                self.assertNotIn("QMLOGV2", command)
                self.assertIn(log_v2.LOG_PATHS[source], command)

    def test_wait_for_marker_requires_one_authentic_line_per_source(
        self,
    ) -> None:
        marker = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)["before"]
        authentic = _marker_line(marker).decode("utf-8")

        class Ssh:
            def __init__(self, values: dict[str, str]) -> None:
                self.values = values

            def run(
                self,
                command: str,
                *,
                check: bool,
                timeout: int,
            ) -> SimpleNamespace:
                del check, timeout
                source = next(
                    source
                    for source, path in log_v2.LOG_PATHS.items()
                    if path in command
                )
                return SimpleNamespace(
                    returncode=0,
                    stdout=self.values[source],
                    stderr="",
                )

        class Cancel:
            def __init__(self) -> None:
                self.waits = 0

            def is_set(self) -> bool:
                return False

            def wait(self, _seconds: float) -> None:
                self.waits += 1

        class Clock:
            def __init__(self) -> None:
                self.value = 0.0

            def __call__(self) -> float:
                self.value += 0.2
                return self.value

        visible = log_v2.wait_for_marker(
            Ssh({source: authentic for source in log_v2.LOG_PATHS}),
            marker,
            Cancel(),
            timeout_seconds=2.0,
            monotonic=Clock(),
        )
        self.assertTrue(visible["visible"])
        self.assertFalse(visible["ambiguous"])

        duplicate_values = {
            source: authentic for source in log_v2.LOG_PATHS
        }
        duplicate_values["vobd"] = authentic + authentic
        duplicate = log_v2.wait_for_marker(
            Ssh(duplicate_values),
            marker,
            Cancel(),
            timeout_seconds=2.0,
            monotonic=Clock(),
        )
        self.assertFalse(duplicate["visible"])
        self.assertTrue(duplicate["ambiguous"])
        self.assertEqual(
            duplicate["sources"]["vobd"]["authenticCount"],
            2,
        )

        missing_values = {
            source: authentic for source in log_v2.LOG_PATHS
        }
        missing_values["syslog"] = "unrelated\n"
        cancel = Cancel()
        missing = log_v2.wait_for_marker(
            Ssh(missing_values),
            marker,
            cancel,
            timeout_seconds=1.0,
            monotonic=Clock(),
        )
        self.assertFalse(missing["visible"])
        self.assertFalse(missing["ambiguous"])
        self.assertGreaterEqual(cancel.waits, 1)


class InventoryAndCutTests(unittest.TestCase):
    @staticmethod
    def _inventory_line(
        source: str,
        path: str,
        inode: int,
        size: int,
        digest: str,
    ) -> str:
        return (
            f"MEMBER\t{source}\t{path}\t{inode}\t{size}"
            f"\t{inode}\t{size}\t{digest}"
        )

    def test_inventory_parse_accepts_closed_continuous_layout(self) -> None:
        digest = "1" * 64
        lines: list[str] = []
        inode = 10
        for source, active in log_v2.LOG_PATHS.items():
            lines.append(
                self._inventory_line(source, active, inode, 100, digest)
            )
            inode += 1
        lines.extend(
            [
                self._inventory_line(
                    "syslog",
                    "/var/run/log/syslog.0.gz",
                    inode,
                    90,
                    digest,
                ),
                self._inventory_line(
                    "syslog",
                    "/var/run/log/syslog.1.gz",
                    inode + 1,
                    80,
                    digest,
                ),
            ]
        )
        result = log_v2.parse_inventory(
            "\n".join(lines) + "\n",
            command=log_v2.inventory_command(),
            return_code=0,
            stderr="",
        )
        self.assertTrue(result["complete"], result["faults"])
        syslog = [
            item for item in result["members"]
            if item["source"] == "syslog"
        ]
        self.assertEqual(
            [item["slot"] for item in syslog],
            ["active", "rot-000", "rot-001"],
        )
        self.assertEqual(
            [item["encoding"] for item in syslog],
            ["plain", "gzip", "gzip"],
        )

    def test_inventory_parse_rejects_malformed_duplicate_and_gapped_layout(
        self,
    ) -> None:
        digest = "2" * 64
        base = [
            self._inventory_line(source, active, 20 + index, 10, digest)
            for index, (source, active) in enumerate(
                log_v2.LOG_PATHS.items()
            )
        ]
        bad = base + [
            self._inventory_line(
                "syslog",
                "/var/run/log/syslog.0.gz",
                30,
                10,
                digest,
            ),
            self._inventory_line(
                "syslog",
                "/var/run/log/syslog.log.0.gz",
                31,
                10,
                digest,
            ),
            self._inventory_line(
                "vmkernel",
                "/var/run/log/vmkernel.1.gz",
                32,
                10,
                digest,
            ),
            "not-an-inventory-line",
        ]
        result = log_v2.parse_inventory(
            "\n".join(bad),
            command=log_v2.inventory_command() + "\n# drift",
            return_code=9,
            stderr="unexpected",
        )
        self.assertFalse(result["complete"])
        joined = "\n".join(result["faults"])
        self.assertIn("inventory command differs", joined)
        self.assertIn("inventory command returned 9", joined)
        self.assertIn("inventory command produced stderr", joined)
        self.assertIn("inventory slot is duplicated", joined)
        self.assertIn("rotation generations are not continuous", joined)
        self.assertIn("is malformed", joined)

    def test_inventory_parse_enforces_per_source_raw_byte_limit(self) -> None:
        digest = "3" * 64
        lines = [
            self._inventory_line(source, active, 40 + index, 10, digest)
            for index, (source, active) in enumerate(
                log_v2.LOG_PATHS.items()
            )
        ]
        lines.append(
            self._inventory_line(
                "syslog",
                "/var/run/log/syslog.0.gz",
                50,
                10,
                digest,
            )
        )
        with mock.patch.object(
            log_v2,
            "MAX_RAW_BYTES_PER_SOURCE",
            15,
        ):
            result = log_v2.parse_inventory(
                "\n".join(lines),
                command=log_v2.inventory_command(),
                return_code=0,
                stderr="",
            )
        self.assertFalse(result["complete"])
        self.assertTrue(
            any(
                "raw rotation chain exceeds byte limit" in fault
                for fault in result["faults"]
            ),
            result["faults"],
        )

    def test_abc_cut_validation_accepts_stable_rotations_and_active_prefix(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), _active_pieces)
            self.assertEqual(
                log_v2.validate_cut_attempt(fixture.control),
                [],
            )

    def test_abc_cut_validation_rejects_set_drift_mutation_and_shrink(
        self,
    ) -> None:
        def pieces(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (
                    0,
                    "gzip",
                    b"old log\n" + _marker_line(protocol["before"]),
                ),
                (
                    None,
                    "plain",
                    b"AER-COR current\n"
                    + _marker_line(protocol["after"]),
                ),
            ]

        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), pieces)
            self.assertEqual(
                log_v2.validate_cut_attempt(fixture.control),
                [],
            )

            set_drift = copy.deepcopy(fixture.control)
            set_drift["inventoryC"]["members"].pop()
            _rebind_inventory_transcript(set_drift["inventoryC"])
            self.assertTrue(
                any(
                    "member sets differ" in fault
                    for fault in log_v2.validate_cut_attempt(set_drift)
                )
            )

            rotation_mutation = copy.deepcopy(fixture.control)
            rotated = next(
                item
                for item in rotation_mutation["inventoryC"]["members"]
                if item["source"] == "syslog"
                and item["slot"] == "rot-000"
            )
            rotated["sha256"] = "f" * 64
            _rebind_inventory_transcript(
                rotation_mutation["inventoryC"]
            )
            self.assertTrue(
                any(
                    "rotated member changed" in fault
                    for fault in log_v2.validate_cut_attempt(
                        rotation_mutation
                    )
                )
            )

            active_shrink = copy.deepcopy(fixture.control)
            active = next(
                item
                for item in active_shrink["inventoryB"]["members"]
                if item["source"] == "syslog"
                and item["slot"] == "active"
            )
            staged = next(
                item
                for item in active_shrink["stagedMembers"]
                if item["source"] == "syslog"
                and item["slot"] == "active"
            )
            active["targetSizeBytes"] = staged["cutBytes"] - 1
            _rebind_inventory_transcript(active_shrink["inventoryB"])
            self.assertTrue(
                any(
                    "append-safe staged prefix" in fault
                    for fault in log_v2.validate_cut_attempt(active_shrink)
                )
            )

            bad_proof = copy.deepcopy(fixture.control)
            proof = next(
                item
                for item in bad_proof["prefixProof2"]["proofs"]
                if item["source"] == "syslog"
                and item["slot"] == "active"
            )
            proof["sha256"] = "e" * 64
            _rebind_proof_transcript(bad_proof["prefixProof2"])
            self.assertTrue(
                any(
                    "staged cut/prefix hashes are inconsistent" in fault
                    for fault in log_v2.validate_cut_attempt(bad_proof)
                )
            )

    def test_cut_validation_rejects_duplicate_evidence_identities(self) -> None:
        mutations = {
            "inventory": lambda value: value["inventoryB"][
                "members"
            ].append(copy.deepcopy(value["inventoryB"]["members"][0])),
            "staged": lambda value: value["stagedMembers"].append(
                copy.deepcopy(value["stagedMembers"][0])
            ),
            "proof": lambda value: value["prefixProof2"][
                "proofs"
            ].append(
                copy.deepcopy(value["prefixProof2"]["proofs"][0])
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = _CaseFixture(
                        Path(directory),
                        _active_pieces,
                    )
                    changed = copy.deepcopy(fixture.control)
                    mutate(changed)
                    faults = log_v2.validate_cut_attempt(changed)
                    self.assertTrue(
                        any(
                            "duplicate" in fault or "differs" in fault
                            for fault in faults
                        ),
                        faults,
                    )


class RebuildTests(unittest.TestCase):
    def test_raw_and_gzip_chain_rebuilds_in_oldest_to_active_order(
        self,
    ) -> None:
        def pieces(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (
                    2,
                    "gzip",
                    b"outside-before\n"
                    + _marker_line(protocol["before"]),
                ),
                (1, "gzip", b"AER-COR oldest\n"),
                (0, "gzip", b"AER-COR newer\n"),
                (
                    None,
                    "plain",
                    b"AER-COR active\n"
                    + _marker_line(protocol["after"])
                    + b"outside-after\n",
                ),
            ]

        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), pieces)
            result = fixture.rebuild()
            self.assertTrue(result["complete"], result["faults"])
            self.assertEqual(
                result["classification"],
                "MATCHING_EVENT_OBSERVED",
            )
            for source, source_result in result["sources"].items():
                with self.subTest(source=source):
                    self.assertTrue(
                        source_result["complete"],
                        source_result["faults"],
                    )
                    self.assertEqual(
                        [
                            item["slot"]
                            for item in source_result["members"]
                        ],
                        [
                            "rot-002",
                            "rot-001",
                            "rot-000",
                            "active",
                        ],
                    )
                    self.assertEqual(
                        source_result["semanticAerLines"],
                        [
                            "AER-COR oldest",
                            "AER-COR newer",
                            "AER-COR active",
                        ],
                    )
                    matched = (
                        source_result["markers"]["before"]["matchedLines"]
                        + source_result["markers"]["after"]["matchedLines"]
                    )
                    self.assertFalse(
                        any("outside-" in line for line in matched)
                    )

    def test_marker_missing_duplicate_and_reverse_are_inconclusive(
        self,
    ) -> None:
        def missing(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (
                    None,
                    "plain",
                    b"AER-COR event\n" + _marker_line(protocol["after"]),
                )
            ]

        def duplicate(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (
                    None,
                    "plain",
                    _marker_line(protocol["before"])
                    + _marker_line(protocol["before"])
                    + b"AER-COR event\n"
                    + _marker_line(protocol["after"]),
                )
            ]

        def reversed_order(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (
                    None,
                    "plain",
                    _marker_line(protocol["after"])
                    + b"AER-COR event\n"
                    + _marker_line(protocol["before"]),
                )
            ]

        scenarios = {
            "missing": (missing, "BEFORE marker count is 0"),
            "duplicate": (duplicate, "BEFORE marker count is 2"),
            "reversed": (reversed_order, "marker order is reversed"),
        }
        for name, (factory, expected_fault) in scenarios.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = _CaseFixture(Path(directory), factory)
                    result = fixture.rebuild()
                    self.assertFalse(result["complete"])
                    self.assertEqual(
                        result["classification"],
                        "INCONCLUSIVE_LOG_WINDOW",
                    )
                    for source_result in result["sources"].values():
                        self.assertTrue(
                            any(
                                expected_fault in fault
                                for fault in source_result["faults"]
                            ),
                            source_result["faults"],
                        )
                        self.assertEqual(
                            source_result["semanticAerLines"],
                            [],
                        )

    def test_raw_artifact_and_control_tamper_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), _active_pieces)
            target = fixture.case_dir / fixture.staged[0]["artifact"]
            raw = target.read_bytes()
            target.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            result = fixture.rebuild()
            self.assertFalse(result["complete"])
            self.assertTrue(
                any(
                    "raw artifact size/hash drift" in fault
                    for fault in result["sources"]["syslog"]["faults"]
                )
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), _active_pieces)
            control = json.loads(
                fixture.control_path.read_text(encoding="utf-8")
            )
            control["cleanup"] = {"complete": False}
            _write_json(fixture.control_path, control)
            result = fixture.rebuild()
            self.assertFalse(result["complete"])
            self.assertTrue(
                any(
                    "control SHA-256 differs" in fault
                    for fault in result["faults"]
                ),
                result["faults"],
            )

    def test_raw_transcript_and_derived_fields_cannot_diverge(self) -> None:
        def replace_last_digest(text: str) -> str:
            lines = text.splitlines()
            fields = lines[0].split("\t")
            fields[-1] = (
                "0" * 64 if fields[-1] != "0" * 64 else "1" * 64
            )
            lines[0] = "\t".join(fields)
            return "\n".join(lines) + "\n"

        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "inventory-a": lambda control: control["inventoryA"].update(
                {
                    "stdout": replace_last_digest(
                        control["inventoryA"]["stdout"]
                    )
                }
            ),
            "inventory-b": lambda control: control["inventoryB"].update(
                {
                    "stdout": replace_last_digest(
                        control["inventoryB"]["stdout"]
                    )
                }
            ),
            "inventory-c": lambda control: control["inventoryC"].update(
                {
                    "stdout": replace_last_digest(
                        control["inventoryC"]["stdout"]
                    )
                }
            ),
            "proof-p1": lambda control: control["prefixProof1"][
                "command"
            ].update(
                {
                    "stdout": replace_last_digest(
                        control["prefixProof1"]["command"]["stdout"]
                    )
                }
            ),
            "proof-p2": lambda control: control["prefixProof2"][
                "command"
            ].update(
                {
                    "stdout": replace_last_digest(
                        control["prefixProof2"]["command"]["stdout"]
                    )
                }
            ),
            "stage": lambda control: control["stagedMembers"][0][
                "command"
            ].update(
                {
                    "stdout": replace_last_digest(
                        control["stagedMembers"][0]["command"]["stdout"]
                    )
                }
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = _CaseFixture(
                        Path(directory),
                        _active_pieces,
                    )
                    mutate(fixture.control)
                    fixture.bind_control()
                    result = fixture.rebuild()
                    self.assertFalse(
                        result["complete"],
                        "raw transcript/derived divergence was trusted",
                    )
                    self.assertEqual(
                        result["classification"],
                        "INCONCLUSIVE_LOG_WINDOW",
                    )
                    self.assertTrue(
                        bool(result["faults"]),
                        result["faults"],
                    )

    def test_offline_rebuild_rechecks_raw_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), _active_pieces)
            with mock.patch.object(
                log_v2,
                "MAX_RAW_BYTES_PER_SOURCE",
                1,
            ):
                result = fixture.rebuild()
            self.assertFalse(
                result["complete"],
                "offline rebuild trusted capture-time raw byte accounting",
            )
            all_faults = list(result["faults"])
            for source_result in result["sources"].values():
                all_faults.extend(source_result["faults"])
            self.assertTrue(
                any(
                    "byte limit" in fault or "byte budget" in fault
                    for fault in all_faults
                ),
                all_faults,
            )

    def test_offline_rebuild_enforces_aggregate_decoded_budget(self) -> None:
        def pieces(
            _source: str,
            protocol: dict[str, Any],
        ) -> list[tuple[int | None, str, bytes]]:
            return [
                (1, "gzip", _marker_line(protocol["before"])),
                (0, "gzip", b"AER-COR middle\n"),
                (None, "plain", _marker_line(protocol["after"])),
            ]

        with tempfile.TemporaryDirectory() as directory:
            fixture = _CaseFixture(Path(directory), pieces)
            with mock.patch.object(
                log_v2,
                "MAX_DECODED_BYTES_PER_SOURCE",
                150,
            ):
                result = fixture.rebuild()
            self.assertFalse(result["complete"])
            self.assertEqual(
                result["classification"],
                "INCONCLUSIVE_LOG_WINDOW",
            )
            for source, source_result in result["sources"].items():
                with self.subTest(source=source):
                    self.assertTrue(
                        any(
                            "decoded rotation chain exceeds byte limit"
                            in fault
                            for fault in source_result["faults"]
                        ),
                        source_result["faults"],
                    )
                    self.assertEqual(
                        source_result["semanticAerLines"],
                        [],
                    )

    def test_missing_control_fails_closed_instead_of_raising(self) -> None:
        protocol = log_v2.protocol_for_case(CAMPAIGN_ID, CASE_ID)
        with tempfile.TemporaryDirectory() as directory:
            result = log_v2.rebuild_log_window(
                case_dir=Path(directory),
                campaign_id=CAMPAIGN_ID,
                case_id=CASE_ID,
                case_protocol=protocol,
                capture_summary={
                    "selectedAttempt": 1,
                    "attempts": [],
                    "complete": False,
                },
                semantic_classifier=_semantic_classifier,
            )
            self.assertFalse(result["complete"])
            self.assertEqual(
                result["classification"],
                "INCONCLUSIVE_LOG_WINDOW",
            )
            self.assertIn(
                "selected V2 control artifact is missing",
                result["faults"],
            )

    def test_inconsistent_capture_summary_fails_closed(self) -> None:
        mutations = {
            "complete": lambda value: value.update({"complete": False}),
            "attempt-count": lambda value: value.update(
                {"attemptCount": 99}
            ),
            "protocol": lambda value: value.update(
                {"protocol": {"id": "tampered"}}
            ),
            "selected-faults": lambda value: value["attempts"][0].update(
                {"faults": ["tampered"]}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = _CaseFixture(
                        Path(directory),
                        _active_pieces,
                    )
                    mutate(fixture.summary)
                    result = fixture.rebuild()
                    self.assertFalse(
                        result["complete"],
                        "capture-summary inconsistency was ignored",
                    )
                    self.assertEqual(
                        result["classification"],
                        "INCONCLUSIVE_LOG_WINDOW",
                    )

    def test_artifact_path_cannot_escape_case_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case_dir = root / "case"
            fixture = _CaseFixture(case_dir, _active_pieces)
            member = fixture.staged[0]
            original = case_dir / member["artifact"]
            outside = root / "outside-syslog.raw"
            outside.write_bytes(original.read_bytes())
            member["artifact"] = "../outside-syslog.raw"
            fixture.bind_control()

            result = fixture.rebuild()
            self.assertFalse(
                result["complete"],
                "rebuild accepted evidence outside the case directory",
            )
            self.assertEqual(
                result["classification"],
                "INCONCLUSIVE_LOG_WINDOW",
            )

    def test_duplicate_or_missing_active_member_fails_closed(self) -> None:
        mutations = {
            "missing": lambda members: members.__setitem__(
                slice(None),
                [
                    item
                    for item in members
                    if not (
                        item["source"] == "syslog"
                        and item["slot"] == "active"
                    )
                ],
            ),
            "duplicate": lambda members: members.append(
                copy.deepcopy(
                    next(
                        item
                        for item in members
                        if item["source"] == "syslog"
                        and item["slot"] == "active"
                    )
                )
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = _CaseFixture(
                        Path(directory),
                        _active_pieces,
                    )
                    mutate(fixture.control["stagedMembers"])
                    fixture.bind_control()
                    result = fixture.rebuild()
                    self.assertFalse(result["complete"])
                    self.assertEqual(
                        result["classification"],
                        "INCONCLUSIVE_LOG_WINDOW",
                    )


class GzipBoundaryTests(unittest.TestCase):
    def test_single_gzip_member_round_trips(self) -> None:
        expected = b"one\ntwo\n"
        self.assertEqual(
            log_v2._strict_gzip_decode(
                gzip.compress(expected, mtime=0)
            ),
            expected,
        )

    def test_concatenated_gzip_members_are_rejected(self) -> None:
        raw = (
            gzip.compress(b"one\n", mtime=0)
            + gzip.compress(b"two\n", mtime=0)
        )
        with self.assertRaisesRegex(
            log_v2.LogWindowV2Error,
            "concatenated|trailing",
        ):
            log_v2._strict_gzip_decode(raw)

    def test_truncated_gzip_member_is_rejected(self) -> None:
        raw = gzip.compress(b"payload\n", mtime=0)
        with self.assertRaisesRegex(
            log_v2.LogWindowV2Error,
            "truncated|CRC|format",
        ):
            log_v2._strict_gzip_decode(raw[:-3])

    def test_gzip_trailing_bytes_are_rejected(self) -> None:
        raw = gzip.compress(b"payload\n", mtime=0) + b"trailing"
        with self.assertRaisesRegex(
            log_v2.LogWindowV2Error,
            "trailing",
        ):
            log_v2._strict_gzip_decode(raw)

    def test_decoded_gzip_byte_limit_is_enforced(self) -> None:
        with mock.patch.object(
            log_v2,
            "MAX_DECODED_BYTES_PER_MEMBER",
            64,
        ):
            raw = gzip.compress(b"x" * 65, mtime=0)
            with self.assertRaisesRegex(
                log_v2.LogWindowV2Error,
                "exceeds byte limit",
            ):
                log_v2._strict_gzip_decode(raw)

    def test_budget_exhaustion_does_not_call_unbounded_flush(self) -> None:
        class Decoder:
            def __init__(self) -> None:
                self.eof = False
                self.unconsumed_tail = b"compressed-tail"
                self.unused_data = b""
                self.flush_called = False

            def decompress(
                self,
                _raw: bytes,
                max_length: int,
            ) -> bytes:
                return b"x" * max_length

            def flush(self, *_args: Any) -> bytes:
                self.flush_called = True
                raise AssertionError("unbounded flush must not be called")

        decoder = Decoder()
        with (
            mock.patch.object(
                log_v2,
                "MAX_DECODED_BYTES_PER_MEMBER",
                64,
            ),
            mock.patch.object(
                log_v2.zlib,
                "decompressobj",
                return_value=decoder,
            ),
        ):
            with self.assertRaises(log_v2.LogWindowV2Error):
                log_v2._strict_gzip_decode(b"compressed")
        self.assertFalse(decoder.flush_called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
