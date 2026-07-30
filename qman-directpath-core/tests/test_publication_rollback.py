from __future__ import annotations

import base64
import copy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import inspect
from pathlib import Path
import shutil

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory import VerifiedInventoryContext
from qman_directpath_core.publication_decision import (
    verify_host_snapshot_publication_decision,
)
from qman_directpath_core.publication_rollback import (
    HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS,
    PublicationRollbackVerifierLimits,
    VerifiedHostSnapshotPublicationRollbackContext,
    replay_host_snapshot_publication_rollback_closure,
    verify_host_snapshot_publication_rollback_closure,
)
from qman_directpath_core.trust import verify_trust_context
from tests.test_host_snapshot_anchor import (
    ANCHOR_PATH,
    HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
    HostSnapshotAnchorFixture,
)
from tests.test_inventory import InventoryFixture
from tests.test_publication_capture import PublicationFixture, thaw
from tests.test_publication_decision import (
    DEFAULT_BEGAN_AT,
    PREFLIGHT_DOMAIN,
    ReadSetFixture,
    artifact,
    stamp_candidate,
    unpublished_host_authority,
)
from tests.test_trust import (
    NONCE,
    NOW,
    TrustFixture,
    signature_text,
)


PREFLIGHT_SIGNATURE_DOMAIN = (
    b"QMAN-DIRECTPATH/"
    b"HOST-SNAPSHOT-ROLLBACK-AUTHORITY-PREFLIGHT-SIGNATURE/V1\x00"
)
TRUST_RING_SIGNATURE_DOMAIN = (
    b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
)
FRESHNESS_SIGNATURE_DOMAIN = b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00"
AFTER_NONCE = (
    base64.urlsafe_b64encode(b"after-freshness!").decode().rstrip("=")
)
LATE_TRUST_NONCE = (
    base64.urlsafe_b64encode(b"late-trust-proof").decode().rstrip("=")
)
LATE_AFTER_NONCE = (
    base64.urlsafe_b64encode(b"late-after-proof").decode().rstrip("=")
)
ALTERNATE_TRUST_NONCE = (
    base64.urlsafe_b64encode(b"alternate-trust!").decode().rstrip("=")
)
ROTATED_TRUST_NONCE = (
    base64.urlsafe_b64encode(b"rotated-trust!!!").decode().rstrip("=")
)
SUBSTITUTE_TRUST_NONCE = (
    base64.urlsafe_b64encode(b"substitute-trust").decode().rstrip("=")
)
PREFLIGHT_SIGNED_AT = "2026-07-24T02:00:00.100000Z"
PREPARED_AT = "2026-07-24T02:00:00.200000Z"
PREPARE_SIGNED_AT = "2026-07-24T02:00:00.300000Z"
PREPARE_EXPIRES_AT = "2026-07-24T02:01:31.000000Z"
FINALIZED_AT = "2026-07-24T02:00:03.000000Z"
FINAL_RECEIPT_ISSUED_AT = "2026-07-24T02:00:04.000000Z"
FINAL_RECEIPT_SIGNED_AT = "2026-07-24T02:00:04.100000Z"
AFTER_OBSERVED_AT = "2026-07-24T02:00:05.000000Z"
AFTER_EXPIRES_AT = "2026-07-24T02:01:45.000000Z"
VERIFIED_AT = datetime(
    2026,
    7,
    24,
    2,
    0,
    6,
    tzinfo=timezone.utc,
)
LATE_VERIFIED_AT = datetime(
    2026,
    7,
    24,
    3,
    0,
    30,
    tzinfo=timezone.utc,
)
EARLY_ROTATION_VERIFIED_AT = datetime(
    2026,
    7,
    24,
    2,
    0,
    0,
    800_000,
    tzinfo=timezone.utc,
)
AUTHORITY_ID = "external-host-snapshot-authority-test"
TRUST_ANCHOR_PATH = "external/trust/current"


def _digest(label: str) -> str:
    return sha256_digest(label.encode())


def _projection_digest(
    document: dict,
    *,
    null_fields: tuple[str, ...],
    empty_fields: tuple[str, ...] = (),
) -> str:
    projection = copy.deepcopy(document)
    for name in null_fields:
        projection[name] = None
    for name in empty_fields:
        projection[name] = []
    return sha256_digest(canonical_json_bytes(projection))


def _cas(predecessor: dict | None) -> dict:
    if predecessor is None:
        return {
            "expectedAnchorVersionOrNull": None,
            "expectedResourceVersionOrNull": None,
            "expectedKernelBootIdOrNull": None,
            "expectedHostEpochOrNull": None,
            "expectedAgentIdentityOrNull": None,
            "expectedAgentGenerationOrNull": None,
            "expectedSnapshotEpochOrNull": None,
            "expectedSnapshotContentHashOrNull": None,
            "expectedHostAuthorityResourceVersionOrNull": None,
            "expectedAnchorDigestOrNull": None,
        }
    return {
        "expectedAnchorVersionOrNull": predecessor["anchorVersion"],
        "expectedResourceVersionOrNull": predecessor["resourceVersion"],
        "expectedKernelBootIdOrNull": predecessor["kernelBootId"],
        "expectedHostEpochOrNull": predecessor["hostEpoch"],
        "expectedAgentIdentityOrNull": predecessor["agentIdentity"],
        "expectedAgentGenerationOrNull": predecessor["agentGeneration"],
        "expectedSnapshotEpochOrNull": predecessor["acceptedSnapshotEpoch"],
        "expectedSnapshotContentHashOrNull": predecessor[
            "acceptedSnapshotContentHash"
        ],
        "expectedHostAuthorityResourceVersionOrNull": predecessor[
            "acceptedHostAuthorityResourceVersion"
        ],
        "expectedAnchorDigestOrNull": predecessor["anchorDigest"],
    }


class RollbackFixture:
    def __init__(
        self,
        branch: str = "SUCCESSOR",
        *,
        schemas: ContractSchemas | None = None,
    ) -> None:
        self.branch = branch
        self.publication = PublicationFixture(
            schemas=schemas,
            maximum_evidence_age_micros=32_000_000
        )
        self.schemas = self.publication.schemas
        self.trust_fixture = TrustFixture(include_inventory_key=True)
        self.trust = verify_trust_context(
            self.schemas,
            pinned_root_set=self.trust_fixture.root,
            pinned_root_digest=self.trust_fixture.root["rootSetDigest"],
            key_ring_documents=[self.trust_fixture.ring],
            external_trust_anchor=self.trust_fixture.anchor,
            trust_anchor_freshness=self.trust_fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        if self.trust_fixture.inventory_private is None:
            raise AssertionError("inventory signing key is required")

        self.current_fixture: InventoryFixture | None = None
        self.current: VerifiedInventoryContext | None = None
        predecessor: HostSnapshotAnchorFixture | None = None
        if branch in {"SUCCESSOR", "NO_CHANGE"}:
            self.current_fixture = InventoryFixture(
                private=self.trust_fixture.inventory_private,
                trust=self.trust,
            )
            self.current_fixture.snapshot["policyHash"] = (
                self.publication.capability_policy.policy_hash
            )
            self.current_fixture.snapshot["snapshotFreshnessPolicyHash"] = (
                self.publication.freshness_policy["policyHash"]
            )
            self.current_fixture.reseal()
            self.current = self.current_fixture.verify()
            if branch == "SUCCESSOR":
                record = self.publication.inventory.records[0]
                raw = bytearray.fromhex(
                    record["role"]["pciStructureFact"][
                        "rawConfigSpaceHexOrNull"
                    ]
                )
                raw[0x0E] ^= 0x80
                self.publication.inventory.bind_pci_capture(record, bytes(raw))
            stamp_candidate(
                self.publication,
                snapshot_epoch=8,
                resource_version=12,
            )
            predecessor = HostSnapshotAnchorFixture(
                genesis=False,
                schemas=self.schemas,
                trust_fixture=self.trust_fixture,
                trust=self.trust,
                inventory=self.current,
            )
            host_authority = None
        elif branch == "GENESIS":
            stamp_candidate(
                self.publication,
                snapshot_epoch=1,
                resource_version=2,
            )
            host_authority = unpublished_host_authority(
                self.publication,
                resource_version=1,
            )
        elif branch == "INCARNATION_GENESIS":
            old = InventoryFixture(
                private=self.trust_fixture.inventory_private,
                trust=self.trust,
            )
            old.snapshot["policyHash"] = (
                self.publication.capability_policy.policy_hash
            )
            old.snapshot["snapshotFreshnessPolicyHash"] = (
                self.publication.freshness_policy["policyHash"]
            )
            old.reseal()
            old_current = old.verify()
            predecessor = HostSnapshotAnchorFixture(
                genesis=False,
                schemas=self.schemas,
                trust_fixture=self.trust_fixture,
                trust=self.trust,
                inventory=old_current,
            )
            self.publication.inventory.snapshot.update(
                {
                    "kernelBootId": "boot-test-2",
                    "hostEpoch": 4,
                    "agentGeneration": 6,
                }
            )
            self.publication.inventory.authority.update(
                {
                    "kernelBootId": "boot-test-2",
                    "hostEpoch": 4,
                    "agentGeneration": 6,
                }
            )
            for record in self.publication.inventory.records:
                record["generations"].update(
                    {
                        "hostEpoch": 4,
                        "agentGeneration": 6,
                    }
                )
            stamp_candidate(
                self.publication,
                snapshot_epoch=1,
                resource_version=14,
            )
            host_authority = unpublished_host_authority(
                self.publication,
                resource_version=13,
            )
            host_authority.update(
                {
                    "kernelBootId": "boot-test-2",
                    "hostEpoch": 4,
                    "agentGeneration": 6,
                }
            )
        else:
            raise AssertionError(f"unknown branch {branch}")

        self.capture = self.publication.verify()
        self.predecessor_fixture = predecessor
        self.read_fixture = ReadSetFixture(
            self.publication,
            current=self.current,
            host_authority=host_authority,
            predecessor=predecessor,
            began_at=DEFAULT_BEGAN_AT,
        )
        self._seal_preflight()
        self._rebuild_decision()
        self.after_inventory = self._after_inventory()
        self.snapshot_after_artifact = artifact(
            (
                "contracts/directpath-portable-hash-subjects.schema.json"
                "#/$defs/hostSnapshot"
            ),
            thaw(self.after_inventory.host_snapshot),
        )
        self.authority_after_artifact = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-HOST-AUTHORITY"
            ),
            thaw(self.after_inventory.host_authority),
        )
        if branch == "NO_CHANGE":
            if predecessor is None:
                raise AssertionError("NO_CHANGE requires a predecessor")
            self.after_anchor = copy.deepcopy(predecessor.anchor)
            self.prepared_anchor = None
        else:
            self.after_anchor, self.prepared_anchor = self._new_anchor()
        self.after_freshness = self._freshness(self.after_anchor)
        self.after_anchor_artifact = artifact(
            "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
            self.after_anchor,
        )
        self.prepared_anchor_artifact = (
            None
            if self.prepared_anchor is None
            else artifact(
                (
                    "contracts/directpath-host-snapshot-rollback-anchor."
                    "schema.json"
                ),
                self.prepared_anchor,
            )
        )
        self.after_freshness_artifact = artifact(
            "contracts/directpath-anchor-freshness-envelope.schema.json",
            self.after_freshness,
        )

    def _root_signature(
        self,
        *,
        domain: bytes,
        digest_field: str,
        digest_value: str,
        signed_at: str,
    ) -> dict:
        subject = {
            "rootKeyId": "root-a",
            "signedAt": signed_at,
            digest_field: digest_value,
        }
        return {
            "rootKeyId": "root-a",
            "signedAt": signed_at,
            "algorithm": "Ed25519",
            "signature": signature_text(
                self.trust_fixture.root_private,
                domain + canonical_json_bytes(subject),
            ),
        }

    def _seal_preflight(self) -> None:
        state = copy.deepcopy(self.read_fixture.preflight["state"])
        state["trustRootDigest"] = self.trust.root_set_digest
        state["receiptDigest"] = None
        state["rootSignatures"] = []
        receipt_digest = sha256_digest(
            PREFLIGHT_DOMAIN + canonical_json_bytes(state)
        )
        state["receiptDigest"] = receipt_digest
        state["rootSignatures"] = [
            self._root_signature(
                domain=PREFLIGHT_SIGNATURE_DOMAIN,
                digest_field="receiptDigest",
                digest_value=receipt_digest,
                signed_at=PREFLIGHT_SIGNED_AT,
            )
        ]
        self.read_fixture.preflight = artifact(
            (
                "contracts/directpath-host-snapshot-rollback-anchor."
                "schema.json#/$defs/rollbackAuthorityPreflightReceipt"
            ),
            state,
        )
        self.read_fixture.reseal_receipt()

    def _rebuild_decision(self) -> None:
        self.read_set = self.read_fixture.verify()
        self.decision = verify_host_snapshot_publication_decision(
            self.capture,
            self.read_set,
        )

    def _after_inventory(self) -> VerifiedInventoryContext:
        if self.branch == "NO_CHANGE":
            if self.current is None:
                raise AssertionError("NO_CHANGE requires current inventory")
            return self.current
        fixture = InventoryFixture(
            private=self.trust_fixture.inventory_private,
            trust=self.trust,
        )
        fixture.records = [
            thaw(record.document)
            for record in self.decision.persisted_device_records
        ]
        batch = self.decision.capture.capture_batch
        current_hash = (
            None
            if self.current is None
            else self.current.snapshot_content_hash
        )
        fixture.snapshot.update(
            {
                "hostId": batch["hostId"],
                "kernelBootId": batch["kernelBootId"],
                "hostEpoch": batch["hostEpoch"],
                "agentGeneration": batch["agentGeneration"],
                "hostAuthorityResourceVersion": (
                    self.decision.proposed_host_authority_resource_version
                ),
                "snapshotEpoch": self.decision.proposed_snapshot_epoch,
                "previousSnapshotContentHashOrNull": current_hash,
                "capturedAt": batch["captureCompletedAt"],
                "policyHash": self.decision.read_set.capability_policy.policy_hash,
                "snapshotFreshnessPolicyHash": (
                    self.decision.read_set.freshness_policy_hash
                ),
                "keyRingVersion": self.trust.key_ring_sequence,
            }
        )
        fixture.authority = thaw(self.decision.read_set.host_authority_before)
        fixture.authority.update(
            {
                "lastSnapshotEpoch": self.decision.proposed_snapshot_epoch,
                "lastObservedAt": batch["captureCompletedAt"],
                "resourceVersion": (
                    self.decision.proposed_host_authority_resource_version
                ),
            }
        )
        fixture.reseal()
        return fixture.verify()

    def _new_anchor(self) -> tuple[dict, dict]:
        predecessor = (
            None
            if self.predecessor_fixture is None
            else self.predecessor_fixture.anchor
        )
        seed = HostSnapshotAnchorFixture(
            genesis=self.after_inventory.snapshot_epoch == 1,
            schemas=self.schemas,
            trust_fixture=self.trust_fixture,
            trust=self.trust,
            inventory=self.after_inventory,
        )
        anchor = copy.deepcopy(seed.anchor)
        anchor_version = (
            1 if predecessor is None else predecessor["anchorVersion"] + 1
        )
        anchor.update(
            {
                "hostId": self.after_inventory.host_id,
                "kernelBootId": self.after_inventory.kernel_boot_id,
                "hostEpoch": self.after_inventory.host_epoch,
                "agentIdentity": self.after_inventory.agent_identity,
                "agentGeneration": self.after_inventory.agent_generation,
                "acceptedSnapshotEpoch": self.after_inventory.snapshot_epoch,
                "acceptedSnapshotContentHash": (
                    self.after_inventory.snapshot_content_hash
                ),
                "acceptedHostAuthorityResourceVersion": (
                    self.after_inventory.snapshot_authority_resource_version
                ),
                "anchorVersion": anchor_version,
                "resourceVersion": anchor_version,
                "previousAnchorDigestOrNull": (
                    None if predecessor is None else predecessor["anchorDigest"]
                ),
                "authorityId": AUTHORITY_ID,
                "casPrecondition": _cas(predecessor),
                "updatedAt": FINALIZED_AT,
            }
        )
        anchor["prepareReceipt"].update(
            {
                "reservationId": f"reservation-{self.branch.lower()}",
                "rollbackAuthorityPreflightReceiptDigest": (
                    self.read_fixture.preflight["state"]["receiptDigest"]
                ),
                "preparedAt": PREPARED_AT,
                "expiresAt": PREPARE_EXPIRES_AT,
                "trustRootDigest": self.trust.root_set_digest,
            }
        )
        anchor["receipt"]["issuedAt"] = FINAL_RECEIPT_ISSUED_AT
        anchor = seed.reseal_anchor(
            anchor,
            prepare_signed_at=PREPARE_SIGNED_AT,
        )
        anchor["receipt"]["rootSignatures"] = [
            self._root_signature(
                domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
                digest_field="receiptDigest",
                digest_value=anchor["receipt"]["receiptDigest"],
                signed_at=FINAL_RECEIPT_SIGNED_AT,
            )
        ]
        prepared = copy.deepcopy(anchor)
        prepared["recordState"] = "PREPARED"
        prepared["updatedAt"] = PREPARED_AT
        prepared["anchorDigest"] = None
        prepared["receipt"] = None
        return anchor, prepared

    def _freshness(
        self,
        anchor: dict,
        *,
        observed_at: str = AFTER_OBSERVED_AT,
        expires_at: str = AFTER_EXPIRES_AT,
        nonce: str = AFTER_NONCE,
    ) -> dict:
        document = {
            "schemaVersion": 1,
            "envelopeId": f"after-freshness-{self.branch.lower()}",
            "anchorKind": "HOST_SNAPSHOT",
            "authorityId": anchor["authorityId"],
            "subjectId": anchor["hostId"],
            "anchorPath": ANCHOR_PATH,
            "anchorBlobSha256": sha256_digest(canonical_json_bytes(anchor)),
            "anchorSchemaRef": (
                "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
            ),
            "anchorSchemaSha256": self.schemas.digest_for_ref(
                (
                    "contracts/directpath-host-snapshot-rollback-anchor."
                    "schema.json"
                ),
                path="test.publicationRollback.anchorSchema",
            ),
            "anchorDigest": anchor["anchorDigest"],
            "anchorVersion": anchor["anchorVersion"],
            "resourceVersion": anchor["resourceVersion"],
            "observedAt": observed_at,
            "expiresAt": expires_at,
            "verifierNonce": nonce,
            "trustRootDigest": self.trust.root_set_digest,
            "freshnessReceiptDigest": None,
            "rootSignatures": [],
        }
        receipt_digest = _projection_digest(
            document,
            null_fields=("freshnessReceiptDigest",),
            empty_fields=("rootSignatures",),
        )
        document["freshnessReceiptDigest"] = receipt_digest
        document["rootSignatures"] = [
            self._root_signature(
                domain=FRESHNESS_SIGNATURE_DOMAIN,
                digest_field="freshnessReceiptDigest",
                digest_value=receipt_digest,
                signed_at=observed_at,
            )
        ]
        return document

    def _seal_ring(self, ring: dict, *, signed_at: str) -> dict:
        document = copy.deepcopy(ring)
        document["keyRingDigest"] = None
        document["rootSignatures"] = []
        ring_digest = _projection_digest(
            document,
            null_fields=("keyRingDigest",),
            empty_fields=("rootSignatures",),
        )
        document["keyRingDigest"] = ring_digest
        signature = self._root_signature(
            domain=TRUST_RING_SIGNATURE_DOMAIN,
            digest_field="keyRingDigest",
            digest_value=ring_digest,
            signed_at=signed_at,
        )
        signature.pop("algorithm")
        document["rootSignatures"] = [signature]
        return document

    def _seal_trust_anchor(self, anchor: dict) -> dict:
        document = copy.deepcopy(anchor)
        document["anchorDigest"] = None
        document["anchorDigest"] = _projection_digest(
            document,
            null_fields=("anchorDigest",),
        )
        return document

    def _trust_freshness(
        self,
        anchor: dict,
        *,
        observed_at: str,
        expires_at: str,
        nonce: str,
        anchor_path: str = TRUST_ANCHOR_PATH,
    ) -> dict:
        freshness = copy.deepcopy(self.trust_fixture.freshness)
        freshness.update(
            {
                "envelopeId": f"trust-freshness-{nonce}",
                "authorityId": anchor["authorityId"],
                "subjectId": anchor["keyRingId"],
                "anchorBlobSha256": sha256_digest(
                    canonical_json_bytes(anchor)
                ),
                "anchorDigest": anchor["anchorDigest"],
                "anchorVersion": anchor["anchorVersion"],
                "resourceVersion": anchor["resourceVersion"],
                "anchorPath": anchor_path,
                "observedAt": observed_at,
                "expiresAt": expires_at,
                "verifierNonce": nonce,
                "freshnessReceiptDigest": None,
                "rootSignatures": [],
            }
        )
        receipt_digest = _projection_digest(
            freshness,
            null_fields=("freshnessReceiptDigest",),
            empty_fields=("rootSignatures",),
        )
        freshness["freshnessReceiptDigest"] = receipt_digest
        freshness["rootSignatures"] = [
            self._root_signature(
                domain=FRESHNESS_SIGNATURE_DOMAIN,
                digest_field="freshnessReceiptDigest",
                digest_value=receipt_digest,
                signed_at=observed_at,
            )
        ]
        return freshness

    def _verify_trust(
        self,
        *,
        rings: list[dict],
        anchor: dict,
        observed_at: str,
        expires_at: str,
        nonce: str,
        now: datetime,
        anchor_path: str = TRUST_ANCHOR_PATH,
    ):
        freshness = self._trust_freshness(
            anchor,
            observed_at=observed_at,
            expires_at=expires_at,
            nonce=nonce,
            anchor_path=anchor_path,
        )
        return verify_trust_context(
            self.schemas,
            pinned_root_set=self.trust_fixture.root,
            pinned_root_digest=self.trust_fixture.root["rootSetDigest"],
            key_ring_documents=rings,
            external_trust_anchor=anchor,
            trust_anchor_freshness=freshness,
            verifier_nonce=nonce,
            now=now,
        )

    def refreshed_trust(self):
        return self._verify_trust(
            rings=[self.trust_fixture.ring],
            anchor=self.trust_fixture.anchor,
            observed_at="2026-07-24T03:00:00.000000Z",
            expires_at="2026-07-24T03:02:00.000000Z",
            nonce=LATE_TRUST_NONCE,
            now=LATE_VERIFIED_AT,
        )

    def rotated_trust(
        self,
        *,
        ring_signed_at: str,
        anchor_updated_at: str,
        observed_at: str,
        expires_at: str,
        nonce: str,
        now: datetime,
    ):
        first_ring = self.trust_fixture.ring
        second_ring = copy.deepcopy(first_ring)
        second_ring.update(
            {
                "keyRingSequence": 2,
                "previousKeyRingDigest": first_ring["keyRingDigest"],
            }
        )
        second_ring = self._seal_ring(
            second_ring,
            signed_at=ring_signed_at,
        )
        first_anchor = self.trust_fixture.anchor
        second_anchor = copy.deepcopy(first_anchor)
        second_anchor.update(
            {
                "minimumSequence": 2,
                "acceptedKeyRingDigest": second_ring["keyRingDigest"],
                "anchorVersion": 2,
                "resourceVersion": 2,
                "previousAnchorDigestOrNull": first_anchor["anchorDigest"],
                "updatedAt": anchor_updated_at,
                "casPrecondition": {
                    "expectedAnchorVersionOrNull": 1,
                    "expectedResourceVersionOrNull": 1,
                    "expectedMinimumSequenceOrNull": 1,
                    "expectedAcceptedKeyRingDigestOrNull": first_ring[
                        "keyRingDigest"
                    ],
                    "expectedAnchorDigestOrNull": first_anchor[
                        "anchorDigest"
                    ],
                },
            }
        )
        second_anchor = self._seal_trust_anchor(second_anchor)
        return self._verify_trust(
            rings=[first_ring, second_ring],
            anchor=second_anchor,
            observed_at=observed_at,
            expires_at=expires_at,
            nonce=nonce,
            now=now,
        )

    def alternate_trust(
        self,
        *,
        key_ring_id: str | None = None,
        authority_id: str | None = None,
        fork_ring: bool = False,
        fork_anchor: bool = False,
        trust_anchor_path: str = TRUST_ANCHOR_PATH,
    ):
        ring = copy.deepcopy(self.trust_fixture.ring)
        if key_ring_id is not None:
            ring["keyRingId"] = key_ring_id
        if fork_ring:
            inventory_key = next(
                key for key in ring["keys"] if key["keyId"] == "inventory-key-v1"
            )
            inventory_key["principalId"] = (
                "urn:qman:principal:inventory-agent-fork"
            )
        ring = self._seal_ring(
            ring,
            signed_at="2026-07-24T02:00:00.000000Z",
        )
        anchor = copy.deepcopy(self.trust_fixture.anchor)
        anchor.update(
            {
                "keyRingId": ring["keyRingId"],
                "acceptedKeyRingDigest": ring["keyRingDigest"],
                "authorityId": (
                    anchor["authorityId"]
                    if authority_id is None
                    else authority_id
                ),
            }
        )
        if fork_anchor:
            anchor["updatedAt"] = "2026-07-24T01:56:00.000000Z"
        anchor = self._seal_trust_anchor(anchor)
        return self._verify_trust(
            rings=[ring],
            anchor=anchor,
            observed_at="2026-07-24T02:00:05.000000Z",
            expires_at="2026-07-24T02:02:00.000000Z",
            nonce=ALTERNATE_TRUST_NONCE,
            now=VERIFIED_AT,
            anchor_path=trust_anchor_path,
        )

    def advanced_anchor_trust(self):
        ring = self.trust_fixture.ring
        first_anchor = self.trust_fixture.anchor
        second_anchor = copy.deepcopy(first_anchor)
        second_anchor.update(
            {
                "anchorVersion": 2,
                "resourceVersion": 2,
                "previousAnchorDigestOrNull": first_anchor["anchorDigest"],
                "updatedAt": "2026-07-24T02:00:00.200000Z",
                "casPrecondition": {
                    "expectedAnchorVersionOrNull": 1,
                    "expectedResourceVersionOrNull": 1,
                    "expectedMinimumSequenceOrNull": 1,
                    "expectedAcceptedKeyRingDigestOrNull": ring[
                        "keyRingDigest"
                    ],
                    "expectedAnchorDigestOrNull": first_anchor[
                        "anchorDigest"
                    ],
                },
            }
        )
        second_anchor = self._seal_trust_anchor(second_anchor)
        return self._verify_trust(
            rings=[ring],
            anchor=second_anchor,
            observed_at="2026-07-24T02:00:00.300000Z",
            expires_at="2026-07-24T02:02:00.000000Z",
            nonce=ROTATED_TRUST_NONCE,
            now=EARLY_ROTATION_VERIFIED_AT,
        )

    def verify(self, **changes):
        schemas = changes.pop("schemas", self.schemas)
        trust = changes.pop("trust", self.trust)
        decision = changes.pop("decision", self.decision)
        arguments = {
            "host_snapshot_after_artifact": canonical_json_bytes(
                self.snapshot_after_artifact
            ),
            "host_authority_after_artifact": canonical_json_bytes(
                self.authority_after_artifact
            ),
            "prepared_anchor_artifact_or_none": (
                None
                if self.prepared_anchor_artifact is None
                else canonical_json_bytes(self.prepared_anchor_artifact)
            ),
            "after_anchor_artifact": canonical_json_bytes(
                self.after_anchor_artifact
            ),
            "after_freshness_artifact": canonical_json_bytes(
                self.after_freshness_artifact
            ),
            "predecessor_freshness_nonce_or_none": (
                None if self.predecessor_fixture is None else NONCE
            ),
            "rollback_preflight_nonce": self.read_fixture.preflight["state"][
                "verifierNonce"
            ],
            "after_freshness_nonce": AFTER_NONCE,
            "expected_authority_id": AUTHORITY_ID,
            "expected_anchor_path": ANCHOR_PATH,
            "expected_trust_anchor_path": TRUST_ANCHOR_PATH,
            "verified_at": VERIFIED_AT,
        }
        arguments.update(changes)
        return verify_host_snapshot_publication_rollback_closure(
            schemas,
            trust,
            decision,
            **arguments,
        )


def test_successor_closes_crypto_chain_and_replays() -> None:
    fixture = RollbackFixture("SUCCESSOR")

    context = fixture.verify()
    replayed = replay_host_snapshot_publication_rollback_closure(context)

    assert context.publication_decision == "SUCCESSOR_COMMITTED"
    assert context.write_required
    assert context.reservation_id_or_null == "reservation-successor"
    assert context.prepare_receipt_digest_or_null is not None
    assert (
        fixture.prepared_anchor["updatedAt"]
        < fixture.prepared_anchor["prepareReceipt"]["rootSignatures"][0][
            "signedAt"
        ]
        <= fixture.read_fixture.receipt["beganAt"]
    )
    assert context.commit_not_before_or_null == DEFAULT_BEGAN_AT
    assert context.commit_not_after_or_null == datetime(
        2026,
        7,
        24,
        2,
        1,
        31,
        tzinfo=timezone.utc,
    )
    assert context.context_digest == replayed.context_digest
    assert context.publication_trust_context_digest == (
        fixture.trust.context_digest
    )
    assert context.recovery_trust_context_digest == fixture.trust.context_digest
    assert context.authority_boundary == (
        HOST_SNAPSHOT_PUBLICATION_ROLLBACK_AUTHORITY_BOUNDARY
    )
    assert not context.product_authorized
    assert context.product_evidence_blockers == (
        HOST_SNAPSHOT_PUBLICATION_ROLLBACK_PRODUCT_EVIDENCE_BLOCKERS
    )
    assert (
        "TARGET_REPOSITORY_COMMIT_RECORD_TIME_BINDING_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        "INDEPENDENT_TRUST_AUTHORITY_PATH_AND_NONCE_TRANSPORT_REQUIRED"
        in context.product_evidence_blockers
    )


def test_long_crash_recovery_uses_new_live_trust_for_current_artifacts() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    late_trust = fixture.refreshed_trust()
    late_freshness = fixture._freshness(
        fixture.after_anchor,
        observed_at="2026-07-24T03:00:10.000000Z",
        expires_at="2026-07-24T03:02:00.000000Z",
        nonce=LATE_AFTER_NONCE,
    )

    context = fixture.verify(
        recovery_trust=late_trust,
        after_freshness_artifact=canonical_json_bytes(
            artifact(
                "contracts/directpath-anchor-freshness-envelope.schema.json",
                late_freshness,
            )
        ),
        after_freshness_nonce=LATE_AFTER_NONCE,
        verified_at=LATE_VERIFIED_AT,
    )

    assert late_trust.verified_at > fixture.decision.read_set.began_at
    assert LATE_VERIFIED_AT > fixture.trust.freshness_expires_at
    assert LATE_VERIFIED_AT > context.commit_not_after_or_null
    assert context.trust.context_digest == fixture.trust.context_digest
    assert context.recovery_trust.verified_at == LATE_VERIFIED_AT


def test_sequence_one_publication_to_sequence_two_recovery_succeeds() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    recovery_trust = fixture.rotated_trust(
        ring_signed_at="2026-07-24T02:59:50.000000Z",
        anchor_updated_at="2026-07-24T02:59:55.000000Z",
        observed_at="2026-07-24T03:00:00.000000Z",
        expires_at="2026-07-24T03:02:00.000000Z",
        nonce=ROTATED_TRUST_NONCE,
        now=LATE_VERIFIED_AT,
    )
    late_freshness = fixture._freshness(
        fixture.after_anchor,
        observed_at="2026-07-24T03:00:10.000000Z",
        expires_at="2026-07-24T03:02:00.000000Z",
        nonce=LATE_AFTER_NONCE,
    )

    context = fixture.verify(
        recovery_trust=recovery_trust,
        after_freshness_artifact=canonical_json_bytes(
            artifact(
                "contracts/directpath-anchor-freshness-envelope.schema.json",
                late_freshness,
            )
        ),
        after_freshness_nonce=LATE_AFTER_NONCE,
        verified_at=LATE_VERIFIED_AT,
    )
    replayed = replay_host_snapshot_publication_rollback_closure(context)

    assert context.trust.key_ring_sequence == 1
    assert context.after_inventory.trust.key_ring_sequence == 1
    assert context.recovery_trust.key_ring_sequence == 2
    assert context.publication_trust_context_digest != (
        context.recovery_trust_context_digest
    )
    assert context.context_receipt["publicationTrustContextDigest"] == (
        context.trust.context_digest
    )
    assert context.context_receipt["recoveryTrustContextDigest"] == (
        recovery_trust.context_digest
    )
    assert replayed.context_receipt_canonical_bytes == (
        context.context_receipt_canonical_bytes
    )


def test_no_change_reuses_exact_current_inventory_across_forward_rotation() -> None:
    fixture = RollbackFixture("NO_CHANGE")
    rotated_trust = fixture.rotated_trust(
        ring_signed_at="2026-07-24T02:00:00.100000Z",
        anchor_updated_at="2026-07-24T02:00:00.200000Z",
        observed_at="2026-07-24T02:00:00.300000Z",
        expires_at="2026-07-24T02:02:00.000000Z",
        nonce=ROTATED_TRUST_NONCE,
        now=EARLY_ROTATION_VERIFIED_AT,
    )

    context = fixture.verify(
        trust=rotated_trust,
        recovery_trust=rotated_trust,
    )

    assert context.after_inventory.host_snapshot_canonical_bytes == (
        fixture.current.host_snapshot_canonical_bytes
    )
    assert context.after_inventory.inventory_verification_receipt_digest == (
        fixture.current.inventory_verification_receipt_digest
    )
    assert context.after_inventory.trust.key_ring_sequence == 1
    assert context.trust.key_ring_sequence == 2
    assert context.recovery_trust.key_ring_sequence == 2


@pytest.mark.parametrize(
    ("key_ring_id", "authority_id", "expected_path"),
    (
        (
            "alternate-ring-namespace",
            None,
            "publicationRollback.publicationToRecoveryTrust.keyRingId",
        ),
        (
            None,
            "alternate-trust-authority",
            (
                "publicationRollback.publicationToRecoveryTrust."
                "trustAnchorAuthorityId"
            ),
        ),
    ),
)
def test_exact_after_bytes_reject_alternate_trust_namespace(
    key_ring_id: str | None,
    authority_id: str | None,
    expected_path: str,
) -> None:
    fixture = RollbackFixture("SUCCESSOR")
    alternate_trust = fixture.alternate_trust(
        key_ring_id=key_ring_id,
        authority_id=authority_id,
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(recovery_trust=alternate_trust)

    assert alternate_trust.root_set_digest == fixture.trust.root_set_digest
    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID"
    assert error.value.path == expected_path


def test_recovery_trust_rejects_alternate_freshness_anchor_path() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    alternate_path_trust = fixture.alternate_trust(
        trust_anchor_path="external/trust/alternate",
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(recovery_trust=alternate_path_trust)

    assert alternate_path_trust.context_digest == fixture.trust.context_digest
    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_PATH_MISMATCH"
    assert error.value.path == (
        "publicationRollback.recoveryTrust.freshnessAnchorPath"
    )


def test_freshness_identity_binds_context_and_rejects_substitution() -> None:
    fixture = RollbackFixture("SUCCESSOR")

    def recovery_trust(nonce: str):
        return fixture._verify_trust(
            rings=[fixture.trust_fixture.ring],
            anchor=fixture.trust_fixture.anchor,
            observed_at="2026-07-24T02:00:05.000000Z",
            expires_at="2026-07-24T02:02:00.000000Z",
            nonce=nonce,
            now=VERIFIED_AT,
        )

    first_trust = recovery_trust(ALTERNATE_TRUST_NONCE)
    second_trust = recovery_trust(SUBSTITUTE_TRUST_NONCE)
    first_context = fixture.verify(recovery_trust=first_trust)
    second_context = fixture.verify(recovery_trust=second_trust)

    assert first_trust.context_digest == second_trust.context_digest
    assert first_trust.verified_at == second_trust.verified_at
    assert first_trust.freshness_expires_at == second_trust.freshness_expires_at
    assert first_trust.freshness_anchor_path == (
        second_trust.freshness_anchor_path
    )
    assert first_trust.freshness_receipt_digest != (
        second_trust.freshness_receipt_digest
    )
    assert first_context.context_digest != second_context.context_digest
    assert first_context.context_receipt_canonical_bytes != (
        second_context.context_receipt_canonical_bytes
    )

    first_receipt_bytes = first_context.context_receipt_canonical_bytes
    object.__setattr__(first_context, "recovery_trust", second_trust)
    with pytest.raises(DirectPathVerificationError) as object_error:
        replay_host_snapshot_publication_rollback_closure(first_context)
    assert object_error.value.code == (
        "PUBLICATION_ROLLBACK_CONTEXT_REPLAY_MISMATCH"
    )

    object.__setattr__(
        second_context,
        "context_receipt_canonical_bytes",
        first_receipt_bytes,
    )
    with pytest.raises(DirectPathVerificationError) as receipt_error:
        replay_host_snapshot_publication_rollback_closure(second_context)
    assert receipt_error.value.code == (
        "PUBLICATION_ROLLBACK_CONTEXT_REPLAY_MISMATCH"
    )


def test_recovery_trust_rejects_same_sequence_history_fork() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    forked_trust = fixture.alternate_trust(fork_ring=True)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(recovery_trust=forked_trust)

    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID"
    assert error.value.path == (
        "publicationRollback.publicationToRecoveryTrust.keyRingHistory"
    )


def test_recovery_trust_rejects_same_version_anchor_fork() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    forked_trust = fixture.alternate_trust(fork_anchor=True)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(recovery_trust=forked_trust)

    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID"
    assert error.value.path == (
        "publicationRollback.publicationToRecoveryTrust.trustAnchorDigest"
    )


def test_recovery_trust_rejects_key_ring_rollback() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    publication_trust = fixture.rotated_trust(
        ring_signed_at="2026-07-24T02:00:00.100000Z",
        anchor_updated_at="2026-07-24T02:00:00.200000Z",
        observed_at="2026-07-24T02:00:00.300000Z",
        expires_at="2026-07-24T02:02:00.000000Z",
        nonce=ROTATED_TRUST_NONCE,
        now=EARLY_ROTATION_VERIFIED_AT,
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(
            trust=publication_trust,
            recovery_trust=fixture.trust,
        )

    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID"
    assert error.value.path == (
        "publicationRollback.publicationToRecoveryTrust.keyRingHistory"
    )


def test_recovery_trust_rejects_trust_anchor_version_rollback() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    publication_trust = fixture.advanced_anchor_trust()

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(
            trust=publication_trust,
            recovery_trust=fixture.trust,
        )

    assert error.value.code == "PUBLICATION_ROLLBACK_TRUST_LINEAGE_INVALID"
    assert error.value.path == (
        "publicationRollback.publicationToRecoveryTrust.trustAnchorVersion"
    )


def test_no_change_has_no_reservation_or_commit_window() -> None:
    fixture = RollbackFixture("NO_CHANGE")

    context = fixture.verify()

    assert context.publication_decision == "NO_CHANGE"
    assert not context.write_required
    assert context.reservation_id_or_null is None
    assert context.prepare_receipt_digest_or_null is None
    assert context.commit_not_before_or_null is None
    assert context.commit_not_after_or_null is None
    assert context.after_inventory.snapshot_content_hash == (
        fixture.current.snapshot_content_hash
    )
    assert context.after_anchor_digest == (
        fixture.predecessor_fixture.anchor["anchorDigest"]
    )


@pytest.mark.parametrize(
    ("branch", "expected_decision", "expected_version"),
    (
        ("GENESIS", "GENESIS_COMMITTED", 1),
        (
            "INCARNATION_GENESIS",
            "INCARNATION_GENESIS_COMMITTED",
            3,
        ),
    ),
)
def test_genesis_and_incarnation_cas_are_closed(
    branch: str,
    expected_decision: str,
    expected_version: int,
) -> None:
    fixture = RollbackFixture(branch)

    context = fixture.verify()

    assert context.publication_decision == expected_decision
    assert context.after_anchor_version == expected_version
    assert context.after_inventory.snapshot_epoch == 1
    if branch == "GENESIS":
        assert context.predecessor_anchor_digest_or_null is None
        assert all(
            value is None
            for value in fixture.after_anchor["casPrecondition"].values()
        )
    else:
        assert context.predecessor_anchor_digest_or_null is not None
        assert fixture.after_anchor["casPrecondition"][
            "expectedAnchorDigestOrNull"
        ] == fixture.predecessor_fixture.anchor["anchorDigest"]


def test_preflight_signature_tamper_fails_cryptographically() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    state = copy.deepcopy(fixture.read_fixture.preflight["state"])
    state["rootSignatures"][0]["signature"] = "ed25519:" + ("A" * 86)
    fixture.read_fixture.preflight = artifact(
        (
            "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
            "#/$defs/rollbackAuthorityPreflightReceipt"
        ),
        state,
    )
    fixture.read_fixture.reseal_receipt()
    fixture._rebuild_decision()

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify()

    assert error.value.code == "SIGNATURE_INVALID"


def test_every_preflight_signature_must_precede_prepared_at() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    state = copy.deepcopy(fixture.read_fixture.preflight["state"])
    state["rootSignatures"] = [
        fixture._root_signature(
            domain=PREFLIGHT_SIGNATURE_DOMAIN,
            digest_field="receiptDigest",
            digest_value=state["receiptDigest"],
            signed_at="2026-07-24T02:00:00.900000Z",
        )
    ]
    fixture.read_fixture.preflight = artifact(
        (
            "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
            "#/$defs/rollbackAuthorityPreflightReceipt"
        ),
        state,
    )
    fixture.read_fixture.reseal_receipt()
    fixture._rebuild_decision()

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify()

    assert error.value.code == "PUBLICATION_ROLLBACK_TIME_INVALID"
    assert error.value.path == (
        "publicationRollback.preparedAnchor.prepareReceipt.preparedAt"
    )


def test_prepared_must_bind_exact_preflight_receipt() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    prepared = copy.deepcopy(fixture.prepared_anchor)
    prepared["prepareReceipt"][
        "rollbackAuthorityPreflightReceiptDigest"
    ] = _digest("wrong-preflight")
    prepared_artifact = artifact(
        "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
        prepared,
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(
            prepared_anchor_artifact_or_none=canonical_json_bytes(
                prepared_artifact
            )
        )

    assert error.value.code == (
        "PUBLICATION_ROLLBACK_PREPARE_RECEIPT_BINDING_MISMATCH"
    )


def test_nonce_reuse_is_rejected_before_after_binding() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    preflight_nonce = fixture.read_fixture.preflight["state"]["verifierNonce"]

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(after_freshness_nonce=preflight_nonce)

    assert error.value.code == "PUBLICATION_ROLLBACK_NONCE_REUSE"


def test_no_change_cannot_smuggle_a_prepared_anchor() -> None:
    no_change = RollbackFixture("NO_CHANGE")
    successor = RollbackFixture("SUCCESSOR")

    with pytest.raises(DirectPathVerificationError) as error:
        no_change.verify(
            prepared_anchor_artifact_or_none=canonical_json_bytes(
                successor.prepared_anchor_artifact
            )
        )

    assert error.value.code == "PUBLICATION_ROLLBACK_NO_CHANGE_MUTATION"


def test_after_anchor_cas_skip_is_rejected_even_when_wrapper_is_resealed() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    after = copy.deepcopy(fixture.after_anchor)
    after["anchorVersion"] += 1
    after["resourceVersion"] += 1
    after_artifact = artifact(
        "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
        after,
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(
            after_anchor_artifact=canonical_json_bytes(after_artifact)
        )

    assert error.value.code in {
        "PUBLICATION_ROLLBACK_FINALIZATION_BINDING_MISMATCH",
        "HOST_SNAPSHOT_ANCHOR_CANDIDATE_DIGEST_INVALID",
    }


def test_successor_updated_at_must_strictly_advance_predecessor() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    predecessor_fixture = fixture.predecessor_fixture
    if predecessor_fixture is None:
        raise AssertionError("SUCCESSOR requires a predecessor")
    began_at = "2026-07-24T02:00:01.000000Z"

    predecessor = copy.deepcopy(predecessor_fixture.anchor)
    predecessor["updatedAt"] = began_at
    predecessor["receipt"]["issuedAt"] = began_at
    predecessor = predecessor_fixture.reseal_anchor(
        predecessor,
        prepare_signed_at=PREPARE_SIGNED_AT,
    )
    predecessor["receipt"]["rootSignatures"] = [
        fixture._root_signature(
            domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
            digest_field="receiptDigest",
            digest_value=predecessor["receipt"]["receiptDigest"],
            signed_at=began_at,
        )
    ]
    predecessor_freshness = fixture._freshness(
        predecessor,
        observed_at=began_at,
        expires_at=AFTER_EXPIRES_AT,
        nonce=NONCE,
    )
    predecessor_fixture.anchor = predecessor
    predecessor_fixture.freshness = predecessor_freshness
    fixture.read_fixture.predecessor_anchor = artifact(
        "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
        predecessor,
    )
    fixture.read_fixture.predecessor_freshness = artifact(
        "contracts/directpath-anchor-freshness-envelope.schema.json",
        predecessor_freshness,
    )
    preflight = copy.deepcopy(fixture.read_fixture.preflight["state"])
    preflight["predecessorAnchorDigestOrNull"] = predecessor["anchorDigest"]
    fixture.read_fixture.preflight = artifact(
        fixture.read_fixture.preflight["schemaRef"],
        preflight,
    )
    fixture._seal_preflight()
    fixture._rebuild_decision()

    fixture.after_inventory = fixture._after_inventory()
    after_anchor, fixture.prepared_anchor = fixture._new_anchor()
    after_anchor["updatedAt"] = began_at
    after_anchor = predecessor_fixture.reseal_anchor(
        after_anchor,
        prepare_signed_at=PREPARE_SIGNED_AT,
    )
    after_anchor["receipt"]["rootSignatures"] = [
        fixture._root_signature(
            domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
            digest_field="receiptDigest",
            digest_value=after_anchor["receipt"]["receiptDigest"],
            signed_at=FINAL_RECEIPT_SIGNED_AT,
        )
    ]
    fixture.after_anchor = after_anchor
    fixture.after_anchor_artifact = artifact(
        "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
        after_anchor,
    )
    fixture.prepared_anchor_artifact = artifact(
        "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
        fixture.prepared_anchor,
    )
    fixture.after_freshness = fixture._freshness(after_anchor)
    fixture.after_freshness_artifact = artifact(
        "contracts/directpath-anchor-freshness-envelope.schema.json",
        fixture.after_freshness,
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify()

    assert error.value.code == "PUBLICATION_ROLLBACK_TIME_INVALID"
    assert error.value.path == "publicationRollback.afterAnchor.updatedAt"


@pytest.mark.parametrize(
    "schema_name",
    (
        "directpath-portable-entities.schema.json",
        "directpath-identity-v1.schema.json",
    ),
)
def test_transitive_schema_identity_must_match_decision(
    tmp_path: Path,
    schema_name: str,
) -> None:
    fixture = RollbackFixture("SUCCESSOR")
    alternate_contracts = tmp_path / "contracts"
    shutil.copytree(fixture.schemas.directory, alternate_contracts)
    schema_path = alternate_contracts / schema_name
    schema_path.write_bytes(schema_path.read_bytes() + b"\n")
    alternate_schemas = ContractSchemas(alternate_contracts)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(schemas=alternate_schemas)

    assert error.value.code == "PUBLICATION_ROLLBACK_SCHEMA_MISMATCH"


def test_artifact_byte_ceiling_fails_closed_before_crypto() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    too_small = PublicationRollbackVerifierLimits(max_artifact_bytes=128)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(limits=too_small)

    assert error.value.code == "PUBLICATION_ROLLBACK_TOO_LARGE"


def test_factory_boundary_and_no_caller_commit_time_parameter() -> None:
    fixture = RollbackFixture("SUCCESSOR")
    context = fixture.verify()

    assert "committed_at" not in inspect.signature(
        verify_host_snapshot_publication_rollback_closure
    ).parameters
    with pytest.raises(TypeError):
        replace(context, product_authorized=True)
    with pytest.raises(FrozenInstanceError):
        context.product_authorized = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationRollbackContext()
