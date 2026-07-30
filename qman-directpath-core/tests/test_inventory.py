from __future__ import annotations

import base64
from collections.abc import Sequence
import copy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import MappingProxyType
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory import (
    DEFAULT_INVENTORY_VERIFIER_LIMITS,
    InventoryVerifierLimits,
    MAX_CURRENT_INVENTORY_DEVICE_RECORDS,
    derive_device_provider_facts_digest,
    verify_inventory_context,
)
from qman_directpath_core.pci_config import (
    normalize_pci_config_capture,
    verify_device_record_pci_facts,
)
from qman_directpath_core.snapshot_semantics import (
    derive_host_snapshot_semantics,
)
from qman_directpath_core.trust import (
    VerifiedKey,
    VerifiedTrustContext,
    _VerifiedRing,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
NOW = datetime(2026, 7, 24, 2, 0, 0, tzinfo=timezone.utc)
CAPTURED_AT = "2026-07-24T01:59:30.000000Z"
CAPTURE_STARTED_AT = "2026-07-24T01:59:29.000000Z"
VALID_FROM = datetime(2026, 1, 1, tzinfo=timezone.utc)
VALID_TO = datetime(2027, 1, 1, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def public_text(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signature_text(private: Ed25519PrivateKey, preimage: bytes) -> str:
    signature = private.sign(preimage)
    return "ed25519:" + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def trust_context(
    private: Ed25519PrivateKey,
    *,
    roles: tuple[str, ...] = ("HOST_INVENTORY_EVIDENCE",),
) -> VerifiedTrustContext:
    key = VerifiedKey._construct(
        key_id="inventory-key-v1",
        principal_id="urn:qman:principal:inventory-agent-test",
        public_key_base64url=public_text(private),
        roles=roles,
        not_before=VALID_FROM,
        not_after=VALID_TO,
        revoked_at=None,
    )
    keys = MappingProxyType({key.key_id: key})
    ring = _VerifiedRing._construct(
        key_ring_id="directpath-ring-test",
        sequence=1,
        digest=digest("ring"),
        previous_digest=None,
        not_before=VALID_FROM,
        expires_at=VALID_TO,
        revoked_key_ids=frozenset(),
        keys=keys,
    )
    return VerifiedTrustContext._construct(
        root_set_id="directpath-root-test",
        root_set_digest=digest("root"),
        root_set_canonical_sha256=digest("root-bytes"),
        key_ring_id=ring.key_ring_id,
        key_ring_sequence=ring.sequence,
        key_ring_digest=ring.digest,
        current_key_ring_canonical_sha256=digest("ring-bytes"),
        verified_history_digest=digest("history"),
        trust_anchor_digest=digest("trust-anchor"),
        trust_anchor_version=1,
        trust_anchor_resource_version=1,
        trust_anchor_authority_id="external-trust-authority-test",
        trust_anchor_canonical_sha256=digest("trust-anchor-bytes"),
        freshness_receipt_digest=digest("freshness"),
        freshness_anchor_path="external/trust/current",
        freshness_expires_at=NOW + timedelta(minutes=5),
        verified_at=NOW - timedelta(minutes=1),
        context_digest=digest("trust-context"),
        keys=keys,
        _root_set=MappingProxyType({}),
        _rings=(ring,),
    )


class InventoryFixture:
    def __init__(
        self,
        *,
        private: Ed25519PrivateKey | None = None,
        trust: VerifiedTrustContext | None = None,
    ) -> None:
        if (private is None) != (trust is None):
            raise ValueError("private and trust must be supplied together")
        self.private = private or Ed25519PrivateKey.generate()
        self.trust = trust or trust_context(self.private)
        self.identity = self._slot_identity()
        self.records = [self.make_record(self.identity, "0000:01:00.0")]
        self.snapshot = {
            "subjectType": "HOST_SNAPSHOT",
            "schemaVersion": 1,
            "hostId": self.identity["hostStableId"],
            "kernelBootId": "boot-test-1",
            "hostEpoch": 3,
            "agentGeneration": 5,
            "hostAuthorityResourceVersion": 11,
            "snapshotEpoch": 7,
            "previousSnapshotContentHashOrNull": digest("previous-snapshot"),
            "capturedAt": CAPTURED_AT,
            "topologyDigest": digest("topology"),
            "deviceRecordDigests": [],
            "providerFactsDigest": digest("snapshot-provider-facts"),
            "policyHash": digest("policy"),
            "snapshotFreshnessPolicyHash": digest(
                "snapshot-freshness-policy"
            ),
            "keyRingVersion": self.trust.key_ring_sequence,
            "signerKeyId": "inventory-key-v1",
            "signature": None,
            "contentHash": None,
        }
        self.authority = {
            "hostId": self.identity["hostStableId"],
            "hostEpoch": 3,
            "kernelBootId": "boot-test-1",
            "agentIdentity": ("urn:qman:principal:inventory-agent-test"),
            "agentGeneration": 5,
            "cooperationState": "ONLINE_COOPERATIVE",
            "lastSnapshotEpoch": 7,
            "currentSnapshotContentHash": digest("placeholder"),
            "lastObservedAt": "2026-07-24T01:59:31.000000Z",
            "resourceVersion": 11,
        }
        self.reseal()

    @staticmethod
    def _slot_identity() -> dict:
        vectors = json.loads(
            (CONTRACTS / "directpath-identity-v1.golden-vectors.json").read_text(
                encoding="utf-8"
            )
        )
        vector = next(
            item
            for item in vectors["identityFingerprintVectors"]
            if item["id"] == "IDENTITY-SLOT-BOUND-001"
        )
        return json.loads(vector["canonicalUtf8"])

    @staticmethod
    def raw_config(
        identity: dict,
        *,
        raw_header_type: int = 0x00,
        pcie_port_type: int = 0x0,
        flr_capable: bool = True,
    ) -> bytes:
        raw = bytearray(256)
        pci_ids = identity["pciIds"]
        raw[0x00:0x02] = int(pci_ids["vendorId"], 16).to_bytes(2, "little")
        raw[0x02:0x04] = int(pci_ids["deviceId"], 16).to_bytes(2, "little")
        raw[0x06:0x08] = (1 << 4).to_bytes(2, "little")
        raw[0x08] = int(pci_ids["revisionId"], 16)
        class_code = bytes.fromhex(pci_ids["classCode"])
        raw[0x09:0x0C] = bytes(
            [class_code[2], class_code[1], class_code[0]]
        )
        raw[0x0E] = raw_header_type
        if raw_header_type & 0x7F == 0:
            raw[0x2C:0x2E] = int(
                pci_ids["subsystemVendorId"], 16
            ).to_bytes(2, "little")
            raw[0x2E:0x30] = int(
                pci_ids["subsystemDeviceId"], 16
            ).to_bytes(2, "little")
        elif raw_header_type & 0x7F == 1:
            raw[0x1A] = 2
        raw[0x34] = 0x40
        raw[0x40] = 0x10
        raw[0x41] = 0
        raw[0x42:0x44] = (
            2 | ((pcie_port_type & 0xF) << 4)
        ).to_bytes(2, "little")
        raw[0x44:0x48] = (
            (1 << 28) if flr_capable else 0
        ).to_bytes(4, "little")
        return bytes(raw)

    @staticmethod
    def make_record(identity: dict, bdf: str) -> dict:
        identity_fingerprint = sha256_digest(canonical_json_bytes(identity))
        device_uid = (
            "urn:qman:directpath:device:v1:"
            f"{identity['hostStableId']}:{identity_fingerprint}"
        )
        provenance = digest(f"provenance-{bdf}")
        iommu_domain_provenance = digest(f"iommu-domain-{bdf}")
        provider_fact_id = f"pci-config-{bdf}"
        pci = normalize_pci_config_capture(
            device_uid=device_uid,
            current_bdf=bdf,
            captured_at=CAPTURED_AT,
            provider_fact_id=provider_fact_id,
            provider_id="linux-pci-provider",
            provider_version=1,
            provider_definition_digest=digest("pci-provider"),
            raw_config_space=InventoryFixture.raw_config(identity),
        )
        self_edge = {
            "targetDeviceUid": device_uid,
            "actionState": "KNOWN",
            "requiredActionOrNull": "PAYLOAD",
            "provenanceDigest": provenance,
        }
        return {
            "subjectType": "DEVICE_RECORD",
            "schemaVersion": 3,
            "hostId": identity["hostStableId"],
            "deviceUid": device_uid,
            "immutableIdentity": copy.deepcopy(identity),
            "identityFingerprint": identity_fingerprint,
            "currentBdf": bdf,
            "physicalPathProvider": copy.deepcopy(identity["physicalPathProvider"]),
            "physicalPath": identity["physicalPath"],
            "role": {
                "structuralRole": "ENDPOINT_PAYLOAD",
                "functionRole": identity["pciIds"]["functionRole"],
                "pciStructureFact": dict(pci.structure_fact),
                "roleFactsDigest": pci.structure_fact_digest,
                "provenanceDigest": pci.capture_evidence_digest,
            },
            "iommuProvider": {
                "dmaIsolationMode": "IOMMU",
                "backendCapability": "LEGACY_VFIO_TYPE1V2",
                "kernelIommuGroup": [bdf],
                "providerId": "linux-iommu-provider",
                "providerVersion": 1,
                "providerDefinitionDigest": digest("iommu-provider"),
                "evidenceHash": digest(f"iommu-evidence-{bdf}"),
            },
            "physicalIsolationDomain": {
                "state": "KNOWN",
                "memberDeviceUids": [device_uid],
                "provenanceDigest": provenance,
            },
            "dependencyDomains": [
                {
                    "kind": "FUNCTIONAL",
                    "state": "KNOWN",
                    "provenanceDigest": digest(f"functional-domain-{bdf}"),
                    "edges": [],
                },
                {
                    "kind": "IOMMU",
                    "state": "KNOWN",
                    "provenanceDigest": iommu_domain_provenance,
                    "edges": [copy.deepcopy(self_edge)],
                },
                {
                    "kind": "MULTIFUNCTION",
                    "state": "KNOWN",
                    "provenanceDigest": digest(f"multifunction-domain-{bdf}"),
                    "edges": [],
                },
                {
                    "kind": "PF_VF",
                    "state": "KNOWN",
                    "provenanceDigest": digest(f"pf-vf-domain-{bdf}"),
                    "edges": [],
                },
                {
                    "kind": "PHYSICAL_ISOLATION",
                    "state": "KNOWN",
                    "provenanceDigest": provenance,
                    "edges": [copy.deepcopy(self_edge)],
                },
                {
                    "kind": "PLATFORM",
                    "state": "KNOWN",
                    "provenanceDigest": digest(f"platform-domain-{bdf}"),
                    "edges": [],
                },
                {
                    "kind": "REQUESTER_ALIAS",
                    "state": "KNOWN",
                    "provenanceDigest": digest(f"requester-alias-domain-{bdf}"),
                    "edges": [],
                },
            ],
            "dependencyActions": [
                {
                    "deviceUid": device_uid,
                    "action": "PAYLOAD",
                    "provenanceDigest": provenance,
                }
            ],
            "resetContract": {
                "state": "KNOWN",
                "supported": True,
                "selectedMethodOrNull": "PCI_FLR",
                "resetAffectedSet": [device_uid],
                "pciFlrCapabilityFact": dict(pci.flr_fact),
                "resetProviderFactId": provider_fact_id,
                "contractDigest": pci.capture_evidence_digest,
                "provenanceDigest": pci.capture_evidence_digest,
            },
            "owner": {
                "adminEnabled": True,
                "desiredOwner": "PASSTHROUGH",
                "effectiveOwner": "PASSTHROUGH",
                "hostActive": True,
                "activationDisposition": "ALREADY_ACTIVE",
                "driverOrNull": "vfio-pci",
                "ownerActivationGroup": [device_uid],
                "exclusiveAttachGroup": f"exclusive-{bdf}",
                "provenanceDigest": provenance,
            },
            "bars": [],
            "interrupts": {
                "supportedModes": [],
                "maximumVectors": 0,
                "interruptRemapping": "PRESENT",
                "ats": "ABSENT",
                "pri": "ABSENT",
                "pasid": "ABSENT",
                "provenanceDigest": provenance,
            },
            "health": {
                "state": "HEALTHY",
                "lastResetResult": "NOT_RUN",
                "quarantineReasonCodeOrNull": None,
                "healthEvidenceHash": digest(f"health-{bdf}"),
                "observedAt": CAPTURED_AT,
            },
            "technicalTraits": ["PCI_EXPRESS_ENDPOINT"],
            "generations": {
                "hostEpoch": 3,
                "agentGeneration": 5,
                "snapshotEpoch": 7,
                "deviceGeneration": 2,
                "resourceVersion": 4,
            },
            "provenance": {
                "captureStartedAt": CAPTURE_STARTED_AT,
                "capturedAt": CAPTURED_AT,
                "providerFacts": [dict(pci.provider_fact)],
                "providerFactsDigest": digest(f"provider-facts-{bdf}"),
            },
            "deviceRecordHash": digest("placeholder"),
        }

    @staticmethod
    def bind_pci_capture(
        record: dict,
        raw_config_space: bytes | None,
        *,
        failure_reason_code: str | None = None,
        observed_at: str | None = None,
    ) -> None:
        provider = record["provenance"]["providerFacts"][0]
        pci = normalize_pci_config_capture(
            device_uid=record["deviceUid"],
            current_bdf=record["currentBdf"],
            captured_at=(
                observed_at or record["provenance"]["capturedAt"]
            ),
            provider_fact_id=provider["factId"],
            provider_id=provider["providerId"],
            provider_version=provider["providerVersion"],
            provider_definition_digest=provider["providerDefinitionDigest"],
            raw_config_space=raw_config_space,
            failure_reason_code=failure_reason_code,
        )
        record["role"]["pciStructureFact"] = dict(pci.structure_fact)
        record["role"]["roleFactsDigest"] = pci.structure_fact_digest
        record["role"]["provenanceDigest"] = pci.capture_evidence_digest
        record["resetContract"]["pciFlrCapabilityFact"] = dict(pci.flr_fact)
        record["resetContract"]["contractDigest"] = pci.capture_evidence_digest
        record["resetContract"]["provenanceDigest"] = pci.capture_evidence_digest
        record["provenance"]["providerFacts"] = [dict(pci.provider_fact)]

    def reseal(self) -> None:
        for record in self.records:
            record["provenance"]["providerFactsDigest"] = (
                derive_device_provider_facts_digest(record)
            )
            projection = copy.deepcopy(record)
            projection["deviceRecordHash"] = None
            record["deviceRecordHash"] = sha256_digest(canonical_json_bytes(projection))
        self.snapshot["deviceRecordDigests"] = sorted(
            (record["deviceRecordHash"] for record in self.records),
            key=canonical_json_bytes,
        )
        semantics = derive_host_snapshot_semantics(
            self.snapshot,
            self.records,
        )
        self.snapshot["topologyDigest"] = semantics.topology_digest
        self.snapshot["providerFactsDigest"] = semantics.provider_facts_digest
        projection = copy.deepcopy(self.snapshot)
        projection["signature"] = None
        projection["contentHash"] = None
        projection_raw = canonical_json_bytes(projection)
        self.snapshot["contentHash"] = sha256_digest(projection_raw)
        self.snapshot["signature"] = signature_text(
            self.private,
            b"QMAN-DIRECTPATH/HOST-SNAPSHOT/V1\x00" + projection_raw,
        )
        self.authority["currentSnapshotContentHash"] = self.snapshot["contentHash"]

    def verify(
        self,
        *,
        before: dict | bytes | None = None,
        after: dict | bytes | None = None,
        snapshot: dict | bytes | None = None,
        records: list[dict] | None = None,
        trust: VerifiedTrustContext | None = None,
        limits: InventoryVerifierLimits | None = None,
    ):
        return verify_inventory_context(
            ContractSchemas(CONTRACTS),
            trust or self.trust,
            host_authority_before=before or self.authority,
            host_snapshot=snapshot or self.snapshot,
            device_records=self.records if records is None else records,
            host_authority_after=after or self.authority,
            now=NOW,
            limits=limits,
        )


class InventoryVerificationTests(unittest.TestCase):
    def test_current_inventory_composition_limit_is_fixed_at_4096(self) -> None:
        self.assertEqual(4096, MAX_CURRENT_INVENTORY_DEVICE_RECORDS)
        self.assertEqual(
            4096,
            DEFAULT_INVENTORY_VERIFIER_LIMITS.max_current_device_records,
        )

    def test_real_ed25519_inventory_returns_immutable_exact_view(self) -> None:
        fixture = InventoryFixture()
        context = fixture.verify()

        self.assertEqual(
            context.snapshot_content_hash,
            fixture.snapshot["contentHash"],
        )
        self.assertEqual(1, len(context.device_records))
        self.assertEqual(
            context.device_records[0],
            context.device(fixture.records[0]["deviceUid"]),
        )
        with self.assertRaises(TypeError):
            context.host_snapshot["hostId"] = "mutated"
        with self.assertRaises(TypeError):
            context.device_records[0].document["currentBdf"] = "mutated"
        with self.assertRaises(FrozenInstanceError):
            context.snapshot_epoch = 8

    def test_component_identity_and_receipt_are_closed_derived_subjects(
        self,
    ) -> None:
        fixture = InventoryFixture()
        schemas = ContractSchemas(CONTRACTS)
        context = fixture.verify()

        algorithm = json.loads(context.verifier_algorithm_identity.canonical_bytes)
        self.assertEqual(
            "COMPONENT_ALGORITHM_IDENTITY_NOT_BINARY_ATTESTATION",
            algorithm["identityKind"],
        )
        for binding in algorithm["schemaBindings"]:
            self.assertEqual(
                schemas.digest_for_ref(
                    binding["schemaRef"],
                    path="test.algorithm.schemaBindings",
                ),
                binding["schemaDigest"],
            )
        algorithm_projection = copy.deepcopy(algorithm)
        algorithm_projection["algorithmIdentityDigest"] = None
        self.assertEqual(
            sha256_digest(
                b"QMAN-DIRECTPATH/INVENTORY-VERIFIER-ALGORITHM/V2\x00"
                + canonical_json_bytes(algorithm_projection)
            ),
            context.inventory_verifier_identity_digest,
        )

        receipt = json.loads(context.inventory_verification_receipt_canonical_bytes)
        schemas.validate(
            "inventory_verification_receipt",
            receipt,
            "test.receipt",
        )
        receipt_projection = copy.deepcopy(receipt)
        receipt_projection["receiptDigest"] = None
        self.assertEqual(
            sha256_digest(
                b"QMAN-DIRECTPATH/INVENTORY-VERIFICATION-RECEIPT/V1\x00"
                + canonical_json_bytes(receipt_projection)
            ),
            context.inventory_verification_receipt_digest,
        )
        self.assertEqual(
            context.trust.freshness_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            receipt["trustFreshnessExpiresAt"],
        )
        self.assertEqual(
            fixture.authority["resourceVersion"],
            context.observed_authority_resource_version,
        )
        self.assertEqual(
            fixture.snapshot["hostAuthorityResourceVersion"],
            context.snapshot_authority_resource_version,
        )
        self.assertEqual(
            context.observed_authority_resource_version,
            context.authority_resource_version,
        )
        self.assertEqual(
            fixture.snapshot["deviceRecordDigests"],
            sorted(
                (item["deviceRecordHash"] for item in receipt["deviceRecords"]),
                key=canonical_json_bytes,
            ),
        )
        descriptor = receipt["deviceRecords"][0]
        self.assertEqual(fixture.records[0]["deviceUid"], descriptor["deviceUid"])
        self.assertEqual(
            sha256_digest(context.device_records[0].canonical_bytes),
            descriptor["canonicalDigest"],
        )

    def test_device_record_legacy_and_incomplete_domain_sets_fail_closed(self) -> None:
        mutations = {
            "v1": lambda domains, record: record.__setitem__("schemaVersion", 1),
            "v2": lambda domains, record: record.__setitem__("schemaVersion", 2),
            "wrong-kind": lambda domains, _record: domains[0].__setitem__(
                "kind",
                "PLATFORM",
            ),
            "missing": lambda domains, _record: domains.pop(),
            "duplicate": lambda domains, _record: domains.__setitem__(
                0,
                copy.deepcopy(domains[1]),
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                fixture = InventoryFixture()
                record = fixture.records[0]
                mutate(record["dependencyDomains"], record)
                fixture.reseal()

                with self.assertRaises(DirectPathVerificationError) as raised:
                    fixture.verify()
                self.assertEqual(
                    "CONTRACT_SCHEMA_VIOLATION",
                    raised.exception.code,
                )

    def test_iommu_domain_must_equal_verified_bdf_uid_mapping(self) -> None:
        fixture = InventoryFixture()
        second_identity = copy.deepcopy(fixture.identity)
        second_identity["physicalPath"] = "acpi:/_SB_/PCI0/RP05#adr=0000000000000001"
        fixture.records.append(fixture.make_record(second_identity, "0000:01:00.1"))
        fixture.records[0]["iommuProvider"]["kernelIommuGroup"] = [
            "0000:01:00.0",
            "0000:01:00.1",
        ]
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual(
            "DEPENDENCY_DOMAIN_MEMBERSHIP_MISMATCH",
            raised.exception.code,
        )

    def test_pci_structure_and_flr_are_factory_replayed_from_raw_bytes(
        self,
    ) -> None:
        fixture = InventoryFixture()
        context = fixture.verify()
        pci = context.device_records[0].pci_config_facts
        self.assertEqual("TYPE_0", pci.header_layout)
        self.assertFalse(pci.multifunction)
        self.assertEqual("ENDPOINT", pci.pcie_device_port_type)
        self.assertTrue(pci.function_level_reset_capable)
        with self.assertRaises(TypeError):
            type(pci)()

        tampered = InventoryFixture()
        fact = tampered.records[0]["role"]["pciStructureFact"]
        raw = bytearray.fromhex(fact["rawConfigSpaceHexOrNull"])
        raw[0x0E] = 0x80
        fact["rawConfigSpaceHexOrNull"] = bytes(raw).hex()
        tampered.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            tampered.verify()
        self.assertEqual("PCI_STRUCTURE_FACT_MISMATCH", raised.exception.code)

    def test_header_layout_is_not_derived_from_class_code(self) -> None:
        fixture = InventoryFixture()
        raw_a = bytearray(fixture.raw_config(fixture.identity))
        raw_b = bytearray(raw_a)
        raw_b[0x09:0x0C] = bytes([0x00, 0x04, 0x06])
        provider = fixture.records[0]["provenance"]["providerFacts"][0]
        common = {
            "device_uid": fixture.records[0]["deviceUid"],
            "current_bdf": fixture.records[0]["currentBdf"],
            "captured_at": CAPTURED_AT,
            "provider_fact_id": provider["factId"],
            "provider_id": provider["providerId"],
            "provider_version": provider["providerVersion"],
            "provider_definition_digest": provider[
                "providerDefinitionDigest"
            ],
        }
        fact_a = normalize_pci_config_capture(
            **common,
            raw_config_space=bytes(raw_a),
        )
        fact_b = normalize_pci_config_capture(
            **common,
            raw_config_space=bytes(raw_b),
        )
        self.assertEqual("TYPE_0", fact_a.header_layout)
        self.assertEqual("TYPE_0", fact_b.header_layout)
        self.assertNotEqual(
            fact_a.structure_fact["classCodeOrNull"],
            fact_b.structure_fact["classCodeOrNull"],
        )

        fixture.bind_pci_capture(fixture.records[0], bytes(raw_b))
        fixture.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("PCI_IDENTITY_MISMATCH", raised.exception.code)

    def test_multifunction_bit_keeps_type_zero_layout(self) -> None:
        fixture = InventoryFixture()
        raw = fixture.raw_config(
            fixture.identity,
            raw_header_type=0x80,
        )
        fixture.bind_pci_capture(fixture.records[0], raw)
        fixture.reseal()
        context = fixture.verify()
        pci = context.device_records[0].pci_config_facts
        self.assertEqual("TYPE_0", pci.header_layout)
        self.assertTrue(pci.multifunction)

    def test_type_one_cannot_be_published_as_payload_endpoint(self) -> None:
        fixture = InventoryFixture()
        raw = fixture.raw_config(
            fixture.identity,
            raw_header_type=0x01,
            pcie_port_type=0x6,
        )
        fixture.bind_pci_capture(fixture.records[0], raw)
        fixture.records[0]["resetContract"]["selectedMethodOrNull"] = (
            "VFIO_HOT_RESET"
        )
        fixture.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("PCI_PAYLOAD_ROLE_INVALID", raised.exception.code)

    def test_pci_flr_selection_requires_device_capabilities_bit_28(
        self,
    ) -> None:
        fixture = InventoryFixture()
        raw = fixture.raw_config(
            fixture.identity,
            flr_capable=False,
        )
        fixture.bind_pci_capture(fixture.records[0], raw)
        fixture.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("PCI_RESET_FACT_INVALID", raised.exception.code)

    def test_pci_flr_selection_requires_payload_structural_role(
        self,
    ) -> None:
        fixture = InventoryFixture()
        record = fixture.records[0]
        record["role"]["structuralRole"] = "FABRIC_DEPENDENCY"
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_device_record_pci_facts(record, path="deviceRecord")
        self.assertEqual("PCI_RESET_FACT_INVALID", raised.exception.code)

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("CONTRACT_SCHEMA_VIOLATION", raised.exception.code)

    def test_pci_flr_rejects_cross_provider_digest_substitution(
        self,
    ) -> None:
        fixture = InventoryFixture()
        record = fixture.records[0]
        original = record["provenance"]["providerFacts"][0]
        substituted = {
            **original,
            "factId": "unrelated-reset-provider-fact",
            "providerId": "unrelated-provider",
        }
        record["provenance"]["providerFacts"].append(substituted)
        record["provenance"]["providerFacts"].sort(
            key=lambda fact: canonical_json_bytes(
                [
                    fact["factId"],
                    fact["providerId"],
                    fact["providerVersion"],
                    fact["evidenceHash"],
                ]
            )
        )
        record["resetContract"]["resetProviderFactId"] = substituted[
            "factId"
        ]
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("PCI_RESET_FACT_INVALID", raised.exception.code)

    def test_pci_provider_fact_may_precede_record_capture_completion(
        self,
    ) -> None:
        fixture = InventoryFixture()
        earlier = CAPTURE_STARTED_AT
        fixture.bind_pci_capture(
            fixture.records[0],
            fixture.raw_config(fixture.identity),
            observed_at=earlier,
        )
        fixture.reseal()

        context = fixture.verify()
        record = context.device_records[0].document
        self.assertEqual(
            earlier,
            record["provenance"]["providerFacts"][0]["observedAt"],
        )
        self.assertEqual(CAPTURED_AT, record["provenance"]["capturedAt"])

    def test_pci_provider_fact_before_capture_start_is_rejected(
        self,
    ) -> None:
        fixture = InventoryFixture()
        fixture.bind_pci_capture(
            fixture.records[0],
            fixture.raw_config(fixture.identity),
            observed_at="2000-01-01T00:00:00.000000Z",
        )
        fixture.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual(
            "DEVICE_CAPTURE_INTERVAL_INVALID",
            raised.exception.code,
        )

    def test_active_owner_requires_passthrough_intent(self) -> None:
        fixture = InventoryFixture()
        fixture.records[0]["owner"]["desiredOwner"] = "HOST"
        fixture.reseal()
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("CONTRACT_SCHEMA_VIOLATION", raised.exception.code)

    def test_unavailable_or_malformed_config_fails_closed(self) -> None:
        with self.subTest("unavailable"):
            fixture = InventoryFixture()
            fixture.bind_pci_capture(
                fixture.records[0],
                None,
                failure_reason_code="PCI_CONFIG_READ_UNAVAILABLE",
            )
            fixture.reseal()
            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify()
            self.assertEqual("PCI_PAYLOAD_ROLE_INVALID", raised.exception.code)

        with self.subTest("cyclic-capability-chain"):
            fixture = InventoryFixture()
            raw = bytearray(fixture.raw_config(fixture.identity))
            raw[0x41] = 0x40
            provider = fixture.records[0]["provenance"]["providerFacts"][0]
            with self.assertRaises(DirectPathVerificationError) as raised:
                normalize_pci_config_capture(
                    device_uid=fixture.records[0]["deviceUid"],
                    current_bdf=fixture.records[0]["currentBdf"],
                    captured_at=CAPTURED_AT,
                    provider_fact_id=provider["factId"],
                    provider_id=provider["providerId"],
                    provider_version=provider["providerVersion"],
                    provider_definition_digest=provider[
                        "providerDefinitionDigest"
                    ],
                    raw_config_space=bytes(raw),
                )
            self.assertEqual(
                "PCI_CAPABILITY_CHAIN_INVALID",
                raised.exception.code,
            )

    def test_snapshot_semantic_digests_are_replayed_not_trusted(self) -> None:
        fixture = InventoryFixture()
        fixture.snapshot["topologyDigest"] = digest("forged-topology")
        fixture.reseal()
        fixture.snapshot["topologyDigest"] = digest("forged-topology")
        projection = copy.deepcopy(fixture.snapshot)
        projection["signature"] = None
        projection["contentHash"] = None
        raw = canonical_json_bytes(projection)
        fixture.snapshot["contentHash"] = sha256_digest(raw)
        fixture.snapshot["signature"] = signature_text(
            fixture.private,
            b"QMAN-DIRECTPATH/HOST-SNAPSHOT/V1\x00" + raw,
        )
        fixture.authority["currentSnapshotContentHash"] = fixture.snapshot[
            "contentHash"
        ]
        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual(
            "HOST_SNAPSHOT_TOPOLOGY_DIGEST_INVALID",
            raised.exception.code,
        )

    def test_physical_typed_domain_must_equal_compatibility_fact(self) -> None:
        fixture = InventoryFixture()
        physical = next(
            domain
            for domain in fixture.records[0]["dependencyDomains"]
            if domain["kind"] == "PHYSICAL_ISOLATION"
        )
        physical["provenanceDigest"] = digest("forged-physical-provenance")
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual(
            "DEPENDENCY_DOMAIN_PROVENANCE_MISMATCH",
            raised.exception.code,
        )

    def test_signature_from_a_different_real_ed25519_key_is_rejected(
        self,
    ) -> None:
        fixture = InventoryFixture()
        projection = copy.deepcopy(fixture.snapshot)
        projection["signature"] = None
        projection["contentHash"] = None
        fixture.snapshot["signature"] = signature_text(
            Ed25519PrivateKey.generate(),
            b"QMAN-DIRECTPATH/HOST-SNAPSHOT/V1\x00" + canonical_json_bytes(projection),
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("SIGNATURE_INVALID", raised.exception.code)

    def test_inventory_signer_requires_current_inventory_role(self) -> None:
        fixture = InventoryFixture()
        wrong_role = trust_context(
            fixture.private,
            roles=("PRODUCT_RELEASE",),
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(trust=wrong_role)
        self.assertEqual("SIGNER_ROLE_INVALID", raised.exception.code)

    def test_snapshot_and_record_hash_projections_are_recomputed(self) -> None:
        with self.subTest(subject="HostSnapshot"):
            fixture = InventoryFixture()
            fixture.snapshot["contentHash"] = digest("forged-content-hash")
            fixture.authority["currentSnapshotContentHash"] = fixture.snapshot[
                "contentHash"
            ]

            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify()
            self.assertEqual(
                "SIGNED_DOCUMENT_DIGEST_INVALID",
                raised.exception.code,
            )

        with self.subTest(subject="DeviceRecord"):
            fixture = InventoryFixture()
            fixture.records[0]["deviceRecordHash"] = digest("forged-device-record-hash")

            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify()
            self.assertEqual(
                "DEVICE_RECORD_HASH_INVALID",
                raised.exception.code,
            )

    def test_before_after_authority_change_is_rejected(self) -> None:
        fixture = InventoryFixture()
        after = copy.deepcopy(fixture.authority)
        after["resourceVersion"] += 1

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(after=after)
        self.assertEqual(
            "INVENTORY_AUTHORITY_CHANGED",
            raised.exception.code,
        )

    def test_exact_current_pointer_resource_version_is_required(self) -> None:
        fixture = InventoryFixture()
        authority = copy.deepcopy(fixture.authority)
        authority["resourceVersion"] += 1

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(before=authority, after=authority)
        self.assertEqual("HOST_SNAPSHOT_NOT_CURRENT", raised.exception.code)

    def test_membership_and_internal_reference_closure_are_complete(self) -> None:
        with self.subTest(failure="missing digest member"):
            fixture = InventoryFixture()

            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify(records=[])
            self.assertEqual(
                "DEVICE_RECORD_SET_TOO_LARGE",
                raised.exception.code,
            )

        with self.subTest(failure="reference outside snapshot"):
            fixture = InventoryFixture()
            foreign_uid = (
                "urn:qman:directpath:device:v1:"
                f"{fixture.identity['hostStableId']}:sha256:{'a' * 64}"
            )
            reset_set = fixture.records[0]["resetContract"]["resetAffectedSet"]
            reset_set.append(foreign_uid)
            reset_set.sort(key=canonical_json_bytes)
            fixture.reseal()

            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify()
            self.assertEqual(
                "INVENTORY_REFERENCE_OUTSIDE_SNAPSHOT",
                raised.exception.code,
            )

    def test_duplicate_current_bdf_is_rejected_across_exact_members(self) -> None:
        fixture = InventoryFixture()
        second_identity = copy.deepcopy(fixture.identity)
        second_identity["physicalPath"] = "acpi:/_SB_/PCI0/RP05#adr=0000000000000001"
        fixture.records.append(fixture.make_record(second_identity, "0000:01:00.0"))
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("DEVICE_BDF_DUPLICATE", raised.exception.code)

    def test_slot_bound_physical_path_cannot_drift(self) -> None:
        fixture = InventoryFixture()
        fixture.records[0]["physicalPath"] = "acpi:/_SB_/PCI0/RP05#adr=0000000000000001"
        fixture.reseal()

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify()
        self.assertEqual("DEVICE_IDENTITY_MISMATCH", raised.exception.code)

    def test_noncanonical_snapshot_bytes_are_rejected(self) -> None:
        fixture = InventoryFixture()
        noncanonical = json.dumps(
            fixture.snapshot,
            indent=2,
        ).encode("utf-8")

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(snapshot=noncanonical)
        self.assertEqual("CANONICAL_JSON_INVALID", raised.exception.code)

    def test_record_count_is_rejected_before_first_record_parse(self) -> None:
        fixture = InventoryFixture()

        class OversizedRecords(Sequence):
            def __len__(self):
                return (
                    DEFAULT_INVENTORY_VERIFIER_LIMITS.max_current_device_records + 1
                )

            def __getitem__(self, _index):
                raise AssertionError("oversized record sequence was iterated")

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(records=OversizedRecords())
        self.assertEqual("DEVICE_RECORD_SET_TOO_LARGE", raised.exception.code)

    def test_oversized_mapping_is_rejected_before_canonicalization(self) -> None:
        fixture = InventoryFixture()
        limits = InventoryVerifierLimits(max_document_bytes=1024)
        oversized = {"oversizedMarker": "x" * 2048}
        original = canonical_json_bytes

        def guarded_canonical_json_bytes(value):
            if isinstance(value, dict) and "oversizedMarker" in value:
                raise AssertionError("oversized mapping reached canonicalization")
            return original(value)

        with patch(
            "qman_directpath_core.inventory.canonical_json_bytes",
            side_effect=guarded_canonical_json_bytes,
        ):
            with self.assertRaises(DirectPathVerificationError) as raised:
                fixture.verify(before=oversized, limits=limits)
        self.assertEqual("INVENTORY_INPUT_TOO_LARGE", raised.exception.code)

    def test_dependency_edge_budget_precedes_record_schema_walk(self) -> None:
        fixture = InventoryFixture()
        limits = InventoryVerifierLimits(max_total_dependency_edges=1)

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(limits=limits)
        self.assertEqual("INVENTORY_INPUT_TOO_LARGE", raised.exception.code)

    def test_callers_cannot_relax_inventory_hard_limits(self) -> None:
        fixture = InventoryFixture()
        limits = InventoryVerifierLimits(
            max_json_depth=DEFAULT_INVENTORY_VERIFIER_LIMITS.max_json_depth + 1
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            fixture.verify(limits=limits)
        self.assertEqual("INVENTORY_LIMIT_INVALID", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
