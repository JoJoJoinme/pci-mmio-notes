from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qman_directpath_core.canonical import canonical_json_bytes, sha256_digest
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.trust import (
    verify_qualification_context,
    verify_trust_context,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
NOW = datetime(2026, 7, 24, 2, 0, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-24T02:00:00.000000Z"
VALID_FROM = "2026-01-01T00:00:00.000000Z"
VALID_TO = "2027-01-01T00:00:00.000000Z"
NONCE = base64.urlsafe_b64encode(b"0123456789abcdef").decode().rstrip("=")


def public_text(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signature_text(private: Ed25519PrivateKey, preimage: bytes) -> str:
    raw = private.sign(preimage)
    return "ed25519:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def projected_digest(
    document: dict,
    *,
    null_fields: tuple[str, ...] = (),
    empty_fields: tuple[str, ...] = (),
) -> tuple[str, bytes]:
    projection = copy.deepcopy(document)
    for field in null_fields:
        projection[field] = None
    for field in empty_fields:
        projection[field] = []
    encoded = canonical_json_bytes(projection)
    return sha256_digest(encoded), encoded


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


class TrustFixture:
    def __init__(self, *, include_inventory_key: bool = False) -> None:
        self.root_private = Ed25519PrivateKey.generate()
        self.qe_private = Ed25519PrivateKey.generate()
        self.release_private = Ed25519PrivateKey.generate()
        self.inventory_private = (
            Ed25519PrivateKey.generate() if include_inventory_key else None
        )
        self.root = self._root_set()
        self.ring = self._ring()
        self.anchor = self._trust_anchor()
        self.freshness = self._freshness()

    def _root_set(self) -> dict:
        document = {
            "schemaVersion": 1,
            "rootSetId": "directpath-root-test",
            "verificationPolicy": {
                "policyId": "N_OF_M_ED25519_DISTINCT_KEYS_V1",
                "requiredSignatures": 1,
                "allowedKeyIds": ["root-a"],
            },
            "keys": [
                {
                    "keyId": "root-a",
                    "principalId": "urn:qman:principal:root-a",
                    "algorithm": "Ed25519",
                    "publicKeyBase64Url": public_text(self.root_private),
                    "notBefore": VALID_FROM,
                    "notAfter": VALID_TO,
                }
            ],
            "rootSetDigest": None,
        }
        document["rootSetDigest"], _ = projected_digest(
            document, null_fields=("rootSetDigest",)
        )
        return document

    def _ring(self) -> dict:
        keys = [
            {
                "keyId": "qe-key-v1",
                "principalId": "urn:qman:principal:qualification-a",
                "algorithm": "Ed25519",
                "publicKeyBase64Url": public_text(self.qe_private),
                "roles": ["QUALIFICATION_ENGINEERING"],
                "notBefore": VALID_FROM,
                "notAfter": VALID_TO,
                "revokedAtOrNull": None,
            },
            {
                "keyId": "release-key-v1",
                "principalId": "urn:qman:principal:release-a",
                "algorithm": "Ed25519",
                "publicKeyBase64Url": public_text(self.release_private),
                "roles": ["PRODUCT_RELEASE"],
                "notBefore": VALID_FROM,
                "notAfter": VALID_TO,
                "revokedAtOrNull": None,
            },
        ]
        if self.inventory_private is not None:
            keys.append(
                {
                    "keyId": "inventory-key-v1",
                    "principalId": ("urn:qman:principal:inventory-agent-test"),
                    "algorithm": "Ed25519",
                    "publicKeyBase64Url": public_text(self.inventory_private),
                    "roles": ["HOST_INVENTORY_EVIDENCE"],
                    "notBefore": VALID_FROM,
                    "notAfter": VALID_TO,
                    "revokedAtOrNull": None,
                }
            )
        keys.sort(key=canonical_json_bytes)
        document = {
            "schemaVersion": 1,
            "keyRingId": "directpath-ring-test",
            "keyRingSequence": 1,
            "previousKeyRingDigest": None,
            "minimumReaderSchemaVersion": 1,
            "keys": keys,
            "revokedKeyIds": [],
            "notBefore": VALID_FROM,
            "expiresAt": VALID_TO,
            "rootSignatures": [],
            "keyRingDigest": None,
        }
        digest, _ = projected_digest(
            document,
            null_fields=("keyRingDigest",),
            empty_fields=("rootSignatures",),
        )
        document["keyRingDigest"] = digest
        subject = {
            "rootKeyId": "root-a",
            "signedAt": NOW_TEXT,
            "keyRingDigest": digest,
        }
        document["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signature": signature_text(
                    self.root_private,
                    b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
                    + canonical_json_bytes(subject),
                ),
                "signedAt": NOW_TEXT,
            }
        ]
        return document

    def _trust_anchor(self) -> dict:
        document = {
            "schemaVersion": 1,
            "recordType": "DIRECTPATH_TRUST_KEY_RING_ROLLBACK_ANCHOR",
            "canonicalProfileId": "CANONICAL-JSON-V1",
            "recordState": "COMMITTED",
            "keyRingId": self.ring["keyRingId"],
            "minimumSequence": 1,
            "acceptedKeyRingDigest": self.ring["keyRingDigest"],
            "anchorVersion": 1,
            "resourceVersion": 1,
            "previousAnchorDigestOrNull": None,
            "updatedAt": "2026-07-24T01:55:00.000000Z",
            "authorityId": "external-trust-authority-test",
            "casPrecondition": {
                "expectedAnchorVersionOrNull": None,
                "expectedResourceVersionOrNull": None,
                "expectedMinimumSequenceOrNull": None,
                "expectedAcceptedKeyRingDigestOrNull": None,
                "expectedAnchorDigestOrNull": None,
            },
            "anchorDigest": None,
        }
        document["anchorDigest"], _ = projected_digest(
            document, null_fields=("anchorDigest",)
        )
        return document

    def _freshness(self) -> dict:
        schema_path = CONTRACTS / "directpath-trust-rollback-anchor.schema.json"
        document = {
            "schemaVersion": 1,
            "envelopeId": "fresh-trust-anchor-test",
            "anchorKind": "TRUST_KEY_RING",
            "authorityId": self.anchor["authorityId"],
            "subjectId": self.anchor["keyRingId"],
            "anchorPath": "external/trust/current",
            "anchorBlobSha256": sha256_digest(canonical_json_bytes(self.anchor)),
            "anchorSchemaRef": (
                "contracts/directpath-trust-rollback-anchor.schema.json"
            ),
            "anchorSchemaSha256": sha256_digest(schema_path.read_bytes()),
            "anchorDigest": self.anchor["anchorDigest"],
            "anchorVersion": self.anchor["anchorVersion"],
            "resourceVersion": self.anchor["resourceVersion"],
            "observedAt": "2026-07-24T01:59:30.000000Z",
            "expiresAt": "2026-07-24T02:02:00.000000Z",
            "verifierNonce": NONCE,
            "trustRootDigest": self.root["rootSetDigest"],
            "freshnessReceiptDigest": None,
            "rootSignatures": [],
        }
        digest, _ = projected_digest(
            document,
            null_fields=("freshnessReceiptDigest",),
            empty_fields=("rootSignatures",),
        )
        document["freshnessReceiptDigest"] = digest
        subject = {
            "rootKeyId": "root-a",
            "signedAt": NOW_TEXT,
            "freshnessReceiptDigest": digest,
        }
        document["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signedAt": NOW_TEXT,
                "algorithm": "Ed25519",
                "signature": signature_text(
                    self.root_private,
                    b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00"
                    + canonical_json_bytes(subject),
                ),
            }
        ]
        return document


class QualificationFixture:
    def __init__(self, trust: TrustFixture) -> None:
        self.trust = trust
        self.record = self._record()
        self.catalog = self._catalog()
        self.anchor = self._catalog_anchor()
        self.freshness = self._catalog_freshness()

    def _record(self) -> dict:
        pci_identity = {
            "vendorId": "1af4",
            "deviceId": "1041",
            "subsystemVendorId": "1af4",
            "subsystemDeviceId": "1100",
            "revisionId": "01",
            "classCode": "020000",
            "functionRoleAlgorithm": "CLASS_CODE_ROLE_V1",
            "functionRoleAlgorithmVersion": 1,
            "functionRoleDefinitionDigest": (
                "sha256:7f119749c919c48f6d9cae971378e78ab3ac39ce404d9f"
                "2651bc6766812ff35f"
            ),
            "functionRole": "NETWORK_CONTROLLER",
            "identityVariant": "STRONG_SERIAL",
            "identityProviderId": "PCI_DSN_EUI64_V1",
            "identityProviderVersion": 1,
            "identityProviderDefinitionDigest": (
                "sha256:c477361654ccb4f6c1b61446d3e9695bf666a0e5cf313"
                "b18789a76d2d340cd65"
            ),
            "identityVectorSetDigest": (
                "sha256:0d24bf773afc921caa8965b69588cbfb5876e6c636c283"
                "b3ff3362507b9ee693"
            ),
            "serialValueHashOrNull": digest("serial"),
            "physicalPathOrNull": None,
            "vendorExtractorIdOrNull": None,
            "vendorExtractorDefinitionDigestOrNull": None,
            "errataProfileId": "NONE",
        }
        firmware = {
            "deviceFirmwareVersion": "fw-1",
            "deviceFirmwareDigest": digest("device-firmware"),
            "optionRomDigestOrNull": None,
            "vpdDigestOrNull": None,
            "settingsDigest": digest("device-settings"),
        }
        runtime = {
            "platformProfileId": "platform-x86-test",
            "osRelease": "qman-test-os",
            "architecture": "X86_64",
            "kernelRelease": "6.6-test",
            "kernelBuildDigest": digest("kernel"),
            "qemuVersion": "5.0-test",
            "qemuBinaryDigest": digest("qemu"),
            "machineType": "q35",
            "machineVersion": "5.0",
            "firmwareKind": "UEFI",
            "firmwareCodeDigest": digest("firmware-code"),
            "firmwareVarsBaseDigestOrNull": digest("firmware-vars"),
            "backendFamily": "LEGACY_VFIO_TYPE1",
            "configuredIommuType": "VFIO_TYPE1V2_IOMMU",
            "runtimeCapabilities": [],
        }
        providers = {
            "iommuProviderId": "iommu-provider-v1",
            "iommuProviderDigest": digest("iommu-provider"),
            "interruptRemappingProviderId": "ir-provider-v1",
            "interruptRemappingProviderDigest": digest("ir-provider"),
            "physicalIsolationProviderId": "isolation-provider-v1",
            "physicalIsolationProviderDigest": digest("isolation-provider"),
            "resetProviderId": "reset-provider-v1",
            "resetProviderDigest": digest("reset-provider"),
            "dmaIrqObserverId": "dma-irq-observer-v1",
            "dmaIrqObserverDigest": digest("dma-irq-observer"),
        }
        guest = {
            "guestAbiClass": "qman-x86-pcie-v1",
            "guestArchitecture": "X86_64",
            "guestOs": "linux",
            "guestKernel": "6.6-guest",
            "guestDriverName": "virtio-net",
            "guestDriverVersion": "1",
            "guestDriverDigest": digest("guest-driver"),
            "guestVcpuCount": 2,
            "guestMemoryMiB": 2048,
            "guestCapabilities": [],
            "workloadId": "network-smoke-v1",
            "workloadDefinitionDigest": digest("workload-definition"),
            "minimumDurationSeconds": 10,
        }
        exact_projection = {
            "platformProfileHash": digest("platform-profile"),
            "pciIdentityMatch": pci_identity,
            "deviceArchetype": "GENERIC_PCI",
            "qualificationCaseMatrixSha256": digest("case-matrix"),
            "deviceFirmwareAndRom": firmware,
            "kernelQemuFirmwareBackend": runtime,
            "iommuInterruptResetProviders": providers,
            "guestDriverAndWorkload": guest,
            "deviceTraits": ["NETWORK_ENDPOINT"],
        }
        document = {
            "schemaVersion": 1,
            "qualificationRecordId": "qualification-record-test",
            "qualificationSubjectManifestDigest": digest("subject-manifest"),
            "exactQualificationKey": sha256_digest(
                canonical_json_bytes(exact_projection)
            ),
            **exact_projection,
            "caseIds": ["C00"],
            "e4EvidenceHashes": sorted([digest("e4-a"), digest("e4-b")]),
            "issuedAt": "2026-07-24T01:40:00.000000Z",
            "notBefore": "2026-07-24T01:45:00.000000Z",
            "expiresAt": "2026-07-24T02:30:00.000000Z",
            "qualificationSignerKeyId": "qe-key-v1",
            "keyRingVersion": 1,
            "signature": None,
            "recordDigest": None,
        }
        self.resign_record(document)
        return document

    def resign_record(self, document: dict) -> None:
        exact_projection = {
            name: copy.deepcopy(document[name])
            for name in (
                "platformProfileHash",
                "pciIdentityMatch",
                "deviceArchetype",
                "qualificationCaseMatrixSha256",
                "deviceFirmwareAndRom",
                "kernelQemuFirmwareBackend",
                "iommuInterruptResetProviders",
                "guestDriverAndWorkload",
                "deviceTraits",
            )
        }
        document["exactQualificationKey"] = sha256_digest(
            canonical_json_bytes(exact_projection)
        )
        document["recordDigest"] = None
        document["signature"] = None
        record_digest, projection = projected_digest(
            document, null_fields=("recordDigest", "signature")
        )
        document["recordDigest"] = record_digest
        document["signature"] = signature_text(
            self.trust.qe_private,
            b"QMAN-DIRECTPATH/QUALIFICATION-RECORD/V1\x00" + projection,
        )

    def _catalog(self) -> dict:
        document = {
            "schemaVersion": 1,
            "catalogId": "supported-catalog-test",
            "catalogSequence": 1,
            "previousCatalogDigest": None,
            "minimumReaderSchemaVersion": 1,
            "qualificationRecordDigests": [self.record["recordDigest"]],
            "denyAndRevocationEntries": [],
            "revocationBehavior": "DENY_NEW_AND_NEXT_POWER_ON",
            "issuedAt": "2026-07-24T01:46:00.000000Z",
            "notBefore": "2026-07-24T01:47:00.000000Z",
            "expiresAt": "2026-07-24T02:30:00.000000Z",
            "keyRingVersion": 1,
            "productReleaseSignerKeyId": "release-key-v1",
            "signature": None,
            "catalogDigest": None,
        }
        self.resign_catalog(document)
        return document

    def resign_catalog(self, document: dict) -> None:
        document["signature"] = None
        document["catalogDigest"] = None
        catalog_digest, projection = projected_digest(
            document, null_fields=("catalogDigest", "signature")
        )
        document["catalogDigest"] = catalog_digest
        document["signature"] = signature_text(
            self.trust.release_private,
            b"QMAN-DIRECTPATH/SUPPORTED-CATALOG/V1\x00" + projection,
        )

    def _catalog_anchor(self, previous: dict | None = None) -> dict:
        if previous is None:
            anchor_version = 1
            previous_digest = None
            cas = {
                "expectedAnchorVersionOrNull": None,
                "expectedResourceVersionOrNull": None,
                "expectedMinimumCatalogSequenceOrNull": None,
                "expectedAcceptedCatalogDigestOrNull": None,
                "expectedAnchorDigestOrNull": None,
            }
        else:
            anchor_version = previous["anchorVersion"] + 1
            previous_digest = previous["anchorDigest"]
            cas = {
                "expectedAnchorVersionOrNull": previous["anchorVersion"],
                "expectedResourceVersionOrNull": previous["resourceVersion"],
                "expectedMinimumCatalogSequenceOrNull": (
                    previous["minimumCatalogSequence"]
                ),
                "expectedAcceptedCatalogDigestOrNull": (
                    previous["acceptedCatalogDigest"]
                ),
                "expectedAnchorDigestOrNull": previous["anchorDigest"],
            }
        document = {
            "schemaVersion": 1,
            "recordType": "DIRECTPATH_CATALOG_ROLLBACK_ANCHOR",
            "canonicalProfileId": "CANONICAL-JSON-V1",
            "recordState": "COMMITTED",
            "catalogId": self.catalog["catalogId"],
            "anchorVersion": anchor_version,
            "resourceVersion": anchor_version,
            "minimumCatalogSequence": self.catalog["catalogSequence"],
            "acceptedCatalogDigest": self.catalog["catalogDigest"],
            "updatedAt": "2026-07-24T01:48:00.000000Z",
            "authorityId": "external-catalog-authority-test",
            "previousAnchorDigestOrNull": previous_digest,
            "casPrecondition": cas,
            "anchorDigest": None,
            "receipt": None,
        }
        document["anchorDigest"], _ = projected_digest(
            document, null_fields=("anchorDigest", "receipt")
        )
        receipt = {
            "schemaVersion": 1,
            "receiptId": f"catalog-anchor-receipt-{anchor_version}",
            "subjectAnchorDigest": document["anchorDigest"],
            "catalogId": document["catalogId"],
            "minimumCatalogSequence": document["minimumCatalogSequence"],
            "acceptedCatalogDigest": document["acceptedCatalogDigest"],
            "anchorVersion": document["anchorVersion"],
            "resourceVersion": document["resourceVersion"],
            "authorityId": document["authorityId"],
            "issuedAt": "2026-07-24T01:49:00.000000Z",
            "trustRootDigest": self.trust.root["rootSetDigest"],
            "receiptDigest": None,
            "rootSignatures": [],
        }
        receipt_digest, _ = projected_digest(
            receipt,
            null_fields=("receiptDigest",),
            empty_fields=("rootSignatures",),
        )
        receipt["receiptDigest"] = receipt_digest
        subject = {
            "rootKeyId": "root-a",
            "signedAt": "2026-07-24T01:49:00.000000Z",
            "receiptDigest": receipt_digest,
        }
        receipt["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signedAt": "2026-07-24T01:49:00.000000Z",
                "algorithm": "Ed25519",
                "signature": signature_text(
                    self.trust.root_private,
                    (b"QMAN-DIRECTPATH/CATALOG-ROLLBACK-ANCHOR-RECEIPT/V1\x00")
                    + canonical_json_bytes(subject),
                ),
            }
        ]
        document["receipt"] = receipt
        return document

    def _catalog_freshness(self) -> dict:
        schema_path = CONTRACTS / "directpath-catalog-rollback-anchor.schema.json"
        document = {
            "schemaVersion": 1,
            "envelopeId": "fresh-catalog-anchor-test",
            "anchorKind": "SUPPORTED_CATALOG",
            "authorityId": self.anchor["authorityId"],
            "subjectId": self.anchor["catalogId"],
            "anchorPath": "external/catalog/current",
            "anchorBlobSha256": sha256_digest(canonical_json_bytes(self.anchor)),
            "anchorSchemaRef": (
                "contracts/directpath-catalog-rollback-anchor.schema.json"
            ),
            "anchorSchemaSha256": sha256_digest(schema_path.read_bytes()),
            "anchorDigest": self.anchor["anchorDigest"],
            "anchorVersion": self.anchor["anchorVersion"],
            "resourceVersion": self.anchor["resourceVersion"],
            "observedAt": "2026-07-24T01:59:30.000000Z",
            "expiresAt": "2026-07-24T02:02:00.000000Z",
            "verifierNonce": NONCE,
            "trustRootDigest": self.trust.root["rootSetDigest"],
            "freshnessReceiptDigest": None,
            "rootSignatures": [],
        }
        receipt_digest, _ = projected_digest(
            document,
            null_fields=("freshnessReceiptDigest",),
            empty_fields=("rootSignatures",),
        )
        document["freshnessReceiptDigest"] = receipt_digest
        subject = {
            "rootKeyId": "root-a",
            "signedAt": NOW_TEXT,
            "freshnessReceiptDigest": receipt_digest,
        }
        document["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signedAt": NOW_TEXT,
                "algorithm": "Ed25519",
                "signature": signature_text(
                    self.trust.root_private,
                    b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00"
                    + canonical_json_bytes(subject),
                ),
            }
        ]
        return document


class TrustContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def verify(self, fixture: TrustFixture, **overrides):
        values = {
            "schemas": self.schemas,
            "pinned_root_set": fixture.root,
            "pinned_root_digest": fixture.root["rootSetDigest"],
            "key_ring_documents": [fixture.ring],
            "external_trust_anchor": fixture.anchor,
            "trust_anchor_freshness": fixture.freshness,
            "verifier_nonce": NONCE,
            "now": NOW,
        }
        values.update(overrides)
        return verify_trust_context(**values)

    def test_real_ed25519_history_anchor_and_freshness_are_stable(self) -> None:
        fixture = TrustFixture()

        first = self.verify(fixture)
        second = self.verify(fixture)

        self.assertEqual(first, second)
        self.assertEqual(first.key_ring_sequence, 1)
        self.assertEqual(first.key_ring_digest, fixture.ring["keyRingDigest"])
        self.assertEqual(first.trust_anchor_digest, fixture.anchor["anchorDigest"])
        self.assertEqual(first.root_set_digest, fixture.root["rootSetDigest"])
        self.assertEqual(
            first.authorized_key(
                "qe-key-v1",
                required_role="QUALIFICATION_ENGINEERING",
                at=NOW,
            ).roles,
            ("QUALIFICATION_ENGINEERING",),
        )
        for role, at, expected_code in (
            ("PRODUCT_RELEASE", NOW, "SIGNER_ROLE_INVALID"),
            (
                "QUALIFICATION_ENGINEERING",
                NOW - timedelta(seconds=1),
                "TRUST_CONTEXT_STALE",
            ),
            (
                "QUALIFICATION_ENGINEERING",
                first.freshness_expires_at + timedelta(microseconds=1),
                "TRUST_CONTEXT_STALE",
            ),
        ):
            with self.subTest(role=role, at=at, expected_code=expected_code):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    first.authorized_key(
                        "qe-key-v1",
                        required_role=role,
                        at=at,
                    )
                self.assertEqual(raised.exception.code, expected_code)

    def test_nonce_replay_or_expired_freshness_fails_closed(self) -> None:
        fixture = TrustFixture()
        for override in (
            {
                "verifier_nonce": base64.urlsafe_b64encode(b"fedcba9876543210")
                .decode()
                .rstrip("=")
            },
            {"now": NOW + timedelta(minutes=10)},
        ):
            with self.subTest(override=override):
                with self.assertRaises(DirectPathVerificationError):
                    self.verify(fixture, **override)

    def test_future_freshness_signature_exceeding_skew_fails_closed(self) -> None:
        fixture = TrustFixture()
        future = copy.deepcopy(fixture.freshness)
        signed_at = "2026-07-24T02:01:00.000000Z"
        subject = {
            "rootKeyId": "root-a",
            "signedAt": signed_at,
            "freshnessReceiptDigest": future["freshnessReceiptDigest"],
        }
        future["rootSignatures"][0]["signedAt"] = signed_at
        future["rootSignatures"][0]["signature"] = signature_text(
            fixture.root_private,
            b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00" + canonical_json_bytes(subject),
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            self.verify(fixture, trust_anchor_freshness=future)
        self.assertEqual(raised.exception.code, "SIGNATURE_TIME_INVALID")

    def test_ring_tamper_or_unknown_root_signer_fails_closed(self) -> None:
        fixture = TrustFixture()
        tampered = copy.deepcopy(fixture.ring)
        tampered["keys"][0]["principalId"] = "urn:qman:principal:attacker"
        unknown = copy.deepcopy(fixture.ring)
        unknown["rootSignatures"][0]["rootKeyId"] = "root-unknown"

        for ring in (tampered, unknown):
            with self.subTest(ring=ring):
                with self.assertRaises(DirectPathVerificationError):
                    self.verify(fixture, key_ring_documents=[ring])

    def test_history_gap_is_rejected_before_anchor_acceptance(self) -> None:
        fixture = TrustFixture()
        future = copy.deepcopy(fixture.ring)
        future["keyRingSequence"] = 3
        future["previousKeyRingDigest"] = fixture.ring["keyRingDigest"]
        future["rootSignatures"] = []
        future["keyRingDigest"] = None
        digest, _ = projected_digest(
            future,
            null_fields=("keyRingDigest",),
            empty_fields=("rootSignatures",),
        )
        future["keyRingDigest"] = digest
        subject = {
            "rootKeyId": "root-a",
            "signedAt": NOW_TEXT,
            "keyRingDigest": digest,
        }
        future["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signedAt": NOW_TEXT,
                "signature": signature_text(
                    fixture.root_private,
                    b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
                    + canonical_json_bytes(subject),
                ),
            }
        ]

        with self.assertRaises(DirectPathVerificationError) as raised:
            self.verify(fixture, key_ring_documents=[fixture.ring, future])
        self.assertEqual(raised.exception.code, "KEY_RING_HISTORY_GAP")


class QualificationContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def contexts(self, fixture: QualificationFixture):
        trust = verify_trust_context(
            self.schemas,
            pinned_root_set=fixture.trust.root,
            pinned_root_digest=fixture.trust.root["rootSetDigest"],
            key_ring_documents=[fixture.trust.ring],
            external_trust_anchor=fixture.trust.anchor,
            trust_anchor_freshness=fixture.trust.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        qualification = verify_qualification_context(
            self.schemas,
            trust,
            catalog_documents=[fixture.catalog],
            qualification_records=[fixture.record],
            external_catalog_anchor=fixture.anchor,
            catalog_anchor_freshness=fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        return trust, qualification

    def test_real_record_catalog_anchor_chain_resolves_exact_profile(self) -> None:
        fixture = QualificationFixture(TrustFixture())

        trust, qualification = self.contexts(fixture)
        profile = qualification.profile(fixture.record["exactQualificationKey"])

        self.assertEqual(
            profile.qualification_record_digest,
            fixture.record["recordDigest"],
        )
        self.assertEqual(profile.qualification_signer_key_id, "qe-key-v1")
        self.assertEqual(
            qualification.product_release_signer_key_id,
            "release-key-v1",
        )
        self.assertNotEqual(qualification.context_digest, trust.context_digest)
        self.assertEqual(profile.applicable_deny_entry_digests, ())
        for value in (
            trust,
            next(iter(trust.keys.values())),
            trust._rings[-1],
            qualification,
            profile,
        ):
            with self.subTest(factory_only=type(value).__name__):
                with self.assertRaises(TypeError):
                    type(value)()
                with self.assertRaises(TypeError):
                    replace(value)

    def test_unknown_signer_or_record_tamper_fails_closed(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        trust, _ = self.contexts(fixture)
        unknown = copy.deepcopy(fixture.record)
        unknown["qualificationSignerKeyId"] = "unknown-qe-key"
        fixture.resign_record(unknown)
        tampered = copy.deepcopy(fixture.record)
        tampered["guestDriverAndWorkload"]["guestDriverVersion"] = "forged"

        for record in (unknown, tampered):
            with self.subTest(record=record):
                with self.assertRaises(DirectPathVerificationError):
                    verify_qualification_context(
                        self.schemas,
                        trust,
                        catalog_documents=[fixture.catalog],
                        qualification_records=[record],
                        external_catalog_anchor=fixture.anchor,
                        catalog_anchor_freshness=fixture.freshness,
                        verifier_nonce=NONCE,
                        now=NOW,
                    )

    def test_active_exact_selector_deny_fails_closed(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        fixture.catalog["denyAndRevocationEntries"] = [
            {
                "entryId": "deny-record-test",
                "selectorKind": "QUALIFICATION_RECORD",
                "selectorDigest": fixture.record["recordDigest"],
                "reasonCode": "QUALIFICATION_REVOKED_TEST",
                "severity": "NORMAL",
                "revocationBehavior": "DENY_NEW_AND_NEXT_POWER_ON",
                "effectiveAt": "2026-07-24T01:50:00.000000Z",
                "evidenceHash": digest("deny-evidence"),
            }
        ]
        fixture.resign_catalog(fixture.catalog)
        fixture.anchor = fixture._catalog_anchor()
        fixture.freshness = fixture._catalog_freshness()
        trust = verify_trust_context(
            self.schemas,
            pinned_root_set=fixture.trust.root,
            pinned_root_digest=fixture.trust.root["rootSetDigest"],
            key_ring_documents=[fixture.trust.ring],
            external_trust_anchor=fixture.trust.anchor,
            trust_anchor_freshness=fixture.trust.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_qualification_context(
                self.schemas,
                trust,
                catalog_documents=[fixture.catalog],
                qualification_records=[fixture.record],
                external_catalog_anchor=fixture.anchor,
                catalog_anchor_freshness=fixture.freshness,
                verifier_nonce=NONCE,
                now=NOW,
            )
        self.assertEqual(raised.exception.code, "QUALIFICATION_DENIED")

    def test_future_deny_truncates_profile_authorization_horizon(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        deny_at = "2026-07-24T02:01:00.000000Z"
        fixture.catalog["denyAndRevocationEntries"] = [
            {
                "entryId": "future-deny-record-test",
                "selectorKind": "QUALIFICATION_RECORD",
                "selectorDigest": fixture.record["recordDigest"],
                "reasonCode": "QUALIFICATION_REVOKED_TEST",
                "severity": "NORMAL",
                "revocationBehavior": "DENY_NEW_AND_NEXT_POWER_ON",
                "effectiveAt": deny_at,
                "evidenceHash": digest("future-deny-evidence"),
            }
        ]
        fixture.resign_catalog(fixture.catalog)
        fixture.anchor = fixture._catalog_anchor()
        fixture.freshness = fixture._catalog_freshness()

        _, qualification = self.contexts(fixture)
        profile = qualification.profile(fixture.record["exactQualificationKey"])

        self.assertEqual(
            profile.expires_at,
            datetime(2026, 7, 24, 2, 1, tzinfo=timezone.utc),
        )

    def test_disjoint_catalog_profile_change_keeps_selected_dependency(self) -> None:
        fixture = QualificationFixture(TrustFixture())
        trust, first = self.contexts(fixture)
        first_catalog = copy.deepcopy(fixture.catalog)
        first_anchor = copy.deepcopy(fixture.anchor)
        second_record = copy.deepcopy(fixture.record)
        second_record["qualificationRecordId"] = "qualification-record-other"
        second_record["platformProfileHash"] = digest("other-platform-profile")
        second_record["kernelQemuFirmwareBackend"]["platformProfileId"] = (
            "platform-x86-other"
        )
        fixture.resign_record(second_record)

        second_catalog = copy.deepcopy(first_catalog)
        second_catalog["catalogSequence"] = 2
        second_catalog["previousCatalogDigest"] = first_catalog["catalogDigest"]
        second_catalog["qualificationRecordDigests"] = sorted(
            [
                fixture.record["recordDigest"],
                second_record["recordDigest"],
            ]
        )
        fixture.resign_catalog(second_catalog)
        fixture.catalog = second_catalog
        fixture.anchor = fixture._catalog_anchor(previous=first_anchor)
        fixture.freshness = fixture._catalog_freshness()

        second = verify_qualification_context(
            self.schemas,
            trust,
            catalog_documents=[first_catalog, second_catalog],
            qualification_records=[fixture.record, second_record],
            external_catalog_anchor=fixture.anchor,
            catalog_anchor_freshness=fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        selected_key = fixture.record["exactQualificationKey"]

        self.assertEqual(
            first.profile(selected_key).dependency_digest,
            second.profile(selected_key).dependency_digest,
        )
        self.assertNotEqual(first.context_digest, second.context_digest)


if __name__ == "__main__":
    unittest.main()
