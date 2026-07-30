from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.identity import verify_identity


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"


class IdentityVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)
        cls.vectors = json.loads(
            (CONTRACTS / "directpath-identity-v1.golden-vectors.json").read_text(
                encoding="utf-8"
            )
        )
        cls.identities = {
            vector["id"]: json.loads(vector["canonicalUtf8"])
            for vector in cls.vectors["identityFingerprintVectors"]
        }

    def test_golden_identity_variants_derive_exact_uid(self) -> None:
        for vector in self.vectors["identityFingerprintVectors"]:
            with self.subTest(vector=vector["id"]):
                verified = verify_identity(
                    self.schemas,
                    vector["canonicalUtf8"].encode("utf-8"),
                )
                self.assertEqual(
                    verified.identity_fingerprint,
                    vector["sha256"],
                )
                self.assertEqual(
                    verified.device_uid,
                    (
                        "urn:qman:directpath:device:v1:"
                        f"{verified.host_stable_id}:{vector['sha256']}"
                    ),
                )
                self.assertEqual(
                    canonical_json_bytes(verified.document),
                    verified.canonical_bytes,
                )
                with self.assertRaises(TypeError):
                    verified.document["hostStableId"] = "mutated"
                with self.assertRaises(FrozenInstanceError):
                    verified.device_uid = "mutated"

    def test_dsn_source_slice_and_byte_order_are_recomputed(self) -> None:
        identity = copy.deepcopy(self.identities["IDENTITY-STRONG-SERIAL-001"])
        identity["serialMaterial"]["extractedBytesHex"] = "8877665544332212"
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, identity)
        self.assertEqual(
            raised.exception.code,
            "IDENTITY_SERIAL_SLICE_INVALID",
        )

        identity = copy.deepcopy(self.identities["IDENTITY-STRONG-SERIAL-001"])
        canonical = bytes.fromhex("1122334455667789")
        identity["serialMaterial"]["canonicalSerialBytesHex"] = canonical.hex()
        identity["serialValueHash"] = sha256_digest(
            b"QMAN-DIRECTPATH/SERIAL-VALUE/V1\x00PCI_DSN_EUI64_V1\x00" + canonical
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, identity)
        self.assertEqual(
            raised.exception.code,
            "IDENTITY_SERIAL_TRANSFORM_INVALID",
        )

    def test_vpd_sn_is_parsed_trimmed_and_normalized_from_raw_image(self) -> None:
        vector = next(
            item
            for item in self.vectors["serialVectors"]
            if item["providerId"] == "PCI_VPD_SN_UTF8_V1"
        )
        identity = copy.deepcopy(self.identities["IDENTITY-STRONG-SERIAL-001"])
        identity["serialProvider"] = {
            "providerId": "PCI_VPD_SN_UTF8_V1",
            "providerVersion": 1,
            "providerDefinitionDigest": (
                "sha256:2ac49a541d5e0324d1f8eaacbcfb87ad8667fe3e8659993"
                "6a751cb74d9769429"
            ),
        }
        identity["serialMaterial"] = {
            "sourceLocator": "PCI_VPD_READ_ONLY_SN_KEYWORD",
            "sourceBytesHex": vector["sourceBytesHex"],
            "extractionOffsetBytes": vector["extractionOffsetBytes"],
            "extractionLengthBytes": vector["extractionLengthBytes"],
            "extractedBytesHex": vector["extractedBytesHex"],
            "byteOrder": "AS_EXTRACTED",
            "textNormalization": "STRICT_UTF8_TRIM_ASCII_SPACE_NFC",
            "canonicalSerialBytesHex": vector["canonicalSerialBytesHex"],
        }
        identity["serialValueHash"] = vector["serialValueHash"]
        verified = verify_identity(self.schemas, identity)
        self.assertEqual(vector["serialValueHash"], verified.serial_value_hash)

        tampered = copy.deepcopy(identity)
        tampered["serialMaterial"]["extractionOffsetBytes"] = 5
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, tampered)
        self.assertEqual(
            raised.exception.code,
            "IDENTITY_SERIAL_SLICE_INVALID",
        )

    def test_vendor_bytes_require_separately_verified_extractor(self) -> None:
        vector = next(
            item
            for item in self.vectors["serialVectors"]
            if item["providerId"] == "VENDOR_QUALIFIED_BYTES_V1"
        )
        identity = copy.deepcopy(self.identities["IDENTITY-STRONG-SERIAL-001"])
        identity["serialProvider"] = {
            "providerId": "VENDOR_QUALIFIED_BYTES_V1",
            "providerVersion": 1,
            "providerDefinitionDigest": (
                "sha256:084e4ef848c737fe0db24231bdda1441c40287cd99743c61"
                "ce2e340644c23764"
            ),
        }
        identity["serialMaterial"] = {
            "sourceLocator": "QUALIFIED_VENDOR_SOURCE",
            "sourceBytesHex": vector["sourceBytesHex"],
            "extractionOffsetBytes": vector["extractionOffsetBytes"],
            "extractionLengthBytes": vector["extractionLengthBytes"],
            "extractedBytesHex": vector["extractedBytesHex"],
            "byteOrder": "AS_EXTRACTED",
            "textNormalization": "QUALIFIED_EXTRACTOR_OUTPUT_BYTES",
            "canonicalSerialBytesHex": vector["canonicalSerialBytesHex"],
            "vendorExtractorId": vector["vendorExtractorId"],
            "vendorExtractorDefinitionDigest": (
                vector["vendorExtractorDefinitionDigest"]
            ),
        }
        identity["serialValueHash"] = vector["serialValueHash"]

        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, identity)
        self.assertEqual(
            raised.exception.code,
            "VENDOR_EXTRACTOR_UNVERIFIED",
        )

    def test_noncanonical_or_unknown_identity_input_fails_closed(self) -> None:
        identity = self.identities["IDENTITY-SLOT-BOUND-001"]
        noncanonical = json.dumps(identity, indent=2).encode("utf-8")
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, noncanonical)
        self.assertEqual(raised.exception.code, "CANONICAL_JSON_INVALID")

        unknown = copy.deepcopy(identity)
        unknown["physicalPathProvider"]["providerId"] = "SYSFS_BDF_V1"
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_identity(self.schemas, unknown)
        self.assertEqual(
            raised.exception.code,
            "CONTRACT_SCHEMA_VIOLATION",
        )

    def test_smbios_slot_designation_has_one_canonical_spelling(self) -> None:
        base = copy.deepcopy(self.identities["IDENTITY-SLOT-BOUND-001"])
        base["physicalPathProvider"] = {
            "providerId": "SMBIOS_SYSTEM_SLOT_V1",
            "providerVersion": 1,
            "providerDefinitionDigest": (
                "sha256:c8a3291773b34ff8ef67511a5574db43be24b07bd7840c900"
                "bbbdab682687b0d"
            ),
        }
        base["physicalPath"] = (
            "smbios-system-slot:/slot-id=0007/designation=Slot%20A/function=0"
        )
        canonical = verify_identity(self.schemas, base)
        self.assertEqual(canonical.physical_path, base["physicalPath"])

        invalid_paths = (
            "smbios-system-slot:/slot-id=0007/designation=%41/function=0",
            "smbios-system-slot:/slot-id=0007/designation=%FF/function=0",
            ("smbios-system-slot:/slot-id=0007/designation=%20Slot%20/function=0"),
            ("smbios-system-slot:/slot-id=0007/designation=Cafe%CC%81/function=0"),
        )
        for physical_path in invalid_paths:
            with self.subTest(physical_path=physical_path):
                tampered = copy.deepcopy(base)
                tampered["physicalPath"] = physical_path
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_identity(self.schemas, tampered)
                self.assertIn(
                    raised.exception.code,
                    {
                        "IDENTITY_PHYSICAL_PATH_INVALID",
                        "IDENTITY_PHYSICAL_PATH_NONCANONICAL",
                    },
                )


if __name__ == "__main__":
    unittest.main()
