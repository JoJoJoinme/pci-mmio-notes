from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.policy import verify_capability_policy


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
NOW = datetime(2026, 7, 24, 8, 0, 0, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def policy_document() -> dict:
    document = {
        "subjectType": "DIRECTPATH_CAPABILITY_POLICY",
        "schemaVersion": 1,
        "policyId": "directpath-production-policy",
        "policyVersion": 7,
        "admissionMode": "PRODUCTION",
        "supportedCatalogDigest": digest("catalog"),
        "catalogSequence": 11,
        "trustKeyRingSequence": 13,
        "qualificationCaseMatrixHash": digest("case-matrix"),
        "dependencyClosure": {
            "resolverAlgorithmId": ("SEVEN_DOMAIN_RESET_FIXED_POINT_V1"),
            "maxDevices": 256,
            "maxEdges": 4096,
        },
        "sourceCompatibilityProfilePolicyDigest": digest(
            "compatibility-profile-policy"
        ),
        "effectiveAt": "2026-07-24T07:00:00.000000Z",
        "expiresAt": "2026-07-24T09:00:00.000000Z",
        "policyHash": None,
    }
    document["policyHash"] = sha256_digest(canonical_json_bytes(document))
    return document


class CapabilityPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def test_verifies_closed_hash_time_and_limits(self) -> None:
        source = policy_document()
        raw = canonical_json_bytes(source)
        verified = verify_capability_policy(
            self.schemas,
            raw,
            verified_at=NOW,
        )

        self.assertEqual(source["policyHash"], verified.policy_hash)
        self.assertEqual(sha256_digest(raw), verified.canonical_digest)
        self.assertEqual(256, verified.closure_limits.max_devices)
        self.assertEqual(4096, verified.closure_limits.max_edges)
        self.assertEqual(NOW, verified.verified_at)
        self.assertEqual(
            {
                "policyId": source["policyId"],
                "policyVersion": source["policyVersion"],
                "policyHash": source["policyHash"],
                "admissionMode": source["admissionMode"],
                "supportedCatalogDigest": (source["supportedCatalogDigest"]),
                "catalogSequence": source["catalogSequence"],
                "trustKeyRingSequence": source["trustKeyRingSequence"],
                "qualificationCaseMatrixHash": (source["qualificationCaseMatrixHash"]),
            },
            verified.request_policy_binding(),
        )

        source["dependencyClosure"]["maxDevices"] = 1
        self.assertEqual(
            256,
            verified.document["dependencyClosure"]["maxDevices"],
        )
        with self.assertRaises(TypeError):
            verified.document["policyId"] = "mutated"
        with self.assertRaises(FrozenInstanceError):
            verified.policy_hash = digest("mutated")

    def test_rejects_noncanonical_bytes_and_unknown_fields(self) -> None:
        source = policy_document()
        pretty = json.dumps(source, indent=2).encode("utf-8")
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                pretty,
                verified_at=NOW,
            )
        self.assertEqual("CANONICAL_JSON_INVALID", raised.exception.code)

        source["undeclared"] = True
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                source,
                verified_at=NOW,
            )
        self.assertEqual(
            "CONTRACT_SCHEMA_VIOLATION",
            raised.exception.code,
        )

    def test_rejects_changed_policy_without_rehash(self) -> None:
        source = policy_document()
        source["dependencyClosure"]["maxDevices"] = 255
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                source,
                verified_at=NOW,
            )
        self.assertEqual(
            "CAPABILITY_POLICY_HASH_INVALID",
            raised.exception.code,
        )
        self.assertEqual("policy.policyHash", raised.exception.path)

    def test_rejects_invalid_or_untrusted_time_window(self) -> None:
        future = policy_document()
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                future,
                verified_at=datetime(2026, 7, 24, 6, 59, tzinfo=timezone.utc),
            )
        self.assertEqual(
            "CAPABILITY_POLICY_NOT_YET_EFFECTIVE",
            raised.exception.code,
        )

        expired = policy_document()
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                expired,
                verified_at=datetime(2026, 7, 24, 9, 0, tzinfo=timezone.utc),
            )
        self.assertEqual(
            "CAPABILITY_POLICY_EXPIRED",
            raised.exception.code,
        )

        inverted = policy_document()
        inverted["expiresAt"] = inverted["effectiveAt"]
        projection = copy.deepcopy(inverted)
        projection["policyHash"] = None
        inverted["policyHash"] = sha256_digest(canonical_json_bytes(projection))
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_capability_policy(
                self.schemas,
                inverted,
                verified_at=NOW,
            )
        self.assertEqual(
            "CAPABILITY_POLICY_TIME_INVALID",
            raised.exception.code,
        )

    def test_schema_enforces_resolver_and_hard_ceiling(self) -> None:
        for field, value in (
            ("resolverAlgorithmId", "CALLER_SELECTED_ALGORITHM"),
            ("maxDevices", 4097),
            ("maxEdges", 65537),
        ):
            with self.subTest(field=field):
                source = policy_document()
                source["dependencyClosure"][field] = value
                projection = copy.deepcopy(source)
                projection["policyHash"] = None
                source["policyHash"] = sha256_digest(canonical_json_bytes(projection))
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_capability_policy(
                        self.schemas,
                        source,
                        verified_at=NOW,
                    )
                self.assertEqual(
                    "CONTRACT_SCHEMA_VIOLATION",
                    raised.exception.code,
                )


if __name__ == "__main__":
    unittest.main()
