from __future__ import annotations

from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from qman_directpath_core.canonical import (
    CanonicalizationError,
    CanonicalJsonLimitError,
    canonical_json_bytes,
    load_canonical_json,
    measure_canonical_json,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"


class CanonicalJsonTests(unittest.TestCase):
    def test_exact_bytes_and_digest_are_deterministic(self) -> None:
        value = {"z": [True, None, -2], "a": {"中": "值"}}
        encoded = canonical_json_bytes(value)

        self.assertEqual(
            encoded,
            '{"a":{"中":"值"},"z":[true,null,-2]}'.encode("utf-8"),
        )
        self.assertEqual(load_canonical_json(encoded), value)
        self.assertEqual(sha256_digest(encoded), sha256_digest(encoded))

    def test_utf16_member_order_matches_portable_profile(self) -> None:
        # U+10000 sorts before U+E000 as UTF-16 code units, unlike code-point
        # order.  This catches accidental use of Python's default key order.
        encoded = canonical_json_bytes({"\ue000": 2, "\U00010000": 1})
        self.assertEqual(
            encoded,
            ('{"\U00010000":1,"\ue000":2}').encode("utf-8"),
        )

    def test_closed_parser_rejects_duplicate_or_noncanonical_input(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{ "a": 1 }',
            b'{"a":1}\\n',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(CanonicalizationError):
                    load_canonical_json(raw)

    def test_nonportable_values_fail_closed(self) -> None:
        for value in (
            9_007_199_254_740_992,
            1.5,
            "e\u0301",
        ):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonical_json_bytes(value)

    def test_bounded_measure_matches_exact_canonical_bytes(self) -> None:
        value = {
            '"key\\\n': ["ascii", "中", "\U00010000", "\u0001", -42, False, None],
        }
        encoded = canonical_json_bytes(value)
        measured_bytes, measured_nodes = measure_canonical_json(
            value,
            max_bytes=len(encoded),
            max_nodes=16,
            max_depth=4,
        )

        self.assertEqual(len(encoded), measured_bytes)
        self.assertEqual(9, measured_nodes)

    def test_bounded_measure_rejects_before_closed_limits_are_crossed(self) -> None:
        value = {"items": [["x" * 64]]}
        for limit_kind, limits in (
            ("bytes", {"max_bytes": 16, "max_nodes": 16, "max_depth": 4}),
            ("nodes", {"max_bytes": 256, "max_nodes": 2, "max_depth": 4}),
            ("depth", {"max_bytes": 256, "max_nodes": 16, "max_depth": 1}),
        ):
            with self.subTest(limit_kind=limit_kind):
                with self.assertRaises(CanonicalJsonLimitError) as raised:
                    measure_canonical_json(value, **limits)
                self.assertEqual(limit_kind, raised.exception.limit_kind)


class ContractSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def test_authoritative_contract_directory_is_loadable(self) -> None:
        root = {
            "schemaVersion": 1,
            "rootSetId": "test-root",
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
                    "publicKeyBase64Url": "A" * 43,
                    "notBefore": "2026-01-01T00:00:00.000000Z",
                    "notAfter": "2027-01-01T00:00:00.000000Z",
                }
            ],
            "rootSetDigest": None,
        }

        self.schemas.validate("root_set", root, "rootSet")

    def test_schema_violation_has_stable_fail_closed_code(self) -> None:
        with self.assertRaises(DirectPathVerificationError) as raised:
            self.schemas.validate("root_set", {}, "rootSet")
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_schema_validation_and_digest_share_one_loaded_snapshot(self) -> None:
        schema_ref = "contracts/directpath-trust-rollback-anchor.schema.json"
        with TemporaryDirectory() as temporary:
            temporary_contracts = Path(temporary)
            for source in CONTRACTS.glob("*.schema.json"):
                shutil.copy2(source, temporary_contracts / source.name)

            loaded = ContractSchemas(temporary_contracts)
            bound_digest = loaded.digest_for_ref(schema_ref, path="schemaRef")
            changed_path = (
                temporary_contracts / "directpath-trust-rollback-anchor.schema.json"
            )
            changed_path.write_bytes(changed_path.read_bytes() + b"\n")

            self.assertEqual(
                loaded.digest_for_ref(schema_ref, path="schemaRef"),
                bound_digest,
            )
            self.assertNotEqual(
                ContractSchemas(temporary_contracts).digest_for_ref(
                    schema_ref,
                    path="schemaRef",
                ),
                bound_digest,
            )

    def test_qualification_schema_resolves_identity_schema(self) -> None:
        # A missing required field is enough to exercise the validator and
        # registry without fabricating a production qualification artifact.
        with self.assertRaises(DirectPathVerificationError) as raised:
            self.schemas.validate(
                "qualification_record",
                {"schemaVersion": 1},
                "qualificationRecord",
            )
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")


if __name__ == "__main__":
    unittest.main()
