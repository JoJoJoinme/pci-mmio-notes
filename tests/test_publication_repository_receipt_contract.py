from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
SCHEMA_PATH = (
    "contracts/"
    "directpath-host-snapshot-publication-repository-receipt.schema.json"
)


class PublicationRepositoryReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((ROOT / SCHEMA_PATH).read_text("utf-8"))
        cls.portable = json.loads(
            (CONTRACTS / "directpath-portable-control-contract.json").read_text(
                "utf-8"
            )
        )
        cls.mapping = json.loads(
            (CONTRACTS / "qman-integration-map.template.json").read_text(
                "utf-8"
            )
        )

    def test_receipt_is_one_closed_draft_2020_12_contract(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(
            "HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT",
            self.schema["properties"]["subjectType"]["const"],
        )
        self.assertEqual(
            (
                "directpath-host-snapshot-publication-trace.schema.json"
                "#/$defs/repositoryTransaction"
            ),
            self.schema["properties"]["repositoryTransaction"]["$ref"],
        )

    def test_portable_closure_governs_receipt_hash_and_signature(self) -> None:
        self.assertIn(SCHEMA_PATH, self.portable["normativeSources"])
        hash_subject = next(
            item
            for item in self.portable["canonicalizationContract"][
                "hashSubjects"
            ]
            if item["subject"]
            == "HostSnapshotPublicationRepositoryReceipt"
        )
        self.assertEqual(SCHEMA_PATH, hash_subject["schemaRef"])
        self.assertEqual("receiptDigest", hash_subject["digestField"])

        signature_profile = next(
            item
            for profile in self.portable["canonicalizationContract"][
                "profiles"
            ]
            if profile["id"] == "SIGNED-ENVELOPE-V1"
            for item in profile["documentProfiles"]
            if item["subject"]
            == "HostSnapshotPublicationRepositoryReceipt"
        )
        self.assertEqual(
            "CONTROL_REPOSITORY_EVIDENCE",
            signature_profile["requiredRole"],
        )
        self.assertEqual("receiptDigest", signature_profile["digestField"])
        self.assertEqual("signature", signature_profile["signatureField"])

    def test_contract_retains_component_only_and_acyclic_boundaries(self) -> None:
        self.assertIn(
            "component-only",
            self.schema["x-qmanAuthorityBoundary"],
        )
        self.assertIn(
            "forbidden from the repository commit record",
            self.schema["x-qmanAcyclicConstructionRule"],
        )
        self.assertIn(
            "publicationMutationCount=N+6",
            self.schema["x-qmanOutcomeClosureRule"],
        )

    def test_repository_port_remains_unmapped_without_target_evidence(
        self,
    ) -> None:
        repository_mapping = next(
            item
            for item in self.mapping["mappings"]
            if item["kind"] == "PORT"
            and item["contractItemId"] == "PORT-GLOBAL-REPOSITORY"
        )
        self.assertEqual("UNMAPPED", repository_mapping["mappingStatus"])
        self.assertEqual(
            "NOT_STARTED",
            repository_mapping["implementationStatus"],
        )
        self.assertEqual([], repository_mapping["targetBindings"])
        self.assertEqual([], repository_mapping["targetTestBindings"])


if __name__ == "__main__":
    unittest.main()
